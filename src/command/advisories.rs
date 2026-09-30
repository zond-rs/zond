// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The distributions' security data a scan uses
//!
//! What lets a scan judge a distribution's build by its distributor's own fix
//! data rather than by its upstream version. Two sources, and a scan uses the
//! newer of them per distributor:
//!
//! - **The snapshot a release build carries**, Ubuntu's, converted from
//!   Canonical's feeds when the release was made. A fresh install judges
//!   Ubuntu's builds correctly without fetching anything. See `build.rs` and
//!   `assets/advisories/NOTICE`.
//! - **The cache `zond update` fills**, for data newer than the release and
//!   for Debian's, which no release carries until Debian states the terms its
//!   tracker's data may be redistributed under.
//!
//! A scan never fetches on its own. The one exception is asked first: the
//! first interactive scan without Debian's data offers to fetch it, once,
//! and a no is remembered in the cache so it is not asked again.

use std::io::{BufRead, IsTerminal, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zond_engine::cve::Advisories;
use zond_engine::fetch::advisory::{Dataset, Feed};
use zond_engine::fetch::{self, Client, Store};
use zond_engine::model::finding::Version;

use crate::diagnostics::Verbosity;
use crate::render::field;
use crate::render::progress;
use crate::settings::Presentation;

/// How old the data may grow before a scan says so: distributions publish
/// fixes daily, and a month-old copy judges builds by fixes a month stale.
const STALE_AFTER: Duration = Duration::from_secs(14 * 86_400);

/// The note that records somebody declining Debian's data.
const DEBIAN_DECLINED: &str = "debian-data-declined";

/// The Ubuntu snapshot this build carries, where the checkout it was built
/// from had one.
#[cfg(bundled_ubuntu)]
const BUNDLED_UBUNTU: Option<&[u8]> = Some(include_bytes!("../../assets/advisories/ubuntu.bin"));
#[cfg(not(bundled_ubuntu))]
const BUNDLED_UBUNTU: Option<&[u8]> = None;

/// The data a scan judges distribution builds by: per distributor, the newer
/// of the carried snapshot and the cached copy, with a line where there is
/// none at all or it has grown old.
pub(crate) fn load() -> Vec<Advisories> {
    let store = fetch::default_cache_dir().map(Store::new);

    let mut loaded = Vec::new();
    let mut oldest: Option<SystemTime> = None;
    for dataset in Dataset::ALL {
        let id = dataset.derived().id().to_owned();
        let cached = store.as_ref().and_then(|store| match dataset.load(store) {
            Ok(found) => found,
            Err(e) => {
                tracing::warn!("{id} unreadable: {e}");
                None
            }
        });
        let bundled = bundled(*dataset);

        // The newer by the data's own date; a tie goes to the cache, which
        // this build's converter made.
        let (advisories, from, dated) = match (cached, bundled) {
            (Some(cached), Some(bundled)) if bundled.version() > cached.advisories.version() => {
                let dated = date_of(bundled.version());
                (bundled, "carried", dated)
            }
            (Some(cached), _) => {
                let dated = cached
                    .metadata
                    .sources
                    .iter()
                    .map(|source| source.fetched_at)
                    .min();
                let from = if cached.current {
                    "cached"
                } else {
                    "cached, feeds changed since"
                };
                (cached.advisories, from, dated)
            }
            (None, Some(bundled)) => {
                let dated = date_of(bundled.version());
                (bundled, "carried", dated)
            }
            (None, None) => {
                tracing::info!(verbosity = 1, "{id}: none (zond update)");
                continue;
            }
        };
        tracing::info!(
            verbosity = 1,
            "{id} {} ({from}, {})",
            advisories.version(),
            dated.map_or_else(|| "undated".into(), field::age)
        );
        oldest = oldest.min(dated).or(dated);
        loaded.push(advisories);
    }

    if loaded.is_empty() {
        tracing::info!("no distro security data: builds unverified (zond update)");
    } else if let Some(oldest) = oldest
        && SystemTime::now()
            .duration_since(oldest)
            .is_ok_and(|age| age > STALE_AFTER)
    {
        tracing::info!(
            "distro security data is {} old (zond update)",
            field::age(oldest)
        );
    }
    loaded
}

/// The snapshot this build carries for `dataset`, where it carries one this
/// engine can read.
fn bundled(dataset: Dataset) -> Option<Advisories> {
    let bytes = match dataset {
        Dataset::Ubuntu => BUNDLED_UBUNTU?,
        _ => return None,
    };
    Advisories::from_bytes(bytes).ok()
}

/// The day a dataset's version names, `YYYY.M.D`, as a time: when the newest
/// record it holds was published.
fn date_of(version: Version) -> Option<SystemTime> {
    let days = days_from_civil(
        version.major.into(),
        version.minor.into(),
        version.patch.into(),
    )?;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(days).ok()? * 86_400))
}

/// Days since 1970-01-01 of a proleptic Gregorian date, where it is one.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let of_cycle = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    Some(era * 146_097 + of_cycle - 719_468)
}

/// Offers to fetch Debian's security data where a person could answer and
/// nobody has, before a scan: once, on a terminal, and never again after a
/// no.
///
/// Debian's is the one dataset a release cannot carry yet, so without this a
/// fresh install judges every Debian build as unchecked until somebody reads
/// the line that says so. Asked rather than fetched, because a scan otherwise
/// sends nothing its command line did not ask for.
///
/// Asked before the scan's own lines, so the question is not lost among
/// them, and only in the `fancy` presentation without `-q`, where a person is
/// reading.
pub(crate) async fn offer_debian(presentation: Presentation, verbosity: Verbosity) {
    let interactive = presentation == Presentation::Fancy && verbosity.narrates();
    let terminal = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    if !interactive || !terminal {
        return;
    }
    let Some(root) = fetch::default_cache_dir() else {
        return;
    };
    let store = Store::new(root);
    let installed = matches!(Dataset::Debian.load(&store), Ok(Some(_)));
    let declined = matches!(store.note(DEBIAN_DECLINED), Ok(Some(_)));
    if installed || declined {
        return;
    }

    let mut out = std::io::stderr();
    let _ = write!(
        out,
        "• Debian security data is not installed. Fetch it now (78 MB)? [Y/n] "
    );
    let _ = out.flush();
    // A closed input is no answer at all: neither a yes to fetch on nor a no
    // to remember.
    let mut answer = String::new();
    if !matches!(std::io::stdin().lock().read_line(&mut answer), Ok(1..)) {
        let _ = writeln!(out);
        return;
    }
    if !wants(&answer) {
        let _ = store.set_note(DEBIAN_DECLINED, "declined when offered before a scan\n");
        tracing::info!("skipped: zond update fetches it any time");
        return;
    }

    let Ok(client) = Client::new() else {
        tracing::warn!("Debian security data: no HTTP client");
        return;
    };
    let tracker = Feed::DebianTracker.resource();
    if super::update::fetch_one(&client, &store, &tracker).await {
        super::update::convert_one(&store, Dataset::Debian).await;
    }
    progress::clear();
}

/// Whether an answer to a `[Y/n]` question is a yes: anything but a no, an
/// empty line included.
fn wants(answer: &str) -> bool {
    !matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Enter is a yes, as the capital says, and only a no is a no.
    #[test]
    fn a_blank_answer_is_a_yes_and_only_no_declines() {
        for yes in ["\n", "y\n", "Y", "yes", " YES \n", "sure"] {
            assert!(wants(yes), "{yes:?}");
        }
        for no in ["n\n", "N", "no", " No \n"] {
            assert!(!wants(no), "{no:?}");
        }
    }

    /// A dataset's version is the day of its newest record, and that day is
    /// what a scan measures the data's age from.
    #[test]
    fn a_dataset_version_reads_as_its_day() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
        assert_eq!(days_from_civil(2026, 9, 28), Some(20_724));
        assert_eq!(date_of(Version::new(0, 0, 0)), None, "an undated dataset");
    }

    /// A release build carries Ubuntu's data, and this build reads it.
    #[cfg(bundled_ubuntu)]
    #[test]
    fn the_carried_ubuntu_snapshot_reads() {
        let carried = bundled(Dataset::Ubuntu).expect("the snapshot reads");
        assert_eq!(carried.distributor(), "ubuntu");
        assert!(!carried.is_empty());
    }
}
