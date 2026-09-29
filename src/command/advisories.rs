// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The distributions' security data a scan uses
//!
//! What `zond update` fetched and converted, read back for a scan so a
//! distribution's build is judged by its distributor's own fix data rather than
//! by its upstream version. Read from the cache and never fetched: a scan
//! sends nothing it was not asked to, and `zond update` is the one command
//! that downloads anything.
//!
//! Absent data is not an error. The scan still runs and reports a
//! distribution's build as unverified, and one line says what would change
//! that.

use std::time::{Duration, SystemTime};

use zond_engine::cve::Advisories;
use zond_engine::fetch::advisory::Dataset;
use zond_engine::fetch::{self, Store};

/// How old the data may grow before a scan says so: distributions publish
/// fixes daily, and a month-old copy judges builds by fixes a month stale.
const STALE_AFTER: Duration = Duration::from_secs(14 * 86_400);

/// Every converted dataset the cache holds, with a line where there is none
/// or it has grown old.
pub(crate) fn load() -> Vec<Advisories> {
    let Some(root) = fetch::default_cache_dir() else {
        return Vec::new();
    };
    let store = Store::new(root);

    let mut loaded = Vec::new();
    let mut oldest: Option<SystemTime> = None;
    for dataset in Dataset::ALL {
        let id = dataset.derived().id().to_owned();
        match dataset.load(&store) {
            Ok(Some(found)) => {
                let fetched = found
                    .metadata
                    .sources
                    .iter()
                    .map(|source| source.fetched_at)
                    .min();
                oldest = oldest.min(fetched).or(fetched);
                tracing::info!(
                    verbosity = 1,
                    "{id} {} ({}{})",
                    found.advisories.version(),
                    fetched.map_or_else(|| "undated".into(), crate::render::field::age),
                    if found.current {
                        ""
                    } else {
                        ", feeds changed since"
                    }
                );
                loaded.push(found.advisories);
            }
            Ok(None) => tracing::info!(verbosity = 1, "{id}: none (zond update)"),
            Err(e) => tracing::warn!("{id} unreadable: {e}"),
        }
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
            crate::render::field::age(oldest)
        );
    }
    loaded
}
