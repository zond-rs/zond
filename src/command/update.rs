// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # `zond update`
//!
//! Brings every resource the engine knows how to fetch up to date in the
//! conventional cache, one line per resource: what it is, how large, and
//! whether it changed or why it failed. Nothing else is said at the default
//! verbosity, because an update run from a timer is read only when a line
//! says something went wrong.
//!
//! Every resource is tried whatever happened to the one before, since the
//! feeds come from different publishers and one being down says nothing about
//! the others. The exit status then says how it went: `0` when every one is
//! current, `3` when some are, `1` when none is.
//!
//! While a resource downloads, the progress line a scan draws says which
//! one and how much of it is in, where standard error is a terminal and the
//! presentation is `fancy`; anywhere else nothing is drawn and the lines are
//! all there is. `Ctrl-C` takes the line back and exits `130`, leaving every
//! stored copy as it was.
//!
//! The cache is the engine's
//! [`default_cache_dir`](zond_engine::fetch::default_cache_dir), found as the
//! journal is, so `XDG_CACHE_HOME` moves it and an update run as the user and
//! a scan run with `sudo` share one copy. There is no flag for it, as there is
//! none for the journal.

use zond_engine::fetch::{self, Client, Outcome as Fetched, Resource, Store};

use crate::diagnostics::Verbosity;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::field;
use crate::render::progress::{self, Counting};
use crate::render::style::{Palette, Style};
use crate::settings::Presentation;

/// Runs `zond update`.
pub(crate) async fn run(
    presentation: Presentation,
    verbosity: Verbosity,
    palette: Palette,
) -> Result<Outcome, Error> {
    let root = fetch::default_cache_dir().ok_or(Error::NoCacheDirectory)?;
    let store = Store::new(root);
    let client = Client::new().map_err(Error::Fetch)?;
    tracing::info!(verbosity = 1, "cache {}", store.root().display());

    // `fancy` alone draws the line, as it does for a scan, and a quiet run
    // draws nothing it was not asked for. `start` itself declines anything
    // that is not a terminal.
    if presentation == Presentation::Fancy && verbosity.narrates() {
        progress::start(Counting::Bytes, Style::commentary(presentation, palette));
    }
    let outcome = tokio::select! {
        outcome = update(&client, &store) => outcome,
        // The fetch under way is dropped, which leaves its resource's stored
        // copy as it was and its staged download for the next update to
        // discard.
        _ = tokio::signal::ctrl_c() => Outcome::Interrupted,
    };
    progress::stop();
    Ok(outcome)
}

/// Fetches every registered resource into `store`, a line for each, and says
/// how it went.
async fn update(client: &Client, store: &Store) -> Outcome {
    let resources = fetch::registry();
    let mut failed = 0;
    for resource in &resources {
        let id = resource.id();
        progress::downloading(id, 0, None);
        let fetched = client
            .fetch(resource, store, |received, total| {
                progress::downloading(id, received, total);
            })
            .await;
        match fetched {
            Ok(fetched) => {
                tracing::info!("{}", line(resource, &fetched));
                tracing::info!(verbosity = 1, "{}", detail(resource, &fetched));
            }
            Err(e) => {
                failed += 1;
                tracing::warn!("{:<WIDTH$} failed: {e}", resource.id());
                tracing::info!(verbosity = 1, "{}: {}", resource.id(), chain(&e));
            }
        }
    }

    concluded(failed, resources.len())
}

/// How wide the resource column is: the longest id the engine registers
/// today, so the sizes line up.
const WIDTH: usize = 25;

/// What a run that tried `total` resources and failed `failed` of them tells
/// the shell.
fn concluded(failed: usize, total: usize) -> Outcome {
    match failed {
        0 => Outcome::Complete,
        failed if failed == total => Outcome::Failed,
        _ => Outcome::Partial,
    }
}

/// The one line a resource gets: its id, its size, and whether it changed.
fn line(resource: &Resource, fetched: &Fetched) -> String {
    let word = match fetched {
        Fetched::Updated(_) => "updated",
        // Two ways to find the same thing: the server said so, or sent the
        // same bytes again. `-v` tells them apart.
        _ => "unchanged",
    };
    format!(
        "{:<WIDTH$} {:>8}  {word}",
        resource.id(),
        field::bytes(fetched.metadata().size)
    )
}

/// What `-v` adds: how much this run downloaded, and when the copy kept was
/// downloaded, which for an unchanged resource is some earlier update.
fn detail(resource: &Resource, fetched: &Fetched) -> String {
    let fetched_at = field::age(fetched.metadata().fetched_at);
    let when = if fetched_at == "now" {
        fetched_at
    } else {
        format!("{fetched_at} ago")
    };
    format!(
        "{}: {} downloaded, copy fetched {when}",
        resource.id(),
        field::bytes(fetched.downloaded()),
    )
}

/// Every cause behind `error`, outermost first, for the person at `-v` who
/// needs more than the few words the line gives.
fn chain(error: &dyn std::error::Error) -> String {
    let mut causes = vec![error.to_string()];
    let mut cause = error.source();
    while let Some(current) = cause {
        causes.push(current.to_string());
        cause = current.source();
    }
    causes.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A timer that runs the update tells a partial failure from a total one
    /// by the status alone: some feeds current is worth a look, none is
    /// worth an alarm.
    #[test]
    fn the_status_says_how_many_resources_failed() {
        assert_eq!(concluded(0, 3), Outcome::Complete);
        assert_eq!(concluded(1, 3), Outcome::Partial);
        assert_eq!(concluded(3, 3), Outcome::Failed);
    }

    /// Every registered id fits the column, so no line is pushed out of step
    /// with the rest.
    #[test]
    fn every_resource_id_fits_the_column() {
        for resource in fetch::registry() {
            assert!(resource.id().len() <= WIDTH, "{}", resource.id());
        }
    }
}
