// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # `zond discover`
//!
//! Which hosts on a network are alive.
//!
//! The engine does the scanning and [`drive`](super::drive) does the watching.
//! What this module contributes is deciding what the user asked about.
//!
//! A sweep is recorded like a port scan, and continued the same way: an address
//! that answered, or that was asked as many times as it is going to be, is one
//! a later sitting does not repeat. `zond journal` lists what is on record and
//! `zond read` prints any of it back.

use zond_engine::journal::manifest::Plan;
use zond_engine::journal::store::Journal;
use zond_engine::model::ip::set::IpSet;
use zond_engine::{ZondConfig, discover, discover_with_journal};

use crate::cli::DiscoverArgs;
use crate::command::{self, Recording, Stopping};
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::{Phase, Renderer};
use crate::target::{self, Targets};

/// Runs a discovery sweep.
pub(crate) async fn run(
    args: &DiscoverArgs,
    recording: Recording,
    renderer: &mut dyn Renderer,
) -> Result<Outcome, Error> {
    // Before anything is sent: a misspelt extension is a mistake made in the
    // first second of a run that may take hours, and the end of one is the
    // worst moment to be told.
    let destinations = args.export.destinations()?;

    // Before the targets: whether a hostname may be looked up at all depends
    // on the `no_dns` these layers settle on, which a file may set as well as a
    // flag.
    let mut config = command::engine_settings(args.engine.profile.as_deref())?.config;
    args.engine.apply_to(&mut config);

    // A resume needs no targets: the plan comes from the record, which is what
    // ran rather than what somebody types the second time.
    let (targets, journal) = match args.resume.as_deref() {
        Some(id) => continued(id, &mut config)?,
        None => started(args, recording, &mut config).await?,
    };

    let redaction = command::redaction(&config);
    renderer.started(Phase::Discovery { targets: &targets }, redaction)?;

    let ips = targets.into_ips();
    let (session, task) = match journal {
        Some(journal) => discover_with_journal(ips, &config, journal).await?,
        None => discover(ips, &config).await?,
    };

    command::drive(
        session,
        task,
        &destinations,
        redaction,
        // A plan half-walked: stopping leaves ground uncovered.
        Stopping::CutsShort,
        renderer,
    )
    .await
}

/// A sweep of what the command line asked for.
async fn started(
    args: &DiscoverArgs,
    recording: Recording,
    config: &mut ZondConfig,
) -> Result<(Targets, Option<Journal>), Error> {
    // Exclusions travel with the targets: same grammar, same DNS policy, one
    // module deciding what either half of a scope means.
    let targets = target::resolve(
        &args.targets,
        &args.engine.exclude,
        &config.exclusions,
        !config.no_dns,
    )
    .await?;

    // After `apply_to`, because whether this is a segment sweep is part of what
    // gets recorded, and `lan` is one of the things that decides it. Before the
    // sweep is announced, so that where it is being written appears above the
    // results rather than in the middle of them.
    targets.apply_to(config);
    let journal = recording
        .wanted
        .then(|| {
            command::record(
                &Plan::discovery(targets.ips(), &config.exclusions, config.segment_sweep),
                summarise(targets.ips()),
                recording.limit,
            )
        })
        .flatten();

    Ok((targets, journal))
}

/// A sweep continuing one already on record.
///
/// The plan is the recorded one, so there is nothing to type but the id. What
/// the engine is handed back is the whole of it. The addresses this sitting has
/// to ask about are worked out from the record's own cursor, which is the only
/// thing that knows what the earlier sittings earned.
fn continued(id: &str, config: &mut ZondConfig) -> Result<(Targets, Option<Journal>), Error> {
    let resumed = command::reopen(id, "addresses")?;

    let Some(addresses) = resumed.plan.addresses().cloned() else {
        return Err(Error::WrongPhase {
            id: resumed.id,
            held: "a port scan",
            remedy: "zond scan --resume",
        });
    };

    // The record's own answer, not this run's: whether the first sitting swept
    // the segment beyond its addresses is part of what is being continued.
    config.segment_sweep = resumed.journal.manifest().sweep;

    Ok((
        Targets::resumed(addresses, resumed.remaining, resumed.id),
        Some(resumed.journal),
    ))
}

/// How a sweep is described in a listing.
///
/// Short enough for a column and specific enough to recognise: where it started
/// and how much ground it covered. Nothing decides anything from this text.
fn summarise(addresses: &IpSet) -> String {
    let first = addresses
        .iter()
        .next()
        .map_or_else(|| String::from("nothing"), |ip| ip.to_string());

    match addresses.len() {
        0 | 1 => first,
        n => format!("{first} and {} more", n - 1),
    }
}
