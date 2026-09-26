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

    // A resume asks what the recorded sweep asked; see `scan` for the order
    // the layers go on in.
    let resumed = args
        .resume
        .as_deref()
        .map(|id| command::reopen(id, "addresses", args.take_over))
        .transpose()?;
    if let Some(resumed) = &resumed {
        command::restore(resumed, &mut config);
    }
    args.engine.apply_to(&mut config);
    if let Some(resumed) = &resumed {
        command::held_to_record(resumed, &config)?;
    }

    // A resume needs no targets: the plan comes from the record, which is what
    // ran rather than what somebody types the second time.
    let (targets, journal) = match resumed {
        Some(resumed) => continued(resumed, &mut config)?,
        None => started(args, recording, &mut config).await?,
    };

    let ips = targets.ips();
    args.engine.warn_unpinned(
        &config,
        ips.v4()
            .iter()
            .map(|range| std::net::IpAddr::V4(range.start_addr()))
            .chain(
                ips.v6()
                    .iter()
                    .map(|range| std::net::IpAddr::V6(range.start_addr())),
            ),
    );

    let redaction = command::redaction(&config);
    renderer.started(
        Phase::Discovery {
            targets: &targets,
            resumable: journal.is_some(),
        },
        redaction,
    )?;

    let ips = targets.into_ips();
    // Taken before the journal is handed over, and only for a record this run
    // claimed: a resumed one was announced once its checks passed.
    let fresh = journal
        .as_ref()
        .filter(|_| args.resume.is_none())
        .map(|journal| journal.manifest().id.clone());

    let (session, task) = match journal {
        Some(journal) => discover_with_journal(ips, &config, journal).await?,
        None => discover(ips, &config).await?,
    };

    if let Some(id) = fresh {
        command::announce(&id, recording.limit);
    }

    command::drive(
        session,
        task,
        &destinations,
        redaction,
        // A plan half-walked: stopping leaves ground uncovered.
        Stopping::CutsShort,
        None,
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
    // sweep is announced, so a record that cannot be claimed is said above it
    // rather than in the middle of its results.
    targets.apply_to(config);
    let journal = recording
        .wanted
        .then(|| {
            command::record(
                &Plan::discovery(targets.ips(), &config.exclusions, config.segment_sweep),
                targets.summary().to_owned(),
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
fn continued(
    resumed: command::Resumed,
    config: &mut ZondConfig,
) -> Result<(Targets, Option<Journal>), Error> {
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

    resumed.announce();
    let described = resumed.described();
    Ok((
        Targets::resumed(addresses, resumed.remaining, described),
        Some(resumed.journal),
    ))
}
