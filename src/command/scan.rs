// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # `zond scan`
//!
//! Which of the named hosts' ports are open.
//!
//! It probes what it was given. It does not sweep first to check the targets are
//! there, and it does not decide which of them are worth the probes. The engine
//! keeps [`discover`](zond_engine::discover) and [`scan`]
//! apart so that the caller chooses, and a front end that quietly ran both would
//! be taking that choice back.
//!
//! There is a real cost to knowing nothing first: an address nothing lives at
//! comes back with every port closed or filtered, having spent a probe on each.
//! That is the caller's trade to make. `zond discover` answers which hosts are
//! there, and its output feeds straight back in.

use zond_engine::journal::manifest::Plan;
use zond_engine::journal::store::Journal;
use zond_engine::model::target::TargetMap;
use zond_engine::scanner::scan_with_journal;
use zond_engine::system::privilege::Privilege;
use zond_engine::{PortSet, ZondConfig, scan};

use crate::cli::ScanArgs;
use crate::command::{self, Recording, Stopping};
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::{Phase, Renderer};
use crate::target::{self, ScanTargets};

/// How many of the engine's ranked TCP ports are probed when neither the
/// command line nor the settings file says.
///
/// A thousand probes per host is cheap enough to be a sensible default and
/// narrow enough that anybody who cares will say what they actually want. What
/// changed is *which* thousand: this was the well-known range, `1-1024`, and
/// that range is both incomplete and wasteful. Most of what a machine listens on
/// in 2026 sits above it, so a home server answering on 3001, 5432 and 7778 was
/// reported as running half the services it runs. Much of what is inside it
/// belongs to protocols nobody has deployed this century.
///
/// The same thousand probes, spent on the thousand ports most likely to answer.
/// See `zond_engine::model::port::catalog` for the ranking and its provenance.
const DEFAULT_TOP_PORTS: usize = 1000;

/// Runs a port scan.
pub(crate) async fn run(
    args: &ScanArgs,
    recording: Recording,
    reasons: bool,
    renderer: &mut dyn Renderer,
) -> Result<Outcome, Error> {
    // Before anything is sent: a misspelt extension is a mistake made in the
    // first second of a run that may take hours, and the end of one is the
    // worst moment to be told.
    let destinations = args.export.destinations()?;

    // Read once, here, and threaded down: `ports` and `config` come out of the
    // same document, and asking for them separately means parsing `engine.toml`
    // twice and warning about it twice. See `settings::EngineSettings`.
    let settings = command::engine_settings(args.engine.profile.as_deref())?;
    let mut config = settings.config;
    args.apply_to(&mut config);

    // A SYN scan reaches `filtered` from silence and from a refusal alike, so it
    // does not ask its capture for ICMP unless something wants to tell the two
    // apart. `--reason` is that request.
    if reasons {
        config.icmp_evidence = true;
    }

    let ports = ports(args, settings.ports);

    // A resume needs no targets: the plan comes from the record, which is what
    // ran rather than what somebody types the second time. Targets given anyway
    // are checked against it.
    let (targets, journal) = match args.resume.as_deref() {
        Some(id) => continued(id, args, ports, &config).await?,
        None => started(args, recording, ports, &mut config).await?,
    };

    let redaction = command::redaction(&config);
    renderer.started(Phase::PortScan { targets: &targets }, redaction)?;

    let plan = targets.into_map();

    // The corpus the scan runs against a service it identifies, held to the
    // ceiling `config.detection` names. The built-in catalogue unless
    // `--detections` named more, and every one of them compiled before the scan
    // starts: a detection that will not build is a mistake made before the run
    // and the end of one is the worst moment to be told.
    let detections = command::detections::corpus(&args.detections)?;

    // Read before the scan starts, for the reason the export destinations are:
    // a catalogue that will not parse is a mistake made in the first second of a
    // run that may take hours, and the end of one is the worst moment to hear
    // about it.
    let catalogue = args
        .cve_catalogue
        .as_deref()
        .map(command::cve_catalogue)
        .transpose()?;

    let (session, task) = match journal {
        Some(journal) => scan_with_journal(plan, &config, detections, journal).await?,
        None => scan(plan, &config, detections).await?,
    };

    command::drive(
        session,
        task,
        &destinations,
        redaction,
        // A plan half-walked: stopping leaves ground uncovered.
        Stopping::CutsShort,
        catalogue.as_ref(),
        renderer,
    )
    .await
}

/// A scan of what the command line asked for.
async fn started(
    args: &ScanArgs,
    recording: Recording,
    ports: PortSet,
    config: &mut ZondConfig,
) -> Result<(ScanTargets, Option<Journal>), Error> {
    let targets = target::resolve_ports(
        &args.targets,
        &args.engine.exclude,
        &config.exclusions,
        ports,
        !config.no_dns,
    )
    .await?;
    targets.apply_to(config);

    // Before the scan is announced: a journal another scan is writing means
    // there is nothing to announce, and saying "scanning 4 probes" and then
    // refusing reads as a scan that went wrong rather than one that never
    // started.
    let journal = recording
        .wanted
        .then(|| {
            command::record(
                &Plan::port_scan(targets.map(), &config.exclusions, config.tcp_technique),
                summarise(targets.map()),
                recording.limit,
            )
        })
        .flatten();

    Ok((targets, journal))
}

/// A scan continuing one already on record.
///
/// The plan is the recorded one. Targets named on the command line are checked
/// against it and refused if they describe something else, because continuing
/// the wrong scan quietly would count positions against a plan they were never
/// counted in.
async fn continued(
    id: &str,
    args: &ScanArgs,
    ports: PortSet,
    config: &ZondConfig,
) -> Result<(ScanTargets, Option<Journal>), Error> {
    let resumed = command::reopen(id, "targets")?;

    let Some(plan) = resumed.plan.targets().cloned() else {
        return Err(Error::WrongPhase {
            id: resumed.id,
            held: "a sweep",
            remedy: "zond discover --resume",
        });
    };

    if !args.targets.is_empty() {
        let named = target::resolve_ports(
            &args.targets,
            &args.engine.exclude,
            &config.exclusions,
            ports,
            !config.no_dns,
        )
        .await?;

        let manifest = resumed.journal.manifest();
        manifest.covers(
            &Plan::port_scan(named.map(), &config.exclusions, manifest.technique()),
            Privilege::current(),
        )?;
    }

    Ok((
        ScanTargets::resumed(plan, resumed.remaining, resumed.id),
        Some(resumed.journal),
    ))
}

/// How a plan is described in a listing.
///
/// Short enough for a column and specific enough to recognise: what was scanned
/// and how much of it. Nothing decides anything from this text.
fn summarise(plan: &TargetMap) -> String {
    let addresses = plan.gross_ips().unwrap_or_default();
    let ports: usize = plan.units.iter().map(|unit| unit.ports().len()).sum();

    let first = plan
        .units
        .first()
        .and_then(|unit| unit.ips().iter().next())
        .map_or_else(|| String::from("nothing"), |ip| ip.to_string());

    let ports = match ports {
        1 => String::from("1 port"),
        n => format!("{n} ports"),
    };

    match addresses {
        0 | 1 => format!("{first} on {ports}"),
        n => format!("{first} and {} more on {ports}", n - 1),
    }
}

/// The ports to probe: `--ports`, then the two top-ports flags, then the
/// settings file, then the engine's ranked default.
///
/// The top-ports flags combine, so `--top-ports 100 --top-ports-udp 50` probes
/// both lists and either one alone probes only its own transport. Naming one of
/// them is naming the whole port set for this run, which is why the TCP default
/// is not folded back in when only the UDP flag is given.
///
/// Either outranks the settings file deliberately. A flag typed on the command
/// line is a decision about this run, and a default written in a configuration
/// file is a decision about every other one.
fn ports(args: &ScanArgs, configured: Option<PortSet>) -> PortSet {
    if let Some(ports) = args.ports.clone() {
        return ports;
    }
    if args.top_ports.is_some() || args.top_ports_udp.is_some() {
        let tcp = PortSet::top_tcp(args.top_ports.unwrap_or(0));
        let udp = PortSet::top_udp(args.top_ports_udp.unwrap_or(0));
        return tcp.union(&udp);
    }
    configured.unwrap_or_else(|| PortSet::top_tcp(DEFAULT_TOP_PORTS))
}
