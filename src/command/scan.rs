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

    // A resume asks what the recorded scan asked: its options go over the
    // settings files, and the flags typed for this sitting over those, where
    // one that changes what the scan asks is refused.
    let resumed = args
        .resume
        .as_deref()
        .map(|id| command::reopen(id, "targets", args.take_over))
        .transpose()?;
    if let Some(resumed) = &resumed {
        command::restore(resumed, &mut config);
    }
    args.apply_to(&mut config);
    if let Some(resumed) = &resumed {
        command::held_to_record(resumed, &config)?;
    }

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
    let (targets, journal) = match resumed {
        Some(resumed) => continued(resumed, args, ports, &config).await?,
        None => started(args, recording, ports, &mut config).await?,
    };

    args.engine
        .warn_unpinned(&config, targets.map().iter().map(|target| target.ip));

    let redaction = command::redaction(&config);
    renderer.started(
        Phase::PortScan {
            targets: &targets,
            resumable: journal.is_some(),
        },
        redaction,
    )?;

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

    // Taken before the journal is handed over, and only for a record this run
    // claimed: a resumed one was announced once its checks passed.
    let fresh = journal
        .as_ref()
        .filter(|_| args.resume.is_none())
        .map(|journal| journal.manifest().id.clone());

    let (session, task) = match journal {
        Some(journal) => scan_with_journal(plan, &config, detections, journal).await?,
        None => scan(plan, &config, detections).await?,
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
        &config.excluded_ports,
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
                targets.summary().to_owned(),
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
    resumed: command::Resumed,
    args: &ScanArgs,
    ports: PortSet,
    config: &ZondConfig,
) -> Result<(ScanTargets, Option<Journal>), Error> {
    let Some(plan) = resumed.plan.targets().cloned() else {
        return Err(Error::WrongPhase {
            id: resumed.id,
            held: "a sweep",
            remedy: "zond discover --resume",
        });
    };

    // Ports named without targets are held to the plan as a flag is held to
    // the record's options: the ports every target was asked are the same
    // scan, and any others would be ignored, since what this sitting asks
    // comes from the record. Named with targets, they are checked with them
    // below, where a target that carries ports of its own is told apart from
    // one given these.
    if args.targets.is_empty()
        && let Some((named, flag)) = typed_ports(args)
        && !plan.units.iter().all(|unit| *unit.ports() == named)
    {
        return Err(Error::OptionChanged { flag });
    }

    if !args.targets.is_empty() {
        // A target named without ports stands for the one it names on record,
        // so it is given the ports the record asked, where it asked every
        // target the same ones: the settings file's or the built-in default
        // would describe a scan the record never ran. A plan whose targets were
        // asked differing ports has no one set to lend, so there a target is
        // resolved as a fresh scan would resolve it, and agrees only where it
        // names its own ports or the default happens to be the record's.
        let ports = typed_ports(args)
            .map(|(ports, _)| ports)
            .or_else(|| uniform_ports(&plan))
            .unwrap_or(ports);
        let named = target::resolve_ports(
            &args.targets,
            &args.engine.exclude,
            &config.exclusions,
            ports,
            &config.excluded_ports,
            !config.no_dns,
        )
        .await?;

        let manifest = resumed.journal.manifest();
        manifest.covers(
            &Plan::port_scan(named.map(), &config.exclusions, manifest.technique()),
            Privilege::current(),
        )?;
    }

    resumed.announce();
    let described = resumed.described();
    Ok((
        ScanTargets::resumed(plan, resumed.remaining, described),
        Some(resumed.journal),
    ))
}

/// The ports a plan asked every one of its targets, or `None` where its
/// targets were asked differing ports, or it has none.
fn uniform_ports(plan: &TargetMap) -> Option<PortSet> {
    let (first, rest) = plan.units.split_first()?;
    rest.iter()
        .all(|unit| unit.ports() == first.ports())
        .then(|| first.ports().clone())
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
    typed_ports(args)
        .map(|(ports, _)| ports)
        .or(configured)
        .unwrap_or_else(|| PortSet::top_tcp(DEFAULT_TOP_PORTS))
}

/// The ports named on the command line, if any flag named them, and that flag
/// as it is typed, for a refusal that has to say which one to drop.
fn typed_ports(args: &ScanArgs) -> Option<(PortSet, &'static str)> {
    if let Some(ports) = args.ports.clone() {
        return Some((ports, "--ports"));
    }
    if args.top_ports.is_some() || args.top_ports_udp.is_some() {
        let tcp = PortSet::top_tcp(args.top_ports.unwrap_or(0));
        let udp = PortSet::top_udp(args.top_ports_udp.unwrap_or(0));
        let flag = if args.top_ports.is_some() {
            "--top-ports"
        } else {
            "--top-ports-udp"
        };
        return Some((tcp.union(&udp), flag));
    }
    None
}
