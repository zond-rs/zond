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
//! there, and it does not decide which of them are worth the probes — the engine
//! keeps [`discover`](zond_engine::discover) and [`scan`](zond_engine::scan)
//! apart so that the caller chooses, and a front end that quietly ran both would
//! be taking that choice back.
//!
//! There is a real cost to knowing nothing first: an address nothing lives at
//! comes back with every port closed or filtered, having spent a probe on each.
//! That is the caller's trade to make. `zond discover` answers which hosts are
//! there, and its output feeds straight back in.

use zond_engine::{PortSet, scan};

use crate::cli::ScanArgs;
use crate::command;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::{Phase, Renderer};
use crate::target;

/// How many of the engine's ranked TCP ports are probed when neither the
/// command line nor the settings file says.
///
/// A thousand probes per host is cheap enough to be a sensible default and
/// narrow enough that anybody who cares will say what they actually want. What
/// changed is *which* thousand: this was the well-known range, `1-1024`, and
/// that range is both incomplete and wasteful. Most of what a machine listens on
/// in 2026 is above it — a home server answering on 3001, 5432 and 7778 was
/// reported as running half the services it runs — while much of what is inside
/// it belongs to protocols nobody has deployed this century.
///
/// The same thousand probes, spent on the thousand ports most likely to answer.
/// See `zond_engine::model::port::catalog` for the ranking and its provenance.
const DEFAULT_TOP_PORTS: usize = 1000;

/// Runs a port scan.
pub(crate) async fn run(args: &ScanArgs, renderer: &mut dyn Renderer) -> Result<Outcome, Error> {
    let settings = command::engine_settings(args.engine.profile.as_deref())?;
    let mut config = settings.config;
    args.apply_to(&mut config);

    let ports = ports(args, settings.ports);
    let targets = target::resolve_ports(
        &args.targets,
        &args.engine.exclude,
        &config.exclusions,
        ports,
        !config.no_dns,
    )
    .await?;
    targets.apply_to(&mut config);

    let redaction = command::redaction(&config);
    renderer.started(Phase::PortScan { targets: &targets }, redaction)?;

    let (session, task) = scan(targets.into_map(), &config).await?;

    command::drive(session, task, renderer).await
}

/// The ports to probe: `--ports`, then `--top-ports`, then the settings file,
/// then the engine's ranked default.
///
/// `--top-ports` outranks the settings file deliberately. A flag typed on the
/// command line is a decision about this run, and a default written in a
/// configuration file is a decision about every other one.
fn ports(args: &ScanArgs, configured: Option<PortSet>) -> PortSet {
    if let Some(ports) = args.ports.clone() {
        return ports;
    }
    if let Some(count) = args.top_ports {
        return PortSet::top_tcp(count);
    }
    configured.unwrap_or_else(|| PortSet::top_tcp(DEFAULT_TOP_PORTS))
}
