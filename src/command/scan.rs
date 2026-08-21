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

/// The ports probed when neither the command line nor the settings file says.
///
/// The well-known range: everything a service is conventionally registered
/// under. A starting point rather than a recommendation — a thousand probes per
/// host is cheap enough to be a sensible default and narrow enough that anybody
/// who cares will say what they actually want.
const DEFAULT_PORTS: &str = "1-1024";

/// Runs a port scan.
pub(crate) async fn run(args: &ScanArgs, renderer: &mut dyn Renderer) -> Result<Outcome, Error> {
    let settings = command::engine_settings(args.engine.profile.as_deref())?;
    let mut config = settings.config;
    args.apply_to(&mut config);

    let ports = ports(args, settings.ports);
    let targets = target::resolve_ports(&args.targets, ports, !config.no_dns).await?;
    targets.apply_to(&mut config);

    let redaction = command::redaction(&config);
    renderer.started(Phase::PortScan { targets: &targets }, redaction)?;

    let (session, task) = scan(targets.into_map(), &config).await?;

    command::drive(session, task, renderer).await
}

/// The ports to probe: the flag, then the settings file, then the well-known
/// range.
fn ports(args: &ScanArgs, configured: Option<PortSet>) -> PortSet {
    args.ports.clone().or(configured).unwrap_or_else(|| {
        DEFAULT_PORTS
            .parse()
            .expect("the built-in default is a port specification")
    })
}
