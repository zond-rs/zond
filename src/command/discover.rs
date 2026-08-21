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

use zond_engine::discover;

use crate::cli::DiscoverArgs;
use crate::command;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::{Phase, Renderer};
use crate::target;

/// Runs a discovery sweep.
pub(crate) async fn run(
    args: &DiscoverArgs,
    renderer: &mut dyn Renderer,
) -> Result<Outcome, Error> {
    // Before the targets: whether a hostname may be looked up at all depends
    // on the `no_dns` these layers settle on, which a file may set as well as a
    // flag.
    let mut config = command::engine_settings(args.engine.profile.as_deref())?.config;
    args.engine.apply_to(&mut config);

    let targets = target::resolve(&args.targets, !config.no_dns).await?;

    let redaction = command::redaction(&config);
    renderer.started(Phase::Discovery { targets: &targets }, redaction)?;

    targets.apply_to(&mut config);

    let (session, task) = discover(targets.into_ips(), &config).await?;

    command::drive(session, task, renderer).await
}
