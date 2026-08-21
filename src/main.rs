// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Zond, as a command-line tool
//!
//! The front end to [`zond_engine`]. The engine finds hosts and ports; this
//! binary decides what a person typed, what to show them, and what to tell the
//! shell afterwards.
//!
//! The engine takes an already-resolved set of addresses, emits `tracing` events
//! and installs no subscriber, and holds no opinion about terminals. The four
//! modules with any judgement in them are what follows from that:
//!
//! - [`cli`] — the grammar, and how it becomes a
//!   [`ZondConfig`](zond_engine::ZondConfig).
//! - [`target`] — what a target expression stands for. `lan` and `%en0` need the
//!   host's interface table, which the engine's parser will not read for itself.
//! - [`render`] — what a run looks like. The only thing here that knows about
//!   columns and streams.
//! - [`exit`] — what the shell is told, written down rather than improvised.
//!
//! [`command`] drives those against the engine, one module per subcommand.
//! [`diagnostics`] is the subscriber the engine's events would otherwise fall
//! into the void without. [`input`] is how a person stops a running scan.
//!
//! **Standard output carries records. Standard error carries narration.** So
//! `zond discover lan > hosts.txt` leaves a file with nothing in it but hosts,
//! and the person who ran it still watches the sweep happen.

mod cli;
mod command;
mod diagnostics;
mod error;
mod exit;
mod input;
mod render;
mod settings;
mod target;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::error::Error;
use crate::exit::Outcome;

#[tokio::main]
async fn main() -> ExitCode {
    // Exits the process itself on a usage error: the one exit path that does
    // not come through the code below.
    let cli = Cli::parse();

    match run(cli).await {
        Ok(outcome) => outcome.code(),
        Err(error) => {
            error.report();
            error.code()
        }
    }
    .into()
}

/// Runs a parsed command line to completion.
///
/// The one place the pieces are wired together: diagnostics are installed, a
/// renderer is chosen, and the subcommand is handed both.
async fn run(cli: Cli) -> Result<Outcome, Error> {
    let verbosity = cli.output.verbosity();

    // Before anything that might emit an event: a subscriber installed after
    // the first one silently loses it.
    diagnostics::install(verbosity);

    // Before the settings are read, so a first run reads what it just created.
    provision();

    let (settings, warnings) = settings::resolve()?;
    for warning in warnings {
        tracing::warn!("{warning}");
    }

    let presentation = cli.output.presentation(settings.presentation());
    let mut renderer = render::renderer(presentation, verbosity)?;

    match &cli.command {
        Command::Discover(args) => command::discover::run(args, renderer.as_mut()).await,
        Command::Scan(args) => command::scan::run(args, renderer.as_mut()).await,
    }
}

/// Creates the two settings files if this is the first run that can.
///
/// Fails at nothing: a home that cannot be written to means built-in defaults,
/// not a refusal to scan. A file that has just appeared is mentioned once,
/// because a program that writes into somebody's home should say so.
fn provision() {
    let (created, problems) = settings::provision_all();

    for path in created {
        tracing::info!("created {}", path.display());
    }
    for problem in problems {
        // At `-v`: this changes nothing about the run that follows, but
        // somebody wondering where their file went should be able to ask.
        tracing::warn!(verbosity = 1, "could not create settings file: {problem}");
    }
}
