// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Zond, as a command-line tool
//!
//! The front end to [`zond_engine`]. The engine finds hosts and ports. This
//! binary works out what a person typed, what to show them, and what to tell
//! the shell afterwards.
//!
//! The engine takes an already-resolved set of addresses, emits `tracing`
//! events without installing a subscriber, and holds no opinion about
//! terminals. Four modules here fill those gaps, and they are the four with any
//! judgement in them:
//!
//! - [`cli`] is the grammar, and the translation of it into a
//!   [`ZondConfig`](zond_engine::ZondConfig).
//! - [`target`] is what a target expression stands for. `lan` and `%en0` need
//!   this host's interface table, which the engine's parser will not read for
//!   itself.
//! - [`render`] is what a run looks like, and the only thing here that knows
//!   about columns and streams.
//! - [`exit`] is what the shell is told, written down rather than improvised.
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
mod descriptors;
mod diagnostics;
mod error;
mod exit;
mod export;
mod input;
mod nmap;
mod render;
mod settings;
mod target;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command};
use crate::command::Recording;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::style::{Palette, Style};
use crate::settings::EntryLimit;

fn main() -> ExitCode {
    // Before anything is written: a console that is going to be drawn on has to
    // be told to interpret what is drawn.
    render::terminal::prepare();

    // Before any scan, which sizes itself from the limit it finds, and before
    // the runtime, which takes descriptors of its own.
    descriptors::raise();

    // Nmap's output spellings first: `-oX f` cannot be expressed as an argument,
    // so it is turned into one before the parser sees it. See `nmap`.
    let arguments = match nmap::rewrite(std::env::args_os()) {
        Ok(arguments) => arguments,
        Err(error) => {
            error.report();
            return error.code().into();
        }
    };

    // Exits the process itself on a usage error: the one exit path that does
    // not come through the code below.
    let cli = Cli::parse_from(arguments);

    let outcome = runtime().and_then(|runtime| runtime.block_on(run(cli)));
    match outcome {
        Ok(outcome) => outcome.code(),
        Err(error) => {
            error.report();
            error.code()
        }
    }
    .into()
}

/// Builds the runtime every command runs on.
///
/// Built here rather than by an attribute on `main`, because a process started
/// with almost no descriptors cannot build one, and that has to reach the
/// shell as an error and a status rather than a panic. Tokio returns most of
/// the ways a build fails, but panics on one: the socket pair it opens to hear
/// signals. That panic is caught, with the default hook set aside so its
/// message does not reach the console, and stands for the same error.
fn runtime() -> Result<tokio::runtime::Runtime, Error> {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let built = std::panic::catch_unwind(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
    });
    std::panic::set_hook(hook);

    match built {
        Ok(Ok(runtime)) => Ok(runtime),
        Ok(Err(cause)) => Err(Error::Runtime(cause)),
        Err(_) => Err(Error::Runtime(std::io::Error::other(
            "no socket pair for signals",
        ))),
    }
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
    // What it did is said further down, once the output knows how to draw.
    let provisioned = settings::provision_all();

    let (settings, warnings) = settings::resolve()?;

    let presentation = cli.output.presentation(settings.presentation());
    // The two decisions about paint travel together from here: every renderer
    // and every command that draws wants both, and neither is useful alone.
    let palette = Palette::new(
        cli.output.colour(settings.colour()),
        settings.accent_colour().unwrap_or_default(),
    );

    // The subscriber was installed before any of this was known, so that nothing
    // emitted on the way here went unheard. This is the first moment it can be
    // told how to draw.
    diagnostics::paint(Style::commentary(presentation, palette));

    // The first line of a run that watches the network, and the reason the two
    // above are held back until here: a transcript that does not say which build
    // produced it, or when, is a transcript nobody can check a finding against a
    // year later.
    //
    // Only such a run. `read`, `diff`, `merge`, `journal` and `detections` look
    // things up — a stored scan carries its own provenance inside it, and a
    // catalogue is not a record of anything — so a build stamp there is a line
    // standing between somebody and the answer they asked for.
    if cli.command.watches_the_network() {
        tracing::info!(
            "zond-cli {} \u{b7} zond-engine {} \u{b7} {}",
            render::field::major_minor(env!("CARGO_PKG_VERSION")),
            render::field::major_minor(zond_engine::report::ENGINE_VERSION),
            render::field::moment(std::time::SystemTime::now())
        );
    }

    report_provisioning(provisioned);
    for warning in warnings {
        tracing::warn!("{warning}");
    }

    // The flag wins, then the file, then the built-in default, which is the
    // order every other setting layers in. Resolved once here because four
    // commands draw hosts and each of them asking separately is how one of them
    // ends up ignoring the file.
    //
    // Certificates come from the verbosity rather than a key, since `-v` is what
    // asks for the working behind anything.
    let showing = render::field::Showing {
        certificates: verbosity.explains(),
        reasons: cli.output.reason || settings.reason().unwrap_or(false),
        excerpts: cli.output.evidence || settings.evidence().unwrap_or(false),
        remedies: cli.output.remedy || settings.remedy().unwrap_or(false),
        // The flag, then the file, then the built-in floor, which is the order
        // every other setting layers in.
        risk: cli
            .output
            .risk
            .or_else(|| settings.risk())
            .unwrap_or_default(),
    };

    // `journal` reads what is already on disk rather than watching a run, so it
    // takes the presentation and not a `Renderer`.
    if let Command::Journal(args) = &cli.command {
        return command::journal::run(args, presentation, verbosity, palette);
    }

    let mut renderer = render::renderer(presentation, verbosity, palette, showing);

    // On unless the run or the settings file says otherwise: somebody wants to
    // continue or re-read a scan after it is over, not before. The limit rides
    // along because it is answered by the same file and only matters to a run
    // that records.
    let recording = |declined: bool| Recording {
        wanted: !declined && settings.journal().unwrap_or(true),
        limit: settings
            .journal_entry_limit()
            .unwrap_or(EntryLimit::DEFAULT),
    };

    match &cli.command {
        Command::Discover(args) => {
            command::discover::run(args, recording(args.no_journal), renderer.as_mut()).await
        }
        Command::Scan(args) => {
            command::scan::run(
                args,
                recording(args.no_journal),
                showing.reasons,
                renderer.as_mut(),
            )
            .await
        }
        Command::Listen(args) => {
            command::listen::run(args, recording(args.no_journal), renderer.as_mut()).await
        }
        Command::Diff(args) => command::diff::run(args, presentation, palette),
        Command::Merge(args) => {
            command::merge::run(args, presentation, verbosity, palette, showing)
        }
        Command::Read(args) => command::read::run(args, presentation, verbosity, palette, showing),
        Command::Detections(args) => match &args.action {
            // A test drives the network and draws a scan, so it is async and takes
            // the same rendering the scan path does, where the rest of `detections`
            // reads or compiles and stays synchronous.
            Some(cli::DetectionsAction::Test(test)) => {
                command::detections::test(test, presentation, verbosity, palette).await
            }
            _ => command::detections::run(args, presentation, verbosity, palette),
        },
        Command::Journal(_) => unreachable!("handled above"),
    }
}

/// Says which settings files this run created, and which it could not.
///
/// A file that has just appeared is mentioned once, because a program that
/// writes into somebody's home should say so. A file that could not be written
/// changes nothing about the run, so it waits for `-v`, where somebody
/// wondering where their file went can find it.
fn report_provisioning(provisioned: settings::Provisioning) {
    for path in provisioned.created {
        tracing::info!("created {}", path.display());
    }
    for problem in provisioned.problems {
        tracing::warn!(verbosity = 1, "could not create settings file: {problem}");
    }
}
