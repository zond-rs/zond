// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The engine's own voice
//!
//! The engine emits `tracing` events and installs no subscriber. This module is
//! the other half of that arrangement.
//!
//! Engine events carry two fields no off-the-shelf formatter knows about:
//!
//! - `verbosity` — how much detail an event is. It sits on the *event*, not in
//!   its level: everything here is logged at `INFO`, and `verbosity = 2` means
//!   "only if asked for". A level filter cannot express that, which is why this
//!   module carries its own [`Layer`].
//! - `status` — `info`, `success`, `warn`, `error`, `incoming`, `outgoing`.
//!   Unread here; it is what a coloured renderer will select on.
//!
//! Output is plain lines on standard error with `warning:` and `error:`
//! prefixes, following `rustc` and `cargo`. No timestamps, no target, no level.

use std::fmt;
use std::io::Write;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::Registry;

/// How much a run says about itself.
///
/// Copied around rather than referenced: it is two bytes, and both the
/// subscriber and the renderer need it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Verbosity {
    detail: u8,
    quiet: bool,
}

impl Verbosity {
    /// From the count of `-v` flags and whether `-q` was given.
    ///
    /// The two cannot both be set — the argument parser refuses it — so no rule
    /// for reconciling them is needed or invented here.
    #[must_use]
    pub(crate) fn new(detail: u8, quiet: bool) -> Self {
        Self { detail, quiet }
    }

    /// Whether the run was asked to keep quiet.
    #[must_use]
    pub(crate) fn is_quiet(self) -> bool {
        self.quiet
    }

    /// Whether a renderer should narrate — headers, live progress, the summary.
    ///
    /// Only narration is suppressed by `-q`. The hosts a scan found are the
    /// answer to the question that was asked, and go to standard output whatever
    /// this says.
    #[must_use]
    pub(crate) fn narrates(self) -> bool {
        !self.quiet
    }

    /// Whether an event at `level` carrying `verbosity` should be shown.
    ///
    /// An error is always shown. Silence about a failure is the one thing a
    /// quiet flag must not buy: it turns a scan that went wrong into a scan that
    /// found nothing, and those look identical afterwards.
    fn shows(self, verbosity: u8, level: Level) -> bool {
        if level == Level::ERROR {
            return true;
        }
        !self.quiet && verbosity <= self.detail
    }
}

/// Installs the subscriber that renders the engine's events.
///
/// Call once, before anything that might emit one. A second call is ignored
/// rather than treated as an error: `tracing` allows exactly one global
/// subscriber per process, and a test that runs two commands should not fail
/// over which of them got there first.
pub(crate) fn install(verbosity: Verbosity) {
    let subscriber = Registry::default().with(ConsoleLayer { verbosity });
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Writes the engine's events to standard error as plain lines.
struct ConsoleLayer {
    verbosity: Verbosity,
}

impl<S: Subscriber> Layer<S> for ConsoleLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // Several of the engine's dependencies emit `tracing` too, at whoever
        // asked them to — which is not the person running a scan.
        if !event.metadata().target().starts_with("zond") {
            return;
        }

        let mut fields = EngineEvent::default();
        event.record(&mut fields);

        if !self
            .verbosity
            .shows(fields.verbosity, *event.metadata().level())
        {
            return;
        }

        let Some(message) = fields.message else {
            return;
        };

        let prefix = match *event.metadata().level() {
            Level::ERROR => "error: ",
            Level::WARN => "warning: ",
            _ => "",
        };

        // A scan should not end because the terminal went away.
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{prefix}{message}");
    }

    /// Nothing below `INFO` is ever rendered, so nothing below it needs to be
    /// built. This is what stops the engine paying to format events that would
    /// be dropped a microsecond later.
    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(if self.verbosity.is_quiet() {
            LevelFilter::ERROR
        } else {
            LevelFilter::INFO
        })
    }
}

/// The two fields of an engine event this renderer reads.
#[derive(Default)]
struct EngineEvent {
    message: Option<String>,
    verbosity: u8,
}

impl Visit for EngineEvent {
    /// The message arrives here: a formatted `format_args!` is recorded as a
    /// `Debug`, and `Debug` for it is the formatted text without quotes.
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "verbosity" {
            self.verbosity = u8::try_from(value).unwrap_or(u8::MAX);
        }
    }

    /// The same field again. An integer literal in a `tracing` macro is recorded
    /// signed unless it was written with a type, so `verbosity = 2` arrives here
    /// and `verbosity = 2u64` arrives above; a reader that handles one and not
    /// the other works until somebody writes the literal differently.
    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "verbosity" {
            self.verbosity = u8::try_from(value).unwrap_or(u8::MAX);
        }
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    /// A default run shows headlines only, and every one of these is `INFO` —
    /// which is why the layer reads the field rather than filtering on level.
    #[test]
    fn a_default_run_shows_headlines_only() {
        let default = Verbosity::default();
        assert!(default.shows(0, Level::INFO));
        assert!(!default.shows(1, Level::INFO));
        assert!(!default.shows(2, Level::INFO));
    }

    #[test]
    fn each_v_uncovers_one_more_layer_of_detail() {
        assert!(Verbosity::new(1, false).shows(1, Level::INFO));
        assert!(!Verbosity::new(1, false).shows(2, Level::INFO));
        assert!(Verbosity::new(2, false).shows(2, Level::INFO));
    }

    /// Quiet buys silence about progress, never about failure: a scan that could
    /// not run and one that found nothing look identical afterwards.
    #[test]
    fn quiet_silences_everything_except_errors() {
        let quiet = Verbosity::new(0, true);
        assert!(!quiet.shows(0, Level::INFO));
        assert!(!quiet.shows(0, Level::WARN));
        assert!(quiet.shows(0, Level::ERROR));
        assert!(quiet.shows(2, Level::ERROR));
    }

    #[test]
    fn quiet_stops_the_renderer_narrating() {
        assert!(Verbosity::default().narrates());
        assert!(!Verbosity::new(0, true).narrates());
    }
}
