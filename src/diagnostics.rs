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
//! - `verbosity` says how much detail an event is. It sits on the *event*, not
//!   in its level: everything here is logged at `INFO`, and `verbosity = 2`
//!   means "only if asked for". A level filter cannot express that, which is why
//!   this module carries its own [`Layer`].
//! - `status` is one of `info`, `success`, `warn`, `error`, `incoming` and
//!   `outgoing`. It is what the glyph opening each line is chosen from; see
//!   [`Mark`].
//!
//! Every line opens with one column saying what kind of line it is: `·` for
//! ordinary commentary, `»` and `«` for a probe and its answer, `━` and `×` for
//! the two that want reading. This crate's own narration answers to the same
//! six, so one stream does not carry two vocabularies.
//!
//! The glyph replaced the `warning:` and `error:` words this module used to
//! follow `rustc` and `cargo` in printing. It says the same thing in one column
//! instead of eight, and it says it in a *shape*, so a run piped to a file keeps
//! the distinction that a run piped to a terminal gets from the colour as well.
//!
//! ## Colour arrives late, on purpose
//!
//! [`install`] runs before the settings are read, because a subscriber installed
//! after the fact misses everything before it. At that point nobody knows
//! whether this run wants colour, so the layer starts unpainted and [`paint`]
//! hands it a [`Style`] once the palette is resolved. The handful of events that
//! can be emitted in between stay unpainted, which is the right answer rather
//! than a shortcoming: painting them would be guessing at a preference the run
//! has not yet been asked for.

use std::fmt;
use std::io::Write;

use std::sync::OnceLock;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::Registry;

use crate::render::style::{Mark, Style};

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
    /// The two cannot both be set, because the argument parser refuses it, so no
    /// rule for reconciling them is needed or invented here.
    #[must_use]
    pub(crate) fn new(detail: u8, quiet: bool) -> Self {
        Self { detail, quiet }
    }

    /// Whether the run was asked to keep quiet.
    #[must_use]
    pub(crate) fn is_quiet(self) -> bool {
        self.quiet
    }

    /// Whether a renderer should narrate: headers, live progress, the summary.
    ///
    /// Only narration is suppressed by `-q`. The hosts a scan found are the
    /// answer to the question that was asked, and go to standard output whatever
    /// this says.
    #[must_use]
    pub(crate) fn narrates(self) -> bool {
        !self.quiet
    }

    /// Whether a record should carry the working behind it.
    ///
    /// The distinction is between a *finding* and what it was read off. "Linux
    /// 6.x" is the finding and is always shown; the stack shape and the series
    /// readings behind it are the working, and a person only wants those when
    /// they are checking the answer rather than using it. That is what asking
    /// for detail means.
    #[must_use]
    pub(crate) fn explains(self) -> bool {
        !self.quiet && self.detail >= 1
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

/// How this layer draws, once anybody knows.
///
/// A `OnceLock` rather than an argument to [`install`], because the two are
/// answered at different moments: the subscriber has to exist before the first
/// event and the palette is not resolved until the settings have been read.
static STYLE: OnceLock<Style> = OnceLock::new();

/// Tells the layer how standard error may be drawn on.
///
/// Called once, after the settings are read. A second call is ignored rather
/// than refused: there is only one answer per run, and a caller that asks twice
/// has not made the output wrong.
pub(crate) fn paint(style: Style) {
    let _ = STYLE.set(style);
}

/// How to draw, or plainly where the question has not been answered yet.
fn style() -> Style {
    STYLE.get().copied().unwrap_or_else(Style::bare)
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
        // Several of the engine's dependencies emit `tracing` too, addressed to
        // whoever asked them to, who is not the person running a scan.
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

        // The event's own word for itself where it has one, and its level
        // otherwise: an event from a dependency of the engine carries no
        // `status`, and a line with no glyph at all would be the one line on the
        // stream that did not line up with the others.
        let mark = fields.status.as_deref().and_then(Mark::named).unwrap_or(
            match *event.metadata().level() {
                Level::ERROR => Mark::Error,
                Level::WARN => Mark::Warning,
                _ => Mark::Info,
            },
        );

        let style = style();

        // A running scan holds a line at the bottom of this stream. Take it
        // back first, and let the next tick put it below this one.
        crate::render::progress::clear();

        // A scan should not end because the terminal went away.
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{}", style.line(mark, &message));
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
    /// What kind of thing the event is, as the engine named it.
    status: Option<String>,
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
        if field.name() == "status" {
            self.status = Some(value.to_owned());
        }
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

    /// A default run shows headlines only, and every one of these is `INFO`.
    /// That is why the layer reads the field rather than filtering on level.
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
