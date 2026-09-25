// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # `zond listen`
//!
//! What a link already carries, read without sending anything.
//!
//! The third phase, and the only one that puts no packet on the wire. It is for
//! the networks the other two may not touch — segments where probing is
//! forbidden by policy or is a bad idea on the equipment — and for the findings
//! no probe obtains: which switch port this machine is on, which VLANs the link
//! carries, what a device says about itself while asking for an address.
//!
//! ## It runs until it is stopped
//!
//! `discover` and `scan` finish: they enumerate something and reach the end of
//! it. A watch has nothing to finish. It ends on `Ctrl-C`, on `q`, or after
//! `--for`, and the report describes however long it ran.

use std::time::Duration;

use zond_engine::journal::manifest::Plan;
use zond_engine::journal::store::Journal;
use zond_engine::model::ip::scoped::Zone;
use zond_engine::{ListenScope, listen, listen_with_journal, resolve};

use crate::cli::ListenArgs;
use crate::command::{self, Recording, Stopping};
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::{Phase, Renderer};

/// Runs a watch.
pub(crate) async fn run(
    args: &ListenArgs,
    recording: Recording,
    renderer: &mut dyn Renderer,
) -> Result<Outcome, Error> {
    // Before anything is opened: a misspelt extension is a mistake made in the
    // first second of a run that may last for days, and the end of one is the
    // worst moment to be told.
    let destinations = args.export.destinations()?;

    let mut config = command::engine_settings(args.engine.profile.as_deref())?.config;
    args.engine.apply_to(&mut config);

    let span = args.r#for;

    // A resume needs no links: they come from the record, which is what was
    // being watched rather than what somebody types the second time.
    let (links, journal) = match args.resume.as_deref() {
        Some(id) => continued(id, args.take_over)?,
        None => started(args, recording)?,
    };

    let mut scope = ListenScope::on(links.clone());
    if args.everything {
        scope = scope.recording_everything();
    }
    if let Some(span) = span {
        scope = scope.for_at_most(span);
    }

    let redaction = command::redaction(&config);
    renderer.started(
        Phase::Listen {
            links: &links,
            span,
        },
        redaction,
    )?;

    // Taken before the journal is handed over, and only for a record this run
    // claimed: a resumed one was announced as it was reopened.
    let fresh = journal
        .as_ref()
        .filter(|_| args.resume.is_none())
        .map(|journal| journal.manifest().id.clone());

    let (session, task) = match journal {
        Some(journal) => listen_with_journal(scope, &config, journal).await?,
        None => listen(scope, &config).await?,
    };

    if let Some(id) = fresh {
        command::announce(&id, recording.limit);
    }

    // **The one phase where being stopped is how it finishes.** A watch with no
    // `--for` was asked to run until somebody stopped it, so `Ctrl-C` and `q`
    // are its ending rather than an interruption of it — and reporting them as
    // an interruption would leave `zond listen en0` with no way to exit `0`,
    // which is the whole of what a sensor's wrapper script tests.
    //
    // With `--for`, it is back to being a job with an end of its own: asked for
    // ten minutes and stopped at three really was cut short, and the engine
    // already keeps the deadline from raising the same signal so the two cannot
    // be confused. See `Stopping`.
    let stopping = if span.is_some() {
        Stopping::CutsShort
    } else {
        Stopping::Completes
    };

    command::drive(
        session,
        task,
        &destinations,
        redaction,
        stopping,
        None,
        renderer,
    )
    .await
}

/// A watch of what the command line asked for.
fn started(args: &ListenArgs, recording: Recording) -> Result<(Vec<Zone>, Option<Journal>), Error> {
    let links = resolve::for_listening(&args.links)?;

    let journal = recording
        .wanted
        .then(|| command::record(&Plan::listen(links.clone()), summarise(&links)))
        .flatten();

    Ok((links, journal))
}

/// A sitting added to a watch already on record.
///
/// Nothing is skipped, because a watch settles nothing. What reopening buys is
/// that the earlier sittings' findings are restored before this one starts, so
/// the report describes the whole watch rather than the last few minutes of it.
fn continued(id: &str, take_over: bool) -> Result<(Vec<Zone>, Option<Journal>), Error> {
    let resumed = command::reopen(id, "links", take_over)?;

    let Some(links) = resumed.plan.links().map(<[Zone]>::to_vec) else {
        return Err(Error::WrongPhase {
            id: resumed.id,
            held: "a scan",
            remedy: "zond discover --resume or zond scan --resume",
        });
    };

    // The recorded links are names without the numbers this kernel gave them —
    // an index read from a file was true of some other boot. Resolved against
    // this machine so a link-local address found tonight is usable.
    let named: Vec<String> = links.iter().map(|link| link.name().to_owned()).collect();
    let links = resolve::for_listening(&named)?;

    Ok((links, Some(resumed.journal)))
}

/// How a watch is described in a listing.
fn summarise(links: &[Zone]) -> String {
    match links {
        [] => String::from("nothing"),
        [one] => one.name().to_owned(),
        [first, rest @ ..] => format!("{} and {} more", first.name(), rest.len()),
    }
}

/// The units a span is spoken in, largest first.
///
/// The same four the command line takes, in the same order a person writes them.
const SPOKEN_UNITS: [(u64, &str); 4] = [(86_400, "d"), (3_600, "h"), (60, "m"), (1, "s")];

/// How long a watch has been asked to run, for the line that announces it.
///
/// **The span as it was asked for, not rounded to whichever unit is largest.**
/// The line this appears in is what a person checks before walking away from a
/// run that may last days, and dividing by the largest unit reported `--for 90m`
/// as `for 1h` — the one reading that matters, said wrong, in the one place it
/// is checked.
///
/// So a remainder is carried into the next unit down and the trailing zeroes are
/// left off: `4h`, `1h30m`, `2d`, `2d12h`. Two parts at most, because a third is
/// precision nobody asked for on a span somebody typed.
pub(crate) fn spoken_span(span: Option<Duration>) -> String {
    let Some(span) = span else {
        return String::from("until stopped");
    };

    let mut left = span.as_secs();
    let mut parts: Vec<String> = Vec::new();

    for (seconds, suffix) in SPOKEN_UNITS {
        if parts.len() == 2 {
            break;
        }
        let count = left / seconds;
        // Skipped while nothing has been said yet, so a short span does not
        // open with the units it has none of. Once something has, a zero in the
        // middle is skipped too: 1d 0h 5m is `1d` and not `1d0h`.
        if count > 0 {
            parts.push(format!("{count}{suffix}"));
            left -= count * seconds;
        }
    }

    // Only reachable for a zero span, which the parser refuses. Answered anyway
    // rather than returning `for `, since this formats an `Option` somebody else
    // filled in.
    if parts.is_empty() {
        return String::from("for no time at all");
    }

    format!("for {}", parts.concat())
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

    /// The span as it was asked for, not rounded away to whichever unit is
    /// largest.
    ///
    /// This line is what a person reads before walking away from a run that may
    /// last days, and dividing by the largest unit reported `--for 90m` as
    /// `for 1h`. Half an hour lost, in the one place the number is checked, on
    /// the phase where the number is the only thing bounding the run.
    #[test]
    fn a_span_is_announced_as_the_span_that_was_asked_for() {
        let spoken = |seconds| spoken_span(Some(Duration::from_secs(seconds)));

        assert_eq!(
            spoken(5_400),
            "for 1h30m",
            "the reading that used to be lost"
        );
        assert_eq!(spoken(90), "for 1m30s");
        assert_eq!(spoken(216_000), "for 2d12h");
    }

    /// A unit with nothing in it is left out, wherever it falls.
    ///
    /// Leading, so a short watch does not open with the units it has none of;
    /// and in the middle, so a day and five minutes is `1d5m` rather than
    /// `1d0h`. Two parts at most, because a third is precision nobody asked for
    /// on a span somebody typed.
    #[test]
    fn only_the_units_the_span_actually_has_are_spoken() {
        let spoken = |seconds| spoken_span(Some(Duration::from_secs(seconds)));

        assert_eq!(spoken(45), "for 45s", "no leading zeroes");
        assert_eq!(spoken(14_400), "for 4h", "and no trailing ones");
        assert_eq!(spoken(86_700), "for 1d5m", "nor one in the middle");
        assert_eq!(
            spoken(93_784),
            "for 1d2h",
            "two parts at most: the minutes and seconds are dropped"
        );
    }

    /// A watch with no span runs until somebody stops it, which is the default
    /// and the thing a sensor wants.
    #[test]
    fn a_watch_with_no_span_says_so() {
        assert_eq!(spoken_span(None), "until stopped");
    }

    /// How a watch is named in a listing, which is the only way to tell two of
    /// them apart in `zond journal`.
    #[test]
    fn a_watch_is_summarised_by_the_links_it_reads() {
        assert_eq!(summarise(&[]), "nothing");
        assert_eq!(summarise(&[Zone::unresolved("en0")]), "en0");
        assert_eq!(
            summarise(&[
                Zone::unresolved("en0"),
                Zone::unresolved("en1"),
                Zone::unresolved("en2"),
            ]),
            "en0 and 2 more"
        );
    }
}
