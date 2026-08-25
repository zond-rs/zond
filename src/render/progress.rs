// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The line that says the scan is still running
//!
//! ```text
//! ⠹  12 hosts found so far
//! ```
//!
//! One line, held at the bottom of standard error and rewritten in place while a
//! scan runs. A sweep of a `/16` can go a minute without a single reply, and a
//! program that says nothing for a minute is a program somebody reaches for
//! `^C` on.
//!
//! ## It answers two different questions, in turn
//!
//! A tip, then the count, then a tip, every [`WINDOW`], from the first frame.
//!
//! **Which tip is decided per run, not per turn.** Advancing through the list as
//! a run goes on sounds right and is useless: a sweep of a `/24` is over inside
//! two turns, so the second tip would be seen once in a while, the third almost
//! never, and the sixth by nobody. Each run opens somewhere else in the list and
//! walks on from there, so the one tip a short scan shows is a different one
//! each time and a long scan still works through them all.
//!
//! There is no settling period, because there is nothing to settle into: a sweep
//! of a `/24` is over in a couple of seconds, and a device that waits ten before
//! it has anything to say would spend its whole life on a run that had already
//! finished. Two seconds a turn means a scan that takes six shows three things
//! rather than one.
//!
//! Advice comes first for the same reason. At the top of a run the count is
//! zero, the least interesting number it will ever hold, and the spinner has
//! already said the only thing the count would have: something is happening.
//!
//! ## The cursor is put away while it runs
//!
//! A terminal parks its cursor after the last thing written, which on a line
//! that is being rewritten eight times a second is a block sitting at the end of
//! the sentence, blinking. It is hidden for as long as the line is live and put
//! back by [`stop`], which every path out of a scan goes through, the
//! interrupted one included.
//!
//! ## Drawn only where there is something to draw on
//!
//! Nothing here runs unless standard error is a terminal. Redirected, the line
//! would be a file full of carriage returns and erase sequences, and the whole
//! device depends on being able to take back what it wrote.
//!
//! `fancy` alone starts one. `minimal` promises abbreviated tags and `pipe`
//! promises a stable interface; a line that rewrites itself is neither.
//!
//! ## Everything else on this stream erases it first
//!
//! The engine's diagnostics and a run's narration write to the same file
//! descriptor, so they call [`clear`] before their own line and let the next
//! tick put this one back. That is why the state lives in a static: a `tracing`
//! layer has no path to be handed anything.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::render::style::Style;

/// How often the line is redrawn.
///
/// Eight frames a second: fast enough to read as motion, slow enough that a
/// terminal being written to over ssh is not spending its bandwidth on it.
const TICK: Duration = Duration::from_millis(125);

/// How long each thing the line has to say stays on screen.
///
/// Two seconds: long enough to read a short sentence, short enough that a run
/// which is over in five has still shown more than one of them.
const WINDOW: Duration = Duration::from_secs(2);

/// The turning thing on the left.
///
/// Braille, because it is the one animation that turns in a single column
/// without the line appearing to change width. A spinner made of `/-\|` jitters
/// as the glyphs differ in weight, and one made of blocks is a strobe.
const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// What a run is told while it waits.
///
/// Short enough that the whole line fits a narrow terminal without wrapping. The
/// erase sequence takes back one line, so a line that wrapped would leave its
/// first half behind.
const TIPS: [&str; 6] = [
    "--assume-up scans a host that answers no liveness probe",
    "-n keeps the run from generating any DNS traffic",
    "zond journal lists what is on record",
    "--resume continues a scan that stopped part way",
    "zond diff compares two records",
    "accent_colour in cli.toml sets the one hue you choose",
];

/// What the line counts, which is whatever the run is for.
///
/// A sweep is asking who is there, so it counts hosts. A port scan already knows
/// who is there, having been told, so counting them again would be counting its
/// own input. What it is asking is what is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Counting {
    /// A sweep: every host is news.
    Hosts,
    /// A port scan: open ports, and the hosts they were found on.
    ///
    /// Both, because either alone is a figure somebody has to ask a second
    /// question about: nine open ports across one host and across nine are
    /// different findings, and the scan already knows which.
    Ports,
}

/// The line's state while it is running.
struct Live {
    /// How many hosts have arrived.
    hosts: usize,
    /// How many open ports have been found on them.
    open: usize,
    /// When the run started, which is what decides between counting and
    /// advising.
    since: Instant,
    /// What is being counted.
    counting: Counting,
    /// How standard error may be drawn on.
    style: Style,
    /// Which frame the spinner is on.
    frame: usize,
    /// Which tip this run opens with.
    ///
    /// See the module note: a short run only ever shows its first, so the list
    /// has to be entered at a different place each time rather than walked from
    /// the top.
    tip: usize,
    /// Whether there is a line on screen to take back.
    shown: bool,
}

/// The one line, or none.
static LIVE: Mutex<Option<Live>> = Mutex::new(None);

/// Whether the drawing thread should keep going.
///
/// Separate from [`LIVE`] so the thread can be told to stop without waiting for
/// whoever is holding the lock.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Takes the lock, or gives up.
///
/// A poisoned lock means a thread panicked mid-draw. The scan is not the
/// casualty of that and must not become one: the line simply stops moving.
fn held() -> Option<MutexGuard<'static, Option<Live>>> {
    LIVE.lock().ok()
}

/// Starts the line, if there is a terminal to put it on.
///
/// Silently does nothing otherwise, which is what lets the caller start one
/// unconditionally.
pub(crate) fn start(counting: Counting, style: Style) {
    if !std::io::stderr().is_terminal() || RUNNING.load(Ordering::Acquire) {
        return;
    }

    let Some(mut live) = held() else {
        return;
    };

    *live = Some(Live {
        hosts: 0,
        open: 0,
        since: Instant::now(),
        counting,
        style,
        frame: 0,
        tip: opening_tip(),
        shown: false,
    });
    drop(live);

    // Nothing is written on this line that anybody is about to type into, and a
    // cursor blinking at the end of a sentence that rewrites itself is the one
    // part of this a reader cannot ignore.
    hide_cursor();

    RUNNING.store(true, Ordering::Release);

    // A plain thread rather than a task: this does nothing but sleep and write,
    // and putting it on the runtime that is driving the scan makes it something
    // the scan can be delayed behind.
    std::thread::spawn(|| {
        while RUNNING.load(Ordering::Acquire) {
            std::thread::sleep(TICK);
            draw();
        }
    });
}

/// What the run has turned up so far.
///
/// A running total rather than an increment, because a port scan announces the
/// same host again every time one of its ports settles. The caller is the one
/// that knows which announcements are the same machine, so the caller keeps the
/// tally and this holds the latest of it.
pub(crate) fn seen(hosts: usize, open: usize) {
    if let Some(mut live) = held()
        && let Some(live) = live.as_mut()
    {
        live.hosts = hosts;
        live.open = open;
    }
}

/// Takes the line back, so something permanent can be written where it was.
///
/// The next tick puts it back. Cheap enough to call before every line on this
/// stream, and a no-op when nothing is running, which is most of the time and
/// all of the time in the two modes that never start one.
pub(crate) fn clear() {
    let Some(mut live) = held() else {
        return;
    };
    let Some(live) = live.as_mut() else {
        return;
    };

    if live.shown {
        erase();
        live.shown = false;
    }
}

/// Stops the line and takes it back for good.
pub(crate) fn stop() {
    RUNNING.store(false, Ordering::Release);

    let Some(mut live) = held() else {
        return;
    };

    if live.as_ref().is_some_and(|live| live.shown) {
        erase();
    }

    if live.is_some() {
        show_cursor();
    }

    *live = None;
}

/// Puts the cursor away.
fn hide_cursor() {
    let mut stderr = std::io::stderr().lock();
    let _ = write!(stderr, "\u{1b}[?25l");
    let _ = stderr.flush();
}

/// Gives it back.
///
/// Every way out of a scan reaches [`stop`], so this runs whether the run
/// finished or was interrupted. A process killed outright leaves the cursor
/// hidden, which is true of every program that has ever hidden one and is what
/// `reset` is for.
fn show_cursor() {
    let mut stderr = std::io::stderr().lock();
    let _ = write!(stderr, "\u{1b}[?25h");
    let _ = stderr.flush();
}

/// Where in the list this run starts.
///
/// From the clock rather than a random number generator: this picks a tip, and a
/// dependency earning its place has to do more than that. The nanoseconds inside
/// the current second are as unpredictable as anything a scan needs here, and
/// two runs a second apart do not collide.
fn opening_tip() -> usize {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());

    nanos as usize % TIPS.len()
}

/// Erases whatever is on the current line and returns to its start.
fn erase() {
    let mut stderr = std::io::stderr().lock();
    let _ = write!(stderr, "\r\u{1b}[2K");
    let _ = stderr.flush();
}

/// Rewrites the line where it stands.
fn draw() {
    let Some(mut live) = held() else {
        return;
    };
    let Some(live) = live.as_mut() else {
        return;
    };

    live.frame = (live.frame + 1) % FRAMES.len();
    let text = line(live);

    let mut stderr = std::io::stderr().lock();
    let _ = write!(stderr, "\r\u{1b}[2K{text}");
    let _ = stderr.flush();
    live.shown = true;
}

/// What the line says right now.
///
/// Two spaces after the spinner rather than one, so the text sits where a
/// permanent line's text sits: those open with a glyph and one space, and a
/// spinner that shifted the column every time it turned would be the one moving
/// thing on the screen that moved sideways.
fn line(live: &Live) -> String {
    let style = live.style;
    let spinner = style.accent(FRAMES[live.frame]);

    format!("{spinner}  {}", said(live))
}

/// The count, or a tip, depending on how long this has been going.
fn said(live: &Live) -> String {
    let style = live.style;

    // Alternating from the first frame, advice on the even turns. Measured in
    // milliseconds rather than whole seconds so the switch lands where the
    // window ends rather than at the next tick of the clock.
    let turn = live
        .since
        .elapsed()
        .as_millis()
        .saturating_div(WINDOW.as_millis().max(1));

    if turn % 2 == 1 {
        return counted(live);
    }

    // A run long enough to overflow this has been going rather longer than the
    // universe, so the wrap is theatre. A silent truncation on a thirty-two bit
    // target is the kind of theatre that becomes a bug report.
    let along = usize::try_from(turn / 2).unwrap_or(0);
    let tip = TIPS[(live.tip + along) % TIPS.len()];
    format!("{} {}", style.faint("tip"), style.plain(tip))
}

/// The count, with the figures carrying the weight and the words around them
/// not.
fn counted(live: &Live) -> String {
    let style = live.style;

    match live.counting {
        Counting::Hosts => tally(style, live.hosts, "host found so far", "hosts found so far"),
        Counting::Ports => format!(
            "{} {} {}",
            tally(style, live.open, "open port", "open ports"),
            style.faint("on"),
            tally(style, live.hosts, "host", "hosts")
        ),
    }
}

/// A figure and the word for it.
fn tally(style: Style, count: usize, singular: &str, plural: &str) -> String {
    let word = if count == 1 { singular } else { plural };

    format!("{} {}", style.strong(&count.to_string()), style.faint(word))
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

    fn live(hosts: usize, counting: Counting, elapsed: Duration) -> Live {
        Live {
            hosts,
            open: 0,
            since: Instant::now()
                .checked_sub(elapsed)
                .expect("the machine has been up longer than the test pretends"),
            counting,
            style: Style::bare(),
            frame: 0,
            tip: 0,
            shown: false,
        }
    }

    /// The same, opened at a chosen place in the list.
    fn live_from(tip: usize, elapsed: Duration) -> Live {
        Live {
            tip,
            ..live(0, Counting::Hosts, elapsed)
        }
    }

    /// The line opens with advice, because at the top of a run the count is zero
    /// and the spinner has already said the only thing that number would.
    #[test]
    fn a_run_opens_with_advice() {
        let opening = said(&live(0, Counting::Hosts, Duration::from_millis(1)));

        assert!(opening.starts_with("tip "), "{opening}");
        assert!(opening.contains(TIPS[0]), "{opening}");
    }

    /// One is one. A count that says `1 hosts` is a count nobody wrote on
    /// purpose.
    #[test]
    fn one_of_a_thing_is_said_in_the_singular() {
        let bare = Style::bare();

        assert_eq!(tally(bare, 1, "host", "hosts"), "1 host");
        assert_eq!(tally(bare, 0, "host", "hosts"), "0 hosts");
        assert_eq!(tally(bare, 2, "host", "hosts"), "2 hosts");
    }

    /// Advice and the count take turns from the first frame. A run that lasts
    /// six seconds, which is most of them, shows three things rather than one.
    #[test]
    fn advice_and_the_count_take_turns_from_the_start() {
        let at = |millis| said(&live(7, Counting::Hosts, Duration::from_millis(millis)));

        assert!(at(500).starts_with("tip "), "{}", at(500));
        assert_eq!(at(2_500), "7 hosts found so far", "the count never came");
        assert!(at(4_500).starts_with("tip "), "advice came only once");
        assert_eq!(at(6_500), "7 hosts found so far", "the count was retired");

        // The turn is two seconds, not one and not three.
        assert!(at(1_900).starts_with("tip "), "the turn ended early");
        assert_eq!(at(2_100), "7 hosts found so far", "the turn ran long");
    }

    /// A sweep asks who is there. A port scan was told who is there, so what it
    /// counts is what is open, and across how many machines, since nine ports on
    /// one host and nine on nine are different findings.
    #[test]
    fn each_run_counts_what_it_is_for() {
        let mid = Duration::from_millis(2_500);

        assert_eq!(
            said(&live(12, Counting::Hosts, mid)),
            "12 hosts found so far"
        );

        let mut scanning = live(2, Counting::Ports, mid);
        scanning.open = 9;
        assert_eq!(said(&scanning), "9 open ports on 2 hosts");

        let mut alone = live(1, Counting::Ports, mid);
        alone.open = 1;
        assert_eq!(said(&alone), "1 open port on 1 host");

        let nothing = live(3, Counting::Ports, mid);
        assert_eq!(said(&nothing), "0 open ports on 3 hosts");
    }

    /// A long run works through the whole list from wherever it started.
    #[test]
    fn a_long_run_works_through_the_whole_list() {
        for opening in 0..TIPS.len() {
            let mut seen = Vec::new();
            for turn in 0..TIPS.len() {
                // Advice falls on the even turns; half a window in is
                // comfortably inside one.
                let step = u32::try_from(turn).expect("a handful of tips");
                seen.push(said(&live_from(opening, WINDOW * (2 * step) + WINDOW / 2)));
            }

            for tip in TIPS {
                assert!(
                    seen.iter().any(|said| said.contains(tip)),
                    "opening at {opening}, '{tip}' is never offered"
                );
            }
        }
    }

    /// The one tip a short run shows is a different one each time.
    ///
    /// This is the whole reason the list is entered at a chosen place: almost
    /// every scan is over inside two turns, so a run that always started at the
    /// top would show the first tip and retire the other five.
    #[test]
    fn a_short_run_shows_a_different_tip_each_time() {
        let opening = Duration::from_millis(500);

        let first: Vec<String> = (0..TIPS.len())
            .map(|tip| said(&live_from(tip, opening)))
            .collect();

        for tip in TIPS {
            assert!(
                first.iter().any(|said| said.contains(tip)),
                "'{tip}' can never be the one a short run shows"
            );
        }
    }

    /// And the place it starts from is not the same every run.
    #[test]
    fn the_opening_tip_moves_between_runs() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(opening_tip());
            std::thread::sleep(Duration::from_micros(50));
        }

        assert!(
            seen.len() > 1,
            "every run would open on the same tip: {seen:?}"
        );
        assert!(seen.iter().all(|tip| *tip < TIPS.len()));
    }

    /// The whole line has to fit a narrow terminal. The erase sequence takes
    /// back one line, so a line that wrapped would leave its first half on the
    /// screen every time the spinner turned.
    #[test]
    fn nothing_the_line_says_can_wrap_a_narrow_terminal() {
        // Two for the spinner and its gap, four for "tip ", and the longest
        // count this is ever going to hold.
        for tip in TIPS {
            assert!(tip.chars().count() + 6 <= 64, "too long to draw: {tip}");
        }

        let mut crowded = live(65_535, Counting::Ports, Duration::from_millis(2_500));
        crowded.open = 1_000_000;
        let widest = said(&crowded);
        assert!(widest.chars().count() + 3 <= 64, "{widest}");
    }

    /// Nothing is drawn where there is nothing to draw on, and the calls that
    /// take the line back are safe to make whether or not one is running. That
    /// is what lets every writer on this stream call `clear` unconditionally.
    #[test]
    fn the_line_is_inert_when_it_was_never_started() {
        clear();
        seen(1, 1);
        stop();
        clear();

        assert!(held().expect("the lock").is_none());
    }
}
