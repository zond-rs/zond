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
//! The count and a tip take turns, and **each keeps the screen for its own
//! length of time**: [`COUNT_WINDOW`] for a figure, [`INSIGHT_WINDOW`] for a
//! sentence. Holding both for the same two seconds meant one of them was always
//! wrong — a number sitting still for as long as it takes to read a line of
//! prose, or a line of prose leaving before it had been.
//!
//! **Which half a run opens on is a coin flip.** Advice-first was the rule, on
//! the grounds that the count is zero at the top of a run and the spinner has
//! already said the only thing that number would. True, and it made every run
//! open identically — and a scan that finds something in its first two seconds
//! has a real figure to show. Half of runs still open on `0 hosts found so far`,
//! which is the price of the mix.
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
//! finished.
//!
//! ## Space turns it over now
//!
//! Waiting out a five-second sentence to see a number is the one thing this
//! device can do that is worse than saying nothing, so it does not have to be
//! waited out: the space bar puts the other half up and starts its window
//! afresh. Read by [`input`](crate::input) alongside `q`, and answered here
//! rather than passed to the scan, which has no opinion about what the line
//! says.
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

/// How long the count keeps the screen.
///
/// Two seconds. It is a figure, and a figure is read at a glance; longer would
/// leave something motionless on the one line whose job is to look alive.
const COUNT_WINDOW: Duration = Duration::from_secs(2);

/// How long a tip keeps the screen.
///
/// Five, because it is a sentence rather than a figure. A sentence that leaves
/// before it has been read is worse than no sentence at all: the reader knows
/// they missed something and has no way to ask for it back — which is also why
/// the space bar exists.
const INSIGHT_WINDOW: Duration = Duration::from_secs(5);

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

/// Which of the line's two halves is up.
///
/// They are not interchangeable and the difference is why this is a type rather
/// than a parity: one is a figure and the other is a sentence, they are read at
/// different speeds, and each holds the screen for its own
/// [`window`](Self::window).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Saying {
    /// What the run has turned up: hosts, or open ports across hosts.
    Count,
    /// One of [`TIPS`].
    Insight,
}

impl Saying {
    /// How long this half keeps the screen before the line turns over.
    fn window(self) -> Duration {
        match self {
            Saying::Count => COUNT_WINDOW,
            Saying::Insight => INSIGHT_WINDOW,
        }
    }

    /// The other half.
    fn other(self) -> Self {
        match self {
            Saying::Count => Saying::Insight,
            Saying::Insight => Saying::Count,
        }
    }
}

/// The line's state while it is running.
struct Live {
    /// How many hosts have arrived.
    hosts: usize,
    /// How many open ports have been found on them.
    open: usize,
    /// Which half is up.
    saying: Saying,
    /// When it went up.
    ///
    /// Held rather than derived from how long the run has been going, which is
    /// what this was. Two windows of different lengths make that arithmetic
    /// harder to read than the state it replaces — and the space bar moves the
    /// line off a schedule the elapsed time knows nothing about.
    turned_at: Instant,
    /// What is being counted.
    counting: Counting,
    /// How standard error may be drawn on.
    style: Style,
    /// Which frame the spinner is on.
    frame: usize,
    /// Which tip is up, and where this run entered the list.
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

    let (tip, saying) = opening();
    *live = Some(Live {
        hosts: 0,
        open: 0,
        saying,
        turned_at: Instant::now(),
        counting,
        style,
        frame: 0,
        tip,
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

/// Where in the list this run starts, and which half it opens on.
///
/// From the clock rather than a random number generator: this picks a tip and
/// tosses a coin, and a dependency earning its place has to do more than that.
/// The nanoseconds inside the current second are as unpredictable as anything a
/// scan needs here, and two runs a second apart do not collide.
///
/// **The two answers come off different digits of one reading, deliberately.**
/// `nanos % 6` and `nanos % 2` are the same coin: an even remainder from the
/// first forces an even one from the second, so three of the six tips could only
/// ever appear on a run that opened one way and the mix would be no mix at all.
/// The tip comes off the bottom of the nanosecond and the coin off the
/// millisecond above it, which turn over at rates a thousandfold apart.
fn opening() -> (usize, Saying) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());

    opening_from(nanos)
}

/// The arithmetic of [`opening`], over a reading handed in rather than taken.
///
/// Split out because the property worth pinning is about the two remainders and
/// not about the clock, and a test that samples the clock in a loop measures its
/// own sleep: at a fixed interval `nanos % 6` walks a cycle of three, which says
/// nothing about what the function does with the arbitrary readings real runs
/// give it.
fn opening_from(nanos: u32) -> (usize, Saying) {
    let saying = if (nanos / 1_000_000).is_multiple_of(2) {
        Saying::Count
    } else {
        Saying::Insight
    };

    (nanos as usize % TIPS.len(), saying)
}

/// Puts the other half of the line up now, and starts its window afresh.
///
/// The space bar, and the only thing that moves this line off its own schedule.
/// Nothing is drawn here: the next tick is at most [`TICK`] away and picks the
/// change up, which is faster than a key can be pressed again and keeps every
/// write to the terminal in one place.
///
/// A no-op when no line is running, which is what lets [`input`](crate::input)
/// answer the key without knowing whether there is a terminal to draw on.
pub(crate) fn advance() {
    if let Some(mut live) = held()
        && let Some(live) = live.as_mut()
    {
        turn(live);
    }
}

/// Swaps the halves and restarts the window.
///
/// The tip moves on when a tip is what is *leaving*, so the one that is up stays
/// put for the whole of its turn and the next insight is the next in the list —
/// which is what lets a run enter the list wherever [`opening`] put it and still
/// walk the whole thing.
fn turn(live: &mut Live) {
    if live.saying == Saying::Insight {
        live.tip = (live.tip + 1) % TIPS.len();
    }

    live.saying = live.saying.other();
    live.turned_at = Instant::now();
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
fn line(live: &mut Live) -> String {
    let style = live.style;
    let spinner = style.accent(FRAMES[live.frame]);

    format!("{spinner}  {}", said(live))
}

/// Whichever half is up, turning the line over first if that half has had its
/// time.
///
/// **The turn is here rather than a step beside it**, which is why this takes
/// the line by mutable reference to answer a question about what it says.
/// Nothing can render this line without the half that is up having been given
/// its window, because rendering it is what asks. A separate call is one a
/// future edit to [`draw`] can leave out, and the failure that produces — a
/// line that comes up and never changes again — reads exactly like a scan that
/// finished in the first two seconds.
fn said(live: &mut Live) -> String {
    if live.turned_at.elapsed() >= live.saying.window() {
        turn(live);
    }

    match live.saying {
        Saying::Count => counted(live),
        Saying::Insight => {
            let style = live.style;
            let tip = TIPS[live.tip % TIPS.len()];
            format!("{} {}", style.faint("tip"), style.plain(tip))
        }
    }
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

    fn live(hosts: usize, counting: Counting, saying: Saying) -> Live {
        Live {
            hosts,
            open: 0,
            saying,
            turned_at: Instant::now(),
            counting,
            style: Style::bare(),
            frame: 0,
            tip: 0,
            shown: false,
        }
    }

    /// The same, with its current turn already `elapsed` old.
    fn aged(mut live: Live, elapsed: Duration) -> Live {
        live.turned_at = Instant::now()
            .checked_sub(elapsed)
            .expect("the machine has been up longer than the test pretends");
        live
    }

    /// What is up after the line has been asked what it says.
    ///
    /// Through `said` rather than a copy of its rule, so that a turn the drawing
    /// path stopped taking is a turn these tests stop seeing.
    fn after_drawing(mut live: Live) -> Saying {
        let _ = said(&mut live);
        live.saying
    }

    /// What a line says, asked the way the drawing path asks it.
    fn says(mut live: Live) -> String {
        said(&mut live)
    }

    /// How many of each remainder inside a millisecond the sweep below walks.
    ///
    /// A multiple of [`TIPS`]`.len()`, so every tip is reached the same number
    /// of times within each millisecond and neither figure below is an artefact
    /// of where the sweep stopped.
    const PER_MILLISECOND: u32 = 600;

    /// Every shape of clock reading that matters, as a nanosecond within a
    /// second.
    ///
    /// The coin comes off the millisecond and the tip off the whole reading, so
    /// a sweep has to move both. A flat range of a million holds the millisecond
    /// at zero and proves only that the coin has one side — which is what the
    /// first draft of this did.
    fn readings() -> impl Iterator<Item = u32> {
        (0..1_000u32).flat_map(|ms| (0..PER_MILLISECOND).map(move |rest| ms * 1_000_000 + rest))
    }

    /// Which half a run opens on is a coin flip, and it comes up both ways
    /// equally often.
    ///
    /// The line used to open on advice every time; always opening the same way
    /// is what this replaces. Swept over the readings a clock can give rather
    /// than sampled from one, for the reason [`opening_from`] gives.
    #[test]
    fn a_run_opens_on_either_half_half_the_time() {
        let total = readings().count();
        let counts = readings()
            .filter(|nanos| opening_from(*nanos).1 == Saying::Count)
            .count();

        assert_eq!(
            counts * 2,
            total,
            "the coin is not even: {counts} of {total} open on the count"
        );
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

    /// The two halves take turns, and each keeps the screen for its own length
    /// of time.
    ///
    /// A figure is read at a glance and a sentence is not, so holding both for
    /// the same window meant one of them was always wrong. The boundaries are
    /// pinned from both sides: a half that leaves early is a sentence nobody
    /// finished, and one that stays late is the line standing still.
    #[test]
    fn each_half_keeps_the_screen_for_its_own_window() {
        let still_up = |saying, millis| {
            let line = aged(
                live(7, Counting::Hosts, saying),
                Duration::from_millis(millis),
            );
            after_drawing(line) == saying
        };

        assert!(still_up(Saying::Count, 1_900), "the count left early");
        assert!(!still_up(Saying::Count, 2_100), "the count stayed late");

        assert!(still_up(Saying::Insight, 4_900), "the tip left early");
        assert!(!still_up(Saying::Insight, 5_100), "the tip stayed late");
    }

    /// A turn puts the other half up and gives it the whole of its own window,
    /// rather than whatever was left of the last one.
    #[test]
    fn a_half_that_has_just_come_up_gets_its_full_turn() {
        let mut line = aged(
            live(7, Counting::Hosts, Saying::Insight),
            Duration::from_millis(5_100),
        );
        let _ = said(&mut line);
        assert_eq!(line.saying, Saying::Count, "the tip had had its five");

        // Its predecessor was four seconds over its window; none of that is
        // charged to the half that replaced it.
        let _ = said(&mut line);
        assert_eq!(line.saying, Saying::Count, "the count was cut short");
    }

    /// Space puts the other half up now, and again, and back.
    ///
    /// Waiting out a five-second sentence to see a number is the one thing this
    /// line can do that is worse than saying nothing.
    #[test]
    fn the_space_bar_turns_the_line_over_now() {
        let mut line = live(7, Counting::Hosts, Saying::Insight);
        assert!(said(&mut line).starts_with("tip "));

        turn(&mut line);
        assert_eq!(said(&mut line), "7 hosts found so far", "space did nothing");

        turn(&mut line);
        assert!(
            said(&mut line).starts_with("tip "),
            "and back again: {}",
            said(&mut line)
        );

        // Not the tip that was up before, since that one has had its turn.
        assert!(said(&mut line).contains(TIPS[1]), "{}", said(&mut line));
    }

    /// A sweep asks who is there. A port scan was told who is there, so what it
    /// counts is what is open, and across how many machines, since nine ports on
    /// one host and nine on nine are different findings.
    #[test]
    fn each_run_counts_what_it_is_for() {
        assert_eq!(
            says(live(12, Counting::Hosts, Saying::Count)),
            "12 hosts found so far"
        );

        let mut scanning = live(2, Counting::Ports, Saying::Count);
        scanning.open = 9;
        assert_eq!(says(scanning), "9 open ports on 2 hosts");

        let mut alone = live(1, Counting::Ports, Saying::Count);
        alone.open = 1;
        assert_eq!(says(alone), "1 open port on 1 host");

        let nothing = live(3, Counting::Ports, Saying::Count);
        assert_eq!(says(nothing), "0 open ports on 3 hosts");
    }

    /// A long run works through the whole list from wherever it started.
    #[test]
    fn a_long_run_works_through_the_whole_list() {
        for opening in 0..TIPS.len() {
            let mut line = live(0, Counting::Hosts, Saying::Insight);
            line.tip = opening;

            let mut seen = Vec::new();
            for _ in 0..TIPS.len() {
                seen.push(said(&mut line));
                // Off to the count and back, which is the only way round.
                turn(&mut line);
                turn(&mut line);
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
        let first: Vec<String> = (0..TIPS.len())
            .map(|tip| {
                let mut line = live(0, Counting::Hosts, Saying::Insight);
                line.tip = tip;
                said(&mut line)
            })
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
            seen.insert(opening().0);
            std::thread::sleep(Duration::from_micros(50));
        }

        assert!(
            seen.len() > 1,
            "every run would open on the same tip: {seen:?}"
        );
        assert!(seen.iter().all(|tip| *tip < TIPS.len()));
    }

    /// Which tip a run opens on does not decide which half it opens with.
    ///
    /// They come off one reading of the clock, and the obvious way to take both
    /// — `nanos % 6` and `nanos % 2` — is one coin twice: an even remainder from
    /// the first forces an even one from the second, so three of the six tips
    /// could only ever appear on a run that opened on a count, and the mix would
    /// be no mix at all.
    #[test]
    fn the_opening_tip_and_the_opening_half_are_not_the_same_coin() {
        let pairs: std::collections::HashSet<(usize, Saying)> =
            readings().map(opening_from).collect();

        for tip in 0..TIPS.len() {
            assert!(
                pairs.contains(&(tip, Saying::Count)),
                "tip {tip} never opens on a count"
            );
            assert!(
                pairs.contains(&(tip, Saying::Insight)),
                "tip {tip} never opens on a tip"
            );
        }
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

        let mut crowded = live(65_535, Counting::Ports, Saying::Count);
        crowded.open = 1_000_000;
        let widest = says(crowded);
        assert!(widest.chars().count() + 3 <= 64, "{widest}");
    }

    /// Nothing is drawn where there is nothing to draw on, and the calls that
    /// take the line back are safe to make whether or not one is running. That
    /// is what lets every writer on this stream call `clear` unconditionally.
    #[test]
    fn the_line_is_inert_when_it_was_never_started() {
        clear();
        seen(1, 1);
        // Including the key: `input` reads it wherever stdin is a terminal, and
        // that is not the same question as whether stderr is one.
        advance();
        stop();
        clear();

        assert!(held().expect("the lock").is_none());
    }
}
