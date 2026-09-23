// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The running commentary
//!
//! The standard-error half of a run: the header, the interruption, and the
//! summary. Not the hosts, because the records carry those and a line per host
//! as it arrives says the same thing twice. Shared by every presentation,
//! because none of it is presentation: it is the same sentences whatever the
//! records on the other stream look like.
//!
//! What a mode decides for itself is the records: see
//! [`minimal`](super::minimal) and [`pipe`](super::pipe).

use std::io::{self, Write};

use zond_engine::export::Redaction;
use zond_engine::report::{ScanKind, ScannerKind};
use zond_engine::system::privilege::Privilege;
use zond_engine::{Exclusions, PortState, ScanReport};

use crate::diagnostics::Verbosity;
use crate::render::field::plural;
use crate::render::style::{Mark, Style};
use crate::render::{MergeSource, Phase, field};

/// Writes the commentary, or does not, depending on the verbosity.
pub(crate) struct Narrator {
    out: Box<dyn Write>,
    verbosity: Verbosity,
    reader: field::Reader,
    /// How this stream may be drawn on.
    ///
    /// Standard error's own answer, which is not standard output's:
    /// `zond discover lan | less` redirects one of them and not the other, so
    /// the records lose their colour and the commentary keeps it.
    ///
    /// Every mode carries one. `pipe` and `minimal` pass a style that paints
    /// nothing, so the sentences below are written once rather than twice.
    style: Style,
}

impl Narrator {
    /// Narrating to `out`, which is standard error in a real run.
    pub(crate) fn new(out: Box<dyn Write>, verbosity: Verbosity, style: Style) -> Self {
        Self {
            out,
            verbosity,
            reader: field::Reader::default(),
            style,
        }
    }

    /// Adopts the masking policy for the run about to start.
    pub(crate) fn redact(&mut self, redaction: Redaction) {
        self.reader = field::Reader::new(redaction);
    }

    /// Whether anything is being narrated at all.
    ///
    /// A presentation asks so it can decide about its own decoration: a heading
    /// row is for a reader, and a run with no reader has no use for one.
    pub(crate) fn narrates(&self) -> bool {
        self.verbosity.narrates()
    }

    /// Writes one already-painted line, if this run narrates.
    ///
    /// The gate and nothing else. Callers paint, because what a line is worth
    /// is theirs to know.
    fn say(&mut self, line: &str) -> io::Result<()> {
        if !self.verbosity.narrates() {
            return Ok(());
        }

        // A running scan holds a line at the bottom of this stream. Take it back
        // first, and let the next tick put it below whatever goes here.
        crate::render::progress::clear();
        writeln!(self.out, "{line}")
    }

    /// One line, opened by the glyph that says what kind of line it is.
    ///
    /// The same six the engine names its own events with, so a run's narration
    /// and the engine's diagnostics read as one stream rather than as two that
    /// happen to share a file descriptor.
    fn marked(&mut self, mark: Mark, line: &str) -> io::Result<()> {
        let drawn = self.style.line(mark, line);
        self.say(&drawn)
    }

    /// A line of ordinary commentary.
    ///
    /// Furniture, and drawn as it: what is on standard output is the records,
    /// and a sentence about how many of them there are is not one of them.
    fn remark(&mut self, line: &str) -> io::Result<()> {
        self.marked(Mark::Info, line)
    }

    /// A line qualifying the counts above it: the run covered less than it
    /// looks, or measured less than it could have.
    ///
    /// The glyph says `note:`, so the sentence no longer has to.
    fn note(&mut self, line: &str) -> io::Result<()> {
        self.marked(Mark::Warning, line)
    }

    /// A line saying the run did not do what it was asked.
    fn warn(&mut self, line: &str) -> io::Result<()> {
        self.marked(Mark::Error, line)
    }

    /// What is about to happen, and how much of it.
    ///
    /// The counts are what the run will cover, so they are the ones left after
    /// any exclusion policy. What that policy removed is said on a line of its
    /// own rather than folded into them: the number a person checks against a
    /// scope document is a number, and the thing they check is a range.
    pub(crate) fn started(&mut self, phase: Phase<'_>, redaction: Redaction) -> io::Result<()> {
        self.redact(redaction);

        // Its own shape. A fold has a line per source rather than one line and a
        // qualifier under it, and those lines are the whole of what lets a
        // reader check the report that follows.
        match phase {
            Phase::Merged { sources } => return self.folding(sources),
            Phase::Folded { id, sources } => return self.folded(id, sources),
            _ => {}
        }

        let (line, excluded) = match phase {
            Phase::Discovery { targets } => {
                let count = targets.len();
                (
                    format!(
                        "discovering {count} {} ({targets})",
                        plural(count, "address")
                    ),
                    withheld(targets.exclusions(), targets.excluded()),
                )
            }
            // No exclusion line, and no count of ground: a watch covers no
            // address. Where it is standing and how long it means to stand
            // there is the whole of what can be said before it starts.
            Phase::Listen { links, span } => {
                let names: Vec<&str> = links.iter().map(zond_engine::Zone::name).collect();
                (
                    format!(
                        "listening on {} {}, {}",
                        names.len(),
                        plural(names.len() as u128, "link"),
                        crate::command::listen::spoken_span(span),
                    ),
                    None,
                )
            }
            Phase::PortScan { targets } => {
                let hosts = targets.hosts();
                let probes = targets.probes();
                (
                    format!(
                        "scanning {probes} {} across {hosts} {} ({targets})",
                        plural(probes, "probe"),
                        plural(hosts, "host"),
                    ),
                    withheld(targets.exclusions(), targets.excluded()),
                )
            }
            // No exclusion line: what a record holds is what the scan covered,
            // and whatever it was kept out of was kept out at the time.
            Phase::Recorded {
                id,
                started_at,
                produced_by,
            } => (read_line(id, started_at, produced_by), None),
            Phase::Merged { .. } | Phase::Folded { .. } => unreachable!("answered above"),
        };

        self.remark(&line)?;
        if let Some(excluded) = excluded {
            self.remark(&excluded)?;
        }
        self.out.flush()
    }

    /// What is being folded, oldest first, and on whose word each part of it
    /// comes.
    ///
    /// One line per source rather than a count of them. A merge settles every
    /// disagreement by taking the newest source's word, so which source is
    /// newest decides what the report says; a reader who cannot see that cannot
    /// check the answer against the documents they handed in. The order here is
    /// the order the fold uses.
    ///
    /// Ages rather than timestamps, for the reason a listing gives: what is
    /// being asked is which of these is the recent one, and `7d` answers it
    /// where an RFC 3339 timestamp makes the reader do arithmetic. A merge is a
    /// handful of sources, so the columns are measured and padded.
    fn folding(&mut self, sources: &[MergeSource<'_>]) -> io::Result<()> {
        let count = sources.len();
        self.remark(&format!(
            "folding {count} {} into one report, oldest first",
            plural(count as u128, "source")
        ))?;
        self.sources(sources)
    }

    /// The same, for a fold being read back rather than made.
    ///
    /// A merged report carries the name every phase was folded under, so what
    /// went into it survives being written to a file and read again — including
    /// through a second fold, which leaves the labels its sources were already
    /// given alone. This is the only thing that shows them.
    ///
    /// What it cannot show is what each source held, because a fold puts every
    /// document's hosts into one set and no source's own count comes back out.
    /// See [`MergeSource::hosts`].
    fn folded(&mut self, id: &str, sources: &[MergeSource<'_>]) -> io::Result<()> {
        let count = sources.len();
        self.remark(&format!(
            "reading {id}, folded from {count} {}",
            plural(count as u128, "source")
        ))?;
        self.sources(sources)
    }

    /// One line per source, in the order given, with the columns measured.
    fn sources(&mut self, sources: &[MergeSource<'_>]) -> io::Result<()> {
        let name = sources
            .iter()
            .map(|source| source.name.len())
            .max()
            .unwrap_or_default();
        let age = sources
            .iter()
            .map(|source| field::age(source.observed_at).len())
            .max()
            .unwrap_or_default();

        for source in sources {
            // The host count only where it is still knowable.
            let held = match source.hosts {
                Some(hosts) => format!(", {hosts} {}", plural(hosts as u128, "host")),
                None => String::new(),
            };

            self.remark(&format!(
                "  {:name$}  {:age$}  {}{held}",
                source.name,
                field::age(source.observed_at),
                produced_by(source.engine_version),
            ))?;
        }

        self.out.flush()
    }

    /// The user asked the scan to stop.
    pub(crate) fn interrupted(&mut self) -> io::Result<()> {
        self.remark("interrupted; stopping and reporting what was found so far")?;
        self.out.flush()
    }

    /// What the run amounted to, and anything that qualifies it.
    pub(crate) fn summary(&mut self, report: &ScanReport) -> io::Result<()> {
        let summary = field::summary(report);

        self.say("")?;

        let hosts = format!(
            "{} {} up",
            summary.hosts_alive,
            plural(summary.hosts_alive as u128, "host")
        );

        // A scan and a sweep close on different numbers, so their one line is
        // built differently rather than sharing a shape that fits neither. A
        // scan is about ports: the hosts that answered, then what their ports
        // came to, and no address count — a scan probes the hosts a liveness
        // pass found, not a range, so "of N addresses" is the sweep's number and
        // reads as noise here. A sweep is about ground: how much answered out of
        // how much was swept.
        let line = if field::kind(report) == Some(ScanKind::PortScan) {
            // Probed means asked. A port the scan named and never asked about is
            // on the record so a truncated list cannot pass for a complete one,
            // and counting it among the probed would undo exactly that: ten dead
            // neighbours scanned on trust read `0 open ports of 200 probed` with
            // not one probe answered or even sent. So it is counted apart, on
            // this line, where the shortfall is visible beside the number it
            // qualifies.
            let unasked = summary
                .ports_by_state
                .get(&PortState::Unasked)
                .copied()
                .unwrap_or(0);
            let probed = summary.ports_total.saturating_sub(unasked);
            let ports = if probed > 0 {
                format!(
                    "{} open {} of {probed} probed",
                    summary.ports_open,
                    plural(summary.ports_open as u128, "port"),
                )
            } else {
                String::from("no ports probed")
            };
            let ports = match unasked {
                0 => ports,
                unasked => format!("{ports}, {unasked} unasked"),
            };
            format!("{hosts}, {ports}{}", timing(report))
        } else {
            // Named only where the record says what the ground was: a foreign
            // report often does not, and "3 hosts up of 0 addresses" reads as a
            // broken tool rather than an absence.
            let ground = match field::addresses_scanned(report) {
                Some(scanned) => format!(" of {scanned} {}", plural(scanned, "address")),
                None => String::new(),
            };
            format!("{hosts}{ground}{}", timing(report))
        };
        // What the scan concluded is wrong, where it concluded anything. On the
        // summary line rather than under it, because a run that turned up a
        // critical vulnerability should not make a reader open every block to
        // find out, and a second bullet saying only `3 findings` spends a line on
        // a number that fits at the end of this one. The count at high or above
        // is still called out, since that is the part that asks for action rather
        // than a note in a review.
        let line = match field::findings_tally(report) {
            Some((total, serious)) => {
                let found = format!("{total} {}", plural(total as u128, "finding"));
                match serious {
                    0 => format!("{line}, {found}"),
                    _ => format!("{line}, {found} ({serious} high or above)"),
                }
            }
            None => line,
        };

        self.remark(&line)?;
        self.qualifications(report)?;

        self.out.flush()
    }

    /// What qualifies the count above it: the ground the run did not
    /// cover, the tier it was not asked to run, and the strategies that
    /// did not finish.
    ///
    /// Its own method because a summary is one line and a page of
    /// caveats, and the line is the part every run prints.
    fn qualifications(&mut self, report: &ScanReport) -> io::Result<()> {
        // Ground the engine declined before sending anything, in its own words.
        // First, because it is what explains a count of nothing above it, and
        // at every verbosity, because it is the whole reason such a run exits
        // `3`: a refused technique or an unwalkable range would otherwise end
        // on a short count and a status with nothing on the console to say why.
        for reason in field::refusals(report) {
            self.note(&format!("not covered: {reason}"))?;
        }

        // After the count rather than before the scan: both notes say the count
        // is an undercount, which matters when somebody is looking at it. The
        // engine already announced the privilege level; this adds the remedy.
        //
        // A report with no phase at all measured nothing and has no privilege
        // level to advise about. That is a record read back from a scan which
        // stopped before it wrote one, rather than a scan that ran unprivileged.
        //
        // Nor has a report another scanner produced, which is the second way of
        // having nothing to say here and the one that read worst: an nmap sweep
        // performed over ARP as root was told it had run without raw sockets and
        // advised to use sudo, on the same page as the ARP replies that answered
        // it. `Some(Connect)` and nothing else, so silence is never read as a
        // finding.
        //
        // A port scan's note is a claim about how its TCP ports were probed,
        // so it is made only where one was. A scan whose technique was refused
        // probed none, and one that named only UDP completed no connection.
        if let Some(kind) = field::kind(report)
            && field::privilege(report) == Some(Privilege::Connect)
        {
            match kind {
                // A watch sends nothing, so it has no connect fallback to
                // describe and nothing sudo would change about how it probed.
                // It records `Connect` when no link could be captured on, and
                // the engine's failure line already says why, naming a missing
                // privilege only where that is what refused it. A second line
                // guessing at the cause would tell a root user, whose link
                // refused for some other reason, that the watch needed root.
                ScanKind::Listen => {}
                ScanKind::PortScan if !field::probed_tcp(report) => {}
                // And a sweep's is a claim about connect attempts, made only
                // where there were some. One whose whole range was refused made
                // none, and its refusal above has already said what would work.
                ScanKind::Discovery if !field::attempted_probes(report) => {}
                ScanKind::PortScan => self.note(
                    "ran without raw sockets, so every TCP port was tested by \
                     completing a connection. Run with sudo for SYN scanning, \
                     which is faster, less visible, and the only way to ask a \
                     port anything other than \"will you accept\".",
                )?,
                _ => self.note(
                    "ran without raw sockets, so this was TCP connect \
                     attempts against a few common ports. Run with sudo for ARP \
                     and ICMPv6 discovery, which finds hosts this cannot.",
                )?,
            }
        }

        // The result most likely to be read as a broken tool rather than an
        // answer: nothing scanned, and no reason given for it.
        //
        // Two reasons an address goes unscanned, and they are said separately
        // because the advice differs. A host that was asked and stayed silent
        // may well be up behind a firewall, and `--assume-up` reaches it. A host
        // this one could not reach was never asked, and nothing about scanning
        // on trust changes that. Offering it there is advice that cannot work,
        // sent to somebody already wondering why their target is missing.
        //
        // "Could not be reached" rather than "had no route", because the engine
        // files two things here: an address with no route to it, and one on the
        // local segment that never answered its address resolution. The second
        // has a route, and a reader told otherwise goes looking at a routing
        // table for a host that is simply not there.
        let unroutable = field::unroutable(report);
        if unroutable > 0 {
            self.note(&format!(
                "{unroutable} {} could not be reached from this host and {} never probed.",
                plural(unroutable, "address"),
                if unroutable == 1 { "was" } else { "were" },
            ))?;
        }

        let skipped = field::skipped_as_down(report);
        if skipped > 0 {
            self.note(&format!(
                "{skipped} {} answered no liveness probe and {} not port-scanned. \
                 Pass --assume-up to probe {} anyway.",
                plural(skipped, "address"),
                if skipped == 1 { "was" } else { "were" },
                if skipped == 1 { "it" } else { "them" },
            ))?;
        }

        // A host a time budget left where it stood. Its results are whatever the
        // scan had reached, which is narrower than what was asked, so a reader
        // acting on the count should know it was cut short rather than finished.
        let timed_out = field::timed_out(report);
        if timed_out > 0 {
            self.note(&format!(
                "{timed_out} {} still outstanding when a time budget expired and {} left \
                 where {} stood. Raise --host-timeout or --scan-timeout to finish {}.",
                plural(timed_out, "host"),
                if timed_out == 1 { "was" } else { "were" },
                if timed_out == 1 { "it" } else { "they" },
                if timed_out == 1 { "it" } else { "them" },
            ))?;
        }

        if report.is_partial() {
            self.shortfall(report)?;
        }

        Ok(())
    }

    /// The line closing a run that covered less than it was asked to.
    ///
    /// The engine files two different things as work that did not complete,
    /// and they are counted apart because only one of them is a fault. A
    /// strategy that did not run is something broken on this machine or this
    /// network. A detection that did not finish is almost always one its own
    /// declared budget stopped against a target that cost more than it
    /// allowed: it ran, and was cut short. The engine has already said which
    /// detection, which budget and how far it got, a line each as it happened,
    /// so this counts them rather than repeating them. Counted as strategies
    /// that did not run, they would send a reader looking for a fault where
    /// the detections ran and the target cost more than their budgets allowed.
    ///
    /// Said as a note when detections are all there is, since nothing failed,
    /// and as a warning when a strategy did not run.
    fn shortfall(&mut self, report: &ScanReport) -> io::Result<()> {
        let (detections, strategies): (Vec<_>, Vec<_>) = report
            .failures()
            .partition(|failure| failure.scanner() == ScannerKind::Detection);
        let strategies = strategies.len();
        let detections = detections.len();

        // Written out rather than passed through `plural`, which knows the four
        // words a scan counts and not this one.
        let not_run = format!(
            "{strategies} {} did not run",
            if strategies == 1 {
                "strategy"
            } else {
                "strategies"
            }
        );
        let unfinished = format!(
            "{detections} {} did not finish",
            plural(detections as u128, "detection")
        );
        let what = match (strategies, detections) {
            (_, 0) => not_run,
            (0, _) => unfinished,
            _ => format!("{not_run} and {unfinished}"),
        };
        let line = format!("{what}; this run covered less than it was asked to");

        if strategies == 0 {
            self.note(&line)
        } else {
            self.warn(&line)
        }
    }
}

/// The line that says what a run was forbidden to touch, or `None` when nothing
/// was.
///
/// Silent under no policy, because "0 addresses excluded" on every run of every
/// scan trains a reader to skip the line on the one run where it matters.
///
/// The ranges come first and the count second. A person reads this to check a
/// scope document, and what they are checking is which ranges were named; the
/// count is what tells them the ranges actually met the targets, which is the
/// mistake a typo in an exclusion produces.
fn withheld(exclusions: &Exclusions, addresses: u128) -> Option<String> {
    if exclusions.is_empty() {
        return None;
    }

    let ranges: Vec<String> = exclusions
        .ranges()
        .iter()
        .map(|range| {
            if range.start_addr() == range.end_addr() {
                range.start_addr().to_string()
            } else {
                format!("{}-{}", range.start_addr(), range.end_addr())
            }
        })
        .collect();

    Some(format!(
        "excluding {} ({addresses} {} withheld)",
        ranges.join(", "),
        plural(addresses, "address"),
    ))
}

/// How long the run behind a report took, as a clause that follows the counts.
///
/// **A merged report has no duration**, and this is the whole reason it is
/// asked. `elapsed` is a sum over the phases; for a scan that is exactly right,
/// since the engine really did work through each of them in turn. For a report
/// folded out of documents it is the working time of several scanners across
/// arbitrary moments added together, which is a real quantity and is not a
/// length of time anything took. Printed as `in 6.18s` it describes a scan that
/// never ran, and the further apart the sources are the worse it reads: a year
/// of archived files sums to hours and reports itself as an afternoon.
///
/// What such a report has instead is the span it draws on, from the earliest
/// phase to the latest. That is the number a reader wants from a merged report
/// anyway, because it says how much drift is baked into a single answer
/// assembled out of several moments.
fn timing(report: &ScanReport) -> String {
    if !report.is_merged() {
        return format!(" in {:.2}s", report.elapsed().as_secs_f64());
    }

    let span = report
        .finished_at()
        .duration_since(report.started_at())
        .unwrap_or_default();

    format!(", drawn from {} of scanning", field::span(span))
}

/// Whether an attribution names the scanner that produced it.
///
/// The one rule for telling a foreign report from this engine's, and the reason
/// it is a rule rather than a comparison: a scanner that is not this one
/// attributes itself with its name — `nmap 7.94` — and this engine records a
/// bare crate version, because a document of its own has never needed telling
/// apart from itself. Comparing against *this build's* version would answer
/// wrongly for a record an older build of this engine left behind.
fn names_its_scanner(engine_version: &str) -> bool {
    engine_version.contains(' ')
}

/// What produced a source, in a form that names it.
///
/// For a listing, where `0.13.0` sitting beside `nmap 7.94` would leave a reader
/// to work out which tool the bare number belongs to. An attribution that
/// already names its scanner is left alone; one that does not is this engine's
/// and is named as such.
fn produced_by(engine_version: &str) -> String {
    if names_its_scanner(engine_version) {
        return engine_version.to_owned();
    }

    format!("{} {engine_version}", zond_engine::format::ENGINE_NAME)
}

/// The line that opens a document being read.
///
/// Three facts, each present only where the document has it: what is being read,
/// who produced it, and when. This engine's own attribution is left off, because
/// a reader of `zond read latest` knows what produced it and a line saying so on
/// every read is furniture; another scanner's is the whole point, since nothing
/// else on a terminal says whose findings these are.
fn read_line(id: &str, started_at: Option<std::time::SystemTime>, produced_by: &str) -> String {
    let by = if names_its_scanner(produced_by) {
        format!(" by {produced_by}")
    } else {
        String::new()
    };
    let from = match started_at {
        Some(at) => format!(" from {}", field::timestamp(at)),
        None => String::new(),
    };

    // A document with neither is a document there is nothing to say about but
    // its name, and "a scan" on its own is not worth a clause.
    if by.is_empty() && from.is_empty() {
        return format!("reading {id}");
    }

    format!("reading {id}, a scan{by}{from}")
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

    use crate::render::test_support::{Capture, host, recorded_at, scoped};

    /// A run says nothing about ports it never probed.
    ///
    /// "0 open ports of 0 probed" on every discovery sweep reads as a finding
    /// about the hosts rather than as a phase that did not happen, and a sweep
    /// is the commonest thing this program does.
    #[test]
    fn a_sweep_says_nothing_about_ports() {
        let said = summarised(&scoped(vec![host(1)], "192.0.2.0/24"));

        assert!(said.contains("1 host up of 256 addresses"), "{said}");
        assert!(!said.contains("port"), "{said}");
    }

    /// Every count in the summary is pluralised, including the two that were
    /// composed by hand and got "addresss" and "1 hosts" wrong in turn.
    #[test]
    fn the_counts_read_as_english_at_one_and_at_many() {
        let one = summarised(&scoped(vec![host(1)], "192.0.2.1"));
        assert!(one.contains("1 host up of 1 address"), "{one}");

        let many = summarised(&scoped(vec![host(1), host(2)], "192.0.2.0/24"));
        assert!(many.contains("2 hosts up of 256 addresses"), "{many}");
    }

    // -----------------------------------------------------------------------
    // What a fold says went into it
    // -----------------------------------------------------------------------

    /// Every source is named, in the order it was handed over — which the
    /// command has already put in fold order.
    ///
    /// The whole worth of these lines is that a reader can check the report
    /// underneath against the documents they handed in, and a source missing
    /// from them is a document whose findings arrived unannounced.
    #[test]
    fn a_fold_names_every_source_in_the_order_it_will_use() {
        let said = folded(&[
            source("q1.xml", "nmap 7.94", 41),
            source("baseline.json", "0.12.1", 52),
        ]);

        assert!(said.contains("folding 2 sources"), "{said}");
        let (first, second) = (
            said.find("q1.xml").expect("the first source"),
            said.find("baseline.json").expect("the second source"),
        );
        assert!(first < second, "the fold order was not kept: {said}");
    }

    /// A bare version is this engine's and is named as such; one that already
    /// names its scanner is left alone. Both spellings sit in the same column of
    /// a mixed fold, which is the only place the difference shows.
    #[test]
    fn a_source_says_which_scanner_produced_it() {
        let said = folded(&[
            source("q1.xml", "nmap 7.94", 1),
            source("tonight.json", "0.13.0", 1),
        ]);

        assert!(said.contains("nmap 7.94"), "{said}");
        assert!(
            said.contains(&format!("{} 0.13.0", zond_engine::format::ENGINE_NAME)),
            "a bare version was left unattributed: {said}"
        );
    }

    /// The counts read as English at one and at many, as every other count this
    /// module writes does.
    #[test]
    fn the_source_counts_read_as_english() {
        let one = folded(&[source("a.json", "0.13.0", 1), source("b.json", "0.13.0", 2)]);

        assert!(one.contains("1 host"), "{one}");
        assert!(one.contains("2 hosts"), "{one}");
    }

    /// A run told to say nothing says nothing, the fold included. A merge
    /// written into a file by a scheduled job has no reader for this.
    #[test]
    fn a_quiet_run_narrates_no_fold_at_all() {
        let capture = Capture::default();
        let mut narrator = Narrator::new(
            Box::new(capture.clone()),
            Verbosity::new(0, true),
            Style::bare(),
        );

        narrator
            .started(
                Phase::Merged {
                    sources: &[source("a.json", "0.13.0", 1)],
                },
                Redaction::None,
            )
            .expect("a capture never fails");

        assert_eq!(capture.text(), "");
    }

    /// One source as the command would describe it.
    fn source<'a>(name: &'a str, engine_version: &'a str, hosts: usize) -> MergeSource<'a> {
        MergeSource {
            name,
            engine_version,
            observed_at: recorded_at(),
            hosts: Some(hosts),
        }
    }

    /// What a narrator writes for a fold about to happen, as one string.
    fn folded(sources: &[MergeSource<'_>]) -> String {
        let capture = Capture::default();
        let mut narrator = Narrator::new(
            Box::new(capture.clone()),
            Verbosity::default(),
            Style::bare(),
        );

        narrator
            .started(Phase::Merged { sources }, Redaction::None)
            .expect("a capture never fails");
        capture.text()
    }

    // -----------------------------------------------------------------------
    // What a document being read says about itself
    // -----------------------------------------------------------------------

    /// Another scanner's report says whose it is.
    ///
    /// It did not, and nothing else on a terminal did either: the document knew,
    /// the JSON said `produced_by`, the HTML colophon said it, and the one place
    /// a person actually reads a scan said nothing at all.
    #[test]
    fn reading_another_scanners_report_names_the_scanner() {
        let said = read_line("q1.xml", Some(recorded_at()), "nmap 7.94");
        assert_eq!(
            said,
            format!(
                "reading q1.xml, a scan by nmap 7.94 from {}",
                field::timestamp(recorded_at())
            )
        );
    }

    /// This engine's own does not, because a bare version on every read is
    /// furniture: whoever typed `zond read latest` knows what produced it.
    #[test]
    fn reading_this_engines_own_report_says_nothing_about_the_scanner() {
        let said = read_line("latest", Some(recorded_at()), "0.13.0");

        assert!(!said.contains("0.13.0"), "{said}");
        assert!(said.starts_with("reading latest, a scan from"), "{said}");
    }

    /// A document with nothing to date it by is not dated, and one with nothing
    /// to say at all is just named.
    #[test]
    fn a_document_saying_nothing_about_itself_is_only_named() {
        assert_eq!(
            read_line("q1.xml", None, "nmap 7.94"),
            "reading q1.xml, a scan by nmap 7.94"
        );
        assert_eq!(
            read_line("mystery.json", None, "0.13.0"),
            "reading mystery.json"
        );
    }

    // -----------------------------------------------------------------------
    // Advice about this engine, under this engine's runs only
    // -----------------------------------------------------------------------

    /// A scan this engine ran without raw sockets is told what it cost and what
    /// to do about it.
    #[test]
    fn an_unprivileged_run_of_this_engine_is_advised_to_use_sudo() {
        let said = summarised(&unprivileged());

        assert!(said.contains("without raw sockets"), "{said}");
        assert!(said.contains("sudo"), "{said}");
    }

    /// A report another scanner produced is not.
    ///
    /// The failure: an nmap sweep performed over ARP as root read back as
    /// `ran without raw sockets ... Run with sudo for ARP and ICMPv6 discovery`,
    /// printed directly beneath the ARP replies that answered it. Whether *this*
    /// engine's raw strategies had their sockets is not something another
    /// scanner's document says, and its silence was being read as a no.
    #[test]
    fn a_report_this_engine_did_not_measure_attracts_no_advice_about_it() {
        let said = summarised(&foreign());

        assert!(
            !said.contains("raw sockets"),
            "advice about this engine's privileges under another scanner's \
             findings: {said}"
        );
        assert!(!said.contains("sudo"), "{said}");
    }

    /// A watch that could not capture is not told it ran connect attempts, or
    /// that sudo would have helped.
    ///
    /// A watch records `Connect` whenever no link could be captured on, root
    /// or not, and it probes nothing, so neither half of the note is true of
    /// it. The engine's own failure line names what refused the capture, and
    /// names privilege only where privilege was missing: a root watch on a
    /// tunnel read `ran without raw sockets` beneath a failure that had
    /// nothing to do with privilege.
    #[test]
    fn a_watch_that_could_not_capture_is_not_advised_about_raw_sockets() {
        let said = summarised(&listened_by(Privilege::Connect));

        assert!(!said.contains("raw sockets"), "{said}");
        assert!(!said.contains("connect attempts"), "{said}");
        assert!(!said.contains("sudo"), "{said}");
    }

    /// A scan of this engine's whose phase said nothing, on the same rule: the
    /// note follows a recorded privilege and never an absence.
    fn unprivileged() -> ScanReport {
        rebuilt(Some(Privilege::Connect))
    }

    /// A report of one listening phase, run with `privilege`.
    fn listened_by(privilege: Privilege) -> ScanReport {
        use zond_engine::report::{PhaseParts, ScanPhase};

        let report = scoped(vec![host(1)], "192.0.2.0/24");
        let phase = &report.phases()[0];

        let listened = ScanPhase::from_parts(PhaseParts {
            attachments: Vec::new(),
            kind: ScanKind::Listen,
            started_at: phase.started_at(),
            elapsed: phase.elapsed(),
            privilege: Some(privilege),
            targets: phase.targets().clone(),
            settings: phase.settings().clone(),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: Vec::new(),
            timed_out: Vec::new(),
            reached_by_connect: Vec::new(),
            probes: Vec::new(),
            origin: None,
        });

        let hosts: Vec<_> = report.hosts().cloned().collect();
        ScanReport::recorded("test", vec![listened], hosts)
    }

    fn foreign() -> ScanReport {
        rebuilt(None)
    }

    /// The test fixture's report with its phase's privilege set to `privilege`,
    /// carrying the connect attempts a sweep of it would have made.
    fn rebuilt(privilege: Option<Privilege>) -> ScanReport {
        rebuilt_with(privilege, Vec::new(), connect_attempts(256))
    }

    /// The same, declining what `refusals` name and having made `attempts`.
    fn rebuilt_with(
        privilege: Option<Privilege>,
        refusals: Vec<zond_engine::report::Refusal>,
        attempts: zond_engine::report::ProbeStats,
    ) -> ScanReport {
        use zond_engine::report::{PhaseParts, ScanPhase};

        let report = scoped(vec![host(1)], "192.0.2.0/24");
        let phase = &report.phases()[0];

        let rebuilt = ScanPhase::from_parts(PhaseParts {
            attachments: phase.attachments().to_vec(),
            kind: phase.kind(),
            started_at: phase.started_at(),
            elapsed: phase.elapsed(),
            privilege,
            targets: phase.targets().clone(),
            settings: phase.settings().clone(),
            failures: phase.failures().to_vec(),
            refusals,
            unroutable: phase.unroutable().to_vec(),
            timed_out: phase.timed_out().to_vec(),
            reached_by_connect: phase.reached_by_connect().to_vec(),
            probes: vec![attempts],
            origin: phase.origin().cloned(),
        });

        let hosts: Vec<_> = report.hosts().cloned().collect();
        ScanReport::recorded("test", vec![rebuilt], hosts)
    }

    /// What a connect sweep records of itself having made `attempts` connect
    /// attempts at as many targets.
    fn connect_attempts(attempts: u64) -> zond_engine::report::ProbeStats {
        use std::time::Duration;
        use zond_engine::report::{
            ATTEMPTS_COUNTED, BUCKET_BOUNDS_MS, ProbeStats, ProbeStatsParts, ScannerKind,
            StopReason,
        };

        ProbeStats::from_parts(ProbeStatsParts {
            scanner: ScannerKind::Connect,
            targets: u128::from(attempts),
            stop_reason: StopReason::AttemptsSpent,
            elapsed: Duration::from_secs(1),
            sends_attempted: attempts,
            sends_failed: 0,
            sends_witnessed: 0,
            segments_seen: 0,
            window: None,
            segments_off_target: 0,
            replies_without_rtt: 0,
            hosts_found: 0,
            answered_on: [0; ATTEMPTS_COUNTED],
            answered_unattributed: 0,
            first_reply: None,
            last_reply: None,
            found_at: [0; BUCKET_BOUNDS_MS.len() + 1],
            capture: None,
        })
    }

    /// A connect sweep whose whole range was refused made no connect attempt,
    /// and is not told it was connect attempts against a few common ports.
    ///
    /// Measured on the connect path: `zond d 2001:db8::/64` refused the prefix
    /// as too large to walk, then closed by describing the connect attempts it
    /// had made against it, and advised sudo a second time beneath a refusal
    /// that had already said to run as root. The refusal is the whole of what
    /// happened, and it is said once.
    #[test]
    fn a_connect_sweep_that_attempted_nothing_describes_no_attempts() {
        let refused = zond_engine::report::Refusal::new(
            zond_engine::report::ScannerKind::Connect,
            "2001:db8::/64 is too large to probe one address at a time. Run with root",
        );
        let said = summarised(&rebuilt_with(
            Some(Privilege::Connect),
            vec![refused],
            connect_attempts(0),
        ));

        assert!(said.contains("not covered: 2001:db8::/64"), "{said}");
        assert!(!said.contains("connect attempts"), "{said}");
        assert!(!said.contains("sudo"), "{said}");
    }

    // -----------------------------------------------------------------------
    // A port scan that reached no ports says so, rather than reading as a sweep
    // -----------------------------------------------------------------------

    /// A report of one port-scan phase over `covered`, holding `hosts`.
    ///
    /// The discovery-phase fixtures elsewhere here are `Discovery`-kind; this is
    /// the one that says a *port scan* ran, which is what the note under test
    /// keys on.
    fn port_scanned(hosts: Vec<zond_engine::Host>, covered: &str) -> ScanReport {
        port_scanned_by(Privilege::Raw, hosts, covered, Vec::new())
    }

    /// The same, run with `privilege` and declining what `refusals` name.
    fn port_scanned_by(
        privilege: Privilege,
        hosts: Vec<zond_engine::Host>,
        covered: &str,
        refusals: Vec<zond_engine::report::Refusal>,
    ) -> ScanReport {
        port_scanned_past(privilege, hosts, covered, refusals, Vec::new())
    }

    /// The same, unable to reach the addresses `unroutable` names.
    fn port_scanned_past(
        privilege: Privilege,
        hosts: Vec<zond_engine::Host>,
        covered: &str,
        refusals: Vec<zond_engine::report::Refusal>,
        unroutable: Vec<std::net::IpAddr>,
    ) -> ScanReport {
        use std::time::Duration;
        use zond_engine::ZondConfig;
        use zond_engine::model::exclusion::Exclusions;
        use zond_engine::model::parse::ip::to_set;
        use zond_engine::report::{PhaseParts, ScanKind, ScanPhase, ScanSettings, TargetScope};

        let mut targets = to_set(&[covered], None, None).expect("a range");
        let phase = ScanPhase::from_parts(PhaseParts {
            attachments: Vec::new(),
            kind: ScanKind::PortScan,
            started_at: recorded_at(),
            elapsed: Duration::from_secs(1),
            privilege: Some(privilege),
            targets: TargetScope::from_ip_set(&mut targets, &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            refusals,
            unroutable,
            timed_out: Vec::new(),
            reached_by_connect: Vec::new(),
            probes: Vec::new(),
            origin: None,
        });
        ScanReport::recorded("test", vec![phase], hosts)
    }

    /// A port scan that found a host and probed none of its ports says so on the
    /// one summary line, so it does not read as the discovery it otherwise looks
    /// like: an address and how it answered, and a count of hosts alone.
    #[test]
    fn a_port_scan_that_reached_no_ports_says_no_ports_probed() {
        let said = summarised(&port_scanned(vec![host(1)], "192.0.2.1"));

        assert!(
            said.contains("1 host up, no ports probed"),
            "a scan that reached no ports should say so: {said}"
        );
        // And not the sweep's address count, which for a scan is the wrong
        // number and the noise this rework removed.
        assert!(
            !said.contains("address"),
            "no address count on a scan: {said}"
        );
    }

    /// The port clause is a scan's alone. A discovery sweep probes no ports by
    /// design, so it keeps its ground count and says nothing about ports.
    #[test]
    fn a_discovery_sweep_says_nothing_about_ports() {
        let said = summarised(&scoped(vec![host(1)], "192.0.2.0/24"));

        assert!(!said.contains("no ports probed"), "{said}");
        assert!(said.contains("1 host up of 256 addresses"), "{said}");
    }

    /// And a port scan that did probe ports is not told it reached none, however
    /// few were open.
    #[test]
    fn a_port_scan_with_probed_ports_gets_no_such_note() {
        let mut host = host(1);
        host.add_port(zond_engine::Port::new(
            22,
            zond_engine::Protocol::Tcp,
            zond_engine::PortState::Closed,
        ));
        let said = summarised(&port_scanned(vec![host], "192.0.2.1"));

        assert!(
            !said.contains("no ports probed"),
            "a port that was probed and came back closed is still a probed port: {said}"
        );
    }

    /// A host holding `ports`, each of `protocol` and in `state`.
    fn host_holding(
        ports: std::ops::RangeInclusive<u16>,
        protocol: zond_engine::Protocol,
        state: zond_engine::PortState,
    ) -> zond_engine::Host {
        let mut host = host(1);
        for port in ports {
            host.add_port(zond_engine::Port::new(port, protocol, state));
        }
        host
    }

    /// A port nobody asked about is not a probed port, and the summary does not
    /// count it as one.
    ///
    /// Measured: ten dead neighbours scanned on trust came back with every one
    /// of their two hundred ports unasked, under a summary that said
    /// `0 open ports of 200 probed`. Those ports are on the record so a
    /// truncated list cannot pass for a complete one, and they are counted
    /// apart for the same reason.
    #[test]
    fn a_port_scan_counts_an_unasked_port_apart_from_the_probed_ones() {
        let mut host = host_holding(
            1..=20,
            zond_engine::Protocol::Tcp,
            zond_engine::PortState::Unasked,
        );
        host.add_port(zond_engine::Port::new(
            80,
            zond_engine::Protocol::Tcp,
            zond_engine::PortState::Open,
        ));
        let said = summarised(&port_scanned(vec![host], "192.0.2.1"));

        assert!(
            said.contains("1 open port of 1 probed, 20 unasked"),
            "{said}"
        );
    }

    /// A scan whose every port went unasked probed none, and says so in the
    /// words a scan that reached no ports uses.
    #[test]
    fn a_port_scan_whose_every_port_went_unasked_says_none_were_probed() {
        let host = host_holding(
            1..=20,
            zond_engine::Protocol::Tcp,
            zond_engine::PortState::Unasked,
        );
        let said = summarised(&port_scanned(vec![host], "192.0.2.1"));

        assert!(said.contains("no ports probed, 20 unasked"), "{said}");
        assert!(!said.contains("of 20 probed"), "{said}");
    }

    /// An address the engine could not reach is said not to have been reached,
    /// in words true of both ways that happens: no route to it, and a
    /// neighbour that never answered for it. A dead host on the local segment
    /// has a route; what it lacks is anything answering at the end of it.
    #[test]
    fn an_unreachable_address_is_said_not_to_have_been_reached() {
        let dead: std::net::IpAddr = "192.0.2.1".parse().expect("a literal address");
        let report = port_scanned_past(
            Privilege::Raw,
            vec![host_holding(
                1..=2,
                zond_engine::Protocol::Tcp,
                zond_engine::PortState::Unasked,
            )],
            "192.0.2.1",
            Vec::new(),
            vec![dead],
        );
        let said = summarised(&report);

        assert!(
            said.contains("1 address could not be reached from this host and was never probed"),
            "{said}"
        );
        assert!(!said.contains("no route"), "{said}");
    }

    // -----------------------------------------------------------------------
    // What a scan without raw sockets says it did
    // -----------------------------------------------------------------------

    /// A connect scan whose TCP ports all went unasked tested none of them by a
    /// connection, and does not say it did.
    #[test]
    fn a_connect_scan_whose_tcp_ports_went_unasked_claims_no_connections() {
        let report = port_scanned_by(
            Privilege::Connect,
            vec![host_holding(
                1..=2,
                zond_engine::Protocol::Tcp,
                zond_engine::PortState::Unasked,
            )],
            "192.0.2.1",
            Vec::new(),
        );
        let said = summarised(&report);

        assert!(!said.contains("completing a connection"), "{said}");
    }

    /// A host whose one probed port is `port`, of `protocol`, and closed.
    fn host_with(port: u16, protocol: zond_engine::Protocol) -> zond_engine::Host {
        let mut host = host(1);
        host.add_port(zond_engine::Port::new(
            port,
            protocol,
            zond_engine::PortState::Closed,
        ));
        host
    }

    /// A connect scan that probed TCP ports says how it probed them, and what
    /// running as root would add.
    #[test]
    fn a_connect_scan_of_tcp_ports_says_it_completed_connections() {
        let report = port_scanned_by(
            Privilege::Connect,
            vec![host_with(22, zond_engine::Protocol::Tcp)],
            "192.0.2.1",
            Vec::new(),
        );
        let said = summarised(&report);

        assert!(said.contains("completing a connection"), "{said}");
        assert!(said.contains("sudo"), "{said}");
    }

    /// A technique the connect path cannot express is refused, and the summary
    /// says so rather than that every port was tested by a connection.
    ///
    /// The refusal is the one line that explains the `no ports probed` above
    /// it and the exit status after it, so it is said at the default
    /// verbosity. The claim about connections is left out because no
    /// connection was made: the one sentence would contradict the other.
    #[test]
    fn a_refused_technique_is_named_and_no_port_is_said_to_be_tested() {
        let refused = zond_engine::report::Refusal::new(
            zond_engine::report::ScannerKind::TcpPort,
            "the fin technique needs raw sockets",
        );
        let report = port_scanned_by(
            Privilege::Connect,
            vec![host(1)],
            "192.0.2.1",
            vec![refused],
        );
        let said = summarised(&report);

        assert!(
            said.contains("not covered: the fin technique needs raw sockets"),
            "the refusal was not said: {said}"
        );
        assert!(
            !said.contains("completing a connection"),
            "a scan that probed no port claimed to have tested them: {said}"
        );
    }

    /// Only TCP completes a connection, so a scan that probed nothing else
    /// makes no claim that it did.
    #[test]
    fn a_connect_scan_of_udp_ports_alone_claims_no_connections() {
        let report = port_scanned_by(
            Privilege::Connect,
            vec![host_with(53, zond_engine::Protocol::Udp)],
            "192.0.2.1",
            Vec::new(),
        );
        let said = summarised(&report);

        assert!(!said.contains("completing a connection"), "{said}");
    }

    /// A refusal met by two phases is one reason, and is said once.
    #[test]
    fn a_refusal_two_phases_filed_is_said_once() {
        let refused = || {
            zond_engine::report::Refusal::new(
                zond_engine::report::ScannerKind::Local,
                "too large to walk",
            )
        };
        let report = port_scanned_by(
            Privilege::Raw,
            vec![host(1)],
            "192.0.2.1",
            vec![refused(), refused()],
        );
        let said = summarised(&report);

        assert_eq!(said.matches("too large to walk").count(), 1, "{said}");
    }

    // -----------------------------------------------------------------------
    // What a run that covered less than it was asked to says about it
    // -----------------------------------------------------------------------

    /// The test fixture's report with `failures` filed on its phase.
    fn failing(failures: Vec<zond_engine::report::ScannerFailure>) -> ScanReport {
        use zond_engine::report::{PhaseParts, ScanPhase};

        let report = scoped(vec![host(1)], "192.0.2.0/24");
        let phase = &report.phases()[0];
        let rebuilt = ScanPhase::from_parts(PhaseParts {
            attachments: phase.attachments().to_vec(),
            kind: phase.kind(),
            started_at: phase.started_at(),
            elapsed: phase.elapsed(),
            privilege: phase.privilege(),
            targets: phase.targets().clone(),
            settings: phase.settings().clone(),
            failures,
            refusals: phase.refusals().to_vec(),
            unroutable: phase.unroutable().to_vec(),
            timed_out: phase.timed_out().to_vec(),
            reached_by_connect: phase.reached_by_connect().to_vec(),
            probes: phase.probe_stats().to_vec(),
            origin: phase.origin().cloned(),
        });
        let hosts: Vec<_> = report.hosts().cloned().collect();
        ScanReport::recorded("test", vec![rebuilt], hosts)
    }

    /// A detection its budget cut short, as the engine files one.
    fn cut_short(port: u16) -> zond_engine::report::ScannerFailure {
        zond_engine::report::ScannerFailure::new(
            ScannerKind::Detection,
            format!(
                "detection 'backup-files' on 192.0.2.1:{port} went unanswered: \
                 its 3000 ms time budget ran out with 3 of 6 requests answered"
            ),
        )
    }

    /// Detections that ran and were cut short are counted as what they are.
    /// Nothing about them failed to run, and a line saying strategies did not
    /// run sends a reader looking for a fault on their machine.
    #[test]
    fn detections_cut_short_are_not_counted_as_strategies_that_did_not_run() {
        let said = summarised(&failing(vec![cut_short(80), cut_short(443)]));

        assert!(
            said.contains(
                "2 detections did not finish; this run covered less than it was asked to"
            ),
            "{said}"
        );
        assert!(!said.contains("did not run"), "{said}");
    }

    /// A strategy that did not run is still said to have not run, beside the
    /// detections that did not finish.
    #[test]
    fn a_strategy_that_did_not_run_is_counted_apart_from_detections_that_did_not_finish() {
        let broken =
            zond_engine::report::ScannerFailure::new(ScannerKind::Local, "raw socket unavailable");
        let said = summarised(&failing(vec![broken, cut_short(443)]));

        assert!(
            said.contains(
                "1 strategy did not run and 1 detection did not finish; \
                 this run covered less than it was asked to"
            ),
            "{said}"
        );
    }

    // -----------------------------------------------------------------------
    // What the summary says a run took
    // -----------------------------------------------------------------------

    /// A scan reports its own duration, which is what it has: the engine worked
    /// through its phases in turn and the sum is how long that was.
    #[test]
    fn a_scan_reports_how_long_it_took() {
        let said = summarised(&scoped(vec![host(1)], "192.0.2.0/24"));

        assert!(said.contains(" in 1.00s"), "{said}");
        assert!(!said.contains("drawn from"), "{said}");
    }

    /// A merged report reports the span its sources cover instead.
    ///
    /// The failure this replaces: `elapsed` sums the phases, so two one-second
    /// scans a day apart summed to two seconds and the line called it the length
    /// of the run. No run took two seconds, and the thing a reader of a merged
    /// report actually needs to know — that its answers were assembled out of
    /// moments a day apart — was the part left out.
    #[test]
    fn a_merged_report_says_the_span_its_sources_cover() {
        let said = summarised(&folded_a_day_apart());

        assert!(
            said.contains("drawn from 1d of scanning"),
            "the span its sources cover was not reported: {said}"
        );
        assert!(
            !said.contains("2.00s"),
            "the sum of the sources' scanning was reported as a duration: {said}"
        );
    }

    /// Two one-second scans, folded, whose phases are a day apart.
    fn folded_a_day_apart() -> ScanReport {
        use std::time::Duration;

        use zond_engine::merge::{Merge, MergeOptions};

        use crate::render::test_support::{recorded_at, scoped_at};

        let day = Duration::from_secs(24 * 60 * 60);
        let mut merge = Merge::new(MergeOptions::default());
        merge.add_from(
            "yesterday",
            scoped_at(vec![host(1)], "192.0.2.0/24", recorded_at()),
        );
        merge.add_from(
            "today",
            scoped_at(vec![host(2)], "192.0.2.0/24", recorded_at() + day),
        );
        merge.finish()
    }

    /// What a narrator writes for a finished report, as one string.
    fn summarised(report: &ScanReport) -> String {
        let capture = Capture::default();
        let mut narrator = Narrator::new(
            Box::new(capture.clone()),
            Verbosity::default(),
            Style::bare(),
        );

        narrator.summary(report).expect("a capture never fails");
        capture.text()
    }
}
