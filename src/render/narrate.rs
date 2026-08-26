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
use zond_engine::scanner::report::ScanKind;
use zond_engine::{Exclusions, ScanReport};

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
            // A document that carries no phase has no date of its own, and
            // reading it is not a reason to give it one.
            Phase::Recorded { id, started_at } => (
                match started_at {
                    Some(at) => format!("reading {id}, a scan from {}", field::timestamp(at)),
                    None => format!("reading {id}"),
                },
                None,
            ),
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

        // The ground covered is named only where the record says what it was.
        // A report from another scanner often does not, and "3 hosts up of 0
        // addresses" reads as a broken tool rather than as an absence.
        let ground = match field::addresses_scanned(report) {
            Some(scanned) => format!(" of {scanned} {}", plural(scanned, "address")),
            None => String::new(),
        };

        self.say("")?;
        self.remark(&format!(
            "{} {} up{ground}{}",
            summary.hosts_alive,
            plural(summary.hosts_alive as u128, "host"),
            timing(report),
        ))?;

        // A discovery sweep probes no ports, and "0 open ports" would read as a
        // finding rather than as nothing having been asked.
        if summary.ports_total > 0 {
            self.remark(&format!(
                "{} open {} of {} probed",
                summary.ports_open,
                plural(summary.ports_open as u128, "port"),
                summary.ports_total,
            ))?;
        }

        // After the count rather than before the scan: both notes say the count
        // is an undercount, which matters when somebody is looking at it. The
        // engine already announced the privilege level; this adds the remedy.
        //
        // A report with no phase at all measured nothing and has no privilege
        // level to advise about. That is a record read back from a scan which
        // stopped before it wrote one, rather than a scan that ran unprivileged.
        if let Some(kind) = field::kind(report)
            && !field::was_privileged(report)
        {
            self.note(match kind {
                ScanKind::PortScan => {
                    "ran without raw sockets, so every port was tested by \
                     completing a connection. Run with sudo for SYN scanning, \
                     which is faster, less visible, and the only way to ask a \
                     port anything other than \"will you accept\"."
                }
                _ => {
                    "ran without raw sockets, so this was TCP connect \
                     attempts against a few common ports. Run with sudo for ARP \
                     and ICMPv6 discovery, which finds hosts this cannot."
                }
            })?;
        }

        // The result most likely to be read as a broken tool rather than an
        // answer: nothing scanned, and no reason given for it.
        //
        // Two reasons an address goes unscanned, and they are said separately
        // because the advice differs. A host that was asked and stayed silent
        // may well be up behind a firewall, and `--assume-up` reaches it. A host
        // there is no route to was never asked, and nothing about scanning on
        // trust creates a route. Offering it there is advice that cannot work,
        // sent to somebody already wondering why their target is missing.
        let unroutable = field::unroutable(report);
        if unroutable > 0 {
            self.note(&format!(
                "{unroutable} {} had no route from this host and {} never probed.",
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

        if report.is_partial() {
            // Written out rather than passed through `plural`, which knows the
            // four words a scan counts and not this one.
            let failures = report.failures().count();
            let strategies = if failures == 1 {
                "strategy"
            } else {
                "strategies"
            };
            self.warn(&format!(
                "{failures} {strategies} did not run; this run covered less \
                 than it was asked to",
            ))?;
        }

        self.out.flush()
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

/// What produced a source, in a form that names it.
///
/// A foreign scanner attributes itself with its name — `nmap 7.94` — and this
/// engine records a bare version, because a document of its own has never needed
/// telling apart from itself. In a fold it does: `0.13.0` sitting beside
/// `nmap 7.94` leaves a reader to work out which tool the bare number belongs
/// to. So a version that already names its scanner is left alone, and one that
/// does not is this engine's and is named as such.
fn produced_by(engine_version: &str) -> String {
    if engine_version.contains(' ') {
        return engine_version.to_owned();
    }

    format!("{} {engine_version}", zond_engine::format::ENGINE_NAME)
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

    use crate::render::test_support::{Capture, host, scoped};

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
            observed_at: crate::render::test_support::recorded_at(),
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
