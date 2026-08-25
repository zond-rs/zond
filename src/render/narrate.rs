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
use crate::render::{Phase, field};

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
            Phase::Recorded { id, started_at } => (
                format!("reading {id}, a scan from {}", field::timestamp(started_at)),
                None,
            ),
        };

        self.remark(&line)?;
        if let Some(excluded) = excluded {
            self.remark(&excluded)?;
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
        let elapsed = report.elapsed().as_secs_f64();

        // The ground covered is named only where the record says what it was.
        // A report from another scanner often does not, and "3 hosts up of 0
        // addresses" reads as a broken tool rather than as an absence.
        let ground = match field::addresses_scanned(report) {
            Some(scanned) => format!(" of {scanned} {}", plural(scanned, "address")),
            None => String::new(),
        };

        self.say("")?;
        self.remark(&format!(
            "{} {} up{ground} in {elapsed:.2}s",
            summary.hosts_alive,
            plural(summary.hosts_alive as u128, "host"),
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
