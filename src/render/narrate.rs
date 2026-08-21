// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The running commentary
//!
//! The standard-error half of a run: the header, the hosts as they are found,
//! the interruption, and the summary. Shared by every presentation, because none
//! of it is presentation — it is the same sentences whatever the records on the
//! other stream look like.
//!
//! What a mode decides for itself is the records: see
//! [`minimal`](super::minimal) and [`pipe`](super::pipe).

use std::collections::HashSet;
use std::io::{self, Write};
use std::net::IpAddr;

use zond_engine::export::Redaction;
use zond_engine::scanner::report::ScanKind;
use zond_engine::{Host, ScanReport};

use crate::diagnostics::Verbosity;
use crate::render::field::plural;
use crate::render::{Phase, field};

/// Writes the commentary, or does not, depending on the verbosity.
pub(crate) struct Narrator {
    out: Box<dyn Write>,
    verbosity: Verbosity,
    announced: HashSet<IpAddr>,
    reader: field::Reader,
}

impl Narrator {
    /// Narrating to `out`, which is standard error in a real run.
    pub(crate) fn new(out: Box<dyn Write>, verbosity: Verbosity) -> Self {
        Self {
            out,
            verbosity,
            announced: HashSet::new(),
            reader: field::Reader::default(),
        }
    }

    /// Adopts the masking policy for the run about to start.
    ///
    /// The live "found" lines carry addresses too, not only the results.
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

    /// Writes one line, if this run narrates.
    fn say(&mut self, line: &str) -> io::Result<()> {
        if !self.verbosity.narrates() {
            return Ok(());
        }
        writeln!(self.out, "{line}")
    }

    /// What is about to happen, and how much of it.
    pub(crate) fn started(&mut self, phase: Phase<'_>, redaction: Redaction) -> io::Result<()> {
        self.redact(redaction);

        let line = match phase {
            Phase::Discovery { targets } => {
                let count = targets.len();
                format!(
                    "discovering {count} {} ({targets})",
                    plural(count, "address")
                )
            }
            Phase::PortScan { targets } => {
                let hosts = targets.hosts();
                let probes = targets.probes();
                format!(
                    "scanning {probes} {} across {hosts} {} ({targets})",
                    plural(probes, "probe"),
                    plural(hosts, "host"),
                )
            }
        };

        self.say(&line)?;
        self.out.flush()
    }

    /// A host found, announced once however many times it is updated.
    pub(crate) fn found(&mut self, host: &Host) -> io::Result<()> {
        if !self.announced.insert(host.primary_ip()) {
            return Ok(());
        }
        self.say(&format!("found {}", self.reader.primary_address(host)))?;
        self.out.flush()
    }

    /// The user asked the scan to stop.
    pub(crate) fn interrupted(&mut self) -> io::Result<()> {
        self.say("interrupted; stopping and reporting what was found so far")?;
        self.out.flush()
    }

    /// What the run amounted to, and anything that qualifies it.
    pub(crate) fn summary(&mut self, report: &ScanReport) -> io::Result<()> {
        let summary = field::summary(report);
        let scanned = field::addresses_scanned(report);
        let elapsed = report.elapsed().as_secs_f64();

        self.say("")?;
        self.say(&format!(
            "{} host{} up of {scanned} address{} in {elapsed:.2}s",
            summary.hosts_alive,
            if summary.hosts_alive == 1 { "" } else { "s" },
            if scanned == 1 { "" } else { "es" },
        ))?;

        // A discovery sweep probes no ports, and "0 open ports" would read as a
        // finding rather than as nothing having been asked.
        if summary.ports_total > 0 {
            self.say(&format!(
                "{} open port{} of {} probed",
                summary.ports_open,
                if summary.ports_open == 1 { "" } else { "s" },
                summary.ports_total,
            ))?;
        }

        // After the count rather than before the scan: both notes say the count
        // is an undercount, which matters when somebody is looking at it. The
        // engine already announced the privilege level; this adds the remedy.
        if !field::was_privileged(report) {
            self.say(match field::kind(report) {
                Some(ScanKind::PortScan) => {
                    "note: ran without raw sockets, so every port was tested by \
                     completing a connection. Run with sudo for SYN scanning, \
                     which is faster, less visible, and the only way to ask a \
                     port anything other than \"will you accept\"."
                }
                _ => {
                    "note: ran without raw sockets, so this was TCP connect \
                     attempts against a few common ports. Run with sudo for ARP \
                     and ICMPv6 discovery, which finds hosts this cannot."
                }
            })?;
        }

        // The result most likely to be read as a broken tool rather than an
        // answer: nothing scanned, and no reason given for it.
        let skipped = field::skipped_as_down(report);
        if skipped > 0 {
            self.say(&format!(
                "note: {skipped} {} answered no liveness probe and {} not port-scanned. \
                 Pass --assume-up to probe {} anyway.",
                plural(skipped, "address"),
                if skipped == 1 { "was" } else { "were" },
                if skipped == 1 { "it" } else { "them" },
            ))?;
        }

        if report.is_partial() {
            let failures = report.failures().count();
            self.say(&format!(
                "warning: {failures} strateg{} did not run; this scan covered less \
                 than it was asked to",
                if failures == 1 { "y" } else { "ies" },
            ))?;
        }

        self.out.flush()
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

    /// "address" is the word that caught this out: appending a bare `s` to it
    /// produces "addresss", which every discovery header printed.
    #[test]
    fn a_word_ending_in_s_takes_es() {
        assert_eq!(plural(16, "address"), "addresses");
        assert_eq!(plural(1, "address"), "address");
    }

    #[test]
    fn every_other_word_takes_s() {
        assert_eq!(plural(0, "host"), "hosts");
        assert_eq!(plural(1, "host"), "host");
        assert_eq!(plural(3, "probe"), "probes");
    }
}
