// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a run looks like
//!
//! One trait, one implementation per [`Presentation`], and the function that
//! picks between them. The trait is what keeps the commands from knowing about
//! columns.
//!
//! - [`pipe`] is every field, tab-separated, in fixed units, with no padding and
//!   no heading. The only mode whose output is a stable interface.
//! - [`minimal`] is a tagged block per host, for reading.
//! - [`fancy`] is a numbered block per host, with colour and the transport
//!   hanging under a port. The default, and what every command draws in.
//!
//! `pipe` is not a step on that ladder; it is a different audience.
//!
//! The three drawn modes share [`narrate`] and [`field`]: the same sentences on
//! standard error, and one answer to what a vendor or a round-trip time is.
//! What a mode decides for itself is the records.
//!
//! **Failures are not a renderer's business.** The engine logs a failed strategy
//! *and* records it, and [`diagnostics`](crate::diagnostics) already prints the
//! log. A renderer gets the finished [`ScanReport`], which says how much of the
//! scan was covered.
//!
//! **Records to standard output, commentary to standard error**, in every mode.
//! A renderer is the only thing here that writes to either.

// One module per presentation.
pub(crate) mod fancy;
pub(crate) mod minimal;
pub(crate) mod pipe;

// What the scans on this machine look like. Not a `Renderer`: see the module.
pub(crate) mod journal;

// What changed between two of them. Not a `Renderer` either, and for the same
// reason.
pub(crate) mod diff;

// What a fold of several of them says beside the report it produces. The report
// is a `ScanReport` and prints through the renderer a scan's does, so this is
// only the lines that are about the command rather than about the network.
pub(crate) mod merge;

// The shape every record is drawn in: one header line and its labelled facts,
// with the whole listing measured before any of it is drawn. A scan, a
// comparison and a stored record are the same six line types.
pub(crate) mod block;

// The line that says a scan is still running, held at the bottom of standard
// error and rewritten in place. `fancy` alone starts one.
pub(crate) mod progress;

// Plumbing they share: the field values, the commentary on stderr, and whether
// this terminal takes colour at all.
pub(crate) mod field;
pub(crate) mod narrate;
pub(crate) mod style;

#[cfg(test)]
pub(crate) mod test_support;

use std::io;

use zond_engine::ScanReport;
use zond_engine::export::Redaction;

use crate::diagnostics::Verbosity;
use crate::render::style::Palette;
use crate::settings::Presentation;
use crate::target::{ScanTargets, Targets};

/// What a run is about to do.
///
/// Facts rather than a pre-composed sentence, so the phrasing stays in the
/// renderer. The two scanning variants are separate because the phases are
/// counted in different units: a sweep in addresses, a port scan in probes.
#[derive(Clone, Copy)]
pub(crate) enum Phase<'a> {
    /// Finding which hosts are alive.
    Discovery {
        /// What was asked about.
        targets: &'a Targets,
    },
    /// Finding which of the named hosts' ports are open.
    PortScan {
        /// What was asked about, and on which ports.
        targets: &'a ScanTargets,
    },
    /// Watching a link, having sent nothing.
    ///
    /// The links are the whole of the ground: a watch covers no address, so
    /// there is no range to announce and no total to count towards. What a
    /// reader wants before it starts is where it is standing and how long it
    /// intends to stand there.
    Listen {
        /// The links being read.
        links: &'a [zond_engine::model::ip::scoped::Zone],
        /// How long it will run, or `None` for until it is stopped.
        span: Option<std::time::Duration>,
    },
    /// Reading a scan back out of the record it left, rather than running one.
    ///
    /// Nothing is probed, so there is no ground about to be covered to
    /// announce. It is still a phase, because this is where a renderer is told
    /// the masking policy for what it is about to print.
    Recorded {
        /// What it was named on the command line: a path, or a record id.
        id: &'a str,
        /// When the scan it holds began, where the document says.
        ///
        /// `None` for one that carries no phase to date it by — a report from
        /// another scanner that recorded no timing, or a record of a scan that
        /// stopped before it wrote a phase down. Saying nothing beats dating it
        /// to the moment it was read.
        started_at: Option<std::time::SystemTime>,
        /// What produced the findings, as that scanner attributed itself.
        ///
        /// Passed whoever produced them, and named only where that was not this
        /// engine — the renderer decides, so the one rule for telling those
        /// apart stays in one place. A person reading somebody else's file has
        /// no other way to see whose findings they are: the document says so and
        /// the terminal did not.
        produced_by: &'a str,
    },
    /// Reading a report that was folded out of documents rather than measured
    /// by one run.
    ///
    /// Told apart from [`Recorded`](Self::Recorded) because a fold has no single
    /// scan to date it by, and because what it does have — which documents went
    /// into it — is the thing a reader needs and the thing nothing else would
    /// show them. It is in the file: every folded phase carries the name it was
    /// folded under.
    Folded {
        /// What it was named on the command line.
        id: &'a str,
        /// The documents it was folded from, oldest first.
        sources: &'a [MergeSource<'a>],
    },
    /// Folding several documents into one report, rather than running a scan.
    ///
    /// Nothing is probed. The sources arrive in the order they will be folded,
    /// oldest first, because a fold answers every disagreement by taking the
    /// newest source's word and a reader who cannot see which source that is
    /// cannot check the answer.
    Merged {
        /// Every document going in, oldest first.
        sources: &'a [MergeSource<'a>],
    },
}

/// One document going into a merge, as the command that read it knows it.
///
/// What a person checks before trusting a merged report is that the sources are
/// the ones they meant and that the newest of them is the one whose answers they
/// expect to win. So this carries the name they typed rather than the path it
/// resolved to, and the clock the fold itself orders by rather than any other
/// time in the document.
#[derive(Clone, Copy)]
pub(crate) struct MergeSource<'a> {
    /// What it was called on the command line: a path, or a record id.
    pub(crate) name: &'a str,
    /// What produced it, as that scanner attributed itself. `nmap 7.94` for a
    /// document read out of nmap's XML.
    pub(crate) engine_version: &'a str,
    /// The moment its findings are as of, which is what the fold orders by.
    pub(crate) observed_at: std::time::SystemTime,
    /// How many hosts it holds, before any of them are folded together.
    ///
    /// `None` where that can no longer be known, which is every source of a
    /// report read back from disk: a fold puts the hosts of every document into
    /// one set, and no source's own count survives that. Available only to the
    /// command doing the folding, which still has the documents.
    pub(crate) hosts: Option<usize>,
}

/// Everything a run shows, as it happens.
///
/// Every method returns [`io::Result`] rather than swallowing failures: a closed
/// standard output is how `zond discover lan | head` ends, and the command has
/// to hear about it rather than scan a network into a pipe nobody is reading.
pub(crate) trait Renderer {
    /// A run is about to start, under `redaction`.
    ///
    /// The masking policy arrives here rather than at construction because it
    /// comes from the resolved configuration. This is the first moment it is
    /// known, and the last at which it can be delivered.
    fn started(&mut self, phase: Phase<'_>, redaction: Redaction) -> io::Result<()>;

    /// How much the run has turned up so far: hosts alive, and open ports
    /// across them.
    ///
    /// Called for every update the engine announces, which for a port scan is
    /// once per port that settles.
    ///
    /// **Counts rather than the host itself.** Reaching a host means cloning its
    /// port map, and doing that once per port is quadratic in the ports of one
    /// address: on twenty thousand ports it turned a one-second scan into an
    /// eighteen-second one, all of it spent copying findings nobody read. The
    /// figures come off a borrow instead, and the whole of every host arrives
    /// once, in the report.
    ///
    /// Defaulted, because the two modes that promise a fixed shape have nothing
    /// to do with a figure that changes.
    fn progressed(&mut self, _hosts: usize, _open: usize) -> io::Result<()> {
        Ok(())
    }

    /// The user asked the scan to stop. It is winding down, and will still
    /// report what it found.
    fn interrupted(&mut self) -> io::Result<()>;

    /// The scan is over. This is where the results are written.
    fn finished(&mut self, report: &ScanReport) -> io::Result<()>;
}

/// The renderer to use for this run.
///
/// The one place presentation is chosen. Every mode is built, so this cannot
/// fail: a name that is not a mode was already refused when the settings file or
/// the command line was read.
pub(crate) fn renderer(
    presentation: Presentation,
    verbosity: Verbosity,
    palette: Palette,
    reasons: bool,
) -> Box<dyn Renderer> {
    match presentation {
        // `pipe` takes no `reasons`, and that is the mode's own promise rather
        // than an omission: its fields are a stable interface, and adding one
        // because a flag was passed would move every field after it for every
        // script already reading them. A program that wants the evidence reads
        // the JSON, which has carried all of it — the packet, the TTL, the round
        // trip — since long before there was a flag to ask for it.
        Presentation::Pipe => Box::new(pipe::PipeRenderer::to_terminal(verbosity)),
        Presentation::Minimal => {
            Box::new(minimal::MinimalRenderer::to_terminal(verbosity, reasons))
        }
        Presentation::Fancy => Box::new(fancy::FancyRenderer::to_terminal(
            verbosity, palette, reasons,
        )),
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

    /// Every mode named produces a renderer. Nothing here can refuse, which is
    /// the point: a mode that is named but not built used to be answered with
    /// "not ready", and there is no longer such a mode.
    #[test]
    fn every_mode_produces_a_renderer() {
        for mode in Presentation::ALL {
            let _: Box<dyn Renderer> =
                renderer(mode, Verbosity::default(), Palette::default(), false);
        }
    }
}
