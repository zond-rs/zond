// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # `zond read`
//!
//! One scan in, the same scan out. Nothing is probed and nothing is contacted:
//! the findings are already written down, and this prints them.
//!
//! ## Whatever it was that wrote it
//!
//! A record on this machine, a report this engine exported, an nmap file from
//! somebody else, or a merge of all three. They are all reports, so they all
//! print the same way — through the renderer a scan ends with, because that is
//! the only shape this program draws a host in.
//!
//! Named the way every other command that takes a scan names one: a file on disk
//! is read as a file, and anything else is a record id. See
//! [`scan_named`](super::scan_named).
//!
//! ## Why it exists
//!
//! Because everything else could write a report and nothing could read one back.
//! `zond merge a b -o merged.json` produced a document no command would open,
//! and a merged report carries the name of every document folded into it — which
//! survives export, and survives a second fold. This is what shows them.
//!
//! It converts, for the same reason: the report went in through one reader and
//! comes out through whichever writer `-o` names, so `zond read q1.xml -o
//! q1.json` is a conversion and needed no code to become one.
//!
//! ## Where it goes
//!
//! The terminal, unless a file is named, and then only the file. A scan prints
//! *and* writes because somebody is watching it happen and the file is for
//! later. Nobody is watching a document be read. Naming a file is saying where
//! this goes.

use zond_engine::ScanReport;

use crate::cli::ReadArgs;
use crate::command;
use crate::diagnostics::Verbosity;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::style::Palette;
use crate::render::{MergeSource, Phase, renderer};
use crate::settings::Presentation;

/// Prints the scan named, or writes it where it was asked for.
pub(crate) fn run(
    args: &ReadArgs,
    presentation: Presentation,
    verbosity: Verbosity,
    palette: Palette,
    reasons: bool,
) -> Result<Outcome, Error> {
    // Before the document is read, so a misspelt extension is answered at once
    // rather than after the findings are in hand.
    let destinations = args.export.destinations()?;

    let (name, report) = command::scan_named(&args.source)?;

    // From this machine's settings rather than from the document. What a scan
    // saw is in the file; whether to mask it on the way out belongs to whoever
    // is reading it now.
    let redaction = command::redaction(&command::engine_settings(None)?.config);

    let mut renderer = renderer(presentation, verbosity, palette, reasons);

    // Borrowed from `report`, so scoped to end before the export below takes it
    // by reference again.
    {
        let sources = folded_from(&report);
        let phase = if sources.is_empty() {
            // Dated only where the document says: a report carrying no phase has
            // no time of its own, and reading it is not a reason to give it one.
            Phase::Recorded {
                id: &name,
                started_at: (!report.phases().is_empty()).then(|| report.started_at()),
                produced_by: report.engine_version(),
            }
        } else {
            Phase::Folded {
                id: &name,
                sources: &sources,
            }
        };

        renderer.started(phase, redaction)?;
    }

    let written = command::deliver(&report, &destinations, redaction, renderer.as_mut())?;

    // The scan's own verdict, carried through: a record of a run that left
    // ground uncovered reports as partial, the same as the run did.
    let outcome = command::outcome(&report, false);

    // A document that could not be written where it was asked is a request that
    // half happened, whatever the scan it describes amounted to.
    Ok(if written { outcome } else { Outcome::Partial })
}

/// The documents this report was folded from, oldest first, or nothing where it
/// was not folded at all.
///
/// Read back out of the phases, each of which carries the name it was folded
/// under. Several phases share a source — a scan that swept and then port
/// scanned contributes two — so they are gathered rather than listed, and the
/// oldest phase of each dates it, since that is the source's own beginning
/// rather than whichever of its phases happens to come last.
///
/// A source folded in without a name still counts: it produced findings, and a
/// listing that dropped it would report fewer sources than the fold had. It is
/// named for what produced it, which is all the document says about it.
fn folded_from(report: &ScanReport) -> Vec<MergeSource<'_>> {
    let mut sources: Vec<MergeSource<'_>> = Vec::new();

    for phase in report.phases() {
        let Some(origin) = phase.origin() else {
            continue;
        };

        let name = origin.label().unwrap_or(UNNAMED);
        match sources
            .iter_mut()
            .find(|source| source.name == name && source.engine_version == origin.engine_version())
        {
            Some(seen) => seen.observed_at = seen.observed_at.min(phase.started_at()),
            None => sources.push(MergeSource {
                name,
                engine_version: origin.engine_version(),
                observed_at: phase.started_at(),
                // Not recoverable from a fold: see the field.
                hosts: None,
            }),
        }
    }

    sources.sort_by_key(|source| source.observed_at);
    sources
}

/// What a source folded in without a name is called.
///
/// An origin carries a label only where the caller supplied one, and the engine
/// has no word for a document it did not open. Every source `zond merge` folds
/// is named, so this is for a report some other program built.
const UNNAMED: &str = "unnamed source";

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
    use zond_engine::merge::{Merge, MergeOptions};

    use super::*;
    use crate::render::test_support::{host, recorded_at, scoped_at};

    const DAY: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

    /// A report that was not folded has no sources to list, and says so by
    /// having none rather than by listing itself as one.
    #[test]
    fn a_scan_was_folded_from_nothing() {
        let scan = scoped_at(vec![host(1)], "192.0.2.0/24", recorded_at());
        assert!(folded_from(&scan).is_empty());
    }

    /// The names a fold was made under come back out of the document, oldest
    /// first, which is the order the fold itself used.
    #[test]
    fn a_fold_names_its_sources_when_it_is_read_back() {
        let mut merge = Merge::new(MergeOptions::default());
        merge.add_from(
            "today",
            scoped_at(vec![host(2)], "192.0.2.0/24", recorded_at() + DAY),
        );
        merge.add_from(
            "yesterday",
            scoped_at(vec![host(1)], "192.0.2.0/24", recorded_at()),
        );
        let folded = merge.finish();

        let named: Vec<&str> = folded_from(&folded)
            .iter()
            .map(|source| source.name)
            .collect();
        assert_eq!(named, ["yesterday", "today"]);
    }

    /// A source that contributed several phases is one source.
    ///
    /// A scan that swept and then port scanned leaves two phases under one name,
    /// and listing it twice would report a fold of more documents than there
    /// were.
    #[test]
    fn a_source_of_several_phases_is_listed_once() {
        let two_phases = {
            let mut merge = Merge::new(MergeOptions::default());
            merge.add_from(
                "sweep",
                scoped_at(vec![host(1)], "192.0.2.0/24", recorded_at()),
            );
            merge.add_from(
                "ports",
                scoped_at(vec![host(1)], "192.0.2.0/24", recorded_at() + DAY),
            );
            merge.finish()
        };
        assert_eq!(two_phases.phases().len(), 2);

        // Folded again under one name, so both of its phases carry `first` —
        // no. They keep the names they already had, which is the point: an
        // origin already on a phase is left alone.
        let mut merge = Merge::new(MergeOptions::default());
        merge.add_from("folded-again", two_phases);
        merge.add_from(
            "fresh",
            scoped_at(vec![host(3)], "192.0.2.0/24", recorded_at() + DAY * 2),
        );
        let twice = merge.finish();

        let named: Vec<&str> = folded_from(&twice).iter().map(|s| s.name).collect();
        assert_eq!(
            named,
            ["sweep", "ports", "fresh"],
            "a second fold relabelled what its sources were already called"
        );
    }

    /// Nothing read back out of a fold claims to know what each source held.
    #[test]
    fn a_read_back_fold_does_not_claim_a_host_count_it_cannot_have() {
        let mut merge = Merge::new(MergeOptions::default());
        merge.add_from("a", scoped_at(vec![host(1)], "192.0.2.0/24", recorded_at()));
        merge.add_from(
            "b",
            scoped_at(vec![host(2)], "192.0.2.0/24", recorded_at() + DAY),
        );

        let folded = merge.finish();
        assert!(folded_from(&folded).iter().all(|s| s.hosts.is_none()));
    }
}
