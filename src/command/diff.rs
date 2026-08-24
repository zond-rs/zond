// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # `zond diff`
//!
//! Two scans in, what changed out. Nothing is probed and nothing is contacted:
//! both sides are already written down, and this reads them.
//!
//! ## Either side may be a file or a record
//!
//! A side that names a file that exists is read as a file, and anything else is
//! taken for a record on this machine. A record's id is sixteen hexadecimal
//! characters, so the two are not going to be confused by accident — and the
//! test is decidable, which "does this look like an id" is not.
//!
//! That gives every combination without a flag to say which is which:
//!
//! ```text
//! zond diff latest 20aa1f3c8e5b0d92     two records
//! zond diff baseline.json latest        an archive against tonight
//! zond diff q1.xml q2.xml               two nmap files, neither of them ours
//! ```
//!
//! The last is the one worth pointing at. A comparison takes reports and asks
//! nothing about where they came from, so a team with a year of nmap output in
//! an engagement repository can use this against files this engine never wrote.
//!
//! ## What the exit status says
//!
//! `0` for no change and `4` for changes, so a scheduled job is
//! `zond diff last tonight || notify`. **Only confirmed changes count**: a
//! change the other scan is not known to have looked for is a fact about the
//! scan rather than about the network, and waking somebody for one is how a
//! monitor teaches its owner to ignore it. See [`exit`](crate::exit).

use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};

use zond_engine::ScanReport;
use zond_engine::diff::ScanDiff;
use zond_engine::export::ExportOptions;
use zond_engine::export::diff::{DiffExporter, JsonDiffExporter};
use zond_engine::import::report::{ReportFormat, ReportOptions};
use zond_engine::journal::store;

use crate::cli::DiffArgs;
use crate::command;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::diff as render;
use crate::settings::Presentation;

/// Compares the two scans named and reports what moved.
pub(crate) fn run(args: &DiffArgs, presentation: Presentation) -> Result<Outcome, Error> {
    // Before either side is read, so a misspelt extension is answered at once
    // rather than after both reports are in hand.
    let destinations = destinations(&args.output)?;

    let (baseline_name, baseline) = side(&args.before)?;
    let (current_name, current) = side(&args.after)?;

    // From this machine's settings rather than from either record. What a scan
    // saw is in the file; whether to mask it on the way out belongs to whoever
    // is reading it now.
    let redaction = command::redaction(&command::engine_settings(None)?.config);
    let options = ExportOptions::new().with_redaction(redaction);

    let diff = ScanDiff::between(&baseline, &current);

    let written = if destinations.is_empty() {
        let mut records = io::stdout().lock();
        let mut narration = io::stderr();

        render::comparing(&baseline_name, &current_name, &diff, &mut narration)?;
        render::write(&diff, presentation, &options, &mut records, &mut narration)?;
        true
    } else {
        write_all(&destinations, &diff, &options)
    };

    // A comparison that could not be written where it was asked is a request
    // that half happened, whatever it found.
    Ok(if written {
        outcome(&diff)
    } else {
        Outcome::Partial
    })
}

/// What a comparison ends as.
///
/// Only a change the other scan is known to have looked for counts. A widened
/// scan turns up hosts nobody had checked, and reporting those as findings is
/// the failure the whole comparison is arranged to avoid.
fn outcome(diff: &ScanDiff) -> Outcome {
    let summary = diff.summary();

    let confirmed = summary.hosts_added.confirmed
        + summary.hosts_removed.confirmed
        + summary.hosts_changed
        + summary.ports_opened.confirmed
        + summary.ports_closed.confirmed
        + summary.ports_changed;

    if confirmed > 0 {
        Outcome::Changed
    } else {
        Outcome::Complete
    }
}

/// One side of the comparison: a file if that is what it names, and a record on
/// this machine otherwise.
///
/// Returns what to call it as well, since a person reading the commentary wants
/// the name they typed rather than a path this resolved it to.
fn side(name: &str) -> Result<(String, ScanReport), Error> {
    let path = Path::new(name);
    if path.is_file() {
        return Ok((name.to_owned(), from_file(path)?));
    }

    let entries = crate::command::journal::read()?;
    let entry = crate::command::journal::find(&entries, name)?;

    Ok((entry.manifest.id.clone(), store::report(&entry.directory)?))
}

/// A report read out of a document.
///
/// The extension decides the format, and a name that says nothing this build
/// reads is refused rather than sniffed: a file called `scan.txt` is a mistake
/// worth naming, and guessing at it would have this read an nmap file as JSON
/// and blame the contents.
fn from_file(path: &Path) -> Result<ScanReport, Error> {
    let Some(format) = ReportFormat::from_path(path) else {
        return Err(Error::UnknownReportFormat {
            path: path.to_path_buf(),
        });
    };

    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::new(file);

    Ok(format.read(&mut reader, ReportOptions::new())?)
}

/// Every file this comparison was told to write.
fn destinations(paths: &[PathBuf]) -> Result<Vec<PathBuf>, Error> {
    for path in paths {
        let json = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));

        if !json {
            return Err(Error::UnknownDiffFormat { path: path.clone() });
        }
    }

    Ok(paths.to_vec())
}

/// Writes the comparison to each destination, and reports whether every one
/// landed.
///
/// A failure is logged rather than returned, on the same reasoning the report
/// exporter gives: the comparison is already made, and a file that could not be
/// written does not unmake it.
fn write_all(destinations: &[PathBuf], diff: &ScanDiff, options: &ExportOptions) -> bool {
    let exporter = JsonDiffExporter::new(options.clone());
    let mut all_written = true;

    for path in destinations {
        match write_one(&exporter, path, diff) {
            // To stderr: where a comparison went is commentary, and somebody
            // piping its records should still be told.
            Ok(()) => tracing::info!("wrote {}", path.display()),
            Err(e) => {
                tracing::error!("could not write {}: {e}", path.display());
                all_written = false;
            }
        }
    }

    all_written
}

/// Writes one file, buffered, and flushes before reporting success.
///
/// The flush is the point: a `BufWriter` dropped without one swallows the error
/// from the last write, which is exactly the write that fills a disk.
fn write_one(
    exporter: &JsonDiffExporter,
    path: &Path,
    diff: &ScanDiff,
) -> Result<(), zond_engine::export::ExportError> {
    let file = std::fs::File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);

    exporter.export(diff, &mut writer)?;
    writer.flush()?;
    Ok(())
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
    use zond_engine::{Port, PortState, Protocol};

    use super::*;
    use crate::exit::Code;
    use crate::render::diff::tests::scoped;
    use crate::render::test_support::host;

    #[test]
    fn two_scans_of_an_unchanged_network_exit_zero() {
        let report = scoped(vec![host(1), host(2)], "192.0.2.0/24");
        let diff = ScanDiff::between(&report, &report);

        assert_eq!(outcome(&diff), Outcome::Complete);
        assert_eq!(outcome(&diff).code(), Code::Success);
    }

    #[test]
    fn a_port_that_opened_where_both_scans_looked_exits_four() {
        let mut later = host(1);
        later.add_port(Port::new(8080, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(
            &scoped(vec![host(1)], "192.0.2.0/24"),
            &scoped(vec![later], "192.0.2.0/24"),
        );

        assert_eq!(outcome(&diff), Outcome::Changed);
        assert_eq!(outcome(&diff).code(), Code::Changed);
        assert_eq!(Code::Changed.as_u8(), 4);
    }

    /// The rule the whole comparison is arranged around, at the one point where
    /// losing it would wake somebody at three in the morning.
    ///
    /// A wider scan turns up hosts the earlier one never walked. Those are
    /// reported — they are in the output above — and they are not what the exit
    /// status is for.
    #[test]
    fn a_wider_scan_alone_does_not_exit_four() {
        let diff = ScanDiff::between(
            &scoped(vec![host(1)], "192.0.2.0/26"),
            &scoped(vec![host(1), host(200)], "192.0.2.0/24"),
        );

        assert!(
            !diff.is_empty(),
            "the host is still reported, or this test proves nothing"
        );
        assert_eq!(diff.summary().hosts_added.total, 1);
        assert_eq!(diff.summary().hosts_added.confirmed, 0);

        assert_eq!(
            outcome(&diff),
            Outcome::Complete,
            "nobody had looked for that host, so its arrival is news about the scan"
        );
    }

    /// And a confirmed change alongside an unconfirmed one still counts.
    #[test]
    fn a_confirmed_change_beside_an_unconfirmed_one_still_exits_four() {
        let mut later = host(1);
        later.add_port(Port::new(8080, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(
            &scoped(vec![host(1)], "192.0.2.0/26"),
            &scoped(vec![later, host(200)], "192.0.2.0/24"),
        );

        assert_eq!(outcome(&diff), Outcome::Changed);
    }

    // -----------------------------------------------------------------------
    // Where a comparison is written
    // -----------------------------------------------------------------------

    #[test]
    fn a_destination_that_is_not_json_is_refused_by_name() {
        let error = destinations(&[PathBuf::from("changes.csv")]).expect_err("refused");
        assert!(error.to_string().contains("changes.csv"), "{error}");
    }

    #[test]
    fn json_is_accepted_however_it_is_spelled() {
        assert!(destinations(&[PathBuf::from("changes.JSON")]).is_ok());
        assert!(destinations(&[PathBuf::from("a.json"), PathBuf::from("b.json")]).is_ok());
    }

    #[test]
    fn naming_nothing_is_how_a_comparison_reaches_the_terminal() {
        assert_eq!(
            destinations(&[]).expect("no destinations"),
            Vec::<PathBuf>::new()
        );
    }
}
