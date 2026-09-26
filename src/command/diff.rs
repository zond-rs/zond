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
//! characters, so the two are not going to be confused by accident, and the test
//! is decidable, which "does this look like an id" is not.
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

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use zond_engine::diff::{DiffOptions, ScanDiff};
use zond_engine::export::ExportOptions;
use zond_engine::export::diff::{DiffExporter, HtmlDiffExporter, JsonDiffExporter};

use crate::cli::DiffArgs;
use crate::command;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::diff as render;
use crate::render::style::{Palette, Style};
use crate::settings::{Identity, Presentation};

/// Compares the two scans named and reports what moved.
pub(crate) fn run(
    args: &DiffArgs,
    presentation: Presentation,
    palette: Palette,
) -> Result<Outcome, Error> {
    // Asked once, and asked of each stream separately: a comparison piped into a
    // file must lose its colour while the commentary beside it keeps it. Inert
    // in every mode but `standard`, which is the only one that promises colour.
    let style = Style::records(presentation, palette);
    let narration_style = Style::commentary(presentation, palette);

    // Before either side is read, so a misspelt extension is answered at once
    // rather than after both reports are in hand.
    let destinations = destinations(&args.output)?;

    let (baseline_name, baseline) = command::scan_named(&args.before)?;
    let (current_name, current) = command::scan_named(&args.after)?;

    let redaction = command::reading_redaction(&args.redact)?;
    let options = ExportOptions::new().with_redaction(redaction);

    let diff = ScanDiff::compare(
        &baseline,
        &current,
        &comparison(args, command::configured_identity()?),
    );

    let written = if destinations.is_empty() {
        let mut records = io::stdout().lock();
        let mut narration = io::stderr();

        render::comparing(
            &baseline_name,
            &current_name,
            &diff,
            &mut narration,
            narration_style,
        )?;
        render::write(
            &diff,
            presentation,
            &options,
            &mut records,
            &mut narration,
            style,
            narration_style,
        )?;
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

/// What this comparison was asked to assume.
///
/// The one thing about a comparison a caller has to decide is what makes two
/// records the same host; everything else the engine settles. Separated from
/// [`run`] so the flag's effect can be asserted without a file on disk.
fn comparison(args: &DiffArgs, configured: Option<Identity>) -> DiffOptions {
    // The flag wins, then the file, then the built-in default, which is the
    // order every other setting layers in.
    let identity = args.identity.or(configured).unwrap_or_default();
    DiffOptions::new().with_identity(identity.into())
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

/// A format a comparison can be written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffFormat {
    /// One JSON document, for whatever ingests it.
    Json,
    /// One self-contained page, for whoever reads it.
    Html,
}

impl DiffFormat {
    /// The format a path's extension names, if it names one this build writes.
    fn from_path(path: &Path) -> Option<Self> {
        match path
            .extension()
            .and_then(|extension| extension.to_str())?
            .to_ascii_lowercase()
            .as_str()
        {
            "json" => Some(DiffFormat::Json),
            "html" | "htm" => Some(DiffFormat::Html),
            _ => None,
        }
    }
}

/// Every file this comparison was told to write, with the format each names.
///
/// Resolved before either side is read, so a misspelt extension is answered at
/// once rather than after both reports are in hand.
fn destinations(paths: &[PathBuf]) -> Result<Vec<(PathBuf, DiffFormat)>, Error> {
    paths
        .iter()
        .map(|path| {
            DiffFormat::from_path(path)
                .map(|format| (path.clone(), format))
                .ok_or_else(|| Error::UnknownDiffFormat { path: path.clone() })
        })
        .collect()
}

/// Writes the comparison to each destination, and reports whether every one
/// landed.
///
/// A failure is logged rather than returned, on the same reasoning the report
/// exporter gives: the comparison is already made, and a file that could not be
/// written does not unmake it.
fn write_all(
    destinations: &[(PathBuf, DiffFormat)],
    diff: &ScanDiff,
    options: &ExportOptions,
) -> bool {
    let mut all_written = true;

    for (path, format) in destinations {
        match write_one(*format, path, diff, options) {
            // To stderr: where a comparison went is commentary, and somebody
            // piping its records should still be told.
            Ok(()) => tracing::info!("wrote {}", path.display()),
            Err(e) => {
                crate::export::not_written(path, &e);
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
    format: DiffFormat,
    path: &Path,
    diff: &ScanDiff,
    options: &ExportOptions,
) -> Result<(), zond_engine::export::ExportError> {
    let file = std::fs::File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);

    match format {
        DiffFormat::Json => JsonDiffExporter::new(options.clone()).export(diff, &mut writer)?,
        DiffFormat::Html => HtmlDiffExporter::new(options.clone()).export(diff, &mut writer)?,
    }

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
    use crate::render::test_support::{host, scoped};

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
    /// reported, and appear in the output above, but they are not what the exit
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
    fn a_destination_naming_no_format_is_refused_by_name() {
        let error = destinations(&[PathBuf::from("changes.csv")]).expect_err("refused");
        assert!(error.to_string().contains("changes.csv"), "{error}");
    }

    /// The extension decides, however it was typed. One run can leave the
    /// document a pipeline reads and the page a person does.
    #[test]
    fn the_extension_decides_the_format() {
        let written = destinations(&[
            PathBuf::from("changes.JSON"),
            PathBuf::from("changes.html"),
            PathBuf::from("changes.htm"),
        ])
        .expect("all three name a format");

        let formats: Vec<DiffFormat> = written.into_iter().map(|(_, format)| format).collect();
        assert_eq!(
            formats,
            [DiffFormat::Json, DiffFormat::Html, DiffFormat::Html]
        );
    }

    #[test]
    fn naming_nothing_is_how_a_comparison_reaches_the_terminal() {
        assert!(destinations(&[]).expect("no destinations").is_empty());
    }
}

#[cfg(test)]
mod identity {
    use zond_engine::diff::HostIdentity;
    use zond_engine::model::mac::MacAddr;

    use super::*;
    use crate::render::test_support::{host, scoped};

    fn asked(identity: Option<Identity>) -> DiffArgs {
        DiffArgs {
            before: "a".to_string(),
            after: "b".to_string(),
            identity,
            output: Vec::new(),
            redact: crate::cli::RedactArgs::default(),
        }
    }

    #[test]
    fn the_flag_names_the_engines_policy() {
        assert_eq!(
            comparison(&asked(None), None).identity(),
            HostIdentity::AnyAddress
        );
        assert_eq!(
            comparison(&asked(Some(Identity::Hardware)), None).identity(),
            HostIdentity::Hardware
        );
        assert_eq!(
            comparison(&asked(Some(Identity::Primary)), None).identity(),
            HostIdentity::PrimaryAddress
        );
    }

    /// The flag wins over the file, and the file over the default, which is the
    /// order every other setting layers in.
    #[test]
    fn the_flag_wins_over_the_file_and_the_file_over_the_default() {
        assert_eq!(
            comparison(&asked(None), None).identity(),
            HostIdentity::AnyAddress,
            "nothing said, so the built-in default"
        );
        assert_eq!(
            comparison(&asked(None), Some(Identity::Hardware)).identity(),
            HostIdentity::Hardware,
            "the file, where the command line said nothing"
        );
        assert_eq!(
            comparison(&asked(Some(Identity::Primary)), Some(Identity::Hardware)).identity(),
            HostIdentity::PrimaryAddress,
            "the flag, over a file that said otherwise"
        );
    }

    /// The flag has to reach the comparison, not merely parse.
    ///
    /// A machine whose lease moved shares no address between the two scans, so
    /// only the hardware policy can follow it. Under the default it reads as one
    /// host gone and another arrived, which is what a DHCP segment produces
    /// every night.
    #[test]
    fn hardware_follows_a_machine_whose_lease_moved() {
        let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3);

        let mut before = host(10);
        before.record_mac(mac);
        let mut after = host(60);
        after.record_mac(mac);

        let (before, after) = (
            scoped(vec![before], "192.0.2.0/24"),
            scoped(vec![after], "192.0.2.0/24"),
        );

        let default = ScanDiff::compare(&before, &after, &comparison(&asked(None), None));
        assert_eq!(default.summary().hosts_added.total, 1);
        assert_eq!(default.summary().hosts_removed.total, 1);

        let followed = ScanDiff::compare(
            &before,
            &after,
            &comparison(&asked(Some(Identity::Hardware)), None),
        );
        assert_eq!(followed.summary().hosts_added.total, 0);
        assert_eq!(followed.summary().hosts_removed.total, 0);
        assert_eq!(followed.summary().hosts_changed, 1);
    }
}
