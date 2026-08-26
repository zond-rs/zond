// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Writing a report to a file
//!
//! The terminal shows a scan; this writes it down. Both happen. A run that
//! wrote a file still prints, because the person watching it asked for a scan
//! and the file is for later.
//!
//! `zond read` and `zond merge` are where that is not so, and for the same
//! reason: nobody is watching a document be read or folded, so naming a file
//! there is naming where the report goes rather than adding a copy of it. See
//! [`read`](crate::command::read).
//!
//! ## Three ways to name a destination, and one that decides the format
//!
//! - `-o report.json` lets the extension say the format, which is the spelling
//!   most people want. [`ExportFormat::from_path`] resolves it, so every front
//!   end of this engine reads an extension the same way.
//! - `--output-as xml=report.out` is for a name whose extension would say the
//!   wrong thing, or nothing.
//! - `--output-all engagement` writes every format this build can produce, each
//!   under its own extension.
//!
//! Nmap's spellings are accepted for the same thing; see [`nmap`](crate::nmap).
//!
//! ## Destinations are resolved before the scan, not after it
//!
//! A misspelt extension is a mistake the person made in the first second of a
//! run that may take three hours. Finding out at the end, with the report in
//! memory and nowhere to put it, is the worst moment to be told. So
//! [`Destination::resolve`] runs before a probe is sent, and a run that cannot
//! write where it was told does not start.
//!
//! What it cannot check that early is whether the disk will still take the
//! bytes. That failure is reported and does not discard the scan: the terminal
//! already has the results, and a run that found things is not a run that
//! failed.

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use zond_engine::ScanReport;
use zond_engine::export::{ExportError, ExportFormat, ExportOptions, Redaction};

use crate::error::Error;

/// A file a report is to be written to, and the format to write it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Destination {
    path: PathBuf,
    format: ExportFormat,
}

impl Destination {
    /// Works out every file this run was told to write.
    ///
    /// Refuses rather than guesses: a path whose extension names no format this
    /// build can write is a mistake, and writing JSON into a file called
    /// `report.txt` would be a worse answer than saying so.
    pub(crate) fn resolve(
        by_extension: &[PathBuf],
        tagged: &[FormatAndPath],
        every_format: Option<&Path>,
    ) -> Result<Vec<Self>, Error> {
        let mut destinations = Vec::new();

        for path in by_extension {
            let Some(format) = ExportFormat::from_path(path) else {
                return Err(Error::UnknownExportFormat {
                    path: path.clone(),
                    known: known_formats(),
                });
            };
            destinations.push(Self {
                path: path.clone(),
                format,
            });
        }

        for tagged in tagged {
            destinations.push(Self {
                path: tagged.path.clone(),
                format: tagged.format,
            });
        }

        if let Some(base) = every_format {
            for format in ExportFormat::all() {
                destinations.push(Self {
                    path: base.with_extension(format.extension()),
                    format: *format,
                });
            }
        }

        Ok(destinations)
    }
}

/// A format named alongside the file to write it to: `xml=report.out`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FormatAndPath {
    format: ExportFormat,
    path: PathBuf,
}

impl std::str::FromStr for FormatAndPath {
    type Err = Error;

    /// Parses `FORMAT=PATH`.
    ///
    /// Split at the *first* `=`, since a path may hold one and a format name
    /// never does.
    fn from_str(written: &str) -> Result<Self, Self::Err> {
        let (format, path) = written
            .split_once('=')
            .ok_or_else(|| Error::MalformedOutputAs {
                written: written.to_owned(),
                known: known_formats(),
            })?;

        let format =
            ExportFormat::from_extension(format).ok_or_else(|| Error::UnknownFormatName {
                named: format.to_owned(),
                known: known_formats(),
            })?;

        if path.is_empty() {
            return Err(Error::MalformedOutputAs {
                written: written.to_owned(),
                known: known_formats(),
            });
        }

        Ok(Self {
            format,
            path: PathBuf::from(path),
        })
    }
}

/// The formats this build can write, for a message that has to list them.
///
/// Read from the engine rather than spelled here, so a build without a format
/// feature never offers it.
pub(crate) fn known_formats() -> String {
    ExportFormat::all()
        .iter()
        .map(|format| format.extension())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Writes `report` to every destination, reporting each as it lands.
///
/// One failure does not stop the others: a report that reached three of four
/// files is worth more than one that reached none because the fourth was on a
/// full disk. Returns whether every write succeeded, which is what the exit
/// code is drawn from.
pub(crate) fn write_all(
    destinations: &[Destination],
    report: &ScanReport,
    redaction: Redaction,
) -> bool {
    let options = ExportOptions::new().with_redaction(redaction);
    let mut all_written = true;

    for destination in destinations {
        match write_one(destination, report, options.clone()) {
            // To stderr: where a report went is commentary on the run, and
            // somebody piping its records should still be told.
            Ok(()) => tracing::info!("wrote {}", destination.path.display()),
            Err(e) => {
                tracing::error!("could not write {}: {e}", destination.path.display());
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
    destination: &Destination,
    report: &ScanReport,
    options: ExportOptions,
) -> Result<(), ExportError> {
    use std::io::Write;

    let mut out = BufWriter::new(File::create(&destination.path)?);
    destination
        .format
        .exporter(options)
        .export(report, &mut out)?;
    out.flush()?;
    Ok(())
}
