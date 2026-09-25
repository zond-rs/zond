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
//! Each file is opened then too, and held until its report is written. A path
//! that cannot be opened, in a directory that is not there or one that is not
//! the user's, is the same mistake made in the same second. And a file asked
//! for once the scan is over asks for a descriptor at the moment the process
//! is likeliest to have none: a scan run with few to spare ends with every one
//! of them taken by what the process picked up on the way, its runtime, its
//! signal handling, the platform's own libraries, and nothing the scan gives
//! back when it finishes makes room. Held from the start, a report is written
//! however full the table is by then. [`ReportFile`] says what holding it
//! leaves on disk.
//!
//! What it cannot check that early is whether the disk will still take the
//! bytes. That failure is reported and does not discard the scan: the terminal
//! already has the results, and a run that found things is not a run that
//! failed.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

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

    /// Opens the file its report is to be written to, creating it if it is
    /// not there, and leaves what it holds until the report is written.
    pub(crate) fn open(self) -> Result<ReportFile, Error> {
        let created = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path);
        let opened = match created {
            Ok(file) => Ok((file, true)),
            // Opened with `create` all the same: a link whose target is not
            // there yet is refused by `create_new` and written through by
            // this, as it is when nothing was there to find.
            Err(e) if e.kind() == ErrorKind::AlreadyExists => OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&self.path)
                .map(|file| (file, false)),
            Err(e) => Err(e),
        };

        match opened {
            Ok((file, created)) => Ok(ReportFile {
                destination: self,
                file,
                unclaimed: AtomicBool::new(created),
            }),
            Err(cause) => Err(Error::Unwritable {
                path: self.path,
                cause,
            }),
        }
    }
}

/// A file a report is to be written to, held open from before the work that
/// fills it.
///
/// Opened without being emptied, and emptied only as its report is written, so
/// a report already at the path survives a run that is refused or abandoned
/// before it has one to write. A file the run brought into being and never
/// began to write is removed when this is dropped, so such a run leaves no
/// empty report behind either; only a process killed outright does.
///
/// Each holds one descriptor for as long as the run lasts, which the room the
/// engine leaves the rest of the process is sized to include.
#[derive(Debug)]
pub(crate) struct ReportFile {
    destination: Destination,
    file: File,
    /// Whether this run created the file and has not begun to write it, which
    /// is when dropping it removes the file.
    ///
    /// Atomic, so a report file can be shared between threads as the `File`
    /// it holds can: its report is written through a shared reference.
    unclaimed: AtomicBool,
}

impl Drop for ReportFile {
    fn drop(&mut self) {
        if *self.unclaimed.get_mut() {
            let _ = std::fs::remove_file(&self.destination.path);
        }
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
    destinations: &[ReportFile],
    report: &ScanReport,
    redaction: Redaction,
) -> bool {
    let options = ExportOptions::new().with_redaction(redaction);
    let mut all_written = true;

    for held in destinations {
        let path = &held.destination.path;
        match write_one(held, report, options.clone()) {
            // To stderr: where a report went is commentary on the run, and
            // somebody piping its records should still be told.
            Ok(()) => tracing::info!("wrote {}", path.display()),
            Err(e) => {
                not_written(path, &e);
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
    held: &ReportFile,
    report: &ScanReport,
    options: ExportOptions,
) -> Result<(), ExportError> {
    use std::io::Write;

    // The file is the report's from here, whether or not the write lands.
    held.unclaimed.store(false, Ordering::Relaxed);

    // Emptied here rather than when it was opened, so what the path held
    // survives until there is a report to replace it. Only a file has a length
    // to cut: a terminal or a pipe named as a destination is written as it is.
    if held.file.metadata()?.is_file() {
        held.file.set_len(0)?;
    }

    let mut out = BufWriter::new(&held.file);
    held.destination
        .format
        .exporter(options)
        .export(report, &mut out)?;
    out.flush()?;
    Ok(())
}

/// Says on the console that the report meant for `path` was not written, and
/// why, in the one line a failed export takes whichever command it was for.
pub(crate) fn not_written(path: &Path, error: &ExportError) {
    let why = match error {
        ExportError::Io(e) => reason(e),
        other => other.to_string(),
    };
    tracing::error!("{} not written ({why})", path.display());
}

/// Why a file could not be opened or written, in the few words a console line
/// gives a reason.
///
/// The system's own words for an operating-system error, less the error number
/// the standard library appends to them: `no space left on device` rather than
/// `No space left on device (os error 28)`, since the number tells the person
/// reading nothing the words did not.
pub(crate) fn reason(error: &io::Error) -> String {
    let said = error.to_string();
    let Some(code) = error.raw_os_error() else {
        return said;
    };
    let words = said
        .strip_suffix(&format!(" (os error {code})"))
        .unwrap_or(&said)
        .trim_end_matches('.');

    let mut letters = words.chars();
    letters.next().map_or_else(String::new, |first| {
        first.to_lowercase().chain(letters).collect()
    })
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
    use crate::cli::ExportArgs;
    use zond_engine::import::report::{ReportFormat, ReportOptions};

    /// A directory of this test's own, empty, and named for the process so two
    /// runs of the suite never share one.
    fn scratch(test: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("zond-cli-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a writable scratch directory");
        directory
    }

    /// Every file a run given `-o path` is to write, as the run would get them.
    fn told_to_write(path: &Path) -> Vec<ReportFile> {
        ExportArgs {
            output: vec![path.to_path_buf()],
            ..ExportArgs::default()
        }
        .destinations()
        .expect("a destination that can be written")
    }

    /// The smallest report there is, which is all a test of where it lands
    /// needs.
    fn report() -> ScanReport {
        ScanReport::recorded("test", Vec::new(), Vec::new())
    }

    /// Whether `path` holds one whole report and nothing else, as the reader
    /// every command opens a file with would take it.
    fn holds_a_report(path: &Path) -> bool {
        let bytes = std::fs::read(path).expect("a file to read");
        ReportFormat::Json
            .read(&mut bytes.as_slice(), ReportOptions::new())
            .is_ok()
    }

    /// A console line has room for the reason a file could not be written and
    /// not for the error number beside it, which says nothing the words do
    /// not. An error that is not the system's is left as it was said.
    #[cfg(unix)]
    #[test]
    fn a_reason_is_the_systems_words_without_the_error_number() {
        let missing = io::Error::from_raw_os_error(rustix::io::Errno::NOENT.raw_os_error());
        assert_eq!(reason(&missing), "no such file or directory");

        let other = io::Error::other("Written By Hand (os error 2)");
        assert_eq!(reason(&other), "Written By Hand (os error 2)");
    }

    /// **The report is written however full the descriptor table is by the
    /// time it is.**
    ///
    /// A scan run with few descriptors to spare can end with none: what the
    /// runtime, the signal handling and the platform's libraries took along
    /// the way stays taken, and nothing the scan gives back when it finishes
    /// makes room. A report that asks for its file only then is lost, after a
    /// scan that may have taken hours. Its file is the run's from the start, so
    /// writing it asks the table for nothing.
    #[cfg(unix)]
    #[test]
    fn a_report_is_written_however_full_the_descriptor_table_is_by_then() {
        if !crate::descriptors::testing::in_a_process_of_its_own(
            module_path!(),
            "a_report_is_written_however_full_the_descriptor_table_is_by_then",
        ) {
            return;
        }
        let directory = scratch("full-table");
        let path = directory.join("report.json");
        let destinations = told_to_write(&path);

        let held = crate::descriptors::testing::exhaust();
        let written = write_all(&destinations, &report(), Redaction::None);
        drop(held);

        assert!(written, "the report was not written with the table full");
        assert!(holds_a_report(&path), "the file holds no whole report");
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// **A file this run created and never wrote is removed.** It is created
    /// when the run starts, so a run refused or abandoned before it has a
    /// report would otherwise leave an empty one behind, under the name a
    /// person will go looking for their results by.
    #[test]
    fn a_file_the_run_created_and_never_wrote_is_removed() {
        let directory = scratch("created-unwritten");
        let path = directory.join("report.json");

        let destinations = told_to_write(&path);
        assert!(path.exists(), "the file is the run's from the start");
        drop(destinations);

        assert!(!path.exists(), "an empty report was left behind");
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// **A report already at the path is kept until a new one replaces it
    /// whole.** A run refused or abandoned before it has a report leaves the
    /// last one where it was, and a run that writes one leaves nothing of the
    /// old file past the end of the new, however much longer the old was.
    #[test]
    fn an_existing_report_is_kept_until_a_new_one_replaces_it_whole() {
        let directory = scratch("existing");
        let path = directory.join("report.json");
        let earlier = "an earlier report, longer than the one replacing it ".repeat(64);
        std::fs::write(&path, &earlier).expect("an earlier report");

        drop(told_to_write(&path));
        assert_eq!(
            std::fs::read_to_string(&path).expect("the earlier report"),
            earlier,
            "a run with nothing to write changed the file"
        );

        let destinations = told_to_write(&path);
        assert_eq!(
            std::fs::read_to_string(&path).expect("the earlier report"),
            earlier,
            "the file changed before there was a report to write"
        );
        assert!(write_all(&destinations, &report(), Redaction::None));
        drop(destinations);

        assert!(
            holds_a_report(&path),
            "the new report left some of the old one behind it"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
}
