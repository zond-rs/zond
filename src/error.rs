// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What stops a command
//!
//! One variant per thing that can go wrong badly enough to end a run. An enum
//! rather than `anyhow` because every variant has to be assigned an
//! [exit code](crate::exit::Code), and a new failure mode should not compile
//! until somebody has said what the shell is told about it.
//!
//! Anything that does *not* end a run is not here. A strategy that failed part
//! way through is a finding, recorded in the report and rendered as a warning,
//! and the command carries on. So is the user stopping a scan: it is something
//! a run did, not something that went wrong with it. Both are an
//! [`Outcome`](crate::exit::Outcome).

use std::io::ErrorKind;

use zond_engine::ScanError;

use crate::exit::Code;
use crate::target::TargetError;

/// A failure that ends a command.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum Error {
    /// A target expression could not be turned into addresses to scan.
    #[error("{0}")]
    Target(#[from] TargetError),

    /// A link expression named nothing on this machine to listen on.
    ///
    /// Its own variant rather than folded into [`Target`](Self::Target), because
    /// a link is not a target: the two accept different vocabularies and fail
    /// for different reasons, and the engine's refusal already names what this
    /// machine does have.
    #[error("{0}")]
    Link(#[from] zond_engine::resolve::LinkError),

    /// The engine refused the scan before it sent anything, or the task behind
    /// it panicked or was killed, rather than a strategy inside it failing.
    ///
    /// Printed in the engine's own words, which already say which of those it
    /// was: a prefix claiming the scan did not complete would be false of a
    /// refusal, since that scan never started.
    #[error("{0}")]
    Scan(#[from] ScanError),

    /// Writing the results failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// The runtime every command runs on could not be built, before anything
    /// was read or sent. The process was started with too few descriptors, or
    /// threads, to hold one.
    #[error("could not start ({})", crate::export::reason(.0))]
    Runtime(std::io::Error),

    /// A settings file could not be read, parsed, or used.
    #[error("{0}")]
    Settings(#[from] crate::settings::SettingsError),

    /// A document handed in could not be read as a report.
    #[error("{0}")]
    Import(#[from] zond_engine::import::ImportError),

    /// A file was named as one side of a comparison and its extension names no
    /// format this build reads.
    #[error(
        "'{path}' is not a report this build can read. Reports are read from \
         this engine's JSON (.json) and from nmap's XML (.xml); a record on this \
         machine is named by its id instead."
    )]
    UnknownReportFormat {
        /// What was named.
        path: std::path::PathBuf,
    },

    /// A comparison was told to write itself somewhere it cannot be written.
    #[error(
        "'{path}' does not name a format a comparison can be written in. A \
         comparison is written as JSON (.json) or as one self-contained page \
         (.html)."
    )]
    UnknownDiffFormat {
        /// What was named.
        path: std::path::PathBuf,
    },

    /// `zond merge` was given one scan. Folding needs something to fold against,
    /// and a glob that matched a single file is the way this is usually reached.
    ///
    /// Refused here rather than by the grammar so the message can name the
    /// command that does print one report, which is the thing the person
    /// wanted.
    #[error("one scan is not a merge; `zond read {named}` prints a single report")]
    NotAFold {
        /// What was named, so the remedy can be typed as it stands.
        named: String,
    },

    /// A detection file could not be read.
    #[error("'{path}': {cause}")]
    DetectionPath {
        /// What was named.
        path: std::path::PathBuf,
        /// Why it could not be read.
        cause: std::io::Error,
    },

    /// A detection file has a name this platform will not hand over as text, so
    /// there is nothing a `[compute]` body reference could name it by.
    #[error("'{path}' has a name that is not valid text")]
    DetectionName {
        /// What was named.
        path: std::path::PathBuf,
    },

    /// Two detection files arrived under one name.
    ///
    /// Refused rather than resolved by order: a `[compute]` section references
    /// its body by name, so taking the second would run one detection under
    /// another's code.
    #[error(
        "'{name}' was named twice; detections are keyed by file name, so two          directories cannot each hold one"
    )]
    DuplicateDetection {
        /// The name given twice.
        name: String,
    },

    /// `--detections` named paths that hold no detection.
    #[error(
        "no detections in {}; a detection is a .toml document, and a directory          is read one level deep",
        named.iter().map(|path| format!("'{}'", path.display()))
            .collect::<Vec<_>>().join(", ")
    )]
    NoDetections {
        /// What was named.
        named: Vec<std::path::PathBuf>,
    },

    /// A detection would not compile.
    #[error("{0}")]
    Detections(zond_engine::detect::DetectionError),

    /// A vulnerability catalogue named by `--cve-catalogue` would not read.
    ///
    /// Named separately from [`Io`](Self::Io) so the message says which file was
    /// meant: a scan naming a catalogue and a scan naming a report both fail with
    /// a path, and "no such file" on its own does not say which one.
    #[error("the catalogue '{path}' could not be read: {source}")]
    Catalogue {
        /// What was named.
        path: std::path::PathBuf,
        /// Why it would not read.
        source: zond_engine::cve::CatalogueError,
    },

    /// A detection bundle did not verify against the key it was checked with.
    #[error("{0}")]
    Bundle(zond_engine::detect::bundle::BundleError),

    /// A signature document could not be read.
    #[error("{0}")]
    Signature(#[from] zond_engine::signature::SignatureError),

    /// `zond detections keygen` was pointed at a path that already holds a key.
    ///
    /// Refused rather than overwritten: every bundle already published under a
    /// key is verified with it, and replacing one ends all of them at once.
    #[error("'{path}' already exists; a key is never written over an existing one")]
    KeyExists {
        /// What was named.
        path: std::path::PathBuf,
    },

    /// `--trust-key` named a file that does not hold a hex public key.
    #[error("'{path}' does not hold a public key; a key is written as hex")]
    MalformedKey {
        /// What was named.
        path: std::path::PathBuf,
    },

    /// A journal could not be read or written.
    #[error("{0}")]
    Journal(#[from] zond_engine::journal::format::JournalError),

    /// A journal could not be opened for this scan: it is being written, or it
    /// was written against a different plan.
    #[error("{0}")]
    JournalOpen(#[from] zond_engine::journal::store::OpenError),

    /// Targets were named alongside `--resume` that describe a different scan.
    #[error("{0}; drop the targets to continue the scan as it was recorded")]
    PlanChanged(#[from] zond_engine::journal::manifest::PlanChanged),

    /// A flag was given alongside `--resume` that changes what the recorded
    /// scan asks, which would put two scans' answers in one record.
    #[error("{flag} differs from the record (drop it to resume)")]
    OptionChanged {
        /// The flag, as it is typed.
        flag: &'static str,
    },

    /// A journal was named that this machine has no record of.
    #[error(
        "no scan on record with id '{id}'{}",
        if *known == 0 {
            String::from("; there are none")
        } else {
            format!("; `zond journal` lists the {known} there are")
        }
    )]
    NoSuchJournal {
        /// What was asked for.
        id: String,
        /// How many there are, so the message can say whether to go looking.
        known: usize,
    },

    /// The record named holds the other phase of a scan.
    ///
    /// A sweep counts addresses and a port scan counts address-and-port pairs,
    /// so continuing one as the other would skip targets nothing ever probed.
    /// The engine refuses it; this is the same refusal with the command that
    /// would have worked.
    #[error("{id} records {held}, so continue it with `{remedy} {id}`")]
    WrongPhase {
        /// The record that was named.
        id: String,
        /// What it holds, as a phrase that reads after "records".
        held: &'static str,
        /// The command that continues that phase.
        remedy: &'static str,
    },

    /// A destination's extension names no format this build can write.
    #[error(
        "{} names no format this build can write. Give it one of: {known}. Or \
         say which with --output-as FORMAT=FILE.",
        path.display()
    )]
    UnknownExportFormat {
        /// The destination as it was given.
        path: std::path::PathBuf,
        /// The formats that would have worked.
        known: String,
    },

    /// A file a report is to be written to could not be opened, which is found
    /// before the work that would fill it starts.
    #[error("{} not writable ({})", path.display(), crate::export::reason(cause))]
    Unwritable {
        /// The destination as it was given.
        path: std::path::PathBuf,
        /// Why it could not be opened.
        cause: std::io::Error,
    },

    /// `--output-as` was given something that is not `FORMAT=FILE`.
    #[error("--output-as takes FORMAT=FILE, as in `json=report.out`, not '{written}' ({known})")]
    MalformedOutputAs {
        /// What was written.
        written: String,
        /// The formats that would have worked.
        known: String,
    },

    /// `--output-as` named a format this build cannot write.
    #[error("'{named}' is not a format this build can write. It knows: {known}")]
    UnknownFormatName {
        /// The name that was given.
        named: String,
        /// The formats that would have worked.
        known: String,
    },

    /// One of nmap's output spellings names a format that is not built yet.
    ///
    /// Refused by name rather than left to fail as an unknown flag: "not built
    /// yet" and "no such thing" send a person to different places.
    #[error("{spelling} is one of nmap's formats that zond does not write yet. It writes: {known}")]
    FormatNotBuilt {
        /// The spelling that was given.
        spelling: String,
        /// The formats that would have worked.
        known: String,
    },

    /// A page was asked for that the listing does not have.
    ///
    /// Refused rather than answered with nothing: an empty listing reads as
    /// "no scans on record", which is a different and more alarming thing than
    /// "you asked for the ninth page of two".
    #[error("there is no page {asked}: the listing ends at page {pages}")]
    NoSuchPage {
        /// The page that was asked for.
        asked: usize,
        /// How many there are.
        pages: usize,
    },

    /// A shortened id names more than one scan.
    ///
    /// Refused rather than resolved to the first match: the wrong scan deleted
    /// is not something a person gets back.
    #[error("'{id}' names more than one scan, among them {first} and {second}")]
    AmbiguousJournal {
        /// The prefix that was given.
        id: String,
        /// One scan it matches.
        first: String,
        /// Another.
        second: String,
    },

    /// There is nowhere on this machine to keep scan records.
    ///
    /// The environment names no home at all, which happens in a container or a
    /// daemon with a cleared environment.
    #[error("no directory to keep scan records in: this environment names no home")]
    NoJournalDirectory,

    /// The endpoint `zond detections test` was given was not a `host:port`.
    #[error(
        "'{target}' is not a host and port; name one as host:port, an IPv6 address bracketed as [::1]:443"
    )]
    MalformedTarget { target: String },
}

impl Error {
    /// The status to exit with.
    ///
    /// A closed output stream is the odd one out. `zond discover lan | head`
    /// closes the pipe as soon as `head` has what it wanted, and that is not a
    /// failure. It exits `0`, like every other tool a pipeline may cut short.
    #[must_use]
    pub(crate) fn code(&self) -> Code {
        match self {
            Error::Target(_)
            | Error::Link(_)
            | Error::Settings(_)
            | Error::NoSuchJournal { .. }
            | Error::NoSuchPage { .. }
            | Error::UnknownExportFormat { .. }
            | Error::Unwritable { .. }
            | Error::UnknownReportFormat { .. }
            | Error::UnknownDiffFormat { .. }
            | Error::MalformedOutputAs { .. }
            | Error::UnknownFormatName { .. }
            | Error::FormatNotBuilt { .. }
            | Error::WrongPhase { .. }
            | Error::NotAFold { .. }
            | Error::AmbiguousJournal { .. }
            | Error::DetectionPath { .. }
            | Error::DetectionName { .. }
            | Error::DuplicateDetection { .. }
            | Error::NoDetections { .. }
            | Error::Detections(_)
            | Error::Catalogue { .. }
            | Error::Bundle(_)
            | Error::Signature(_)
            | Error::MalformedKey { .. }
            | Error::KeyExists { .. }
            // A plan that does not match, or a scan already running: both are
            // the caller asking for something that cannot be done, not a fault.
            | Error::JournalOpen(_)
            | Error::PlanChanged(_)
            | Error::OptionChanged { .. } => Code::Usage,
            // A document that will not parse is a fault in the file rather than
            // in what was asked for: the name was right and the contents were
            // not. It joins the outright failures for that reason.
            Error::Import(_)
            | Error::Scan(_)
            | Error::Journal(_)
            | Error::NoJournalDirectory
            | Error::Runtime(_)
            | Error::MalformedTarget { .. } => Code::Failure,
            Error::Io(e) => {
                if e.kind() == ErrorKind::BrokenPipe {
                    Code::Success
                } else {
                    Code::Failure
                }
            }
        }
    }

    /// Prints this to standard error, unless there is nothing worth saying.
    ///
    /// Written directly rather than as a `tracing` event: an error must be shown
    /// whatever the verbosity, and can happen before a subscriber exists.
    ///
    /// A broken pipe says nothing, because it means the reader has gone.
    /// Complaining about it is what makes `| head` print a stack of errors.
    pub(crate) fn report(&self) {
        if matches!(self, Error::Io(e) if e.kind() == ErrorKind::BrokenPipe) {
            return;
        }
        eprintln!("error: {self}");
    }
}
