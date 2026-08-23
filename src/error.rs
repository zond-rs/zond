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

    /// The scan did not run to completion — the task behind it panicked or was
    /// killed, as opposed to a strategy inside it failing.
    #[error("the scan did not run to completion: {0}")]
    Scan(#[from] ScanError),

    /// Writing the results failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// A settings file could not be read, parsed, or used.
    #[error("{0}")]
    Settings(#[from] crate::settings::SettingsError),

    /// A presentation mode was named that is not built yet.
    #[error("{0}")]
    Presentation(#[from] crate::render::Unavailable),

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
}

impl Error {
    /// The status to exit with.
    ///
    /// A closed output stream is the odd one out. `zond discover lan | head`
    /// closes the pipe as soon as `head` has what it wanted, and that is not a
    /// failure — it exits `0`, like every other tool a pipeline may cut short.
    #[must_use]
    pub(crate) fn code(&self) -> Code {
        match self {
            Error::Target(_)
            | Error::Settings(_)
            | Error::Presentation(_)
            | Error::NoSuchJournal { .. }
            | Error::AmbiguousJournal { .. }
            // A plan that does not match, or a scan already running: both are
            // the caller asking for something that cannot be done, not a fault.
            | Error::JournalOpen(_)
            | Error::PlanChanged(_) => Code::Usage,
            Error::Scan(_) | Error::Journal(_) | Error::NoJournalDirectory => Code::Failure,
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
    pub(crate) fn report(&self) {
        if self.is_silent() {
            return;
        }
        eprintln!("error: {self}");
    }

    /// Whether reporting this would only be noise.
    ///
    /// A broken pipe means the reader has gone. Complaining about it is what
    /// makes `| head` print a stack of errors.
    #[must_use]
    pub(crate) fn is_silent(&self) -> bool {
        matches!(self, Error::Io(e) if e.kind() == ErrorKind::BrokenPipe)
    }
}
