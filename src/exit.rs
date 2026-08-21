// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the shell is told
//!
//! A scanner is run from scripts more often than from a keyboard, so its exit
//! status is part of its interface. This module is that interface written down,
//! in one place, rather than a set of integers spread across the commands.
//!
//! ## The codes
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | The run finished and covered everything it was asked to cover. |
//! | 1 | The run could not be carried out. |
//! | 2 | What was asked for was not usable: an unknown flag, a target that is not a target, or a settings file that says something this program cannot act on. |
//! | 3 | The run finished, but something it was asked to cover was not covered. |
//! | 130 | Interrupted with `Ctrl-C`. |
//!
//! **Finding nothing is not a failure.** A sweep of an empty range exits `0`.
//!
//! **Code 3 is the one worth explaining.** A scan whose raw scanner would not
//! start, or whose range no strategy could walk, still returns every host it did
//! find. That result is narrower than what was asked for and dangerous to read
//! as though it were not. A script that does not care writes
//! `zond discover lan || true`.

/// The process exit status, and the whole set of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Code {
    /// The run finished and covered everything it was asked to.
    Success = 0,
    /// The run could not be carried out at all.
    Failure = 1,
    /// What was asked for was not usable — on the command line or in a settings
    /// file, which are two ways of asking for the same things and deserve the
    /// same answer. Matches the convention `clap` already exits with for a flag
    /// it does not know, so the two agree.
    Usage = 2,
    /// The run finished, but part of what was asked for was not covered.
    Partial = 3,
    /// Interrupted. `128 + SIGINT`, which is what a shell reports for a process
    /// killed by that signal and therefore what a script already tests for.
    Interrupted = 130,
}

impl Code {
    /// The status as the number a shell sees.
    #[must_use]
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<Code> for std::process::ExitCode {
    fn from(code: Code) -> Self {
        Self::from(code.as_u8())
    }
}

/// How a command ended.
///
/// Distinct from [`Code`]: a command reports what happened, and this module
/// decides what the shell is told about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Outcome {
    /// Everything asked for was covered.
    Complete,
    /// The run produced results, but something was left uncovered — a strategy
    /// that failed, or a target range nothing could take.
    Partial,
    /// The user stopped it. The results collected up to that point were still
    /// reported.
    Interrupted,
}

impl Outcome {
    /// The status to exit with.
    #[must_use]
    pub(crate) fn code(self) -> Code {
        match self {
            Outcome::Complete => Code::Success,
            Outcome::Partial => Code::Partial,
            Outcome::Interrupted => Code::Interrupted,
        }
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

    /// The table in this module's documentation, as an assertion.
    #[test]
    fn the_documented_numbers_are_the_numbers() {
        assert_eq!(Code::Success.as_u8(), 0);
        assert_eq!(Code::Failure.as_u8(), 1);
        assert_eq!(Code::Usage.as_u8(), 2);
        assert_eq!(Code::Partial.as_u8(), 3);
        assert_eq!(Code::Interrupted.as_u8(), 130);
    }

    #[test]
    fn every_outcome_has_the_status_it_claims() {
        assert_eq!(Outcome::Complete.code(), Code::Success);
        assert_eq!(Outcome::Partial.code(), Code::Partial);
        assert_eq!(Outcome::Interrupted.code(), Code::Interrupted);
    }

    /// A shell reports a signalled process as `128 + signal`.
    #[test]
    fn interruption_is_the_shells_own_number_for_it() {
        const SIGINT: u8 = 2;
        assert_eq!(Code::Interrupted.as_u8(), 128 + SIGINT);
    }
}
