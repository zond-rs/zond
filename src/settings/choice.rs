// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a person may choose
//!
//! The vocabulary the settings file and the command line share: how a run is
//! drawn, what makes two records the same host, how many records are kept. One
//! type per choice, each with the spelling it takes in a file and the error it
//! returns when that spelling is not one of them.
//!
//! Kept apart from the file that carries them because the two are used by
//! different halves of the program. These types are named all over the crate:
//! `cli` parses them and every renderer switches on one. Reading, layering and
//! provisioning a `cli.toml` happens once, in `main`. A module whose name
//! appears in fifty places should be small enough to read.
//!
//! **Every error here carries the spellings that would have worked**, so
//! whoever prints it can print it verbatim rather than composing a second
//! sentence about it. That is the shape the engine's own settings errors take.

use std::fmt;
use std::str::FromStr;

use zond_engine::diff::HostIdentity;
use zond_engine::model::finding::Severity;
use zond_engine::record::wire;

/// How a run is drawn.
///
/// Three modes, differing in register rather than in how much they say.
/// [`Pipe`](Self::Pipe) shouts in field names a program matches on,
/// [`Minimal`](Self::Minimal) mutters in abbreviated tags, and
/// [`Fancy`](Self::Fancy) speaks in words.
///
/// `pipe` is not a step on that ladder, it is a different audience: `minimal` is
/// a listing and `pipe` is a record format, and both show everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Presentation {
    /// Tab-separated records for a program: no padding, no heading, no unit
    /// suffixes, and every field a scan established. The only mode whose output
    /// is a stable interface.
    Pipe,
    /// A tagged block per host, in abbreviated tags and no colour. The terse
    /// reading mode, for a narrow terminal or a long sweep.
    Minimal,
    /// A numbered block per host, with colour and the transport hanging under
    /// the port that carried it. The default, and the shape every command draws
    /// in.
    #[default]
    Fancy,
}

impl Presentation {
    /// Every mode, least to most, with the machine-readable one first.
    pub(crate) const ALL: [Presentation; 3] = [
        Presentation::Pipe,
        Presentation::Minimal,
        Presentation::Fancy,
    ];

    /// The mode as it is written in a settings file or on the command line.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Presentation::Pipe => "pipe",
            Presentation::Minimal => "minimal",
            Presentation::Fancy => "fancy",
        }
    }
}

impl fmt::Display for Presentation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error [`Presentation::from_str`] returns.
///
/// Carries the names that would have worked, so whoever prints it can print it
/// verbatim. That is the shape the engine's own settings errors take.
#[derive(Debug, thiserror::Error)]
#[error("unknown presentation '{written}': expected one of {}", expected.join(", "))]
pub(crate) struct UnknownPresentation {
    /// What was written.
    pub written: String,
    /// The names that would have worked.
    pub expected: Vec<&'static str>,
}

impl FromStr for Presentation {
    type Err = UnknownPresentation;

    fn from_str(written: &str) -> Result<Self, Self::Err> {
        Presentation::ALL
            .into_iter()
            .find(|mode| written.eq_ignore_ascii_case(mode.as_str()))
            .ok_or_else(|| UnknownPresentation {
                written: written.to_owned(),
                expected: Presentation::ALL.map(Presentation::as_str).to_vec(),
            })
    }
}

/// The lowest grade of finding a listing draws.
///
/// A scan turns up more than a reader wants on every run. `missing HTTP security
/// headers` is true of most web servers and says the same thing on each, and a
/// sweep of forty of them is forty rows nobody reads. This is where the floor
/// sits, and everything at or above it is drawn.
///
/// The count on a host's header is not filtered by it. A finding below the floor
/// is one the reader is not being shown, and a block that also revised its own
/// total would be hiding the fact that it hid something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Risk(Severity);

impl Risk {
    /// Whether a finding of this grade is drawn.
    #[must_use]
    pub(crate) fn admits(self, severity: Severity) -> bool {
        severity >= self.0
    }

    /// How the floor is written, in the spelling that sets it.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        wire::severity_name(self.0)
    }
}

impl Risk {
    /// The floor that draws every finding, however it is graded.
    ///
    /// A run reaches it by name, through `--risk info`. This is the same floor
    /// for the tests that measure a listing's shape rather than the floor.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn everything() -> Self {
        Self(Severity::Info)
    }
}

impl Default for Risk {
    /// Medium.
    ///
    /// The grade below which a finding is hardening advice more often than it is
    /// an exposure, so it is the floor that keeps a sweep readable without
    /// deciding, from a detection author's guess, that a reader should not see an
    /// open door.
    fn default() -> Self {
        Self(Severity::Medium)
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error [`Risk::from_str`] returns, carrying the grades that would have
/// worked so a caller can print it verbatim.
#[derive(Debug, thiserror::Error)]
#[error("unusable risk floor '{written}': expected one of {}", expected.join(", "))]
pub(crate) struct UnknownRisk {
    /// What was written.
    pub written: String,
    /// The grades that would have worked, weakest first.
    pub expected: Vec<&'static str>,
}

impl FromStr for Risk {
    type Err = UnknownRisk;

    /// A grade by name, without regard to case.
    ///
    /// Read through [`wire::severity`] rather than from a table written here, so
    /// the word a person types and the word a record carries stay one
    /// vocabulary.
    fn from_str(written: &str) -> Result<Self, Self::Err> {
        wire::severity(&written.to_ascii_lowercase())
            .map(Self)
            .ok_or_else(|| UnknownRisk {
                written: written.to_owned(),
                expected: Severity::ALL
                    .iter()
                    .copied()
                    .map(wire::severity_name)
                    .collect(),
            })
    }
}

/// What makes two records, in two different scans, the same host.
///
/// A thin mirror of the engine's own [`HostIdentity`], because a value the
/// command line parses needs a `FromStr` this crate is allowed to write. The
/// meanings are the engine's and are documented there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Identity {
    /// Two records are the same host when they share any address.
    #[default]
    Any,
    /// That, and when they share a hardware address.
    Hardware,
    /// Only when their primary addresses match.
    Primary,
}

impl Identity {
    /// Every spelling, in the order the help lists them.
    pub(crate) const ALL: [Identity; 3] = [Identity::Any, Identity::Hardware, Identity::Primary];

    /// What this is called on the command line.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Identity::Any => "any",
            Identity::Hardware => "hardware",
            Identity::Primary => "primary",
        }
    }
}

impl From<Identity> for HostIdentity {
    fn from(identity: Identity) -> Self {
        match identity {
            Identity::Any => HostIdentity::AnyAddress,
            Identity::Hardware => HostIdentity::Hardware,
            Identity::Primary => HostIdentity::PrimaryAddress,
        }
    }
}

/// The error [`Identity::from_str`] returns.
///
/// Carries the names that would have worked, so whoever prints it can print it
/// verbatim, in the shape [`UnknownPresentation`] takes.
#[derive(Debug, thiserror::Error)]
#[error("unknown identity '{written}': expected one of {}", expected.join(", "))]
pub(crate) struct UnknownIdentity {
    /// What was written.
    pub written: String,
    /// The names that would have worked.
    pub expected: Vec<&'static str>,
}

impl std::str::FromStr for Identity {
    type Err = UnknownIdentity;

    fn from_str(written: &str) -> Result<Self, Self::Err> {
        Identity::ALL
            .into_iter()
            .find(|identity| written.eq_ignore_ascii_case(identity.as_str()))
            .ok_or_else(|| UnknownIdentity {
                written: written.to_owned(),
                expected: Identity::ALL.map(Identity::as_str).to_vec(),
            })
    }
}

/// How many journals this machine keeps.
///
/// The journal directory grows by one record per scan and nothing about a scan
/// shrinks it, so something has to say when the oldest record has served its
/// purpose. This is that number, and a run that records applies it as soon as
/// it has claimed a record of its own.
///
/// [`Unlimited`](Self::Unlimited) is the way out for somebody keeping records
/// deliberately: an engagement where the journal is evidence wants a directory
/// bounded by the disk rather than by a count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryLimit {
    /// Keep at most this many, oldest out first.
    ///
    /// Zero keeps none. The record of the run in flight is still written, since
    /// `--resume` is the reason a journal exists at all, and it goes when the
    /// next run claims one.
    AtMost(usize),
    /// Keep every record, however many there are.
    Unlimited,
}

impl EntryLimit {
    /// What a machine keeps when nothing says otherwise.
    ///
    /// A hundred is well past the point where anybody resumes a scan and small
    /// enough that the directory stays something a person can read through.
    pub(crate) const DEFAULT: Self = Self::AtMost(100);

    /// The word that spells [`Unlimited`](Self::Unlimited) in a settings file.
    ///
    /// Not `none`, though `None` is what it becomes: read quickly, in a file
    /// where `0` means keep none, `none` and `0` look like two spellings of one
    /// thing and are opposites.
    pub(super) const UNLIMITED: &'static str = "unlimited";

    /// The cap as [`Retention`](zond_engine::journal::store::Retention) takes
    /// it, `None` being no cap at all.
    #[must_use]
    pub(crate) fn cap(self) -> Option<usize> {
        match self {
            Self::AtMost(count) => Some(count),
            Self::Unlimited => None,
        }
    }

    /// Reads what a document wrote for this key.
    ///
    /// A count or the word `unlimited`, and nothing else. A limit is a number or
    /// the absence of one. `true` is neither, and a negative count is a number
    /// of records nobody can have.
    pub(super) fn from_value(value: &toml::Value) -> Result<Self, UnknownEntryLimit> {
        // Quoted back as TOML, so a string keeps its quotes and a number does
        // not: what the message shows is what the file has in it.
        let refuse = || UnknownEntryLimit {
            written: value.to_string(),
        };

        match value {
            toml::Value::Integer(count) => usize::try_from(*count)
                .map(Self::AtMost)
                .map_err(|_| refuse()),
            toml::Value::String(word) if word.eq_ignore_ascii_case(Self::UNLIMITED) => {
                Ok(Self::Unlimited)
            }
            _ => Err(refuse()),
        }
    }
}

/// The error [`EntryLimit::from_value`] returns.
///
/// Names what would have worked, like its neighbour above, so whoever prints it
/// prints it verbatim. It names both ends apart as well, because the value this
/// mostly catches is `none`, and somebody writing that could mean either of them.
#[derive(Debug, thiserror::Error)]
#[error(
    "unusable journal entry limit {written}: expected a count like 100, 0 to keep none, or \"unlimited\" for no limit"
)]
pub(crate) struct UnknownEntryLimit {
    /// What was written, as it was written.
    pub written: String,
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

    /// The floor is read through the engine's own vocabulary, so the word a
    /// person types and the word a record carries stay one spelling.
    #[test]
    fn a_grade_is_read_by_name_whatever_the_case() {
        for (written, grade) in [
            ("info", Severity::Info),
            ("LOW", Severity::Low),
            ("Medium", Severity::Medium),
            ("high", Severity::High),
            ("critical", Severity::Critical),
        ] {
            let read = Risk::from_str(written).expect(written);
            assert!(read.admits(grade), "{written} does not admit its own grade");
        }
    }

    /// The default is medium, which is the grade below which a finding is
    /// hardening advice more often than it is an exposure.
    #[test]
    fn the_floor_defaults_to_medium() {
        let floor = Risk::default();

        assert!(floor.admits(Severity::Critical));
        assert!(floor.admits(Severity::High));
        assert!(floor.admits(Severity::Medium));
        assert!(!floor.admits(Severity::Low));
        assert!(!floor.admits(Severity::Info));
        assert_eq!(floor.as_str(), "medium");
    }

    /// Anything that is not a grade names the ones that are.
    #[test]
    fn an_unknown_grade_names_the_ones_that_would_have_worked() {
        let refused = Risk::from_str("severe").expect_err("not a grade");
        let message = refused.to_string();

        for grade in Severity::ALL {
            assert!(
                message.contains(wire::severity_name(grade)),
                "{message} does not name {}",
                wire::severity_name(grade)
            );
        }
    }
    use super::*;

    /// Every spelling round-trips, and shouting is still asking.
    ///
    /// A settings file and a command line are typed by hand, so a value that
    /// parses only in the case this crate happens to write it in is a value
    /// somebody will get wrong once and never work out why.
    #[test]
    fn every_mode_parses_back_from_its_own_name_however_it_is_typed() {
        for mode in Presentation::ALL {
            assert_eq!(mode.as_str().parse::<Presentation>().expect("known"), mode);
            assert_eq!(
                mode.as_str()
                    .to_uppercase()
                    .parse::<Presentation>()
                    .expect("known"),
                mode
            );
        }
    }

    /// The same, for the policy `zond diff` compares under.
    #[test]
    fn every_identity_parses_back_from_its_own_name_however_it_is_typed() {
        for identity in Identity::ALL {
            assert_eq!(
                identity.as_str().parse::<Identity>().expect("its own name"),
                identity
            );
            assert_eq!(
                identity
                    .as_str()
                    .to_uppercase()
                    .parse::<Identity>()
                    .expect("known"),
                identity
            );
        }
    }

    /// A name that is not one is refused with the names that would have worked,
    /// rather than falling back to the default and comparing under a policy
    /// nobody asked for.
    #[test]
    fn a_name_that_is_not_one_is_refused_with_the_alternatives() {
        let refused = "shiny".parse::<Presentation>().expect_err("not a mode");
        assert_eq!(refused.written, "shiny");
        for mode in Presentation::ALL {
            assert!(refused.expected.contains(&mode.as_str()), "{refused}");
        }

        let refused = "mac".parse::<Identity>().expect_err("not a policy");
        assert_eq!(refused.written, "mac");
        for identity in Identity::ALL {
            assert!(refused.expected.contains(&identity.as_str()), "{refused}");
        }
    }

    /// What a mode is called and what it is are one decision, so the default is
    /// pinned here rather than left to whichever variant carries the attribute.
    #[test]
    fn the_default_is_the_drawn_one() {
        assert_eq!(Presentation::default(), Presentation::Fancy);
        assert_eq!(Identity::default(), Identity::Any);
    }

    /// What the cap becomes for the engine: a number, or no cap at all.
    ///
    /// Zero is a cap of zero and not the absence of one, which is the confusion
    /// [`EntryLimit::UNLIMITED`] is spelled the way it is to avoid.
    #[test]
    fn only_unlimited_means_no_cap() {
        assert_eq!(EntryLimit::Unlimited.cap(), None);
        assert_eq!(EntryLimit::AtMost(0).cap(), Some(0));
        assert_eq!(EntryLimit::AtMost(100).cap(), Some(100));
        assert_eq!(EntryLimit::DEFAULT.cap(), Some(100));
    }
}
