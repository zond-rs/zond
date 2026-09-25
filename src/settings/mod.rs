// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Settings on disk
//!
//! Two files, in one directory a person can find and back up:
//!
//! | | |
//! |---|---|
//! | `~/.config/zond/engine.toml` | what a scan puts on the wire. The engine's, read with the engine's own reader. |
//! | `~/.config/zond/cli.toml` | how a run is shown. This crate's. |
//!
//! The split is the engine's boundary, not an arrangement invented here:
//! [`ZondConfig`] holds only what can change a finding, and a report records it,
//! so a key that cannot change a finding has no business in it. Presentation is
//! exactly such a key, and it lives here.
//!
//! The locations come from the engine's
//! [`paths`](zond_engine::import::settings::paths) so that the two files cannot
//! land in different directories. That is `$XDG_CONFIG_HOME` when it is
//! absolute, `$HOME/.config` otherwise, and `/etc/zond` for a host-wide file
//! underneath both.
//!
//! ## When the files appear
//!
//! On the first run that can write them, from templates compiled in with
//! `include_str!`, so a first run works offline. Not at build time, because a
//! package installed by `root` would provision `root`'s configuration and
//! nobody else's.
//!
//! Provisioning never overwrites, never edits, and never changes behaviour:
//! every key in both templates is commented out. Failure to write is not fatal.
//!
//! Discovery wants root, so the first run is very often `sudo zond discover lan`.
//! The files would then be created `root`-owned and mode `0600`, which the
//! user's own later runs cannot read. When `SUDO_UID` and `SUDO_GID` say who
//! asked, anything newly created is handed to them. See [`provision`].

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::render::style::{Accent, ColourChoice, UnknownAccent, UnknownColourChoice};

use serde::Deserialize;

use zond_engine::import::settings as engine_settings;
use zond_engine::{PortSet, ZondConfig};

mod choice;

pub(crate) use choice::{
    EntryLimit, Identity, Presentation, Risk, UnknownEntryLimit, UnknownIdentity,
    UnknownPresentation, UnknownRisk,
};

/// This crate's settings file, as it is named on disk.
///
/// It sits beside the engine's `engine.toml`, which is what the engine's own
/// path documentation says a front end should do.
pub(crate) const FILE_NAME: &str = "cli.toml";

/// The document written when there is not one already.
///
/// Compiled in rather than fetched or generated: see the module documentation.
pub(crate) const TEMPLATE: &str = include_str!("../../assets/settings/cli.toml");

/// A value a settings file gave for a key this program does know.
///
/// One variant per key that can be written wrong. It is kept as a type rather
/// than flattened to a string so that a caller, or a test, can ask which key it
/// was.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum UnusableValue {
    /// `presentation` named something that is not a mode.
    #[error(transparent)]
    Presentation(#[from] UnknownPresentation),
    /// `journal_entry_limit` was neither a count nor `unlimited`.
    #[error(transparent)]
    EntryLimit(#[from] UnknownEntryLimit),
    /// `identity` named something that is not a policy.
    #[error(transparent)]
    Identity(#[from] UnknownIdentity),
    /// `colour` named something that is not a setting.
    #[error(transparent)]
    Colour(#[from] UnknownColourChoice),
    /// `accent_colour` was neither a named accent nor a colour.
    #[error(transparent)]
    Accent(#[from] UnknownAccent),
    /// `risk` named something that is not a grade.
    #[error(transparent)]
    Risk(#[from] UnknownRisk),
}

/// Something a settings file said that this program could not use.
///
/// A warning rather than an error, so a file written by a newer `zond` does not
/// stop an older one running. The key is ignored and named.
#[derive(Debug, Clone)]
pub(crate) struct Warning {
    /// The file it came from.
    pub path: PathBuf,
    /// The key that was not understood.
    pub key: String,
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: unknown setting '{}', ignored",
            self.path.display(),
            self.key
        )
    }
}

/// A settings file this program could not use at all.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum SettingsError {
    /// The file exists and could not be read.
    #[error("{}", unreadable(path, source))]
    Unreadable {
        /// The file.
        path: PathBuf,
        /// Why it could not be read.
        #[source]
        source: std::io::Error,
    },

    /// The file, or the directory it belongs in, was missing and could not be
    /// created.
    #[error("{} not created ({})", path.display(), crate::export::reason(source))]
    Uncreatable {
        /// What was being created.
        path: PathBuf,
        /// Why it could not be.
        #[source]
        source: std::io::Error,
    },

    /// The file exists and is not valid TOML.
    #[error("{path}: {source}")]
    Malformed {
        /// The file.
        path: PathBuf,
        /// What the parser made of it.
        #[source]
        source: toml::de::Error,
    },

    /// A key was understood and its value was not.
    #[error("{path}: {source}")]
    BadValue {
        /// The file.
        path: PathBuf,
        /// What was wrong with the value.
        #[source]
        source: UnusableValue,
    },

    /// The engine's own settings could not be resolved.
    ///
    /// A file the engine could not read is said as this crate's own is, since
    /// the two sit side by side and a person reading either wants the same
    /// line; everything else is in the engine's words.
    #[error("{}", engine_failure(.0))]
    Engine(#[from] engine_settings::SettingsError),
}

/// The engine's settings failure as [`SettingsError`] says its own.
fn engine_failure(error: &engine_settings::SettingsError) -> String {
    match error {
        engine_settings::SettingsError::Io { path, source } => unreadable(path, source),
        other => other.to_string(),
    }
}

/// A settings file that could not be read, in the one line a console gives it.
fn unreadable(path: &Path, source: &std::io::Error) -> String {
    format!(
        "{} not readable ({})",
        path.display(),
        crate::export::reason(source)
    )
}

/// What this crate's settings file said.
///
/// Every field is optional and means "this file did not mention it". That is
/// what makes layering work: saying nothing must not overrule a lower layer.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Settings {
    presentation: Option<Presentation>,
    colour: Option<ColourChoice>,
    accent_colour: Option<Accent>,
    reason: Option<bool>,
    remedy: Option<bool>,
    evidence: Option<bool>,
    identity: Option<Identity>,
    journal: Option<bool>,
    journal_entry_limit: Option<EntryLimit>,
    page_size: Option<usize>,
    risk: Option<Risk>,
}

impl Settings {
    /// The presentation these settings ask for, if they ask for one.
    #[must_use]
    pub(crate) fn presentation(self) -> Option<Presentation> {
        self.presentation
    }

    /// Whether these settings ask for the evidence behind every verdict.
    ///
    /// Worth a key rather than a flag alone for the same reason `presentation`
    /// is one: somebody who wants to see what a verdict rests on wants it on
    /// every scan they run, and a flag they must remember nightly is a flag
    /// they will forget.
    #[must_use]
    pub(crate) fn reason(self) -> Option<bool> {
        self.reason
    }

    /// Whether these settings ask for the advice a finding carries.
    #[must_use]
    pub(crate) fn remedy(self) -> Option<bool> {
        self.remedy
    }

    /// The lowest grade of finding these settings draw, if they say.
    ///
    /// Worth a key rather than a flag alone for the reason `reason` is one:
    /// somebody sweeping a network they already know wants the floor raised on
    /// every run, and somebody auditing one host wants it on the floor.
    #[must_use]
    pub(crate) fn risk(self) -> Option<Risk> {
        self.risk
    }

    /// Whether these settings ask for what each detection saw.
    #[must_use]
    pub(crate) fn evidence(self) -> Option<bool> {
        self.evidence
    }

    /// Whether these settings ask for colour, if they say.
    #[must_use]
    pub(crate) fn colour(self) -> Option<ColourChoice> {
        self.colour
    }

    /// The hue these settings mark names and handles with, if they name one.
    ///
    /// The only colour in the palette a person may move, because it is the only
    /// one that carries no meaning. The three greys are a legibility decision
    /// and the three states are what a verdict looks like, and a settings file
    /// is not the place to reopen either.
    #[must_use]
    pub(crate) fn accent_colour(self) -> Option<Accent> {
        self.accent_colour
    }

    /// What these settings say makes two records the same host, if they say.
    ///
    /// Read only by `zond diff`. A machine whose segment runs DHCP wants
    /// `hardware` on every comparison it ever makes, and saying so once in a
    /// file is the difference between that and remembering a flag nightly.
    #[must_use]
    pub(crate) fn identity(self) -> Option<Identity> {
        self.identity
    }

    /// Whether scans should be recorded, if these settings say.
    #[must_use]
    pub(crate) fn journal(self) -> Option<bool> {
        self.journal
    }

    /// How many records this machine keeps at all, if these settings say.
    ///
    /// Distinct from [`page_size`](Self::page_size), which is how many of them
    /// are shown at once. One bounds a directory and the other a screen.
    #[must_use]
    pub(crate) fn journal_entry_limit(self) -> Option<EntryLimit> {
        self.journal_entry_limit
    }

    /// How many records a listing shows at once, if these settings say.
    ///
    /// Zero is read as "no limit", which is what somebody writing `0` means.
    #[must_use]
    pub(crate) fn page_size(self) -> Option<usize> {
        self.page_size
    }

    /// Lays `other` over this, key by key.
    fn overlay(&mut self, other: Settings) {
        if let Some(presentation) = other.presentation {
            self.presentation = Some(presentation);
        }
        if let Some(colour) = other.colour {
            self.colour = Some(colour);
        }
        if let Some(accent) = other.accent_colour {
            self.accent_colour = Some(accent);
        }
        if let Some(remedy) = other.remedy {
            self.remedy = Some(remedy);
        }
        if let Some(evidence) = other.evidence {
            self.evidence = Some(evidence);
        }
        if let Some(reason) = other.reason {
            self.reason = Some(reason);
        }
        if let Some(identity) = other.identity {
            self.identity = Some(identity);
        }
        if let Some(journal) = other.journal {
            self.journal = Some(journal);
        }
        if let Some(limit) = other.journal_entry_limit {
            self.journal_entry_limit = Some(limit);
        }
        if let Some(page_size) = other.page_size {
            self.page_size = Some(page_size);
        }
        if let Some(risk) = other.risk {
            self.risk = Some(risk);
        }
    }
}

/// The shape of the document on disk.
///
/// Unknown keys are collected rather than refused. See [`Warning`].
#[derive(Debug, Default, Deserialize)]
struct Document {
    presentation: Option<String>,
    // Both spellings, because this is the one key in the file whose name is a
    // word two large groups of English speakers write differently, and being
    // told `color` is an unknown key is a poor way to find that out.
    colour: Option<String>,
    color: Option<String>,
    // Both spellings again, and for the same reason: a file that accepts
    // `color` and refuses `accent_color` has taught one lesson and then broken
    // it one key later.
    accent_colour: Option<String>,
    accent_color: Option<String>,
    identity: Option<String>,
    reason: Option<bool>,
    remedy: Option<bool>,
    evidence: Option<bool>,
    journal: Option<bool>,
    // Left as it was written, because this key takes a count or a word and the
    // message for anything else should be able to quote what was there.
    journal_entry_limit: Option<toml::Value>,
    page_size: Option<usize>,
    risk: Option<String>,
    #[serde(flatten)]
    unknown: BTreeMap<String, toml::Value>,
}

/// Reads one document, reporting what it could not use.
fn parse(text: &str, path: &Path) -> Result<(Settings, Vec<Warning>), SettingsError> {
    let document: Document = toml::from_str(text).map_err(|source| SettingsError::Malformed {
        path: path.to_path_buf(),
        source,
    })?;

    let bad_value = |source: UnusableValue| SettingsError::BadValue {
        path: path.to_path_buf(),
        source,
    };

    let presentation = document
        .presentation
        .as_deref()
        .map(Presentation::from_str)
        .transpose()
        .map_err(|source| bad_value(source.into()))?;

    let colour = document
        .colour
        .as_deref()
        .or(document.color.as_deref())
        .map(ColourChoice::from_str)
        .transpose()
        .map_err(|source| bad_value(source.into()))?;

    let accent_colour = document
        .accent_colour
        .as_deref()
        .or(document.accent_color.as_deref())
        .map(Accent::from_str)
        .transpose()
        .map_err(|source| bad_value(source.into()))?;

    let identity = document
        .identity
        .as_deref()
        .map(Identity::from_str)
        .transpose()
        .map_err(|source| bad_value(source.into()))?;

    let journal_entry_limit = document
        .journal_entry_limit
        .as_ref()
        .map(EntryLimit::from_value)
        .transpose()
        .map_err(|source| bad_value(source.into()))?;

    let risk = document
        .risk
        .as_deref()
        .map(Risk::from_str)
        .transpose()
        .map_err(|source| bad_value(source.into()))?;

    let warnings = document
        .unknown
        .into_keys()
        .map(|key| Warning {
            path: path.to_path_buf(),
            key,
        })
        .collect();

    Ok((
        Settings {
            presentation,
            colour,
            accent_colour,
            reason: document.reason,
            remedy: document.remedy,
            evidence: document.evidence,
            identity,
            journal: document.journal,
            journal_entry_limit,
            page_size: document.page_size,
            risk,
        },
        warnings,
    ))
}

/// Where this crate's settings file would be, for this user.
///
/// `None` when the environment names no home at all, which is a container or a
/// daemon with a cleared environment. A caller getting `None` carries on with
/// built-in defaults rather than inventing a location.
#[must_use]
pub(crate) fn user_path() -> Option<PathBuf> {
    engine_settings::paths::user_directory().map(|directory| directory.join(FILE_NAME))
}

/// Where a host-wide settings file for this crate would be.
///
/// Derived from the engine's own system path rather than spelled out, so the two
/// files stay in one directory on every platform the engine comes to support.
#[must_use]
pub(crate) fn system_path() -> Option<PathBuf> {
    engine_settings::paths::system()?
        .parent()
        .map(|directory| directory.join(FILE_NAME))
}

/// Every settings file that may apply, in the order they layer.
///
/// System first, user second, so the user's file has the last word.
#[must_use]
pub(crate) fn layered() -> Vec<PathBuf> {
    [system_path(), user_path()].into_iter().flatten().collect()
}

/// Loads this crate's settings from the files that exist.
///
/// An absent file is skipped. One that is there and cannot be read or parsed is
/// an error: treating it as absent would run under settings the user believes
/// they wrote.
pub(crate) fn resolve() -> Result<(Settings, Vec<Warning>), SettingsError> {
    let mut settings = Settings::default();
    let mut warnings = Vec::new();

    for path in layered() {
        if !path.exists() {
            continue;
        }

        let text = std::fs::read_to_string(&path).map_err(|source| SettingsError::Unreadable {
            path: path.clone(),
            source,
        })?;

        let (parsed, found) = parse(&text, &path)?;
        settings.overlay(parsed);
        warnings.extend(found);
    }

    Ok((settings, warnings))
}

/// Everything the engine's settings files said, from one read of them.
///
/// The engine's own reader, its own layering, its own profile selection. This
/// crate does not parse `engine.toml`; it asks the engine what it says.
#[derive(Debug, Clone)]
pub(crate) struct EngineSettings {
    /// What the files said a scan should put on the wire.
    pub(crate) config: ZondConfig,
    /// The ports they said to probe, if they said.
    ///
    /// Read here rather than on demand because it comes out of the same
    /// document. Asking for it separately means reading and parsing
    /// `engine.toml` a second time, and two reads can disagree.
    pub(crate) ports: Option<PortSet>,
}

/// Reads the engine's settings once, reporting what it could not use.
///
/// The warnings come back as finished sentences rather than as the engine's own
/// type, because every caller does the same thing with them: log one line each.
pub(crate) fn engine(
    profile: Option<&str>,
) -> Result<(EngineSettings, Vec<String>), SettingsError> {
    let (settings, warnings) = engine_settings::resolve(profile)?;

    let mut config = ZondConfig::default();
    settings.apply_to(&mut config);

    let ports = settings
        .ports()
        .transpose()
        .map_err(SettingsError::Engine)?;

    let warnings = warnings
        .into_iter()
        .map(|warning| match warning.suggestion {
            Some(suggestion) => format!(
                "unknown engine setting '{}', ignored. Did you mean '{suggestion}'?",
                warning.key
            ),
            None => format!("unknown engine setting '{}', ignored", warning.key),
        })
        .collect();

    Ok((EngineSettings { config, ports }, warnings))
}

/// Whether a settings file exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Provisioned {
    /// It was created just now.
    Created,
    /// It was already there, and was not read, rewritten or extended.
    Existed,
}

/// What one pass of [`provision_all`] left behind, for the caller to mention.
///
/// Only files created just now are listed. A file that was already there is not
/// news, and saying so on every run would train a reader to skip the line on the
/// one run where something did appear.
#[derive(Debug, Default)]
pub(crate) struct Provisioning {
    /// The settings files this run created.
    pub(crate) created: Vec<PathBuf>,
    /// Why any of them could not be created.
    pub(crate) problems: Vec<String>,
}

/// Creates both settings files if they are not already there.
///
/// Best effort. A run that could not write one is a run with built-in defaults,
/// not a run that refuses to start.
#[must_use]
pub(crate) fn provision_all() -> Provisioning {
    let mut provisioning = Provisioning::default();

    let engine = engine_settings::paths::user().map(|path| (path, engine_settings::TEMPLATE));
    let cli = user_path().map(|path| (path, TEMPLATE));

    for (path, template) in [engine, cli].into_iter().flatten() {
        match provision(&path, template) {
            Ok(Provisioned::Created) => provisioning.created.push(path),
            Ok(Provisioned::Existed) => {}
            Err(problem) => provisioning.problems.push(problem.to_string()),
        }
    }

    provisioning
}

/// Creates a settings file at `path` if there is not one already.
///
/// Never overwrites. `create_new` fails atomically, so two racing processes
/// cannot both decide the file was missing, and an existing file is never read,
/// reformatted or extended.
///
/// On Unix the directory is `0700` and the file `0600`, because a settings file
/// records which networks somebody scans. Anything created under `sudo` is
/// handed to the user who invoked it; see [`hand_to_invoker`].
pub(crate) fn provision(path: &Path, template: &str) -> Result<Provisioned, SettingsError> {
    let fresh_directory = match path.parent() {
        Some(parent) if !parent.exists() => {
            create_directory(parent)?;
            Some(parent)
        }
        _ => None,
    };

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(template.as_bytes())
                .map_err(|source| SettingsError::Uncreatable {
                    path: path.to_path_buf(),
                    source,
                })?;

            if let Some(directory) = fresh_directory {
                hand_to_invoker(directory);
            }
            hand_to_invoker(path);

            Ok(Provisioned::Created)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(Provisioned::Existed),
        Err(source) => Err(SettingsError::Uncreatable {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Creates a directory and its parents, restrictively on Unix.
fn create_directory(path: &Path) -> Result<(), SettingsError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }

    builder
        .create(path)
        .map_err(|source| SettingsError::Uncreatable {
            path: path.to_path_buf(),
            source,
        })
}

/// Gives something just created to the user who invoked `sudo`.
///
/// Without this, a first run under `sudo` leaves `0600` `root`-owned files in a
/// directory the user is meant to edit, and every later unprivileged run fails
/// to read them.
///
/// Does nothing when `SUDO_UID` and `SUDO_GID` are absent. Failure is ignored.
#[cfg(unix)]
fn hand_to_invoker(path: &Path) {
    let invoker = std::env::var("SUDO_UID")
        .ok()
        .and_then(|uid| uid.parse::<u32>().ok())
        .zip(
            std::env::var("SUDO_GID")
                .ok()
                .and_then(|gid| gid.parse::<u32>().ok()),
        );

    if let Some((uid, gid)) = invoker {
        let _ = std::os::unix::fs::chown(path, Some(uid), Some(gid));
    }
}

/// No `sudo`, and no ownership to hand over.
#[cfg(not(unix))]
fn hand_to_invoker(_path: &Path) {}

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

    fn parse_text(text: &str) -> Result<(Settings, Vec<Warning>), SettingsError> {
        parse(text, Path::new("cli.toml"))
    }

    /// A file that could not be read or created is one console line: the path,
    /// what did not happen to it, and the system's words for why, without the
    /// error number a person reading it has no use for. The engine's file is
    /// said the same way as this crate's.
    #[test]
    fn a_settings_file_that_could_not_be_touched_is_said_in_one_short_line() {
        let path = PathBuf::from("/home/someone/.config/zond/engine.toml");
        let full = || std::io::Error::from_raw_os_error(24);

        let ours = SettingsError::Unreadable {
            path: path.clone(),
            source: full(),
        };
        let engines = SettingsError::Engine(engine_settings::SettingsError::Io {
            path: path.clone(),
            source: full(),
        });
        for error in [ours, engines] {
            assert_eq!(
                error.to_string(),
                "/home/someone/.config/zond/engine.toml not readable (too many open files)"
            );
        }

        let created = SettingsError::Uncreatable {
            path,
            source: std::io::Error::from_raw_os_error(13),
        };
        assert_eq!(
            created.to_string(),
            "/home/someone/.config/zond/engine.toml not created (permission denied)"
        );
    }

    /// The promise [`provision`] makes: a file appearing changes nothing about
    /// the run that follows it.
    #[test]
    fn the_shipped_template_sets_nothing() {
        let (settings, warnings) = parse_text(TEMPLATE).expect("the template is valid TOML");

        assert_eq!(settings.presentation(), None);
        assert_eq!(settings.journal(), None);
        assert_eq!(settings.journal_entry_limit(), None);
        assert_eq!(settings.page_size(), None);
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// A renamed variant the template was not updated for would advertise a
    /// value that is refused.
    #[test]
    fn the_template_documents_every_mode_by_its_real_name() {
        for mode in Presentation::ALL {
            assert!(
                TEMPLATE.contains(mode.as_str()),
                "the template never mentions '{mode}'"
            );
        }
    }

    /// A policy this program does not know is refused, and the file that carried
    /// it is named. Which spellings would have worked is
    /// [`Identity`]'s own business and is asserted beside it.
    #[test]
    fn an_identity_that_is_not_one_is_refused_and_the_file_is_named() {
        let refused = parse_text("identity = \"mac\"\n").expect_err("not a policy");

        assert!(
            matches!(
                refused,
                SettingsError::BadValue {
                    source: UnusableValue::Identity(_),
                    ..
                }
            ),
            "a value that is not a policy cannot be acted on: {refused}"
        );

        let message = refused.to_string();
        assert!(message.contains("cli.toml"), "{message}");
        assert!(message.contains("'mac'"), "{message}");
    }

    /// Every key this document carries is read back out of it.
    ///
    /// One assertion rather than one test per key: the parser is a list of
    /// lookups, and what can go wrong is a key wired to the wrong field or left
    /// out of the struct at the end.
    #[test]
    fn every_key_is_read_out_of_the_document() {
        let (settings, warnings) = parse_text(
            "presentation = \"pipe\"\n\
             colour = \"never\"\n\
             accent_colour = \"violet\"\n\
             identity = \"hardware\"\n\
             journal = false\n\
             journal_entry_limit = 7\n\
             page_size = 3\n",
        )
        .expect("a usable document");

        assert_eq!(settings.presentation(), Some(Presentation::Pipe));
        assert_eq!(settings.colour(), Some(ColourChoice::Never));
        assert_eq!(settings.accent_colour(), Some(Accent::VIOLET));
        assert_eq!(settings.identity(), Some(Identity::Hardware));
        assert_eq!(settings.journal(), Some(false));
        assert_eq!(settings.journal_entry_limit(), Some(EntryLimit::AtMost(7)));
        assert_eq!(settings.page_size(), Some(3));
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// Ignored and named, so a file written by a newer `zond` does not stop an
    /// older one running.
    #[test]
    fn an_unknown_key_is_a_warning_and_not_a_failure() {
        // Deliberately not a key this program might plausibly grow. `colour`
        // stood here until `colour` became real, at which point the test was
        // asserting that a supported key was unsupported.
        let (settings, warnings) =
            parse_text("wobble = true\npresentation = \"minimal\"").expect("still usable");

        assert_eq!(settings.presentation(), Some(Presentation::Minimal));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].key, "wobble");
    }

    /// A known key with an unusable value is different: the user meant to change
    /// something and it did not change.
    #[test]
    fn an_unusable_value_for_a_known_key_is_refused() {
        let refused = parse_text(r#"presentation = "shiny""#);

        let Err(SettingsError::BadValue {
            source: UnusableValue::Presentation(source),
            ..
        }) = refused
        else {
            panic!("a value that is not a mode cannot be acted on");
        };
        assert_eq!(source.written, "shiny");
        assert!(
            source.expected.contains(&"minimal"),
            "the error carries the names that would have worked: {:?}",
            source.expected
        );
    }

    /// Both spellings of the one key in this file whose name is a word English
    /// splits on, because being told `color` is unknown is a poor way to find
    /// out that the file wanted `colour`.
    #[test]
    fn either_spelling_of_the_colour_key_is_read() {
        for text in [r#"colour = "never""#, r#"color = "never""#] {
            let (settings, warnings) = parse_text(text).expect("a known key");
            assert_eq!(settings.colour(), Some(ColourChoice::Never), "{text}");
            assert!(warnings.is_empty(), "{text}: {warnings:?}");
        }
    }

    /// The three shapes a limit can take: a count, none, and every record.
    #[test]
    fn a_journal_entry_limit_is_a_count_or_the_word_unlimited() {
        let read = |text: &str| {
            parse_text(text)
                .expect("a usable limit")
                .0
                .journal_entry_limit()
        };

        assert_eq!(
            read("journal_entry_limit = 10"),
            Some(EntryLimit::AtMost(10))
        );
        assert_eq!(read("journal_entry_limit = 0"), Some(EntryLimit::AtMost(0)));
        assert_eq!(
            read(r#"journal_entry_limit = "unlimited""#),
            Some(EntryLimit::Unlimited)
        );
        assert_eq!(
            read(r#"journal_entry_limit = "UNLIMITED""#),
            Some(EntryLimit::Unlimited)
        );
    }

    /// Refused rather than rounded to something: somebody who wrote one of
    /// these meant a limit, and a limit that quietly did not apply is how a
    /// state directory fills up while its owner believes it is bounded.
    #[test]
    fn a_limit_that_is_not_a_count_or_unlimited_is_refused() {
        for written in [
            "journal_entry_limit = -1",
            "journal_entry_limit = true",
            r#"journal_entry_limit = "all""#,
            r#"journal_entry_limit = "none""#,
            r#"journal_entry_limit = "100""#,
            "journal_entry_limit = 1.5",
        ] {
            let Err(SettingsError::BadValue {
                source: UnusableValue::EntryLimit(source),
                ..
            }) = parse_text(written)
            else {
                panic!("'{written}' is not a limit and must be refused");
            };

            let message = source.to_string();
            assert!(
                message.contains("unlimited"),
                "the message names what would have worked: {message}"
            );

            let value = written.split_once(" = ").expect("a key and a value").1;
            assert!(
                message.contains(value),
                "the message quotes back what was written ({value}): {message}"
            );
        }
    }

    /// Every accent the code accepts by name is one the template names. A
    /// colour nobody can discover is a colour nobody has.
    #[test]
    fn the_template_lists_every_accent_it_could_be_given() {
        for (name, _) in Accent::ALL {
            assert!(
                TEMPLATE.contains(name),
                "the template never mentions the '{name}' accent"
            );
        }

        assert!(
            TEMPLATE.contains(&Accent::default().as_hex()),
            "the template never shows a triplet, which is the other half of the key"
        );
    }

    /// The number in the template is the number the code applies. These drift
    /// apart silently: nothing about a wrong comment stops a build.
    #[test]
    fn the_template_documents_the_default_limit_it_actually_gets() {
        let EntryLimit::AtMost(default) = EntryLimit::DEFAULT else {
            panic!("the default has to be a number to be documented as one");
        };

        assert!(
            TEMPLATE.contains(&format!("journal_entry_limit = {default}")),
            "the template never shows the default of {default}"
        );
        assert!(
            TEMPLATE.contains(&format!(r#""{}""#, EntryLimit::UNLIMITED)),
            "the template never mentions the one value that lifts the limit"
        );
    }

    /// A file that says nothing about a key leaves the lower layer's answer
    /// standing.
    #[test]
    fn a_later_file_overrides_only_what_it_mentions() {
        let mut settings = Settings {
            risk: None,
            presentation: Some(Presentation::Minimal),
            colour: Some(ColourChoice::Never),
            accent_colour: Some(Accent::VIOLET),
            reason: Some(true),
            remedy: None,
            evidence: None,
            identity: Some(Identity::Hardware),
            journal: Some(false),
            journal_entry_limit: Some(EntryLimit::Unlimited),
            page_size: Some(3),
        };

        settings.overlay(Settings::default());
        assert_eq!(
            settings.presentation(),
            Some(Presentation::Minimal),
            "a file that said nothing must not reset anything"
        );
        assert_eq!(
            settings.colour(),
            Some(ColourChoice::Never),
            "nor any other"
        );
        assert_eq!(
            settings.identity(),
            Some(Identity::Hardware),
            "nor any other"
        );
        assert_eq!(settings.journal(), Some(false), "nor any other");
        assert_eq!(settings.reason(), Some(true), "nor any other");
        assert_eq!(
            settings.journal_entry_limit(),
            Some(EntryLimit::Unlimited),
            "nor any other"
        );
        assert_eq!(settings.page_size(), Some(3), "nor any other");
        assert_eq!(
            settings.accent_colour(),
            Some(Accent::VIOLET),
            "nor the one colour a person is allowed to move"
        );

        settings.overlay(Settings {
            risk: None,
            presentation: Some(Presentation::Minimal),
            colour: None,
            accent_colour: None,
            reason: None,
            remedy: None,
            evidence: None,
            identity: None,
            journal: None,
            journal_entry_limit: None,
            page_size: None,
        });
        assert_eq!(settings.presentation(), Some(Presentation::Minimal));
        assert_eq!(
            settings.journal(),
            Some(false),
            "a file that mentioned only the presentation left this alone"
        );
    }

    /// If these diverged, a user would edit one of two config directories at
    /// random.
    #[test]
    fn this_crates_file_sits_beside_the_engines() {
        let (Some(ours), Some(theirs)) = (user_path(), engine_settings::paths::user()) else {
            // No home in the environment, so nothing to compare.
            return;
        };

        assert_eq!(ours.parent(), theirs.parent());
        assert_ne!(ours.file_name(), theirs.file_name());
    }
}
