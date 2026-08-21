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
//! land in different directories — `$XDG_CONFIG_HOME` when it is absolute,
//! `$HOME/.config` otherwise, and `/etc/zond` for a host-wide file underneath
//! both.
//!
//! ## When the files appear
//!
//! On the first run that can write them, from templates compiled in with
//! `include_str!` — so a first run works offline. Not at build time, because a
//! package installed by `root` would provision `root`'s configuration and
//! nobody else's.
//!
//! Provisioning never overwrites, never edits, and never changes behaviour:
//! every key in both templates is commented out. Failure to write is not fatal.
//!
//! Discovery wants root, so the first run is very often `sudo zond discover lan`
//! and the files would be created `root`-owned and mode `0600` — unreadable by
//! the user's own later runs. When `SUDO_UID` and `SUDO_GID` say who asked,
//! anything newly created is handed to them. See [`provision`].

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

use zond_engine::import::settings as engine_settings;
use zond_engine::{PortSet, ZondConfig};

/// This crate's settings file, as it is named on disk.
///
/// Beside the engine's `engine.toml`, which is what the engine's own path
/// documentation says a front end should do.
pub(crate) const FILE_NAME: &str = "cli.toml";

/// The document written when there is not one already.
///
/// Compiled in rather than fetched or generated: see the module documentation.
pub(crate) const TEMPLATE: &str = include_str!("../assets/settings/cli.toml");

/// How a run is drawn.
///
/// Four modes: one for programs and three for people. [`Pipe`](Self::Pipe) is
/// not a step on that ladder, it is a different audience.
///
/// [`Standard`](Self::Standard) and [`Fancy`](Self::Fancy) are named before they
/// are built, so that `presentation = "fancy"` is answered with "not ready"
/// rather than "not a word".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Presentation {
    /// Tab-separated records for a program: no padding, no heading, no unit
    /// suffixes, and every field a scan established. The only mode whose output
    /// is a stable interface.
    Pipe,
    /// A narrow aligned table for a person. The default until
    /// [`Standard`](Self::Standard) exists.
    #[default]
    Minimal,
    /// Not built yet. More of what a scan found, still without colour, and
    /// intended to become the default.
    Standard,
    /// Not built yet. Colour and decoration, for a terminal being watched by a
    /// person rather than a script.
    Fancy,
}

impl Presentation {
    /// Every mode, least to most, with the machine-readable one first.
    pub(crate) const ALL: [Presentation; 4] = [
        Presentation::Pipe,
        Presentation::Minimal,
        Presentation::Standard,
        Presentation::Fancy,
    ];

    /// The mode as it is written in a settings file or on the command line.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Presentation::Pipe => "pipe",
            Presentation::Minimal => "minimal",
            Presentation::Standard => "standard",
            Presentation::Fancy => "fancy",
        }
    }

    /// Whether this mode has been built.
    ///
    /// One that has not is refused rather than quietly served as
    /// [`Minimal`](Self::Minimal).
    #[must_use]
    pub(crate) fn is_available(self) -> bool {
        matches!(self, Presentation::Pipe | Presentation::Minimal)
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
/// verbatim — the same shape the engine's own settings errors take.
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
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// Why it could not be read.
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
        source: UnknownPresentation,
    },

    /// The engine's own settings could not be resolved.
    #[error("{0}")]
    Engine(#[from] engine_settings::SettingsError),
}

/// What this crate's settings file said.
///
/// Every field is optional and means "this file did not mention it". That is
/// what makes layering work: saying nothing must not overrule a lower layer.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Settings {
    presentation: Option<Presentation>,
}

impl Settings {
    /// The presentation these settings ask for, if they ask for one.
    #[must_use]
    pub(crate) fn presentation(self) -> Option<Presentation> {
        self.presentation
    }

    /// Lays `other` over this, key by key.
    fn overlay(&mut self, other: Settings) {
        if let Some(presentation) = other.presentation {
            self.presentation = Some(presentation);
        }
    }
}

/// The shape of the document on disk.
///
/// Unknown keys are collected rather than refused. See [`Warning`].
#[derive(Debug, Default, Deserialize)]
struct Document {
    presentation: Option<String>,
    #[serde(flatten)]
    unknown: BTreeMap<String, toml::Value>,
}

/// Reads one document, reporting what it could not use.
fn parse(text: &str, path: &Path) -> Result<(Settings, Vec<Warning>), SettingsError> {
    let document: Document = toml::from_str(text).map_err(|source| SettingsError::Malformed {
        path: path.to_path_buf(),
        source,
    })?;

    let presentation = document
        .presentation
        .as_deref()
        .map(Presentation::from_str)
        .transpose()
        .map_err(|source| SettingsError::BadValue {
            path: path.to_path_buf(),
            source,
        })?;

    let warnings = document
        .unknown
        .into_keys()
        .map(|key| Warning {
            path: path.to_path_buf(),
            key,
        })
        .collect();

    Ok((Settings { presentation }, warnings))
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
/// files stay in one directory on every platform the engine decides to support.
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

        let text = std::fs::read_to_string(&path).map_err(|source| SettingsError::Io {
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
    /// document: asking for it separately meant reading and parsing
    /// `engine.toml` a second time, and two reads can disagree.
    pub(crate) ports: Option<PortSet>,
}

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

/// Creates both settings files if they are not already there.
///
/// Best effort: a run that could not write one is a run with built-in defaults,
/// not a run that refuses to start. Returns the files created just now — an
/// existing file is not news — and whatever went wrong, for the caller to
/// mention.
#[must_use]
pub(crate) fn provision_all() -> (Vec<PathBuf>, Vec<String>) {
    let mut created = Vec::new();
    let mut problems = Vec::new();

    let engine = engine_settings::paths::user().map(|path| (path, engine_settings::TEMPLATE));
    let cli = user_path().map(|path| (path, TEMPLATE));

    for (path, template) in [engine, cli].into_iter().flatten() {
        match provision(&path, template) {
            Ok(Provisioned::Created) => created.push(path),
            Ok(Provisioned::Existed) => {}
            Err(problem) => problems.push(problem.to_string()),
        }
    }

    (created, problems)
}

/// Creates a settings file at `path` if there is not one already.
///
/// Never overwrites — `create_new` fails atomically, so two racing processes
/// cannot both decide the file was missing. Never reads, reformats or extends an
/// existing one.
///
/// On Unix the directory is `0700` and the file `0600`: a settings file records
/// which networks somebody scans. Anything created under `sudo` is handed to the
/// user who invoked it — see [`hand_to_invoker`].
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
                .map_err(|source| SettingsError::Io {
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
        Err(source) => Err(SettingsError::Io {
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

    builder.create(path).map_err(|source| SettingsError::Io {
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

    /// The promise [`provision`] makes: a file appearing changes nothing about
    /// the run that follows it.
    #[test]
    fn the_shipped_template_sets_nothing() {
        let (settings, warnings) = parse_text(TEMPLATE).expect("the template is valid TOML");

        assert_eq!(settings.presentation(), None);
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

    #[test]
    fn a_presentation_is_read_from_the_document() {
        let (settings, _) = parse_text(r#"presentation = "pipe""#).expect("a known mode");
        assert_eq!(settings.presentation(), Some(Presentation::Pipe));
    }

    /// Ignored and named, so a file written by a newer `zond` does not stop an
    /// older one running.
    #[test]
    fn an_unknown_key_is_a_warning_and_not_a_failure() {
        let (settings, warnings) =
            parse_text("colour = true\npresentation = \"minimal\"").expect("still usable");

        assert_eq!(settings.presentation(), Some(Presentation::Minimal));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].key, "colour");
    }

    /// A known key with an unusable value is different: the user meant to change
    /// something and it did not change.
    #[test]
    fn an_unusable_value_for_a_known_key_is_refused() {
        let refused = parse_text(r#"presentation = "shiny""#);

        let Err(SettingsError::BadValue { source, .. }) = refused else {
            panic!("a value that is not a mode cannot be acted on");
        };
        assert_eq!(source.written, "shiny");
        assert!(
            source.expected.contains(&"minimal"),
            "the error carries the names that would have worked: {:?}",
            source.expected
        );
    }

    /// The list of built modes, asserted rather than left to drift. A half-built
    /// mode reporting itself available is how one ships.
    #[test]
    fn only_the_built_modes_report_themselves_available() {
        assert!(Presentation::Pipe.is_available());
        assert!(Presentation::Minimal.is_available());
        assert!(!Presentation::Standard.is_available());
        assert!(!Presentation::Fancy.is_available());
        assert_eq!(Presentation::default(), Presentation::Minimal);
    }

    #[test]
    fn a_mode_is_read_whatever_its_case() {
        assert_eq!(
            "MINIMAL".parse::<Presentation>().expect("known"),
            Presentation::Minimal
        );
        assert_eq!(
            "Fancy".parse::<Presentation>().expect("known"),
            Presentation::Fancy
        );
    }

    #[test]
    fn every_mode_parses_back_from_its_own_name() {
        for mode in Presentation::ALL {
            assert_eq!(mode.as_str().parse::<Presentation>().expect("known"), mode);
        }
    }

    /// A file that says nothing about a key leaves the lower layer's answer
    /// standing.
    #[test]
    fn a_later_file_overrides_only_what_it_mentions() {
        let mut settings = Settings {
            presentation: Some(Presentation::Fancy),
        };

        settings.overlay(Settings::default());
        assert_eq!(
            settings.presentation(),
            Some(Presentation::Fancy),
            "a file that said nothing must not reset anything"
        );

        settings.overlay(Settings {
            presentation: Some(Presentation::Minimal),
        });
        assert_eq!(settings.presentation(), Some(Presentation::Minimal));
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
