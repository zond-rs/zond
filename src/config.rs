// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # CLI Presentation Configuration
//!
//! Presentation is a concern of the interface, not of the engine. The core
//! [`ZondConfig`](zond_engine::core::config::ZondConfig) exists to drive the
//! *scan* — how packets are placed on the wire, whether DNS is emitted — and
//! deliberately knows nothing about terminals, colors, or verbosity. That keeps
//! the engine reusable behind any front end: this CLI today, a TUI or a Web UI
//! tomorrow.
//!
//! [`DisplayConfig`] is where the terminal front end keeps *its* state. It is
//! built from the parsed [`CommandLine`] and consumed only by the
//! [`terminal`](crate::terminal) layer; the engine never sees it. Adding a new
//! output toggle means adding a field here, not widening the engine's config.

use crate::commands::CommandLine;

/// Runtime presentation preferences for the terminal front end.
///
/// Holds every flag that changes *how results are rendered* rather than *what is
/// scanned*. Constructed once from the CLI arguments and handed to
/// [`Print::init`](crate::terminal::print::Print::init).
#[derive(Debug, Clone, Copy, Default)]
pub struct DisplayConfig {
    /// Suppresses the startup ASCII banner while keeping logs and colors.
    pub no_banner: bool,

    /// Visual-density level, mapped from `-q` / `--quiet`.
    ///
    /// * `0` — full UI.
    /// * `1` — reduced styling.
    /// * `2` — raw, pipe-friendly output.
    pub quiet: u8,

    /// Masks sensitive fields (IPv6 suffixes, MAC addresses, hostnames) so
    /// output is safe to share.
    pub redact: bool,

    /// Expands each identified service into the full fingerprint evidence —
    /// vendor, environment `extrainfo`, CPE identifiers, and identification
    /// confidence — as a nested detail tree.
    ///
    /// Purely presentational: fingerprinting always runs in the engine, this
    /// only controls how much of its result reaches the terminal.
    pub detailed: bool,
}

impl From<&CommandLine> for DisplayConfig {
    fn from(cmd: &CommandLine) -> Self {
        Self {
            no_banner: cmd.no_banner,
            quiet: cmd.quiet,
            redact: cmd.redact,
            detailed: cmd.detailed,
        }
    }
}
