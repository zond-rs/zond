// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a run looks like
//!
//! One trait, one implementation per [`Presentation`], and the function that
//! picks between them. The trait is what keeps the commands from knowing about
//! columns.
//!
//! - [`pipe`] — every field, tab-separated, fixed units, no padding, no
//!   heading. The only mode whose output is a stable interface.
//! - [`minimal`] — a tagged block per host, for reading.
//! - `standard` and `fancy` — not built. See [`Presentation`].
//!
//! `pipe` is not a step on that ladder; it is a different audience.
//!
//! **Failures are not a renderer's business.** The engine logs a failed strategy
//! *and* records it, and [`diagnostics`](crate::diagnostics) already prints the
//! log. A renderer gets the finished [`ScanReport`], which says how much of the
//! scan was covered.
//!
//! **Records to standard output, commentary to standard error** — in every mode.
//! A renderer is the only thing here that writes to either.

// One module per presentation.
pub(crate) mod minimal;
pub(crate) mod pipe;

// Plumbing the two share: the field values, and the commentary on stderr.
pub(crate) mod field;
pub(crate) mod narrate;

#[cfg(test)]
pub(crate) mod test_support;

use std::io;

use zond_engine::export::Redaction;
use zond_engine::{Host, ScanReport};

use crate::diagnostics::Verbosity;
use crate::settings::Presentation;
use crate::target::{ScanTargets, Targets};

/// What a run is about to do.
///
/// Facts rather than a pre-composed sentence, so the phrasing stays in the
/// renderer. Two variants because the phases are counted in different units — a
/// sweep in addresses, a port scan in probes.
#[derive(Clone, Copy)]
pub(crate) enum Phase<'a> {
    /// Finding which hosts are alive.
    Discovery {
        /// What was asked about.
        targets: &'a Targets,
    },
    /// Finding which of the named hosts' ports are open.
    PortScan {
        /// What was asked about, and on which ports.
        targets: &'a ScanTargets,
    },
}

/// Everything a run shows, as it happens.
///
/// Every method returns [`io::Result`] rather than swallowing failures: a closed
/// standard output is how `zond discover lan | head` ends, and the command has
/// to hear about it rather than scan a network into a pipe nobody is reading.
pub(crate) trait Renderer {
    /// A run is about to start, under `redaction`.
    ///
    /// The masking policy arrives here rather than at construction because it
    /// comes from the resolved configuration — the first moment it is known, and
    /// the last at which it can be delivered.
    fn started(&mut self, phase: Phase<'_>, redaction: Redaction) -> io::Result<()>;

    /// A host has been found alive that was not known before.
    ///
    /// Called for every update the engine announces; a renderer that reports
    /// each host once is responsible for remembering which ones it has already
    /// reported.
    fn host_found(&mut self, host: &Host) -> io::Result<()>;

    /// The user asked the scan to stop. It is winding down, and will still
    /// report what it found.
    fn interrupted(&mut self) -> io::Result<()>;

    /// The scan is over. This is where the results are written.
    fn finished(&mut self, report: &ScanReport) -> io::Result<()>;
}

/// A presentation mode that is named but not built.
///
/// Returned rather than quietly substituted: somebody who set
/// `presentation = "fancy"` and got plain columns would go looking for the
/// wrong bug.
#[derive(Debug, thiserror::Error)]
#[error(
    "the '{presentation}' presentation is not built yet. Built so far: {}.",
    Presentation::ALL
        .iter()
        .filter(|mode| mode.is_available())
        .map(|mode| mode.as_str())
        .collect::<Vec<_>>()
        .join(", ")
)]
pub(crate) struct Unavailable {
    /// The mode that was asked for.
    pub presentation: Presentation,
}

/// The renderer to use for this run.
///
/// The one place presentation is chosen.
pub(crate) fn renderer(
    presentation: Presentation,
    verbosity: Verbosity,
) -> Result<Box<dyn Renderer>, Unavailable> {
    match presentation {
        Presentation::Pipe => Ok(Box::new(pipe::PipeRenderer::to_terminal(verbosity))),
        Presentation::Minimal => Ok(Box::new(minimal::MinimalRenderer::to_terminal(verbosity))),
        Presentation::Standard | Presentation::Fancy => Err(Unavailable { presentation }),
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

    #[test]
    fn the_built_modes_produce_a_renderer() {
        assert!(renderer(Presentation::Pipe, Verbosity::default()).is_ok());
        assert!(renderer(Presentation::Minimal, Verbosity::default()).is_ok());
    }

    /// Named but not built is an error, not a quiet fall back. Somebody who set
    /// `fancy` and got plain columns would go looking for a bug in their
    /// settings file.
    #[test]
    fn a_mode_that_is_not_built_is_refused_rather_than_substituted() {
        for mode in [Presentation::Standard, Presentation::Fancy] {
            let refused = renderer(mode, Verbosity::default());
            let Err(unavailable) = refused else {
                panic!("{mode} is not built and must not silently become another mode");
            };
            assert_eq!(unavailable.presentation, mode);
            assert!(unavailable.to_string().contains("minimal"));
        }
    }

    /// Whatever the enum grows, the two questions must keep the same answer: a
    /// mode `is_available` exactly when a renderer can be built for it.
    #[test]
    fn availability_agrees_with_what_can_be_built() {
        for mode in Presentation::ALL {
            assert_eq!(
                mode.is_available(),
                renderer(mode, Verbosity::default()).is_ok(),
                "{mode} disagrees with itself"
            );
        }
    }
}
