// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a merge says beside its report
//!
//! Almost nothing, and that is the point. A merge produces a
//! [`ScanReport`](zond_engine::ScanReport), which is the same thing a scan
//! produces, so it prints through the same renderer and there is nothing here
//! about hosts or ports.
//!
//! What is here is the line that is about the command rather than about the
//! network: where the report went. Which source said what is narrated before the
//! fold instead, from [`Phase::Merged`](crate::render::Phase::Merged).

use std::io::{self, Write};

use crate::render::style::{Mark, Style};

/// Says the report went to the terminal, and how to put it in a file instead.
///
/// **Only for a report that reached a terminal.** Somebody who redirected this
/// has already said where they want it, and a scheduled job that finds this in
/// its log every night learns to filter the stream it carries the real
/// commentary on.
///
/// Written after the report rather than before it, because that is where a
/// reader is standing when they decide they wanted a file: at the bottom, having
/// just watched two hundred hosts go past.
pub(crate) fn printed(out: &mut dyn Write, style: Style) -> io::Result<()> {
    writeln!(
        out,
        "{}",
        style.line(
            Mark::Info,
            "printed to the terminal; add -o FILE to write it down"
        )
    )
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

    /// It names the flag, because a line telling somebody a file would have been
    /// possible without saying how is worse than no line at all.
    #[test]
    fn the_line_names_the_flag_that_writes_a_file() {
        let mut written = Vec::new();
        printed(&mut written, Style::bare()).expect("a vector takes writes");

        let written = String::from_utf8(written).expect("text");
        assert!(written.contains("-o FILE"), "{written}");
    }
}
