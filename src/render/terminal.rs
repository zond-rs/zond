// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Whether a stream draws what is written to it
//!
//! Colour and the progress line are escape sequences this crate writes itself,
//! and a terminal has to turn them into colour and cursor movement rather than
//! print them. A unix terminal always does. A Windows console does once virtual
//! terminal processing is on for it: Windows Terminal turns it on for every
//! program it hosts, and the classic console host turns it on for none. Left
//! off, every painted line prints as `←[38;5;103m…←[0m` and every redraw of the
//! progress line lands on a line of its own.
//!
//! So each console is asked to interpret them, once and before anything is
//! drawn, and what it answers decides whether anything is. A terminal that
//! cannot interpret them is written to as a redirected stream is: plain text,
//! and no line that rewrites itself.
//!
//! The mode is left on at exit. It changes how the console reads escape
//! sequences and nothing else, and the shell that gets the console back does
//! not depend on its being off.

use std::io::IsTerminal;
use std::sync::OnceLock;

/// One of the two streams this program draws on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    /// Where the records go.
    Stdout,
    /// Where the commentary and the progress line go.
    Stderr,
}

/// What a stream's console said when asked to interpret escape sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Console {
    /// There is no console to ask. Every unix terminal is this, and so on
    /// Windows is a terminal emulator that reaches its program through a pipe,
    /// as mintty does, interpreting the sequences itself.
    Absent,
    /// It interprets them, whether it already did or has just been asked to.
    ///
    /// Only a Windows console answers this way, so only a Windows build, or
    /// the tests, construct it.
    #[cfg_attr(not(windows), allow(dead_code))]
    Interprets,
    /// It declined, as a console host older than virtual terminal processing
    /// does.
    Declined,
}

/// Whether escape sequences written to a stream are drawn rather than printed.
///
/// Only a terminal draws anything. A redirected stream keeps whatever is
/// written to it, so it gets plain text whatever its console would say, and a
/// terminal draws unless it is a console that declined.
fn draws(is_terminal: bool, console: Console) -> bool {
    is_terminal && console != Console::Declined
}

/// Standard output's answer and standard error's, settled once.
static DRAWS: OnceLock<[bool; 2]> = OnceLock::new();

/// Asks each console to interpret escape sequences, before anything is drawn.
///
/// Called first thing in `main`. The first question [`interprets`] is asked
/// would do the same, so calling this again, or not at all, changes nothing
/// but when the console is asked.
pub(crate) fn prepare() {
    let _ = settled();
}

/// Whether escape sequences written to `stream` are drawn rather than printed.
///
/// The question colour and the progress line both put before writing any.
pub(crate) fn interprets(stream: Stream) -> bool {
    let [stdout, stderr] = *settled();

    match stream {
        Stream::Stdout => stdout,
        Stream::Stderr => stderr,
    }
}

fn settled() -> &'static [bool; 2] {
    DRAWS.get_or_init(|| [settle(Stream::Stdout), settle(Stream::Stderr)])
}

/// Asks one stream's console, and says whether the stream draws.
///
/// A stream that is not a terminal is not asked: it is written to plainly
/// whatever its console says, and asking would change the mode of a console
/// this stream does not write to.
fn settle(stream: Stream) -> bool {
    let is_terminal = match stream {
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
    };

    let console = if is_terminal {
        console::ask(stream)
    } else {
        Console::Absent
    };

    draws(is_terminal, console)
}

/// The Windows console, asked through the two calls that read and set its mode.
///
/// The one place this crate uses `unsafe`: std offers no safe way to set a
/// console's mode, and the lint table denies it everywhere else.
#[cfg(windows)]
#[allow(unsafe_code)]
mod console {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::System::Console::{
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, SetConsoleMode,
    };

    use super::{Console, Stream};

    /// Turns virtual terminal processing on for `stream`'s console, if it has
    /// one and it is not on already.
    pub(super) fn ask(stream: Stream) -> Console {
        let handle = match stream {
            Stream::Stdout => std::io::stdout().as_raw_handle(),
            Stream::Stderr => std::io::stderr().as_raw_handle(),
        };

        let mut mode = 0;
        // SAFETY: `mode` is a live local the call writes one `u32` into. The
        // handle is this process's own standard handle and is only read by the
        // call: one that is null or not a console makes it fail, which is the
        // answer asked for.
        if unsafe { GetConsoleMode(handle, &raw mut mode) } == 0 {
            return Console::Absent;
        }

        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return Console::Interprets;
        }

        // SAFETY: the handle the call above has just read a mode from, and that
        // mode with one flag added. A console that does not know the flag
        // refuses the call and keeps its mode.
        if unsafe { SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) } == 0 {
            return Console::Declined;
        }

        Console::Interprets
    }
}

/// Anywhere else a terminal interprets escape sequences itself, and there is
/// no console to ask.
#[cfg(not(windows))]
mod console {
    use super::{Console, Stream};

    pub(super) fn ask(_: Stream) -> Console {
        Console::Absent
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

    /// A console that declined is written to plainly, which is the whole of
    /// the defect this module exists for: it is a terminal, and one that prints
    /// every escape sequence it is sent.
    #[test]
    fn a_console_that_declined_is_written_to_plainly() {
        assert!(!draws(true, Console::Declined));
    }

    /// A console that interprets the sequences, whether it did already or was
    /// just asked, is drawn on.
    #[test]
    fn a_console_that_interprets_is_drawn_on() {
        assert!(draws(true, Console::Interprets));
    }

    /// A terminal with no console behind it is drawn on as it always was.
    ///
    /// Every unix terminal is one, so this is the case that must not move, and
    /// so is a Windows terminal emulator reached through a pipe, which would
    /// lose its colour if a failed console query were read as a refusal.
    #[test]
    fn a_terminal_with_no_console_is_drawn_on() {
        assert!(draws(true, Console::Absent));
    }

    /// A redirected stream gets plain text whatever its console would have
    /// said, so a file or a pipe never collects escape sequences it would keep.
    #[test]
    fn a_redirected_stream_is_never_drawn_on() {
        for console in [Console::Absent, Console::Interprets, Console::Declined] {
            assert!(!draws(false, console), "{console:?}");
        }
    }
}
