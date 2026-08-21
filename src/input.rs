// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the user asks of a running scan
//!
//! Two ways to stop a running scan, meaning the same thing: `Ctrl-C`, and `q`.
//!
//! Asking once stops the scan and waits for it, so the hosts already found are
//! still reported and the report records that the run was cut short. Asking
//! twice leaves immediately, giving up the probes still in flight.
//!
//! ## Reading a single keypress
//!
//! A terminal is line-buffered, so `q` would not arrive until Enter followed it.
//! This module puts the terminal in *cbreak* for the length of the run —
//! `ICANON` and `ECHO` off — and puts it back afterwards.
//!
//! Cbreak rather than raw mode: `ISIG` stays on, so the terminal still turns
//! `Ctrl-C` into `SIGINT`. Raw mode would deliver it as a keystroke instead, and
//! a run that died without restoring the terminal would leave a shell that
//! cannot interrupt anything.
//!
//! When stdin is not a terminal — a pipe, a script, the test suite — nothing is
//! changed and no key is read. `Ctrl-C` still stops the scan.

use std::io::Read;

use tokio::signal;
use tokio::sync::mpsc;

use zond_engine::ScanHandle;

/// The keys that stop a scan.
const QUIT: [u8; 2] = *b"qQ";

/// The user's requests to stop the run.
///
/// Holds the terminal's original settings for as long as the run lasts, so
/// dropping this is what puts the terminal back.
pub(crate) struct StopRequests {
    requests: mpsc::Receiver<()>,
    _terminal: Option<terminal::Cbreak>,
}

impl StopRequests {
    /// Waits for the next request to stop.
    ///
    /// `None` when nothing can ask any more, which cannot happen while a scan is
    /// running: the signal watcher outlives it.
    pub(crate) async fn recv(&mut self) -> Option<()> {
        self.requests.recv().await
    }
}

/// Starts watching for a request to stop the scan behind `handle`.
pub(crate) fn watch(handle: &ScanHandle) -> StopRequests {
    // Two slots: stop the scan, then give up waiting for it. A third request
    // has nothing left to ask for.
    let (requests, receiver) = mpsc::channel(2);

    watch_signals(requests.clone(), handle.clone());

    let terminal = terminal::cbreak();
    if terminal.is_some() {
        watch_keys(requests, handle.clone());
    }

    StopRequests {
        requests: receiver,
        _terminal: terminal,
    }
}

/// Asks the scan to stop on `Ctrl-C`, and passes on each press.
///
/// A task of its own, always waiting on the next signal, rather than a branch in
/// the caller's `select!`. A future built fresh each time round a loop is not
/// listening in the gap between iterations, and the one signal a user sends is
/// exactly the thing that must not land in a gap.
fn watch_signals(requests: mpsc::Sender<()>, handle: ScanHandle) {
    tokio::spawn(async move {
        while signal::ctrl_c().await.is_ok() {
            // Here rather than in the receiver, so winding down starts at the
            // press instead of whenever the event loop next comes round.
            handle.abort();
            if requests.send(()).await.is_err() {
                break;
            }
        }
    });
}

/// Asks the scan to stop when `q` is pressed.
///
/// An ordinary thread, not `spawn_blocking`: a blocking read of stdin cannot be
/// cancelled, and tokio waits for its blocking pool before shutting down. A
/// thread the runtime does not know about is abandoned at exit instead.
///
/// The read still times out. A thread sitting in `read` after the scan ends
/// would swallow the first thing typed at the shell. See [`terminal::cbreak`].
fn watch_keys(requests: mpsc::Sender<()>, handle: ScanHandle) {
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut typed = [0u8; 1];

        while !requests.is_closed() {
            match stdin.read(&mut typed) {
                Ok(read) if read > 0 && QUIT.contains(&typed[0]) => {
                    handle.abort();
                    // Legal because this thread is not the runtime's, and wanted
                    // because a dropped request is a keypress made twice.
                    if requests.blocking_send(()).is_err() {
                        break;
                    }
                }
                // Timed out with nothing typed, or a key that is not the one.
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
}

/// Putting the terminal into cbreak, and putting it back.
#[cfg(unix)]
mod terminal {
    use rustix::stdio::stdin;
    use rustix::termios::{
        LocalModes, OptionalActions, SpecialCodeIndex, Termios, isatty, tcgetattr, tcsetattr,
    };

    /// How long a read waits before returning empty-handed, in tenths of a
    /// second.
    ///
    /// The whole of what stops the reading thread parking forever.
    const READ_TIMEOUT_DECISECONDS: u8 = 1;

    /// The terminal's settings from before the scan, put back on drop.
    pub(super) struct Cbreak(Termios);

    /// Puts stdin in cbreak, if stdin is a terminal at all.
    ///
    /// `None` when it is not, and when the terminal refuses — neither is a
    /// reason to fail a scan, and both simply mean `q` will not be read.
    pub(super) fn cbreak() -> Option<Cbreak> {
        if !isatty(stdin()) {
            return None;
        }

        let original = tcgetattr(stdin()).ok()?;
        let mut wanted = original.clone();

        // ICANON off delivers the key without Enter; ECHO off keeps it out of
        // the results. ISIG is left alone, and that keeps Ctrl-C a signal.
        wanted
            .local_modes
            .remove(LocalModes::ICANON | LocalModes::ECHO);
        wanted.special_codes[SpecialCodeIndex::VMIN] = 0;
        wanted.special_codes[SpecialCodeIndex::VTIME] = READ_TIMEOUT_DECISECONDS;

        tcsetattr(stdin(), OptionalActions::Now, &wanted).ok()?;

        Some(Cbreak(original))
    }

    impl Drop for Cbreak {
        fn drop(&mut self) {
            // Nothing useful to do if this fails, and a scan that answered the
            // question should not fail over its own tidying up.
            let _ = tcsetattr(stdin(), OptionalActions::Now, &self.0);
        }
    }
}

/// No terminal to put into cbreak, so no key to read.
#[cfg(not(unix))]
mod terminal {
    /// Nothing to restore.
    pub(super) struct Cbreak;

    /// Always `None`, which leaves `Ctrl-C` as the only way to stop a scan.
    pub(super) fn cbreak() -> Option<Cbreak> {
        None
    }
}
