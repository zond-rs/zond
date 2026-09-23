// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # How many files this process may hold open
//!
//! Every connect probe holds a socket, and the engine gives its probes half
//! the process's soft descriptor limit and no more. A macOS Terminal starts at
//! 256, which holds a sweep to 128 connects in flight where it would keep
//! 2,048, and a Linux shell at 1,024. The engine reads that limit and never
//! raises it, because the process is not a library's to change. This binary
//! is the process, so it raises its own soft limit at start, before a scan
//! reads it.
//!
//! Only the soft limit moves, and never past the hard one, which is where an
//! administrator set the ceiling; a shell that lowered both, as `ulimit -n`
//! does, is taken at its word.

/// The soft limit this binary raises itself to, where the hard limit allows.
///
/// macOS's `OPEN_MAX`, the most `setrlimit` accepts on every version of it,
/// and enough for the engine's half to hold the widest sweep it runs with room
/// to spare. Nothing here needs more, and the limit is inherited by anything
/// the process starts.
#[cfg(unix)]
const WANTED: u64 = 10_240;

/// Raises this process's soft descriptor limit towards [`WANTED`].
///
/// Best effort. A limit that cannot be raised leaves the scan slower, never
/// wrong: the engine sizes itself from whatever limit it finds.
pub(crate) fn raise() {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, getrlimit, setrlimit};

        let mut limit = getrlimit(Resource::Nofile);
        let wanted = limit.maximum.map_or(WANTED, |hard| hard.min(WANTED));
        if limit.current.is_some_and(|soft| soft < wanted) {
            limit.current = Some(wanted);
            let _ = setrlimit(Resource::Nofile, limit);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use rustix::process::{Resource, getrlimit};

    /// The soft limit ends at least where the hard one lets it reach, and the
    /// hard one is left where it was. Raising is all this does, so it is safe
    /// to run in the test process itself.
    #[test]
    fn the_soft_limit_is_raised_as_far_as_the_hard_one_allows() {
        let before = getrlimit(Resource::Nofile);
        raise();
        let after = getrlimit(Resource::Nofile);

        let wanted = before.maximum.map_or(WANTED, |hard| hard.min(WANTED));
        assert!(
            after.current.is_none_or(|soft| soft >= wanted),
            "the soft limit stayed at {:?} under a hard limit of {:?}",
            after.current,
            after.maximum
        );
        assert_eq!(after.maximum, before.maximum, "the hard limit is not moved");
    }
}
