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
//! the process's soft descriptor limit and no more, keeping at least sixteen
//! for everything else the process holds, this binary's journal among them.
//! A macOS Terminal starts at 256, which holds a sweep to 128 connects in
//! flight where it would keep 2,048, and a Linux shell at 1,024; under a
//! limit too small to keep both, the engine refuses the scan before it
//! starts. The engine reads that limit and never raises it, because the
//! process is not a library's to change. This binary is the process, so it
//! raises its own soft limit at start, before a scan reads it.
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

/// Running a test out of descriptors without taking every other test down
/// with it.
///
/// A test that fills this process's descriptor table would take every test
/// running beside it down too, so it runs its body in a process of its own:
/// [`in_a_process_of_its_own`](testing::in_a_process_of_its_own) re-runs the
/// test binary on that one test, and the re-run fills its own table with
/// [`exhaust`](testing::exhaust).
#[cfg(all(test, unix))]
pub(crate) mod testing {
    use rustix::process::{Resource, getrlimit, setrlimit};

    /// The variable a re-run finds itself under, naming the test it is.
    const OWN_PROCESS: &str = "ZOND_TEST_IN_OWN_PROCESS";

    /// How many descriptors past those already open [`exhaust`] lowers the
    /// limit to, so filling the table costs a few dozen opens rather than as
    /// many as the shell allows.
    const HEADROOM: u64 = 32;

    /// Whether this is the process the test `name`, in the module `module`
    /// (its `module_path!()`), should run its body in.
    ///
    /// The first call re-runs this binary on that one test and fails if the
    /// re-run does, and the re-run is the call that answers `true`.
    pub(crate) fn in_a_process_of_its_own(module: &str, name: &str) -> bool {
        if std::env::var(OWN_PROCESS).is_ok_and(|running| running == name) {
            return true;
        }
        let path = format!(
            "{}::{name}",
            module.split_once("::").expect("a crate path").1
        );
        let run = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([path.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(OWN_PROCESS, name)
            .output()
            .expect("re-running the test in a process of its own");
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            run.status.success(),
            "{name} failed in its own process:\n{stdout}{}",
            String::from_utf8_lossy(&run.stderr),
        );
        // A filter that matched nothing exits cleanly too.
        assert!(
            stdout.contains("1 passed"),
            "{name} did not run in its own process:\n{stdout}"
        );
        false
    }

    /// Opens files until this process may open no more, so the next file or
    /// socket anything asks for is refused. The files are handed back, and
    /// dropping them is what frees the table.
    pub(crate) fn exhaust() -> Vec<std::fs::File> {
        let mut limit = getrlimit(Resource::Nofile);
        let open = std::fs::read_dir("/dev/fd").map_or(0, Iterator::count);
        limit.current = Some(open as u64 + HEADROOM);
        setrlimit(Resource::Nofile, limit).expect("lowering the descriptor limit");

        let refused = rustix::io::Errno::MFILE.raw_os_error();
        let mut held = Vec::new();
        loop {
            match std::fs::File::open("/dev/null") {
                Ok(file) => held.push(file),
                Err(e) if e.raw_os_error() == Some(refused) => return held,
                Err(e) => panic!("filling the descriptor table: {e}"),
            }
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
