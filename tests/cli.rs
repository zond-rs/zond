// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A command, end to end
//!
//! These run the real binary as a process and assert on what a shell sees: the
//! exit status, and what reached standard error.
//!
//! Every test points `XDG_CONFIG_HOME` at a directory of its own under
//! `CARGO_TARGET_TMPDIR`. Without that a run would provision into the real
//! `~/.config/zond` and then read it back, so a developer with their own
//! `presentation = "fancy"` would watch the suite fail over a setting.
//!
//! Only loopback and the documentation ranges are used. A test that reached for
//! whatever network it happens to run on passes on a laptop and fails in a
//! container.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A settings directory of this test's own, empty until the run creates it.
///
/// `CARGO_TARGET_TMPDIR` is given to integration tests for exactly this, so it
/// needs no dependency and is cleaned up with the rest of `target/`.
fn config_home(test: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("a writable target directory");
    directory
}

/// Runs the real binary against a settings directory the test already holds.
fn zond_in(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zond"))
        .args(args)
        .env("XDG_CONFIG_HOME", directory)
        .output()
        .expect("the binary under test should run")
}

/// Runs the real binary with a settings directory of this test's own.
fn zond(test: &str, args: &[&str]) -> Output {
    zond_in(&config_home(test), args)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A record with the round-trip times taken out: fields 3, 9, 10 and 11 of the
/// documented format. Two runs never agree on those and always should on the
/// rest.
fn untimed(fields: &[String]) -> Vec<String> {
    fields
        .iter()
        .enumerate()
        .filter(|(index, _)| !matches!(index, 2 | 8 | 9 | 10))
        .map(|(_, field)| field.clone())
        .collect()
}

/// The tab-separated fields of the one record a `--pipe` run produced.
fn record(output: &Output) -> Vec<String> {
    let text = stdout(output);
    let line = text.lines().next().unwrap_or_else(|| {
        panic!(
            "expected one record, got nothing. stderr:\n{}",
            stderr(output)
        )
    });
    line.split('\t').map(str::to_owned).collect()
}

/// The status as a shell would see it.
fn status(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the run should not be signalled")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Does not assert loopback was *found* — that depends on something listening,
/// which is true of a developer's machine and not of a build container. What is
/// checked is that the scan runs to completion.
#[test]
fn a_loopback_sweep_runs_to_completion() {
    let run = zond("loopback", &["-q", "d", "127.0.0.1"]);
    assert_eq!(status(&run), 0, "{}", stderr(&run));
}

#[test]
fn an_ipv6_target_runs_the_same_way() {
    let run = zond("ipv6", &["-q", "d", "::1"]);
    assert_eq!(status(&run), 0, "{}", stderr(&run));
}

/// Finding nothing is an answer. TEST-NET-1 belongs to no one.
#[test]
fn an_empty_result_is_still_a_success() {
    let run = zond("empty", &["-q", "d", "192.0.2.1-4"]);
    assert_eq!(status(&run), 0, "{}", stderr(&run));
}

/// The shell is told the request was wrong, not that the scan failed.
#[test]
fn a_malformed_target_is_a_usage_error() {
    let run = zond("malformed", &["d", "192.168.0.300"]);
    assert_eq!(status(&run), 2, "{}", stderr(&run));
}

/// Refused by the front end: how long a person will wait is not a question the
/// engine can answer.
#[test]
fn an_ipv4_range_too_large_to_sweep_is_a_usage_error() {
    let run = zond("huge-v4", &["d", "10.0.0.0/8"]);
    assert_eq!(status(&run), 2, "{}", stderr(&run));
    assert!(stderr(&run).contains("16777216"), "{}", stderr(&run));
}

/// The other side of that division. A `/64` is not refused here; where it
/// genuinely cannot be walked — unprivileged and off-link, as here — the engine
/// turns it away and records why, so the run exits `3` rather than `2`.
#[test]
fn an_unwalkable_ipv6_range_is_refused_by_the_engine_and_reported_partial() {
    let run = zond("unwalkable-v6", &["-q", "d", "2001:db8::/64"]);
    assert_eq!(status(&run), 3, "{}", stderr(&run));
}

/// Resolving a target name is DNS traffic before the scan has started, so a run
/// forbidden from sending any has to refuse the name rather than drop it.
#[test]
fn a_hostname_is_refused_when_dns_is_forbidden() {
    let run = zond("no-dns", &["-q", "d", "-n", "one.one.one.one"]);
    assert_eq!(status(&run), 2, "{}", stderr(&run));
    assert!(stderr(&run).contains("--no-dns"), "{}", stderr(&run));
}

/// The first run leaves the user with two files to edit, in one directory.
#[test]
fn a_first_run_provisions_both_settings_files() {
    let directory = config_home("provision");

    let run = zond_in(&directory, &["-q", "d", "127.0.0.1"]);
    assert_eq!(status(&run), 0, "{}", stderr(&run));

    assert!(directory.join("zond/cli.toml").is_file());
    assert!(directory.join("zond/engine.toml").is_file());
}

/// The files appearing must not change the run that follows them.
///
/// Compares what the two runs produced, not merely that both exited `0` — a
/// provisioning step that corrupted every setting would still exit `0` twice.
/// Every field but the round-trip times, which no two runs agree on.
#[test]
fn provisioned_files_change_nothing_about_the_next_run() {
    let directory = config_home("provision-inert");
    let args = ["-q", "--pipe", "s", "127.0.0.1", "-p", "1,2"];

    let first = zond_in(&directory, &args);
    let second = zond_in(&directory, &args);

    assert_eq!(status(&first), 0, "{}", stderr(&first));
    assert_eq!(status(&second), status(&first));
    assert_eq!(
        untimed(&record(&second)),
        untimed(&record(&first)),
        "the second run saw the files the first one created"
    );
}

/// Named but not built is refused, not quietly served as another mode.
#[test]
fn a_presentation_that_is_not_built_is_a_usage_error() {
    let run = zond("fancy", &["--presentation", "fancy", "d", "127.0.0.1"]);
    assert_eq!(status(&run), 2, "{}", stderr(&run));
    assert!(stderr(&run).contains("not built yet"), "{}", stderr(&run));
}

/// A settings file and a flag are two ways of asking for the same thing, so an
/// unusable value in either gets the same status.
#[test]
fn an_unusable_settings_file_is_a_usage_error() {
    let directory = config_home("bad-settings");
    std::fs::create_dir_all(directory.join("zond")).expect("a writable directory");
    std::fs::write(
        directory.join("zond/cli.toml"),
        "presentation = \"shiny\"\n",
    )
    .expect("a writable file");

    let run = zond_in(&directory, &["d", "127.0.0.1"]);

    assert_eq!(status(&run), 2, "{}", stderr(&run));
    assert!(stderr(&run).contains("shiny"), "{}", stderr(&run));
}

/// A key this program does not know is ignored and named, so that a file written
/// by a newer `zond` does not stop an older one from running.
#[test]
fn an_unknown_setting_is_a_warning_and_the_run_continues() {
    let directory = config_home("unknown-setting");
    std::fs::create_dir_all(directory.join("zond")).expect("a writable directory");
    std::fs::write(directory.join("zond/cli.toml"), "colour = true\n").expect("a writable file");

    let run = zond_in(&directory, &["d", "127.0.0.1"]);

    assert_eq!(status(&run), 0, "{}", stderr(&run));
    assert!(stderr(&run).contains("colour"), "{}", stderr(&run));
}

/// `default_ports` is read from the engine's file and reaches the scan.
///
/// Also pins that it is read *once*: a value the file sets and a value the flag
/// sets must not both end up in the same run.
#[test]
fn the_engines_default_ports_decide_a_scan_with_no_flag() {
    let directory = config_home("engine-default-ports");
    std::fs::create_dir_all(directory.join("zond")).expect("a writable directory");
    std::fs::write(
        directory.join("zond/engine.toml"),
        "[defaults]\ndefault_ports = \"9001,9002\"\n",
    )
    .expect("a writable file");

    let from_file = zond_in(&directory, &["s", "192.0.2.1"]);
    assert!(
        stderr(&from_file).contains("scanning 2 probes across 1 host"),
        "{}",
        stderr(&from_file)
    );

    let from_flag = zond_in(&directory, &["s", "192.0.2.1", "-p", "1-5"]);
    assert!(
        stderr(&from_flag).contains("scanning 5 probes across 1 host"),
        "the flag must win outright, not merge: {}",
        stderr(&from_flag)
    );
}

/// A value the program understands, carrying something it cannot act on, is
/// refused — on every subcommand, not only the one that would have used it.
#[test]
fn an_unusable_default_ports_is_refused_by_either_subcommand() {
    let directory = config_home("bad-default-ports");
    std::fs::create_dir_all(directory.join("zond")).expect("a writable directory");
    std::fs::write(
        directory.join("zond/engine.toml"),
        "[defaults]\ndefault_ports = \"not-ports\"\n",
    )
    .expect("a writable file");

    for subcommand in ["d", "s"] {
        let run = zond_in(&directory, &["-q", subcommand, "127.0.0.1"]);
        assert_eq!(status(&run), 2, "{subcommand}: {}", stderr(&run));
        assert!(
            stderr(&run).contains("default_ports"),
            "{subcommand}: {}",
            stderr(&run)
        );
    }
}

/// The engine's file is read, not merely created. Provisioning a file and then
/// ignoring it would be writing somebody a file that lies.
#[test]
fn the_engines_settings_file_is_honoured() {
    let directory = config_home("engine-settings");
    std::fs::create_dir_all(directory.join("zond")).expect("a writable directory");
    std::fs::write(
        directory.join("zond/engine.toml"),
        "[defaults]\nno_dns = true\n",
    )
    .expect("a writable file");

    // No `-n` on this command line. If the file is being read, the hostname is
    // refused anyway; if it is not, the name resolves and the scan runs.
    let run = zond_in(&directory, &["-q", "d", "one.one.one.one"]);

    assert_eq!(status(&run), 2, "{}", stderr(&run));
    assert!(stderr(&run).contains("engine.toml"), "{}", stderr(&run));
}

// ── zond scan ────────────────────────────────────────────────────────────────
//
// Loopback answers even on a closed port — the kernel sends a reset — so unlike
// a discovery sweep these do not depend on anything listening, and can assert on
// the records themselves.

#[test]
fn a_port_scan_runs_to_completion() {
    let run = zond("scan-loopback", &["-q", "s", "127.0.0.1", "-p", "1,2,3"]);
    assert_eq!(status(&run), 0, "{}", stderr(&run));
}

/// `-p` decides what a run costs, and the header says so before a probe is sent.
/// Both halves of the arithmetic are pinned: ports per host, and hosts.
#[test]
fn the_ports_flag_decides_how_many_probes_are_spent() {
    let one = zond("scan-probes-one", &["s", "192.0.2.1", "-p", "22,80,443"]);
    assert!(
        stderr(&one).contains("scanning 3 probes across 1 host"),
        "{}",
        stderr(&one)
    );

    let many = zond("scan-probes-many", &["s", "192.0.2.1-4", "-p", "1-10"]);
    assert!(
        stderr(&many).contains("scanning 40 probes across 4 hosts"),
        "{}",
        stderr(&many)
    );
}

/// Addresses times ports, refused before anything is sent.
#[test]
fn a_scan_beyond_the_probe_limit_is_a_usage_error() {
    let run = zond("scan-too-many", &["s", "10.0.0.0/16", "-p", "1-1024"]);

    assert_eq!(status(&run), 2, "{}", stderr(&run));
    assert!(stderr(&run).contains("67108864"), "{}", stderr(&run));
    assert!(stderr(&run).contains("4194304"), "{}", stderr(&run));
}

/// A technique needing raw sockets is refused, never quietly served as a connect
/// scan — which answers a different question and would say it answered this one.
///
/// The host is still reported: the liveness phase established it is there before
/// the port phase refused to probe it. What must be absent is any *port* record,
/// because none was tried.
#[test]
fn a_technique_that_needs_root_is_refused_rather_than_downgraded() {
    let run = zond(
        "scan-technique",
        &[
            "--pipe",
            "s",
            "127.0.0.1",
            "-p",
            "22",
            "--tcp-technique",
            "fin",
        ],
    );

    assert_eq!(status(&run), 3, "{}", stderr(&run));
    assert!(stderr(&run).contains("raw sockets"), "{}", stderr(&run));

    let fields = record(&run);
    assert_eq!(fields[1], "Up", "the liveness phase still ran");
    assert_eq!(fields[11], "-", "no port was probed");
    assert_eq!(fields[12], "-", "and none was counted closed");
}

/// The field list the README publishes as a stable interface. A field appended
/// without the documentation catching up is a promise quietly broken.
#[test]
fn the_pipe_format_carries_every_documented_field() {
    let run = zond(
        "scan-pipe",
        &["-q", "--pipe", "s", "127.0.0.1", "-p", "1,2,3"],
    );
    assert_eq!(status(&run), 0, "{}", stderr(&run));

    let fields = record(&run);
    assert_eq!(fields.len(), 13, "{fields:?}");
    assert_eq!(fields[0], "127.0.0.1");
    assert_eq!(fields[1], "Up", "a reset proves the host is there");

    let closed: usize = fields[12]
        .parse()
        .unwrap_or_else(|_| panic!("CLOSED should be a count, got {:?}", fields[12]));
    assert!(
        closed <= 3,
        "more ports came back than were probed: {closed}"
    );
}

/// The case this exists for: a dead address must not cost a probe per port.
///
/// Asserted as behaviour, not timing — no port record, and a note saying which
/// flag scans it anyway.
#[test]
fn an_address_nothing_answers_for_is_not_port_scanned() {
    let run = zond("scan-dead", &["--pipe", "s", "192.0.2.1", "-p", "1-64"]);

    assert_eq!(status(&run), 0, "{}", stderr(&run));
    assert_eq!(stdout(&run), "", "a dead address produced port records");
    assert!(
        stderr(&run).contains("--assume-up"),
        "the note has to name the flag that overrides it: {}",
        stderr(&run)
    );
}

/// `--assume-up` is what reaches a host that is up and answering no knock.
#[test]
fn assume_up_scans_an_address_that_answered_nothing() {
    let run = zond(
        "scan-assume-up",
        &["-q", "--pipe", "s", "192.0.2.1", "-p", "1,2", "--assume-up"],
    );

    assert_eq!(status(&run), 0, "{}", stderr(&run));

    let fields = record(&run);
    assert_eq!(fields[0], "192.0.2.1");
    assert!(
        fields[11].contains("1/tcp") && fields[11].contains("2/tcp"),
        "both ports should have been probed on trust: {:?}",
        fields[11]
    );
}

/// A live target is still scanned, and the liveness phase is what fills in the
/// round-trip time a port scan used not to have.
#[test]
fn a_live_host_is_scanned_and_timed() {
    let run = zond(
        "scan-live-timed",
        &["-q", "--pipe", "s", "127.0.0.1", "-p", "1,2"],
    );

    let fields = record(&run);
    assert_eq!(fields[1], "Up");
    assert_ne!(fields[2], "-", "the liveness phase measured a round trip");
    assert_eq!(
        fields[12], "2",
        "both ports were probed and came back closed"
    );
}

/// The engine records only the intent to redact; masking on the way out is this
/// program's job, so a flag that never reached the renderer would do nothing.
///
/// Asserted against the IPv6 loopback rather than the IPv4 one, because an IPv6
/// address is masked by its own bits. Whether a *hostname* appears at all
/// depends on reverse lookup, which is not this program's to guarantee — so that
/// half is checked only when there was something to mask.
#[test]
fn redaction_masks_what_identifies_a_host() {
    let args = ["-q", "--pipe", "s", "::1", "-p", "1,2"];

    let plain = zond("scan-plain", &args);
    assert_eq!(status(&plain), 0, "{}", stderr(&plain));
    let plain = record(&plain);

    let mut redacted_args = args.to_vec();
    redacted_args.push("--redact");
    let redacted = zond("scan-redacted", &redacted_args);
    assert_eq!(status(&redacted), 0, "{}", stderr(&redacted));
    let redacted = record(&redacted);

    assert_eq!(plain[0], "::1");
    assert_ne!(redacted[0], "::1", "the address survived --redact");

    if plain[5] != "-" {
        assert_ne!(redacted[5], plain[5], "the name survived --redact");
    }
}
