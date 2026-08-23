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
///
/// The state directory goes to the same place, so a test that journals a scan
/// writes into its own corner of `target/` rather than the runner's home.
fn zond_in(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zond"))
        .args(args)
        .env("XDG_CONFIG_HOME", directory)
        .env("XDG_STATE_HOME", directory)
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

/// The flag reaches the scan, and the run says what it will not touch.
///
/// TEST-NET-1 answers nothing either way, so what is asserted is the accounting
/// rather than a finding: four addresses named, two of them withheld, and the
/// header reporting the two that are left. That is the whole path — clap to the
/// target grammar to the engine's policy to the line a person reads — and no
/// unit test covers all of it.
#[test]
fn an_excluded_range_is_named_and_left_out_of_the_count() {
    let run = zond("exclude", &["d", "192.0.2.1-4", "--exclude", "192.0.2.3-4"]);
    assert_eq!(status(&run), 0, "{}", stderr(&run));

    let said = stderr(&run);
    assert!(said.contains("discovering 2 addresses"), "{said}");
    assert!(said.contains("excluding 192.0.2.3-192.0.2.4"), "{said}");
    assert!(said.contains("2 addresses withheld"), "{said}");
}

/// A run with nothing left to scan is a usage error, not a sweep of nothing.
///
/// The likely cause is a typo in the exclusion, and a run that reported no hosts
/// would look exactly like a network with nothing on it.
#[test]
fn excluding_every_target_is_a_usage_error() {
    let run = zond(
        "exclude-all",
        &["d", "192.0.2.0/24", "--exclude", "192.0.2.0/24"],
    );
    assert_eq!(status(&run), 2, "{}", stderr(&run));
    assert!(stderr(&run).contains("--exclude"), "{}", stderr(&run));
}

/// A settings file's exclusions and the flag's are both in force.
///
/// The one key in that document that accumulates rather than being overridden:
/// a range an administrator wrote into the file must not be droppable by
/// somebody passing an exclusion of their own on the command line. Asserted
/// through the front door because the layering runs across three modules and
/// two crates.
#[test]
fn a_files_exclusions_survive_a_flag_that_adds_its_own() {
    let directory = config_home("exclude-layers");
    std::fs::create_dir_all(directory.join("zond")).expect("a writable directory");
    std::fs::write(
        directory.join("zond/engine.toml"),
        "[defaults]\nexclude = [\"192.0.2.1\"]\n",
    )
    .expect("a writable file");

    let run = zond_in(&directory, &["d", "192.0.2.1-4", "--exclude", "192.0.2.4"]);
    assert_eq!(status(&run), 0, "{}", stderr(&run));

    let said = stderr(&run);
    assert!(said.contains("discovering 2 addresses"), "{said}");
    assert!(
        said.contains("192.0.2.1"),
        "the file's range is in force: {said}"
    );
    assert!(
        said.contains("192.0.2.4"),
        "the flag's range is too: {said}"
    );
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

/// The spelling everybody arrives with, in all three of its forms.
///
/// `-p-` has to survive the argument parser as much as the port grammar: clap
/// reads a leading dash as the start of another flag unless told otherwise, and
/// a scanner that refused the one port specification its users already know
/// would be wrong in the most visible possible place.
#[test]
fn a_range_may_leave_off_either_end_on_the_command_line() {
    for (spec, probes) in [
        ("-p-", "65535 probes"),
        ("-p-1024", "1024 probes"),
        ("-p65000-", "536 probes"),
    ] {
        let run = zond(
            "scan-open-range",
            &["s", "127.0.0.1", spec, "--no-service-detection"],
        );
        assert!(
            stderr(&run).contains(probes),
            "`{spec}` should scan {probes}: {}",
            stderr(&run)
        );
    }
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

/// A scan leaves a record without being asked, and `zond journal` finds it.
///
/// This is the whole point of recording by default: the moment somebody wants
/// to continue a scan is *after* it was cut short, and a flag they had to pass
/// beforehand is one they did not.
#[test]
fn a_scan_is_recorded_without_being_asked() {
    let home = config_home("journal-list");

    let scan = zond_in(&home, &["-q", "s", "::1", "-p", "1,2"]);
    assert_eq!(status(&scan), 0, "{}", stderr(&scan));

    let listed = zond_in(&home, &["--pipe", "journal"]);
    assert_eq!(status(&listed), 0, "{}", stderr(&listed));

    let text = stdout(&listed);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "one scan, one record: {lines:?}");

    let fields: Vec<&str> = lines[0].split('\t').collect();
    assert_eq!(fields.len(), 5, "the documented field count: {fields:?}");
    assert_eq!(fields[1], "complete", "the scan ran to the end");
    assert_eq!(fields[3], "2/2", "both targets settled");
}

/// `--no-journal` records nothing, for a run somebody would rather not leave a
/// trace of.
#[test]
fn a_scan_can_decline_to_be_recorded() {
    let home = config_home("journal-declined");

    let scan = zond_in(&home, &["-q", "s", "::1", "-p", "1", "--no-journal"]);
    assert_eq!(status(&scan), 0, "{}", stderr(&scan));

    let listed = zond_in(&home, &["--pipe", "journal"]);
    assert_eq!(status(&listed), 0, "{}", stderr(&listed));
    assert!(stdout(&listed).is_empty(), "{}", stdout(&listed));
}

/// And `journal = false` declines for every run.
#[test]
fn a_settings_file_can_decline_for_good() {
    let home = config_home("journal-declined-standing");
    std::fs::create_dir_all(home.join("zond")).expect("a settings directory");
    std::fs::write(home.join("zond").join("cli.toml"), "journal = false\n")
        .expect("a settings file");

    let scan = zond_in(&home, &["-q", "s", "::1", "-p", "1"]);
    assert_eq!(status(&scan), 0, "{}", stderr(&scan));

    let listed = zond_in(&home, &["--pipe", "journal"]);
    assert!(stdout(&listed).is_empty(), "{}", stdout(&listed));
}

/// Resuming a scan whose plan has changed is refused, and says what moved.
#[test]
fn resuming_a_different_plan_is_refused() {
    let home = config_home("journal-mismatch");

    let scan = zond_in(&home, &["-q", "s", "::1", "-p", "1,2"]);
    assert_eq!(status(&scan), 0, "{}", stderr(&scan));

    let listed = zond_in(&home, &["--pipe", "journal"]);
    let id = stdout(&listed)
        .lines()
        .next()
        .and_then(|line| line.split('\t').next().map(str::to_owned))
        .expect("a listed scan");

    // One more port than the record was written against.
    let resumed = zond_in(&home, &["-q", "s", "::1", "-p", "1,2,3", "--resume", &id]);

    assert_eq!(status(&resumed), 2, "a usage error, not a failed scan");
    assert!(
        stderr(&resumed).contains("different plan"),
        "{}",
        stderr(&resumed)
    );
    assert!(
        stdout(&resumed).is_empty(),
        "nothing was scanned, so nothing should be reported"
    );
}

/// An id nothing on record matches is a usage error that says how to look.
#[test]
fn an_unknown_id_says_where_to_look() {
    let home = config_home("journal-unknown");

    let shown = zond_in(&home, &["journal", "show", "01NOTAREALID"]);

    assert_eq!(status(&shown), 2);
    assert!(
        stderr(&shown).contains("01NOTAREALID"),
        "{}",
        stderr(&shown)
    );
}

/// A dry run says what would go and leaves it there.
#[test]
fn pruning_can_be_rehearsed() {
    let home = config_home("journal-prune");

    let scan = zond_in(&home, &["-q", "s", "::1", "-p", "1"]);
    assert_eq!(status(&scan), 0, "{}", stderr(&scan));

    let rehearsed = zond_in(&home, &["journal", "prune", "--completed", "--dry-run"]);
    assert_eq!(status(&rehearsed), 0, "{}", stderr(&rehearsed));
    assert!(
        stdout(&rehearsed).contains("would delete"),
        "{}",
        stdout(&rehearsed)
    );

    let still_there = zond_in(&home, &["--pipe", "journal"]);
    assert_eq!(
        stdout(&still_there).lines().count(),
        1,
        "a rehearsal deleted something"
    );

    let swept = zond_in(&home, &["journal", "prune", "--completed"]);
    assert_eq!(status(&swept), 0, "{}", stderr(&swept));

    let gone = zond_in(&home, &["--pipe", "journal"]);
    assert!(stdout(&gone).is_empty(), "{}", stdout(&gone));
}

/// A scan is continued by its id alone.
///
/// The plan is on record, so there is nothing to type again — and nothing to
/// mistype. What ran the first time is what continues, rather than whatever
/// somebody reconstructs from memory.
#[test]
fn a_scan_is_continued_by_its_id_alone() {
    let home = config_home("journal-resume-bare");

    let scan = zond_in(&home, &["-q", "s", "::1", "-p", "1,2"]);
    assert_eq!(status(&scan), 0, "{}", stderr(&scan));

    let listed = zond_in(&home, &["--pipe", "journal"]);
    let id = stdout(&listed)
        .lines()
        .next()
        .and_then(|line| line.split('\t').next().map(str::to_owned))
        .expect("a listed scan");

    // No target, no ports: the id is the whole of it. Not quiet, because what
    // is being continued is the thing worth saying.
    let resumed = zond_in(&home, &["s", "--resume", &id]);

    assert_eq!(status(&resumed), 0, "{}", stderr(&resumed));
    assert!(
        stderr(&resumed).contains(&id),
        "the run should say what it is continuing: {}",
        stderr(&resumed)
    );
}

/// Targets named alongside `--resume` are checked, and refused when they
/// describe something else.
#[test]
fn targets_given_with_resume_must_agree_with_the_record() {
    let home = config_home("journal-resume-checked");

    let scan = zond_in(&home, &["-q", "s", "::1", "-p", "1,2"]);
    assert_eq!(status(&scan), 0, "{}", stderr(&scan));

    let listed = zond_in(&home, &["--pipe", "journal"]);
    let id = stdout(&listed)
        .lines()
        .next()
        .and_then(|line| line.split('\t').next().map(str::to_owned))
        .expect("a listed scan");

    let agreeing = zond_in(&home, &["-q", "s", "::1", "-p", "1,2", "--resume", &id]);
    assert_eq!(status(&agreeing), 0, "{}", stderr(&agreeing));

    let disagreeing = zond_in(&home, &["-q", "s", "::1", "-p", "1,2,3", "--resume", &id]);
    assert_eq!(status(&disagreeing), 2, "{}", stderr(&disagreeing));
    assert!(
        stderr(&disagreeing).contains("drop the targets"),
        "the message should say how to proceed: {}",
        stderr(&disagreeing)
    );
}

/// One scan can be deleted by name, shortened to any prefix that names only it.
#[test]
fn a_named_scan_can_be_deleted() {
    let home = config_home("journal-rm");

    for port in ["1", "2"] {
        let scan = zond_in(&home, &["-q", "s", "::1", "-p", port]);
        assert_eq!(status(&scan), 0, "{}", stderr(&scan));
    }

    let listed = zond_in(&home, &["--pipe", "journal"]);
    let ids: Vec<String> = stdout(&listed)
        .lines()
        .filter_map(|line| line.split('\t').next().map(str::to_owned))
        .collect();
    assert_eq!(ids.len(), 2);

    // Shortened to what tells the two apart, which is what a person types.
    let prefix: String = ids[0].chars().take(12).collect();
    let removed = zond_in(&home, &["journal", "rm", &prefix]);
    assert_eq!(status(&removed), 0, "{}", stderr(&removed));

    let left = zond_in(&home, &["--pipe", "journal"]);
    let text = stdout(&left);
    let left: Vec<&str> = text.lines().collect();
    assert_eq!(left.len(), 1, "one should have gone");
    assert!(left[0].starts_with(&ids[1]), "the wrong one went");
}

/// A prefix naming more than one scan deletes nothing.
///
/// The wrong scan deleted is not something a person gets back, so an ambiguous
/// name is refused rather than resolved to whichever matched first.
#[test]
fn an_ambiguous_name_deletes_nothing() {
    let home = config_home("journal-ambiguous");

    for port in ["1", "2"] {
        let scan = zond_in(&home, &["-q", "s", "::1", "-p", port]);
        assert_eq!(status(&scan), 0, "{}", stderr(&scan));
    }

    // The prefix the two actually share, rather than one assumed: ids begin with
    // the time they were minted, so what that is changes with the calendar.
    let listed = zond_in(&home, &["--pipe", "journal"]);
    let text = stdout(&listed);
    let ids: Vec<&str> = text
        .lines()
        .filter_map(|line| line.split('\t').next())
        .collect();
    let shared: String = ids[0]
        .chars()
        .zip(ids[1].chars())
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect();
    assert!(
        !shared.is_empty(),
        "two ids minted together should share a prefix"
    );

    let refused = zond_in(&home, &["journal", "rm", &shared]);

    assert_eq!(status(&refused), 2, "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("more than one"),
        "{}",
        stderr(&refused)
    );

    let left = zond_in(&home, &["--pipe", "journal"]);
    assert_eq!(stdout(&left).lines().count(), 2, "something was deleted");
}

/// Naming several, one of them wrong, deletes none of them.
///
/// Half a command is worse than none of it when the half that ran cannot be
/// undone.
#[test]
fn a_bad_name_among_good_ones_deletes_nothing() {
    let home = config_home("journal-rm-partial");

    let scan = zond_in(&home, &["-q", "s", "::1", "-p", "1"]);
    assert_eq!(status(&scan), 0, "{}", stderr(&scan));

    let listed = zond_in(&home, &["--pipe", "journal"]);
    let id = stdout(&listed)
        .lines()
        .next()
        .and_then(|line| line.split('\t').next().map(str::to_owned))
        .expect("a listed scan");

    let refused = zond_in(&home, &["journal", "rm", &id, "01NOTAREALID"]);
    assert_eq!(status(&refused), 2, "{}", stderr(&refused));

    let left = zond_in(&home, &["--pipe", "journal"]);
    assert_eq!(
        stdout(&left).lines().count(),
        1,
        "the good name was acted on despite the bad one"
    );
}
