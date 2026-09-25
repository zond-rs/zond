// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What changed between two scans
//!
//! Functions rather than a [`Renderer`](super::Renderer), on the same reasoning
//! [`journal`](super::journal) gives: that trait describes a run, and a
//! comparison is not one. Nothing is probed, nothing arrives over time, and the
//! whole answer is in hand before a line is written.
//!
//! ## One file per presentation, as everywhere else
//!
//! [`pipe`] is one line per change, tab-separated, no heading. [`minimal`] is
//! one block per host, in the same tagged grammar a scan is drawn in, where the
//! bullet carries whether the host arrived, went or merely changed and so costs
//! no line of its own. [`fancy`] draws the blocks [`block`](super::block)
//! defines, which is what makes a comparison and a scan read as one program.
//!
//! The three sit beside each other here for the same reason `pipe`, `minimal`
//! and `fancy` sit beside each other one directory up, and share [`change`] for
//! the same reason they share [`field`]: what a comparison is
//! entitled to claim is one judgement, not three.
//!
//! What stays in this file is what belongs to no single presentation: the switch
//! between them, the line that says what is being compared, and the summary that
//! closes every mode.
//!
//! ## One host, one address, three modes
//!
//! [`change::identity`] decides which of a host's addresses a record is reported
//! under, and all three modes ask it. A comparison read on a terminal and the
//! same comparison read by a script have to be talking about the same machine.
//!
//! It is not always the address the engine keys the delta by. See that function.
//!
//! ## Whether the other scan looked is never dropped
//!
//! Every change carries it: `CONFIRMED` in `pipe`, a `note:` line in `minimal`.
//! A host missing from tonight's scan is gone if tonight's scan covered its
//! address and is merely unobserved if it did not, and a comparison that
//! flattened the two would raise an alarm every time somebody narrowed a scan.
//! The engine works to keep that distinction; losing it here would waste the
//! whole of it at the last step.
//!
//! ## The `pipe` contract
//!
//! Seven fields, in this order, on every line:
//!
//! | | Field | |
//! |---|---|---|
//! | 1 | `CHANGE` | what moved: `host_added`, `port_opened`, `service_version`, `certificate_rotated`, … |
//! | 2 | `CONFIRMED` | `yes` or `no`, saying whether the other scan is known to have looked here |
//! | 3 | `ADDRESS` | the host: an address both scans hold where they hold one, and the later scan's primary otherwise |
//! | 4 | `PORT` | `443/tcp`, or `-` for a host-level change |
//! | 5 | `FIELD` | which field moved, or `-` where the change *is* the field |
//! | 6 | `BEFORE` | what the earlier scan found, or `-` |
//! | 7 | `AFTER` | what the later scan found, or `-` |
//!
//! The tokens in field 1 are the engine's, shared with the JSON comparison
//! document, so a rule written against one reads the other. Two are this
//! module's own, because a record appearing or disappearing is a change the
//! document expresses as a `presence` rather than as a change: `host_added`,
//! `host_removed`, `port_added` and `port_removed`.
//!
//! A field with nothing in it is `-`, never empty, so the count never changes.
//! Nothing changed means no lines at all.

mod change;
mod fancy;
mod minimal;
mod pipe;

use std::io::{self, Write};

use zond_engine::diff::ScanDiff;
use zond_engine::export::ExportOptions;
use zond_engine::report::ScanKind;

use crate::render::field;
use crate::render::style::{Mark, Style};
use crate::settings::Presentation;

/// Writes a comparison.
///
/// `records` is standard output and `narration` standard error, the split every
/// other renderer here keeps: a comparison is a record, and what is being
/// compared is commentary.
pub(crate) fn write(
    diff: &ScanDiff,
    presentation: Presentation,
    options: &ExportOptions,
    records: &mut dyn Write,
    narration: &mut dyn Write,
    style: Style,
    narration_style: Style,
) -> io::Result<()> {
    match presentation {
        Presentation::Pipe => pipe::write(diff, options, records),
        Presentation::Fancy => {
            fancy::write(diff, options, records, narration, style, narration_style)
        }
        Presentation::Minimal => minimal::write(diff, options, records, narration, narration_style),
    }
}

/// A one-line account of what was compared, for standard error.
pub(crate) fn comparing(
    baseline: &str,
    current: &str,
    diff: &ScanDiff,
    out: &mut dyn Write,
    style: Style,
) -> io::Result<()> {
    // How long ago, not when. Two full timestamps put a hundred characters on
    // the line before the first finding, and what a reader checks here is that
    // they picked the right pair. `14m` answers that where
    // `2026-08-25T17:40:33.403417Z` makes them work it out.
    writeln!(
        out,
        "{}",
        style.line(
            Mark::Info,
            &format!(
                "comparing {baseline} ({}) with {current} ({})",
                field::age(diff.baseline().at()),
                field::age(diff.current().at()),
            )
        )
    )?;

    // Nothing enforces which of the two is earlier, since a comparison takes the
    // order it was given. Said here rather than refused, because comparing a
    // scan with an older one is a reasonable thing to ask for and reading the
    // result as though it ran forwards is not.
    if diff.baseline().at() > diff.current().at() {
        writeln!(
            out,
            "{}",
            style.line(
                Mark::Warning,
                "the first scan is the later of the two, so this reads backwards"
            )
        )?;
    }

    // A sweep and a port scan answer different questions, and comparing them
    // reports every port one of them looked at as a change. That is what the
    // records say and it is not what somebody expecting a nightly comparison
    // meant to ask, so the difference is named before the wall of lines rather
    // than left to be worked out from them.
    let (before, after) = (diff.baseline().kinds(), diff.current().kinds());
    if !before.is_empty() && !after.is_empty() {
        let scanned_ports = |kinds: &[ScanKind]| kinds.contains(&ScanKind::PortScan);

        // Naming which one looked, rather than listing both phase lists: a port
        // scan records a discovery phase of its own, so "discovery against
        // discovery and port scan" is accurate and tells nobody anything.
        match (scanned_ports(before), scanned_ports(after)) {
            (false, true) => writeln!(
                out,
                "{}",
                style.line(
                    Mark::Warning,
                    "only the later scan looked at ports, so most of what follows is \
                     the earlier one not having looked"
                )
            )?,
            (true, false) => writeln!(
                out,
                "{}",
                style.line(
                    Mark::Warning,
                    "only the earlier scan looked at ports, so most of what follows is \
                     the later one not having looked"
                )
            )?,
            _ => {}
        }
    }

    Ok(())
}

/// The count a comparison ends with, on standard error.
fn summary(diff: &ScanDiff, out: &mut dyn Write, style: Style) -> io::Result<()> {
    if diff.is_empty() {
        return writeln!(out, "{}", style.faint("no change"));
    }

    let summary = diff.summary();
    let mut parts = Vec::new();

    if summary.hosts_changed > 0 {
        parts.push(style.caution(&change::counted(summary.hosts_changed, "host changed")));
    }
    // Each count is drawn in the colour its mark carries up in the listing, so a
    // reader who has just run down a column of `+`, `-` and `~` meets the same
    // three colours in the same three meanings at the bottom.
    for (count, word, arrived) in [
        (summary.hosts_added, "host appeared", true),
        (summary.hosts_removed, "host gone", false),
    ] {
        if count.total > 0 {
            let phrase = change::unconfirmed(count.total, count.confirmed, word);
            parts.push(if arrived {
                style.good(&phrase)
            } else {
                style.alarm(&phrase)
            });
        }
    }
    for (count, word, opened) in [
        (summary.ports_opened, "port opened", true),
        (summary.ports_closed, "port closed", false),
    ] {
        if count.total > 0 {
            let phrase = change::unconfirmed(count.total, count.confirmed, word);
            parts.push(if opened {
                style.good(&phrase)
            } else {
                style.alarm(&phrase)
            });
        }
    }
    if summary.certificates_rotated > 0 {
        parts.push(style.plain(&change::counted(
            summary.certificates_rotated,
            "certificate rotated",
        )));
    }
    if summary.certificates_expiring > 0 {
        parts.push(style.caution(&change::counted(
            summary.certificates_expiring,
            "certificate expiring",
        )));
    }
    if summary.certificates_expired > 0 {
        parts.push(style.alarm(&change::counted(
            summary.certificates_expired,
            "certificate expired",
        )));
    }

    // Findings that appeared and resolved, counted from the deltas rather than
    // the summary: the engine's `DiffSummary` counts hosts, ports, services and
    // certificates, and a finding moving is none of those. A new one is alarming
    // and a resolved one is good, the two colours the marks up in the listing
    // already carry. Reassessed severities are left to the listing, where the
    // before and after can be read; a bare count of them would not say which way
    // any went.
    let (appeared, resolved) = finding_counts(diff);
    if appeared > 0 {
        parts.push(style.alarm(&change::counted(appeared, "finding appeared")));
    }
    if resolved > 0 {
        parts.push(style.good(&change::counted(resolved, "finding resolved")));
    }

    // A blank line first: the summary is about the listing rather than part of
    // it, and butted against the last block it reads as one more finding.
    writeln!(out)?;
    // Composed here rather than through `Style::line`, which escapes what it is
    // given, as it must, since most of what reaches it came off a network. The
    // parts here are this program's own and already painted.
    writeln!(out, "{} {}", style.mark(Mark::Info), parts.join(", "))
}

/// How many findings appeared and resolved across a comparison, host and port
/// alike.
///
/// Walked here because the engine's [`DiffSummary`](zond_engine::diff::DiffSummary)
/// does not carry it: a finding is not a host, a port, a service or a
/// certificate, and those are what it counts. Both enums are matched with a
/// wildcard, so a change a newer engine adds is passed over here rather than
/// stopping this from compiling — the listing still draws it.
fn finding_counts(diff: &ScanDiff) -> (usize, usize) {
    use zond_engine::diff::host::HostChange;
    use zond_engine::diff::port::PortChange;

    let mut appeared = 0usize;
    let mut resolved = 0usize;

    for host in diff.hosts() {
        for change in host.changes() {
            if let HostChange::Findings {
                appeared: a,
                resolved: r,
                ..
            } = change
            {
                appeared += a.len();
                resolved += r.len();
            }
        }
        for port in host.ports() {
            for change in port.changes() {
                if let PortChange::Findings {
                    appeared: a,
                    resolved: r,
                    ..
                } = change
                {
                    appeared += a.len();
                    resolved += r.len();
                }
            }
        }
    }

    (appeared, resolved)
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
    use zond_engine::diff::change::Change;
    use zond_engine::diff::host::HostChange;
    use zond_engine::export::diff::schema::ChangeDto;
    use zond_engine::report::ScanKind;
    use zond_engine::{Port, PortState, Protocol};

    use super::change::{readable, sentence};
    use super::pipe::{FIELDS, SEPARATOR};
    use super::*;
    use crate::render::test_support::{Capture, host, scoped};

    /// What both presentations wrote, as `(records, narration)`.
    fn drawn(diff: &ScanDiff, presentation: Presentation) -> (String, String) {
        let mut records = Capture::default();
        let mut narration = Capture::default();

        write(
            diff,
            presentation,
            &ExportOptions::new(),
            &mut records,
            &mut narration,
            Style::bare(),
            Style::bare(),
        )
        .expect("a capture never fails");

        (records.text(), narration.text())
    }

    // -----------------------------------------------------------------------
    // pipe
    // -----------------------------------------------------------------------

    /// The field count is the contract: a script told to read field 6 reads
    /// field 6 after the next release.
    #[test]
    fn every_pipe_record_has_the_documented_field_count() {
        let mut later = host(1);
        later.add_port(Port::new(443, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(
            &scoped(vec![host(1), host(9)], "192.0.2.0/24"),
            &scoped(vec![later, host(7)], "192.0.2.0/24"),
        );

        let (records, _) = drawn(&diff, Presentation::Pipe);
        assert!(!records.is_empty(), "the comparison found nothing to print");

        for line in records.lines() {
            assert_eq!(
                line.split(SEPARATOR).count(),
                FIELDS,
                "'{line}' is not {FIELDS} fields"
            );
            assert!(!line.contains("\t\t"), "an empty field in '{line}'");
        }
    }

    /// The field that decides whether a nightly alert is worth waking somebody
    /// for.
    #[test]
    fn pipe_says_whether_the_other_scan_looked() {
        // The earlier scan walked a quarter of the segment; the host that turns
        // up in the wider one was never in reach of it.
        let diff = ScanDiff::between(
            &scoped(vec![host(1)], "192.0.2.0/26"),
            &scoped(vec![host(1), host(200)], "192.0.2.0/24"),
        );

        let (records, _) = drawn(&diff, Presentation::Pipe);
        let line = records.lines().next().expect("one host appeared");

        let fields: Vec<&str> = line.split(SEPARATOR).collect();
        assert_eq!(fields[0], "host_added");
        assert_eq!(
            fields[1], "no",
            "the earlier scan never covered this address: {line}"
        );
        assert_eq!(fields[2], "192.0.2.200");
    }

    #[test]
    fn a_change_both_scans_covered_is_confirmed() {
        let mut later = host(1);
        later.add_port(Port::new(443, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(
            &scoped(vec![host(1), host(9)], "192.0.2.0/24"),
            &scoped(vec![later], "192.0.2.0/24"),
        );

        let (records, _) = drawn(&diff, Presentation::Pipe);
        let gone = records
            .lines()
            .find(|line| line.starts_with("host_removed"))
            .expect("a host went");

        assert_eq!(gone.split(SEPARATOR).nth(1), Some("yes"));
    }

    #[test]
    fn an_unchanged_comparison_writes_no_records_at_all() {
        let report = scoped(vec![host(1), host(2)], "192.0.2.0/24");
        let diff = ScanDiff::between(&report, &report);

        let (records, _) = drawn(&diff, Presentation::Pipe);
        assert_eq!(records, "", "a script counts lines");
    }

    // -----------------------------------------------------------------------
    // minimal
    // -----------------------------------------------------------------------

    /// The bullet is what a reader's eye runs down, so it carries the presence
    /// rather than costing a line.
    #[test]
    fn the_bullet_says_what_happened_to_the_host() {
        let mut later = host(1);
        later.add_port(Port::new(443, Protocol::Tcp, PortState::Open));

        let diff = ScanDiff::between(
            &scoped(vec![host(1), host(9)], "192.0.2.0/24"),
            &scoped(vec![later, host(7)], "192.0.2.0/24"),
        );

        let (records, _) = drawn(&diff, Presentation::Minimal);

        assert!(records.contains("* 192.0.2.1"), "changed: {records}");
        assert!(records.contains("+ 192.0.2.7"), "appeared: {records}");
        assert!(records.contains("- 192.0.2.9"), "gone: {records}");
    }

    /// The line that keeps a comparison honest for somebody reading it.
    #[test]
    fn a_host_nobody_had_looked_for_says_so_in_the_block() {
        let diff = ScanDiff::between(
            &scoped(vec![host(1)], "192.0.2.0/26"),
            &scoped(vec![host(1), host(200)], "192.0.2.0/24"),
        );

        let (records, _) = drawn(&diff, Presentation::Minimal);

        assert!(records.contains("+ 192.0.2.200"), "{records}");
        assert!(
            records.contains("note:") && records.contains("did not cover this address"),
            "an unconfirmed appearance must not read as a finding: {records}"
        );
    }

    /// And a confirmed one does not carry the caveat, or every block would.
    #[test]
    fn a_host_that_genuinely_appeared_carries_no_note() {
        let diff = ScanDiff::between(
            &scoped(vec![host(1)], "192.0.2.0/24"),
            &scoped(vec![host(1), host(7)], "192.0.2.0/24"),
        );

        let (records, _) = drawn(&diff, Presentation::Minimal);

        assert!(records.contains("+ 192.0.2.7"), "{records}");
        assert!(!records.contains("note:"), "{records}");
    }

    #[test]
    fn an_unchanged_comparison_says_so_on_the_commentary_stream() {
        let report = scoped(vec![host(1)], "192.0.2.0/24");
        let diff = ScanDiff::between(&report, &report);

        let (records, narration) = drawn(&diff, Presentation::Minimal);

        assert_eq!(records, "", "nothing to report is nothing printed");
        assert_eq!(narration.trim(), "no change");
    }

    /// The count a person reads first, and the one that is easiest to get
    /// grammatically wrong.
    #[test]
    fn the_summary_counts_read_as_english() {
        assert_eq!(change::counted(1, "host changed"), "1 host changed");
        assert_eq!(change::counted(2, "host changed"), "2 hosts changed");
        assert_eq!(
            change::counted(1, "certificate rotated"),
            "1 certificate rotated"
        );
        assert_eq!(change::counted(3, "port opened"), "3 ports opened");
    }

    /// A number that includes records nobody looked for says how many, because
    /// the two are not the same finding.
    #[test]
    fn a_count_holding_unconfirmed_records_says_how_many() {
        assert_eq!(
            change::unconfirmed(3, 3, "host appeared"),
            "3 hosts appeared"
        );
        assert_eq!(
            change::unconfirmed(3, 1, "host appeared"),
            "3 hosts appeared (2 unconfirmed)"
        );
    }

    /// Comparing a sweep with a port scan reports every port one of them looked
    /// at, and nothing in the wall of lines says why. The note is what stops
    /// that reading as a network that changed.
    #[test]
    fn a_comparison_of_two_different_kinds_of_scan_says_so() {
        use std::time::{Duration, SystemTime};
        use zond_engine::ZondConfig;
        use zond_engine::model::exclusion::Exclusions;
        use zond_engine::model::parse::ip::to_set;
        use zond_engine::report::{PhaseParts, ScanPhase, ScanReport, ScanSettings, TargetScope};
        use zond_engine::system::privilege::Privilege;

        let phase = |kind| {
            let mut targets = to_set(&["192.0.2.0/24"], None, None).expect("a range");
            ScanPhase::from_parts(PhaseParts {
                attachments: Vec::new(),
                kind,
                started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_000_000),
                elapsed: Duration::from_secs(1),
                privilege: Some(Privilege::Raw),
                targets: TargetScope::from_ip_set(&mut targets, &Exclusions::none()),
                settings: ScanSettings::from(&ZondConfig::default()),
                failures: Vec::new(),
                refusals: Vec::new(),
                unroutable: Vec::new(),
                timed_out: Vec::new(),
                icmp_rate_limited: Vec::new(),
                reached_by_connect: Vec::new(),
                undecided: Vec::new(),
                liveness_skipped: None,
                silent: Vec::new(),
                stopped: None,
                unreached: 0,
                unheard_probes: 0,
                probes: Vec::new(),
                origin: None,
            })
        };

        let swept = ScanReport::recorded("test", vec![phase(ScanKind::Discovery)], vec![host(1)]);
        let scanned = ScanReport::recorded(
            "test",
            vec![phase(ScanKind::Discovery), phase(ScanKind::PortScan)],
            vec![host(1)],
        );

        let mut out = Capture::default();
        comparing(
            "a",
            "b",
            &ScanDiff::between(&swept, &scanned),
            &mut out,
            Style::bare(),
        )
        .expect("a capture never fails");
        assert!(
            out.text().contains("only the later scan looked at ports"),
            "{}",
            out.text()
        );

        // The other way round names the other one.
        let mut out = Capture::default();
        comparing(
            "a",
            "b",
            &ScanDiff::between(&scanned, &swept),
            &mut out,
            Style::bare(),
        )
        .expect("a capture never fails");
        assert!(
            out.text().contains("only the earlier scan looked at ports"),
            "{}",
            out.text()
        );

        // And two of a kind say nothing.
        let mut out = Capture::default();
        comparing(
            "a",
            "b",
            &ScanDiff::between(&swept, &swept),
            &mut out,
            Style::bare(),
        )
        .expect("a capture never fails");
        assert!(!out.text().contains("note:"), "{}", out.text());
    }

    /// A set member that went says so once. "lost 2a02:… , now none" reads as
    /// a mistake, and a real segment produced exactly that line.
    #[test]
    fn a_set_member_that_went_is_not_also_said_to_be_none() {
        // Through the engine's own lowering rather than a hand-written DTO, so
        // the `kind` these assertions read is the one a real comparison emits.
        let options = ExportOptions::default();
        let dto = |change| {
            ChangeDto::of_host(&change, &options)
                .pop()
                .expect("the change lowers to one fact")
        };

        let lost = dto(HostChange::Addresses {
            gained: Vec::new(),
            lost: vec!["2a02:908:8c1:b880::b99a".parse().expect("an address")],
        });
        assert_eq!(
            sentence(&lost, field::Reader::default()),
            "lost   2a02:908:8c1:b880::b99a"
        );

        // A field that genuinely emptied still says so.
        let emptied = dto(HostChange::Vendor(Change {
            before: Some("Arris Group, Inc".to_string()),
            after: None,
        }));
        assert_eq!(
            sentence(&emptied, field::Reader::default()),
            "vendor Arris Group, Inc, now none"
        );
    }

    /// A finding the current scan never settled reads as unsettled, never as
    /// resolved: the walk it rests on was cut short, so its absence is not a
    /// fix, and a reader skimming for "resolved" must not count it as one.
    #[test]
    fn a_finding_the_current_scan_never_settled_reads_as_unsettled() {
        use zond_engine::diff::port::PortChange;
        use zond_engine::model::confidence::Confidence;
        use zond_engine::model::finding::{
            DetectionClass, DetectionId, Finding, Severity, Version,
        };

        let detection =
            DetectionId::new("zond:tls/tls10", Version::new(1, 0, 0), "").expect("a valid id");
        let finding = Finding::new(
            detection,
            "TLSv1.0 is still accepted",
            Severity::Medium,
            Confidence::Probable,
            DetectionClass::Passive,
        )
        .expect("a valid finding");

        let lowered = ChangeDto::of_port(
            &PortChange::Findings {
                appeared: Vec::new(),
                resolved: Vec::new(),
                unsettled: vec![finding],
                reassessed: Vec::new(),
            },
            &ExportOptions::default(),
        );
        assert_eq!(
            sentence(&lowered[0], field::Reader::default()),
            "unsettled medium: TLSv1.0 is still accepted"
        );
    }

    /// A finding that appeared or resolved reads as one-sided, and reaches a
    /// word for it rather than the raw `finding_appeared` the wire spells.
    #[test]
    fn a_finding_that_moved_reads_as_a_finding_and_not_a_wire_name() {
        use zond_engine::diff::host::{HostChange, Reassessment};
        use zond_engine::model::confidence::Confidence;
        use zond_engine::model::finding::{
            DetectionClass, DetectionId, Finding, Severity, Version,
        };

        let finding = |severity| {
            let detection = DetectionId::new("zond:host/telnet", Version::new(1, 0, 0), "")
                .expect("a valid id");
            Finding::new(
                detection,
                "Telnet is reachable",
                severity,
                Confidence::Probable,
                DetectionClass::Passive,
            )
            .expect("a valid finding")
        };

        let options = ExportOptions::default();
        let lower = |change| ChangeDto::of_host(&change, &options);

        let appeared = lower(HostChange::Findings {
            appeared: vec![finding(Severity::High)],
            resolved: Vec::new(),
            reassessed: Vec::new(),
        });
        assert_eq!(
            sentence(&appeared[0], field::Reader::default()),
            "found  high: Telnet is reachable"
        );

        let resolved = lower(HostChange::Findings {
            appeared: Vec::new(),
            resolved: vec![finding(Severity::High)],
            reassessed: Vec::new(),
        });
        assert_eq!(
            sentence(&resolved[0], field::Reader::default()),
            "resolved high: Telnet is reachable",
        );

        // A severity that moved is a transition and reads for itself, no lead-in
        // and no ", now none" tail.
        let reassessed = lower(HostChange::Findings {
            appeared: Vec::new(),
            resolved: Vec::new(),
            reassessed: vec![Reassessment {
                finding: finding(Severity::Critical),
                severity: Change {
                    before: Severity::High,
                    after: Severity::Critical,
                },
            }],
        });
        assert_eq!(
            sentence(&reassessed[0], field::Reader::default()),
            "high: Telnet is reachable -> critical: Telnet is reachable"
        );
    }

    /// Which scan failed to look depends on which one lacks the record.
    #[test]
    fn the_caveat_names_the_scan_that_did_not_look() {
        let mut later = host(1);
        later.add_port(Port::new(8080, Protocol::Tcp, PortState::Open));

        // A port only the later scan has: the earlier one is the one that
        // did not look.
        let appeared = ScanDiff::between(
            &scoped(vec![host(1)], "192.0.2.0/24"),
            &scoped(vec![later.clone()], "192.0.2.0/24"),
        );
        let (records, _) = drawn(&appeared, Presentation::Minimal);
        assert!(records.contains("(not looked for before)"), "{records}");

        // And the other way round.
        let went = ScanDiff::between(
            &scoped(vec![later], "192.0.2.0/24"),
            &scoped(vec![host(1)], "192.0.2.0/24"),
        );
        let (records, _) = drawn(&went, Presentation::Minimal);
        assert!(records.contains("(not looked for since)"), "{records}");
    }

    // -----------------------------------------------------------------------
    // Which address a host is reported under
    // -----------------------------------------------------------------------

    /// A machine that answered at a link-local address in both scans, and whose
    /// primary address moved to `192.0.2.55` between them.
    ///
    /// What a DHCP segment produces nightly, and the case the engine's own key
    /// reads worst on: the later scan's primary is an address the earlier scan
    /// never saw.
    fn relet() -> (zond_engine::ScanReport, zond_engine::ScanReport) {
        let link_local: std::net::IpAddr = "fe80::abcd".parse().expect("an address");
        let zone = zond_engine::model::ip::scoped::Zone::new(4, "en0");

        let mut before = zond_engine::Host::new(link_local);
        before.set_status(zond_engine::HostStatus::Up);
        before.set_zone(zone.clone());

        let mut after = host(55);
        after.add_ip(link_local);
        after.add_ip("2001:db8::beef".parse().expect("an address"));
        after.set_zone(zone);
        after.set_hostname(Some("laptop.example".to_owned()));

        (
            scoped(vec![before], "192.0.2.0/24"),
            scoped(vec![after], "192.0.2.0/24"),
        )
    }

    /// A host both scans hold is led by an address both scans hold.
    ///
    /// The engine keys a delta by the later scan's primary, which here is an
    /// address the block itself reports as *gained*. Leading with it made a host
    /// that merely changed read as a host that arrived, and put the same string
    /// on the screen twice with a `~` in front of it.
    #[test]
    fn a_changed_host_is_led_by_an_address_both_scans_hold() {
        let (before, after) = relet();
        let diff = ScanDiff::between(&before, &after);

        let (records, _) = drawn(&diff, Presentation::Fancy);

        assert!(
            records.contains("~ fe80::abcd%en0  laptop.example"),
            "the block is not led by the shared address: {records}"
        );
        assert!(
            records.contains("gained 192.0.2.55"),
            "the address it moved to is still reported: {records}"
        );
        assert!(
            !records.contains("~ 192.0.2.55"),
            "the block is led by an address it reports as gained: {records}"
        );
    }

    /// The ordinary host does not move. Only a primary that changed reaches for
    /// the earlier scan's address, so a segment where nothing was re-leased
    /// reads exactly as it did.
    #[test]
    fn a_host_whose_primary_stayed_put_keeps_the_key() {
        let mut later = host(1);
        later.set_hostname(Some("router.example".to_owned()));

        let diff = ScanDiff::between(
            &scoped(vec![host(1)], "192.0.2.0/24"),
            &scoped(vec![later], "192.0.2.0/24"),
        );

        let (records, _) = drawn(&diff, Presentation::Fancy);
        assert!(records.contains("~ 192.0.2.1  router.example"), "{records}");
    }

    /// A host only one scan holds has nothing to share, so it keeps the key.
    #[test]
    fn a_host_only_one_scan_holds_keeps_the_key() {
        let diff = ScanDiff::between(
            &scoped(vec![host(1)], "192.0.2.0/24"),
            &scoped(vec![host(2)], "192.0.2.0/24"),
        );

        let (records, _) = drawn(&diff, Presentation::Fancy);
        assert!(records.contains("- 192.0.2.1"), "{records}");
        assert!(records.contains("+ 192.0.2.2"), "{records}");
    }

    /// All three modes name the same host the same way.
    ///
    /// A comparison read on a terminal and the same comparison read by a script
    /// have to be talking about the same machine, and the three used to reach
    /// for the address separately.
    #[test]
    fn every_mode_reports_a_host_under_one_address() {
        let (before, after) = relet();
        let diff = ScanDiff::between(&before, &after);

        for mode in [
            Presentation::Fancy,
            Presentation::Minimal,
            Presentation::Pipe,
        ] {
            let (records, _) = drawn(&diff, mode);
            assert!(
                records.contains("fe80::abcd%en0"),
                "{mode} named the host something else: {records}"
            );
        }
    }

    /// A link-local address without its zone names no interface, so a listing
    /// of them is a listing of addresses a reader cannot act on.
    #[test]
    fn a_link_local_carries_its_zone() {
        let (before, after) = relet();
        let (records, _) = drawn(&ScanDiff::between(&before, &after), Presentation::Fancy);

        assert!(records.contains("fe80::abcd%en0"), "{records}");
        assert!(
            !records.contains("fe80::abcd  "),
            "the zone was dropped: {records}"
        );
    }

    /// **Every address a comparison prints is masked under redaction.**
    ///
    /// The header address and the gained and lost lists both used to go out
    /// raw, so a redacted comparison printed in full the IPv6 host part that
    /// the same run masked everywhere else. A link-local's host part is the
    /// hardware address in another notation, which is the thing redaction
    /// exists to hide.
    #[test]
    fn redaction_reaches_every_address_a_comparison_prints() {
        let (before, after) = relet();
        let diff = ScanDiff::between(&before, &after);

        let mut records = Capture::default();
        let mut narration = Capture::default();
        write(
            &diff,
            Presentation::Fancy,
            &ExportOptions::new().with_redaction(zond_engine::export::Redaction::Standard),
            &mut records,
            &mut narration,
            Style::bare(),
            Style::bare(),
        )
        .expect("a capture never fails");

        let text = records.text();
        assert!(
            !text.contains("abcd"),
            "the header's host part survived redaction: {text}"
        );
        assert!(
            !text.contains("beef"),
            "a gained address survived redaction: {text}"
        );
        assert!(
            text.contains("%en0"),
            "the zone names an interface here, not there, and survives: {text}"
        );
        assert!(
            !text.contains("laptop.example"),
            "the name survived redaction: {text}"
        );
    }

    /// A fingerprint is an identity, not a value to read: a block shows enough
    /// of it to tell two apart and no more.
    #[test]
    fn a_block_shortens_a_fingerprint_and_a_pipe_record_does_not() {
        let long = "a".repeat(64);
        let shortened = readable("certificate_rotated", Some(&long), field::Reader::default())
            .expect("a value");

        assert!(shortened.ends_with('…'));
        assert!(shortened.chars().count() < 20, "{shortened}");
        assert_eq!(
            readable("service_version", Some(&long), field::Reader::default()).as_deref(),
            Some(long.as_str()),
            "only a fingerprint is shortened"
        );
    }

    #[test]
    fn a_block_shows_an_expiry_as_a_date() {
        assert_eq!(
            readable(
                "certificate_expiring",
                Some("2026-09-20T00:00:00.000000Z"),
                field::Reader::default()
            )
            .as_deref(),
            Some("2026-09-20")
        );
    }

    /// The mark is shaped as well as coloured, so a comparison captured to a
    /// file still says which of the three things happened. It is deliberately
    /// not a scan's lamp: this block is about a difference between two runs, not
    /// about a host's reachability.
    #[test]
    fn the_three_presences_take_three_marks() {
        let before = scoped(vec![host(1)], "192.0.2.0/24");
        let after = scoped(vec![host(2)], "192.0.2.0/24");
        let diff = ScanDiff::between(&before, &after);

        let (records, _) = drawn(&diff, Presentation::Fancy);

        // In front of the address, in a column of their own, and one space
        // after every one of them however it is painted.
        assert!(records.contains("  1  - 192.0.2.1"), "{records}");
        assert!(records.contains("  2  + 192.0.2.2"), "{records}");
    }

    /// A host that was more than merely there still says so.
    ///
    /// `beyond_presence` drops the line only where it would repeat the tag. A
    /// host that was filtered, or that arrived with something open, is not what
    /// `gone` or `arrived` on its own implies.
    #[test]
    fn a_host_that_was_more_than_present_still_says_what() {
        let mut serving = host(1);
        serving.add_port(zond_engine::Port::new(
            22,
            zond_engine::Protocol::Tcp,
            zond_engine::PortState::Open,
        ));

        let before = scoped(Vec::new(), "192.0.2.0/24");
        let after = scoped(vec![serving], "192.0.2.0/24");
        let (records, _) = drawn(&ScanDiff::between(&before, &after), Presentation::Fancy);

        assert!(records.contains("  1  + 192.0.2.1"), "{records}");
        assert!(
            records.contains("now    up, 1 port open"),
            "what it arrived with was dropped: {records}"
        );
    }

    /// Every block is opened by a blank line, the first one included.
    ///
    /// `comparing` has just written what is being compared on the other stream,
    /// and one host butted against the next is two findings a reader has to tell
    /// apart for themselves.
    #[test]
    fn every_block_is_opened_by_a_blank_line() {
        let before = scoped(vec![host(1)], "192.0.2.0/24");
        let after = scoped(vec![host(2)], "192.0.2.0/24");
        let (records, _) = drawn(&ScanDiff::between(&before, &after), Presentation::Fancy);

        let lines: Vec<&str> = records.split('\n').collect();
        let openings: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains("192.0.2."))
            .map(|(at, _)| at)
            .collect();

        assert_eq!(openings.len(), 2, "{records:?}");

        for at in openings {
            assert_eq!(
                at.checked_sub(1)
                    .and_then(|above| lines.get(above))
                    .copied(),
                Some(""),
                "the block on line {at} is not opened by a blank line: {records:?}"
            );
        }
    }

    /// And the summary is set apart from the last of them, because it is about
    /// the listing rather than one more finding in it.
    #[test]
    fn the_summary_is_set_apart_from_the_listing() {
        let before = scoped(vec![host(1)], "192.0.2.0/24");
        let after = scoped(vec![host(2)], "192.0.2.0/24");
        let (_, narration) = drawn(&ScanDiff::between(&before, &after), Presentation::Fancy);

        assert!(
            narration.contains("\n\n") || narration.starts_with('\n'),
            "the summary is butted against the listing: {narration:?}"
        );
    }

    /// A comparison draws in the same shape a scan does, so the two read as one
    /// program.
    #[test]
    fn a_change_reads_as_a_block() {
        let before = scoped(vec![host(1)], "192.0.2.0/24");
        let after = scoped(Vec::new(), "192.0.2.0/24");
        let (records, _) = drawn(&ScanDiff::between(&before, &after), Presentation::Fancy);

        assert!(records.contains("  1  - 192.0.2.1\n"), "{records}");

        // And nothing under it. A host that was simply up and is now gone has
        // had everything about it said by the tag; `was up` beneath is the same
        // fact in a second place. See `change::beyond_presence`.
        assert!(
            !records.contains("was"),
            "the tag was said twice: {records}"
        );
    }

    /// `fancy` is the only mode that promises colour, so the others must not
    /// pick it up merely because the terminal would accept it.
    #[test]
    fn only_fancy_is_painted() {
        let before = scoped(vec![host(1)], "192.0.2.0/24");
        let after = scoped(Vec::new(), "192.0.2.0/24");
        let diff = ScanDiff::between(&before, &after);

        for mode in [Presentation::Pipe, Presentation::Minimal] {
            assert_eq!(
                Style::records(
                    mode,
                    crate::render::style::Palette::when(crate::render::style::ColourChoice::Always)
                ),
                Style::bare(),
                "{mode} must not be painted"
            );
        }

        // And the one that does promise it gets it, whatever the stream is.
        assert!(
            Style::records(
                Presentation::Fancy,
                crate::render::style::Palette::when(crate::render::style::ColourChoice::Always)
            )
            .has_colour()
        );

        // Belt and braces: nothing this mode writes carries an escape when the
        // style is inert.
        let (records, _) = drawn(&diff, Presentation::Minimal);
        assert!(!records.contains('\x1b'), "{records:?}");
    }
}

#[cfg(test)]
mod hostile {
    use zond_engine::model::port::{Port, PortState, Protocol, Service};

    use super::pipe::{FIELDS, SEPARATOR};
    use super::*;
    use crate::render::test_support::{Capture, host, scoped};

    /// A scanned host chooses its own banner, and a tab in one would add a field
    /// to a record a script is reading by number.
    #[test]
    fn a_value_a_host_chose_cannot_add_a_field_or_a_line() {
        let listening = |version: &str| {
            let mut listening = host(1);
            listening.add_port(
                Port::new(80, Protocol::Tcp, PortState::Open)
                    .with_service(Service::new("http", 90).with_version(version)),
            );
            scoped(vec![listening], "192.0.2.0/24")
        };

        let diff = ScanDiff::between(
            &listening("1.0"),
            &listening("2.0\tinjected\nport_opened\tyes\t10.0.0.1"),
        );

        let mut records = Capture::default();
        let mut narration = Capture::default();
        write(
            &diff,
            Presentation::Pipe,
            &ExportOptions::new(),
            &mut records,
            &mut narration,
            Style::bare(),
            Style::bare(),
        )
        .expect("a capture never fails");

        let text = records.text();
        assert_eq!(
            text.lines().count(),
            1,
            "a newline in a banner forged a record: {text:?}"
        );
        for line in text.lines() {
            assert_eq!(
                line.split(SEPARATOR).count(),
                FIELDS,
                "a tab in a banner added a field: {line:?}"
            );
        }
        assert!(text.contains("\\t") && text.contains("\\n"), "{text:?}");
    }

    /// And a block is line-oriented too.
    #[test]
    fn a_value_a_host_chose_cannot_forge_a_tagged_line() {
        let mut named = host(1);
        named.set_hostname(Some("evil\n  port: 443/tcp opened".to_string()));

        let diff = ScanDiff::between(
            &scoped(vec![host(1)], "192.0.2.0/24"),
            &scoped(vec![named], "192.0.2.0/24"),
        );

        let mut records = Capture::default();
        let mut narration = Capture::default();
        write(
            &diff,
            Presentation::Minimal,
            &ExportOptions::new(),
            &mut records,
            &mut narration,
            Style::bare(),
            Style::bare(),
        )
        .expect("a capture never fails");

        let text = records.text();
        assert!(
            !text.contains("\n  port:"),
            "a hostname forged a port line: {text}"
        );
    }
}
