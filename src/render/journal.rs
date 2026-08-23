// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the scans on this machine look like
//!
//! Functions rather than a [`Renderer`](super::Renderer), because that trait
//! describes a *run*: something starts, hosts arrive, it finishes. A listing is
//! none of those. It is a page of what is already there, so it is rendered in
//! one call and needs no state.
//!
//! The two presentations keep their usual bargain. `pipe` is tab-separated with
//! a fixed field count, no padding and **no heading**, because a heading is one
//! more line for a program to skip; `minimal` is for reading, and gets one.
//!
//! ## The `pipe` contract
//!
//! Five fields, in this order, on every line:
//!
//! | | Field | |
//! |---|---|---|
//! | 1 | `ID` | what `show`, `report` and `--resume` take |
//! | 2 | `STATE` | `running`, `resumable`, `complete`, `locked`, or `unreadable` |
//! | 3 | `STARTED` | when the first sitting began, RFC 3339 |
//! | 4 | `PROGRESS` | `settled/total`, in whatever the phase counts |
//! | 5 | `SCOPE` | what was scanned |
//!
//! A field with nothing in it is `-`, never empty, so the count never changes.

use std::io::{self, Write};

use zond_engine::journal::lock::LockState;
use zond_engine::journal::store::{Entry, Pruned};
use zond_engine::scanner::report::ScanKind;

use crate::render::field;
use crate::settings::Presentation;

/// What a journal is, in one word.
///
/// More than two, because "can I continue this?" and "is anything happening?"
/// are different questions and a reader is usually asking both.
///
/// The same words for either phase. A sweep is counted in addresses and a port
/// scan in probes, but both settle what they earn, so both can be continued and
/// both are finished when their plan is covered.
///
/// `unreadable` is the one that is not about the scan. Its cursor is there and
/// this process cannot read it — most often a scan run with `sudo` on a build
/// that left the file behind as root. Saying `resumable` instead would offer to
/// continue work that may already be done.
fn state(entry: &Entry) -> &'static str {
    match (&entry.lock, entry.settled(), entry.is_complete()) {
        (LockState::Held { .. }, _, _) => "running",
        (LockState::Stale { .. }, _, _) => "locked",
        (_, None, _) => "unreadable",
        (_, _, true) => "complete",
        (_, _, false) => "resumable",
    }
}

/// How far a journal got, in the units its phase counts.
fn progress(entry: &Entry) -> String {
    match entry.settled() {
        Some(settled) => format!("{settled}/{}", entry.manifest.total_targets),
        None => format!("?/{}", entry.manifest.total_targets),
    }
}

/// How wide the state column is: the longest word it can hold.
const STATE_WIDTH: usize = 10;

/// How wide the id column is. Every id this engine mints is the same length, so
/// this is a constant rather than a measurement.
const ID_WIDTH: usize = 16;

/// Writes every journal, newest first.
pub(crate) fn list(
    entries: &[Entry],
    presentation: Presentation,
    out: &mut dyn Write,
) -> io::Result<()> {
    if matches!(presentation, Presentation::Pipe) {
        for entry in entries {
            writeln!(
                out,
                "{}\t{}\t{}\t{}\t{}",
                entry.manifest.id,
                state(entry),
                field::timestamp(entry.manifest.created_at),
                progress(entry),
                field::or_dash(&entry.manifest.summary),
            )?;
        }
        return Ok(());
    }

    writeln!(
        out,
        "{:<ID_WIDTH$}  {:<STATE_WIDTH$}  {:>4}  {:>4}  {}",
        "ID", "STATE", "DONE", "AGE", "SCOPE"
    )?;

    for entry in entries {
        writeln!(
            out,
            "{:<ID_WIDTH$}  {:<STATE_WIDTH$}  {:>4}  {:>4}  {}",
            entry.manifest.id,
            state(entry),
            done(entry),
            field::age(entry.manifest.created_at),
            field::or_dash(&entry.manifest.summary),
        )?;
    }

    Ok(())
}

/// Writes one journal in full.
pub(crate) fn show(
    entry: &Entry,
    presentation: Presentation,
    out: &mut dyn Write,
) -> io::Result<()> {
    if matches!(presentation, Presentation::Pipe) {
        return list(std::slice::from_ref(entry), presentation, out);
    }

    writeln!(out, "* {}", entry.manifest.id)?;
    writeln!(out, "  state:   {}", state(entry))?;
    writeln!(
        out,
        "  scope:   {}",
        field::or_dash(&entry.manifest.summary)
    )?;
    writeln!(
        out,
        "  started: {}",
        field::timestamp(entry.manifest.created_at)
    )?;
    // Named in the unit the phase counts, since "targets" reads as
    // address-and-port pairs and a sweep has no ports.
    let counted = match entry.kind() {
        ScanKind::Discovery => "addresses",
        _ => "targets",
    };
    match (entry.settled(), percent(entry)) {
        (Some(settled), Some(percent)) => writeln!(
            out,
            "  done:    {settled} of {} {counted} ({percent}%)",
            entry.manifest.total_targets
        )?,
        // Said as a fact about this process rather than about the scan, and with
        // the one thing a reader can act on: whose it is.
        _ => writeln!(
            out,
            "  done:    unknown of {} {counted} — its progress is recorded in a \
             file this user cannot read",
            entry.manifest.total_targets
        )?,
    }
    writeln!(out, "  engine:  {}", entry.manifest.engine_version)?;
    writeln!(out, "  at:      {}", entry.directory.display())?;

    // Only where it says something a reader has to act on. A journal nothing is
    // holding needs no line saying so.
    if let Some(refusal) = entry.lock.refusal() {
        writeln!(out, "  held:    {refusal}")?;
    }

    Ok(())
}

/// Writes what a prune did.
///
/// Silent in `pipe` when nothing was removed, so a scheduled sweep produces no
/// output on the days it has nothing to do.
pub(crate) fn pruned(
    pruned: &Pruned,
    dry_run: bool,
    presentation: Presentation,
    out: &mut dyn Write,
) -> io::Result<()> {
    for id in &pruned.removed {
        match presentation {
            Presentation::Pipe => {
                writeln!(out, "{id}\t{}", if dry_run { "would" } else { "gone" })?
            }
            _ if dry_run => writeln!(out, "would delete {id}")?,
            _ => writeln!(out, "deleted {id}")?,
        }
    }

    // To stderr: a journal a sweep could not take is commentary on the sweep,
    // not one of its records.
    for held in &pruned.held {
        tracing::warn!("kept {}: {}", held.id, held.reason);
    }

    Ok(())
}

/// How much of a journal's plan is settled, as a whole percent.
///
/// Zero for a plan of no targets, rather than a division by zero. A scan with
/// nothing to do is nought per cent done, which is as true as anything else.
///
/// `None` where the cursor could not be read, which is not nought per cent.
fn percent(entry: &Entry) -> Option<u128> {
    let settled = entry.settled()?;
    match entry.manifest.total_targets {
        0 => Some(0),
        total => Some(settled.saturating_mul(100) / total),
    }
}

/// The same, as the listing's narrow column.
fn done(entry: &Entry) -> String {
    percent(entry).map_or_else(|| String::from("   ?"), |percent| format!("{percent:>3}%"))
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚═╝     ╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    use zond_engine::Exclusions;
    use zond_engine::journal::cursor::Checkpoint;
    use zond_engine::journal::manifest::{Manifest, Plan};
    use zond_engine::model::ip::set::IpSet;
    use zond_engine::model::port::PortSet;
    use zond_engine::model::target::{TargetMap, TargetSet};
    use zond_engine::model::technique::TcpScanTechnique;

    /// A record of a port scan, at whatever point through it the caller wants.
    fn entry(id: &str, settled: u64, total: u128, lock: LockState) -> Entry {
        let mut plan = TargetMap::new();
        plan.add_unit(TargetSet::new(
            "192.0.2.1".parse::<IpSet>().expect("a range"),
            "80".parse::<PortSet>().expect("ports"),
        ));

        let manifest = Manifest::new(
            id,
            &Plan::port_scan(&plan, &Exclusions::none(), TcpScanTechnique::Syn),
            true,
            "192.0.2.0/24 on 1000 ports",
        );

        assemble(id, manifest, total, Some(settled), lock)
    }

    /// A record of a sweep, at whatever point through it the caller wants.
    fn sweep(id: &str, settled: u64, addresses: u128, lock: LockState) -> Entry {
        let ips = "192.0.2.0/24".parse::<IpSet>().expect("a range");
        let manifest = Manifest::new(
            id,
            &Plan::discovery(&ips, &Exclusions::none(), false),
            true,
            "192.0.2.0/24",
        );

        assemble(id, manifest, addresses, Some(settled), lock)
    }

    /// Puts one on disk-shaped, with a fixed creation time so the rendered
    /// timestamp does not move between runs.
    fn assemble(
        id: &str,
        mut manifest: Manifest,
        total: u128,
        settled: Option<u64>,
        lock: LockState,
    ) -> Entry {
        manifest.created_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        manifest.engine_version = "0.12.0".to_string();
        manifest.total_targets = total;

        Entry {
            directory: std::path::PathBuf::from("/tmp").join(id),
            manifest,
            checkpoint: settled.map(|watermark| Checkpoint {
                watermark,
                settled_above: Vec::new(),
            }),
            lock,
        }
    }

    fn rendered(f: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> String {
        let mut out = Vec::new();
        f(&mut out).expect("renders");
        String::from_utf8(out).expect("utf-8")
    }

    /// `pipe` carries no heading, whatever `minimal` does. A heading is one more
    /// line for a program to skip, and the format is documented without one.
    #[test]
    fn the_piped_listing_has_no_heading() {
        let entries = [entry("01AAA", 1, 2, LockState::Free)];

        let piped = rendered(|out| list(&entries, Presentation::Pipe, out));
        assert_eq!(piped.lines().count(), 1, "{piped}");
        assert!(piped.starts_with("01AAA"), "{piped}");

        // And `minimal` does, so a reader knows what the columns are.
        let readable = rendered(|out| list(&entries, Presentation::Minimal, out));
        let mut lines = readable.lines();
        assert!(
            lines.next().is_some_and(|line| line.starts_with("ID")),
            "{readable}"
        );
        assert!(lines.next().is_some_and(|line| line.starts_with("01AAA")));
    }

    /// The `pipe` contract: five fields, every line, whatever the state.
    #[test]
    fn every_piped_line_has_the_same_field_count() {
        let entries = [
            entry("01AAA", 100, 200, LockState::Free),
            entry("01BBB", 200, 200, LockState::Free),
            entry(
                "01CCC",
                5,
                200,
                LockState::Held {
                    pid: 42,
                    last_beat: Duration::from_secs(1),
                },
            ),
            sweep("01DDD", 100, 256, LockState::Free),
        ];

        let text = rendered(|out| list(&entries, Presentation::Pipe, out));

        assert_eq!(text.lines().count(), 4);
        for line in text.lines() {
            assert_eq!(line.split('\t').count(), 5, "{line}");
        }
    }

    /// A record whose cursor could not be read must say so rather than showing
    /// a fraction it does not have. Zero would read as a scan that never
    /// started, and `resumable` would offer to continue work that may be done.
    #[test]
    fn a_record_whose_progress_cannot_be_read_says_so() {
        let mut unreadable = entry("01EEE", 0, 200, LockState::Free);
        unreadable.checkpoint = None;

        assert_eq!(state(&unreadable), "unreadable");
        assert_eq!(progress(&unreadable), "?/200");
        assert_eq!(done(&unreadable).trim(), "?");
        assert_eq!(percent(&unreadable), None);

        let text = rendered(|out| show(&unreadable, Presentation::Minimal, out));
        assert!(text.contains("unknown of 200 targets"), "{text}");
        assert!(text.contains("cannot read"), "{text}");
        assert!(!text.contains("0%"), "{text}");
    }

    /// And the pipe contract keeps its field count whatever the state.
    #[test]
    fn an_unreadable_record_still_pipes_five_fields() {
        let mut unreadable = entry("01EEE", 0, 200, LockState::Free);
        unreadable.checkpoint = None;

        let text = rendered(|out| list(&[unreadable], Presentation::Pipe, out));
        assert_eq!(text.lines().count(), 1);
        assert_eq!(text.lines().next().expect("a line").split('\t').count(), 5);
    }

    /// A sweep is counted in addresses where a port scan is counted in probes,
    /// and both settle what they earn — so both answer the same four states and
    /// both report the same fraction. What differs is only the noun.
    #[test]
    fn a_sweep_is_counted_in_addresses_and_continued_like_anything_else() {
        let part_way = sweep("01DDD", 100, 256, LockState::Free);
        assert_eq!(state(&part_way), "resumable");
        assert_eq!(progress(&part_way), "100/256");

        let finished = sweep("01DDD", 256, 256, LockState::Free);
        assert_eq!(state(&finished), "complete");

        let text = rendered(|out| show(&part_way, Presentation::Minimal, out));
        assert!(
            text.contains("done:    100 of 256 addresses (39%)"),
            "{text}"
        );
        assert!(
            !text.contains("targets"),
            "a sweep probes no ports, so it counts addresses: {text}"
        );
    }

    /// A port scan says targets, since that is what it counts: an address paired
    /// with a port, not an address.
    #[test]
    fn a_port_scan_is_counted_in_targets() {
        let text = rendered(|out| {
            show(
                &entry("01AAA", 100, 200, LockState::Free),
                Presentation::Minimal,
                out,
            )
        });

        assert!(text.contains("done:    100 of 200 targets (50%)"), "{text}");
    }

    /// A sweep somebody is running still says so: the lock is about this
    /// moment, and it outranks how far the record got.
    #[test]
    fn a_running_sweep_says_it_is_running() {
        let running = LockState::Held {
            pid: 1,
            last_beat: Duration::from_secs(1),
        };

        assert_eq!(state(&sweep("01DDD", 0, 256, running)), "running");
    }

    /// The states a reader chooses between.
    #[test]
    fn a_journal_says_whether_it_can_be_continued() {
        let running = LockState::Held {
            pid: 1,
            last_beat: Duration::from_secs(1),
        };
        let stale = LockState::Stale {
            pid: 1,
            last_beat: Duration::from_secs(9_000),
        };

        assert_eq!(state(&entry("a", 1, 2, running)), "running");
        assert_eq!(state(&entry("a", 1, 2, stale)), "locked");
        assert_eq!(state(&entry("a", 1, 2, LockState::Free)), "resumable");
        assert_eq!(state(&entry("a", 2, 2, LockState::Free)), "complete");
        assert_eq!(
            state(&entry("a", 2, 2, LockState::Crashed { pid: 1 })),
            "complete",
            "a crashed writer of a finished scan left nothing to do"
        );
    }

    /// A plan of no targets is nought per cent done, not a panic.
    #[test]
    fn an_empty_plan_does_not_divide_by_zero() {
        assert_eq!(percent(&entry("a", 0, 0, LockState::Free)), Some(0));
    }

    /// Progress is reported without rounding up to complete.
    #[test]
    fn progress_never_flatters_itself() {
        assert_eq!(percent(&entry("a", 199, 200, LockState::Free)), Some(99));
        assert_eq!(percent(&entry("a", 200, 200, LockState::Free)), Some(100));
    }

    /// A dry run says what would go, and does not claim it went.
    #[test]
    fn a_dry_run_says_would() {
        let pruned = Pruned {
            removed: vec!["01AAA".to_string()],
            held: Vec::new(),
        };

        let text = rendered(|out| super::pruned(&pruned, true, Presentation::Minimal, out));
        assert!(text.contains("would delete 01AAA"), "{text}");

        let text = rendered(|out| super::pruned(&pruned, false, Presentation::Minimal, out));
        assert!(text.contains("deleted 01AAA"), "{text}");
    }
}
