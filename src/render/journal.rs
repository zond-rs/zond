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
//! | 1 | `ID` | what `show` and `--resume` take |
//! | 2 | `STATE` | `running`, `resumable`, `complete`, or `locked` |
//! | 3 | `STARTED` | when the first sitting began, RFC 3339 |
//! | 4 | `PROGRESS` | `settled/total` targets |
//! | 5 | `SCOPE` | what was scanned |
//!
//! A field with nothing in it is `-`, never empty, so the count never changes.

use std::io::{self, Write};

use zond_engine::journal::lock::LockState;
use zond_engine::journal::store::{Entry, Pruned};

use crate::render::field;
use crate::settings::Presentation;

/// What a journal is, in one word.
///
/// Four rather than two, because "can I continue this?" and "is anything
/// happening?" are different questions and a reader is usually asking both.
fn state(entry: &Entry) -> &'static str {
    match (&entry.lock, entry.is_complete()) {
        (LockState::Held { .. }, _) => "running",
        (LockState::Stale { .. }, _) => "locked",
        (_, true) => "complete",
        (_, false) => "resumable",
    }
}

/// How wide the state column is: the longest word it can hold.
const STATE_WIDTH: usize = 9;

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
                "{}\t{}\t{}\t{}/{}\t{}",
                entry.manifest.id,
                state(entry),
                field::timestamp(entry.manifest.created_at),
                entry.settled(),
                entry.manifest.total_targets,
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
            "{:<ID_WIDTH$}  {:<STATE_WIDTH$}  {:>3}%  {:>4}  {}",
            entry.manifest.id,
            state(entry),
            percent(entry),
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
    writeln!(
        out,
        "  done:    {} of {} targets ({}%)",
        entry.settled(),
        entry.manifest.total_targets,
        percent(entry)
    )?;
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
fn percent(entry: &Entry) -> u128 {
    match entry.manifest.total_targets {
        0 => 0,
        total => entry.settled().saturating_mul(100) / total,
    }
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
    use zond_engine::journal::cursor::Checkpoint;
    use zond_engine::journal::manifest::{Manifest, PlanFingerprint};
    use zond_engine::model::ip::set::IpSet;
    use zond_engine::model::port::PortSet;
    use zond_engine::model::target::{TargetMap, TargetSet};
    use zond_engine::model::technique::TcpScanTechnique;

    fn entry(id: &str, settled: u64, total: u128, lock: LockState) -> Entry {
        let mut plan = TargetMap::new();
        plan.add_unit(TargetSet::new(
            "192.0.2.1".parse::<IpSet>().expect("a range"),
            "80".parse::<PortSet>().expect("ports"),
        ));

        Entry {
            directory: std::path::PathBuf::from("/tmp").join(id),
            manifest: Manifest {
                journal_version: 1,
                id: id.to_string(),
                engine_version: "0.12.0".to_string(),
                created_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                plan: PlanFingerprint::of(&plan, TcpScanTechnique::Syn, true),
                targets: zond_engine::record::PlanRecord::from(&plan),
                technique: TcpScanTechnique::Syn.name().to_owned(),
                privileged: true,
                total_targets: total,
                summary: "192.0.2.0/24 on 1000 ports".to_string(),
            },
            checkpoint: Some(Checkpoint {
                watermark: settled,
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
        ];

        let text = rendered(|out| list(&entries, Presentation::Pipe, out));

        assert_eq!(text.lines().count(), 3);
        for line in text.lines() {
            assert_eq!(line.split('\t').count(), 5, "{line}");
        }
    }

    /// The four states a reader chooses between.
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
        assert_eq!(percent(&entry("a", 0, 0, LockState::Free)), 0);
    }

    /// Progress is reported without rounding up to complete.
    #[test]
    fn progress_never_flatters_itself() {
        assert_eq!(percent(&entry("a", 199, 200, LockState::Free)), 99);
        assert_eq!(percent(&entry("a", 200, 200, LockState::Free)), 100);
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
