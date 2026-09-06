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
//!
//! **No row number.** `minimal` numbers its rows so a person can refer to one;
//! a number is a property of the listing rather than of the record, and putting
//! one in front of these five fields would shift every one of them for every
//! script already reading them.

use std::io::{self, Write};

use zond_engine::journal::lock::LockState;
use zond_engine::journal::store::{Entry, Pruned};
use zond_engine::report::ScanKind;

use crate::render::block::{self, Block, Child, Header};
use crate::render::field;
use crate::render::style::Style;
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
/// this process cannot read it, most often after a scan run with `sudo` on a
/// build that left the file behind as root. Saying `resumable` instead would
/// offer to continue work that may already be done.
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
    first: usize,
    presentation: Presentation,
    out: &mut dyn Write,
    style: Style,
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

    // Wide enough for the largest number on this page. The numbering runs over
    // the whole listing rather than restarting each page, so a row's number
    // says where it is among *all* the records and not merely where it sits on
    // the screen. That is what makes it worth printing beside a footer that
    // says which page this is.
    let last = first + entries.len().saturating_sub(1);
    let number_width = last.to_string().len();

    // A listing is a table and stays one: unlike a host, every record here has
    // the same five things to say, so the columns cannot come out ragged.
    writeln!(
        out,
        "{}",
        style.faint(&format!(
            "{:>number_width$}  {:<ID_WIDTH$}  {:<STATE_WIDTH$}  {:>4}  {:>4}  {}",
            "#", "ID", "STATE", "DONE", "AGE", "SCOPE"
        ))
    )?;

    for (offset, entry) in entries.iter().enumerate() {
        // Padded before it is painted, because a painted string is longer than
        // it looks and a column measured from one is a column the terminal does
        // not have.
        //
        // The handle is furniture and the identifier is the record, exactly as
        // in a drawn block: `discover` opens a host with a faint number and a
        // strong address, and this opens a record with a faint number and a
        // strong identifier. A listing is a listing whatever it lists, and the
        // eye should not have to learn two of them.
        writeln!(
            out,
            "{}  {}  {}  {}  {}  {}",
            style.faint(&format!("{:>number_width$}", first + offset)),
            style.strong(&format!("{:<ID_WIDTH$}", entry.manifest.id)),
            paint_state(style, entry, &format!("{:<STATE_WIDTH$}", state(entry))),
            style.plain(&format!("{:>4}", done(entry))),
            style.plain(&format!("{:>4}", field::age(entry.manifest.created_at))),
            style.plain(field::or_dash(&entry.manifest.summary)),
        )?;
    }

    Ok(())
}

/// A record's state, coloured by what it asks of whoever is reading.
///
/// The same three states the rest of the program marks: all well, something
/// wants attention, something is wrong. A port that is open and a scan that
/// finished are the same kind of news, in that the thing you were looking for is
/// there, so they take the same green.
///
/// `resumable` and `locked` are the amber: neither is a fault, and both are a
/// record that will not do what you want until you do something first. Whatever
/// took the lock is still running, and a resumable scan is work somebody
/// stopped part-way.
///
/// `unreadable` is the red, and it is the one state that is not about the scan
/// at all: the record's cursor is there and this process cannot read it.
///
/// **`running` is the one with no colour**, which looks like an omission and is
/// not. Green here means "done"; a scan still in flight is not done, and it is
/// not asking anything of the reader either. It is a fact about the record, so
/// it takes the colour every other fact in the listing takes.
fn paint_state(style: Style, entry: &Entry, padded: &str) -> String {
    match state(entry) {
        "complete" => style.good(padded),
        "resumable" | "locked" => style.caution(padded),
        "unreadable" => style.alarm(padded),
        _ => style.plain(padded),
    }
}

/// Writes one journal in full.
pub(crate) fn show(
    entry: &Entry,
    presentation: Presentation,
    out: &mut dyn Write,
    style: Style,
) -> io::Result<()> {
    match presentation {
        // `pipe` writes no number, so the one given here is never used.
        Presentation::Pipe => list(std::slice::from_ref(entry), 1, presentation, out, style),
        Presentation::Fancy => drawn(entry, out, style),
        Presentation::Minimal => tagged(entry, out),
    }
}

/// One record in the abbreviated tags `minimal` writes.
fn tagged(entry: &Entry, out: &mut dyn Write) -> io::Result<()> {
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
            "  done:    unknown of {} {counted}. Its progress is recorded in a \
             file this user cannot read.",
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

/// One record as a block, in the shape a scan draws a host.
///
/// The identifier opens it, because that is what `show`, `report` and `--resume`
/// all take, and it is the one thing on the block a reader is going to copy.
fn drawn(entry: &Entry, out: &mut dyn Write, style: Style) -> io::Result<()> {
    // Named in the unit the phase counts, since "targets" reads as
    // address-and-port pairs and a sweep has no ports.
    let counted = match entry.kind() {
        ScanKind::Discovery => "addresses",
        _ => "targets",
    };

    let progress = match (entry.settled(), percent(entry)) {
        (Some(settled), Some(percent)) => style.plain(&format!(
            "{settled} of {} {counted} ({percent}%)",
            entry.manifest.total_targets
        )),
        // Said as a fact about this process rather than about the scan, and with
        // the one thing a reader can act on: whose it is.
        _ => style.caution(&format!(
            "unknown of {} {counted}. Its progress is recorded in a file this \
             user cannot read.",
            entry.manifest.total_targets
        )),
    };

    let mut children = vec![
        Child::one("state", paint_state(style, entry, state(entry))),
        Child::one(
            "scope",
            style.plain(field::or_dash(&entry.manifest.summary)),
        ),
        Child::one("done", progress),
        Child::one(
            "started",
            style.plain(&field::timestamp(entry.manifest.created_at)),
        ),
        Child::one("engine", style.plain(&entry.manifest.engine_version)),
    ];

    // Only where it says something a reader has to act on. A journal nothing is
    // holding needs no line saying so.
    if let Some(refusal) = entry.lock.refusal() {
        children.push(Child::one("held", style.caution(&refusal)));
    }

    // Last, because it is the longest thing here and the least often read: a
    // path runs to whatever the home directory is.
    children.push(Child::one(
        "at",
        style.plain(&entry.directory.display().to_string()),
    ));

    // No handle: this is one record, so there is nothing to count it among, and
    // a listing where nothing is numbered reserves no column for numbering. The
    // identifier is the whole of what opens it, and it is what `show`, `report`
    // and `--resume` all take, so it is this block's identity and takes the
    // weight an identity takes.
    let blocks = [Block {
        header: Header::alone(entry.manifest.id.clone()),
        children,
    }];

    block::write_all(out, style, &blocks, crate::render::width(), |_, _| Ok(()))
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
    style: Style,
) -> io::Result<()> {
    for id in &pruned.removed {
        match presentation {
            Presentation::Pipe => {
                writeln!(out, "{id}\t{}", if dry_run { "would" } else { "gone" })?;
            }
            // A rehearsal and the real thing read differently on purpose: one of
            // them has already happened.
            _ if dry_run => writeln!(
                out,
                "{} {}",
                style.caution("would delete"),
                style.strong(id)
            )?,
            _ => writeln!(out, "{} {}", style.alarm("deleted"), style.strong(id))?,
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
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::test_support::{opener, painting, strip_escapes};
    use std::time::{Duration, SystemTime};
    use zond_engine::Exclusions;
    use zond_engine::journal::cursor::Checkpoint;
    use zond_engine::journal::manifest::{JournalManifest, Plan};
    use zond_engine::model::ip::set::IpSet;
    use zond_engine::model::port::PortSet;
    use zond_engine::model::target::{TargetMap, TargetSet};
    use zond_engine::model::technique::TcpScanTechnique;
    use zond_engine::system::privilege::Privilege;

    /// A record of a port scan, at whatever point through it the caller wants.
    fn entry(id: &str, settled: u64, total: u128, lock: LockState) -> Entry {
        let mut plan = TargetMap::new();
        plan.add_unit(TargetSet::new(
            "192.0.2.1".parse::<IpSet>().expect("a range"),
            "80".parse::<PortSet>().expect("ports"),
        ));

        let manifest = JournalManifest::new(
            id,
            &Plan::port_scan(&plan, &Exclusions::none(), TcpScanTechnique::Syn),
            Privilege::Raw,
            "192.0.2.0/24 on 1000 ports",
        );

        assemble(id, manifest, total, Some(settled), lock)
    }

    /// A record of a sweep, at whatever point through it the caller wants.
    fn sweep(id: &str, settled: u64, addresses: u128, lock: LockState) -> Entry {
        let ips = "192.0.2.0/24".parse::<IpSet>().expect("a range");
        let manifest = JournalManifest::new(
            id,
            &Plan::discovery(&ips, &Exclusions::none(), false),
            Privilege::Raw,
            "192.0.2.0/24",
        );

        assemble(id, manifest, addresses, Some(settled), lock)
    }

    /// Puts one on disk-shaped, with a fixed creation time so the rendered
    /// timestamp does not move between runs.
    fn assemble(
        id: &str,
        mut manifest: JournalManifest,
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

        let piped = rendered(|out| list(&entries, 1, Presentation::Pipe, out, Style::bare()));
        assert_eq!(piped.lines().count(), 1, "{piped}");
        assert!(piped.starts_with("01AAA"), "{piped}");

        // And `minimal` does, so a reader knows what the columns are.
        let readable = rendered(|out| list(&entries, 1, Presentation::Minimal, out, Style::bare()));
        let mut lines = readable.lines();
        assert!(
            lines
                .next()
                .is_some_and(|line| line.trim_start().starts_with("# ")),
            "{readable}"
        );
        assert!(lines.next().is_some_and(|line| line.contains("01AAA")));
    }

    /// A row's number places it in the whole listing rather than on the screen.
    ///
    /// The second page of ten starts at eleven, which is what makes the number
    /// worth printing beside a footer that says which page this is, and what
    /// lets somebody name a record without reading its id back.
    #[test]
    fn a_page_numbers_its_rows_from_where_it_starts() {
        let entries = [
            entry("01AAA", 1, 2, LockState::Free),
            entry("01BBB", 1, 2, LockState::Free),
        ];

        let second_page =
            rendered(|out| list(&entries, 11, Presentation::Minimal, out, Style::bare()));
        let rows: Vec<&str> = second_page.lines().skip(1).collect();

        assert!(rows[0].starts_with("11  01AAA"), "{second_page}");
        assert!(rows[1].starts_with("12  01BBB"), "{second_page}");

        // And the column is as wide as the largest number on the page, so a
        // first page of nine records does not carry a blank column.
        let first_page =
            rendered(|out| list(&entries, 1, Presentation::Minimal, out, Style::bare()));
        assert!(
            first_page
                .lines()
                .nth(1)
                .is_some_and(|row| row.starts_with("1  01AAA")),
            "{first_page}"
        );
    }

    /// `pipe` carries no number: its five fields are a contract that only ever
    /// grows at the end, and a number in front would shift every one of them.
    #[test]
    fn the_piped_listing_carries_no_number() {
        let entries = [entry("01AAA", 1, 2, LockState::Free)];

        let piped = rendered(|out| list(&entries, 11, Presentation::Pipe, out, Style::bare()));
        assert!(piped.starts_with("01AAA"), "{piped}");
        assert_eq!(piped.trim_end().split('\t').count(), 5, "{piped}");
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

        let text = rendered(|out| list(&entries, 1, Presentation::Pipe, out, Style::bare()));

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

        let text = rendered(|out| show(&unreadable, Presentation::Minimal, out, Style::bare()));
        assert!(text.contains("unknown of 200 targets"), "{text}");
        assert!(text.contains("cannot read"), "{text}");
        assert!(!text.contains("0%"), "{text}");
    }

    /// And the pipe contract keeps its field count whatever the state.
    #[test]
    fn an_unreadable_record_still_pipes_five_fields() {
        let mut unreadable = entry("01EEE", 0, 200, LockState::Free);
        unreadable.checkpoint = None;

        let text = rendered(|out| list(&[unreadable], 1, Presentation::Pipe, out, Style::bare()));
        assert_eq!(text.lines().count(), 1);
        assert_eq!(text.lines().next().expect("a line").split('\t').count(), 5);
    }

    /// A sweep is counted in addresses where a port scan is counted in probes,
    /// and both settle what they earn, so both answer the same four states and
    /// both report the same fraction. What differs is only the noun.
    #[test]
    fn a_sweep_is_counted_in_addresses_and_continued_like_anything_else() {
        let part_way = sweep("01DDD", 100, 256, LockState::Free);
        assert_eq!(state(&part_way), "resumable");
        assert_eq!(progress(&part_way), "100/256");

        let finished = sweep("01DDD", 256, 256, LockState::Free);
        assert_eq!(state(&finished), "complete");

        let text = rendered(|out| show(&part_way, Presentation::Minimal, out, Style::bare()));
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
                Style::bare(),
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

        let text =
            rendered(|out| super::pruned(&pruned, true, Presentation::Minimal, out, Style::bare()));
        assert!(text.contains("would delete 01AAA"), "{text}");

        let text = rendered(|out| {
            super::pruned(&pruned, false, Presentation::Minimal, out, Style::bare())
        });
        assert!(text.contains("deleted 01AAA"), "{text}");
    }

    /// A record draws in the same shape a scan draws a host, so `zond journal
    /// show` and `zond scan` read as one program.
    #[test]
    fn a_record_reads_as_a_block_in_fancy() {
        let text = rendered(|out| {
            show(
                &entry("01AAA", 100, 200, LockState::Free),
                Presentation::Fancy,
                out,
                Style::bare(),
            )
        });

        assert_eq!(
            text,
            "  01AAA
  state    resumable
  scope    192.0.2.0/24 on 1000 ports
  done     100 of 200 targets (50%)
  started  2023-11-14T22:13:20.000000Z
  engine   0.12.0
  at       /tmp/01AAA
"
        );
    }

    /// Every state a record can be in takes the colour that says what it asks
    /// of the reader.
    ///
    /// `complete` is the green: a finished scan and an open port are the same
    /// kind of news. `resumable` and `locked` are the amber, since neither is a
    /// fault and both are a record that will not do what you want until you do
    /// something first. `unreadable` is the red. `running` carries no colour at
    /// all, because green here means "done" and a scan in flight is not.
    #[test]
    fn every_state_is_coloured_by_what_it_asks_for() {
        let cases = [
            (
                "complete",
                entry("01A", 2, 2, LockState::Free),
                opener(Style::good),
            ),
            (
                "resumable",
                entry("01B", 1, 2, LockState::Free),
                opener(Style::caution),
            ),
            (
                "locked",
                entry(
                    "01C",
                    1,
                    2,
                    LockState::Stale {
                        pid: 1,
                        last_beat: Duration::from_secs(1),
                    },
                ),
                opener(Style::caution),
            ),
            (
                "running",
                entry(
                    "01D",
                    1,
                    2,
                    LockState::Held {
                        pid: 1,
                        last_beat: Duration::from_secs(1),
                    },
                ),
                opener(Style::plain),
            ),
        ];

        for (expected, entry, role) in cases {
            assert_eq!(state(&entry), expected, "the fixture is not what it claims");

            let painted = paint_state(painting(), &entry, expected);
            assert!(
                painted.starts_with(&role),
                "'{expected}' is not drawn as what it asks for: {painted:?}"
            );
        }

        // The three that mean something are three different things.
        assert_ne!(opener(Style::good), opener(Style::caution));
        assert_ne!(opener(Style::caution), opener(Style::alarm));
        assert_ne!(opener(Style::plain), opener(Style::good));
    }

    /// A record listing paints its columns with the same roles a host listing
    /// does.
    ///
    /// The handle is furniture and the identifier is the record, which are the
    /// same two roles `discover` gives a number and an address. They were both
    /// the accent once, which made a journal the one listing in the program
    /// where the number shouted as loudly as the thing it numbered.
    #[test]
    fn a_record_takes_the_same_roles_a_host_does() {
        let entries = [entry("01AAA", 1, 2, LockState::Free)];
        let text = rendered(|out| list(&entries, 7, Presentation::Fancy, out, painting()));

        let faint = opener(Style::faint);
        let strong = opener(Style::strong);

        assert_ne!(faint, strong, "the two roles have to be tellable apart");
        assert!(
            text.contains(&format!("{faint}7")),
            "the handle is not furniture: {text:?}"
        );
        assert!(
            text.contains(&format!("{strong}01AAA")),
            "the identifier is not the record: {text:?}"
        );

        // And the accent is spent on nothing here, because a record has no name
        // the network gave back, which is the one thing that role marks.
        assert!(
            !text.contains(&opener(Style::accent)),
            "something in a record listing claimed the accent: {text:?}"
        );
    }

    /// A listing stays a table: unlike a host, every record here has the same
    /// five things to say, so the columns cannot come out ragged.
    #[test]
    fn the_listing_keeps_its_columns_when_painted() {
        let entries = [
            entry("01AAA", 1, 2, LockState::Free),
            sweep("01BBB", 254, 254, LockState::Free),
        ];

        let bare = rendered(|out| list(&entries, 1, Presentation::Fancy, out, Style::bare()));
        let painted = rendered(|out| list(&entries, 1, Presentation::Fancy, out, painting()));

        assert_eq!(strip_escapes(&painted), bare, "colour moved the columns");
    }
}
