// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A comparison in abbreviated tags
//!
//! A tagged block per changed host, in the register
//! [`render::minimal`](crate::render::minimal) writes a scan in: short tags, no
//! colour, and a mark rather than a word, so a narrow terminal holds a long
//! comparison.

use std::io::{self, Write};

use zond_engine::diff::{HostDelta, PortDelta, ScanDiff};
use zond_engine::export::ExportOptions;
use zond_engine::export::diff::schema::ChangeDto;

use crate::render::diff::{change, summary};
use crate::render::field;
use crate::render::style::Style;

/// What opens a host that both scans hold.
const CHANGED: &str = "* ";

/// What opens a host only the later scan holds.
const ARRIVED: &str = "+ ";

/// What opens a host only the earlier scan holds.
const DEPARTED: &str = "- ";

/// What each tagged line is indented by, matching a scan's blocks.
const INDENT: &str = "  ";

/// The width a tag is padded to, its colon included. Five, as in `minimal`, so
/// a comparison and a scan put their values in the same column.
const TAG_WIDTH: usize = 5;

/// One block per host, and a count on standard error.
pub(super) fn write(
    diff: &ScanDiff,
    options: &ExportOptions,
    records: &mut dyn Write,
    narration: &mut dyn Write,
    narration_style: Style,
) -> io::Result<()> {
    let mut first = true;
    for host in diff.hosts() {
        if !first {
            writeln!(records)?;
        }
        first = false;
        terse(host, options, records)?;
    }
    records.flush()?;

    summary(diff, narration, narration_style)
}

/// One host, in the tagged register `minimal` writes in.
fn terse(host: &HostDelta, options: &ExportOptions, out: &mut dyn Write) -> io::Result<()> {
    let bullet = match host.presence() {
        zond_engine::diff::Presence::Both => CHANGED,
        zond_engine::diff::Presence::Added { .. } => ARRIVED,
        zond_engine::diff::Presence::Removed { .. } => DEPARTED,
    };

    let reader = field::Reader::new(options.redaction);
    let named = host
        .current()
        .or(host.baseline())
        .and_then(|host| reader.hostname(host))
        .map(|name| format!(" [{}]", field::printable(&name)))
        .unwrap_or_default();

    writeln!(out, "{bullet}{}{named}", change::identity(host, reader))?;

    match host.presence() {
        zond_engine::diff::Presence::Added { .. } => {
            if let Some(current) = host.current() {
                tagged(out, "new", &[change::describe(current)])?;
            }
        }
        zond_engine::diff::Presence::Removed { .. } => {
            if let Some(baseline) = host.baseline() {
                tagged(
                    out,
                    "gone",
                    &[format!("was {}", change::describe(baseline))],
                )?;
            }
        }
        zond_engine::diff::Presence::Both => {}
    }

    for change in host.changes() {
        for change in ChangeDto::of_host(change, options) {
            tagged(
                out,
                tag_for(change.kind),
                &[change::sentence(&change, reader)],
            )?;
        }
    }

    // A block is read; a wall of lines is not. Endpoints that merely turned up
    // or stopped being reported, at a state nobody would act on, are counted
    // rather than listed. That is what two tools with different port lists
    // produce hundreds of, and what a `pipe` record still carries every one of.
    let (notable, bulk): (Vec<&PortDelta>, Vec<&PortDelta>) = host
        .ports()
        .iter()
        .partition(|port| change::is_notable(port));

    let mut ports: Vec<String> = notable
        .iter()
        .flat_map(|port| change::port_lines(port, options, reader))
        .collect();
    ports.extend(change::counted_bulk(&bulk));

    if !ports.is_empty() {
        tagged(out, "port", &ports)?;
    }

    // The one line that makes an appearance or a disappearance readable for what
    // it is. Only ever printed when it changes the meaning of the block above.
    if !host.presence().is_confirmed()
        && let Some(coverage) = host.presence().counterpart_coverage()
    {
        tagged(out, "note", &[change::unlooked(host, coverage)])?;
    }

    Ok(())
}

/// A tagged line, its continuations aligned under the first value.
fn tagged(out: &mut dyn Write, tag: &str, values: &[String]) -> io::Result<()> {
    let mut values = values.iter();
    let Some(first) = values.next() else {
        return Ok(());
    };

    writeln!(out, "{INDENT}{:<TAG_WIDTH$} {first}", format!("{tag}:"))?;
    for value in values {
        writeln!(out, "{INDENT}{:<TAG_WIDTH$} {value}", "")?;
    }
    Ok(())
}

/// The tag a host-level change is filed under.
///
/// A handful rather than one per kind: a block is read down its left edge, and
/// twenty distinct tags would be a column of noise.
fn tag_for(kind: &str) -> &'static str {
    match kind {
        "hostname" => "name",
        "os" => "os",
        "status" => "state",
        "vendor" | "mac_gained" | "mac_lost" => "mac",
        "address_gained" | "address_lost" => "addr",
        _ => "also",
    }
}
