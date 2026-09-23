// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A comparison as blocks, for reading
//!
//! The same six line types a scan draws in, because a comparison is a listing of
//! records and that is what [`block`] is for. What is
//! decided here is which facts a change has and what colour each takes; the
//! shape is not this module's to choose.

use std::io::{self, Write};

use zond_engine::diff::{HostDelta, PortDelta, ScanDiff};
use zond_engine::export::ExportOptions;
use zond_engine::export::diff::schema::ChangeDto;

use crate::render::block::{self, Block, Child, Header};
use crate::render::diff::{change, summary};
use crate::render::field;
use crate::render::style::Style;

/// One tree per host, in the shape a scan draws.
///
/// The same facts `minimal` shows, grouped rather than emitted as they are
/// found: a host whose name and operating system both moved gets one `System`
/// child with the moves under it, instead of a `System` line each time the
/// comparison happens to reach one.
pub(super) fn write(
    diff: &ScanDiff,
    options: &ExportOptions,
    records: &mut dyn Write,
    narration: &mut dyn Write,
    style: Style,
    narration_style: Style,
) -> io::Result<()> {
    // Numbered on the same reasoning a scan numbers its hosts: a comparison is a
    // listing, and a listing somebody is reading off a screen wants a handle for
    // each row. Built before any of it is drawn, because the columns are
    // measured across the whole listing. See `block::Columns`.
    let blocks: Vec<Block> = diff
        .hosts()
        .iter()
        .enumerate()
        .map(|(index, host)| Block {
            header: changed_header(host, options, style, index + 1),
            children: changes(host, options, style),
        })
        .collect();

    // Above the first block as well as between them: `comparing` has just
    // written what is being compared, and one host butted against the next is
    // two findings a reader has to tell apart for themselves.
    block::write_all(records, style, &blocks, crate::render::width(), |out, _| {
        writeln!(out)
    })?;
    records.flush()?;

    summary(diff, narration, narration_style)
}

/// The line a change opens with.
///
/// The number places the row in the listing, exactly as a scan's does, and what
/// happened to the host leads it: `+` arrived, `-` gone, `~` changed.
///
/// **In front of the address rather than after it.** A scan's verdict trails
/// because it is what came *of* a host, read once you know which host it was; a
/// comparison's is a classification, and running down one looking for what went
/// is why anybody opened it. Trailing, it would also have to clear the widest
/// identity in the listing, and a single IPv6 address pushes every other row's
/// mark thirty columns to the right.
///
/// One column, and the three are told apart by shape as well as by colour, so a
/// comparison captured to a file still says which of them happened.
fn changed_header(host: &HostDelta, options: &ExportOptions, style: Style, at: usize) -> Header {
    let reader = field::Reader::new(options.redaction);
    let named = host
        .current()
        .or(host.baseline())
        .and_then(|host| reader.hostname(host));

    Header::numbered(at, change::identity(host, reader))
        .named(named)
        .tagged(Some(happened(style, host)), TAG_WIDTH)
}

/// How wide the mark column is. One, and all three fit it.
const TAG_WIDTH: usize = 1;

/// What became of this host between the two scans.
fn happened(style: Style, host: &HostDelta) -> String {
    match host.presence() {
        zond_engine::diff::Presence::Added { .. } => style.good("+"),
        zond_engine::diff::Presence::Removed { .. } => style.alarm("-"),
        zond_engine::diff::Presence::Both => style.caution("~"),
    }
}

/// What moved, as children of the host it moved on.
fn changes(host: &HostDelta, options: &ExportOptions, style: Style) -> Vec<Child> {
    let reader = field::Reader::new(options.redaction);
    let mut children = Vec::new();

    // The presence first, because everything under it is qualified by whether
    // this host was there at all.
    match host.presence() {
        zond_engine::diff::Presence::Added { .. } => {
            if let Some(said) = host.current().and_then(change::beyond_presence) {
                children.push(Child::one("now", style.good(&said)));
            }
        }
        zond_engine::diff::Presence::Removed { .. } => {
            if let Some(said) = host.baseline().and_then(change::beyond_presence) {
                // Only where it says more than the tag did: see
                // `change::beyond_presence`.
                children.push(Child::one("was", style.alarm(&said)));
            }
        }
        zond_engine::diff::Presence::Both => {}
    }

    // Directly under the presence, because it is the line that decides whether
    // the presence above it is a finding about the network or about the scans.
    if !host.presence().is_confirmed()
        && let Some(coverage) = host.presence().counterpart_coverage()
    {
        children.push(Child::one(
            "note",
            style.caution(&change::unlooked(host, coverage)),
        ));
    }

    // Grouped, and in a fixed order, so two comparisons of the same host put
    // their children in the same places whatever order the engine reported them.
    let mut grouped: Vec<(&'static str, Vec<String>)> = Vec::new();
    for change in host.changes() {
        for change in ChangeDto::of_host(change, options) {
            let label = child_for(change.kind);
            let sentence = style.plain(&change::sentence(&change, reader));

            match grouped.iter_mut().find(|(held, _)| *held == label) {
                Some((_, lines)) => lines.push(sentence),
                None => grouped.push((label, vec![sentence])),
            }
        }
    }
    for (label, lines) in grouped {
        children.push(Child::many(label, lines));
    }

    // Last, because it is the longest, and a long value is cheapest at the
    // bottom of a block.
    let (notable, bulk): (Vec<&PortDelta>, Vec<&PortDelta>) = host
        .ports()
        .iter()
        .partition(|port| change::is_notable(port));

    let mut ports: Vec<String> = notable
        .iter()
        .flat_map(|port| change::port_lines(port, options, reader))
        .map(|line| paint_change(style, &line))
        .collect();
    ports.extend(
        change::counted_bulk(&bulk)
            .iter()
            .map(|line| style.faint(line)),
    );

    if !ports.is_empty() {
        children.push(Child::many("ports", ports));
    }

    children
}

/// A port's line, with the word that says which way it went coloured.
///
/// Only the verb, and only where there is one: the rest of the line is the
/// endpoint and the detail, which say the same thing in any colour.
fn paint_change(style: Style, line: &str) -> String {
    for (verb, paint) in [
        (" opened", true),
        (" appeared", true),
        (" closed", false),
        (" was open, no record now", false),
        (" no longer reported", false),
    ] {
        if let Some(at) = line.find(verb) {
            let (endpoint, rest) = line.split_at(at);
            let painted = if paint {
                style.good(rest)
            } else {
                style.alarm(rest)
            };
            return format!("{}{painted}", style.plain(endpoint));
        }
    }

    style.plain(line)
}

/// Which child a host-level change belongs under.
///
/// The scan's own words for the same facts, `system`, `hardware` and
/// `addresses`, so a comparison and a scan of one host name its parts alike.
///
/// Spelled out rather than abbreviated, which is what separates this register
/// from `minimal`'s: a block drawn for reading has the width for `hostname`,
/// and `name` beside `addresses` and `hardware` reads as a shorter word for a
/// different kind of thing.
fn child_for(kind: &str) -> &'static str {
    match kind {
        "hostname" => "hostname",
        "os" => "system",
        "status" => "status",
        "vendor" | "mac_gained" | "mac_lost" => "hardware",
        "address_gained" | "address_lost" => "addresses",
        "role_gained" | "role_lost" => "roles",
        _ => "also",
    }
}
