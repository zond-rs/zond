// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A comparison as records, for a program
//!
//! Tab-separated, every field, fixed units, no padding and no heading. That is
//! the promise [`render::pipe`](crate::render::pipe) makes about a scan, kept
//! about a comparison. The only mode here whose output is a stable interface.

use std::io::{self, Write};

use zond_engine::diff::{HostDelta, PortDelta, ScanDiff};
use zond_engine::export::diff::schema::ChangeDto;
use zond_engine::export::{ExportOptions, HostRedaction};

use crate::render::diff::change;
use crate::render::field;

/// What separates one field from the next in `pipe`.
pub(super) const SEPARATOR: char = '\t';

/// How many fields a `pipe` record carries. See the module documentation.
pub(super) const FIELDS: usize = 7;

/// One line per change.
pub(super) fn write(
    diff: &ScanDiff,
    options: &ExportOptions,
    out: &mut dyn Write,
) -> io::Result<()> {
    for host in diff.hosts() {
        for record in host_records(host, options) {
            writeln!(out, "{}", record.join(&SEPARATOR.to_string()))?;
        }
    }
    out.flush()
}

/// Every `pipe` line one host contributes, in a fixed order: the host's own
/// arrival or departure, then what moved about it, then its endpoints.
fn host_records(host: &HostDelta, options: &ExportOptions) -> Vec<[String; FIELDS]> {
    let address = change::identity(host, field::Reader::new(options.redaction));
    let masking = options.redaction.for_delta(host);
    let confirmed = yes_no(host.presence().is_confirmed());
    let mut records = Vec::new();

    match host.presence() {
        zond_engine::diff::Presence::Added { .. } => records.push(line(
            "host_added",
            &confirmed,
            &address,
            "-",
            "-",
            None,
            host.current().map(change::status).as_deref(),
        )),
        zond_engine::diff::Presence::Removed { .. } => records.push(line(
            "host_removed",
            &confirmed,
            &address,
            "-",
            "-",
            host.baseline().map(change::status).as_deref(),
            None,
        )),
        zond_engine::diff::Presence::Both => {}
    }

    for change in host.changes() {
        for change in ChangeDto::of_host(change, &masking) {
            records.push(line(
                change.kind,
                &confirmed,
                &address,
                "-",
                "-",
                change.before.as_deref(),
                change.after.as_deref(),
            ));
        }
    }

    for port in host.ports() {
        records.extend(port_records(port, &address, &masking));
    }

    records
}

/// Every `pipe` line one endpoint contributes.
fn port_records(port: &PortDelta, address: &str, masking: &HostRedaction) -> Vec<[String; FIELDS]> {
    let endpoint = change::endpoint(port);
    let confirmed = yes_no(port.presence().is_confirmed());
    let mut records = Vec::new();

    // An endpoint that opened or shut is said so outright, whether it did it by
    // changing state or by turning up. A rule that alerts on a port opening
    // should not have to know which of the two happened.
    if port.is_opened() {
        records.push(line(
            "port_opened",
            &confirmed,
            address,
            &endpoint,
            "state",
            port.baseline().map(change::state).as_deref(),
            port.current().map(change::state).as_deref(),
        ));
    }
    if port.is_closed() {
        records.push(line(
            "port_closed",
            &confirmed,
            address,
            &endpoint,
            "state",
            port.baseline().map(change::state).as_deref(),
            port.current().map(change::state).as_deref(),
        ));
    }

    // A record that arrived or went without the endpoint opening or shutting,
    // such as a filtered port that turned up, still happened.
    if !port.is_opened() && !port.is_closed() {
        match port.presence() {
            zond_engine::diff::Presence::Added { .. } => records.push(line(
                "port_added",
                &confirmed,
                address,
                &endpoint,
                "state",
                None,
                port.current().map(change::state).as_deref(),
            )),
            zond_engine::diff::Presence::Removed { .. } => records.push(line(
                "port_removed",
                &confirmed,
                address,
                &endpoint,
                "state",
                port.baseline().map(change::state).as_deref(),
                None,
            )),
            zond_engine::diff::Presence::Both => {}
        }
    }

    for change in port.changes() {
        for change in ChangeDto::of_port(change, masking) {
            // The state is already reported above, in the terms a rule wants.
            if change.kind == "port_state" {
                continue;
            }
            records.push(line(
                change.kind,
                &confirmed,
                address,
                &endpoint,
                "-",
                change.before.as_deref(),
                change.after.as_deref(),
            ));
        }
    }

    records
}

/// One record, with every absent value written as a dash.
fn line(
    change: &str,
    confirmed: &str,
    address: &str,
    port: &str,
    detail: &str,
    before: Option<&str>,
    after: Option<&str>,
) -> [String; FIELDS] {
    [
        change.to_owned(),
        confirmed.to_owned(),
        address.to_owned(),
        port.to_owned(),
        detail.to_owned(),
        // The last two are the only fields a scanned host has any say over, and
        // they are the ones a control character would break the record with.
        field::printable(before.unwrap_or(field::UNKNOWN)).into_owned(),
        field::printable(after.unwrap_or(field::UNKNOWN)).into_owned(),
    ]
}

/// The `CONFIRMED` field: whether the other scan is known to have looked.
fn yes_no(confirmed: bool) -> String {
    if confirmed { "yes" } else { "no" }.to_owned()
}
