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
//! ## The two presentations keep their bargain
//!
//! `pipe` is one line per change, tab-separated, no heading. `minimal` is one
//! block per host, in the same tagged grammar a scan is drawn in — the bullet
//! carries whether the host arrived, went or merely changed, so it costs no
//! line of its own.
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
//! | 2 | `CONFIRMED` | `yes` or `no` — whether the other scan is known to have looked here |
//! | 3 | `ADDRESS` | the host |
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

use std::io::{self, Write};

use zond_engine::diff::{HostDelta, PortDelta, ScanDiff};
use zond_engine::export::ExportOptions;
use zond_engine::export::diff::schema::ChangeDto;
use zond_engine::scanner::report::ScanKind;

use crate::render::field;
use crate::settings::Presentation;

/// What separates one field from the next in `pipe`.
const SEPARATOR: char = '\t';

/// How many fields a `pipe` record carries. See the module documentation.
pub(crate) const FIELDS: usize = 7;

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
) -> io::Result<()> {
    match presentation {
        Presentation::Pipe => pipe(diff, options, records),
        _ => minimal(diff, options, records, narration),
    }
}

/// A one-line account of what was compared, for standard error.
pub(crate) fn comparing(
    baseline: &str,
    current: &str,
    diff: &ScanDiff,
    out: &mut dyn Write,
) -> io::Result<()> {
    writeln!(
        out,
        "comparing {baseline} ({}) with {current} ({})",
        field::timestamp(diff.baseline().at()),
        field::timestamp(diff.current().at()),
    )?;

    // Nothing enforces which of the two is earlier — a comparison takes the
    // order it was given. Said here rather than refused, because comparing a
    // scan with an older one is a reasonable thing to ask for and reading the
    // result as though it ran forwards is not.
    if diff.baseline().at() > diff.current().at() {
        writeln!(
            out,
            "note: the first scan is the later of the two, so this reads backwards"
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
                "note: only the later scan looked at ports, so most of what follows is \
                 the earlier one not having looked"
            )?,
            (true, false) => writeln!(
                out,
                "note: only the earlier scan looked at ports, so most of what follows is \
                 the later one not having looked"
            )?,
            _ => {}
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// pipe
// ---------------------------------------------------------------------------

/// One line per change.
fn pipe(diff: &ScanDiff, options: &ExportOptions, out: &mut dyn Write) -> io::Result<()> {
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
    let address = host.address().to_string();
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
            host.current().map(status).as_deref(),
        )),
        zond_engine::diff::Presence::Removed { .. } => records.push(line(
            "host_removed",
            &confirmed,
            &address,
            "-",
            "-",
            host.baseline().map(status).as_deref(),
            None,
        )),
        zond_engine::diff::Presence::Both => {}
    }

    for change in host.changes() {
        for change in ChangeDto::of_host(change, options) {
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
        records.extend(port_records(port, &address, options));
    }

    records
}

/// Every `pipe` line one endpoint contributes.
fn port_records(port: &PortDelta, address: &str, options: &ExportOptions) -> Vec<[String; FIELDS]> {
    let endpoint = endpoint(port);
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
            port.baseline().map(state).as_deref(),
            port.current().map(state).as_deref(),
        ));
    }
    if port.is_closed() {
        records.push(line(
            "port_closed",
            &confirmed,
            address,
            &endpoint,
            "state",
            port.baseline().map(state).as_deref(),
            port.current().map(state).as_deref(),
        ));
    }

    // A record that arrived or went without the endpoint opening or shutting —
    // a filtered port that turned up, say — still happened.
    if !port.is_opened() && !port.is_closed() {
        match port.presence() {
            zond_engine::diff::Presence::Added { .. } => records.push(line(
                "port_added",
                &confirmed,
                address,
                &endpoint,
                "state",
                None,
                port.current().map(state).as_deref(),
            )),
            zond_engine::diff::Presence::Removed { .. } => records.push(line(
                "port_removed",
                &confirmed,
                address,
                &endpoint,
                "state",
                port.baseline().map(state).as_deref(),
                None,
            )),
            zond_engine::diff::Presence::Both => {}
        }
    }

    for change in port.changes() {
        for change in ChangeDto::of_port(change, options) {
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

fn yes_no(confirmed: bool) -> String {
    if confirmed { "yes" } else { "no" }.to_owned()
}

fn endpoint(port: &PortDelta) -> String {
    format!(
        "{}/{}",
        port.number(),
        zond_engine::export::schema::protocol_name(port.protocol())
    )
}

fn status(host: &zond_engine::Host) -> String {
    zond_engine::export::schema::host_status_name(host.status()).to_owned()
}

fn state(port: &zond_engine::Port) -> String {
    zond_engine::export::schema::port_state_name(port.state()).to_owned()
}

// ---------------------------------------------------------------------------
// minimal
// ---------------------------------------------------------------------------

/// One block per host, and a count on standard error.
fn minimal(
    diff: &ScanDiff,
    options: &ExportOptions,
    records: &mut dyn Write,
    narration: &mut dyn Write,
) -> io::Result<()> {
    let mut first = true;
    for host in diff.hosts() {
        if !first {
            writeln!(records)?;
        }
        first = false;
        block(host, options, records)?;
    }
    records.flush()?;

    summary(diff, narration)
}

/// One host's block.
fn block(host: &HostDelta, options: &ExportOptions, out: &mut dyn Write) -> io::Result<()> {
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

    writeln!(out, "{bullet}{}{named}", host.address())?;

    match host.presence() {
        zond_engine::diff::Presence::Added { .. } => {
            if let Some(current) = host.current() {
                tagged(out, "new", &[describe(current)])?;
            }
        }
        zond_engine::diff::Presence::Removed { .. } => {
            if let Some(baseline) = host.baseline() {
                tagged(out, "gone", &[format!("was {}", describe(baseline))])?;
            }
        }
        zond_engine::diff::Presence::Both => {}
    }

    for change in host.changes() {
        for change in ChangeDto::of_host(change, options) {
            tagged(out, tag_for(change.kind), &[sentence(&change)])?;
        }
    }

    // A block is read; a wall of lines is not. Endpoints that merely turned up
    // or stopped being reported, at a state nobody would act on, are counted
    // rather than listed — which is what two tools with different port lists
    // produce hundreds of, and what a `pipe` record still carries every one of.
    let (notable, bulk): (Vec<&PortDelta>, Vec<&PortDelta>) =
        host.ports().iter().partition(|port| is_notable(port));

    let mut ports: Vec<String> = notable
        .iter()
        .flat_map(|port| port_lines(port, options))
        .collect();
    ports.extend(counted_bulk(&bulk));

    if !ports.is_empty() {
        tagged(out, "port", &ports)?;
    }

    // The one line that makes an appearance or a disappearance readable for what
    // it is. Only ever printed when it changes the meaning of the block above.
    if !host.presence().is_confirmed()
        && let Some(coverage) = host.presence().counterpart_coverage()
    {
        tagged(out, "note", &[unlooked(host, coverage)])?;
    }

    Ok(())
}

/// What a host looked like, in one clause.
fn describe(host: &zond_engine::Host) -> String {
    let open = host
        .ports()
        .filter(|port| port.state() == zond_engine::PortState::Open)
        .count();

    match open {
        0 => field::status(host).to_lowercase(),
        open => format!(
            "{}, {}",
            field::status(host).to_lowercase(),
            counted(open, "port open")
        ),
    }
}

/// Why an appearance or a disappearance is not a finding about the network.
fn unlooked(host: &HostDelta, coverage: zond_engine::diff::Coverage) -> String {
    let other = if host.presence().is_added() {
        "the earlier scan"
    } else {
        "the later scan"
    };

    match coverage {
        zond_engine::diff::Coverage::Withheld => {
            format!("{other} was forbidden this address")
        }
        zond_engine::diff::Coverage::OutOfScope => {
            format!("{other} did not cover this address")
        }
        _ => format!("{other} does not say whether it covered this address"),
    }
}

/// Whether an endpoint is worth a line of its own.
///
/// Anything that opened, shut, or moved a field is. What is left is an endpoint
/// one scan has a record for and the other does not, at a state neither scan
/// would have anybody act on — and there can be hundreds of those between two
/// tools whose port lists do not agree.
fn is_notable(port: &PortDelta) -> bool {
    port.is_opened()
        || port.is_closed()
        || !port.changes().is_empty()
        || port
            .baseline()
            .is_some_and(|port| port.state() == zond_engine::PortState::Open)
        || port
            .current()
            .is_some_and(|port| port.state() == zond_engine::PortState::Open)
}

/// The endpoints not worth a line each, as one line each way.
fn counted_bulk(ports: &[&PortDelta]) -> Vec<String> {
    let mut lines = Vec::new();

    for (matches, phrase, when) in [
        (
            ports
                .iter()
                .filter(|port| port.presence().is_added())
                .collect::<Vec<_>>(),
            "newly recorded",
            "before",
        ),
        (
            ports
                .iter()
                .filter(|port| port.presence().is_removed())
                .collect::<Vec<_>>(),
            "no longer reported",
            // The scan that did not look is the later one here, as it is on the
            // single-endpoint lines above.
            "since",
        ),
    ] {
        if matches.is_empty() {
            continue;
        }

        let unconfirmed = matches
            .iter()
            .filter(|port| !port.presence().is_confirmed())
            .count();
        let counted = counted(matches.len(), "port");
        let caveat = match unconfirmed {
            0 => String::new(),
            n => format!(" ({n} not looked for {when})"),
        };

        lines.push(format!("[{counted} {phrase}, none open{caveat}]"));
    }

    lines
}

/// The lines one endpoint contributes to a block.
fn port_lines(port: &PortDelta, options: &ExportOptions) -> Vec<String> {
    let endpoint = endpoint(port);
    let mut lines = Vec::new();

    if port.is_opened() {
        lines.push(format!("{endpoint} opened"));
    } else if port.is_closed() {
        // "Closed" is a verdict, and only one of these two scans made it. Where
        // the later one has no record at all the honest line says so: a port
        // absent from a report is not a port a scan found shut.
        lines.push(match port.current() {
            Some(_) => format!("{endpoint} closed"),
            None => format!("{endpoint} was open, no record now"),
        });
    }

    for change in port.changes() {
        for change in ChangeDto::of_port(change, options) {
            // Already said above, in a word rather than a transition.
            if change.kind == "port_state" && (port.is_opened() || port.is_closed()) {
                continue;
            }
            lines.push(format!("{endpoint} {}", sentence(&change)));
        }
    }

    if lines.is_empty() {
        match port.presence() {
            zond_engine::diff::Presence::Added { .. } => lines.push(format!("{endpoint} appeared")),
            zond_engine::diff::Presence::Removed { .. } => {
                lines.push(format!("{endpoint} no longer reported"));
            }
            zond_engine::diff::Presence::Both => {}
        }
    }

    // Which scan failed to look depends on which one is missing the record, and
    // saying "before" for both had a port that vanished blaming the wrong scan.
    if !port.presence().is_confirmed()
        && let Some(last) = lines.last_mut()
    {
        last.push_str(if port.presence().is_added() {
            " (not looked for before)"
        } else {
            " (not looked for since)"
        });
    }

    lines
}

/// How much of a certificate fingerprint a block shows.
///
/// A SHA-256 fingerprint is sixty-four characters and two of them on one line is
/// a wall. Twelve is past any accidental collision and short enough to read; the
/// whole of it is one field away in `pipe` and in the JSON document, which is
/// where a program looks anyway.
const FINGERPRINT_SHOWN: usize = 12;

/// One change as a phrase a person reads.
fn sentence(change: &ChangeDto) -> String {
    let what = label(change.kind);
    let before = readable(change.kind, change.before.as_deref());
    let after = readable(change.kind, change.after.as_deref());

    // Some changes read better with no lead-in at all: a hostname or an
    // operating system is its own subject, and "name: router.local ->
    // gateway.local" says everything "name: hostname router.local -> ..." would.
    //
    // A value gained or lost is the exception. With no lead-in, "os: Debian"
    // says the host runs Debian rather than that this scan learned so, and the
    // two are exactly what a comparison exists to keep apart.
    let lead = if what.is_empty() {
        String::new()
    } else {
        format!("{what} ")
    };

    // A change to one member of a set already says which way it went — "lost
    // 2a02:…" needs no ", now none" after it, and reads as a mistake with one.
    let directional = change.kind.ends_with("_gained") || change.kind.ends_with("_lost");

    match (before, after) {
        (Some(before), Some(after)) => format!("{lead}{before} -> {after}"),
        (None, Some(after)) if lead.is_empty() => format!("now {after}"),
        (None, Some(after)) => format!("{lead}{after}"),
        (Some(before), None) if directional => format!("{lead}{before}"),
        (Some(before), None) if lead.is_empty() => format!("no longer {before}"),
        (Some(before), None) => format!("{lead}{before}, now none"),
        (None, None) => what.to_owned(),
    }
}

/// A value shortened to what a person needs to see.
///
/// Only two kinds are touched, and both because the whole value is unreadable
/// rather than because it is long: a fingerprint is an identity nobody reads
/// past the first few characters of, and a certificate's expiry is a date rather
/// than a moment.
fn readable(kind: &str, value: Option<&str>) -> Option<String> {
    // Before anything else: a newline here would forge a tagged line, and the
    // value came from the host being described.
    let value = field::printable(value?).into_owned();

    Some(match kind {
        "certificate_rotated" | "certificate_presented" | "certificate_withdrawn" => {
            match value.char_indices().nth(FINGERPRINT_SHOWN) {
                Some((cut, _)) => format!("{}…", &value[..cut]),
                None => value,
            }
        }
        "certificate_expiring" | "certificate_expired" => value
            .split_once('T')
            .map_or(value.as_str(), |(date, _)| date)
            .to_owned(),
        _ => value,
    })
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

/// What a change is called in a block.
fn label(kind: &'static str) -> &'static str {
    match kind {
        "status" => "status",
        "hostname" => "",
        "os" => "",
        "vendor" => "vendor",
        "address_gained" => "gained",
        "address_lost" => "lost",
        "mac_gained" => "gained",
        "mac_lost" => "lost",
        "role_gained" => "role gained",
        "role_lost" => "role lost",
        "service_identified" => "now running",
        "service_lost" => "no longer identified as",
        "service_name" => "service",
        "service_product" => "product",
        "service_version" => "version",
        "service_vendor" => "service vendor",
        "service_extrainfo" => "detail",
        "cpe_gained" => "platform gained",
        "cpe_lost" => "platform lost",
        "tls_version" => "TLS",
        "cipher_suite" => "cipher",
        "alpn_gained" => "ALPN gained",
        "alpn_lost" => "ALPN lost",
        "certificate_presented" => "certificate now presented,",
        "certificate_withdrawn" => "certificate withdrawn,",
        "certificate_rotated" => "certificate rotated,",
        "certificate_expiring" => "certificate expires",
        "certificate_expired" => "certificate expired",
        other => other,
    }
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

/// The count a comparison ends with, on standard error.
fn summary(diff: &ScanDiff, out: &mut dyn Write) -> io::Result<()> {
    if diff.is_empty() {
        return writeln!(out, "no change");
    }

    let summary = diff.summary();
    let mut parts = Vec::new();

    if summary.hosts_changed > 0 {
        parts.push(counted(summary.hosts_changed, "host changed"));
    }
    for (count, word) in [
        (summary.hosts_added, "host appeared"),
        (summary.hosts_removed, "host gone"),
    ] {
        if count.total > 0 {
            parts.push(unconfirmed(count.total, count.confirmed, word));
        }
    }
    for (count, word) in [
        (summary.ports_opened, "port opened"),
        (summary.ports_closed, "port closed"),
    ] {
        if count.total > 0 {
            parts.push(unconfirmed(count.total, count.confirmed, word));
        }
    }
    if summary.certificates_rotated > 0 {
        parts.push(counted(summary.certificates_rotated, "certificate rotated"));
    }
    if summary.certificates_expiring > 0 {
        parts.push(counted(
            summary.certificates_expiring,
            "certificate expiring",
        ));
    }
    if summary.certificates_expired > 0 {
        parts.push(counted(summary.certificates_expired, "certificate expired"));
    }

    writeln!(out, "{}", parts.join(", "))
}

/// `count` of `phrase`, pluralised on the word that carries the number.
///
/// "host changed" counted twice is "2 hosts changed", not "2 host changeds".
/// [`field::plural`] pluralises a single word, which is every word a scan
/// counts; a comparison counts phrases.
fn counted(count: usize, phrase: &str) -> String {
    let (head, rest) = phrase.split_once(' ').unwrap_or((phrase, ""));
    let head = field::plural(count as u128, head);

    if rest.is_empty() {
        format!("{count} {head}")
    } else {
        format!("{count} {head} {rest}")
    }
}

/// A count, saying how much of it nobody had looked for.
///
/// The parenthesis appears only when it changes the number's meaning, so an
/// ordinary night reads as an ordinary sentence.
fn unconfirmed(total: usize, confirmed: usize, word: &str) -> String {
    let counted = counted(total, word);

    match total - confirmed {
        0 => counted,
        unconfirmed => format!("{counted} ({unconfirmed} unconfirmed)"),
    }
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
pub(crate) mod tests {
    use std::time::{Duration, SystemTime};

    use zond_engine::model::exclusion::Exclusions;
    use zond_engine::model::parse::ip::to_set;
    use zond_engine::scanner::report::{
        PhaseParts, ScanKind, ScanPhase, ScanReport, ScanSettings, TargetScope,
    };
    use zond_engine::{Host, Port, PortState, Protocol, ZondConfig};

    use super::*;
    use crate::render::test_support::{Capture, host};

    /// A report whose one phase says it walked `covered`.
    pub(crate) fn scoped(hosts: Vec<Host>, covered: &str) -> ScanReport {
        let mut targets = to_set(&[covered], None, None).expect("a parseable range");
        let phase = ScanPhase::from_parts(PhaseParts {
            kind: ScanKind::Discovery,
            started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_000_000),
            elapsed: Duration::from_secs(1),
            privileged: true,
            targets: TargetScope::from_ip_set(&mut targets, &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            unroutable: Vec::new(),
            probes: Vec::new(),
        });

        ScanReport::recorded("test", vec![phase], hosts)
    }

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
        assert_eq!(counted(1, "host changed"), "1 host changed");
        assert_eq!(counted(2, "host changed"), "2 hosts changed");
        assert_eq!(counted(1, "certificate rotated"), "1 certificate rotated");
        assert_eq!(counted(3, "port opened"), "3 ports opened");
    }

    /// A number that includes records nobody looked for says how many, because
    /// the two are not the same finding.
    #[test]
    fn a_count_holding_unconfirmed_records_says_how_many() {
        assert_eq!(unconfirmed(3, 3, "host appeared"), "3 hosts appeared");
        assert_eq!(
            unconfirmed(3, 1, "host appeared"),
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
        use zond_engine::scanner::report::{PhaseParts, ScanPhase, ScanSettings, TargetScope};

        let phase = |kind| {
            let mut targets = to_set(&["192.0.2.0/24"], None, None).expect("a range");
            ScanPhase::from_parts(PhaseParts {
                kind,
                started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_000_000),
                elapsed: Duration::from_secs(1),
                privileged: true,
                targets: TargetScope::from_ip_set(&mut targets, &Exclusions::none()),
                settings: ScanSettings::from(&ZondConfig::default()),
                failures: Vec::new(),
                unroutable: Vec::new(),
                probes: Vec::new(),
            })
        };

        let swept = ScanReport::recorded("test", vec![phase(ScanKind::Discovery)], vec![host(1)]);
        let scanned = ScanReport::recorded(
            "test",
            vec![phase(ScanKind::Discovery), phase(ScanKind::PortScan)],
            vec![host(1)],
        );

        let mut out = Capture::default();
        comparing("a", "b", &ScanDiff::between(&swept, &scanned), &mut out)
            .expect("a capture never fails");
        assert!(
            out.text().contains("only the later scan looked at ports"),
            "{}",
            out.text()
        );

        // The other way round names the other one.
        let mut out = Capture::default();
        comparing("a", "b", &ScanDiff::between(&scanned, &swept), &mut out)
            .expect("a capture never fails");
        assert!(
            out.text().contains("only the earlier scan looked at ports"),
            "{}",
            out.text()
        );

        // And two of a kind say nothing.
        let mut out = Capture::default();
        comparing("a", "b", &ScanDiff::between(&swept, &swept), &mut out)
            .expect("a capture never fails");
        assert!(!out.text().contains("note:"), "{}", out.text());
    }

    /// A set member that went says so once. "lost 2a02:… , now none" reads as
    /// a mistake, and a real segment produced exactly that line.
    #[test]
    fn a_set_member_that_went_is_not_also_said_to_be_none() {
        let lost = ChangeDto {
            kind: "address_lost",
            before: Some("2a02:908:8c1:b880::b99a".to_string()),
            after: None,
        };
        assert_eq!(sentence(&lost), "lost 2a02:908:8c1:b880::b99a");

        // A field that genuinely emptied still says so.
        let emptied = ChangeDto {
            kind: "vendor",
            before: Some("Arris Group, Inc".to_string()),
            after: None,
        };
        assert_eq!(sentence(&emptied), "vendor Arris Group, Inc, now none");
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

    /// A fingerprint is an identity, not a value to read: a block shows enough
    /// of it to tell two apart and no more.
    #[test]
    fn a_block_shortens_a_fingerprint_and_a_pipe_record_does_not() {
        let long = "a".repeat(64);
        let shortened = readable("certificate_rotated", Some(&long)).expect("a value");

        assert!(shortened.ends_with('…'));
        assert!(shortened.chars().count() < 20, "{shortened}");
        assert_eq!(
            readable("service_version", Some(&long)).as_deref(),
            Some(long.as_str()),
            "only a fingerprint is shortened"
        );
    }

    #[test]
    fn a_block_shows_an_expiry_as_a_date() {
        assert_eq!(
            readable("certificate_expiring", Some("2026-09-20T00:00:00.000000Z")).as_deref(),
            Some("2026-09-20")
        );
    }
}

#[cfg(test)]
mod hostile {
    use zond_engine::model::port::{Port, PortState, Protocol, Service};

    use super::tests::scoped;
    use super::*;
    use crate::render::test_support::{Capture, host};

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
        )
        .expect("a capture never fails");

        let text = records.text();
        assert!(
            !text.contains("\n  port:"),
            "a hostname forged a port line: {text}"
        );
    }
}
