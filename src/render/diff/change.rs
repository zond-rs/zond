// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a change is, in words
//!
//! The layer under the three presentations: what a host was, what moved, which
//! ports are worth a line and which are worth a count. Shared for the same
//! reason [`render::field`](crate::render::field) is, because two modes
//! disagreeing about which changes a comparison is entitled to claim would be
//! two different answers to the same pair of scans.
//!
//! Named for what it describes rather than called `field`, because a module
//! that draws a comparison needs both this and the scan's own field layer, and
//! two things called `field` in one file is one too many.

use std::net::IpAddr;

use zond_engine::Host;
use zond_engine::diff::{HostDelta, PortDelta};
use zond_engine::export::ExportOptions;
use zond_engine::export::diff::schema::ChangeDto;

use crate::render::field::{self, FINGERPRINT_SHOWN, Reader};

/// The address to lead this host's record with.
///
/// **For a host both scans hold, an address both scans hold.** The engine keys a
/// delta by the later scan's primary address, which is the right key for a host
/// only one side has and the wrong thing to lead with for a host whose primary
/// moved: the block opens with an address it then reports as *gained*, so a host
/// that merely changed reads as a host that arrived, and the `~` on it looks
/// like a mistake. An address both sides hold is the one that paired the two
/// records in the first place, and leading with it is what makes the mark mean
/// what it says.
///
/// Preference runs: the later scan's primary where the earlier one had it too,
/// so the ordinary host does not move; then the earlier scan's primary, which is
/// the address you knew it by; then the lowest address the two have in common.
/// A host only one scan holds keeps the key, there being nothing to share.
///
/// Rendered through `reader`, so the address carries its zone and is masked
/// under `--redact` exactly as the same address is in a scan.
pub(super) fn identity(host: &HostDelta, reader: Reader) -> String {
    let keyed = host.address();

    match (host.baseline(), host.current()) {
        (Some(before), Some(after)) => {
            reader.address(after, common(before, after).unwrap_or(keyed))
        }
        (Some(only), None) | (None, Some(only)) => reader.address(only, keyed),
        // The engine promises a record on one side. Masked rather than raw, so
        // even a delta that broke that promise cannot leak an address.
        (None, None) => reader.masked(keyed),
    }
}

/// The address these two records have in common, if they have one.
fn common(before: &Host, after: &Host) -> Option<IpAddr> {
    let holds = |host: &Host, ip: IpAddr| host.ips().contains(&ip);

    let later = after.primary_ip();
    if holds(before, later) {
        return Some(later);
    }

    let earlier = before.primary_ip();
    if holds(after, earlier) {
        return Some(earlier);
    }

    // Neither primary is shared, which a regrouped host can manage. Lowest
    // rather than first, so two runs of the same comparison agree.
    after
        .ips()
        .iter()
        .copied()
        .filter(|ip| holds(before, *ip))
        .min()
}

/// A port as `443/tcp`, in the engine's own spelling of the protocol.
pub(super) fn endpoint(port: &PortDelta) -> String {
    format!(
        "{}/{}",
        port.number(),
        zond_engine::export::schema::protocol_name(port.protocol())
    )
}

/// A host's reachability verdict, in the engine's own spelling.
pub(super) fn status(host: &zond_engine::Host) -> String {
    zond_engine::export::schema::host_status_name(host.status()).to_owned()
}

/// A port's verdict, in the engine's own spelling.
///
/// The wire name rather than the reader's, because a comparison's `pipe` records
/// and its JSON document are read by the same script and have to agree.
pub(super) fn state(port: &zond_engine::Port) -> String {
    zond_engine::export::schema::port_state_name(port.state()).to_owned()
}

/// What a host is, where that is more than the bare fact of its being there.
///
/// `None` for a host that is simply up with nothing open. The tag on the header
/// has already said `arrived` or `gone`, and `now up` under it is that said a
/// second time in a second place, which on a comparison of a busy segment is
/// half the lines on the screen.
///
/// A host that was *filtered*, or that arrived with something open, is a
/// different matter: neither is what `arrived` on its own implies.
pub(super) fn beyond_presence(host: &zond_engine::Host) -> Option<String> {
    let said = describe(host);

    (said != "up").then_some(said)
}

/// What a host looked like, in one clause: its status, and how much is open.
pub(super) fn describe(host: &zond_engine::Host) -> String {
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
pub(super) fn unlooked(host: &HostDelta, coverage: zond_engine::diff::Coverage) -> String {
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
/// would have anybody act on, and there can be hundreds of those between two
/// tools whose port lists do not agree.
pub(super) fn is_notable(port: &PortDelta) -> bool {
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
pub(super) fn counted_bulk(ports: &[&PortDelta]) -> Vec<String> {
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
pub(super) fn port_lines(port: &PortDelta, options: &ExportOptions, reader: Reader) -> Vec<String> {
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
            lines.push(format!("{endpoint} {}", sentence(&change, reader)));
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

/// How wide the verb in front of a change is padded.
///
/// The longest of them. A fixed figure rather than one measured from the changes
/// in hand, because a host with one `gained` and a host with one `lost` are two
/// blocks in the same listing and their values should still line up.
const LEAD_WIDTH: usize = "gained".len();

/// One change as a phrase a person reads.
///
/// The shape depends on which of the two sides has a value. Both is a
/// transition, one is an arrival or a departure, and neither is the bare name of
/// what moved.
pub(super) fn sentence(change: &ChangeDto, reader: Reader) -> String {
    let what = label(change.kind);
    let before = readable(change.kind, change.before.as_deref(), reader);
    let after = readable(change.kind, change.after.as_deref(), reader);

    // Some changes read better with no lead-in at all: a hostname or an
    // operating system is its own subject, and "name: router.local ->
    // gateway.local" says everything "name: hostname router.local -> ..." would.
    //
    // A value gained or lost is the exception. With no lead-in, "os: Debian"
    // says the host runs Debian rather than that this scan learned so, and the
    // two are exactly what a comparison exists to keep apart.
    // Padded to the widest verb this list uses, so a `gained` and a `lost` under
    // one label put their addresses in one column rather than two.
    let lead = if what.is_empty() {
        String::new()
    } else {
        format!("{what:<LEAD_WIDTH$} ")
    };

    // A change to one member of a set already says which way it went. "lost
    // 2a02:…" needs no ", now none" after it, and reads as a mistake with one.
    // A finding that appeared or resolved is one-sided the same way: it is a
    // whole claim arriving or going, not a field moving from one value to
    // another, so ", now none" after a resolved one would read as a slip.
    let directional = change.kind.ends_with("_gained")
        || change.kind.ends_with("_lost")
        || change.kind == "finding_appeared"
        || change.kind == "finding_resolved";

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

/// A value as this presentation shows it.
///
/// Three kinds are touched. Two are shortened because the whole value is
/// unreadable rather than because it is long: a fingerprint is an identity
/// nobody reads past the first few characters of, and a certificate's expiry is
/// a date rather than a moment.
///
/// The third is an address, which is **masked**. Every other address this
/// program prints goes through [`field::Reader`], and a gained or lost one
/// arriving as a finished string is the one that does not: a redacted
/// comparison printed in full the host part its own header had just masked.
/// An address the engine already masked does not parse back, so it falls
/// through unchanged rather than being masked twice.
pub(super) fn readable(kind: &str, value: Option<&str>, reader: Reader) -> Option<String> {
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
        "address_gained" | "address_lost" => value
            .parse::<IpAddr>()
            .map_or(value.clone(), |ip| reader.masked(ip)),
        _ => value,
    })
}

/// What a change is called in a block.
pub(super) fn label(kind: &'static str) -> &'static str {
    match kind {
        "status" => "status",
        // Their own subject, so a lead-in would say what the value already says.
        // A hostname and an operating system name themselves; a reassessed
        // finding carries its severity and title on both sides of the arrow.
        "hostname" | "os" | "finding_reassessed" => "",
        "vendor" => "vendor",
        "address_gained" | "mac_gained" => "gained",
        "address_lost" | "mac_lost" => "lost",
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
        // The value already carries the severity and title, as `high: Log4Shell
        // remote code execution`, so the lead-in only has to say which way the
        // claim went. Reassessed reads for itself and takes no lead — it shares
        // the empty arm with `hostname` and `os` above.
        "finding_appeared" => "found",
        "finding_resolved" => "resolved",
        "filtering_gained" => "filtering gained",
        "filtering_lost" => "filtering lost",
        // One IP protocol its stack takes delivery of, or no longer does. The
        // value carries the number, the name and the verdict, so this only names
        // the axis.
        "ip_protocol" => "ip protocol",
        other => other,
    }
}

/// `count` of `phrase`, pluralised on the word that carries the number.
///
/// "host changed" counted twice is "2 hosts changed", not "2 host changeds".
/// [`field::plural`] pluralises a single word, which is every word a scan
/// counts; a comparison counts phrases.
pub(super) fn counted(count: usize, phrase: &str) -> String {
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
pub(super) fn unconfirmed(total: usize, confirmed: usize, word: &str) -> String {
    let counted = counted(total, word);

    match total - confirmed {
        0 => counted,
        unconfirmed => format!("{counted} ({unconfirmed} unconfirmed)"),
    }
}
