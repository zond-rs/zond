// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a host contributes to a row
//!
//! The values, once, for every presentation that shows them. A mode decides
//! *which* fields to print and how to lay them out; none of them decides what a
//! vendor or a round-trip time is.
//!
//! A round-trip time has two spellings. [`rtt_human`] changes unit with the
//! magnitude, giving `1.42ms`, `412.0ms` and `1.24s`, which is what a person
//! reads fastest and what a script cannot parse. [`rtt_millis`] writes a bare
//! `1.420` in a unit that never changes.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use crate::settings::Risk;

use zond_engine::Host;
use zond_engine::export::Redaction;
use zond_engine::model::confidence::Confidence;
use zond_engine::model::finding::{Reference, Severity};
use zond_engine::model::host::EvidenceSource;
use zond_engine::model::host::Filtering;
use zond_engine::model::host::NetworkRole;
use zond_engine::model::host::protocol::{IpProtocolState, ip_protocol_name};
use zond_engine::model::host::status::{StatusProtocol, StatusReason};
use zond_engine::model::ip::scoped::ScopedIp;
use zond_engine::model::ip::set::IpSet;
use zond_engine::model::port::discovery::{Discovery, ScanResponse};
use zond_engine::model::tls::Interruption;
use zond_engine::record::wire;
use zond_engine::report::{ScanKind, ScanPhase};
use zond_engine::system::privilege::Privilege;
use zond_engine::{HostStatus, Port, PortState, Protocol, ScanReport, ScanSummary};

/// What a field shows when the scan did not learn it.
///
/// A visible placeholder rather than a blank, so the field count never moves.
pub(crate) const UNKNOWN: &str = "-";

/// [`UNKNOWN`] as an owned string.
pub(crate) fn unknown() -> String {
    UNKNOWN.to_owned()
}

/// A timestamp as RFC 3339, through the engine's own renderer.
///
/// Borrowed rather than reimplemented so a time reads the same in a listing as
/// in an exported report.
pub(crate) fn timestamp(time: std::time::SystemTime) -> String {
    zond_engine::format::time::rfc3339(time)
}

/// A version with its patch component dropped.
///
/// Everything before the second dot, so `0.14.0` and `0.14.0-rc1` both read
/// `0.14`. A patch release changes neither what a detection does nor what a
/// build finds, so the digit that moves for one is a digit nobody reads on a
/// line that carries it every run.
///
/// The whole version is still written down where it is checked against
/// something: a journal entry records the engine that produced it, and so does
/// every export.
pub(crate) fn major_minor(version: &str) -> &str {
    match version.match_indices('.').nth(1) {
        Some((at, _)) => &version[..at],
        None => version,
    }
}

/// A timestamp in the reader's own timezone, for a line somebody reads.
///
/// The same instant [`timestamp`] gives, in the shape a person reads rather than
/// the shape a machine parses: `2026-08-25 18:21:36 +0200`. Records keep the
/// `T`, the `Z` and the microseconds, because that is what makes two of them
/// comparable; a banner is read once, by somebody who wants to know what time it
/// was where they were standing.
///
/// The offset comes with it. A local time with nothing beside it cannot be lined
/// up against a firewall log or a capture, and a finding nobody can correlate is
/// a finding somebody has to go and get again.
pub(crate) fn moment(time: std::time::SystemTime) -> String {
    zond_engine::format::time::local(time)
}

/// How long ago `time` was, in the largest unit that still says something.
///
/// Relative rather than absolute, because the question a listing answers is
/// "which of these was the one I just ran", and `4m` answers it where
/// `2026-08-23T16:42:07Z` makes the reader do arithmetic.
pub(crate) fn age(time: std::time::SystemTime) -> String {
    let Ok(elapsed) = std::time::SystemTime::now().duration_since(time) else {
        // A clock that went backwards, or a record from a machine whose did.
        return String::from("now");
    };

    let seconds = elapsed.as_secs();
    match seconds {
        0..60 => String::from("now"),
        60..3600 => format!("{}m", seconds / 60),
        3600..86_400 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86_400),
    }
}

/// A length of time, in the largest unit that still says something.
///
/// [`age`]'s ladder, for a duration rather than a moment, and it differs at the
/// bottom rung on purpose. A moment less than a minute old is `now`, because
/// what an age answers is which of these is the recent one. A *span* of less
/// than a minute is not `now` — it is how long something took, and a scan that
/// took six seconds has to be able to say so. So the seconds are kept, in the
/// same two decimals a scan reports its own duration in.
pub(crate) fn span(length: Duration) -> String {
    let seconds = length.as_secs();
    match seconds {
        0..60 => format!("{:.2}s", length.as_secs_f64()),
        60..3600 => format!("{}m", seconds / 60),
        3600..86_400 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86_400),
    }
}

/// `text`, or [`UNKNOWN`] where there is none.
pub(crate) fn or_dash(text: &str) -> &str {
    if text.is_empty() { UNKNOWN } else { text }
}

/// Reads a host's fields under a masking policy.
///
/// Carried rather than passed, because it applies to every field that can
/// identify a device and forgetting it on one of them is the whole failure.
/// Fields that cannot identify anything are free functions below.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Reader {
    redaction: Redaction,
}

impl Reader {
    /// Reading under `redaction`.
    pub(crate) fn new(redaction: Redaction) -> Self {
        Self { redaction }
    }

    /// Every address the host answers at, primary first, comma-joined.
    ///
    /// A dual-stack machine answering at three addresses is one device, and
    /// [`Host`] is shaped around never reporting it as three.
    pub(crate) fn addresses(self, host: &Host) -> String {
        std::iter::once(self.primary(host))
            .chain(self.others(host))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The address to lead with.
    pub(crate) fn primary(self, host: &Host) -> String {
        self.address(host, host.primary_ip())
    }

    /// The addresses other than the primary, one per entry.
    ///
    /// A list rather than a joined string: a host answering at four addresses
    /// gets four lines, and a line per address is what stops the longest of them
    /// running off the right edge.
    ///
    /// **A link-local address the host derived from its own hardware address is
    /// left out**, because the block printed that hardware address two lines
    /// above it and this is the same six octets in another notation. Not a
    /// judgement about relevance but an equality test, and one [`mask`] already
    /// relies on being real. `all` keeps it, which is what `-v` asks for.
    pub(crate) fn other_addresses(self, host: &Host, all: bool) -> Vec<String> {
        let hardware: Vec<[u8; 6]> = if all {
            Vec::new()
        } else {
            host.hardware()
                .map(|hardware| {
                    hardware
                        .macs()
                        .keys()
                        .filter_map(|mac| octets(&mac.to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };

        non_primary(host)
            .filter(|ip| match ip {
                IpAddr::V6(v6) => !hardware.iter().any(|mac| restates(*mac, *v6)),
                IpAddr::V4(_) => true,
            })
            .map(|ip| self.address(host, ip))
            .collect()
    }

    /// The host's name, if a lookup found one.
    pub(crate) fn hostname(self, host: &Host) -> Option<String> {
        host.hostname()
            .map(|name| self.redaction.hostname(name).into_owned())
    }

    /// Every hardware address the host was seen at, most recent first.
    ///
    /// Combined for the same reason the IP addresses are: a device seen at two
    /// of them is one device.
    pub(crate) fn macs(self, host: &Host) -> Option<String> {
        let hardware = host.hardware()?;

        let recent = hardware.most_recent_mac();
        let rest = hardware
            .macs()
            .keys()
            .copied()
            .filter(|mac| Some(*mac) != recent);

        let combined: Vec<String> = recent
            .into_iter()
            .chain(rest)
            .map(|mac| self.redaction.mac(&mac))
            .collect();

        if combined.is_empty() {
            None
        } else {
            Some(combined.join(","))
        }
    }

    /// The non-primary addresses, as text.
    fn others(self, host: &Host) -> impl Iterator<Item = String> + '_ {
        non_primary(host).map(move |ip| self.address(host, ip))
    }

    /// One address, masked if the policy says so and scoped if it needs to be.
    ///
    /// The zone survives masking. It names an interface on *this* machine, not
    /// anything about the target, and without it a link-local address does not
    /// identify a machine at all. That would make a redacted result unreadable
    /// rather than discreet.
    pub(crate) fn address(self, host: &Host, ip: IpAddr) -> String {
        let text = self.masked(ip);

        match host.zone() {
            Some(zone) if ScopedIp::needs_zone(&ip) => format!("{text}%{zone}"),
            _ => text,
        }
    }

    /// One address, masked if the policy says so, with no host to scope it by.
    ///
    /// For an address that arrives on its own rather than as one of a host's:
    /// the gained and lost lists a comparison reports are addresses and nothing
    /// else, so there is no interface table entry to attach.
    ///
    /// **Every address this program prints goes through here or through
    /// [`address`](Self::address).** A second path is a second chance to forget,
    /// and forgetting is how a redacted comparison came to print in full the
    /// host part its own header had just masked.
    pub(crate) fn masked(self, ip: IpAddr) -> String {
        match ip {
            IpAddr::V6(v6) if self.redaction.is_active() => mask(&v6),
            _ => ip.to_string(),
        }
    }
}

/// A host's addresses other than the one it is listed under.
///
/// Free rather than a method on [`Reader`], because which addresses a host has
/// is not a question the masking policy has an opinion about. The policy applies
/// to how each one is written, one step later.
fn non_primary(host: &Host) -> impl Iterator<Item = IpAddr> + '_ {
    let primary = host.primary_ip();
    host.ips().iter().copied().filter(move |ip| *ip != primary)
}

/// Masks an IPv6 address according to what kind of address it is.
///
/// A link-local address derives its host part from the hardware address, so
/// masking the name and the MAC while printing the address in full would hand
/// back the MAC anyway. That is the branch that matters, and it keeps the two
/// segments that say which link the address is on.
///
/// Everything else keeps its first segment and loses the rest, which is enough
/// to say `2a02:` or `fd12:` without saying which site or which machine.
///
/// This program's own, and deliberately not the engine's. [`Redaction`] masks a
/// hostname and a hardware address and leaves addresses alone on purpose: a
/// report is a list of hosts, and one that hides which host is which is not a
/// report. A terminal draws a *scan*, where the address is already in the
/// header and the reader is watching it happen, so masking the host part of a
/// v6 address costs nothing there and closes the EUI-64 leak the engine's own
/// documentation names.
fn mask(ip: &Ipv6Addr) -> String {
    let segments = ip.segments();

    if segments[0] & 0xffc0 == 0xfe80 {
        format!(
            "{:x}::{:x}:{:x}:XXXX:XXXX",
            segments[0], segments[4], segments[5]
        )
    } else {
        format!("{:x}::XXXX", segments[0])
    }
}

/// The reachability verdict, in the engine's own spelling.
pub(crate) fn status(host: &Host) -> String {
    host.status().to_string()
}

/// Whether the host answered for itself, which is what most rows in a discovery
/// listing say.
pub(crate) fn is_up(host: &Host) -> bool {
    host.status() == HostStatus::Up
}

/// What proved the host alive, as protocol names.
///
/// Sorted because the engine holds reasons in a `HashSet`, whose order differs
/// between processes; deduplicated because two reasons can name one protocol.
fn protocol_names(host: &Host) -> Vec<String> {
    let mut names: Vec<String> = host
        .reasons()
        .iter()
        .map(|reason| protocol_name(&reason.protocol))
        .collect();

    names.sort_unstable();
    names.dedup();
    names
}

/// What proved the host alive, comma-joined without spaces, for a program.
pub(crate) fn evidence(host: &Host) -> Option<String> {
    let names = protocol_names(host);
    (!names.is_empty()).then(|| names.join(","))
}

/// What proved the host alive, for a reader.
///
/// The same names with a space after each comma. A tab-separated record cannot
/// afford one: the field would still parse, but the value would carry
/// whitespace a consumer did not ask for. A line somebody reads wants it.
pub(crate) fn via(host: &Host) -> Option<String> {
    let names = protocol_names(host);
    (!names.is_empty()).then(|| names.join(", "))
}

/// A protocol's name for the evidence field.
///
/// `StatusProtocol` is `#[non_exhaustive]`, so the fallback derives a name from
/// the variant rather than mapping every unknown to one "other".
fn protocol_name(protocol: &StatusProtocol) -> String {
    match protocol {
        StatusProtocol::Arp => "arp".to_owned(),
        StatusProtocol::Ndp => "ndp".to_owned(),
        StatusProtocol::IcmpEcho => "icmp_echo".to_owned(),
        StatusProtocol::IcmpUnreachable => "icmp_unreachable".to_owned(),
        StatusProtocol::TcpSyn => "tcp_syn".to_owned(),
        StatusProtocol::Tcp => "tcp".to_owned(),
        StatusProtocol::Dhcp => "dhcp".to_owned(),
        StatusProtocol::Udp => "udp".to_owned(),
        StatusProtocol::Custom(name) => name.to_lowercase(),
        other => format!("{other:?}").to_lowercase(),
    }
}

/// What the operating-system finding was read off.
///
/// The stack shape of each reply that contributed. Where the host was asked more
/// than once it also carries what its series of replies turned out to be: `id=`
/// the IP identifier policy, `isn=` the sequence generator, `ts=` the timestamp
/// clock. Those three are the features a rule naming a *release* rather than a
/// family predicates on, and they are only readable across several replies, so
/// they appear only after an active scan.
///
/// Distinct from [`evidence`], which says what proved the host *alive*. Both
/// are evidence; they are evidence for different claims.
///
/// It carries stack features and no address or name, so it is not subject to
/// redaction the way [`Reader`]'s fields are.
pub(crate) fn os_evidence(host: &Host) -> Option<String> {
    host.os()
        .and_then(|os| os.evidence())
        .map(ToOwned::to_owned)
}

/// Who made the hardware, from the address it was seen at.
pub(crate) fn vendor(host: &Host) -> Option<&str> {
    host.vendor()
}

/// What the host appears to be running.
///
/// Passive by default, which means every signal in it was already in a reply
/// the sweep drew for another reason. Absent for most hosts in most scans.
pub(crate) fn os(host: &Host) -> Option<String> {
    host.os().map(ToString::to_string)
}

/// What the round trips came to, for a person.
///
/// One figure when there is no spread to show. Where there is one it is worth
/// reading: a host whose fastest reply is 8ms and slowest 1.2s is not 8ms away,
/// it answered once quickly and then made the scan wait. No median, because
/// three figures already describe the spread and [`rtt_millis`] carries it
/// anyway.
///
/// Whether there is a spread is decided on the figures rather than on the
/// durations behind them, for the reason [`rtt_variation`] gives.
pub(crate) fn rtt_human(host: &Host) -> Option<String> {
    let median = host.median_rtt()?;
    let (Some(min), Some(max), Some(mean)) = (host.min_rtt(), host.max_rtt(), host.average_rtt())
    else {
        return Some(format_rtt(median));
    };

    let (low, middle, high) = (format_rtt(min), format_rtt(mean), format_rtt(max));

    if low == middle && middle == high {
        return Some(format_rtt(median));
    }

    Some(format!("min {low}  avg {middle}  max {high}"))
}

/// What the round trips came to, as the line a block gives them.
///
/// Three figures where they disagreed and one where they did not: `min/avg/max`
/// is worth the width only when the three differ, and a host that answered every
/// probe in the same time has said everything with one number.
///
/// Named by the probe that measured it, where the samples agree on one. A block
/// draws this beside a port's own round trip, and the two measure different
/// distances to the same machine: an ARP reply comes off the link layer, a
/// SYN/ACK crosses the target's IP and TCP stacks, and a printer that answers
/// one in 0.09 ms and the other in 0.22 ms is not contradicting itself. The port
/// says which packet it timed, and until this the host did not.
pub(crate) fn latency(host: &Host) -> Option<String> {
    let figures = rtt_variation(host).or_else(|| host.median_rtt().map(format_rtt))?;

    Some(match host.rtt_protocol() {
        Some(protocol) => format!("{figures} via {}", spoken(&protocol)),
        None => figures,
    })
}

/// What the round trips did apart from the fastest, where they did anything.
///
/// `min/avg/max  1.10 / 1.51 / 2.03 ms`, which is the vocabulary somebody
/// reading a scanner already has from `ping`, with one unit for all three
/// figures so they compare against each other directly. The unit is taken from
/// the slowest.
///
/// `None` when the round trips agree, because then the fastest already said it
/// and three copies of one number say it three times. That is the ordinary case,
/// which is what keeps this out of the way until it means something: a host
/// whose fastest reply is 8 ms and slowest 1.2 s is not 8 ms away, and this is
/// the line that says so.
///
/// Agreement is judged on the three figures, not on the durations they came
/// from. Two round trips that differ by a few microseconds are not the same
/// duration and are the same figure at this precision, and a row reading
/// `6.96 / 6.96 / 6.96 ms` claims a spread while displaying none. What a reader
/// can see is what decides.
pub(crate) fn rtt_variation(host: &Host) -> Option<String> {
    let (min, max, mean) = (host.min_rtt()?, host.max_rtt()?, host.average_rtt()?);

    let (divisor, unit) = if max.as_secs_f64() >= 1.0 {
        (1.0, "s")
    } else {
        (0.001, "ms")
    };
    let figure = |rtt: Duration| format!("{:.2}", rtt.as_secs_f64() / divisor);
    let (low, middle, high) = (figure(min), figure(mean), figure(max));

    if low == middle && middle == high {
        return None;
    }

    Some(format!("min/avg/max  {low} / {middle} / {high} {unit}"))
}

/// What a scan established this host *does*, in the engine's own order.
///
/// A `HashSet` iterates in whatever order its hashing produced, so two runs that
/// found the same roles would print them differently. Filtering
/// [`NetworkRole::ALL`] rather than sorting the set is also what keeps this
/// honest as the engine grows: the enum is `#[non_exhaustive]`, so a list
/// written here would silently drop a role added there.
fn ordered(host: &Host) -> impl Iterator<Item = NetworkRole> + '_ {
    NetworkRole::ALL
        .into_iter()
        .filter(|role| host.network_roles().contains(role))
}

/// The roles, spelled for a reader.
///
/// [`NetworkRole::label`] is the engine's own person-facing spelling, and this
/// crate does not invent a second one. The model documents that label as the
/// thing to reword when it reads better, and a copy here would be a place that
/// rewording fails to reach.
pub(crate) fn roles(host: &Host) -> Option<String> {
    let spoken: Vec<&str> = ordered(host).map(NetworkRole::label).collect();

    (!spoken.is_empty()).then(|| spoken.join("  "))
}

/// The same, in the abbreviated tags `minimal` writes.
pub(crate) fn role_tags(host: &Host) -> Option<String> {
    let names: Vec<&str> = ordered(host).map(wire::network_role_name).collect();

    (!names.is_empty()).then(|| names.join(", "))
}

/// The same again, joined the way a `pipe` field is.
///
/// [`wire::network_role_name`] rather than [`NetworkRole::label`], and that is
/// the whole point of there being two: a record and a `pipe` record are read by
/// the same script, so they must agree on the spelling, and the reader's form is
/// free to change without breaking it.
pub(crate) fn packed_roles(host: &Host) -> Option<String> {
    let names: Vec<&str> = ordered(host).map(wire::network_role_name).collect();

    (!names.is_empty()).then(|| names.join(","))
}

/// What the scan concluded is standing between it and this host, if anything.
///
/// A characterisation pass, or the stateless-filter probe, marks the filter in
/// front of a host: a middlebox answering on its behalf, a stateful filter that
/// passes an ACK but drops a SYN. Reported in the engine's declared order so two
/// runs agree, and spelled for a person rather than in the underscored form a
/// record carries. `None` where nothing was concluded, which is every host on a
/// scan that did not ask.
pub(crate) fn filtering(host: &Host) -> Option<String> {
    let conclusions = host.filtering();
    if conclusions.is_empty() {
        return None;
    }

    // Through the engine's declared order rather than the set's own, which is a
    // `HashSet` and would draw in whatever order it hashed to.
    let spoken: Vec<&str> = Filtering::ALL
        .iter()
        .filter(|conclusion| conclusions.contains(conclusion))
        .map(|conclusion| spoken_filtering(*conclusion))
        .collect();

    (!spoken.is_empty()).then(|| spoken.join("  "))
}

/// One filtering conclusion as a person reads it.
///
/// The wire spells these `stateful_filter`; this is the same list as words. A
/// conclusion a newer engine draws and this build has no phrase for falls back
/// to the wire name rather than being dropped, so a scan never loses a
/// conclusion to a build that is merely behind.
fn spoken_filtering(conclusion: Filtering) -> &'static str {
    match conclusion {
        Filtering::InlineMiddlebox => "inline middlebox",
        Filtering::StatefulFilter => "stateful filter",
        Filtering::PortTrustingAcl => "port-trusting ACL",
        Filtering::StatelessFilter => "stateless filter",
        other => wire::filtering_name(other),
    }
}

/// Which IP protocols a host's stack takes delivery of, one line each.
///
/// From `--ip-protocols`: a datagram per protocol, and what came back. Each line
/// is the number, the protocol's name where this build knows one, and the
/// verdict — `accepted`, `filtered`, `open|filtered`. Ordered by number, so two
/// runs draw the same list. Empty where none were asked.
pub(crate) fn ip_protocols(host: &Host) -> Vec<String> {
    host.ip_protocols()
        .iter()
        .map(|(number, state)| {
            let verdict = spoken_ip_protocol_state(*state);
            match ip_protocol_name(*number) {
                Some(name) => format!("{number} {name}  {verdict}"),
                None => format!("{number}  {verdict}"),
            }
        })
        .collect()
}

/// One IP-protocol verdict as a person reads it.
///
/// The states mirror a port's, and read as one: a stack that answered accepts
/// the protocol, one that sent an unreachable does not, and silence is the same
/// open-or-filtered ambiguity a UDP port has. A state a newer engine records and
/// this build has no word for falls back to the wire spelling.
fn spoken_ip_protocol_state(state: IpProtocolState) -> &'static str {
    match state {
        IpProtocolState::Open => "accepted",
        IpProtocolState::Closed => "not accepted",
        IpProtocolState::Filtered => "filtered",
        IpProtocolState::OpenFiltered => "open|filtered",
        IpProtocolState::Unasked => "not asked",
        other => wire::ip_protocol_state_name(other),
    }
}

/// What proved the host alive, in the casing the protocols are written in.
///
/// `ARP, NDP, ICMP echo`. These are protocol names, and a protocol name is an
/// acronym rather than a word. [`via`] spells the same list in the lower case
/// `minimal`'s register wants, and [`evidence`] in the underscored form a script
/// matches on. None of the three may be derived from another, because the
/// spelling is the part that differs.
pub(crate) fn answered(host: &Host) -> Option<String> {
    let names: Vec<String> = host
        .reasons()
        .iter()
        .map(|reason| spoken(&reason.protocol))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    (!names.is_empty()).then(|| names.join("  "))
}

/// What proved the host alive, one line per piece of evidence.
///
/// [`answered`]'s long form, for `--reason`. The short one names the protocols
/// and stops, which is the right summary and drops the two things that qualify
/// it: what was actually observed, and who said so.
///
/// **Who said so is the one that changes a finding.** An ICMP unreachable from
/// the host itself proves the host is there. The same message from a router
/// proves only that something in the path speaks for that address — a NAT
/// answering on a machine's behalf reads identically to the machine answering,
/// and reporting them the same way is how a scan claims a host that is not
/// there. The engine keeps the distinction; until now nothing showed it.
///
/// Addresses go through `reader`, because a source address identifies a machine
/// as surely as the host's own does and redaction that stopped at the header
/// would not be redaction.
pub(crate) fn answered_in_detail(reader: Reader, host: &Host) -> Vec<String> {
    // Where nothing is qualified, the long form *is* the short form with line
    // breaks in it. A local sweep records every reason through
    // `StatusReason::basic`, which carries neither details nor a source, so
    // `--reason` on one turned `ARP  DHCP  ICMP_echo  NDP` into four lines
    // saying the same four words. A flag that costs four lines has to buy
    // something with them.
    if !host
        .reasons()
        .iter()
        .any(|reason| reason.details.is_some() || reason.source != EvidenceSource::Host)
    {
        return answered(host).into_iter().collect();
    }

    let mut lines: Vec<String> = host
        .reasons()
        .iter()
        .map(|reason| detailed_reason(reader, reason))
        .collect();

    // Sorted for the reason [`answered`] sorts: the engine holds these in a
    // `HashSet`, whose order differs between processes, and a listing that
    // reorders itself between two runs of the same scan cannot be compared.
    lines.sort_unstable();
    lines
}

/// One piece of evidence: the protocol, what was seen, and who sent it.
fn detailed_reason(reader: Reader, reason: &StatusReason) -> String {
    let mut line = spoken(&reason.protocol);

    if let Some(details) = reason.details.as_deref() {
        line.push_str("  ");
        line.push_str(details);
    }

    // `via`, not `from`: the address did not send the finding, it sent an error
    // *about* the finding, and the two readings are the whole reason this field
    // is kept apart from the host's own address. A sender the scan's exclusions
    // forbid naming is still second-hand evidence, and says so as a traced
    // path's withheld router does.
    match reason.source {
        EvidenceSource::Host => {}
        EvidenceSource::Intermediary(source) => {
            line.push_str("  via ");
            line.push_str(&reader.masked(source));
        }
        EvidenceSource::Withheld => line.push_str("  via excluded"),
    }

    line
}

/// A protocol as it is written down.
///
/// The family in capitals and whatever qualifies it in lower case, because
/// `ICMP_UNREACHABLE` is a shout and `ICMP_echo` is the name of a thing. The
/// same rule [`NetworkRole::label`] follows: an acronym shouts and a word does
/// not, and `SYN` is one of the former.
///
/// **The qualifier is joined with an underscore, not a space.** A drawn block
/// separates one value from the next with two spaces, so a value containing a
/// space of its own is a value whose edges a reader has to work out: `ARP
/// ICMP echo NDP` is three things or four depending on how hard you look.
/// Joining the parts makes each protocol a single unbroken token, and then two
/// spaces mean exactly one thing wherever they appear.
///
/// Not derivable from [`protocol_name`], which spells the same list in lower
/// case for a script. Going from `icmp_echo` back to `ICMP_echo` needs to know
/// which half is the acronym, which is a judgement rather than a transformation.
/// That is the same reason a role carries two spellings.
fn spoken(protocol: &StatusProtocol) -> String {
    match protocol {
        StatusProtocol::Arp => "ARP".to_owned(),
        StatusProtocol::Ndp => "NDP".to_owned(),
        StatusProtocol::IcmpEcho => "ICMP_echo".to_owned(),
        StatusProtocol::IcmpUnreachable => "ICMP_unreachable".to_owned(),
        StatusProtocol::TcpSyn => "TCP_SYN".to_owned(),
        StatusProtocol::Tcp => "TCP".to_owned(),
        StatusProtocol::Dhcp => "DHCP".to_owned(),
        StatusProtocol::Udp => "UDP".to_owned(),
        StatusProtocol::Custom(name) => joined(&name.to_uppercase()),
        other => joined(&format!("{other:?}").to_uppercase()),
    }
}

/// A name a host or a newer engine chose, made into one token.
///
/// Whitespace inside a value drawn into a two-space-separated list is the one
/// thing that can make the list ambiguous, and this is the branch where the
/// value did not come from the table above.
fn joined(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join("_")
}

/// The median in milliseconds, with no unit, for a program.
///
/// Fixed unit and fixed precision. [`rtt_human`] changes units with the
/// magnitude and collapses when there is no spread, both of which are right for
/// reading and impossible to parse.
pub(crate) fn rtt_millis(host: &Host) -> Option<String> {
    millis(host.median_rtt())
}

/// The fastest round trip, in milliseconds.
pub(crate) fn rtt_min_millis(host: &Host) -> Option<String> {
    millis(host.min_rtt())
}

/// The mean round trip, in milliseconds.
pub(crate) fn rtt_mean_millis(host: &Host) -> Option<String> {
    millis(host.average_rtt())
}

/// The slowest round trip, in milliseconds.
pub(crate) fn rtt_max_millis(host: &Host) -> Option<String> {
    millis(host.max_rtt())
}

/// A duration as bare milliseconds.
fn millis(rtt: Option<Duration>) -> Option<String> {
    rtt.map(|rtt| format!("{:.3}", rtt.as_secs_f64() * 1000.0))
}

/// A round-trip time at a precision that says something.
///
/// `1.423571ms` claims a precision no scan has. Sub-millisecond times keep two
/// decimals so a switched LAN does not read as a column of `0.0ms`.
fn format_rtt(rtt: Duration) -> String {
    let millis = rtt.as_secs_f64() * 1000.0;

    if millis >= 1000.0 {
        format!("{:.2}s", millis / 1000.0)
    } else if millis >= 10.0 {
        format!("{millis:.1}ms")
    } else {
        format!("{millis:.2}ms")
    }
}

/// The engine's sentinel for a port whose service it could not name.
///
/// Not a name, and not printed: most ports have no registered service.
const NO_SERVICE: &str = "???";

/// Whether a port's verdict is worth a line of its own.
///
/// The most filtered ports listed one per line before the rest are counted.
///
/// Enough that an ordinary firewall policy, meaning a handful of refused
/// services, still reads in full. Few enough that a host refusing everything
/// does not bury the open ports that are the actual result.
const MAX_LISTED_FILTERED: usize = 12;

/// The most unasked ports listed one per line before the rest are counted.
/// Fewer than [`MAX_LISTED_FILTERED`]: which ports went unasked is arbitrary per
/// run, so the count is the finding and the numbers stay in the report.
const MAX_LISTED_UNASKED: usize = 6;

/// One line per router on the way to this host, nearest first.
///
/// Empty when no trace ran, which is every scan that did not ask for one.
///
/// A router that would not identify itself is shown as `*` at its own distance
/// rather than left out. Dropping it would renumber every router past it, and a
/// path that silently closes its gaps reads as a shorter path than the one
/// measured. That is the one way this output could mislead somebody drawing a
/// topology from it.
///
/// A router that did identify itself, from an address the scan's exclusions
/// forbid it to report, is shown as `excluded` at its distance, for the same
/// reason and one more: a `*` there would say nothing answered, and something
/// did.
///
/// A hop taken from another host's trace says so. It is a claim about a router
/// this host's own probes never met.
pub(crate) fn path(reader: Reader, host: &Host) -> Vec<String> {
    hops(reader, host)
        .into_iter()
        .map(|hop| match hop.detail {
            Some(detail) => format!("{}. {} ({detail})", hop.step, hop.address),
            None => format!("{}. {}", hop.step, hop.address),
        })
        .collect()
}

/// One router on the way, kept in parts.
///
/// What [`path`] returns is finished text; a presentation that colours an
/// address needs to know which part of the line is one. Both are built from
/// [`hops`], so the two cannot disagree about what the path was.
///
/// Named apart from the engine's own
/// [`Hop`](zond_engine::model::host::path::Hop), which is the measurement. This
/// is that measurement already split into the pieces a line is drawn from.
pub(crate) struct TracedHop {
    /// The distance from here, padded so the addresses line up under each other.
    ///
    /// A bare number, because in a drawn block it is furniture in the same way
    /// the handle opening the block is, and that one lost its brackets. The
    /// period belongs to [`path`], whose entries are a sentence rather than a
    /// column, and which adds it back.
    pub step: String,
    /// The router, `excluded` where the scan may not name it, or `*` where it
    /// would not identify itself.
    pub address: String,
    /// The round trip, and whether the hop was taken from another host's trace.
    pub detail: Option<String>,
}

/// One entry per router on the way to this host, nearest first.
///
/// Empty when no trace ran, which is every scan that did not ask for one.
///
/// A router that would not identify itself is shown as `*` at its own distance
/// rather than left out, and one the scan may not name as `excluded`, for the
/// reasons [`path`] gives.
pub(crate) fn hops(reader: Reader, host: &Host) -> Vec<TracedHop> {
    let hops = host.path().hops();

    // Wide enough for the furthest distance and no wider, so the addresses line
    // up under each other without a column of blanks on the ordinary path that
    // never reaches ten.
    //
    // Left-aligned, unlike the handle that opens a block. That one is
    // right-aligned because nothing precedes it, so its padding is free. This
    // number *starts* a value, and padding in front of one puts it a column
    // right of every other value in the block. See
    // `a_path_aligns_its_addresses_without_indenting_the_value`. The addresses
    // still line up, which is what the width is for.
    let width = hops
        .last()
        .map_or(1, |hop| hop.distance().to_string().len());

    hops.iter()
        .map(|hop| {
            let address = match hop.address() {
                // Masked like any other address under redaction, and without a
                // zone: a router is not this host, so this host's interface says
                // nothing about where the router's address is valid.
                Some(IpAddr::V6(v6)) if reader.redaction.is_active() => mask(&v6),
                Some(address) => address.to_string(),
                None if hop.is_withheld() => "excluded".to_string(),
                None => "*".to_string(),
            };

            let mut detail = Vec::new();
            if let Some(rtt) = hop.rtt() {
                detail.push(format_rtt(rtt));
            }
            if hop.inferred() {
                detail.push("inferred".to_string());
            }

            TracedHop {
                step: format!("{:<width$}", hop.distance()),
                address,
                detail: (!detail.is_empty()).then(|| detail.join(", ")),
            }
        })
        .collect()
}

/// Everything except plainly closed, which is counted instead of enumerated.
fn notable(state: PortState) -> bool {
    state != PortState::Closed
}

/// How close something is to being a problem.
///
/// Carried beside the words rather than baked into them, so a renderer holding a
/// palette can colour the phrase and one without a palette prints it unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Urgency {
    /// Nothing to flag.
    #[default]
    None,
    /// Ranked, and ranked below the grade worth looking at.
    ///
    /// Apart from [`None`](Urgency::None), which is the absence of a ranking
    /// rather than the bottom of one: a certificate with years left carries no
    /// urgency at all, and a finding graded `LOW` carries the lowest there is.
    /// Drawing the two alike is what made a severity column stop being a column
    /// of colour at exactly the grade where it should have been receding.
    Muted,
    /// Approaching a deadline.
    Caution,
    /// Past it.
    Alarm,
}

/// A fact hanging off a port: what was learned about the transport under the
/// service, rather than about the service itself.
///
/// A label and a value, because that is what every other fact in a block is.
/// `tls  1.3  X25519` reads the way `hardware  00:00:5e:00:53:01` does, one
/// level in, and the reader has one shape to learn rather than two. The note is
/// split off so the colouring does not have to find the interesting phrase by
/// searching a finished sentence for it.
///
/// Named apart from [`block::Detail`](crate::render::block::Detail), which is
/// the drawn line. This is what a port contributes to one, and a presentation
/// turns the first into the second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortDetail {
    /// What the value is.
    pub label: &'static str,
    /// The value.
    pub value: String,
    /// The part whose colour says something, where there is one.
    pub note: Option<String>,
    /// How that part should read.
    pub urgency: Urgency,
}

impl PortDetail {
    /// A detail with nothing to flag.
    fn new(label: &'static str, value: String) -> Self {
        Self {
            label,
            value,
            note: None,
            urgency: Urgency::None,
        }
    }
}

/// The packet that settled a port's state, and what it carried.
///
/// The claim under every verdict, and until `--reason` there was no way to see
/// it: a port reported `filtered` because a firewall said so and one reported
/// `filtered` because nothing came back are the same word and different
/// findings. `ICMP prohibited` is somebody's policy; `no reply` is an absence,
/// and an absence is only as good as the scan that waited for it.
///
/// `None` for a port carrying no telemetry, which is what a report from a
/// scanner that recorded none reads as. Nothing is invented to fill the line.
///
/// What the telemetry has, and only what it has. A raw scan records the packet,
/// the round trip and the hop counter the reply arrived under; a connect scan
/// records the packet alone, having no header to read. A line that named a
/// field the scan never filled would be the one way to make this lie, so each
/// is shown when present and omitted when not.
///
/// The reply's sender, the source address its IP header carried, is the one
/// field left off. No scanner records it, so it arrives only on a port read
/// back from a document that carries one. A sender identifies a machine as
/// surely as the host's own address does, so drawing it needs the redaction
/// [`Reader`] the host's evidence goes through, which this line does not hold.
///
/// The hop counter is worth its place beside the verdict rather than only on the
/// host: it is the initial value less the distance travelled, so a reply whose
/// count disagrees with the host's others did not come from where the others
/// did — which is how a middlebox answering on a host's behalf is caught.
fn reason_detail(port: &Port) -> Option<PortDetail> {
    let discovery = port.discovery()?;

    let mut evidence = vec![spoken_response(discovery.reason())];
    if let Some(ttl) = discovery.ttl() {
        evidence.push(format!("ttl {ttl}"));
    }
    if let Some(rtt) = discovery.rtt() {
        evidence.push(format_rtt(rtt));
    }

    Some(PortDetail::new("reason", evidence.join("  ")))
}

/// A scan response as it is written for a person.
///
/// The rule [`spoken`] follows, for the other half of the evidence: the flags a
/// segment carried are an acronym and shout, and what did not happen is a word
/// and does not. Underscores are [`spoken`]'s answer to a value drawn into a
/// two-space-separated list, and this is not drawn into one — it is a value of
/// its own, beside a label — so the words stay words.
///
/// Deliberately not
/// [`scan_response_name`](zond_engine::record::wire::scan_response_name), which
/// spells the same list as `tcp_syn_ack` for a document. Neither is derivable
/// from the other, and the spelling is the part that differs.
fn spoken_response(response: &ScanResponse) -> String {
    match response {
        ScanResponse::TcpSynAck => "SYN/ACK".to_owned(),
        ScanResponse::TcpRst => "RST".to_owned(),
        ScanResponse::UdpResponse => "UDP reply".to_owned(),
        ScanResponse::NoResponse => "no reply".to_owned(),
        ScanResponse::IcmpUnreachable => "ICMP unreachable".to_owned(),
        ScanResponse::IcmpProhibited => "ICMP prohibited".to_owned(),
        ScanResponse::Custom(name) => name.clone(),
        // A response a newer engine records and this build has no word for.
        // Spelled as the wire spells it, which is the only name this build has:
        // inventing prose for a variant whose meaning it does not know would be
        // the one way to make this line lie.
        other => wire::scan_response_name(other).into_owned(),
    }
}

/// One port worth a line, with its columns padded and anything hanging off it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortRow {
    /// `443/tcp`, padded so every state in the listing starts in one column.
    pub port: String,
    /// `open`, padded likewise.
    pub state: String,
    /// The verdict unformatted, so a renderer can colour it without matching on
    /// the word it was spelled as.
    pub verdict: PortState,
    /// `https`, padded likewise: what kind of thing this port is, and nothing
    /// about what answered on it.
    pub service: Option<String>,
    /// Whether that name was looked up from the port number rather than
    /// established by a probe.
    ///
    /// The engine knows the difference and this used to throw it away, drawing a
    /// guess in the same ink as a fingerprint. See `Service::is_inferred`.
    pub inferred: bool,
    /// `nginx 1.24`, where something identified itself. Unpadded: nothing
    /// follows it.
    pub product: Option<String>,
    /// TLS and certificate lines belonging to this port and to no other.
    pub detail: Vec<PortDetail>,
}

/// What a listing shows beyond the hosts, ports and findings themselves.
///
/// Four axes, separate because a reader wants them separately, and each off
/// until asked for. The working behind a certificate is for somebody auditing a
/// TLS configuration; the packet behind a verdict is for somebody deciding
/// whether to believe the verdict at all; what a detection saw is for somebody
/// deciding whether to believe a finding; and what to do about one is for
/// somebody who has already believed it and is acting.
///
/// The two about findings are separate flags from the two about ports for the
/// same reason the two about ports are separate from each other: somebody
/// triaging findings does not want every port's packet, and somebody auditing a
/// firewall does not want a detection's bytes.
///
/// Named for what it is rather than for evidence, which three of the four are
/// and the last is the opposite of.
//
// Four axes a run sets in any combination, which is what the bool-heavy-struct
// lint counts: folding them into an enum would make the combinations
// unrepresentable, and they are the point.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Showing {
    /// Who issued a certificate, what key it carries, what it fingerprints to.
    /// From `-v`.
    pub(crate) certificates: bool,
    /// The packet that settled each port's state, and what it carried. From
    /// `--reason`.
    pub(crate) reasons: bool,
    /// What the detection behind a finding actually saw. From `--evidence`.
    pub(crate) excerpts: bool,
    /// What to do about a finding. From `--remedy`.
    pub(crate) remedies: bool,
    /// The lowest grade of finding a listing draws. From `--risk`, or `risk` in
    /// `cli.toml`.
    ///
    /// Apart from the four beside it in kind: those are switches and this is a
    /// floor. What it governs stays on the page either way, since a host says
    /// how many findings it has whatever this is set to.
    pub(crate) risk: Risk,
}

/// The ports worth a line, and the notes about what was left out.
///
/// The notes are the renderer talking rather than the scan: counts of the ports
/// this listing decided not to enumerate, and why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PortListing {
    /// One entry per port shown.
    pub rows: Vec<PortRow>,
    /// What was left out, already phrased.
    pub notes: Vec<String>,
}

/// Which ports a listing shows, and what it says about the rest.
///
/// The selection rules live here, once, because they are the part that carries
/// judgement: what a wall of `filtered` means, and what an outrun scan is
/// allowed to claim. Two presentations disagreeing about that would be two
/// different answers to the same scan.
struct Selection<'a> {
    /// The ports to enumerate, in the order they should appear.
    shown: Vec<&'a Port>,
    /// The counts of what was not enumerated.
    notes: Vec<String>,
}

/// The ports worth showing, or `None` when nothing was probed.
fn select(host: &Host, silence_means_something: bool) -> Option<Selection<'_>> {
    let mut shown: Vec<&Port> = host.ports().filter(|port| notable(port.state())).collect();
    let closed = host.ports().filter(|port| !notable(port.state())).count();

    if shown.is_empty() && closed == 0 {
        return None;
    }

    shown.sort_by_key(|port| (port.state() != PortState::Open, port.number()));

    // A wall of filtered ports says one thing, not six hundred of them.
    //
    // Three filtered ports on a host is a firewall policy worth reading line by
    // line. Six hundred is a different fact entirely: the host is refusing the
    // whole range, or the scan lost its replies. Printing them individually
    // buries the two open ports that are the actual result. Measured, on a
    // consumer router probed too fast: nine hundred lines of `filtered`, with
    // `80/tcp` among them.
    //
    // The first few are kept rather than none, because *which* ports were
    // filtered still matters when the list starts at 22 and 23.
    //
    // A scan that could not tell filtered from lost has no filtered ports to
    // report, only ports it failed to reach. Listing them anyway is what turned
    // a saturated radio into two hundred and forty claims about somebody's
    // firewall. See `silence_means_something`.
    let unreachable = if silence_means_something {
        0
    } else {
        let before = shown.len();
        // Silence goes, an ICMP refusal stays: the pacing that made this scan's
        // quiet unreadable has no bearing on an error that arrived.
        shown.retain(|port| port.state() != PortState::Filtered || refused_in_words(port));
        before - shown.len()
    };

    let filtered_over_limit = elide_beyond(&mut shown, PortState::Filtered, MAX_LISTED_FILTERED);
    let unasked_over_limit = elide_beyond(&mut shown, PortState::Unasked, MAX_LISTED_UNASKED);

    let mut notes = Vec::new();

    // What the table covers, before what is in it. A count of what was left out
    // reads as an apology at the bottom of a list and as scope at the top of
    // one, and it is scope: nine rows mean something different once you know
    // they are nine of a thousand. The brackets go with the move — a faint line
    // standing where a port number would be bold is already how a block marks
    // the renderer's own asides.
    if closed > 0 {
        let probed = host.port_count();
        notes.push(format!("{probed} probed, {closed} closed"));
    }

    if filtered_over_limit > 0 {
        notes.push(format!(
            "{filtered_over_limit} more filtered {} not listed",
            plural(filtered_over_limit as u128, "port")
        ));
    }

    if unasked_over_limit > 0 {
        notes.push(format!(
            "{unasked_over_limit} more unasked {} not listed",
            plural(unasked_over_limit as u128, "port")
        ));
    }

    if unreachable > 0 {
        // Not "could not reach": the probes went out. What did not come back is
        // the answer, and the scan was already losing those, so the one thing
        // this cannot say is what a silent port means.
        notes.push(format!(
            "{unreachable} {} unanswered; the scan was outrun, so silence is not a verdict",
            plural(unreachable as u128, "port")
        ));
    }

    Some(Selection { shown, notes })
}

/// Whether this port's verdict came from an ICMP error rather than from silence,
/// so it survives the suppression an outrun scan applies to quiet ports.
fn refused_in_words(port: &Port) -> bool {
    matches!(
        port.discovery().map(Discovery::reason),
        Some(ScanResponse::IcmpUnreachable | ScanResponse::IcmpProhibited)
    )
}

/// Keeps the first `limit` ports in `state` and drops the rest, returning how
/// many were dropped. One rule for every state that arrives in bulk.
fn elide_beyond(shown: &mut Vec<&Port>, state: PortState, limit: usize) -> usize {
    let over = shown
        .iter()
        .filter(|port| port.state() == state)
        .count()
        .saturating_sub(limit);

    if over > 0 {
        let mut kept = 0usize;
        shown.retain(|port| {
            if port.state() != state {
                return true;
            }
            kept += 1;
            kept <= limit
        });
    }

    over
}

/// How wide the port and state columns have to be for `shown`.
///
/// From what is actually being listed rather than from a guess, so a host with
/// only low ports does not pay for the five-digit case.
fn column_widths(shown: &[&Port]) -> (usize, usize) {
    let port = shown
        .iter()
        .map(|port| format!("{}/{}", port.number(), protocol(port.protocol())).len())
        .max()
        .unwrap_or(0);
    let state = shown
        .iter()
        .map(|port| state(port.state()).len())
        .max()
        .unwrap_or(0);
    (port, state)
}

/// One line per port worth showing, ending with a count of what was left out.
///
/// Open first, then by number. Empty when nothing was probed.
///
/// Laid out in columns, which is the whole reason this builds the parts before
/// formatting any of them: a port number is one to five digits and a state is
/// four to twelve characters, so a line assembled left to right puts every state
/// at a different place and the eye has to search each row instead of running
/// down one.
pub(crate) fn ports(host: &Host, silence_means_something: bool, showing: Showing) -> Vec<String> {
    let Some(selection) = select(host, silence_means_something) else {
        return Vec::new();
    };

    let (widest_port, widest_state) = column_widths(&selection.shown);

    let mut lines: Vec<String> = selection
        .shown
        .iter()
        .map(|port| {
            let line = format!(
                "{:<widest_port$}  {:<widest_state$}  {}",
                format!("{}/{}", port.number(), protocol(port.protocol())),
                state(port.state()),
                describe(port).unwrap_or_default()
            );
            // A port with no service would otherwise carry the padding it was
            // never going to fill.
            let mut line = line.trim_end().to_owned();

            // Appended rather than hung, because this mode has nothing to hang
            // from: `minimal` is one tagged line per value and a second line
            // under a port would be a value with no tag. Bracketed so the
            // evidence reads as qualifying the row rather than extending it.
            if let Some(reason) = showing.reasons.then(|| reason_detail(port)).flatten() {
                line = format!("{line}  [{}]", reason.value);
            }

            // An unfinished TLS walk rides the row the same way, unasked for:
            // it qualifies the `risk` lines drawn from that walk, which are
            // drawn whatever the flags say. The label comes with it, since
            // nothing else on the row says what is unfinished.
            for walk in unfinished_walks(port) {
                line = format!("{line}  [{} {}]", walk.label, walk.value);
            }

            line
        })
        .collect();

    lines.extend(selection.notes);
    lines
}

/// The same ports, kept apart rather than joined into a line.
///
/// What [`ports`] returns is finished text; a presentation that colours a
/// verdict or hangs a certificate off a port needs the pieces. Both are built
/// from one [`select`], so the two modes can never disagree about which ports a
/// scan is entitled to claim.
///
/// `showing` decides what hangs off a row beyond the port itself. Everything
/// else is unconditional.
///
/// # Every host at once, because the columns are between them
///
/// The port and state columns used to be measured from one host's ports, which
/// meant a host whose highest port was `9100/tcp` and one whose highest was
/// `80/tcp` put `open` in different places. [`block`](super::block) says the
/// alignments worth having are the ones *between* blocks, and the port table was
/// the one child that did not get them. So this takes the listing.
pub(crate) fn port_listings(
    hosts: &[&Host],
    silence_means_something: bool,
    showing: Showing,
) -> Vec<PortListing> {
    let selections: Vec<Option<Selection<'_>>> = hosts
        .iter()
        .map(|host| select(host, silence_means_something))
        .collect();

    let (mut widest_port, mut widest_state, mut widest_service) = (0, 0, 0);
    for port in selections
        .iter()
        .flatten()
        .flat_map(|selection| selection.shown.iter())
    {
        widest_port = widest_port.max(endpoint(port).chars().count());
        widest_state = widest_state.max(state(port.state()).chars().count());
        if let Some((name, _)) = service_name(port) {
            widest_service = widest_service.max(name.chars().count());
        }
    }

    selections
        .into_iter()
        .map(|selection| {
            let Some(selection) = selection else {
                return PortListing::default();
            };

            let rows = selection
                .shown
                .iter()
                .map(|port| {
                    let named = service_name(port);
                    PortRow {
                        port: format!("{:<widest_port$}", endpoint(port)),
                        state: format!("{:<widest_state$}", state(port.state())),
                        verdict: port.state(),
                        service: named
                            .as_ref()
                            .map(|(name, _)| format!("{name:<widest_service$}")),
                        inferred: named.is_some_and(|(_, inferred)| inferred),
                        product: product_text(port),
                        detail: port_detail(port, showing),
                    }
                })
                .collect();

            PortListing {
                rows,
                notes: selection.notes,
            }
        })
        .collect()
}

/// `text` broken at whitespace into pieces of at most `room` columns.
///
/// A word longer than `room` — a fingerprint, a cipher name, a URL — takes a line
/// of its own and overruns it rather than being broken in the middle, because a
/// broken identifier is one somebody cannot paste.
///
/// Named apart from [`fold`], which gathers claims into rows: that is the
/// domain's word and this is the typesetter's.
pub(crate) fn wrap(text: &str, room: usize) -> Vec<String> {
    if text.chars().count() <= room {
        return vec![text.to_owned()];
    }

    let mut pieces = Vec::new();
    let mut piece = String::new();

    for word in text.split_whitespace() {
        if !piece.is_empty() && piece.chars().count() + 1 + word.chars().count() > room {
            pieces.push(std::mem::take(&mut piece));
        }
        if !piece.is_empty() {
            piece.push(' ');
        }
        piece.push_str(word);
    }

    if !piece.is_empty() {
        pieces.push(piece);
    }

    pieces
}

/// A port as it is written: `443/tcp`.
fn endpoint(port: &Port) -> String {
    format!("{}/{}", port.number(), protocol(port.protocol()))
}

/// How many findings a host carries, and the worst grade among them.
///
/// `None` where it carries none, so a host with nothing wrong says nothing
/// rather than reporting a zero. Counted over the findings themselves rather
/// than over the rows [`findings`] folds them into, because the line at the
/// bottom of a run counts findings and two numbers for one thing that disagree
/// is worse than either.
pub(crate) fn host_risks(host: &Host) -> Option<(usize, Severity)> {
    let mut count = 0usize;
    let mut worst: Option<Severity> = None;

    for finding in host.findings().chain(host.ports().flat_map(Port::findings)) {
        count += 1;
        worst = Some(worst.map_or(finding.severity(), |held: Severity| {
            held.max(finding.severity())
        }));
    }

    worst.map(|worst| (count, worst))
}

/// How many of a host's ports are open, and how many were probed.
///
/// `None` when nothing was probed, so a discovery sweep says nothing about ports
/// rather than reporting that none of them are open.
pub(crate) fn open_ports(host: &Host) -> Option<(usize, usize)> {
    let probed = host.port_count();
    if probed == 0 {
        return None;
    }

    Some((
        host.ports()
            .filter(|port| port.state() == PortState::Open)
            .count(),
        probed,
    ))
}

/// How much of a certificate fingerprint a listing shows.
///
/// A SHA-256 fingerprint is sixty-four characters and a wall on one line. Twelve
/// is past any accidental collision and short enough to read; the whole of it is
/// one field away in `pipe` and in the JSON document, which is where a program
/// looks anyway.
pub(crate) const FINGERPRINT_SHOWN: usize = 12;

/// How long before a certificate's expiry it is worth saying so.
///
/// Thirty days, which is the window in which somebody can still do something
/// about it. Sooner and the warning is the same as the alarm; later and every
/// certificate in an estate is flagged at all times, which trains a reader to
/// skip the line on the one host where it matters.
const EXPIRY_HORIZON: Duration = Duration::from_secs(30 * 86_400);

/// Everything hanging off one port row, in the order it is drawn.
///
/// The reason first: it is what the row's own verdict rests on, and a reader
/// checking a verdict should not have to read past a certificate to find it.
fn port_detail(port: &Port, showing: Showing) -> Vec<PortDetail> {
    let mut detail = Vec::new();

    if showing.reasons {
        detail.extend(reason_detail(port));
    }
    detail.extend(security_detail(port, showing.certificates));

    detail
}

/// What is known about the transport under a port, as lines that hang off it.
///
/// Empty for every port no handshake or enumeration reached, which is most of
/// them.
fn security_detail(port: &Port, detailed: bool) -> Vec<PortDetail> {
    let Some(security) = port.security() else {
        return Vec::new();
    };

    let mut detail = Vec::new();

    // Version, cipher and protocols on one line: they describe a single
    // negotiated session, and three lines for one handshake would outweigh the
    // port it belongs to. The word "TLS" is not among them, because the label
    // beside them is `tls`.
    //
    // The version is kept apart from the rest as the detail's own value, so that
    // it lands in one column down a listing and the cipher lands in the next —
    // the same two columns a certificate's name and its expiry land in.
    let mut session = Vec::new();
    if let Some(version) = security.tls_version() {
        session.push(version.to_owned());
    }
    if let Some(cipher) = security.cipher_suite() {
        session.push(cipher.to_owned());
    }
    if !security.alpn().is_empty() {
        session.push(format!(
            "alpn {}",
            security
                .alpn()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    if !session.is_empty() {
        let mut session = session.into_iter();
        let version = session.next().unwrap_or_default();
        let rest: Vec<String> = session.collect();

        detail.push(PortDetail {
            note: (!rest.is_empty()).then(|| rest.join("  ")),
            ..PortDetail::new("tls", version)
        });
    }

    // Directly under the negotiated version, so the versions an enumeration
    // could not settle are read beside the one a handshake did rather than
    // past a certificate.
    detail.extend(unfinished_walks(port));

    if let Some(certificate) = security.certificate() {
        let (note, urgency) = expiry(certificate.validity_end());
        detail.push(PortDetail {
            note: Some(note),
            urgency,
            ..PortDetail::new("cert", certificate.common_name().to_owned())
        });

        // The working behind it, for somebody checking the certificate rather
        // than reading past it. Three labelled facts rather than one sentence
        // ninety columns long: each is looked up on its own, and a reader
        // checking a fingerprint is not also reading the issuer.
        if detailed {
            let fingerprint = certificate.fingerprint_sha256();
            detail.push(PortDetail::new("issuer", certificate.issuer().to_owned()));
            detail.push(PortDetail::new(
                "key",
                format!(
                    "{} {}",
                    certificate.pubkey_type(),
                    certificate.pubkey_bits()
                ),
            ));
            detail.push(PortDetail::new(
                "sha256",
                fingerprint[..FINGERPRINT_SHOWN.min(fingerprint.len())].to_owned(),
            ));
        }
    }

    detail
}

/// What a TLS enumeration of this port left unfinished, one line per cause.
///
/// A version's walk finishes when the endpoint declines what is left of the
/// offer. One that ended any other way found a floor or nothing, so what the
/// port's findings say about that version is a floor too, and a version it
/// never settled is neither accepted nor refused. Without this line the first
/// reads as the whole answer and the second as a refusal.
///
/// Grouped by cause, because the cause is what a reader acts on: `unanswered`
/// is the endpoint going quiet, which a slower scan gets past, and `stopped` is
/// this scan's own budget or stop, which a longer one does. The versions are
/// the value and nothing is a note, so a long list of them never moves the
/// column every other port's certificate expiry is drawn in.
///
/// Empty for every port whose walks all finished, and for every port no scan
/// enumerated.
fn unfinished_walks(port: &Port) -> Vec<PortDetail> {
    let Some(security) = port.security() else {
        return Vec::new();
    };
    let unfinished = security.support().unfinished();

    Interruption::ALL
        .into_iter()
        .filter_map(|cause| {
            let versions: Vec<&str> = unfinished
                .iter()
                .filter(|walk| walk.interruption() == cause)
                .map(|walk| walk.version().name())
                .collect();

            (!versions.is_empty()).then(|| {
                PortDetail::new(
                    "suites",
                    format!("{}  unfinished, {cause}", versions.join(" ")),
                )
            })
        })
        .collect()
}

/// One finding worth a line, with its columns padded and its citations kept
/// apart from its title.
///
/// A finding is a claim about what is wrong with a host or a port: a known
/// vulnerability the service matches, a detection that fired. The engine
/// produces them and the file formats carry every field; this is the terminal's
/// compact view, which leads with how bad it is and keeps the fix for `-v`.
///
/// The severity is kept unformatted alongside its token so a presentation
/// colours it by rank rather than matching on the word it was spelled as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingView {
    /// `CRIT`, `MED`, padded so every subject in the listing starts in one
    /// column.
    pub token: String,
    /// How bad it is if true, unformatted so a mode can colour it.
    pub severity: Severity,
    /// `80, 631/tcp`, or `host` for a finding about the host itself, padded
    /// likewise.
    pub subject: String,
    /// The title, as the detection wrote it.
    pub title: String,
    /// How many spaces follow the title, so citations land in one column.
    pub pad: usize,
    /// `CVE-2021-44228`, where the finding cites anything.
    pub reference: Option<String>,
    /// The CVEs it cites, worst first and capped, drawn on a line of its own
    /// under the row. Apart from `reference` because a list of identifiers is
    /// data rather than a label, and a row is a label.
    pub cves: Option<String>,
    /// What the detection saw, bounded to one line. Shown under `--reason`,
    /// which is the flag for the evidence behind a verdict.
    pub evidence: Option<String>,
    /// How sure it is true, and `None` where it is certain: a word that is the
    /// same on every line is a word nobody reads.
    pub confidence: Option<&'static str>,
    /// Every port this finding was raised on, where the listing folded more of
    /// them into a count than the subject column will spell. Shown under `-v`.
    pub ports: Option<String>,
    /// What to do about it, where the detection carried advice. Shown under
    /// `-v`, since a person triaging wants the finding and a person acting on it
    /// wants this.
    pub remediation: Option<String>,
}

/// The findings a listing draws, and what it held back.
pub(crate) struct FindingListing {
    /// One entry per row shown, worst first.
    pub rows: Vec<FindingView>,
    /// How many findings sit below the floor.
    ///
    /// Counted in findings rather than in rows, so that this and the count on a
    /// host's header are the same arithmetic: a row folds several ports into
    /// one line, and two totals that disagreed about what a finding is would be
    /// worse than either.
    pub withheld: usize,
}

/// How a severity reads as an urgency, so a finding borrows the same colours a
/// certificate's expiry does rather than inventing a second scale.
///
/// Critical and high are the two that read as a problem now; medium is a
/// caution; the two below it are neither, and colouring them would spend the
/// eye's attention where the finding does not ask for it.
pub(crate) fn severity_urgency(severity: Severity) -> Urgency {
    match severity {
        Severity::Critical | Severity::High => Urgency::Alarm,
        Severity::Low | Severity::Info => Urgency::Muted,
        // Medium, and a severity a newer engine ranks that this build has no
        // place for: a caution. Drawn rather than hidden or made to shout, since
        // an unrankable finding is still a real one and neither silence nor an
        // alarm is honest about it.
        _ => Urgency::Caution,
    }
}

/// A severity as the short token the risks column is built from.
///
/// Four characters at the widest, so the column the eye runs down stays four
/// wide however many levels a listing carries. The engine's own label is the
/// fallback, uppercased and cut to the same width: a level added to the scale
/// after this build was compiled still lands in the column rather than pushing
/// every row on the block out of line.
pub(crate) fn severity_token(severity: Severity) -> String {
    match severity {
        Severity::Critical => "CRIT".to_owned(),
        Severity::High => "HIGH".to_owned(),
        Severity::Medium => "MED".to_owned(),
        Severity::Low => "LOW".to_owned(),
        Severity::Info => "INFO".to_owned(),
        other => other
            .label()
            .chars()
            .take(TOKEN_WIDTH)
            .flat_map(char::to_uppercase)
            .collect(),
    }
}

/// The widest a severity token is allowed to be.
const TOKEN_WIDTH: usize = 4;

/// How many subjects a row spells before it counts them instead.
const SUBJECTS_SPELLED: usize = 3;

/// Where a claim was found: a port and its protocol, or `None` for the host
/// itself.
type Origin = Option<(u16, String)>;

/// One finding as it comes off a host, before rows are folded or padded.
struct Claim {
    /// The port it is about, `None` for one about the host itself.
    port: Origin,
    severity: Severity,
    confidence: Confidence,
    title: String,
    reference: Option<String>,
    /// The CVEs it cites, worst first and capped, drawn under the row.
    cves: Option<String>,
    evidence: Option<String>,
    remediation: Option<String>,
}

/// What makes two claims the same finding seen twice.
///
/// Everything the row would draw except where it was found. A detection that
/// fires on three ports of one host is one weakness in three places, and three
/// rows repeating a sentence is the reader's problem rather than the scan's.
/// Severity is part of the key because the same detection can grade two ports
/// differently, and those are two findings however alike they read.
#[derive(PartialEq, Eq)]
struct Fold {
    severity: Severity,
    confidence: Confidence,
    title: String,
    reference: Option<String>,
    cves: Option<String>,
    evidence: Option<String>,
    remediation: Option<String>,
}

/// One row, once the claims behind it have been gathered.
struct Folded {
    /// What every claim in the row agrees on.
    key: Fold,
    /// Where each of them was found, sorted and without repeats.
    found: Vec<Origin>,
}

/// The findings a host carries, its own and its ports', worst first.
///
/// One list rather than two, because a person reading it wants the worst finding
/// first whether it is about the host or one of its ports, and `subject` says
/// which without splitting the list. Claims alike in everything but their port
/// fold into one row; what is left sorts by severity descending, then by the
/// host's own findings, then by the lowest port a row covers, so two runs of the
/// same scan draw the same order and the risks agree with the ports table about
/// what comes first.
///
/// Empty for the ordinary host, which carries no findings at all: nothing here
/// draws a heading for a host that has nothing wrong with it.
pub(crate) fn findings(host: &Host, floor: Risk) -> FindingListing {
    let mut claims: Vec<Claim> = host
        .findings()
        .map(|finding| claim(None, finding))
        .collect();

    for port in host.ports() {
        let endpoint = (port.number(), protocol(port.protocol()).clone());
        for finding in port.findings() {
            claims.push(claim(Some(endpoint.clone()), finding));
        }
    }

    let mut folded = fold(claims);

    // Worst first. `Severity` orders weakest-to-strongest, so the comparison is
    // reversed; what the row is about breaks the tie, the host's own findings
    // ahead of its ports' and the rest by number, so the order is total.
    folded.sort_by(|a, b| {
        b.key
            .severity
            .cmp(&a.key.severity)
            .then_with(|| a.found.first().cmp(&b.found.first()))
    });

    // Held back before the columns are measured, so a row nobody sees does not
    // set the width of the ones they do.
    let mut withheld = 0usize;
    let rows: Vec<(Fold, String, Option<String>)> = folded
        .into_iter()
        .filter_map(|row| {
            if !floor.admits(row.key.severity) {
                withheld += row.found.len();
                return None;
            }

            let (subject, spelled) = subject(&row.found);
            Some((row.key, subject, spelled))
        })
        .collect();

    let token_width = rows
        .iter()
        .map(|(key, ..)| severity_token(key.severity).len())
        .max()
        .unwrap_or(0);
    let subject_width = rows
        .iter()
        .map(|(_, subject, _)| subject.chars().count())
        .max()
        .unwrap_or(0);
    // From the titles that have something after them: a row ending at its title
    // needs no padding, so a long one that ends there should not push everything
    // else out to meet it.
    //
    // Uncapped, because a cap does not do what it looks like it does. It bounded
    // the column without bounding the titles, so a title past the cap carried
    // its own citation out past everybody else's and the column it was meant to
    // protect was ragged exactly where it mattered. A column is measured from
    // the things that share it or it is not a column.
    let title_width = rows
        .iter()
        .filter(|(key, ..)| key.reference.is_some() || key.confidence != Confidence::Certain)
        .map(|(key, ..)| width(&key.title))
        .max()
        .unwrap_or(0);

    let rows = rows
        .into_iter()
        .map(|(key, subject, ports)| FindingView {
            token: format!("{:<token_width$}", severity_token(key.severity)),
            severity: key.severity,
            subject: format!("{subject:<subject_width$}"),
            pad: title_width.saturating_sub(width(&key.title)),
            title: key.title,
            reference: key.reference,
            cves: key.cves,
            evidence: key.evidence,
            confidence: (key.confidence != Confidence::Certain)
                .then(|| wire::confidence_name(key.confidence)),
            ports,
            remediation: key.remediation,
        })
        .collect();

    FindingListing { rows, withheld }
}

/// The most CVE identifiers a row names before counting the rest.
///
/// A finding correlated against the vulnerability catalogue cites every CVE it
/// matched, which for an OpenSSH from 2015 is forty-four. Three, worst first,
/// and the rest counted.
///
/// Worst rather than lowest-numbered because a finding states its references in
/// the order its detection ranked them, and the correlator ranks by severity.
/// Three of forty-four chosen by identifier would be a fact about numbering.
const MAX_CITED_CVES: usize = 3;

/// One finding as a [`Claim`], with its citations split.
///
/// CVEs are held apart from everything else because they do not belong on the
/// same line. A CWE is one token naming the kind of weakness, which is what
/// every other row in the table carries beside its title; a CVE list is data,
/// and forty-four identifiers wrapped across a row buries the finding they
/// belong to and every row under it. So the CWE stays on the row and the CVEs
/// go beneath it, where `evidence` and `remedy` already sit.
fn claim(port: Option<(u16, String)>, finding: &zond_engine::model::finding::Finding) -> Claim {
    let (cve_refs, other_refs): (Vec<&Reference>, Vec<&Reference>) = finding
        .references()
        .partition(|reference| matches!(reference, Reference::Cve(_)));

    let mut cited: Vec<String> = cve_refs
        .iter()
        .take(MAX_CITED_CVES)
        .map(|reference| reference_text(reference))
        .collect();
    if cve_refs.len() > MAX_CITED_CVES {
        cited.push(format!("+{}", cve_refs.len() - MAX_CITED_CVES));
    }
    let cves = (!cited.is_empty()).then(|| cited.join("  "));

    let others: Vec<String> = other_refs.into_iter().map(reference_text).collect();
    let reference = (!others.is_empty()).then(|| others.join("  "));

    let excerpt = finding.excerpt().as_str();

    Claim {
        port,
        severity: finding.severity(),
        confidence: finding.confidence(),
        title: finding.title().to_owned(),
        reference,
        cves,
        evidence: (!excerpt.trim().is_empty()).then(|| one_line(excerpt)),
        remediation: finding.remediation().map(ToOwned::to_owned),
    }
}

/// An excerpt with the shape taken out of it.
///
/// The engine bounds an excerpt at two kilobytes and says nothing about its
/// shape, so what arrives here may be a sentence, a list, or the bytes of a
/// reply with newlines still in them. Runs of whitespace close up, and that is
/// all: what is left is one paragraph, and the presentation folds it to whatever
/// the terminal is.
///
/// It used to be cut at sixty-eight characters and given an ellipsis, which is
/// the wrong place to decide it twice over. A cut made here does not know the
/// width it is cutting for, and the excerpt is opt-in anyway: somebody who asked
/// for `--reason` asked for the evidence rather than for sixty-eight characters
/// of it.
///
/// The bytes themselves are escaped by the painting, as every value a scanned
/// host chose is.
fn one_line(excerpt: &str) -> String {
    let flattened: String = excerpt.split_whitespace().collect::<Vec<_>>().join(" ");
    printable(&flattened).into_owned()
}

/// Claims alike in everything but their port, gathered into one row each.
///
/// First-seen order is kept rather than sorted here, because the caller sorts
/// what comes back and a fold that reordered as well would decide the tie twice.
fn fold(claims: Vec<Claim>) -> Vec<Folded> {
    let mut rows: Vec<Folded> = Vec::new();

    for claim in claims {
        let key = Fold {
            severity: claim.severity,
            confidence: claim.confidence,
            title: claim.title,
            reference: claim.reference,
            cves: claim.cves,
            evidence: claim.evidence,
            remediation: claim.remediation,
        };

        match rows.iter_mut().find(|row| row.key == key) {
            Some(row) => row.found.push(claim.port),
            None => rows.push(Folded {
                key,
                found: vec![claim.port],
            }),
        }
    }

    for row in &mut rows {
        row.found.sort();
        row.found.dedup();
    }

    rows
}

/// What a row is about, and the full port list where the column would not hold
/// it.
///
/// A finding on the host itself is about the `host`. Ports are spelled in one
/// column, so a run of them sharing a protocol names it once: `80, 631/tcp`
/// rather than a phrase whose second half is the same word three times. Past a
/// few the column would grow wider than everything it sits beside, so the row
/// counts them instead and hands the spelling back for `-v` to hang.
fn subject(ports: &[Origin]) -> (String, Option<String>) {
    let named: Vec<&(u16, String)> = ports.iter().flatten().collect();

    if named.is_empty() {
        return (String::from("host"), None);
    }

    let spelled = spell(&named);

    // The host's own finding folded together with a port's: one claim about two
    // different subjects, so the row says both rather than picking one.
    let spelled = if ports.iter().any(Option::is_none) {
        format!("host, {spelled}")
    } else {
        spelled
    };

    if named.len() <= SUBJECTS_SPELLED {
        return (spelled, None);
    }

    (format!("{} ports", named.len()), Some(spelled))
}

/// A run of ports as one phrase, naming a shared protocol once.
fn spell(ports: &[&(u16, String)]) -> String {
    let first = &ports[0].1;
    if ports.iter().all(|(_, proto)| proto == first) {
        let numbers: Vec<String> = ports.iter().map(|(number, _)| number.to_string()).collect();
        return format!("{}/{first}", numbers.join(", "));
    }

    ports
        .iter()
        .map(|(number, proto)| format!("{number}/{proto}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// How many columns a value the scan chose will occupy once it is printable.
///
/// Measured after escaping, because that is what the terminal will be handed: a
/// title carrying a newline is two characters wider drawn than it is stored, and
/// a column padded from the stored length would be short by exactly that much.
fn width(value: &str) -> usize {
    printable(value).chars().count()
}

/// A reference as the short identifier a reader recognises.
///
/// A CVE and a CWE are their own names; a URL is shown as written, and escaped
/// like any other value a document carried when it reaches a presentation. The
/// bare number a `Cwe` carries is spelled back into `CWE-79`, since the number
/// alone is not the identifier.
fn reference_text(reference: &Reference) -> String {
    match reference {
        Reference::Cve(id) => id.clone(),
        Reference::Cwe(number) => format!("CWE-{number}"),
        Reference::Url(url) => url.clone(),
        // A reference kind a newer engine carries and this build has no spelling
        // for. Named the way the wire names it rather than dropped, so a finding
        // never loses a citation to a build that is merely behind.
        other => wire::reference_kind_name(other).to_owned(),
    }
}

/// How long a certificate has left, and how much that matters.
///
/// Days rather than a date: the question this line answers is "do I have to do
/// something about this", and a date makes the reader do the arithmetic that
/// produces the answer.
fn expiry(end: std::time::SystemTime) -> (String, Urgency) {
    match end.duration_since(std::time::SystemTime::now()) {
        Ok(left) => {
            let days = whole_days(left);
            if days == 0 {
                (String::from("expires today"), Urgency::Caution)
            } else if left <= EXPIRY_HORIZON {
                (format!("expires in {days}d"), Urgency::Caution)
            } else {
                (format!("expires in {days}d"), Urgency::None)
            }
        }
        Err(past) => {
            let days = whole_days(past.duration());
            if days == 0 {
                (String::from("expired today"), Urgency::Alarm)
            } else {
                (format!("expired {days}d ago"), Urgency::Alarm)
            }
        }
    }
}

/// A span in days, to the nearest one.
///
/// Nearest rather than truncated, because a certificate ending in twenty-three
/// hours' time is a day away and `0d` reads as "gone". Truncation also makes the
/// figure depend on the second the scan happened to be rendered at: a
/// certificate a fortnight out reports `13d` or `14d` according to the clock,
/// and neither the record nor a person comparing two runs can tell which.
fn whole_days(span: Duration) -> u64 {
    (span.as_secs() + 86_400 / 2) / 86_400
}

/// A value with every control character made visible.
///
/// **A scanned host chooses its own banner, its own certificate subject and its
/// own hostname**, and all three end up in a record this program writes. A tab
/// in one of them would add a field to a `pipe` record, and a newline would add
/// a whole line. That is not a cosmetic problem: a script reading field 6 would
/// read a value the host chose to put there.
///
/// So a control character is rendered as an escape rather than passed through.
/// The field count survives, the reader sees that something odd is in the value,
/// and no quoting rule has to be invented for a format whose whole appeal is not
/// having one.
///
/// Borrows when there is nothing to escape, which is every value in almost every
/// record.
pub(crate) fn printable(value: &str) -> std::borrow::Cow<'_, str> {
    use std::fmt::Write as _;

    if !value.contains(char::is_control) {
        return std::borrow::Cow::Borrowed(value);
    }

    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            // Written into the string rather than formatted into one of its
            // own: this runs per character, on values a scanned host chose.
            c if c.is_control() => {
                let _ = write!(escaped, "\\x{:02x}", c as u32);
            }
            c => escaped.push(c),
        }
    }

    std::borrow::Cow::Owned(escaped)
}

/// `word`, pluralised, when there is not exactly one of them.
///
/// English only as far as this program needs it: a word already ending in `s`
/// takes `es`, everything else takes `s`. That covers "address", "probe",
/// "host" and "port", which is every word this program counts. A word needing
/// any other rule does not belong here without this growing one.
pub(crate) fn plural(count: u128, word: &str) -> String {
    if count == 1 {
        word.to_owned()
    } else if word.ends_with('s') {
        format!("{word}es")
    } else {
        format!("{word}s")
    }
}

/// The ports worth showing, packed into one field for a program.
///
/// `22/tcp/open/ssh`, comma-joined, so a record stays one line and one host.
/// Closed ports are counted in a field of their own instead.
pub(crate) fn packed_ports(host: &Host) -> Option<String> {
    let mut ports: Vec<&Port> = host.ports().filter(|port| notable(port.state())).collect();
    if ports.is_empty() {
        return None;
    }
    ports.sort_by_key(|port| (port.protocol(), port.number()));

    Some(
        ports
            .into_iter()
            .map(|port| {
                format!(
                    "{}/{}/{}/{}",
                    port.number(),
                    protocol(port.protocol()),
                    state(port.state()),
                    port.service_name().filter(named).unwrap_or(UNKNOWN)
                )
            })
            .collect::<Vec<_>>()
            .join(","),
    )
}

/// How many ports came back plainly closed.
pub(crate) fn closed_ports(host: &Host) -> Option<String> {
    let closed = host.ports().filter(|port| !notable(port.state())).count();

    if host.port_count() == 0 {
        None
    } else {
        Some(closed.to_string())
    }
}

/// Whether a service name is a name rather than the engine's placeholder.
fn named(name: &&str) -> bool {
    *name != NO_SERVICE
}

/// A protocol's name, lower case.
///
/// Spelled out rather than taken from `Debug`: a rename in the engine would
/// otherwise silently change output a script matches on.
fn protocol(protocol: Protocol) -> String {
    match protocol {
        Protocol::Tcp => "tcp".to_owned(),
        Protocol::Udp => "udp".to_owned(),
        other => format!("{other:?}").to_lowercase(),
    }
}

/// A port's verdict, lower case.
///
/// `open-filtered` is one verdict, meaning "no answer, and for this technique
/// that could be either". It is not two states to pick between.
fn state(state: PortState) -> String {
    match state {
        PortState::Open => "open".to_owned(),
        PortState::Closed => "closed".to_owned(),
        PortState::Filtered => "filtered".to_owned(),
        PortState::Unfiltered => "unfiltered".to_owned(),
        PortState::OpenFiltered => "open-filtered".to_owned(),
        PortState::ClosedFiltered => "closed-filtered".to_owned(),
        other => format!("{other:?}").to_lowercase(),
    }
}

/// How many of a run's probes may go unanswered before a scan which already
/// paced itself to its floor has stopped being able to tell filtered from lost.
///
/// One in ten, held as the divisor rather than as `0.10`, so the comparison is
/// exact integer arithmetic. A probe count is a `u128` and does not fit a
/// `f64`'s mantissa, so the float form would round the very counts that make
/// this question worth asking.
const UNREACHED_IN: u128 = 10;

/// Whether this report's silence is a finding.
///
/// A port reported `filtered` is a positive claim: something dropped a probe
/// that a live host would have answered. That claim rests entirely on the scan
/// having *asked properly*. A scan whose own pacing was cut back as far as it
/// goes and which still left most of its probes unanswered did not ask properly;
/// it ran out of link before it ran out of ports.
///
/// Measured, and the reason this exists: a full-range scan from a wireless
/// laptop reported forty-two thousand ports filtered on a host with no firewall
/// at all. The scanner knew, and printed a warning saying so directly above the
/// list, and then printed the list anyway. A warning that contradicts the rows
/// under it is not a warning, it is a footnote nobody reads.
///
/// Both halves are needed. A window at its floor with everything answered is a
/// polite scan that worked; a high unanswered share with the window never cut is
/// a genuinely quiet host, which is a finding. Only the two together mean the
/// scan could not ask.
pub(crate) fn silence_means_something(report: &ScanReport) -> bool {
    !report.phases().iter().any(|phase| {
        phase.probe_stats().iter().any(|stats| {
            let outrun = stats.window().is_some_and(|window| window.at_floor);
            let targets = stats.targets();
            let unanswered = targets.saturating_sub(u128::from(stats.hosts_found()));

            // `unanswered / targets >= 1 / UNREACHED_IN`, multiplied out. A run
            // that asked nothing has no share to speak of.
            outrun && targets > 0 && unanswered.saturating_mul(UNREACHED_IN) >= targets
        })
    })
}

/// The longest supplementary detail worth putting in a port table.
///
/// Wide enough for a product name, which is the longest thing this is *for*, and
/// narrow enough that a row stays one line at any sensible terminal width.
const EXTRAINFO_WIDTH: usize = 24;

/// What kind of thing this port is, and whether anything confirmed it.
///
/// `http`, `ssl/http`, `jetdirect`: a classification out of a small vocabulary,
/// which is a different fact from the software answering on the port and belongs
/// in a different column from it. The two used to be joined into one string
/// separated by a space — the same space that appears inside
/// `Epson_IPP-Server 2.0.0`, which is why nothing separated them.
///
/// The flag is `Service::is_inferred`: whether the engine looked this name up
/// from the port number or a probe established it. This crate had never asked,
/// so a guess and a fingerprint were painted alike, which is the presentation
/// claiming more than the engine did.
fn service_name(port: &Port) -> Option<(String, bool)> {
    let service = port.service()?;
    if !named(&service.name()) {
        return None;
    }

    Some((service.name().to_owned(), service.is_inferred()))
}

/// What answered on the port, where fingerprinting worked it out.
fn product_text(port: &Port) -> Option<String> {
    let service = port.service()?;
    let name = service.name();
    if !named(&name) {
        return None;
    }

    let mut described = String::new();
    if let Some(product) = service.product()
        // A product that merely repeats the service name says nothing twice:
        // `http http` is what an HTTP server nothing identified more precisely
        // renders as, and the second word is noise in every such row. A
        // tunnelled service names both halves, as in `ssl/http`, so the repeat
        // has to be looked for in each of them, or `ssl/http http` gets through.
        && !name
            .split('/')
            .any(|part| part.eq_ignore_ascii_case(product))
    {
        described.push_str(product);
    }
    if let Some(version) = service.version() {
        if !described.is_empty() {
            described.push(' ');
        }
        described.push_str(version);
    }
    // What is running *on* the server, as distinct from the server: the
    // application a title or a vendor-prefixed header named, or the technology
    // an `X-Powered-By` did. Parenthesised because it qualifies the product
    // rather than replacing it: `Kestrel (Jellyfin)` is two true statements
    // about one port, and the second is the one somebody was looking for.
    //
    // Only when it is short enough to be a name. Some of what analyzers put here
    // is a list rather than a label, and an SSH host-key algorithm set runs to
    // seventy characters. A port table is a column of rows somebody scans down,
    // not a place to read a list. The full value is in the report either way;
    // this is the rendering, not the record.
    if let Some(extra) = service
        .extrainfo()
        .filter(|extra| extra.len() <= EXTRAINFO_WIDTH)
    {
        if !described.is_empty() {
            described.push(' ');
        }
        described.push('(');
        described.push_str(extra);
        described.push(')');
    }

    (!described.is_empty()).then_some(described)
}

/// The two of them joined, for a mode with one column to put them in.
///
/// `minimal` is a tagged line per value and has nowhere to align a second
/// column, so it takes the sentence the block used to draw.
fn describe(port: &Port) -> Option<String> {
    let (name, _) = service_name(port)?;

    Some(match product_text(port) {
        Some(product) => format!("{name} {product}"),
        None => name,
    })
}

/// The report's hosts, by address, so two runs can be diffed.
///
/// The order hosts answer in is different every time.
pub(crate) fn sorted_hosts(report: &ScanReport) -> Vec<&Host> {
    let mut hosts: Vec<&Host> = report.hosts().collect();
    hosts.sort_by_key(|host| host.primary_ip());
    hosts
}

/// How many addresses the run was asked to cover, or `None` where the record
/// does not say.
///
/// The union of every phase's ranges, not their sum and not the first of them.
/// A job's port scan covers the addresses its sweep found, so unioning the two
/// gives the sweep's count — which is what was asked about, rather than what
/// survived the asking. A report folded out of several scans has phases that
/// overlap in some places and not others, and only a union answers that.
///
/// `None` for a report whose phases state no scope, which is what a document
/// from another scanner reads as. Saying "0 addresses" there would be a claim
/// the record does not make, and it reads as a broken tool beside a host count
/// that is not zero.
pub(crate) fn addresses_scanned(report: &ScanReport) -> Option<u128> {
    let mut covered = IpSet::new();
    let mut stated = false;

    for phase in report.phases() {
        for range in phase.targets().ranges() {
            covered.insert_range(*range);
            stated = true;
        }
    }

    if !stated {
        return None;
    }

    covered.canonicalize();
    Some(covered.len())
}

/// How many addresses the run was asked about but never port-scanned.
///
/// Zero unless a liveness phase ran and turned something away.
///
/// **Counts only the addresses that were probed and stayed silent.** An address
/// this host has no route to was never asked anything, so it is subtracted out
/// here and reported by [`unroutable`] instead: the two are different findings
/// and only one of them can be answered by scanning on trust.
pub(crate) fn skipped_as_down(report: &ScanReport) -> u128 {
    // Exactly a sweep and the port scan that followed it, which is the one shape
    // this subtraction means anything in. Two port-scan sittings of a resumed
    // job, or the phases of several scans folded into one report, are not one
    // job's before and after, and subtracting them names a number of addresses
    // nothing turned away.
    let [liveness, ports] = report.phases() else {
        return 0;
    };
    if liveness.kind() != ScanKind::Discovery || ports.kind() != ScanKind::PortScan {
        return 0;
    }

    liveness
        .targets()
        .addresses()
        .saturating_sub(ports.targets().addresses())
        .saturating_sub(unroutable(report))
}

/// How many addresses this host had no route to.
///
/// Counted across every phase and de-duplicated, since the liveness phase and
/// the port scan can each meet the same unreachable address.
pub(crate) fn unroutable(report: &ScanReport) -> u128 {
    let mut seen: Vec<IpAddr> = report
        .phases()
        .iter()
        .flat_map(|phase| phase.unroutable().iter().copied())
        .collect();
    seen.sort_unstable();
    seen.dedup();
    seen.len() as u128
}

/// How many hosts a time budget left before they were finished.
///
/// From `--host-timeout` and `--scan-timeout`: a host still outstanding when its
/// budget expired is recorded as timed out, and its results are whatever the
/// scan had reached, which is narrower than what was asked. Counted across
/// phases and deduplicated, the way [`unroutable`] is, so a host cut short in
/// two phases is one host cut short.
pub(crate) fn timed_out(report: &ScanReport) -> u128 {
    let mut seen: Vec<IpAddr> = report
        .phases()
        .iter()
        .flat_map(|phase| phase.timed_out().iter().copied())
        .collect();
    seen.sort_unstable();
    seen.dedup();
    seen.len() as u128
}

/// Why each part of the ground the engine declined went uncovered, once per
/// reason and in the order the phases filed them.
///
/// The engine files a refusal once per phase, and a reader acts on the reason
/// rather than on how many phases met it, so one repeated across phases is said
/// once.
pub(crate) fn refusals(report: &ScanReport) -> Vec<&str> {
    let mut reasons: Vec<&str> = Vec::new();
    for refusal in report.refusals() {
        if !reasons.contains(&refusal.reason()) {
            reasons.push(refusal.reason());
        }
    }
    reasons
}

/// Whether any host in the report carries a TCP port, which is to say a TCP
/// port was probed.
///
/// Every probed port is recorded, closed and unanswered ones included, so a
/// port scan with none has no TCP verdict to account for: its technique was
/// refused, no host answered the liveness pass, or it named other protocols
/// only.
pub(crate) fn probed_tcp(report: &ScanReport) -> bool {
    report
        .hosts()
        .flat_map(Host::ports)
        .any(|port| port.protocol() == Protocol::Tcp)
}

/// What the run was for.
///
/// The *last* phase. A port scan records two, the liveness pass that established
/// anything was there and then the ports, and it is the second that says what
/// the run was asked to do.
pub(crate) fn kind(report: &ScanReport) -> Option<ScanKind> {
    report.phases().last().map(ScanPhase::kind)
}

/// What the run this report describes held.
///
/// Read from the report rather than asked of the process: the two can disagree,
/// and what matters is what the scan actually had.
///
/// `None` where the report cannot say, which is every report another scanner
/// produced. Whether *these* strategies held the sockets they need is not a
/// question an nmap document answers, and reading its silence as
/// [`Connect`](Privilege::Connect) put this program's advice about running as
/// root under a sweep performed over ARP by a process that already was.
pub(crate) fn privilege(report: &ScanReport) -> Option<Privilege> {
    report.phases().last().and_then(ScanPhase::privilege)
}

/// The counts a summary line is drawn from.
pub(crate) fn summary(report: &ScanReport) -> ScanSummary {
    report.summary()
}

/// How many findings a report carries, and how many of those are serious.
///
/// A finding is a claim about what is wrong, so the count belongs on the summary
/// line the way the open-port count does: a run that turned up two critical
/// vulnerabilities should say so where a reader is already looking rather than
/// only inside a host's block.
///
/// `serious` is the count at [`High`](Severity::High) or above, the ones that
/// ask for action tonight rather than at the next review. `None` when the report
/// carries no findings at all, so a clean scan draws no line about them.
pub(crate) fn findings_tally(report: &ScanReport) -> Option<(usize, usize)> {
    let mut total = 0usize;
    let mut serious = 0usize;

    for host in report.hosts() {
        let all = host.findings().chain(host.ports().flat_map(Port::findings));
        for finding in all {
            total += 1;
            if finding.severity() >= Severity::High {
                serious += 1;
            }
        }
    }

    (total > 0).then_some((total, serious))
}

// ─────────────────────────────────────────────────────────────────────────────
// A link-local address that is the hardware address written again
// ─────────────────────────────────────────────────────────────────────────────

/// The six octets of a hardware address as it is written.
///
/// Parsed back out of the spelling rather than taken from the engine's own type,
/// so that this file's one piece of bit-twiddling depends on the canonical
/// notation and on nothing else. `None` for anything that is not six octets.
pub(crate) fn octets(mac: &str) -> Option<[u8; 6]> {
    let mut parsed = [0u8; 6];
    let mut parts = mac.split([':', '-']);

    for octet in &mut parsed {
        *octet = u8::from_str_radix(parts.next()?, 16).ok()?;
    }

    parts.next().is_none().then_some(parsed)
}

/// Whether `address` is `mac` restated as a link-local address.
///
/// The modified EUI-64 construction, which is what a host forms `fe80::` from
/// when it has not been told to do otherwise: flip the universal/local bit of
/// the first octet, insert `ff:fe` in the middle of the six, and hang the result
/// off `fe80::`. `c8:52:61:c7:05:94` becomes `fe80::ca52:61ff:fec7:594`.
///
/// A host whose link-local was formed that way is answering at the hardware
/// address the block has already printed, two lines up, in another notation.
/// Suppressing it removes no finding; it removes a second copy of one.
///
/// **Only link-local addresses.** A *global* address built the same way is
/// routable from somewhere else and is a finding of its own, which is why the
/// prefix is checked rather than the interface identifier alone.
///
/// A host using RFC 7217 stable-privacy addressing fails this test and keeps its
/// line, which is right: that identifier is not derived from anything else on
/// the screen.
pub(crate) fn restates(mac: [u8; 6], address: Ipv6Addr) -> bool {
    if !address.is_unicast_link_local() {
        return false;
    }

    let derived = [
        mac[0] ^ 0b0000_0010,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ];

    address.octets()[8..] == derived
}

// ─────────────────────────────────────────────────────────────────────────────
// A vendor as a person says it
// ─────────────────────────────────────────────────────────────────────────────

/// The words a registry entry ends with that nobody reads out.
///
/// Legal forms, and the handful of organisational fillers that behave like them:
/// "Raspberry Pi Trading Ltd" is said "Raspberry Pi". Matched
/// case-insensitively, and with any trailing period ignored, because the
/// registry is inconsistent about both.
const UNSPOKEN: &[&str] = &[
    "ab",
    "ag",
    "as",
    "bv",
    "co",
    "company",
    "corp",
    "corporation",
    "gmbh",
    "group",
    "holdings",
    "inc",
    "incorporated",
    "international",
    "kk",
    "limited",
    "llc",
    "ltd",
    "nv",
    "oy",
    "plc",
    "pty",
    "sa",
    "spa",
    "srl",
    "trading",
];

/// A vendor as a person says it.
///
/// The IEEE registry stores a legal name, such as "Raspberry Pi Trading Ltd",
/// "Seiko Epson Corp" or "Arris Group, Inc", and the part that makes it legal is
/// the part a reader skips. `pipe` still emits the registry string, because that
/// is an interface; a drawn mode is allowed to spell it the way it is said.
///
/// The first word always survives. A registry entry made entirely of legal
/// forms is pathological rather than impossible, and an empty vendor column is
/// worse than an odd one.
pub(crate) fn spoken_vendor(vendor: &str) -> &str {
    let mut end = vendor.trim_end();

    loop {
        let trimmed = end.trim_end_matches([' ', ',']);
        let Some((rest, last)) = trimmed.rsplit_once(' ') else {
            return if trimmed.is_empty() { vendor } else { trimmed };
        };

        let word = last.trim_end_matches('.').trim_end_matches(',');
        if !UNSPOKEN
            .iter()
            .any(|known| word.eq_ignore_ascii_case(known))
        {
            return trimmed;
        }

        end = rest;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// One unit for a whole listing
// ─────────────────────────────────────────────────────────────────────────────

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
    /// A patch component is a digit that moves for a release changing no
    /// detection's behaviour, so it is not on a line a person reads.
    #[test]
    fn a_version_is_shown_to_major_and_minor() {
        assert_eq!(major_minor("0.14.0"), "0.14");
        assert_eq!(major_minor("0.14.0-rc1"), "0.14");
        assert_eq!(major_minor("1.2"), "1.2");
        assert_eq!(major_minor("7"), "7");
    }

    // -----------------------------------------------------------------------
    // Who said the host is there
    // -----------------------------------------------------------------------

    /// An error a router sent is not the host answering for itself, and the long
    /// form is the only place that shows it.
    ///
    /// The two read identically in the short form — both are `ICMP_unreachable`
    /// — and they are different claims. A NAT answering on a machine's behalf
    /// proves something in the path speaks for that address, not that the
    /// machine is there, and a scan that reported the two the same way would
    /// claim a host nobody has.
    #[test]
    fn evidence_from_the_path_names_who_sent_it() {
        use std::net::Ipv4Addr;
        use zond_engine::model::host::status::{StatusProtocol, StatusReason};

        let router = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254));
        let mut host = host(1);
        host.record_evidence(
            zond_engine::HostStatus::Up,
            StatusReason::new(
                StatusProtocol::IcmpUnreachable,
                "unreachable, from the path",
            )
            .from_source(router),
        );

        let lines = answered_in_detail(Reader::default(), &host);
        let attributed = lines
            .iter()
            .find(|line| line.contains("ICMP_unreachable"))
            .expect("the reason is listed");

        assert!(
            attributed.contains("unreachable, from the path"),
            "{attributed}"
        );
        assert!(attributed.contains("via 192.0.2.254"), "{attributed}");
    }

    /// A sender the scan's exclusions forbid naming still marks the evidence as
    /// second-hand, and says so without the address. Drawn as the host's own
    /// answer it would claim the machine replied; drawn with the address it
    /// would print what the operator excluded.
    #[test]
    fn evidence_from_an_excluded_sender_is_second_hand_and_unnamed() {
        use zond_engine::model::host::status::{StatusProtocol, StatusReason};

        let mut reason = StatusReason::basic(StatusProtocol::IcmpUnreachable);
        reason.source = EvidenceSource::Withheld;
        let mut host = host(1);
        host.record_evidence(zond_engine::HostStatus::Up, reason);

        let lines = answered_in_detail(Reader::default(), &host);
        assert_eq!(lines, vec!["ICMP_unreachable  via excluded".to_string()]);
    }

    /// `--reason` on a local sweep used to cost four lines and buy nothing.
    ///
    /// A sweep records every reason through `StatusReason::basic`, which carries
    /// neither details nor a source — so the long form rendered exactly the
    /// short form's four tokens, one per line. A flag that costs four lines has
    /// to buy something with them.
    #[test]
    fn the_long_form_stays_compact_when_it_has_nothing_to_add() {
        use zond_engine::model::host::status::{StatusProtocol, StatusReason};

        let mut host = host(1);
        for protocol in [
            StatusProtocol::Arp,
            StatusProtocol::Dhcp,
            StatusProtocol::IcmpEcho,
            StatusProtocol::Ndp,
        ] {
            host.record_evidence(zond_engine::HostStatus::Up, StatusReason::basic(protocol));
        }

        let lines = answered_in_detail(Reader::default(), &host);

        assert_eq!(
            lines,
            vec![answered(&host).expect("the compact form")],
            "one row, and the same row the short form draws"
        );
        assert_eq!(lines[0], "ARP  DHCP  ICMP_echo  NDP");
    }

    /// And it expands the moment one reason has something the short form drops.
    ///
    /// The fallback above must not swallow the case the flag exists for: one
    /// qualified reason is enough to make every line worth its own row, because
    /// a reader comparing them needs them aligned.
    #[test]
    fn one_qualified_reason_is_enough_to_open_the_long_form() {
        use zond_engine::model::host::status::{StatusProtocol, StatusReason};

        let mut host = host(1);
        host.record_evidence(
            zond_engine::HostStatus::Up,
            StatusReason::basic(StatusProtocol::Arp),
        );
        host.record_evidence(
            zond_engine::HostStatus::Up,
            StatusReason::new(StatusProtocol::Tcp, "a segment overheard from this host"),
        );

        let lines = answered_in_detail(Reader::default(), &host);

        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines.iter().any(|line| line.contains("overheard")),
            "{lines:?}"
        );
    }

    /// Evidence the host gave for itself carries no `via`, because there is
    /// nobody in between to name.
    #[test]
    fn evidence_from_the_host_itself_names_nobody() {
        use zond_engine::model::host::status::{StatusProtocol, StatusReason};

        let mut host = host(1);
        host.record_evidence(
            zond_engine::HostStatus::Up,
            StatusReason::new(StatusProtocol::Arp, "an address resolution reply"),
        );

        let lines = answered_in_detail(Reader::default(), &host);
        let arp = lines
            .iter()
            .find(|line| line.contains("ARP"))
            .expect("the reason is listed");

        assert!(arp.contains("an address resolution reply"), "{arp}");
        assert!(!arp.contains("via"), "{arp}");
    }

    /// A source address identifies a machine as surely as the host's own does,
    /// so it is masked when the run is redacting.
    #[test]
    fn a_source_address_is_masked_under_redaction() {
        use zond_engine::model::host::status::{StatusProtocol, StatusReason};

        let router: IpAddr = "2001:db8::254".parse().expect("an address");
        let mut host = host(1);
        host.record_evidence(
            zond_engine::HostStatus::Up,
            StatusReason::new(StatusProtocol::IcmpUnreachable, "unreachable").from_source(router),
        );

        let masked = answered_in_detail(Reader::new(Redaction::Standard), &host).join(" ");
        assert!(
            !masked.contains("2001:db8::254"),
            "redaction stopped at the header: {masked}"
        );
    }

    // -----------------------------------------------------------------------
    // The evidence behind a verdict
    // -----------------------------------------------------------------------

    /// The distinction the whole flag exists to draw.
    ///
    /// Two ports, both `filtered`, and the word is all a reader had. One was
    /// dropped by a firewall that said so and one answered nothing at all: the
    /// first is somebody's policy and the second is an absence, which is only as
    /// good as the scan that waited for it.
    #[test]
    fn two_filtered_ports_that_read_alike_are_told_apart_by_their_evidence() {
        use zond_engine::model::port::discovery::{Discovery, ScanResponse};

        let refused = Port::new(80, Protocol::Tcp, PortState::Filtered)
            .with_discovery(Discovery::new(ScanResponse::IcmpProhibited));
        let silent = Port::new(443, Protocol::Tcp, PortState::Filtered)
            .with_discovery(Discovery::new(ScanResponse::NoResponse));

        assert_eq!(
            reason_detail(&refused).expect("evidence").value,
            "ICMP prohibited"
        );
        assert_eq!(reason_detail(&silent).expect("evidence").value, "no reply");
    }

    /// A port carrying no telemetry gets no line, rather than an invented one.
    #[test]
    fn a_port_with_no_telemetry_claims_no_evidence() {
        assert!(reason_detail(&Port::new(22, Protocol::Tcp, PortState::Open)).is_none());
    }

    /// Everything the telemetry has, in one value, and nothing it does not.
    #[test]
    fn the_evidence_carries_what_was_measured_and_leaves_out_what_was_not() {
        use std::time::Duration;
        use zond_engine::model::port::discovery::{Discovery, ScanResponse};

        let bare = Port::new(22, Protocol::Tcp, PortState::Open)
            .with_discovery(Discovery::new(ScanResponse::TcpSynAck));
        assert_eq!(reason_detail(&bare).expect("evidence").value, "SYN/ACK");

        let measured = Port::new(22, Protocol::Tcp, PortState::Open).with_discovery(
            Discovery::new(ScanResponse::TcpSynAck)
                .with_ttl(64)
                .with_rtt(Duration::from_micros(2_240)),
        );
        let value = reason_detail(&measured).expect("evidence").value;
        assert!(value.starts_with("SYN/ACK  ttl 64  "), "{value}");
    }

    /// The evidence hangs off the port only when it was asked for, and above the
    /// certificate working, which is a different reader's question.
    #[test]
    fn evidence_is_shown_only_when_asked_for() {
        use zond_engine::model::port::discovery::{Discovery, ScanResponse};

        let mut host = host(1);
        host.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open)
                .with_discovery(Discovery::new(ScanResponse::TcpSynAck)),
        );

        let quiet = port_listings(&[&host], true, Showing::default());
        assert!(quiet[0].rows[0].detail.is_empty(), "{:?}", quiet[0].rows[0]);

        let asked = port_listings(
            &[&host],
            true,
            Showing {
                certificates: false,
                reasons: true,
                ..Default::default()
            },
        );
        assert_eq!(asked[0].rows[0].detail[0].label, "reason");
    }

    /// The port table is measured across the listing, not across one host.
    ///
    /// A host whose highest port is `9100/tcp` and one whose highest is `80/tcp`
    /// used to put `open` in different columns, because each measured its own
    /// table. `block` says the alignments worth having are the ones between
    /// blocks, and this was the one child that did not get them.
    #[test]
    fn two_hosts_put_their_port_states_in_one_column() {
        let mut low = host(1);
        low.add_port(Port::new(80, Protocol::Tcp, PortState::Open));

        let mut high = host(2);
        high.add_port(Port::new(9100, Protocol::Tcp, PortState::Open));

        let listings = port_listings(&[&low, &high], true, Showing::default());

        assert_eq!(
            listings[0].rows[0].port.chars().count(),
            listings[1].rows[0].port.chars().count(),
            "{:?} and {:?} were padded apart",
            listings[0].rows[0].port,
            listings[1].rows[0].port
        );
    }

    /// `minimal` has nothing to hang a line from, so the evidence rides on the
    /// row it qualifies.
    #[test]
    fn the_terse_mode_carries_the_evidence_on_the_row() {
        use zond_engine::model::port::discovery::{Discovery, ScanResponse};

        let mut host = host(1);
        host.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open)
                .with_discovery(Discovery::new(ScanResponse::TcpSynAck)),
        );

        let lines = ports(
            &host,
            true,
            Showing {
                certificates: false,
                reasons: true,
                ..Default::default()
            },
        );
        assert!(lines[0].ends_with("[SYN/ACK]"), "{}", lines[0]);
    }

    /// An unfinished TLS walk rides on the row too, unasked for: it qualifies
    /// the `risk` lines this mode draws from the same walk, and those are
    /// drawn whatever the flags say.
    #[test]
    fn the_terse_mode_carries_an_unfinished_tls_walk_on_the_row() {
        use zond_engine::model::port::Security;
        use zond_engine::model::tls::{Interruption, TlsSupport, TlsVersion, UnfinishedVersion};

        let mut host = host(1);
        host.add_port(
            Port::new(443, Protocol::Tcp, PortState::Open).with_security(
                Security::new().with_support(TlsSupport::new().leaving_unfinished(
                    UnfinishedVersion::new(TlsVersion::Tls12, Interruption::Unanswered),
                )),
            ),
        );

        let lines = ports(&host, true, Showing::default());
        assert!(
            lines[0].ends_with("[suites TLSv1.2  unfinished, unanswered]"),
            "{}",
            lines[0]
        );
    }

    /// A response this build has no word for is spelled as the wire spells it,
    /// rather than being given prose whose meaning nobody knows.
    #[test]
    fn an_unrecognised_response_falls_back_to_the_name_the_wire_uses() {
        use zond_engine::model::port::discovery::ScanResponse;

        assert_eq!(
            spoken_response(&ScanResponse::Custom("tls-alert".to_owned())),
            "tls-alert"
        );
    }

    /// The ladder a span is written on, and the rung where it parts company with
    /// [`age`].
    ///
    /// A span under a minute keeps its seconds. `age` calls that `now`, which is
    /// the right answer to "how recent is this" and the wrong one to "how long
    /// did it take": a fold of two scans seconds apart would report itself as
    /// having drawn on `now` of scanning.
    #[test]
    fn a_span_is_written_in_the_largest_unit_that_says_something() {
        assert_eq!(span(Duration::from_millis(340)), "0.34s");
        assert_eq!(span(Duration::from_secs(6)), "6.00s");
        assert_eq!(span(Duration::from_secs(59)), "59.00s");
        assert_eq!(span(Duration::from_secs(60)), "1m");
        assert_eq!(span(Duration::from_secs(18 * 60)), "18m");
        assert_eq!(span(Duration::from_secs(3600)), "1h");
        assert_eq!(span(Duration::from_secs(86_400)), "1d");
        assert_eq!(span(Duration::from_secs(341 * 86_400)), "341d");
    }

    use super::*;
    use crate::render::test_support::host;

    use std::net::Ipv4Addr;
    use zond_engine::Service;
    use zond_engine::model::host::NetworkRole;
    use zond_engine::model::host::path::Hop;
    use zond_engine::model::host::status::{StatusProtocol, StatusReason};
    use zond_engine::model::ip::scoped::Zone;

    /// A hardware address as six octets, from the way it is written.
    fn mac(text: &str) -> [u8; 6] {
        octets(text).expect("a hardware address")
    }

    /// An IPv6 address, from the way it is written.
    fn ip(text: &str) -> Ipv6Addr {
        text.parse().expect("an address")
    }

    /// The same, spelled for the tests that were written before `ip` existed.
    fn v6(text: &str) -> Ipv6Addr {
        ip(text)
    }

    /// A round trip in whole milliseconds.
    fn ms(millis: u64) -> Duration {
        Duration::from_micros(millis * 1000)
    }

    /// A scanned host, arranged so the two sort orders disagree: the filtered
    /// port has the *lowest* number, so a listing sorted by number alone would
    /// lead with it, and the UDP port falls between two TCP ones.
    fn scanned() -> Host {
        let mut host = host(1);
        host.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open).with_service(
                Service::new("ssh", 100)
                    .with_product("OpenSSH")
                    .with_version("9.6"),
            ),
        );
        host.add_port(Port::new(443, Protocol::Tcp, PortState::Open));
        host.add_port(Port::new(53, Protocol::Udp, PortState::Open));
        host.add_port(Port::new(21, Protocol::Tcp, PortState::Filtered));
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Closed));
        host
    }

    /// A host with a measured hop at each of `distances`.
    fn traced(distances: &[u8]) -> Host {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        for &distance in distances {
            host.record_hop(Hop::answered(
                distance,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, distance)),
                None,
            ));
        }
        host
    }

    /// Every value a two-space-separated list can hold is one unbroken token.
    ///
    /// This is the whole reason for the underscore. A block separates values
    /// with two spaces, so a value carrying a space of its own leaves the list
    /// with no edges: `ARP  ICMP echo  NDP` is three things or four depending on
    /// how carefully you look, and nothing on the line says which.
    ///
    /// The table below is checked because it can be, but the branch that matters
    /// is the last one: a name a *host* chose, or one a newer engine added that
    /// this build has no arm for.
    #[test]
    fn nothing_a_two_space_list_holds_carries_a_space_of_its_own() {
        let known = [
            StatusProtocol::Arp,
            StatusProtocol::Ndp,
            StatusProtocol::IcmpEcho,
            StatusProtocol::IcmpUnreachable,
            StatusProtocol::TcpSyn,
            StatusProtocol::Tcp,
            StatusProtocol::Dhcp,
            StatusProtocol::Udp,
            StatusProtocol::Custom(std::sync::Arc::from("mdns responder")),
        ];

        for protocol in known {
            let written = spoken(&protocol);
            assert!(
                !written.contains(' '),
                "'{written}' would break the list it is drawn into"
            );
            assert!(!written.is_empty(), "{protocol:?} spells as nothing");
        }

        assert_eq!(
            spoken(&StatusProtocol::Custom(std::sync::Arc::from(
                "mdns responder"
            ))),
            "MDNS_RESPONDER"
        );
        assert_eq!(spoken(&StatusProtocol::IcmpEcho), "ICMP_echo");
        assert_eq!(spoken(&StatusProtocol::TcpSyn), "TCP_SYN");
    }

    /// The banner is read once by a person; a record is compared by a machine.
    /// Neither is derived from the other, because they answer to different
    /// masters: one may be reworded whenever it reads better, and the other may
    /// never change at all.
    #[test]
    fn a_moment_reads_and_a_timestamp_compares() {
        let at = std::time::UNIX_EPOCH + Duration::from_micros(1_700_000_000_123_456);

        assert_eq!(timestamp(at), "2023-11-14T22:13:20.123456Z");

        // Not asserted against a fixed answer: what the wall clock said depends
        // on where this test is running, and one that only passes in one
        // timezone is one that fails in CI.
        let shown = moment(at);
        assert!(!shown.contains('T'), "still a machine format: {shown}");
        assert!(!shown.ends_with('Z'), "claims to be UTC: {shown}");
        assert!(
            !shown.contains(".123456"),
            "kept precision nobody reads: {shown}"
        );
        assert!(
            shown.contains('+') || shown.contains('-'),
            "no offset, so it cannot be lined up against anything: {shown}"
        );
    }

    // ── Roles ────────────────────────────────────────────────────────────────

    /// The order is the engine's, not the set's.
    ///
    /// `network_roles` is a `HashSet`, so its iteration order is whatever its
    /// hashing produced. Two runs that found the same roles would print them
    /// differently, and a golden test would pass or fail by luck. Inserted here
    /// in reverse to prove the output does not follow insertion either.
    #[test]
    fn roles_are_listed_in_the_engines_order_and_not_the_sets() {
        let mut scanned = host(1);
        for role in NetworkRole::ALL.into_iter().rev() {
            scanned.add_network_role(role);
        }

        let listed = packed_roles(&scanned).expect("every role");
        let expected: Vec<&str> = NetworkRole::ALL
            .into_iter()
            .map(zond_engine::record::wire::network_role_name)
            .collect();

        assert_eq!(listed, expected.join(","));
    }

    /// A reader and a script are given different spellings on purpose. The
    /// engine documents its label as the one to reword when it reads better,
    /// and the wire name as the one that may never change; deriving either from
    /// the other would tie them back together.
    ///
    /// The reader's form keeps the acronyms in capitals and leaves the ordinary
    /// words alone, which is the rule [`spoken`] applies to protocols. The
    /// script's form is lower case throughout, because a pattern that has to
    /// know which of eight names is an initialism is not a pattern anyone will
    /// write correctly.
    #[test]
    fn a_role_is_spelled_one_way_for_a_reader_and_another_for_a_script() {
        let mut scanned = host(1);
        scanned.add_network_role(NetworkRole::Router);
        scanned.add_network_role(NetworkRole::DnsServer);

        assert_eq!(roles(&scanned).as_deref(), Some("router  DNS"));
        assert_eq!(role_tags(&scanned).as_deref(), Some("router, dns"));
        assert_eq!(packed_roles(&scanned).as_deref(), Some("router,dns"));
    }

    /// A role is one token too, for the same reason a protocol is.
    #[test]
    fn no_role_carries_a_space() {
        for role in NetworkRole::ALL {
            assert!(
                !role.label().contains(' '),
                "'{}' would break the list it is drawn into",
                role.label()
            );
        }
    }

    /// The two spellings are the same word in two registers.
    ///
    /// Which of them shouts is the engine's judgement and is asserted beside
    /// [`NetworkRole::label`], not here. Whether `DNS` is an acronym is not
    /// something this crate gets a vote on. What *is* this crate's business is
    /// that the two forms never drift into naming different things, since a
    /// reader who grepped a block for `router` and then grepped a record for it
    /// has every right to find the same hosts.
    ///
    /// Title case is refused outright: an acronym shouts and a word does not,
    /// and `Router` is neither.
    #[test]
    fn the_two_spellings_of_a_role_are_one_word() {
        for role in NetworkRole::ALL {
            let spoken = role.label();
            let written = zond_engine::record::wire::network_role_name(role);

            assert_eq!(
                spoken.to_ascii_lowercase(),
                written,
                "'{spoken}' and '{written}' are not the same word"
            );

            let shouts = spoken.chars().all(|letter| letter.is_ascii_uppercase());
            let quiet = spoken.chars().all(|letter| !letter.is_ascii_uppercase());
            assert!(
                shouts || quiet,
                "'{spoken}' is in title case, which is neither an acronym nor a word"
            );
        }
    }

    /// A host nothing was established about says nothing, rather than saying it
    /// has no roles, which would read as a finding.
    #[test]
    fn a_host_with_no_roles_reports_none() {
        assert_eq!(roles(&host(1)), None);
        assert_eq!(role_tags(&host(1)), None);
        assert_eq!(packed_roles(&host(1)), None);
    }

    /// Six octets, in either separator, and nothing else.
    #[test]
    fn a_hardware_address_is_read_back_out_of_its_spelling() {
        assert_eq!(
            octets("c8:52:61:c7:05:94"),
            Some([0xc8, 0x52, 0x61, 0xc7, 0x05, 0x94])
        );
        assert_eq!(octets("C8-52-61-C7-05-94"), octets("c8:52:61:c7:05:94"));

        for refused in [
            "",
            "c8:52:61:c7:05",
            "c8:52:61:c7:05:94:aa",
            "zz:52:61:c7:05:94",
        ] {
            assert_eq!(octets(refused), None, "accepted {refused:?}");
        }
    }

    /// The three link-local addresses in the sweep that started all this are the
    /// hardware address on the line above them, written again.
    #[test]
    fn a_link_local_formed_from_the_mac_is_the_mac_again() {
        for (hardware, address) in [
            ("c8:52:61:c7:05:94", "fe80::ca52:61ff:fec7:594"),
            ("dc:cd:2f:92:82:62", "fe80::decd:2fff:fe92:8262"),
            ("28:87:61:53:ef:8e", "fe80::2a87:61ff:fe53:ef8e"),
        ] {
            assert!(
                restates(mac(hardware), ip(address)),
                "{hardware} does form {address}"
            );
        }
    }

    /// The fourth does not: a host using RFC 7217 stable-privacy addressing
    /// picked an identifier that is not derived from anything else on the
    /// screen, so it carries information and keeps its line.
    #[test]
    fn a_stable_privacy_link_local_is_a_finding_of_its_own() {
        assert!(!restates(
            mac("2c:cf:67:27:15:bc"),
            ip("fe80::a3cd:515a:be67:a12a")
        ));
    }

    /// A global address built the same way is reachable from off the segment and
    /// is a finding whatever it was derived from. Only the link-local is a
    /// restatement.
    #[test]
    fn a_global_address_is_never_a_restatement() {
        assert!(!restates(
            mac("c8:52:61:c7:05:94"),
            ip("2a02:908:8c1:b880:ca52:61ff:fec7:594")
        ));
    }

    /// The universal/local bit is what the construction flips, and forgetting it
    /// is the way to get this subtly wrong: the address would then match a
    /// hardware address two bits away from the real one.
    #[test]
    fn the_universal_local_bit_has_to_have_been_flipped() {
        assert!(!restates(
            mac("c8:52:61:c7:05:94"),
            ip("fe80::c852:61ff:fec7:594")
        ));
    }

    #[test]
    fn a_vendor_loses_the_part_nobody_reads_out() {
        assert_eq!(spoken_vendor("Raspberry Pi Trading Ltd"), "Raspberry Pi");
        assert_eq!(spoken_vendor("Seiko Epson Corp"), "Seiko Epson");
        assert_eq!(spoken_vendor("Arris Group, Inc"), "Arris");
        assert_eq!(spoken_vendor("Cisco Systems, Inc."), "Cisco Systems");
        assert_eq!(spoken_vendor("Nokia Oyj"), "Nokia Oyj");
    }

    /// The first word always survives, however many of the words after it are
    /// on the list. An empty vendor column is worse than an odd one.
    #[test]
    fn the_first_word_of_a_vendor_always_survives() {
        assert_eq!(spoken_vendor("Ltd"), "Ltd");
        assert_eq!(spoken_vendor("Trading Ltd"), "Trading");
        assert_eq!(spoken_vendor("Group Holdings Ltd"), "Group");
        assert!(!spoken_vendor("Inc Inc Inc").is_empty());
    }

    /// A vendor with nothing to trim is left exactly as it was.
    #[test]
    fn a_vendor_with_no_suffix_is_untouched() {
        assert_eq!(spoken_vendor("Apple"), "Apple");
        assert_eq!(
            spoken_vendor("Icann, Iana Department"),
            "Icann, Iana Department"
        );
    }

    // ── The path to a host ───────────────────────────────────────────────────

    /// A path renders its distances wide enough to align and no wider, and the
    /// value never *begins* with the padding.
    ///
    /// Two properties, and the second is the one that broke. The addresses have
    /// to line up under each other, which means the distance column is as wide
    /// as the furthest hop. And a value that starts with a space starts one
    /// column right of every other value in the block. `path` is the only tagged
    /// value built from a number, so it is the only one that can.
    #[test]
    fn a_path_aligns_its_addresses_without_indenting_the_value() {
        for distances in [&[1u8, 2][..], &[1, 9, 12][..], &[7][..]] {
            for line in path(Reader::default(), &traced(distances)) {
                assert!(
                    !line.starts_with(' '),
                    "a value that starts with a space starts in the wrong column: {line:?}"
                );
            }
        }

        let lines = path(Reader::default(), &traced(&[1, 9, 12]));
        let columns: Vec<usize> = lines
            .iter()
            .map(|line| line.find("10.0.0.").expect("an address"))
            .collect();

        assert!(
            columns.windows(2).all(|pair| pair[0] == pair[1]),
            "addresses start in different columns: {lines:?}"
        );
    }

    /// A router the exclusions forbid naming reads as excluded at its own
    /// distance, and a router that stayed silent still reads as `*`. The two are
    /// different findings: one router answered and may not be named, the other
    /// never said anything.
    #[test]
    fn a_withheld_router_reads_as_excluded_and_a_silent_one_as_a_star() {
        let mut host = traced(&[1]);
        host.record_hop(Hop::withheld(2));
        host.record_hop(Hop::silent(3));

        assert_eq!(
            path(Reader::default(), &host),
            vec!["1. 10.0.0.1", "2. excluded", "3. *"]
        );
    }

    // ── Ports a scan is entitled to claim ────────────────────────────────────

    /// A report of one phase whose scanner was outrun or was not, and left
    /// `unanswered` of `targets` probes without a reply.
    fn paced(targets: u128, unanswered: u128, at_floor: bool) -> zond_engine::ScanReport {
        use std::time::{Duration, SystemTime};

        use zond_engine::ZondConfig;
        use zond_engine::model::exclusion::Exclusions;
        use zond_engine::model::parse::ip::to_set;
        use zond_engine::report::{
            ATTEMPTS_COUNTED, BUCKET_BOUNDS_MS, PhaseParts, ProbeStats, ProbeStatsParts, ScanKind,
            ScanPhase, ScanReport, ScanSettings, ScannerKind, StopReason, TargetScope,
            WindowSummary,
        };

        let probes = ProbeStats::from_parts(ProbeStatsParts {
            scanner: ScannerKind::SynPort,
            targets,
            stop_reason: StopReason::AttemptsSpent,
            elapsed: Duration::from_secs(1),
            sends_attempted: 0,
            sends_failed: 0,
            sends_witnessed: 0,
            segments_seen: 0,
            window: Some(WindowSummary {
                capacity: 1,
                peak: 64,
                reductions: 9,
                adaptive: true,
                at_floor,
            }),
            segments_off_target: 0,
            replies_without_rtt: 0,
            hosts_found: u64::try_from(targets - unanswered).expect("a small fixture"),
            answered_on: [0; ATTEMPTS_COUNTED],
            answered_unattributed: 0,
            first_reply: None,
            last_reply: None,
            found_at: [0; BUCKET_BOUNDS_MS.len() + 1],
            capture: None,
        });

        let mut scope = to_set(&["192.0.2.1"], None, None).expect("an address");
        let phase = ScanPhase::from_parts(PhaseParts {
            attachments: Vec::new(),
            kind: ScanKind::PortScan,
            started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_000_000),
            elapsed: Duration::from_secs(1),
            privilege: Some(Privilege::Raw),
            targets: TargetScope::from_ip_set(&mut scope, &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            refusals: Vec::new(),
            unroutable: Vec::new(),
            timed_out: Vec::new(),
            reached_by_connect: Vec::new(),
            probes: vec![probes],
            origin: None,
        });

        ScanReport::recorded("test", vec![phase], Vec::new())
    }

    /// Both halves of the rule are needed, and neither alone means anything.
    ///
    /// A window at its floor with everything answered is a polite scan that
    /// worked. A tenth of the probes unanswered with the window never cut is a
    /// genuinely quiet host, which is a finding. Only the two together mean the
    /// scan could not ask, and only then are its silences withheld.
    #[test]
    fn only_an_outrun_scan_with_probes_it_never_got_answers_for_withholds_its_silence() {
        assert!(
            silence_means_something(&paced(100, 50, false)),
            "a scan that was never cut back asked properly, however quiet the host"
        );
        assert!(
            silence_means_something(&paced(100, 0, true)),
            "a scan at its floor that got every answer asked properly too"
        );
        assert!(
            !silence_means_something(&paced(100, 50, true)),
            "outrun and half unanswered is a scan that ran out of link"
        );
    }

    /// The threshold is one probe in ten, and the arithmetic is exact.
    ///
    /// Held as a divisor rather than as `0.10`, because a probe count is a
    /// `u128` and a full-range scan of a `/16` does not fit a `f64`'s mantissa.
    #[test]
    fn the_share_that_withholds_a_silence_is_one_probe_in_ten_exactly() {
        assert!(
            silence_means_something(&paced(100, 9, true)),
            "nine in a hundred is under the share"
        );
        assert!(
            !silence_means_something(&paced(100, 10, true)),
            "ten in a hundred is the share"
        );

        // A count no `f64` can hold without rounding, at exactly the boundary
        // and one probe under it. In floating point both of these round to the
        // same number and the second would be withheld with the first.
        let enormous = (1u128 << 60) * 10;
        assert!(!silence_means_something(&paced(
            enormous,
            enormous / 10,
            true
        )));
        assert!(silence_means_something(&paced(
            enormous,
            enormous / 10 - 1,
            true
        )));
    }

    /// A scanner that asked nothing has no share to speak of, and dividing by
    /// its target count would be a division by zero.
    #[test]
    fn a_scanner_with_no_targets_withholds_nothing() {
        assert!(silence_means_something(&paced(0, 0, true)));
    }

    /// A scan that could not tell filtered from lost has no filtered ports to
    /// report, only ports it never reached.
    ///
    /// The failure this exists to prevent: a full-range scan from a wireless
    /// laptop printed a warning saying it had been outrun, and then printed
    /// forty-two thousand `filtered` rows underneath it, which are positive
    /// claims about a firewall on a host that has none. A warning contradicted
    /// by the rows below it is a footnote nobody reads.
    #[test]
    fn a_scan_that_was_outrun_reports_no_filtered_ports() {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        host.set_status(HostStatus::Up);
        host.add_port(Port::new(22, Protocol::Tcp, PortState::Open));
        for number in 100..140u16 {
            host.add_port(Port::new(number, Protocol::Tcp, PortState::Filtered));
        }

        let trusted = ports(&host, true, Showing::default());
        assert!(
            trusted.iter().any(|line| line.contains("filtered")),
            "a scan that could ask reports what it found: {trusted:?}"
        );

        let outrun = ports(&host, false, Showing::default());
        assert!(
            outrun.iter().all(|line| !line.contains("filtered")),
            "and one that could not makes no claim at all: {outrun:?}"
        );
        assert!(
            outrun
                .iter()
                .any(|line| line.contains("40 ports unanswered")
                    && line.contains("silence is not a verdict")),
            "but says how many went unanswered, and that it cannot read them: {outrun:?}"
        );
        assert!(
            outrun.iter().any(|line| line.starts_with("22/tcp")),
            "the open port is a finding either way: {outrun:?}"
        );
    }

    // ── Masking ──────────────────────────────────────────────────────────────

    /// Which masker an address gets is decided by two bit tests, and getting
    /// either wrong leaks the thing redaction exists to hide.
    #[test]
    fn an_ipv6_address_is_masked_by_what_kind_of_address_it_is() {
        // fe80::/10. The OUI half of a EUI-64 identifier survives; the device
        // half is the MAC and must not.
        assert_eq!(
            mask(&v6("fe80::200:5eff:fe00:5301")),
            "fe80::200:5eff:XXXX:XXXX"
        );
        assert_eq!(
            mask(&v6("febf::1")),
            "febf::0:0:XXXX:XXXX",
            "the top of fe80::/10"
        );

        // fc00::/7.
        assert_eq!(mask(&v6("fc00::1")), "fc00::XXXX");
        assert_eq!(
            mask(&v6("fd12:3456:789a::1")),
            "fd12::XXXX",
            "the global ID goes"
        );

        assert_eq!(mask(&v6("2001:db8::1")), "2001::XXXX");
    }

    /// `fec0::/10` is deprecated site-local, not a unique-local address. It sits
    /// one bit away from both tests above, which is exactly where a mask goes
    /// wrong.
    #[test]
    fn site_local_is_not_mistaken_for_unique_local() {
        assert_eq!(mask(&v6("fec0::1")), "fec0::XXXX");
    }

    #[test]
    fn redaction_reaches_the_name_and_the_hardware() {
        let mut host = host(1);
        host.set_hostname(Some("router.example".to_owned()));
        host.record_mac("00:00:5e:00:53:01".parse().expect("a valid address"));

        let plain = Reader::default();
        assert_eq!(plain.hostname(&host).as_deref(), Some("router.example"));
        assert_eq!(plain.macs(&host).as_deref(), Some("00:00:5e:00:53:01"));

        let masked = Reader::new(Redaction::Standard);
        assert_ne!(masked.hostname(&host).as_deref(), Some("router.example"));
        assert_ne!(masked.macs(&host).as_deref(), Some("00:00:5e:00:53:01"));
    }

    /// A zone names an interface on *this* machine, so it survives masking.
    /// Without it a link-local address identifies nothing at all.
    #[test]
    fn a_zone_survives_masking() {
        let mut host = Host::new(IpAddr::V6(v6("fe80::1")));
        host.set_zone(Zone::new(4, "en0"));

        assert!(
            Reader::new(Redaction::Standard)
                .primary(&host)
                .ends_with("%en0"),
            "{}",
            Reader::new(Redaction::Standard).primary(&host)
        );
    }

    // ── Addresses ────────────────────────────────────────────────────────────

    #[test]
    fn every_address_is_listed_primary_first() {
        let mut host = host(1);
        host.add_ip(IpAddr::V6(v6("2001:db8::1")));

        assert_eq!(Reader::default().addresses(&host), "192.0.2.1,2001:db8::1");
        assert_eq!(
            Reader::default().other_addresses(&host, false),
            vec!["2001:db8::1".to_owned()]
        );
    }

    #[test]
    fn a_host_at_one_address_has_no_others() {
        assert!(
            Reader::default()
                .other_addresses(&host(1), false)
                .is_empty()
        );
    }

    /// A link-local the host derived from the hardware address the block prints
    /// two lines up is left out, and kept when asked for everything.
    #[test]
    fn a_derived_link_local_is_left_out_unless_everything_was_asked_for() {
        let mut host = host(1);
        host.record_mac("c8:52:61:c7:05:94".parse().expect("a valid address"));
        host.add_ip(IpAddr::V6(v6("fe80::ca52:61ff:fec7:594")));
        host.add_ip(IpAddr::V6(v6("2a02:908:8c1:b880::1")));

        let shown = Reader::default().other_addresses(&host, false);
        assert!(
            shown.iter().all(|address| !address.starts_with("fe80::")),
            "the hardware address was printed twice: {shown:?}"
        );
        assert!(
            shown.iter().any(|address| address.starts_with("2a02:")),
            "a global address is a finding of its own: {shown:?}"
        );

        assert_eq!(Reader::default().other_addresses(&host, true).len(), 2);
    }

    // ── Evidence ─────────────────────────────────────────────────────────────

    /// The engine keeps reasons in a `HashSet`, so they arrive in an order that
    /// differs between processes. Sorting is what makes two runs comparable.
    ///
    /// Deduplicating is a separate job: the set already drops an identical
    /// reason, but two ARP replies recorded with different details are two
    /// members that must still read as one protocol.
    #[test]
    fn evidence_is_sorted_and_names_each_protocol_once() {
        let mut answered = host(1);
        for (protocol, detail) in [
            (StatusProtocol::TcpSyn, "syn-ack"),
            (StatusProtocol::Ndp, "advertisement"),
            (StatusProtocol::IcmpEcho, "reply"),
            (StatusProtocol::Arp, "reply"),
            (StatusProtocol::Arp, "gratuitous"),
        ] {
            answered.add_reason(StatusReason::new(protocol, detail));
        }

        assert_eq!(
            evidence(&answered).as_deref(),
            Some("arp,icmp_echo,ndp,tcp_syn"),
            "the record format cannot afford a space inside a field"
        );
        assert_eq!(
            via(&answered).as_deref(),
            Some("arp, icmp_echo, ndp, tcp_syn"),
            "and a line somebody reads wants one"
        );

        assert_eq!(evidence(&host(2)), None, "nothing answered");
        assert_eq!(via(&host(2)), None);
    }

    // ── Round-trip times ─────────────────────────────────────────────────────

    /// Three thresholds, and the boundaries are where a unit change hides.
    #[test]
    fn a_readable_time_changes_unit_with_its_magnitude() {
        assert_eq!(format_rtt(Duration::from_micros(1_420)), "1.42ms");
        assert_eq!(format_rtt(Duration::from_micros(8_200)), "8.20ms");
        assert_eq!(
            format_rtt(ms(10)),
            "10.0ms",
            "the first millisecond at one decimal"
        );
        assert_eq!(format_rtt(ms(412)), "412.0ms");
        assert_eq!(format_rtt(ms(1_000)), "1.00s", "the first second");
        assert_eq!(format_rtt(ms(1_240)), "1.24s");
    }

    /// The pipe mode's unit never changes, whatever the magnitude. A consumer
    /// reading `1.42ms` and `1.24s` from one column would be a thousand times
    /// wrong the first time a host answered slowly.
    #[test]
    fn a_machine_readable_time_stays_in_milliseconds() {
        let mut quick = host(1);
        quick.add_rtt(Duration::from_micros(412));
        assert_eq!(rtt_millis(&quick).as_deref(), Some("0.412"));

        let mut slow = host(2);
        slow.add_rtt(ms(1_240));
        assert_eq!(rtt_millis(&slow).as_deref(), Some("1240.000"));
    }

    /// One sample, or several that agreed, is one figure. A spread nobody
    /// measured is not worth three numbers that are all the same.
    #[test]
    fn a_time_with_no_spread_prints_as_one_figure() {
        let mut host = host(1);
        host.add_rtt(Duration::from_micros(1_420));

        assert_eq!(rtt_human(&host).as_deref(), Some("1.42ms"));
    }

    /// Samples that differ by less than the precision drawn agree as far as a
    /// reader is concerned, and `min 12.3ms  avg 12.3ms  max 12.3ms` claims a
    /// spread while showing none. The wider band above ten milliseconds rounds
    /// harder, so it is the one that collides in practice.
    #[test]
    fn samples_that_round_together_print_as_one_figure() {
        let mut coarse = host(1);
        coarse.add_rtt(Duration::from_micros(12_310));
        coarse.add_rtt(Duration::from_micros(12_320));
        coarse.add_rtt(Duration::from_micros(12_330));

        assert_eq!(rtt_human(&coarse).as_deref(), Some("12.3ms"));

        let mut fine = host(1);
        fine.add_rtt(Duration::from_micros(6_960));
        fine.add_rtt(Duration::from_micros(6_961));
        fine.add_rtt(Duration::from_micros(6_962));

        assert_eq!(rtt_human(&fine).as_deref(), Some("6.96ms"));
        assert_eq!(rtt_variation(&fine), None);
    }

    #[test]
    fn a_time_with_a_spread_shows_all_of_it() {
        let mut host = host(1);
        host.add_rtt(ms(1));
        host.add_rtt(ms(50));

        let shown = rtt_human(&host).expect("two samples");
        assert!(shown.contains("min"), "{shown}");
        assert!(shown.contains("max"), "{shown}");
    }

    #[test]
    fn a_host_that_never_answered_has_no_time() {
        assert_eq!(rtt_human(&host(1)), None);
        assert_eq!(rtt_millis(&host(1)), None);
    }

    // ── Ports ────────────────────────────────────────────────────────────────

    /// Open first, then by number, with the closed ones counted rather than
    /// listed, and the identifiers padded so the verdicts line up.
    #[test]
    fn ports_are_listed_open_first_with_the_closed_ones_counted() {
        assert_eq!(
            ports(&scanned(), true, Showing::default()),
            vec![
                // Columns, so the eye runs down the states rather than hunting
                // each one at whatever offset its port number left it at.
                "22/tcp   open      ssh OpenSSH 9.6",
                "53/udp   open",
                "443/tcp  open",
                "21/tcp   filtered",
                "5 probed, 1 closed",
            ]
        );
    }

    /// A wall of filtered ports is one fact, not six hundred of them.
    ///
    /// Measured, on a consumer router probed faster than it would answer: nine
    /// hundred lines of `filtered`, with `80/tcp` buried among them. The first
    /// few still print, because *which* ports a firewall refuses matters when
    /// the list starts at 22, and the rest are counted.
    #[test]
    fn a_flood_of_filtered_ports_is_counted_rather_than_listed() {
        let mut host = host(1);
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
        for port in 1..=40u16 {
            host.add_port(Port::new(port + 1000, Protocol::Tcp, PortState::Filtered));
        }

        let lines = ports(&host, true, Showing::default());

        // The open port, twelve filtered, and the rollup.
        assert_eq!(lines.len(), 1 + MAX_LISTED_FILTERED + 1);
        assert!(lines[0].starts_with("80/tcp"), "open first: {lines:?}");
        assert!(
            lines[1].starts_with("1001/tcp"),
            "and the lowest filtered ones are the ones kept: {lines:?}"
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some("28 more filtered ports not listed")
        );
    }

    /// An ICMP-refused port survives the suppression an outrun scan applies to
    /// its silent ports.
    #[test]
    fn a_port_refused_in_words_survives_a_scan_that_was_outrun() {
        let mut host = host(1);
        let quiet = Port::new(81, Protocol::Tcp, PortState::Filtered)
            .with_discovery(Discovery::new(ScanResponse::NoResponse));
        let refused = Port::new(82, Protocol::Tcp, PortState::Filtered)
            .with_discovery(Discovery::new(ScanResponse::IcmpProhibited));
        host.add_port(quiet);
        host.add_port(refused);

        let lines = ports(&host, false, Showing::default());

        assert!(
            lines.iter().any(|line| line.starts_with("82/tcp")),
            "the firewall answered for this one: {lines:?}"
        );
        assert!(
            !lines.iter().any(|line| line.starts_with("81/tcp")),
            "and this one is still only silence: {lines:?}"
        );
    }

    /// A wall of unasked ports is counted, not listed, as a flood of filtered
    /// ones already is.
    #[test]
    fn a_flood_of_unasked_ports_is_counted_rather_than_listed() {
        let mut host = host(1);
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
        for port in 1..=40u16 {
            host.add_port(Port::new(port + 1000, Protocol::Tcp, PortState::Unasked));
        }

        let lines = ports(&host, true, Showing::default());

        // The open port, six unasked, and the rollup.
        assert_eq!(lines.len(), 1 + MAX_LISTED_UNASKED + 1);
        assert!(lines[0].starts_with("80/tcp"), "open first: {lines:?}");
        assert!(
            lines[1].starts_with("1001/tcp"),
            "and the lowest unasked ones are the ones kept: {lines:?}"
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some("34 more unasked ports not listed")
        );
    }

    /// A handful of unasked ports reads in full; the rollup is for the flood.
    #[test]
    fn a_handful_of_unasked_ports_is_listed_in_full() {
        let mut host = host(1);
        for port in [22u16, 23, 111] {
            host.add_port(Port::new(port, Protocol::Tcp, PortState::Unasked));
        }

        let lines = ports(&host, true, Showing::default());
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines.iter().all(|line| !line.contains("not listed")),
            "{lines:?}"
        );
    }

    /// A firewall policy small enough to read is still printed in full: the
    /// rollup exists for the case that buries a result, not for every host with
    /// a closed service.
    #[test]
    fn a_handful_of_filtered_ports_is_listed_in_full() {
        let mut host = host(1);
        for port in [22u16, 23, 111] {
            host.add_port(Port::new(port, Protocol::Tcp, PortState::Filtered));
        }

        let lines = ports(&host, true, Showing::default());
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines.iter().all(|line| !line.contains("omitted")),
            "{lines:?}"
        );
    }

    /// A host whose every port came back shut still says so. The rollup is then
    /// the whole list rather than a footnote to one.
    #[test]
    fn a_host_with_nothing_open_says_so() {
        let mut host = host(1);
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Closed));

        assert_eq!(
            ports(&host, true, Showing::default()),
            vec!["1 probed, 1 closed"]
        );
    }

    #[test]
    fn the_closed_rollup_counts_in_the_plural() {
        let mut host = host(1);
        for number in [80, 443] {
            host.add_port(Port::new(number, Protocol::Tcp, PortState::Closed));
        }

        assert_eq!(
            ports(&host, true, Showing::default()),
            vec!["2 probed, 2 closed"]
        );
    }

    #[test]
    fn a_host_that_was_never_port_scanned_has_no_port_lines() {
        assert!(ports(&host(1), true, Showing::default()).is_empty());
        assert_eq!(closed_ports(&host(1)), None);
    }

    /// One field, sub-delimited, so a record stays one line and one host.
    #[test]
    fn packed_ports_carry_number_protocol_state_and_service() {
        assert_eq!(
            packed_ports(&scanned()).as_deref(),
            Some("21/tcp/filtered/-,22/tcp/open/ssh,443/tcp/open/-,53/udp/open/-"),
            "grouped by protocol, then by number, which is a different order from the listing"
        );
        assert_eq!(closed_ports(&scanned()).as_deref(), Some("1"));
    }

    /// The engine's `???` is a placeholder, not a service name, and printing it
    /// would put a column of them beside most ports.
    #[test]
    fn the_no_service_sentinel_is_never_shown_as_a_name() {
        let mut host = host(1);
        host.add_port(
            Port::new(9999, Protocol::Tcp, PortState::Open)
                .with_service(Service::new(NO_SERVICE, 0)),
        );

        assert_eq!(
            ports(&host, true, Showing::default()),
            vec!["9999/tcp  open"]
        );
        assert_eq!(packed_ports(&host).as_deref(), Some("9999/tcp/open/-"));
    }

    // ── Spellings ────────────────────────────────────────────────────────────

    /// These are values a script matches on. Deriving them from variant names
    /// would let a rename in the engine change this program's output.
    #[test]
    fn a_compound_port_state_keeps_its_hyphen() {
        assert_eq!(state(PortState::Open), "open");
        assert_eq!(state(PortState::OpenFiltered), "open-filtered");
        assert_eq!(state(PortState::ClosedFiltered), "closed-filtered");
        assert_eq!(protocol(Protocol::Tcp), "tcp");
        assert_eq!(protocol(Protocol::Udp), "udp");
    }

    #[test]
    fn a_protocol_that_proved_a_host_alive_has_a_stable_name() {
        assert_eq!(protocol_name(&StatusProtocol::Arp), "arp");
        assert_eq!(protocol_name(&StatusProtocol::IcmpEcho), "icmp_echo");
        assert_eq!(protocol_name(&StatusProtocol::TcpSyn), "tcp_syn");
    }

    #[test]
    fn a_status_is_only_shown_when_it_is_not_simply_up() {
        assert!(is_up(&host(1)));
        assert_eq!(status(&host(1)), "Up");

        let down = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        assert!(!is_up(&down));
    }

    /// "address" is the word that caught this out: appending a bare `s` to it
    /// produces "addresss", which every discovery header printed.
    #[test]
    fn a_word_ending_in_s_takes_es_and_every_other_word_takes_s() {
        assert_eq!(plural(1, "address"), "address");
        assert_eq!(plural(16, "address"), "addresses");

        assert_eq!(plural(0, "host"), "hosts");
        assert_eq!(plural(1, "host"), "host");
        assert_eq!(plural(3, "probe"), "probes");
        assert_eq!(plural(2, "port"), "ports");
    }

    // ── Times ────────────────────────────────────────────────────────────────

    /// An age is the largest unit that still says something, so a listing reads
    /// at a glance rather than by arithmetic.
    #[test]
    fn an_age_uses_the_largest_useful_unit() {
        let ago = |seconds| std::time::SystemTime::now() - Duration::from_secs(seconds);

        assert_eq!(age(ago(0)), "now");
        assert_eq!(age(ago(59)), "now");
        assert_eq!(age(ago(60)), "1m");
        assert_eq!(age(ago(3_599)), "59m");
        assert_eq!(age(ago(3_600)), "1h");
        assert_eq!(age(ago(86_399)), "23h");
        assert_eq!(age(ago(86_400)), "1d");
        assert_eq!(age(ago(90 * 86_400)), "90d");
    }

    /// A record from a machine whose clock was ahead reads as new, not as a
    /// negative age or a panic.
    #[test]
    fn an_age_from_the_future_reads_as_now() {
        assert_eq!(
            age(std::time::SystemTime::now() + Duration::from_secs(600)),
            "now"
        );
    }

    // -----------------------------------------------------------------------
    // What a folded report is allowed to claim
    // -----------------------------------------------------------------------

    /// A document from another scanner often records no scope, and a summary
    /// that answered "0 addresses" beside a host count that is not zero reads as
    /// a broken tool rather than as an absence.
    #[test]
    fn a_report_that_states_no_scope_names_no_ground() {
        let report = zond_engine::ScanReport::recorded("nmap 7.94", Vec::new(), vec![host(1)]);

        assert_eq!(addresses_scanned(&report), None);
    }
}
