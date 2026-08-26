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

use zond_engine::Host;
use zond_engine::export::{Redaction, redact};
use zond_engine::model::host::NetworkRole;
use zond_engine::model::host::status::StatusProtocol;
use zond_engine::model::ip::scoped::ScopedIp;
use zond_engine::model::ip::set::IpSet;
use zond_engine::record::wire;
use zond_engine::scanner::report::{ScanKind, ScanPhase};
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
/// back the MAC anyway. That is the branch that matters.
///
/// The unique-local branch is kept for what it says, not for what it does: the
/// engine's `unique_local` and `global_unicast` currently produce the same
/// string, so no output can tell the two apart.
fn mask(ip: &Ipv6Addr) -> String {
    let leading = ip.segments()[0];

    if leading & 0xffc0 == 0xfe80 {
        redact::link_local(ip)
    } else if leading & 0xfe00 == 0xfc00 {
        redact::unique_local(ip)
    } else {
        redact::global_unicast(ip)
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
pub(crate) fn rtt_human(host: &Host) -> Option<String> {
    let median = host.median_rtt()?;
    let (Some(min), Some(max), Some(mean)) = (host.min_rtt(), host.max_rtt(), host.average_rtt())
    else {
        return Some(format_rtt(median));
    };

    if min == max {
        return Some(format_rtt(median));
    }

    Some(format!(
        "min {}  avg {}  max {}",
        format_rtt(min),
        format_rtt(mean),
        format_rtt(max)
    ))
}

/// The fastest round trip a host answered in.
///
/// The figure that answers "how far away is this". The fastest rather than the
/// median because it is the one the network is capable of: a slower reply says
/// the host or the path was busy at that moment, which is a different fact and
/// belongs in [`rtt_variation`].
pub(crate) fn fastest(host: &Host) -> Option<Duration> {
    host.min_rtt().or_else(|| host.median_rtt())
}

/// What the round trips did apart from the fastest, where they did anything.
///
/// `min/avg/max  1.10 / 1.51 / 2.03 ms`, which is the vocabulary somebody
/// reading a scanner already has from `ping`, with one unit for all three
/// figures so they compare against each other directly. The unit is taken from
/// the slowest.
///
/// `None` when every round trip agreed, because then the fastest already said
/// it and three copies of one number say it three times. That is the ordinary
/// case, which is what keeps this out of the way until it means something: a
/// host whose fastest reply is 8 ms and slowest 1.2 s is not 8 ms away, and this
/// is the line that says so.
pub(crate) fn rtt_variation(host: &Host) -> Option<String> {
    let (min, max, mean) = (host.min_rtt()?, host.max_rtt()?, host.average_rtt()?);

    if min == max {
        return None;
    }

    let (divisor, unit) = if max.as_secs_f64() >= 1.0 {
        (1.0, "s")
    } else {
        (0.001, "ms")
    };
    let figure = |rtt: Duration| format!("{:.2}", rtt.as_secs_f64() / divisor);

    Some(format!(
        "min/avg/max  {} / {} / {} {unit}",
        figure(min),
        figure(mean),
        figure(max)
    ))
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
    /// The router, or `*` where it would not identify itself.
    pub address: String,
    /// The round trip, and whether the hop was taken from another host's trace.
    pub detail: Option<String>,
}

/// One entry per router on the way to this host, nearest first.
///
/// Empty when no trace ran, which is every scan that did not ask for one.
///
/// A router that would not identify itself is shown as `*` at its own distance
/// rather than left out, for the reason [`path`] gives.
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
    /// `https nginx 1.24`, where a service was named.
    pub service: Option<String>,
    /// TLS and certificate lines belonging to this port and to no other.
    pub detail: Vec<PortDetail>,
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
        shown.retain(|port| port.state() != PortState::Filtered);
        before - shown.len()
    };

    let filtered_over_limit = shown
        .iter()
        .filter(|port| port.state() == PortState::Filtered)
        .count()
        .saturating_sub(MAX_LISTED_FILTERED);

    if filtered_over_limit > 0 {
        let mut kept = 0usize;
        shown.retain(|port| {
            if port.state() != PortState::Filtered {
                return true;
            }
            kept += 1;
            kept <= MAX_LISTED_FILTERED
        });
    }

    let mut notes = Vec::new();

    if filtered_over_limit > 0 {
        notes.push(format!(
            "[{filtered_over_limit} more filtered {} omitted]",
            plural(filtered_over_limit as u128, "port")
        ));
    }

    if unreachable > 0 {
        notes.push(format!(
            "[{unreachable} {} the scan could not reach; it was outrun, so these are \
             not firewall verdicts]",
            plural(unreachable as u128, "port")
        ));
    }

    if closed > 0 {
        notes.push(format!(
            "[{closed} closed {} omitted]",
            plural(closed as u128, "port")
        ));
    }

    Some(Selection { shown, notes })
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
pub(crate) fn ports(host: &Host, silence_means_something: bool) -> Vec<String> {
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
            line.trim_end().to_owned()
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
/// `detailed` adds the working behind a certificate: who issued it, what key it
/// carries, what it fingerprints to. Everything else is unconditional.
pub(crate) fn port_rows(host: &Host, silence_means_something: bool, detailed: bool) -> PortListing {
    let Some(selection) = select(host, silence_means_something) else {
        return PortListing::default();
    };

    let (widest_port, widest_state) = column_widths(&selection.shown);

    let rows = selection
        .shown
        .iter()
        .map(|port| PortRow {
            port: format!(
                "{:<widest_port$}",
                format!("{}/{}", port.number(), protocol(port.protocol()))
            ),
            state: format!("{:<widest_state$}", state(port.state())),
            verdict: port.state(),
            service: describe(port),
            detail: security_detail(port, detailed),
        })
        .collect();

    PortListing {
        rows,
        notes: selection.notes,
    }
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

/// What is known about the transport under a port, as lines that hang off it.
///
/// Empty for every port nothing negotiated a session on, which is most of them.
fn security_detail(port: &Port, detailed: bool) -> Vec<PortDetail> {
    let Some(security) = port.security() else {
        return Vec::new();
    };

    let mut detail = Vec::new();

    // Version, cipher and protocols on one line: they describe a single
    // negotiated session, and three lines for one handshake would outweigh the
    // port it belongs to. The word "TLS" is not among them, because the label
    // beside them is `tls`.
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
        detail.push(PortDetail::new("tls", session.join("  ")));
    }

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

/// What is listening, where fingerprinting worked it out.
fn describe(port: &Port) -> Option<String> {
    let service = port.service()?;
    if !named(&service.name()) {
        return None;
    }

    let mut described = service.name().to_owned();
    if let Some(product) = service.product()
        // A product that merely repeats the service name says nothing twice:
        // `http http` is what an HTTP server nothing identified more precisely
        // renders as, and the second word is noise in every such row. A
        // tunnelled service names both halves, as in `ssl/http`, so the repeat
        // has to be looked for in each of them, or `ssl/http http` gets through.
        && !described
            .split('/')
            .any(|part| part.eq_ignore_ascii_case(product))
    {
        described.push(' ');
        described.push_str(product);
    }
    if let Some(version) = service.version() {
        described.push(' ');
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
        described.push_str(" (");
        described.push_str(extra);
        described.push(')');
    }

    Some(described)
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

/// What the run was for.
///
/// The *last* phase. A port scan records two, the liveness pass that established
/// anything was there and then the ports, and it is the second that says what
/// the run was asked to do.
pub(crate) fn kind(report: &ScanReport) -> Option<ScanKind> {
    report.phases().last().map(ScanPhase::kind)
}

/// Whether the run this report describes held raw-socket privileges.
///
/// Read from the report rather than asked of the process: the two can disagree,
/// and what matters is what the scan actually had.
pub(crate) fn was_privileged(report: &ScanReport) -> bool {
    report.phases().last().is_some_and(ScanPhase::privileged)
}

/// The counts a summary line is drawn from.
pub(crate) fn summary(report: &ScanReport) -> ScanSummary {
    report.summary()
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

/// What every latency in a listing is written in, or `None` where none was
/// measured.
///
/// One unit for the whole column: `1.20 s` beside `4.87 ms` is two numbers a
/// reader has to convert before they mean anything, and the whole point of the
/// column is that they should not have to.
///
/// **Chosen from the fastest, not the slowest.** The unit has to be able to hold
/// the *smallest* measurement, because that is the one a coarser unit destroys.
/// 4.87 ms written in seconds is `0.01`, and a column of those has thrown away
/// the difference between a router two hops away and one across the room. The
/// largest measurement loses nothing to a finer unit; it takes more columns and
/// says the same thing, and columns are cheap where significant digits are not.
///
/// This is where [`rtt_variation`]'s rule does *not* generalise. A min/avg/max
/// triple belongs to one host and its three figures sit close together, so
/// either end picks a unit that serves all three. A listing's figures are
/// uncorrelated and routinely span four orders of magnitude.
///
/// The space is part of the unit, so the figure can be right-aligned on its
/// digits with nothing between them and the column.
pub(crate) fn listing_unit(fastest: Option<Duration>) -> Option<&'static str> {
    fastest.map(|rtt| {
        if rtt.as_secs_f64() >= 1.0 {
            " s"
        } else {
            " ms"
        }
    })
}

/// One latency as a bare figure in `unit`.
///
/// Two decimals always, whatever the magnitude. A column whose entries carry
/// different precisions does not line up on the decimal point, and lining up on
/// the decimal point is the only reason the column exists: `148.40` beside
/// `4.87` is a comparison, `148.4` beside `4.87` is two strings.
pub(crate) fn listing_figure(rtt: Duration, unit: &'static str) -> String {
    let millis = rtt.as_secs_f64() * 1000.0;

    if unit == " s" {
        format!("{:.2}", millis / 1000.0)
    } else {
        format!("{millis:.2}")
    }
}

/// The quickest round trip anything in this listing managed.
///
/// What picks the listing's unit. `None` when nothing was measured at all,
/// because every host was sniffed rather than probed or answered something that
/// carries no round trip, and then the listing has no latency column.
pub(crate) fn fastest_of(hosts: &[&Host]) -> Option<Duration> {
    hosts.iter().filter_map(|host| host.min_rtt()).min()
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

    /// One unit for the column, taken from the **fastest**, which is the
    /// measurement a coarser unit would destroy.
    ///
    /// A sweep that turns up a 4.87 ms router and a 1.49 s phone has to write
    /// both in milliseconds. Written in seconds the router reads `0.01`, and the
    /// column has thrown away the whole difference it exists to show.
    #[test]
    fn a_listing_takes_its_unit_from_the_fastest_measurement() {
        let quick = Duration::from_micros(4_870);
        let slow = Duration::from_millis(1_490);

        assert_eq!(listing_unit(Some(quick)), Some(" ms"));
        assert_eq!(listing_unit(Some(slow)), Some(" s"));

        // The case that was wrong: both in one listing.
        let unit = listing_unit([quick, slow].into_iter().min()).expect("a unit");
        assert_eq!(unit, " ms");
        assert_eq!(listing_figure(quick, unit), "4.87");
        assert_eq!(
            listing_figure(slow, unit),
            "1490.00",
            "the slow host takes more columns and loses nothing; the quick one \
             would have lost everything"
        );
    }

    /// A listing that measured nothing has no unit, and therefore no column.
    #[test]
    fn a_listing_that_measured_nothing_has_no_unit() {
        assert_eq!(listing_unit(None), None);
    }

    /// Fixed precision, so the decimal points land in one column. This is the
    /// whole reason the figures are worth aligning.
    #[test]
    fn every_figure_carries_the_same_precision() {
        let figures = [
            listing_figure(Duration::from_micros(4_870), " ms"),
            listing_figure(Duration::from_micros(148_400), " ms"),
            listing_figure(Duration::from_micros(183_700), " ms"),
        ];

        assert_eq!(figures, ["4.87", "148.40", "183.70"]);

        let decimals: Vec<usize> = figures
            .iter()
            .map(|figure| figure.len() - figure.find('.').expect("a decimal point"))
            .collect();
        assert!(
            decimals.windows(2).all(|pair| pair[0] == pair[1]),
            "the figures carry different precisions: {figures:?}"
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

    // ── Ports a scan is entitled to claim ────────────────────────────────────

    /// A report of one phase whose scanner was outrun or was not, and left
    /// `unanswered` of `targets` probes without a reply.
    fn paced(targets: u128, unanswered: u128, at_floor: bool) -> zond_engine::ScanReport {
        use std::time::{Duration, SystemTime};

        use zond_engine::ZondConfig;
        use zond_engine::model::exclusion::Exclusions;
        use zond_engine::model::parse::ip::to_set;
        use zond_engine::scanner::pacing::congestion::WindowSummary;
        use zond_engine::scanner::report::{
            ATTEMPTS_COUNTED, BUCKET_BOUNDS_MS, PhaseParts, ProbeStats, ProbeStatsParts, ScanKind,
            ScanPhase, ScanReport, ScanSettings, StopReason, TargetScope,
        };
        use zond_engine::scanner::session::ScannerKind;

        let probes = ProbeStats::from_parts(ProbeStatsParts {
            scanner: ScannerKind::SynPort,
            targets,
            stop_reason: StopReason::AttemptsSpent,
            elapsed: Duration::from_secs(1),
            sends_attempted: 0,
            sends_failed: 0,
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
            kind: ScanKind::PortScan,
            started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_000_000),
            elapsed: Duration::from_secs(1),
            privileged: true,
            targets: TargetScope::from_ip_set(&mut scope, &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            unroutable: Vec::new(),
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

        let trusted = ports(&host, true);
        assert!(
            trusted.iter().any(|line| line.contains("filtered")),
            "a scan that could ask reports what it found: {trusted:?}"
        );

        let outrun = ports(&host, false);
        assert!(
            outrun.iter().all(|line| !line.contains("filtered")),
            "and one that could not makes no claim at all: {outrun:?}"
        );
        assert!(
            outrun
                .iter()
                .any(|line| line.contains("40 ports the scan could not reach")),
            "but says how many it could not reach: {outrun:?}"
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
            ports(&scanned(), true),
            vec![
                // Columns, so the eye runs down the states rather than hunting
                // each one at whatever offset its port number left it at.
                "22/tcp   open      ssh OpenSSH 9.6",
                "53/udp   open",
                "443/tcp  open",
                "21/tcp   filtered",
                "[1 closed port omitted]",
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

        let lines = ports(&host, true);

        // The open port, twelve filtered, and the rollup.
        assert_eq!(lines.len(), 1 + MAX_LISTED_FILTERED + 1);
        assert!(lines[0].starts_with("80/tcp"), "open first: {lines:?}");
        assert!(
            lines[1].starts_with("1001/tcp"),
            "and the lowest filtered ones are the ones kept: {lines:?}"
        );
        assert_eq!(
            lines.last().map(String::as_str),
            Some("[28 more filtered ports omitted]")
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

        let lines = ports(&host, true);
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

        assert_eq!(ports(&host, true), vec!["[1 closed port omitted]"]);
    }

    #[test]
    fn the_closed_rollup_counts_in_the_plural() {
        let mut host = host(1);
        for number in [80, 443] {
            host.add_port(Port::new(number, Protocol::Tcp, PortState::Closed));
        }

        assert_eq!(ports(&host, true), vec!["[2 closed ports omitted]"]);
    }

    #[test]
    fn a_host_that_was_never_port_scanned_has_no_port_lines() {
        assert!(ports(&host(1), true).is_empty());
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

        assert_eq!(ports(&host, true), vec!["9999/tcp  open"]);
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
