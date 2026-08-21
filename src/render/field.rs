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
//! magnitude — `1.42ms`, `412.0ms`, `1.24s` — which is what a person reads
//! fastest and what a script cannot parse. [`rtt_millis`] writes a bare `1.420`
//! in a unit that never changes.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use zond_engine::Host;
use zond_engine::export::{Redaction, redact};
use zond_engine::model::host::status::StatusProtocol;
use zond_engine::model::ip::scoped::ScopedIp;
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
    pub(crate) fn other_addresses(self, host: &Host) -> Vec<String> {
        self.others(host).collect()
    }

    /// The primary address alone, with a count of the others when there are any.
    ///
    /// For the running commentary, where the point is that something was found
    /// rather than everything about it.
    pub(crate) fn primary_address(self, host: &Host) -> String {
        let address = self.primary(host);

        match host.ips().len().saturating_sub(1) {
            0 => address,
            others => format!("{address} +{others}"),
        }
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

    /// The non-primary addresses.
    fn others(self, host: &Host) -> impl Iterator<Item = String> + '_ {
        let primary = host.primary_ip();
        host.ips()
            .iter()
            .copied()
            .filter(move |ip| *ip != primary)
            .map(move |ip| self.address(host, ip))
    }

    /// One address, masked if the policy says so and scoped if it needs to be.
    ///
    /// The zone survives masking. It names an interface on *this* machine, not
    /// anything about the target, and without it a link-local address does not
    /// identify a machine at all — which would make a redacted result unreadable
    /// rather than discreet.
    fn address(self, host: &Host, ip: IpAddr) -> String {
        let text = match ip {
            IpAddr::V6(v6) if self.redaction.is_active() => mask(&v6),
            _ => ip.to_string(),
        };

        match host.zone() {
            Some(zone) if ScopedIp::needs_zone(&ip) => format!("{text}%{zone}"),
            _ => text,
        }
    }
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
/// afford one — the field would still parse, but the value would carry
/// whitespace a consumer did not ask for — and a line somebody reads wants it.
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
        StatusProtocol::Udp => "udp".to_owned(),
        StatusProtocol::Custom(name) => name.to_lowercase(),
        other => format!("{other:?}").to_lowercase(),
    }
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
/// it answered once quickly and then made the scan wait. No median — three
/// figures already describe the spread, and [`rtt_millis`] carries it anyway.
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
/// Everything except plainly closed, which is counted instead of enumerated.
fn notable(state: PortState) -> bool {
    state != PortState::Closed
}

/// One line per port worth showing, ending with a count of what was left out.
///
/// Open first, then by number. Empty when nothing was probed.
pub(crate) fn ports(host: &Host) -> Vec<String> {
    let mut shown: Vec<&Port> = host.ports().filter(|port| notable(port.state())).collect();
    let closed = host.ports().filter(|port| !notable(port.state())).count();

    if shown.is_empty() && closed == 0 {
        return Vec::new();
    }

    shown.sort_by_key(|port| (port.state() != PortState::Open, port.number()));

    let mut lines: Vec<String> = shown
        .iter()
        .map(|port| {
            let mut line = format!(
                "{}/{} {}",
                port.number(),
                protocol(port.protocol()),
                state(port.state())
            );
            if let Some(service) = describe(port) {
                line.push_str(" (");
                line.push_str(&service);
                line.push(')');
            }
            line
        })
        .collect();

    if closed > 0 {
        lines.push(format!(
            "[{closed} closed {} omitted]",
            plural(closed as u128, "port")
        ));
    }

    lines
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
/// `open-filtered` is one verdict — "no answer, and for this technique that
/// could be either" — not two states to pick between.
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

/// What is listening, where fingerprinting worked it out.
fn describe(port: &Port) -> Option<String> {
    let service = port.service()?;
    if !named(&service.name()) {
        return None;
    }

    let mut described = service.name().to_owned();
    if let Some(product) = service.product() {
        described.push(' ');
        described.push_str(product);
    }
    if let Some(version) = service.version() {
        described.push(' ');
        described.push_str(version);
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

/// How many addresses the run was asked to cover.
///
/// The *first* phase, deliberately, where [`kind`] reads the last. A port scan's
/// second phase covers only the addresses that answered, and "3 hosts up of 4
/// addresses" is a count of what was asked about — not of what survived the
/// asking.
pub(crate) fn addresses_scanned(report: &ScanReport) -> u128 {
    report
        .phases()
        .first()
        .map_or(0, |phase| phase.targets().addresses())
}

/// How many addresses the run was asked about but never port-scanned.
///
/// Zero unless a liveness phase ran and turned something away.
pub(crate) fn skipped_as_down(report: &ScanReport) -> u128 {
    let [liveness, ports, ..] = report.phases() else {
        return 0;
    };

    liveness
        .targets()
        .addresses()
        .saturating_sub(ports.targets().addresses())
}

/// What the run was for.
///
/// The *last* phase. A port scan records two — the liveness pass that
/// established anything was there, then the ports — and it is the second that
/// says what the run was asked to do.
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
    use crate::render::test_support::host;
    use std::net::Ipv4Addr;
    use zond_engine::Service;
    use zond_engine::model::host::status::{StatusProtocol, StatusReason};
    use zond_engine::model::ip::scoped::Zone;

    fn v6(text: &str) -> Ipv6Addr {
        text.parse().expect("a valid address")
    }

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

    /// A zone names an interface on *this* machine, so it survives masking —
    /// without it a link-local address identifies nothing at all.
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
            Reader::default().other_addresses(&host),
            vec!["2001:db8::1".to_owned()]
        );
    }

    /// The commentary counts the rest rather than listing them.
    #[test]
    fn the_progress_line_counts_the_other_addresses() {
        let mut host = host(1);
        assert_eq!(Reader::default().primary_address(&host), "192.0.2.1");

        host.add_ip(IpAddr::V6(v6("2001:db8::1")));
        assert_eq!(Reader::default().primary_address(&host), "192.0.2.1 +1");
    }

    #[test]
    fn a_host_at_one_address_has_no_others() {
        assert!(Reader::default().other_addresses(&host(1)).is_empty());
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

    /// The pipe mode's unit never changes, whatever the magnitude — a consumer
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
    /// listed — and the identifiers padded so the verdicts line up.
    #[test]
    fn ports_are_listed_open_first_with_the_closed_ones_counted() {
        assert_eq!(
            ports(&scanned()),
            vec![
                "22/tcp open (ssh OpenSSH 9.6)",
                "53/udp open",
                "443/tcp open",
                "21/tcp filtered",
                "[1 closed port omitted]",
            ]
        );
    }

    /// A host whose every port came back shut still says so — the rollup is the
    /// whole list rather than a footnote to one.
    #[test]
    fn a_host_with_nothing_open_says_so() {
        let mut host = host(1);
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Closed));

        assert_eq!(ports(&host), vec!["[1 closed port omitted]"]);
    }

    #[test]
    fn the_closed_rollup_counts_in_the_plural() {
        let mut host = host(1);
        for number in [80, 443] {
            host.add_port(Port::new(number, Protocol::Tcp, PortState::Closed));
        }

        assert_eq!(ports(&host), vec!["[2 closed ports omitted]"]);
    }

    #[test]
    fn a_host_that_was_never_port_scanned_has_no_port_lines() {
        assert!(ports(&host(1)).is_empty());
        assert_eq!(closed_ports(&host(1)), None);
    }

    /// One field, sub-delimited, so a record stays one line and one host.
    #[test]
    fn packed_ports_carry_number_protocol_state_and_service() {
        assert_eq!(
            packed_ports(&scanned()).as_deref(),
            Some("21/tcp/filtered/-,22/tcp/open/ssh,443/tcp/open/-,53/udp/open/-"),
            "grouped by protocol, then by number — a different order from the listing"
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

        assert_eq!(ports(&host), vec!["9999/tcp open"]);
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
}
