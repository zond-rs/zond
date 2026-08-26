// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A numbered block per host, for reading
//!
//! ```text
//! • recording this run as 06G3JC56RSVTRBTR        <- stderr
//! • discovering 1024 addresses (192.0.2.0/22)     <- stderr
//!                                                 <- stdout, from here
//!   1  192.0.2.1  router.example    1.10 ms   2 open
//!      hardware  00:00:5e:00:53:01  Icann, Iana
//!      system    Linux 6.x [84%]
//!      answered  ARP  NDP
//!      also      2001:db8::1
//!      path      1  192.0.2.254  0.90ms
//!                2  *
//!      ports     22/tcp   open      ssh    OpenSSH 9.6
//!                443/tcp  open      https  nginx 1.24
//!                  tls   1.3  X25519  alpn h2, http/1.1
//!                  cert  router.example  expires in 12d
//!                5/tcp    filtered
//!                [996 closed ports omitted]
//!
//!   2  192.0.2.44
//!
//!   3  192.0.2.51                             Filtered
//!      answered  ARP
//!
//! • 3 hosts up of 1024 addresses in 4.12s         <- stderr
//! ```
//!
//! ## What this module decides, and what it does not
//!
//! The shape is [`block`](super::block)'s: the six line types, the columns
//! measured across the whole listing, and what a handle and an identity look
//! like. What is decided here is which facts a host has, in what order, and what
//! colour each one takes. Those are the judgements that need to know what a port
//! and a certificate are, which is exactly what `block` is kept ignorant of.
//!
//! ## `ports` is last on purpose
//!
//! It is the longest child, and a long value is cheapest at the bottom of a
//! block: its continuation lines run down into empty space rather than pushing
//! the rest of the facts away from the header they belong to.
//!
//! ## What a block pays for
//!
//! Only what it has. Every child is conditional, so a host nothing was learned
//! about is its header line alone, which is what keeps a sweep of a mostly empty
//! `/22` from being two hundred near-identical blocks. There are no
//! placeholders.
//!
//! ## The header carries what a listing is scanned for
//!
//! Which machine, what it calls itself, how far away it is, and what came of it,
//! on one line. The fastest round trip rides here in a column of its own rather
//! than taking a row; what the round trips did *apart* from the fastest is a
//! separate fact, and waits for `-v`.
//!
//! ## The number is the handle
//!
//! A host opens with its place in the listing, right-aligned to the width of the
//! largest, so the numbers form a straight column whatever the run turned up and
//! a person can say "look at four" about a screen neither of you can point at.
//! Every label beneath then starts in the column the address starts in.
//!
//! **Colour never carries a fact by itself.** See [`style`](super::style): every
//! state a colour marks is also a word, and a host that is anything other than
//! up says so on its header line.

use std::io::{self, BufWriter, Write};

use zond_engine::export::Redaction;
use zond_engine::{Host, HostStatus, PortState, ScanReport};

use crate::diagnostics::Verbosity;
use crate::render::block::{self, Block, Child, Detail, Distance, Header, Row};
use crate::render::narrate::Narrator;
use crate::render::progress::{self, Counting};
use crate::render::style::{Palette, Style};
use crate::render::{Phase, Renderer, field};

/// The tree renderer.
pub(crate) struct FancyRenderer {
    records: Box<dyn Write>,
    narrator: Narrator,
    reader: field::Reader,
    /// The record stream's own style, which is not the commentary stream's:
    /// `zond discover lan | less` redirects one and not the other.
    style: Style,
    /// Decides whether a block shows the working behind its operating-system
    /// finding and behind a certificate.
    verbosity: Verbosity,
}

impl FancyRenderer {
    /// Writing to this process's own streams.
    #[must_use]
    pub(crate) fn to_terminal(verbosity: Verbosity, palette: Palette) -> Self {
        // Records are buffered, since they arrive as thousands of lines in one
        // burst at the end. Commentary is not: a progress line held in a buffer
        // is not progress.
        Self::new(
            Box::new(BufWriter::new(io::stdout())),
            Box::new(io::stderr()),
            verbosity,
            Style::for_stdout(palette),
            Style::for_stderr(palette),
        )
    }

    /// Writing wherever the caller says, which is how this is tested.
    #[must_use]
    pub(crate) fn new(
        records: Box<dyn Write>,
        narration: Box<dyn Write>,
        verbosity: Verbosity,
        style: Style,
        narration_style: Style,
    ) -> Self {
        Self {
            records,
            narrator: Narrator::new(narration, verbosity, narration_style),
            reader: field::Reader::default(),
            style,
            verbosity,
        }
    }
}

/// What the line at the bottom counts for a run of this kind.
///
/// A sweep is asking who is there, so it counts hosts. A port scan was handed
/// its hosts and is asking what is open, so counting them again would be
/// counting its own input back.
///
/// `None` for a record read off disk or a fold of several: nothing is running,
/// so there is nothing for a line at the bottom to say about it.
fn counting(phase: Phase<'_>) -> Option<Counting> {
    match phase {
        Phase::Discovery { .. } => Some(Counting::Hosts),
        Phase::PortScan { .. } => Some(Counting::Ports),
        Phase::Recorded { .. } | Phase::Merged { .. } | Phase::Folded { .. } => None,
    }
}

/// The line a block opens with: which machine this is, and what came of it.
fn header(
    style: Style,
    reader: field::Reader,
    host: &Host,
    at: usize,
    unit: Option<&'static str>,
) -> Header {
    Header {
        at: Some(at),
        // A scan does not sort its hosts into kinds; what came of one trails it.
        tag: None,
        identity: reader.primary(host),
        // The name says which machine this is, so it belongs with the address
        // rather than among the things that were learned about it.
        name: reader.hostname(host),
        // The fastest round trip rather than the median: it is the one the
        // network is capable of, and a slower reply says the host or the path
        // was busy at that moment, which is a different fact and waits for `-v`.
        //
        // A host the listing has a column for but no measurement of still gets a
        // `Distance`, with nothing in it. See `block::Distance::figure`.
        distance: unit.map(|unit| Distance {
            figure: field::fastest(host).map(|rtt| field::listing_figure(rtt, unit)),
            unit,
        }),
        verdict: verdict(style, host),
    }
}

/// What came of the host, in the fewest words that say it.
///
/// Nothing at all for a host that is simply up and had no ports probed, which is
/// every host in an ordinary discovery sweep. The block existing has already
/// said it.
fn verdict(style: Style, host: &Host) -> Option<String> {
    let mut parts = Vec::new();

    if !field::is_up(host) {
        let status = field::status(host);
        parts.push(match host.status() {
            HostStatus::Filtered => style.caution(&status),
            _ => style.faint(&status),
        });
    }

    if let Some((open, _probed)) = field::open_ports(host) {
        parts.push(if open == 0 {
            style.faint("no open ports")
        } else {
            style.good(&format!("{open} open"))
        });
    }

    (!parts.is_empty()).then(|| parts.join(", "))
}

/// The facts this host has, in the order they are drawn.
///
/// `ports` last, and not by accident: it is the longest, and the longest value
/// is the one whose continuation lines are cheapest at the bottom of a block.
fn children(
    style: Style,
    reader: field::Reader,
    host: &Host,
    verbosity: Verbosity,
    silence_means_something: bool,
) -> Vec<Child> {
    let mut children = Vec::new();

    // The vendor was read out of the hardware address, so it is shown against
    // it, and faintly, because it qualifies that address rather than competing
    // with it. Spelled the way a person says it: see `field::spoken_vendor`.
    if let Some(macs) = reader.macs(host) {
        let line = match field::vendor(host) {
            Some(vendor) => format!(
                "{}  {}",
                style.plain(&macs),
                style.faint(field::spoken_vendor(vendor))
            ),
            None => style.plain(&macs),
        };
        children.push(Child::one("hardware", line));
    }

    // Directly under the hardware, because the two answer the same question from
    // different sides: what this box is, and what it does. A role is also the
    // one finding here the engine can make without probing, since a router
    // advertisement arrives unasked, so a host may carry one and nothing else.
    if let Some(roles) = field::roles(host) {
        children.push(Child::one("roles", style.plain(&roles)));
    }

    if let Some(os) = field::os(host) {
        children.push(Child::one("system", style.plain(&os)));
    }

    // Directly under `system` because it is that line's working: the shape of
    // each reply the verdict was drawn from. Only under detail, because a person
    // using the finding wants the finding and a person checking it wants this.
    if verbosity.explains()
        && let Some(working) = field::os_evidence(host)
    {
        children.push(Child::one("evidence", style.plain(&working)));
    }

    // Not a row: the fastest round trip rides on the header. What is left here
    // is the part a header has no room for, and only when the round trips
    // disagreed enough for it to mean something.
    if verbosity.explains()
        && let Some(variation) = field::rtt_variation(host)
    {
        children.push(Child::one("latency", style.plain(&variation)));
    }

    if let Some(answered) = field::answered(host) {
        children.push(Child::one("answered", style.plain(&answered)));
    }

    // The further addresses only. The primary is already on the header line, and
    // a link-local the host derived from the hardware address two lines up is
    // that address written again, and `-v` keeps it. See
    // `Reader::other_addresses`.
    let others = reader.other_addresses(host, verbosity.explains());
    if !others.is_empty() {
        children.push(Child::many(
            "also",
            others.iter().map(|address| style.plain(address)).collect(),
        ));
    }

    // Above the ports because it is about how this host was reached rather than
    // what was found on it. Built from the parts rather than the finished line,
    // so the step number is furniture and the router is a finding.
    let path = field::hops(reader, host);
    if !path.is_empty() {
        children.push(Child::many(
            "path",
            path.iter()
                .map(|hop| {
                    let mut line =
                        format!("{}  {}", style.faint(&hop.step), style.plain(&hop.address));
                    if let Some(detail) = &hop.detail {
                        line.push_str("  ");
                        line.push_str(&style.faint(detail));
                    }
                    line
                })
                .collect(),
        ));
    }

    let listing = field::port_rows(host, silence_means_something, verbosity.explains());
    if !listing.rows.is_empty() || !listing.notes.is_empty() {
        children.push(ports(style, &listing));
    }

    children
}

/// The `ports` child: a table, and whatever hangs off one of its rows.
///
/// A child like any other, which is the whole point: the table is what this
/// value happens to be, not a section of its own.
fn ports(style: Style, listing: &field::PortListing) -> Child {
    let mut rows = Vec::new();

    for row in &listing.rows {
        // Every column is painted trimmed and padded after, so no escape
        // sequence ever wraps a run of spaces: what the terminal measures is
        // exactly what the widths were computed from.
        let endpoint = row.port.trim_end();
        let word = row.state.trim_end();

        let mut text = format!(
            "{}{}  {}",
            style.strong(endpoint),
            " ".repeat(row.port.len() - endpoint.len()),
            state(style, row)
        );

        if let Some(service) = &row.service {
            text.push_str(&" ".repeat(row.state.len() - word.len()));
            text.push_str("  ");
            text.push_str(&style.plain(service));
        }

        rows.push(Row::with_detail(
            text,
            row.detail.iter().map(hanging).collect(),
        ));
    }

    // The renderer's own notes about what it decided not to enumerate. Faint,
    // and with nothing in the column the port numbers are bold in, which is what
    // makes them read as this program talking rather than as another port.
    for note in &listing.notes {
        rows.push(Row::plain(style.faint(note)));
    }

    Child::rows("ports", rows)
}

/// A port's state, coloured by what it is.
fn state(style: Style, row: &field::PortRow) -> String {
    let word = row.state.trim_end();

    match row.verdict {
        PortState::Open => style.good(word),
        PortState::Filtered | PortState::OpenFiltered => style.caution(word),
        _ => style.faint(word),
    }
}

/// A fact hanging off a port, in the block's own grammar one level in.
fn hanging(detail: &field::PortDetail) -> Detail {
    let carried = Detail::new(detail.label, detail.value.clone());

    match &detail.note {
        Some(note) => carried.noted(note.clone(), detail.urgency),
        None => carried,
    }
}

impl Renderer for FancyRenderer {
    fn started(&mut self, phase: Phase<'_>, redaction: Redaction) -> io::Result<()> {
        self.reader = field::Reader::new(redaction);
        self.narrator.started(phase, redaction)?;

        if let Some(counting) = counting(phase) {
            progress::start(counting, self.style);
        }

        Ok(())
    }

    fn progressed(&mut self, hosts: usize, open: usize) -> io::Result<()> {
        progress::seen(hosts, open);
        Ok(())
    }

    fn interrupted(&mut self) -> io::Result<()> {
        progress::stop();
        self.narrator.interrupted()
    }

    fn finished(&mut self, report: &ScanReport) -> io::Result<()> {
        // Before a single record is written: the answer goes where the line was.
        progress::stop();

        let hosts = field::sorted_hosts(report);
        let trustworthy = field::silence_means_something(report);

        // One unit for the whole column, chosen from the quickest host in the
        // run, so two latencies in this listing compare against each other
        // without either being converted first. See `field::listing_unit`.
        let unit = field::listing_unit(field::fastest_of(&hosts));

        // Every block is built before any of it is drawn, because the columns
        // are measured across the listing: a handle right-aligned to the widest,
        // a latency right-aligned to a column the longest name allows. See
        // `block::Columns`.
        let blocks: Vec<Block> = hosts
            .iter()
            .enumerate()
            .map(|(index, host)| Block {
                header: header(self.style, self.reader, host, index + 1, unit),
                children: children(self.style, self.reader, host, self.verbosity, trustworthy),
            })
            .collect();

        // The separator belongs to the listing, so it goes on the record stream.
        // Above the first block only if there is commentary to separate it from.
        let narrates = self.narrator.narrates();
        block::write_all(&mut self.records, self.style, &blocks, |out, index| {
            if index > 0 || narrates {
                writeln!(out)?;
            }
            Ok(())
        })?;

        self.records.flush()?;
        self.narrator.summary(report)
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
mod tests {
    use super::*;
    use crate::render::test_support::{Capture, host, opener, painting, strip_escapes};

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use zond_engine::model::host::OsFingerprint;
    use zond_engine::model::host::path::Hop;
    use zond_engine::model::host::status::{StatusProtocol, StatusReason};
    use zond_engine::model::ip::scoped::Zone;
    use zond_engine::model::port::security::{CertificateInfo, Security};
    use zond_engine::{Port, Protocol, Service};

    /// The block a plain run writes: no colour, no detail asked for. Asserting
    /// on this reads the layout rather than a wall of escapes.
    fn block(host: &Host) -> String {
        rendered(field::Reader::default(), host, Verbosity::default())
    }

    /// The block a run asked for detail writes.
    fn explained(host: &Host) -> String {
        rendered(field::Reader::default(), host, Verbosity::new(1, false))
    }

    fn rendered(reader: field::Reader, host: &Host, verbosity: Verbosity) -> String {
        drawn(Style::bare(), reader, host, verbosity)
    }

    /// One host as a listing of one, which is how a block is measured: the
    /// columns come from the whole listing, so there is no drawing a block
    /// outside of one.
    fn drawn(style: Style, reader: field::Reader, host: &Host, verbosity: Verbosity) -> String {
        let unit = field::listing_unit(field::fastest(host));
        let blocks = vec![Block {
            header: header(style, reader, host, 1, unit),
            children: children(style, reader, host, verbosity, true),
        }];

        let mut out = Vec::new();
        block::write_all(&mut out, style, &blocks, |_, _| Ok(())).expect("a vector cannot fail");
        String::from_utf8(out).expect("the renderer writes text")
    }

    /// A whole listing, measured together the way a run measures one.
    fn listing(hosts: &[&Host]) -> String {
        let style = Style::bare();
        let reader = field::Reader::default();
        let unit = field::listing_unit(field::fastest_of(hosts));

        let blocks: Vec<Block> = hosts
            .iter()
            .enumerate()
            .map(|(index, host)| Block {
                header: header(style, reader, host, index + 1, unit),
                children: Vec::new(),
            })
            .collect();

        let mut out = Vec::new();
        block::write_all(&mut out, style, &blocks, |_, _| Ok(())).expect("a vector cannot fail");
        String::from_utf8(out).expect("the renderer writes text")
    }

    /// The column every value in a one-block listing begins in.
    fn value_column(host: &Host) -> usize {
        let unit = field::listing_unit(field::fastest(host));
        let style = Style::bare();
        block::Columns::of(&[Block {
            header: header(style, field::Reader::default(), host, 1, unit),
            children: children(
                style,
                field::Reader::default(),
                host,
                Verbosity::default(),
                true,
            ),
        }])
        .value_column()
    }

    /// The same block, painted, for the tests about colour.
    fn painted(host: &Host) -> String {
        drawn(
            painting(),
            field::Reader::default(),
            host,
            Verbosity::default(),
        )
    }

    fn furnished() -> Host {
        let mut host = host(1);
        host.add_ip("fe80::1".parse().expect("a valid address"));
        host.set_zone(Zone::new(4, "en0"));
        host.add_rtt(Duration::from_micros(1_420));
        host.add_reason(StatusReason::new(StatusProtocol::Arp, "reply"));
        host.add_reason(StatusReason::new(StatusProtocol::Ndp, "advertisement"));
        host.record_mac("00:00:5e:00:53:01".parse().expect("a valid address"));
        host.set_hostname(Some("router.example".to_owned()));
        host.record_hop(Hop::answered(
            1,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)),
            Some(Duration::from_micros(900)),
        ));
        host.record_hop(Hop::silent(2));
        host
    }

    /// A host serving TLS on 443, with a certificate ending at `expiry`.
    fn serving_tls(expiry: std::time::SystemTime) -> Host {
        let mut host = host(30);
        let certificate = CertificateInfo::new(
            "printer.example",
            "Let's Encrypt R3",
            std::time::SystemTime::now() - Duration::from_secs(400 * 86_400),
            expiry,
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        );
        host.add_port(
            Port::new(443, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("https", 100).with_product("nginx"))
                .with_security(
                    Security::new()
                        .with_tls_version("1.3")
                        .with_cipher_suite("X25519")
                        .with_alpn("h2")
                        .with_certificate(certificate),
                ),
        );
        host
    }

    /// The shape the whole design rests on. If this drifts, everything else in
    /// this module is asserting on a layout nobody chose.
    #[test]
    fn a_furnished_host_reads_as_a_block() {
        assert_eq!(
            block(&furnished()),
            "  1  192.0.2.1  router.example  1.42 ms
     hardware  00:00:5e:00:53:01  Icann, Iana Department
     answered  ARP  NDP
     also      fe80::1%en0
     path      1  192.0.2.254  0.90ms
               2  *
"
        );
    }

    /// A value that continues onto another line lands in the column its first
    /// line started in, and carries nothing in front of it.
    #[test]
    fn a_continued_value_keeps_the_column_and_nothing_else() {
        let text = block(&furnished());
        let second_hop = text
            .lines()
            .skip_while(|line| !line.contains("path"))
            .nth(1)
            .expect("the second hop");

        assert!(
            second_hop.starts_with(&" ".repeat(value_column(&furnished()))),
            "something survived into the continuation: {second_hop:?}"
        );
    }

    /// Every value begins in the same column, whatever the label above it was.
    /// That column is what lets an eye run down them.
    #[test]
    fn every_label_lines_its_value_up_with_the_others() {
        let text = block(&furnished());

        let column = value_column(&furnished());

        for line in text.lines().skip(1) {
            let value = line
                .char_indices()
                .nth(column)
                .map(|(index, _)| &line[index..]);
            if let Some(value) = value {
                assert!(
                    !value.starts_with(' '),
                    "value does not begin at column {column}: {line:?}"
                );
            }
        }
    }

    /// What a host *does* is a finding like any other, and until now the only
    /// place it reached the screen was a comparison saying it had changed.
    #[test]
    fn a_role_the_scan_established_reaches_the_block() {
        use zond_engine::model::host::NetworkRole;

        let mut router = furnished();
        router.add_network_role(NetworkRole::Router);
        router.add_network_role(NetworkRole::DnsServer);

        assert!(
            block(&router).contains("roles     router  DNS"),
            "{}",
            block(&router)
        );
    }

    /// A router advertisement arrives without being asked for, so a host can
    /// carry a role and nothing else at all.
    #[test]
    fn a_host_known_only_by_its_role_still_draws_a_block() {
        use zond_engine::model::host::NetworkRole;

        let mut only = host(44);
        only.add_network_role(NetworkRole::Router);

        assert_eq!(block(&only), "  1  192.0.2.44\n     roles  router\n");
    }

    /// A sweep of a home segment turns up a router a few milliseconds away and a
    /// phone that takes a second and a half. Both are written in milliseconds,
    /// because the unit has to hold the *smallest* measurement. Written in
    /// seconds the router reads `0.01`, and the column has thrown away the
    /// difference it exists to show.
    #[test]
    fn a_quick_host_keeps_its_precision_beside_a_slow_one() {
        let mut quick = host(1);
        quick.add_rtt(Duration::from_micros(4_870));

        let mut slow = host(2);
        slow.add_rtt(Duration::from_millis(1_490));

        let text = listing(&[&quick, &slow]);

        assert!(text.contains("4.87 ms"), "{text}");
        assert!(text.contains("1490.00 ms"), "{text}");
        assert!(
            !text.contains(" s\n"),
            "the column switched to seconds: {text}"
        );
    }

    /// A host the scan overheard rather than timed still has a place in the
    /// column, and says so. A blank there reads as a rendering fault and a zero
    /// reads as a finding, and it is neither.
    #[test]
    fn a_host_that_was_never_timed_says_so_in_the_column() {
        let mut timed = host(1);
        timed.add_rtt(Duration::from_micros(4_870));

        let text = listing(&[&timed, &host(2)]);
        let lines: Vec<&str> = text.lines().collect();

        assert!(lines[0].ends_with("4.87 ms"), "{text}");
        assert!(lines[1].ends_with('-'), "{text}");

        // The dash stands where the last digit does, so the column reads as one.
        assert_eq!(
            lines[0].rfind(|c: char| c.is_ascii_digit()),
            lines[1].rfind('-'),
            "the stand-in is not in the column: {text}"
        );
    }

    /// A listing that measured nothing at all has no column to stand in.
    #[test]
    fn a_listing_that_timed_nothing_draws_no_column() {
        let text = listing(&[&host(1), &host(2)]);

        assert_eq!(text, "  1  192.0.2.1\n  2  192.0.2.2\n");
    }

    /// A host nothing was learned about is its header alone. This is what keeps
    /// a sweep of a mostly empty range from being a wall of near-identical
    /// blocks.
    #[test]
    fn a_host_with_nothing_known_is_one_line() {
        assert_eq!(block(&host(44)), "  1  192.0.2.44\n");
    }

    /// A discovery sweep probes no ports, so the header says nothing about
    /// them: "no open ports" would read as a finding rather than as nothing
    /// having been asked.
    #[test]
    fn a_host_with_no_ports_probed_claims_nothing_about_them() {
        let text = block(&furnished());
        assert!(!text.contains("open"), "{text}");
    }

    #[test]
    fn the_header_counts_the_open_ports() {
        let text = block(&serving_tls(away(400)));
        assert!(text.starts_with("  1  192.0.2.30   1 open\n"), "{text}");
    }

    /// A host whose ports were all shut says so, rather than leaving a reader to
    /// infer it from a missing line.
    #[test]
    fn a_host_with_nothing_open_says_so() {
        let mut host = host(7);
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Closed));

        assert!(block(&host).contains("no open ports"), "{}", block(&host));
    }

    /// TLS and the certificate hang off the port that negotiated them, indented
    /// past the port column so they cannot be read as ports themselves.
    #[test]
    fn a_certificate_hangs_off_the_port_that_served_it() {
        let text = block(&serving_tls(away(12)));

        assert!(text.contains("tls   1.3  X25519  alpn h2"), "{text}");
        assert!(
            text.contains("cert  printer.example  expires in 12d"),
            "{text}"
        );

        // Indented past the column the port numbers stand in, which is what
        // marks them as belonging to 443 rather than being ports themselves.
        // No glyph does that work any more, so the indent has to.
        let port_column = text
            .lines()
            .find(|line| line.contains("443/tcp"))
            .and_then(|line| line.find("443/tcp"))
            .expect("the port");

        let hanging: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("tls ") || line.contains("cert "))
            .collect();
        assert_eq!(hanging.len(), 2, "{text}");

        for line in &hanging {
            let label = line.len() - line.trim_start().len();
            assert!(
                label > port_column,
                "detail is not indented past the port column: {line:?}"
            );
        }
    }

    /// An end that is `days` away, or behind us when `days` is negative.
    fn away(days: i64) -> std::time::SystemTime {
        let offset = Duration::from_secs(days.unsigned_abs() * 86_400);
        if days < 0 {
            std::time::SystemTime::now() - offset
        } else {
            std::time::SystemTime::now() + offset
        }
    }

    /// A certificate past its end is not merely coloured. The words say it, so
    /// the finding survives being piped to a file.
    #[test]
    fn an_expired_certificate_says_so_in_words() {
        let text = block(&serving_tls(away(-9)));
        assert!(text.contains("expired 9d ago"), "{text}");
    }

    /// The colour is the second signal, not the only one. A certificate inside
    /// the horizon is cautioned and one well outside it is not.
    #[test]
    fn only_a_certificate_near_its_end_is_coloured() {
        let soon = painted(&serving_tls(away(12)));
        let later = painted(&serving_tls(away(400)));

        let caution = opener(Style::caution);

        assert!(
            soon.contains(&format!("{caution}expires in 12d")),
            "{soon:?}"
        );
        assert!(
            !later.contains(&format!("{caution}expires in")),
            "{later:?}"
        );
        assert!(later.contains("expires in 400d"), "{later:?}");
    }

    /// The working behind a certificate is for somebody checking it, and noise
    /// to somebody reading past it.
    #[test]
    fn a_certificates_issuer_and_fingerprint_wait_for_detail() {
        let host = serving_tls(away(90));

        assert!(!block(&host).contains("Let's Encrypt"), "{}", block(&host));
        assert!(
            explained(&host).contains("issuer  Let's Encrypt R3"),
            "{}",
            explained(&host)
        );
    }

    /// The working behind an operating-system finding, on the same rule.
    #[test]
    fn the_working_behind_an_os_finding_appears_only_under_detail() {
        let mut host = furnished();
        host.set_os(
            OsFingerprint::new("Linux", 65)
                .with_family("Linux")
                .with_generation("6.x")
                .with_evidence("syn-ack hops>=64 opts=M,S,T,N,W id=zero isn=hashed"),
        );

        assert!(block(&host).contains("Linux 6.x"), "{}", block(&host));
        assert!(!block(&host).contains("isn=hashed"), "{}", block(&host));
        assert!(
            explained(&host).contains("isn=hashed"),
            "{}",
            explained(&host)
        );
    }

    /// A host answering at one address has nothing to add below its header.
    #[test]
    fn one_address_gets_no_list_of_its_own() {
        let mut host = host(1);
        host.add_rtt(Duration::from_micros(8_200));

        assert!(!block(&host).contains("Also"), "{}", block(&host));
    }

    /// The fastest round trip rides on the header in a column of its own, not in
    /// a row: it is one figure, and the header is where a listing is scanned. It
    /// needs no mark either, because the column says what it is, which is the
    /// whole reason the hourglass could be retired.
    #[test]
    fn the_fastest_round_trip_rides_on_the_header() {
        let text = block(&furnished());
        let opening = text.lines().next().expect("a header");

        assert!(opening.ends_with("1.42 ms"), "{text}");
        assert!(!text.contains("latency"), "it took no row: {text}");
    }

    /// What the round trips did *apart* from the fastest is a different fact: a
    /// host whose fastest reply is 8 ms and slowest 1.2 s is not 8 ms away. It
    /// waits for somebody to ask, because most hosts have nothing to say.
    #[test]
    fn the_spread_is_a_row_and_only_under_detail() {
        let mut spread = host(1);
        spread.add_rtt(Duration::from_micros(1_100));
        spread.add_rtt(Duration::from_micros(1_510));
        spread.add_rtt(Duration::from_micros(2_030));

        assert!(
            !block(&spread).contains("min/avg/max"),
            "{}",
            block(&spread)
        );

        let detailed = explained(&spread);
        assert!(detailed.contains("latency  min/avg/max"), "{detailed}");
        assert!(detailed.contains("1.10 / 1.55 / 2.03 ms"), "{detailed}");
    }

    /// A host whose round trips all agreed has no spread to report, so asking
    /// for detail turns up no row rather than three copies of one number.
    #[test]
    fn round_trips_that_agree_produce_no_spread_row() {
        let detailed = explained(&furnished());
        assert!(!detailed.contains("Latency"), "{detailed}");
    }

    /// Protocol names are acronyms, not words, and they are written as such.
    #[test]
    fn the_protocols_a_host_answered_on_are_written_as_names() {
        let text = block(&furnished());

        assert!(text.contains("answered  ARP  NDP"), "{text}");
        assert!(!text.contains("arp, ndp"), "{text}");
    }

    /// The primary is on the header line already. Repeating it below puts one
    /// string on the screen twice, which, once the two are coloured by family,
    /// reads as two findings rather than one machine.
    #[test]
    fn the_primary_address_is_not_repeated_below_the_header() {
        let text = block(&furnished());

        assert_eq!(
            text.matches("192.0.2.1\n").count(),
            0,
            "the primary is listed again: {text}"
        );
        assert!(text.contains("also      fe80::1%en0"), "{text}");
    }

    /// The status is a word on the header line, so nothing about a host's
    /// reachability rests on the paint.
    #[test]
    fn a_filtered_host_says_so_without_colour() {
        let mut filtered = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        filtered.set_status(zond_engine::HostStatus::Filtered);

        let text = block(&filtered);
        assert!(text.starts_with("  1  "), "{text}");
        assert!(text.contains("Filtered"), "{text}");
    }

    #[test]
    fn redaction_masks_the_name_the_hardware_and_the_address() {
        let masked = rendered(
            field::Reader::new(Redaction::Standard),
            &furnished(),
            Verbosity::default(),
        );

        assert!(!masked.contains("router.example"), "{masked}");
        assert!(!masked.contains("00:00:5e:00:53:01"), "{masked}");
    }

    /// Redaction is off unless asked for. A scan holds what it found.
    #[test]
    fn nothing_is_masked_by_default() {
        let plain = block(&furnished());
        assert!(plain.contains("router.example"), "{plain}");
        assert!(plain.contains("00:00:5e:00:53:01"), "{plain}");
    }

    /// The point of the palette: which field a value belongs to is said by the
    /// label beside it, so hue is free to say something else. What it says is
    /// rank. The address the block is about is the one bold thing on the screen,
    /// everything the scan established shares one colour, and the furniture and
    /// the qualifiers share another.
    #[test]
    fn rank_rather_than_hue_separates_the_fields() {
        let text = painted(&furnished());

        let strong = opener(Style::strong);
        let plain = opener(Style::plain);
        let faint = opener(Style::faint);
        let accent = opener(Style::accent);

        for (sequence, value, what) in [
            (&strong, "192.0.2.1", "the address the block is about"),
            (&accent, "router.example", "the name the network gave back"),
            (&plain, "00:00:5e:00:53:01", "the hardware address"),
            (&plain, "1.42", "a measurement"),
            (&faint, " ms", "the unit it is measured in"),
            (&plain, "ARP  NDP", "what answered"),
            (&plain, "fe80::1%en0", "a further address"),
            (&plain, "192.0.2.254", "a router partway along the path"),
            (&faint, "hardware", "a label"),
            (
                &faint,
                "Icann, Iana Department",
                "the vendor, which qualifies the address beside it",
            ),
        ] {
            assert!(
                text.contains(&format!("{sequence}{value}")),
                "{what}: {text:?}"
            );
        }

        // Five findings, one colour. That is the change, and a role creeping
        // back per field is what this is here to catch.
        assert_ne!(strong, plain);
        assert_ne!(plain, faint);
        assert_ne!(accent, plain);
    }

    /// A version six address announces itself, having colons and hexadecimal in
    /// it, so a second hue spent saying so is a hue spent twice, and the two
    /// loudest entries in the palette used to go on exactly that. What a reader
    /// needs told apart is the address the block is *about* from the further
    /// ones it also answers at, and that is rank rather than family: a hop's
    /// version four address and a further version six address are the same kind
    /// of thing and now look it.
    #[test]
    fn an_address_is_not_coloured_by_its_family() {
        let text = painted(&furnished());

        let strong = opener(Style::strong);
        let plain = opener(Style::plain);

        assert!(text.contains(&format!("{strong}192.0.2.1")), "{text:?}");
        assert!(text.contains(&format!("{plain}fe80::1%en0")), "{text:?}");
        assert!(text.contains(&format!("{plain}192.0.2.254")), "{text:?}");
    }

    /// Furniture and findings never swap places.
    ///
    /// Labels, brackets, leaders, a hop's index and a qualifier are furniture; an
    /// address, a hardware address, a name, a measurement and a protocol list are
    /// not. A finding drawn as furniture is a finding a person has to read rather
    /// than scan, which was the whole complaint the palette exists to answer.
    #[test]
    fn nothing_a_scan_found_is_drawn_as_furniture() {
        let text = painted(&furnished());
        let faint = opener(Style::faint);

        assert!(
            text.contains(&faint),
            "this block drew no furniture at all, so the loop below proves nothing: {text:?}"
        );

        for finding in [
            "192.0.2.1",
            "router.example",
            "00:00:5e:00:53:01",
            "1.42",
            "ARP  NDP",
            "fe80::1%en0",
            "192.0.2.254",
        ] {
            assert!(
                !text.contains(&format!("{faint}{finding}")),
                "a finding was drawn as furniture: {finding}"
            );
        }
    }

    /// A label is furniture and its value is not. That is the distinction the
    /// leader dots used to draw with punctuation, and the reason they are not
    /// needed to draw it.
    #[test]
    fn a_label_is_furniture_and_its_value_is_not() {
        let text = painted(&furnished());

        let faint = opener(Style::faint);
        let plain = opener(Style::plain);

        assert_ne!(faint, plain);
        assert!(text.contains(&format!("{faint}hardware")), "{text:?}");
        assert!(
            text.contains(&format!("{plain}00:00:5e:00:53:01")),
            "{text:?}"
        );
    }

    /// The two palettes never contend for one piece of text. An address says
    /// which machine this is; a verdict says how it answered. A host being
    /// filtered must not repaint its address, or the colour stops meaning "this
    /// is an address" and starts meaning nothing in particular.
    #[test]
    fn a_verdict_does_not_repaint_an_identifier() {
        let mut filtered = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        filtered.set_status(HostStatus::Filtered);
        filtered.set_hostname(Some("router.example".to_owned()));

        let text = painted(&filtered);
        assert!(
            text.contains(&format!("{}192.0.2.9", opener(Style::strong))),
            "{text:?}"
        );
        assert!(
            text.contains(&format!("{}router.example", opener(Style::accent))),
            "{text:?}"
        );
        assert!(
            text.contains(&format!("{}Filtered", opener(Style::caution))),
            "the verdict keeps its own colour: {text:?}"
        );
    }

    /// Padding is measured on the text, not on the painted text. A painted
    /// string is longer than it looks, and padding inside the escape codes is
    /// padding the terminal cannot see.
    #[test]
    fn colour_does_not_move_the_columns() {
        let mut host = host(30);
        host.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("ssh", 100).with_product("OpenSSH")),
        );
        host.add_port(Port::new(5, Protocol::Tcp, PortState::Filtered));

        let bare = block(&host);
        let coloured = painted(&host);

        let stripped: String = strip_escapes(&coloured);
        assert_eq!(stripped, bare, "colour changed the layout");
    }

    /// Everything a scanned host chose is escaped before it is painted, so a
    /// value cannot carry an escape sequence of its own into the terminal.
    #[test]
    fn a_painted_value_is_still_escaped() {
        let mut scanned = host(1);
        scanned.set_hostname(Some("evil\x1b[2J".to_owned()));

        let text = painted(&scanned);
        assert!(!text.contains("\x1b[2J"), "{text:?}");
        assert!(text.contains("\\x1b[2J"), "{text:?}");
    }

    fn renderer(verbosity: Verbosity) -> (FancyRenderer, Capture, Capture) {
        let records = Capture::default();
        let narration = Capture::default();
        let renderer = FancyRenderer::new(
            Box::new(records.clone()),
            Box::new(narration.clone()),
            verbosity,
            Style::bare(),
            Style::bare(),
        );
        (renderer, records, narration)
    }

    /// Commentary is furniture, and drawn as it.
    ///
    /// What is on standard output is the records; a sentence about how the run
    /// went is not one of them. It used to go out unpainted, which left it at
    /// the terminal's own foreground: brighter than every finding it was talking
    /// about, and the one thing on the screen louder than the addresses.
    #[test]
    fn commentary_is_drawn_as_furniture_and_not_left_bare() {
        let records = Capture::default();
        let narration = Capture::default();
        let mut renderer = FancyRenderer::new(
            Box::new(records.clone()),
            Box::new(narration.clone()),
            Verbosity::default(),
            Style::bare(),
            painting(),
        );

        renderer.interrupted().expect("capture cannot fail");

        let said = narration.text();
        assert!(
            said.starts_with(&opener(Style::faint)),
            "commentary went out unpainted: {said:?}"
        );
        assert!(said.contains("interrupted"), "{said:?}");
    }

    /// Each kind of run counts what it is for, and a record read off disk counts
    /// nothing because nothing is running.
    #[test]
    fn each_phase_counts_what_that_run_is_asking() {
        use crate::target::{ScanTargets, Targets};
        use zond_engine::PortSet;
        use zond_engine::model::target::{TargetMap, TargetSet};

        let ips = "192.0.2.0/30"
            .parse::<zond_engine::IpSet>()
            .expect("a range");
        let swept = Targets::resumed(ips.clone(), 4, "192.0.2.0/30".to_owned());

        let mut plan = TargetMap::new();
        plan.add_unit(TargetSet::new(
            ips,
            "80".parse::<PortSet>().expect("a port"),
        ));
        let scanned = ScanTargets::resumed(plan, 4, "192.0.2.0/30 on 1 port".to_owned());

        assert_eq!(
            counting(Phase::Discovery { targets: &swept }),
            Some(Counting::Hosts)
        );
        assert_eq!(
            counting(Phase::PortScan { targets: &scanned }),
            Some(Counting::Ports)
        );
        assert_eq!(
            counting(Phase::Recorded {
                id: "01AAA",
                started_at: Some(std::time::SystemTime::UNIX_EPOCH),
                produced_by: "0.13.0",
            }),
            None,
            "a record read off disk has nothing running to count"
        );
    }

    #[test]
    fn quiet_narrates_nothing() {
        let (mut renderer, _records, narration) = renderer(Verbosity::new(0, true));
        renderer.progressed(1, 0).expect("capture cannot fail");
        renderer.interrupted().expect("capture cannot fail");
        assert_eq!(narration.text(), "");
    }

    /// Counted from one, because a listing a person reads off a screen is.
    #[test]
    fn the_numbering_starts_at_one() {
        let text = block(&furnished());
        let opening = text.lines().next().expect("a header");

        assert!(opening.trim_start().starts_with('1'), "{opening:?}");
    }
}

#[cfg(test)]
mod hostile {
    use super::*;
    use crate::render::test_support::host;

    /// A block is line-oriented, so a newline in a value a host chose would put
    /// a fact in it that no scan produced. The grammar is plain columns rather
    /// than glyphs, which makes a forgery *easier* to write and no easier to
    /// land: escaping happens before anything is placed.
    #[test]
    fn a_hostname_a_host_chose_cannot_forge_a_fact() {
        let mut scanned = host(1);
        scanned.set_hostname(Some("evil\n     ports     443/tcp  open".to_owned()));

        let style = Style::bare();
        let reader = field::Reader::default();
        let unit = field::listing_unit(field::fastest(&scanned));
        let blocks = vec![Block {
            header: header(style, reader, &scanned, 1, unit),
            children: children(style, reader, &scanned, Verbosity::default(), false),
        }];

        let mut out = Vec::new();
        block::write_all(&mut out, style, &blocks, |_, _| Ok(())).expect("a vector cannot fail");

        let text = String::from_utf8(out).expect("the renderer writes text");
        assert_eq!(
            text.lines().count(),
            1,
            "a value a host chose forged a line: {text}"
        );
        assert!(text.contains("\\n"), "{text}");
    }
}
