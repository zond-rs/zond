// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A tagged block per host, for reading
//!
//! ```text
//! discovering 64 addresses (192.0.2.0/26)      <- stderr
//! found 192.0.2.1 +1                           <- stderr, as it happens
//! found 192.0.2.30
//!                                              <- stdout, from here
//! * 192.0.2.1 [router.example]
//!   mac:  00:00:5e:00:53:01 (Icann, Iana Department)
//!   rtt:  min 1.10ms  avg 1.51ms  max 2.03ms
//!   via:  arp, ndp
//!   also: 2001:db8::1
//!         fe80::1%eth0
//!
//! * 192.0.2.30 [printer.example]
//!   mac:  00:00:5e:00:53:02 (Icann, Iana Department)
//!   os:   Linux [84%]
//!   rtt:  12.1ms
//!   via:  arp
//!   port: 22/tcp open (ssh OpenSSH 9.6)
//!         80/tcp open (http nginx 1.24)
//!         5/tcp filtered
//!         [996 closed ports omitted]
//!
//! * 2001:db8::4
//!   mac:  02:00:5e:00:53:04
//!   rtt:  8.20ms
//!   via:  ndp
//!
//! 3 hosts up of 64 addresses in 1.42s            <- stderr
//! ```
//!
//! The address identifies the machine, so it opens the block and takes the
//! hostname with it. Everything else is a tagged line, and every tag is short
//! enough that the values line up under one column.
//!
//! A block pays only for what it has: a host nothing is known about is one
//! line, a well-furnished one is seven. Nothing is padded to the width of the
//! most interesting host in the sweep, and nothing runs off the right edge. The
//! cost is length — a `/24` with two hundred live hosts is long, and that is
//! what `--pipe` is for.
//!
//! **A missing line was not learned.** There are no placeholders. The one line
//! that means something by its absence is `status`, which appears only when the
//! host is not simply up — so an address something is filtering stands out
//! instead of being one block among two hundred.

use std::io::{self, BufWriter, Write};

use zond_engine::export::Redaction;
use zond_engine::{Host, ScanReport};

use crate::diagnostics::Verbosity;
use crate::render::narrate::Narrator;
use crate::render::{Phase, Renderer, field};

/// What opens a host's block.
const BULLET: &str = "* ";

/// What each tagged line is indented by.
const INDENT: &str = "  ";

/// The width a tag is padded to, its colon included.
///
/// Five, which is `also:` and `port:` — the longest. Every value therefore
/// begins in the same column, which is what lets an eye run down them. A longer
/// tag would still print and would push its own value out by however much it
/// overran, so this is an alignment choice rather than a limit.
const TAG_WIDTH: usize = 5;

/// The column every value begins in.
const VALUE_COLUMN: usize = INDENT.len() + TAG_WIDTH + 1;

/// The tagged-block renderer.
pub(crate) struct MinimalRenderer {
    records: Box<dyn Write>,
    narrator: Narrator,
    reader: field::Reader,
}

impl MinimalRenderer {
    /// Writing to this process's own streams.
    #[must_use]
    pub(crate) fn to_terminal(verbosity: Verbosity) -> Self {
        // Records are buffered — thousands of lines in one burst at the end.
        // Commentary is not: a progress line held in a buffer is not progress.
        Self::new(
            Box::new(BufWriter::new(io::stdout())),
            Box::new(io::stderr()),
            verbosity,
        )
    }

    /// Writing wherever the caller says, which is how this is tested.
    #[must_use]
    pub(crate) fn new(
        records: Box<dyn Write>,
        narration: Box<dyn Write>,
        verbosity: Verbosity,
    ) -> Self {
        Self {
            records,
            narrator: Narrator::new(narration, verbosity),
            reader: field::Reader::default(),
        }
    }
}

/// Writes one host's block.
fn write_host(out: &mut dyn Write, reader: field::Reader, host: &Host) -> io::Result<()> {
    // The address and the name are one fact — which machine this is — so they
    // share the line that opens the block rather than the name sitting among
    // the things that were learned about it.
    match reader.hostname(host) {
        Some(name) => writeln!(out, "{BULLET}{} [{name}]", reader.primary(host))?,
        None => writeln!(out, "{BULLET}{}", reader.primary(host))?,
    }

    if !field::is_up(host) {
        tag(out, "status", &field::status(host))?;
    }

    // The vendor was read from the hardware address, so it is shown against it.
    if let Some(macs) = reader.macs(host) {
        let line = match field::vendor(host) {
            Some(vendor) => format!("{macs} ({vendor})"),
            None => macs,
        };
        tag(out, "mac", &line)?;
    }

    for (name, value) in [
        ("os", field::os(host)),
        ("rtt", field::rtt_human(host)),
        ("via", field::via(host)),
    ] {
        if let Some(value) = value {
            tag(out, name, &value)?;
        }
    }

    // Last, and one line each: a host with forty open ports is a list, and a
    // list comma-joined into one value runs off the screen.
    tagged_list(out, "also", &reader.other_addresses(host))?;
    tagged_list(out, "port", &field::ports(host))?;

    Ok(())
}

/// One tagged line.
fn tag(out: &mut dyn Write, name: &str, value: &str) -> io::Result<()> {
    writeln!(out, "{INDENT}{:<TAG_WIDTH$} {value}", format!("{name}:"))
}

/// A line per value, tagged once and then aligned under itself.
fn tagged_list(out: &mut dyn Write, name: &str, values: &[String]) -> io::Result<()> {
    for (index, value) in values.iter().enumerate() {
        if index == 0 {
            tag(out, name, value)?;
        } else {
            writeln!(out, "{:VALUE_COLUMN$}{value}", "")?;
        }
    }

    Ok(())
}

impl Renderer for MinimalRenderer {
    fn started(&mut self, phase: Phase<'_>, redaction: Redaction) -> io::Result<()> {
        self.reader = field::Reader::new(redaction);
        self.narrator.started(phase, redaction)
    }

    fn host_found(&mut self, host: &Host) -> io::Result<()> {
        self.narrator.found(host)
    }

    fn interrupted(&mut self) -> io::Result<()> {
        self.narrator.interrupted()
    }

    fn finished(&mut self, report: &ScanReport) -> io::Result<()> {
        let hosts = field::sorted_hosts(report);

        for (index, host) in hosts.iter().enumerate() {
            // The separator belongs to the listing, so it goes on the record
            // stream. Above the first block only if there is commentary to
            // separate it from.
            if index > 0 || self.narrator.narrates() {
                writeln!(self.records)?;
            }
            write_host(&mut self.records, self.reader, host)?;
        }

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
    use crate::render::test_support::{Capture, host};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use zond_engine::export::Redaction;
    use zond_engine::model::host::status::{StatusProtocol, StatusReason};
    use zond_engine::model::ip::scoped::Zone;
    use zond_engine::{HostStatus, Port, PortState, Protocol, Service};

    fn block(host: &Host) -> String {
        rendered(field::Reader::default(), host)
    }

    fn rendered(reader: field::Reader, host: &Host) -> String {
        let mut out = Vec::new();
        write_host(&mut out, reader, host).expect("a vector cannot fail");
        String::from_utf8(out).expect("the renderer writes text")
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
        host
    }

    #[test]
    fn a_furnished_host_reads_as_a_tagged_block() {
        assert_eq!(
            block(&furnished()),
            "* 192.0.2.1 [router.example]\n\
             \x20 mac:  00:00:5e:00:53:01 (Icann, Iana Department)\n\
             \x20 rtt:  1.42ms\n\
             \x20 via:  arp, ndp\n\
             \x20 also: fe80::1%en0\n"
        );
    }

    /// The name says which machine this is, so it belongs with the address
    /// rather than among the things that were learned about it.
    #[test]
    fn a_host_with_no_name_opens_with_the_address_alone() {
        let mut host = furnished();
        host.set_hostname(None);

        assert!(
            block(&host).starts_with("* 192.0.2.1\n"),
            "{}",
            block(&host)
        );
    }

    /// The vendor was read from the hardware address, so it is shown against it
    /// rather than on a line of its own.
    #[test]
    fn the_vendor_sits_on_the_hardware_line() {
        assert!(
            block(&furnished()).contains("mac:  00:00:5e:00:53:01 (Icann, Iana Department)"),
            "{}",
            block(&furnished())
        );
    }

    /// One line per address, aligned under the tag rather than comma-joined into
    /// a value that runs off the screen.
    #[test]
    fn further_addresses_get_a_line_each() {
        let mut host = furnished();
        host.add_ip("2001:db8::1".parse().expect("a valid address"));

        let text = block(&host);
        let also: Vec<&str> = text
            .lines()
            .skip_while(|line| !line.contains("also:"))
            .collect();

        assert_eq!(also.len(), 2, "{text}");
        assert!(also[0].starts_with("  also: "), "{text}");
        assert_eq!(
            &also[1][..VALUE_COLUMN],
            " ".repeat(VALUE_COLUMN),
            "a continued value is aligned under the first: {text}"
        );
    }

    #[test]
    fn ports_are_tagged_once_and_listed_under_it() {
        let mut host = host(1);
        host.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("ssh", 100).with_product("OpenSSH")),
        );
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Closed));

        let text = block(&host);
        assert!(text.contains("  port: 22/tcp open (ssh OpenSSH)"), "{text}");
        assert!(text.contains("\n        [1 closed port omitted]"), "{text}");
    }

    #[test]
    fn redaction_masks_the_name_the_hardware_and_the_address() {
        let masked = rendered(field::Reader::new(Redaction::Standard), &furnished());

        assert!(!masked.contains("router.example"), "{masked}");
        assert!(!masked.contains("00:00:5e:00:53:01"), "{masked}");
    }

    /// A link-local address derives its host part from the hardware address, so
    /// masking the MAC while printing the address hands the MAC straight back.
    #[test]
    fn a_link_local_address_cannot_give_back_the_hardware_address() {
        let mut host = host(1);
        host.set_zone(Zone::new(4, "en0"));
        host.add_ip("fe80::200:5eff:fe00:5301".parse().expect("a valid address"));
        host.record_mac("00:00:5e:00:53:01".parse().expect("a valid address"));

        let masked = rendered(field::Reader::new(Redaction::Standard), &host);

        assert!(
            !masked.contains("fe00:5301"),
            "the host part survived masking: {masked}"
        );
    }

    /// Redaction is off unless asked for. A scan holds what it found.
    #[test]
    fn nothing_is_masked_by_default() {
        let plain = block(&furnished());
        assert!(plain.contains("router.example"), "{plain}");
        assert!(plain.contains("00:00:5e:00:53:01"), "{plain}");
    }

    #[test]
    fn a_host_nothing_is_known_about_carries_no_empty_lines() {
        let mut host = host(36);
        host.add_rtt(Duration::from_micros(8_200));
        host.record_mac("02:00:5e:00:53:04".parse().expect("a valid address"));
        host.add_reason(StatusReason::new(StatusProtocol::Arp, "reply"));

        assert_eq!(
            block(&host),
            "* 192.0.2.36\n\
             \x20 mac:  02:00:5e:00:53:04\n\
             \x20 rtt:  8.20ms\n\
             \x20 via:  arp\n"
        );
    }

    #[test]
    fn an_unknown_fact_produces_no_line() {
        let bare = block(&host(1));

        assert_eq!(bare, "* 192.0.2.1\n");
        for absent in ["mac:", "rtt:", "os:", "via:", "also:", "port:", "[", "-"] {
            assert!(!bare.contains(absent), "{absent:?} in {bare:?}");
        }
    }

    #[test]
    fn status_appears_only_when_it_is_not_simply_up() {
        assert!(!block(&host(1)).contains("status"));

        // Built directly rather than through the `host` helper: the engine
        // promotes a status and never lowers one, so a host marked `Up` first
        // would stay `Up` and this test would be asserting nothing.
        let mut filtered = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        filtered.set_status(HostStatus::Filtered);
        assert!(block(&filtered).contains("status: Filtered"));
    }

    /// Every value begins in the same column, whatever the tag above it was.
    /// That column is what lets an eye run down the values.
    #[test]
    fn every_tag_lines_its_value_up_with_the_others() {
        let text = block(&furnished());
        let mut lines = text.lines();

        assert!(lines.next().expect("a header line").starts_with(BULLET));

        for line in lines {
            assert!(line.starts_with(INDENT), "not indented: {line:?}");
            assert!(
                !line[VALUE_COLUMN..].starts_with(' '),
                "value does not begin at column {VALUE_COLUMN}: {line:?}"
            );
        }
    }

    /// A link-local primary still names the interface that makes it mean
    /// something.
    #[test]
    fn a_link_local_primary_keeps_its_zone() {
        let mut host = Host::new("fe80::9".parse().expect("a valid address"));
        host.set_status(HostStatus::Up);
        host.set_zone(Zone::new(4, "en0"));
        host.add_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let text = block(&host);
        assert!(text.starts_with("* fe80::9%en0\n"), "{text}");
        assert!(text.contains("also: 10.0.0.1"), "{text}");
    }

    fn renderer(verbosity: Verbosity) -> (MinimalRenderer, Capture, Capture) {
        let records = Capture::default();
        let narration = Capture::default();
        let renderer = MinimalRenderer::new(
            Box::new(records.clone()),
            Box::new(narration.clone()),
            verbosity,
        );
        (renderer, records, narration)
    }

    /// Nothing but the records reaches the other end of a pipe.
    #[test]
    fn progress_never_reaches_the_record_stream() {
        let (mut renderer, records, narration) = renderer(Verbosity::default());
        renderer.host_found(&host(1)).expect("capture cannot fail");
        renderer.host_found(&host(2)).expect("capture cannot fail");

        assert_eq!(records.text(), "");
        assert!(narration.text().contains("found 192.0.2.1"));
        assert!(narration.text().contains("found 192.0.2.2"));
    }

    #[test]
    fn a_host_is_announced_once_however_often_it_is_updated() {
        let (mut renderer, _records, narration) = renderer(Verbosity::default());
        for _ in 0..5 {
            renderer.host_found(&host(1)).expect("capture cannot fail");
        }
        assert_eq!(narration.text().matches("found 192.0.2.1").count(), 1);
    }

    #[test]
    fn quiet_narrates_nothing() {
        let (mut renderer, _records, narration) = renderer(Verbosity::new(0, true));
        renderer.host_found(&host(1)).expect("capture cannot fail");
        renderer.interrupted().expect("capture cannot fail");
        assert_eq!(narration.text(), "");
    }
}
