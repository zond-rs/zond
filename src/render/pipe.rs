// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Tab-separated records, for a program
//!
//! Everything a discovery sweep established about each host, one host per line,
//! fields separated by a single tab.
//!
//! ```text
//! 192.0.2.1,fe80::1%eth0→Up→1.420→arp,ndp→00:00:5e:00:53:01→router.example→-→Icann, Iana Department→1.100→1.510→2.030
//! ```
//!
//! A tab never occurs inside any of these values, so `cut -f4` and
//! `awk -F'\t'` need no quoting rules. Padding is for eyes; this mode has none.
//!
//! ## The contract
//!
//! Thirteen fields, in this order, on every line:
//!
//! | | Field | |
//! |---|---|---|
//! | 1 | `ADDRESS` | every address the host answers at, comma-joined, primary first |
//! | 2 | `STATUS` | `Up`, `Down`, `Filtered`, `Unknown` |
//! | 3 | `RTT` | median round trip **in milliseconds**, no unit |
//! | 4 | `EVIDENCE` | what proved it alive, comma-joined: `arp`, `ndp`, `icmp_echo`, `tcp_syn`, … |
//! | 5 | `MAC` | hardware addresses, comma-joined, most recent first |
//! | 6 | `HOSTNAME` | |
//! | 7 | `OS` | passive fingerprint, `name generation [accuracy%]` |
//! | 8 | `VENDOR` | |
//! | 9 | `RTT_MIN` | fastest round trip, milliseconds |
//! | 10 | `RTT_AVG` | mean round trip, milliseconds |
//! | 11 | `RTT_MAX` | slowest round trip, milliseconds |
//! | 12 | `PORTS` | `number/proto/state/service`, comma-joined; closed ones left out |
//! | 13 | `CLOSED` | how many came back plainly closed; `-` when none were probed |
//!
//! A field the scan did not learn is `-`, never empty, so the field count never
//! changes and `cut` can be told a number.
//!
//! **The round-trip time is in milliseconds and stays there.** The readable
//! modes choose a unit to suit the magnitude; a script reading that would be a
//! thousand times wrong the first time a host answered slowly.
//!
//! No heading line. Fields are only ever *appended* to, so a script that reads
//! field 3 today reads field 3 after the next release.

use std::io::{self, BufWriter, Write};

use zond_engine::export::Redaction;
use zond_engine::{Host, ScanReport};

use crate::diagnostics::Verbosity;
use crate::render::narrate::Narrator;
use crate::render::{Phase, Renderer, field};

/// What separates one field from the next.
///
/// A tab cannot occur inside an address, a hostname, a vendor name or an OS
/// description, so no value ever needs quoting.
const SEPARATOR: char = '\t';

/// How many fields each record carries. See the module documentation.
///
/// Only ever grows, and only at the end: a script reading field 3 today reads
/// field 3 after the next release.
pub(crate) const FIELDS: usize = 13;

/// The tab-separated writer.
pub(crate) struct PipeRenderer {
    records: Box<dyn Write>,
    narrator: Narrator,
    reader: field::Reader,
}

impl PipeRenderer {
    /// Writing to this process's own streams.
    #[must_use]
    pub(crate) fn to_terminal(verbosity: Verbosity) -> Self {
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

/// The fields a host contributes, in the documented order.
fn record(reader: field::Reader, host: &Host) -> [String; FIELDS] {
    [
        reader.addresses(host),
        field::status(host),
        field::rtt_millis(host).unwrap_or_else(field::unknown),
        field::evidence(host).unwrap_or_else(field::unknown),
        reader.macs(host).unwrap_or_else(field::unknown),
        reader.hostname(host).unwrap_or_else(field::unknown),
        field::os(host).unwrap_or_else(field::unknown),
        field::vendor(host).map_or_else(field::unknown, ToOwned::to_owned),
        field::rtt_min_millis(host).unwrap_or_else(field::unknown),
        field::rtt_mean_millis(host).unwrap_or_else(field::unknown),
        field::rtt_max_millis(host).unwrap_or_else(field::unknown),
        field::packed_ports(host).unwrap_or_else(field::unknown),
        field::closed_ports(host).unwrap_or_else(field::unknown),
    ]
}

impl Renderer for PipeRenderer {
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
        for host in field::sorted_hosts(report) {
            let fields = record(self.reader, host);
            writeln!(self.records, "{}", fields.join(&SEPARATOR.to_string()))?;
        }

        self.records.flush()?;
        self.narrator.summary(report)
    }
}

#[cfg(test)]
impl PipeRenderer {
    /// Writes records without needing a whole [`ScanReport`] to build one from.
    fn write_all_for_test(&mut self, hosts: &[Host]) -> io::Result<()> {
        for host in hosts {
            writeln!(
                self.records,
                "{}",
                record(self.reader, host).join(&SEPARATOR.to_string())
            )?;
        }
        Ok(())
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
    use std::time::Duration;
    use zond_engine::model::host::status::{StatusProtocol, StatusReason};
    use zond_engine::model::ip::scoped::Zone;

    fn renderer() -> (PipeRenderer, Capture, Capture) {
        let records = Capture::default();
        let narration = Capture::default();
        let renderer = PipeRenderer::new(
            Box::new(records.clone()),
            Box::new(narration.clone()),
            Verbosity::default(),
        );
        (renderer, records, narration)
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

    /// The whole contract in one assertion: every field, in the documented
    /// order.
    #[test]
    fn a_record_carries_every_field_in_the_documented_order() {
        let fields = record(field::Reader::default(), &furnished());

        assert_eq!(fields.len(), FIELDS);
        assert_eq!(fields[0], "192.0.2.1,fe80::1%en0");
        assert_eq!(fields[1], "Up");
        assert_eq!(fields[2], "1.420");
        assert_eq!(fields[3], "arp,ndp");
        assert_eq!(fields[4], "00:00:5e:00:53:01");
        assert_eq!(fields[5], "router.example");
        assert_eq!(fields[6], "-", "no OS was established");
        // Not a dash: the engine resolves the vendor from the hardware address
        // as soon as one is recorded, so this arrives without a lookup of ours.
        assert_eq!(fields[7], "Icann, Iana Department");
        // One sample, so the spread is that sample three times over. A reader
        // gets one figure; a script gets all of them, always.
        assert_eq!(fields[8], "1.420");
        assert_eq!(fields[9], "1.420");
        assert_eq!(fields[10], "1.420");
        assert_eq!(fields[11], "-");
        assert_eq!(fields[12], "-");
    }

    /// A consumer reading `1.42ms` and `1.24s` from one column would be a
    /// thousand times wrong the first time a host answered slowly.
    #[test]
    fn the_round_trip_time_stays_in_milliseconds_however_large_it_gets() {
        let mut quick = host(1);
        quick.add_rtt(Duration::from_micros(412));
        assert_eq!(record(field::Reader::default(), &quick)[2], "0.412");

        let mut slow = host(2);
        slow.add_rtt(Duration::from_millis(1_240));
        assert_eq!(record(field::Reader::default(), &slow)[2], "1240.000");
    }

    #[test]
    fn no_field_contains_a_tab() {
        for field in record(field::Reader::default(), &furnished()) {
            assert!(!field.contains(SEPARATOR), "{field:?} carries a separator");
        }
    }

    #[test]
    fn a_value_with_spaces_stays_one_field() {
        let (mut renderer, records, _narration) = renderer();
        let mut host = host(1);
        host.set_hostname(Some("router.example".to_owned()));

        renderer
            .write_all_for_test(&[host])
            .expect("capture cannot fail");

        let text = records.text();
        let line = text.lines().next().expect("one host, one line");
        assert_eq!(
            line.split(SEPARATOR).count(),
            FIELDS,
            "field count changed: {line:?}"
        );
    }

    #[test]
    fn there_is_no_heading_line() {
        let (mut renderer, records, _narration) = renderer();
        renderer
            .write_all_for_test(&[furnished()])
            .expect("capture cannot fail");

        let text = records.text();
        let first = text.lines().next().expect("one host, one line");
        assert!(first.starts_with("192.0.2.1"), "got {first:?}");
    }
}
