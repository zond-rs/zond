// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scaffolding the presentation tests share.
//!
//! Three things every module that draws needs: somewhere to write, a host to
//! draw, and a way to read a painted string back. The last two exist here rather
//! than once per module because four copies of an escape stripper is four
//! chances for one of them to be subtly wrong about what it is measuring.

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use zond_engine::{Host, HostStatus};

use crate::render::style::{ColourChoice, Palette, Style};

/// A writer that keeps what was written, so a test can read it back.
///
/// The `Arc<Mutex<..>>` is what lets the test hold one end while the renderer
/// owns the other.
#[derive(Clone, Default)]
pub(crate) struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    /// Everything written so far.
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("not poisoned").clone())
            .expect("a renderer writes text")
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("not poisoned").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A live host at `192.0.2.<last_octet>`, with nothing else known about it.
///
/// TEST-NET-1 (RFC 5737), like every other address, name and hardware address in
/// this crate's tests and documentation. None of it is a network anyone has.
pub(crate) fn host(last_octet: u8) -> Host {
    let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet)));
    host.set_status(HostStatus::Up);
    host
}

/// A style that actually paints, for the tests that are about colour.
///
/// `Always` rather than a detected style, because `cargo test` runs with
/// standard output redirected and nothing would be painted at all.
pub(crate) fn painting() -> Style {
    Style::detect(Palette::when(ColourChoice::Always), false)
}

/// The escape sequence `role` opens with, taken from the style rather than
/// written out.
///
/// These tests are about which role a field takes, not about what the palette
/// currently resolves that role to: moving a colour should not move a test, and
/// moving a *field* to a different role should break one.
pub(crate) fn opener(role: fn(Style, &str) -> String) -> String {
    let painted = role(painting(), "x");
    let at = painted.find('x').expect("the sentinel survives painting");
    painted[..at].to_owned()
}

/// `text` with every escape sequence taken out, so a painted drawing can be
/// compared against the bare one.
///
/// What is checked with this is that colour changed nothing but the colour. A
/// column measured on painted text is a column the terminal does not have, and
/// stripping is how that shows up as a failing equality rather than as a ragged
/// screen.
pub(crate) fn strip_escapes(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut characters = text.chars();

    while let Some(character) = characters.next() {
        if character != '\x1b' {
            plain.push(character);
            continue;
        }
        // Everything up to and including the `m` that ends the sequence.
        for inside in characters.by_ref() {
            if inside == 'm' {
                break;
            }
        }
    }

    plain
}

/// When [`scoped`] says its scan began: fixed, so nothing drawn from one of
/// these moves between runs.
pub(crate) fn recorded_at() -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_780_000_000)
}

/// A report of one discovery phase that says it walked `covered`.
///
/// What a comparison needs and a live scan cannot give it: two reports whose
/// *scope* is known, so that a host missing from one can be told apart from a
/// host that one of them never looked for. The phase carries a fixed start time,
/// so nothing drawn from it moves between runs.
pub(crate) fn scoped(hosts: Vec<Host>, covered: &str) -> zond_engine::ScanReport {
    scoped_at(hosts, covered, recorded_at())
}

/// The same report, with its scan placed at `started_at`.
///
/// For the tests that need two reports a clock apart. Anything that folds or
/// compares reports orders them by their own timing, so a test asserting on that
/// order cannot use two reports built at the same fixed instant.
pub(crate) fn scoped_at(
    hosts: Vec<Host>,
    covered: &str,
    started_at: std::time::SystemTime,
) -> zond_engine::ScanReport {
    use std::time::Duration;

    use zond_engine::ZondConfig;
    use zond_engine::model::exclusion::Exclusions;
    use zond_engine::model::parse::ip::to_set;
    use zond_engine::scanner::report::{
        PhaseParts, ScanKind, ScanPhase, ScanReport, ScanSettings, TargetScope,
    };

    let mut targets = to_set(&[covered], None, None).expect("a parseable range");
    let phase = ScanPhase::from_parts(PhaseParts {
        kind: ScanKind::Discovery,
        started_at,
        elapsed: Duration::from_secs(1),
        privileged: Some(true),
        targets: TargetScope::from_ip_set(&mut targets, &Exclusions::none()),
        settings: ScanSettings::from(&ZondConfig::default()),
        failures: Vec::new(),
        unroutable: Vec::new(),
        probes: Vec::new(),
        origin: None,
    });

    ScanReport::recorded("test", vec![phase], hosts)
}
