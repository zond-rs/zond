// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scaffolding the presentation tests share.

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use zond_engine::{Host, HostStatus};

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
