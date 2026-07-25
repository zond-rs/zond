// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::{net::IpAddr, time::Duration};

use colored::*;
use unicode_width::UnicodeWidthStr;
use zond_engine::core::models::host::Host;
use zond_engine::core::models::port::{Port, PortState, Protocol};

use crate::{
    terminal::{
        colors, format,
        print::{self, Print, TOTAL_WIDTH},
    },
    zprint,
};

/// Provides terminal printing capabilities for network hosts.
///
/// This trait encapsulates the visual formatting and standard output routing
/// for a given host record, ensuring consistent terminal representation.
pub(crate) trait PrintableHost {
    /// Evaluates the host's details and configuration state to print
    /// a formatted tree representation to the standard output.
    ///
    /// # Arguments
    ///
    /// * `index` - The chronological index of the host in the current discovery sequence.
    fn print(&self, index: usize);
}

impl PrintableHost for Host {
    fn print(&self, index: usize) {
        let p = Print::get();
        let primary_ip: IpAddr = self.primary_ip();

        print_host_head(index, &primary_ip, self);

        let mut details = format::ip_to_detail(self, p.redact);

        if let Some(mac_detail) = format::mac_to_detail(self.mac(), p.redact) {
            details.push(mac_detail);
        }

        if let Some(vendor_detail) = format::vendor_to_detail(self.vendor()) {
            details.push(vendor_detail);
        }

        if let Some(hostname_detail) = format::hostname_to_detail(self.hostname(), p.redact) {
            details.push(hostname_detail);
        }

        print::as_tree(details);

        let ports: Vec<_> = self.ports().cloned().collect();
        if !ports.is_empty() {
            print_services(&ports);
        }
    }
}

/// Formats and prints the primary header line for a host.
///
/// Constructs the top-level identifier for a host in the terminal tree,
/// aligning the index, primary IP address, and the calculated Round Trip Time (RTT).
///
/// # Arguments
///
/// * `idx` - The enumeration index of the host.
/// * `primary_ip` - The main IP address of the responding host.
/// * `host` - Reference to the host model to extract RTT metrics.
fn print_host_head(idx: usize, primary_ip: &IpAddr, host: &Host) {
    let rtt_string: String = rtt_to_string(host);
    let rtt_width: usize = rtt_string.width();

    let block_width: usize = 20;
    let local_pad: usize = block_width.saturating_sub(rtt_width);
    let right_part: String = format!("{}{}", " ".repeat(local_pad), rtt_string);

    let left_part: String = format!("[{}] {}", idx, primary_ip);
    let used_width: usize = left_part.width() + block_width;

    let padding_len: usize = TOTAL_WIDTH.saturating_sub(used_width + 1);
    let padding: String = " ".repeat(padding_len);

    zprint!(
        "{} {}{}{}",
        format!("[{}]", idx.to_string().color(colors::ACCENT)).color(colors::SEPARATOR),
        primary_ip.to_string().color(colors::PRIMARY),
        padding,
        right_part.color(colors::SECONDARY)
    );
}

/// Computes a formatted string representing the host's median Round Trip Time (RTT).
///
/// The median is a single, outlier-resistant summary of typical latency. The
/// value is rendered with three significant figures and a fixed-width numeric
/// field (e.g. `2.34ms`, `27.1ms`, ` 108ms`) so the `ms` units line up across
/// every host row.
///
/// # Arguments
///
/// * `host` - The host model containing recorded RTT measurements.
fn rtt_to_string(host: &Host) -> String {
    let Some(median) = host.median_rtt() else {
        return String::new();
    };

    format!("⌛ {}", format_rtt(median))
}

/// Formats a duration as milliseconds with three significant figures in a
/// fixed four-character field, so the trailing `ms` aligns column-to-column.
///
/// Examples: `2.34ms`, `27.1ms`, ` 108ms`, `1234ms`.
fn format_rtt(rtt: Duration) -> String {
    let ms = rtt.as_secs_f64() * 1000.0;

    let value = if ms < 10.0 {
        format!("{ms:.2}")
    } else if ms < 100.0 {
        format!("{ms:.1}")
    } else {
        format!("{ms:.0}")
    };

    format!("{value:>4}ms")
}

fn print_services(ports: &[Port]) {
    let mut open_c = 0;
    let mut filtered_c = 0;
    let mut _closed_c = 0;
    for p in ports {
        match p.state() {
            PortState::Open => open_c += 1,
            PortState::Filtered | PortState::OpenFiltered => filtered_c += 1,
            PortState::Closed => _closed_c += 1,
            _ => (),
        }
    }

    let mut stats = Vec::new();
    if open_c > 0 {
        stats.push(format!("{} OPEN", open_c).green().bold().to_string());
    }
    if filtered_c > 0 {
        stats.push(format!("{} FILTERED", filtered_c).cyan().bold().to_string());
    }

    let stats_str = if stats.is_empty() {
        "ALL CHECKS CLOSED".dimmed().to_string()
    } else {
        stats.join(&format!("{}", "  /  ".bright_black().bold()))
    };

    zprint!(
        " {} {}{}{} {}",
        "└─".bright_black(),
        "SERVICES".color(colors::TEXT_DEFAULT),
        ".".repeat(2).color(colors::SEPARATOR),
        ":".color(colors::SEPARATOR),
        stats_str
    );

    for (i, p) in ports.iter().enumerate() {
        let last = i + 1 == ports.len();
        let branch = if !last { "├─" } else { "└─" }.bright_black();

        let proto_str = match p.protocol() {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        };
        let port_spec = format!("{}/{}", p.number(), proto_str);
        let port_spec_padded = format!("{:width$}", port_spec, width = 9);

        let (state_str, state_color) = match p.state() {
            PortState::Open => ("OPEN   ", Color::Green),
            PortState::Filtered => ("FILTERED", Color::Cyan),
            PortState::OpenFiltered => ("OPEN|FIL", Color::Yellow),
            PortState::Closed => ("CLOSED ", Color::Red),
            _ => ("UNKNOWN", Color::White),
        };

        let state_fmt = format!("[ {} ]", state_str.color(state_color));
        let svc_name = p.service_name().unwrap_or("???");

        zprint!(
            "      {} {} {}  {}",
            branch,
            port_spec_padded.color(colors::PRIMARY),
            state_fmt,
            svc_name.color(colors::TEXT_DEFAULT)
        );
    }
}
