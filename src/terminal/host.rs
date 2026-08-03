// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

use std::{net::IpAddr, time::Duration};

use colored::*;
use unicode_width::UnicodeWidthStr;
use zond_engine::core::models::host::Host;
use zond_engine::core::models::port::{Port, PortState, Protocol, Service};

use crate::{
    terminal::{
        colors, format,
        print::{self, Detail, Print, TOTAL_WIDTH},
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

        let ports: Vec<_> = self.ports().cloned().collect();

        // The identity tree flows into the Services subtree, so it must not close
        // itself with a `└─` when ports follow.
        print::as_tree(details, !ports.is_empty());

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

    // Dotted the same way `as_tree` dots its keys (padded to "Hostname"'s width),
    // so the `Services` colon lines up with the identity rows' colons above it.
    let label = "Services";
    let dots = ".".repeat("Hostname".len().saturating_sub(label.len()));
    zprint!(
        " {} {}{}{} {}",
        "└─".bright_black(),
        label.color(colors::TEXT_DEFAULT),
        dots.color(colors::SEPARATOR),
        ":".color(colors::SEPARATOR),
        stats_str
    );

    let detailed = Print::get().detailed;

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

        // The badge hugs its label — `[ OPEN ]`, `[ FILTERED ]` — so there is no
        // dead space inside the brackets. Alignment of the service column that
        // follows is handled *outside* the badge: the whole `[ … ]` token is
        // padded out to the widest badge's width, so a short state simply trails
        // more space after its bracket rather than stretching the bracket itself.
        let (state_str, state_color) = match p.state() {
            PortState::Open => ("OPEN", Color::Green),
            PortState::Filtered => ("FILTERED", Color::Cyan),
            PortState::OpenFiltered => ("OPEN|FIL", Color::Yellow),
            PortState::Closed => ("CLOSED", Color::Red),
            _ => ("UNKNOWN", Color::White),
        };

        // Widest badge is `[ FILTERED ]` / `[ OPEN|FIL ]` at 12 visible columns.
        const STATE_FIELD: usize = 12;
        let badge_width = state_str.len() + 4; // "[ " + label + " ]"
        let state_pad = " ".repeat(STATE_FIELD.saturating_sub(badge_width));
        let state_fmt = format!("[ {} ]{}", state_str.color(state_color), state_pad);

        // Expand into a full attribute tree only under `-D`, and only when the
        // fingerprinter actually resolved something worth breaking out. A bare
        // port→name guess (a closed port, or an open one that stayed silent)
        // stays on a single compact line rather than exploding into a one-row
        // tree that says nothing the port line doesn't already.
        let expand = detailed && p.service().is_some_and(service_has_evidence);

        // When expanding, the identity moves *into* the tree (service, product,
        // version get their own rows), so the port line is left bare. Otherwise
        // it carries the compact summary — with `extrainfo` folded in, since no
        // tree will.
        let trailing = if expand {
            String::new()
        } else {
            format!("  {}", service_summary(p.service(), p.service_name()))
        };

        zprint!(
            "      {} {} {}{}",
            branch,
            port_spec_padded.color(colors::PORT),
            state_fmt,
            trailing
        );

        if expand {
            print_service_detail(p.service(), last);
        }
    }
}

/// Whether a service carries anything beyond the bare port→name heuristic — a
/// product, version, vendor, environment hint, CPE, or a non-zero confidence.
/// Gates the detailed tree so only genuinely fingerprinted ports expand.
fn service_has_evidence(service: &Service) -> bool {
    service.product().is_some()
        || service.version().is_some()
        || service.vendor().is_some()
        || service.extrainfo().is_some()
        || !service.cpe().is_empty()
        || service.confidence() > 0
}

/// Renders a service's one-line summary for the compact (non-`-D`) view: the
/// protocol name, then the identified product and version when fingerprinting
/// resolved them, and finally a trailing `extrainfo` hint in parentheses so
/// nothing the engine learned is dropped when there is no detail tree to carry
/// it.
fn service_summary(service: Option<&Service>, name: Option<&str>) -> String {
    let name = name.unwrap_or("???");
    let mut out = name.color(colors::TEXT_DEFAULT).to_string();

    let Some(service) = service else {
        return out;
    };

    // A product that merely echoes the service name carries no new information.
    if let Some(product) = service.product().filter(|p| *p != name) {
        out.push(' ');
        out.push_str(&product.color(colors::SECONDARY).bold().to_string());
    }

    if let Some(version) = service.version() {
        out.push(' ');
        out.push_str(&version.bright_black().to_string());
    }

    if let Some(extra) = service.extrainfo() {
        out.push(' ');
        out.push_str(&format!("({extra})").bright_black().italic().to_string());
    }

    out
}

/// Prints a service's full fingerprint as a nested detail tree — one dot-aligned
/// child row per resolved attribute, in the same visual language as the host
/// discovery tree. The identity (service, product, version) leads, followed by
/// attribution (vendor, extrainfo, CPE) and the confidence meter. Rows with no
/// data are skipped, so the tree only ever shows what the engine actually
/// learned rather than a column of blanks.
///
/// `port_last` selects the correct continuation glyph so the sub-tree hangs
/// under its port without breaking the outer service tree's vertical guides.
fn print_service_detail(service: Option<&Service>, port_last: bool) {
    let Some(service) = service else {
        return;
    };
    let name = service.name();

    // Identity first, then attribution, then the confidence meter — only the
    // fields the engine actually resolved.
    let mut rows: Vec<Detail> = Vec::new();
    rows.push(("service".into(), name.color(colors::SECONDARY).bold()));
    // A product that merely echoes the service name adds no information.
    if let Some(product) = service.product().filter(|p| *p != name) {
        rows.push(("product".into(), product.color(colors::SECONDARY).bold()));
    }
    if let Some(version) = service.version() {
        rows.push(("version".into(), version.color(colors::TEXT_DEFAULT)));
    }
    if let Some(vendor) = service.vendor() {
        rows.push(("vendor".into(), vendor.color(colors::TEXT_DEFAULT)));
    }
    if let Some(extra) = service.extrainfo() {
        rows.push(("extrainfo".into(), extra.color(colors::TEXT_DEFAULT)));
    }
    for cpe in service.cpe() {
        rows.push(("cpe".into(), cpe.color(colors::SECONDARY)));
    }
    // Confidence is only meaningful once something was probed; a 0 score is the
    // port-number heuristic and says nothing worth a row.
    if service.confidence() > 0 {
        rows.push(("confidence".into(), confidence_bar(service.confidence())));
    }

    // The guide under the port branch: a continuing pipe for a middle port, or
    // blank once the port itself was the last of its tree.
    let guide = if port_last { "  " } else { "│ " }.bright_black();
    let label_width = "confidence".len();

    for (i, (label, value)) in rows.iter().enumerate() {
        let last = i + 1 == rows.len();
        let dbranch = if !last { "├─" } else { "└─" }.bright_black();
        let dots = ".".repeat(label_width.saturating_sub(label.len()));

        zprint!(
            "      {}   {} {}{}{} {}",
            guide,
            dbranch,
            label.color(colors::TEXT_DEFAULT),
            dots.color(colors::SEPARATOR),
            ":".color(colors::SEPARATOR),
            value
        );
    }
}

/// Renders an identification-confidence score (`0..=100`) as a ten-cell meter
/// plus its percentage. The fill color tracks the same tiers the engine's
/// `Confidence` levels project onto, so a glance conveys how much to trust the
/// identification: green for a strong/certain match, yellow for probable, red
/// for a weak signal.
fn confidence_bar(score: u8) -> ColoredString {
    const CELLS: u8 = 10;
    let filled = ((score as u16 * CELLS as u16 + 50) / 100) as u8;
    let filled = filled.clamp(1, CELLS);

    let color = match score {
        90..=100 => Color::Green,
        70..=89 => Color::TrueColor {
            r: 154,
            g: 205,
            b: 50,
        }, // yellow-green
        40..=69 => Color::Yellow,
        _ => Color::Red,
    };

    let meter = format!(
        "{}{}",
        "▰".repeat(filled as usize),
        "▱".repeat((CELLS - filled) as usize)
    );

    format!("{} {:>3}%", meter.color(color), score).color(colors::TEXT_DEFAULT)
}
