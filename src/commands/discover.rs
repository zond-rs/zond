// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Discovery Command Implementation
//!
//! Implements the logic for `zond discover`.
//!
//! This module wraps the core scanning functionality with the necessary terminal UI.
//! Since the core `scanner` module is silent and purely functional, this module is responsible
//! for noise operations: parsing CLI strings, managing the loading spinner, and rendering
//! the final report table.
//!
//! ## Execution Flow
//!
//! 1.  **Parse**: Converts raw target strings (e.g., "10.0.0.0/24") into a valid [`IpCollection`].
//! 2.  **Monitor**: Spawns a background spinner to show progress during the async scan.
//! 3.  **Execute**: Calls [`scanner::discover`] to do the actual scanning.
//! 4.  **Render**: Sorts the resulting host list by IP and prints the summary to stdout.

use std::time::Instant;

use crate::terminal::colors;
use crate::terminal::input;
use crate::terminal::print::Print;
use crate::terminal::spinner::SpinnerGuard;
use colored::*;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::info_span;
use zond_engine::core::config::ZondConfig;
use zond_engine::core::models::host::Host;
use zond_engine::core::parse;
use zond_engine::scanner;
use zond_engine::system::interface;

/// Runs the active discovery scan on the provided targets.
///
/// This handles the full scan lifecycle: parsing the target strings, managing the
/// progress spinner, and printing the sorted results to stdout.
///
/// If no hosts are found, it prints a "No results" message and exits cleanly.
///
/// # Arguments
///
/// * `targets` - Raw target strings from the CLI (e.g., `["192.168.1.1", "10.0.0.0/24"]`).
/// * `cfg` - Scan configuration (timeout, ports, etc).
///
/// # Errors
///
/// Returns an error if:
/// * The target strings cannot be parsed into valid IPs or CIDRs.
/// * The underlying scanner encounters a fatal network error.
pub async fn discover(targets: &[String], cfg: &ZondConfig) -> anyhow::Result<()> {
    Print::header("performing host discovery");
    let ip_set = parse::to_ipset(targets, Some(interface::resolve::resolve))?;
    let start_time = Instant::now();

    let (session, scan_task) = scanner::discover(ip_set, cfg).await?;
    let _input_guard = input::start_listener(session.handle.clone());
    let _guard: SpinnerGuard = run_spinner(session.store.clone());

    scan_task.await??;
    let mut hosts: Vec<Host> = session.store.iter().map(|kv| kv.value().clone()).collect();

    if hosts.is_empty() {
        Print::no_results();
        return Ok(());
    }
    hosts.sort_by_key(|host| *host.ips().iter().next().unwrap_or(&host.primary_ip()));

    Print::header("Network Discovery");
    Print::hosts(&hosts)?;
    Print::discovery_summary(hosts.len(), start_time.elapsed());

    Ok(())
}

fn run_spinner(store: Arc<DashMap<IpAddr, Host>>) -> SpinnerGuard {
    let span = info_span!("discover", indicatif.pb_show = true);
    let _enter = span.enter();

    SpinnerGuard::with_status(span.clone(), move || {
        let count = store.len();
        let count_str = count.to_string().green().bold();
        let label = if count == 1 { "host" } else { "hosts" };
        format!("Identified {} {} so far...", count_str, label)
            .color(colors::TEXT_DEFAULT)
            .italic()
    })
}
