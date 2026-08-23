// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The subcommands
//!
//! One module per subcommand, and the parts they have in common.
//!
//! A subcommand's own job is deciding *what* to scan: which settings apply,
//! what the target expressions stand for, and which of the engine's two entry
//! points to call. Everything after that call is the same either way, and is
//! [`drive`] — the engine hands back the same pair whichever phase was asked
//! for, so watching one is watching the other.
//!
//! Nothing here formats anything, and nothing here decides an exit code. Those
//! belong to [`render`](crate::render) and [`exit`](crate::exit).

pub(crate) mod discover;
pub(crate) mod journal;
pub(crate) mod scan;

use std::collections::HashSet;
use std::net::IpAddr;

use zond_engine::export::Redaction;
use zond_engine::model::host::Host;
use zond_engine::{ScanEvent, ScanReport, ScanSession, ScanTask, ZondConfig};

use crate::error::Error;
use crate::exit::Outcome;
use crate::input;
use crate::render::Renderer;
use crate::settings;

/// What the engine's settings files said, with what they could not be used for
/// reported on the way past.
fn engine_settings(profile: Option<&str>) -> Result<settings::EngineSettings, Error> {
    let (settings, warnings) = settings::engine(profile)?;

    for warning in warnings {
        tracing::warn!("{warning}");
    }

    Ok(settings)
}

/// The masking policy a resolved configuration settles on.
///
/// The engine only records the intent — it holds everything a scan found — so
/// masking on the way out is this program's job, and a `--redact` that did not
/// reach the renderer would be a flag that does nothing.
fn redaction(config: &ZondConfig) -> Redaction {
    if config.redact {
        Redaction::Standard
    } else {
        Redaction::None
    }
}

/// Runs a scan the engine has already been asked for, and reports it.
///
/// Watches the run happen so a person sees hosts as they are found rather than
/// after a silence, stops cleanly when they ask it to, and says what the run
/// amounted to. See [`input`] for what counts as asking.
async fn drive(
    session: ScanSession,
    task: ScanTask,
    renderer: &mut dyn Renderer,
) -> Result<Outcome, Error> {
    // Taken apart because holding the whole session would borrow it twice in
    // the `select!` below.
    let (hosts, mut events, handle) = session.into_parts();
    let mut stops = input::watch(&handle);

    // Gates the message and the escalation only. What the run amounted to is
    // read from the handle afterwards.
    let mut announced = false;
    // Addresses already announced, so the same host is not fetched again for
    // every remaining port of it.
    //
    // A port scan changes a host once per port and fires an event each time, and
    // the renderer announces an address once — so all but the first of those
    // events end in a discard. Answering them with `HostStore::get` cloned the
    // host's whole port map to reach that discard, once per port, which is
    // quadratic in the ports of one host and does not show at all until the
    // count is large: ten thousand ports on one address spent under a fifth of a
    // second scanning and three seconds cloning what it found.
    let mut seen: HashSet<IpAddr> = HashSet::new();
    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else { break };
                // A `ScannerFailed` is already on its way to the terminal as a
                // `tracing` event, and is in the report the summary is drawn
                // from. Rendering it here would say it a third time.
                //
                // Liveness is read through the borrowing accessor rather than a
                // clone, because an address that is not alive yet may become so
                // later and cannot be written off — so this runs on every event
                // of every address, alive or not, and has to cost nothing.
                if let ScanEvent::HostUpdated(ip) = event
                    && !seen.contains(&ip)
                    && hosts.read(&ip, Host::is_alive).unwrap_or(false)
                    && let Some(host) = hosts.get(&ip)
                {
                    seen.insert(ip);
                    renderer.host_found(&host)?;
                }
            }
            _ = stops.recv() => {
                if announced {
                    return Ok(Outcome::Interrupted);
                }
                announced = true;
                renderer.interrupted()?;
            }
        }
    }

    let report = task.join().await?;
    renderer.finished(&report)?;

    // From the handle, not from whether the branch above ran. `select!` picks
    // at random between ready branches, and an abort closes the event stream —
    // so the loop can break before the request that caused it is ever read, and
    // the run would call itself complete having been cut short.
    Ok(outcome(&report, handle.should_stop()))
}

/// What the run amounted to.
fn outcome(report: &ScanReport, stopped: bool) -> Outcome {
    if stopped {
        Outcome::Interrupted
    } else if report.is_partial() {
        Outcome::Partial
    } else {
        Outcome::Complete
    }
}
