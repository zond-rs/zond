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
//! [`drive`]. The engine hands back the same pair whichever phase was asked for,
//! so watching one is watching the other.
//!
//! Nothing here formats anything, and nothing here decides an exit code. Those
//! belong to [`render`](crate::render) and [`exit`](crate::exit).

pub(crate) mod diff;
pub(crate) mod discover;
pub(crate) mod journal;
pub(crate) mod scan;

use zond_engine::export::Redaction;
use zond_engine::import::report::{ReportFormat, ReportOptions};

use crate::export::Destination;
use zond_engine::journal::manifest::Plan;
use zond_engine::journal::paths;
use zond_engine::journal::store::{self, Journal, Retention};
use zond_engine::system::privilege;
use zond_engine::{ScanEvent, ScanReport, ScanSession, ScanTask, ZondConfig};

use std::collections::HashMap;
use std::net::IpAddr;

use crate::error::Error;
use crate::exit::Outcome;
use crate::input;
use crate::render::Renderer;
use crate::settings;

/// What this machine's settings say makes two records the same host.
///
/// Read here rather than in `main`, as the journal listing reads its page size:
/// only the two commands that take scans they did not run have an opinion about
/// it, and threading one through every command for the sake of two would cost
/// more than it saves.
pub(crate) fn configured_identity() -> Result<Option<settings::Identity>, Error> {
    let (settings, _) = settings::resolve()?;
    Ok(settings.identity())
}

/// The scan a name on the command line stands for: a file if that is what it
/// names, and a record on this machine otherwise.
///
/// A name that is a file on disk is read as one, and anything else is taken for
/// a record id. That gives every combination without a flag to say which is
/// which, and the test is decidable, which "does this look like an id" is not.
///
/// Returns what to call it as well, since a person reading the commentary wants
/// the name they typed rather than a path this resolved it to.
///
/// Used by [`diff`], which takes scans it did not run.
pub(crate) fn scan_named(name: &str) -> Result<(String, ScanReport), Error> {
    let path = std::path::Path::new(name);
    if path.is_file() {
        return Ok((name.to_owned(), scan_in_file(path)?));
    }

    let entries = journal::read()?;
    let entry = journal::find(&entries, name)?;

    Ok((entry.manifest.id.clone(), store::report(&entry.directory)?))
}

/// A report read out of a document.
///
/// The extension decides the format, and a name that says nothing this build
/// reads is refused rather than sniffed: a file called `scan.txt` is a mistake
/// worth naming, and guessing at it would have this read an nmap file as JSON
/// and blame the contents.
fn scan_in_file(path: &std::path::Path) -> Result<ScanReport, Error> {
    let Some(format) = ReportFormat::from_path(path) else {
        return Err(Error::UnknownReportFormat {
            path: path.to_path_buf(),
        });
    };

    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);

    Ok(format.read(&mut reader, ReportOptions::new())?)
}

/// What the engine's settings files said, with what they could not be used for
/// reported on the way past.
pub(crate) fn engine_settings(profile: Option<&str>) -> Result<settings::EngineSettings, Error> {
    let (settings, warnings) = settings::engine(profile)?;

    for warning in warnings {
        tracing::warn!("{warning}");
    }

    Ok(settings)
}

/// The masking policy a resolved configuration settles on.
///
/// The engine records only the intent, and holds everything a scan found, so
/// masking on the way out is this program's job. A `--redact` that did not reach
/// the renderer would be a flag that does nothing.
pub(crate) fn redaction(config: &ZondConfig) -> Redaction {
    if config.redact {
        Redaction::Standard
    } else {
        Redaction::None
    }
}

/// Whether this run leaves a record, and how many are kept once it has.
///
/// The two travel together because they are answered in the same place from the
/// same file, and because the second only ever comes up when the first is true:
/// a run recording nothing has added nothing to apply a limit to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Recording {
    /// Whether to record at all, from `journal` in `cli.toml` or `--no-journal`.
    pub(crate) wanted: bool,
    /// The most records this machine keeps, from `journal_entry_limit`.
    pub(crate) limit: settings::EntryLimit,
}

/// Starts a record for this run, or says why it could not and carries on.
///
/// Both subcommands record by default, so this is where either of them asks
/// for a journal. `summary` is the line a listing shows and nothing decides
/// anything from it.
///
/// A run that cannot be recorded is still a run worth having. Every way this
/// fails is reported and returns `None`, and the caller scans anyway: no home
/// directory, a state directory that will not take a write, an id that could not
/// be claimed.
///
/// The record having been claimed, `limit` is applied: see [`enforce`].
fn record(plan: &Plan, summary: String, limit: settings::EntryLimit) -> Option<Journal> {
    let Some(root) = paths::root() else {
        tracing::warn!("not recording this run: this environment names no home");
        return None;
    };

    if let Err(e) = std::fs::create_dir_all(&root) {
        tracing::warn!(
            "not recording this run: {} is not writable ({e})",
            root.display()
        );
        return None;
    }

    match Journal::create(&root, plan, privilege::is_elevated(), summary) {
        Ok(journal) => {
            // To stderr: where a scan is writing is commentary on the run, and
            // somebody piping its results should still be told.
            tracing::info!("recording this run as {}", journal.manifest().id);

            // After the record exists, so the limit is a limit on what is there
            // once this run has been counted rather than one record more.
            enforce(&root, limit);
            Some(journal)
        }
        Err(e) => {
            tracing::warn!("not recording this run: {e}");
            None
        }
    }
}

/// Drops the oldest records the standing limit no longer keeps.
///
/// Here, on the way past, rather than in a sweep somebody has to remember to
/// run: the journal directory grows by one record per scan and nothing about a
/// scan shrinks it, so the moment one is added is the moment to say what that
/// pushed out.
///
/// Age plays no part. `zond journal prune` is where a policy about time lives,
/// and this is only the count. A machine that scans twice a year should not find
/// its records gone, and one that scans hourly should not have to sweep.
///
/// What goes is the engine's decision, and it spends finished records before
/// unfinished ones and old before new. The record this run just claimed is
/// never among them: it is locked, and a locked journal is not something a prune
/// takes. That is also why a limit of zero leaves the run in flight alone and
/// takes it on the next run instead.
///
/// Best effort, like recording itself. A record that could not be deleted is
/// mentioned and the scan carries on: a state directory that will not give
/// something up is a reason to say so, not a reason to refuse to scan.
fn enforce(root: &std::path::Path, limit: settings::EntryLimit) {
    // Nothing to count against, and no reason to walk the directory to find
    // that out.
    let Some(cap) = limit.cap() else { return };

    let retention = Retention {
        completed_for: None,
        incomplete_for: None,
        keep_at_most: Some(cap),
    };

    match store::prune(root, &retention) {
        Ok(pruned) => {
            if !pruned.removed.is_empty() {
                tracing::info!(
                    "keeping the newest {cap} records: {} older {} removed",
                    pruned.removed.len(),
                    if pruned.removed.len() == 1 {
                        "one was"
                    } else {
                        "ones were"
                    },
                );
            }

            for held in pruned.held {
                tracing::warn!("could not remove record {}: {}", held.id, held.reason);
            }
        }
        Err(e) => tracing::warn!("could not apply journal_entry_limit: {e}"),
    }
}

/// A record reopened so the scan it holds can be continued.
///
/// Both subcommands take `--resume`, and both want the same three things back:
/// somewhere to keep writing, the plan the earlier sittings were walking, and
/// how much of it is left.
pub(crate) struct Resumed {
    /// The record's full id, with `latest` already resolved.
    pub(crate) id: String,
    /// The journal this sitting appends to.
    pub(crate) journal: Journal,
    /// What the record says was being scanned.
    pub(crate) plan: Plan,
    /// How much of that plan no earlier sitting settled.
    pub(crate) remaining: u128,
}

/// Reopens the record `id` names, ready to be continued.
///
/// `counted` is the unit this phase measures in, for the line that says what is
/// being continued. A sweep counts addresses and a port scan counts targets,
/// and "targets" reads as address-and-port pairs, which a sweep has none of.
///
/// The directory is looked for here rather than left to
/// [`Journal::reopen`](zond_engine::journal::store::Journal::reopen), because a
/// missing one means somebody named a record this machine does not have, and
/// that deserves a message saying how many there are to look through.
pub(crate) fn reopen(id: &str, counted: &'static str) -> Result<Resumed, Error> {
    let id = journal::newest_if_latest(id)?;

    let directory = paths::scan(&id).ok_or(Error::NoJournalDirectory)?;
    if !directory.is_dir() {
        return Err(Error::NoSuchJournal {
            id,
            known: paths::root()
                .and_then(|root| store::list(&root).ok())
                .map_or(0, |entries| entries.len()),
        });
    }

    let (journal, checkpoint, plan) = Journal::reopen(&directory, privilege::is_elevated())?;

    let total = journal.manifest().total_targets;
    let settled = u128::from(checkpoint.watermark) + checkpoint.settled_above.len() as u128;
    tracing::info!("continuing {id}: {settled} of {total} {counted} already settled");

    Ok(Resumed {
        id,
        journal,
        plan,
        remaining: total.saturating_sub(settled),
    })
}

/// Runs a scan the engine has already been asked for, and reports it.
///
/// Watches the run happen so a person sees hosts as they are found rather than
/// after a silence, stops cleanly when they ask it to, and says what the run
/// amounted to. See [`input`] for what counts as asking.
async fn drive(
    session: ScanSession,
    task: ScanTask,
    destinations: &[Destination],
    redaction: Redaction,
    renderer: &mut dyn Renderer,
) -> Result<Outcome, Error> {
    // Taken apart because holding the whole session would borrow it twice in
    // the `select!` below.
    let (hosts, mut events, handle) = session.into_parts();
    let mut stops = input::watch(&handle);

    // Gates the message and the escalation only. What the run amounted to is
    // read from the handle afterwards.
    let mut announced = false;
    // What the run has turned up, kept here because this is the only place that
    // can read it without paying for it. See `Tally`.
    let mut tally = Tally::default();
    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else { break };
                // A `ScannerFailed` is already on its way to the terminal as a
                // `tracing` event, and is in the report the summary is drawn
                // from. Rendering it here would say it a third time.
                //
                // Read through the borrowing accessor and never cloned. An
                // address that is not alive yet may become so later and cannot
                // be written off, so this runs on every event of every address,
                // alive or not, and has to cost nothing. A port scan fires one
                // per port that settles.
                if let ScanEvent::HostUpdated(ip) = event
                    && let Some(Some(open)) =
                        hosts.read(&ip, |host| host.is_alive().then(|| host.open_port_count()))
                {
                    let (hosts, open) = tally.record(ip, open);
                    renderer.progressed(hosts, open)?;
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

    // The terminal first. A file that could not be written must not take the
    // findings with it, and by here they are already in hand.
    renderer.finished(&report)?;
    let written = crate::export::write_all(destinations, &report, redaction);

    // From the handle, not from whether the branch above ran. `select!` picks at
    // random between ready branches, and an abort closes the event stream, so
    // the loop can break before the request that caused it is ever read. The run
    // would then call itself complete having been cut short.
    let outcome = outcome(&report, handle.should_stop());
    Ok(if written { outcome } else { Outcome::Partial })
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

/// What a run has turned up so far, counted as its events arrive.
///
/// Kept by the loop rather than by a renderer because the loop is the only thing
/// holding the host store, and reading a count off a borrow is the difference
/// between this and cloning a port map per port: eighteen seconds against one on
/// a twenty-thousand-port scan.
///
/// A port scan announces the same address again for every port that settles, so
/// this is a tally rather than a count: what each address has open, and the
/// running sum across them.
#[derive(Debug, Default)]
struct Tally {
    /// What each address has open.
    open: HashMap<IpAddr, usize>,
    /// Their sum, carried rather than added up again on every event.
    total: usize,
}

impl Tally {
    /// Records what `ip` has open now, and returns how many addresses have
    /// answered and how many ports are open across them.
    fn record(&mut self, ip: IpAddr, open: usize) -> (usize, usize) {
        let previously = self.open.insert(ip, open).unwrap_or(0);
        self.total = self.total.saturating_sub(previously) + open;

        (self.open.len(), self.total)
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
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    /// A port scan announces the same address once per port that settles, so the
    /// tally has to replace what it knew rather than add to it.
    ///
    /// Adding would report a host with two open ports as having as many as it
    /// has ports, which is what the line at the bottom of a scan would then have
    /// shown.
    #[test]
    fn an_address_announced_again_replaces_what_it_said() {
        let mut tally = Tally::default();

        assert_eq!(tally.record(ip(1), 0), (1, 0));
        assert_eq!(tally.record(ip(1), 1), (1, 1));
        assert_eq!(
            tally.record(ip(1), 2),
            (1, 2),
            "the same host was counted twice"
        );
        assert_eq!(
            tally.record(ip(1), 2),
            (1, 2),
            "an unchanged host moved the total"
        );
    }

    /// A second address adds to both figures.
    #[test]
    fn a_second_address_adds_to_both() {
        let mut tally = Tally::default();

        tally.record(ip(1), 2);
        assert_eq!(tally.record(ip(2), 3), (2, 5));
        assert_eq!(
            tally.record(ip(3), 0),
            (3, 5),
            "a host with nothing open still counts"
        );
    }

    /// A count that went down takes the total down with it.
    ///
    /// Nothing in the engine closes a port it has opened, so this is a guard
    /// against a future that does rather than a case in hand. The saturating
    /// subtraction underneath it is unreachable while the tally is consistent,
    /// and no test can reach it either. It is there because an underflowing
    /// total is eighteen quintillion open ports, and that is a poor way to find
    /// out the tally stopped being consistent.
    #[test]
    fn a_count_that_falls_takes_the_total_with_it() {
        let mut tally = Tally::default();

        tally.record(ip(1), 5);
        assert_eq!(tally.record(ip(1), 1), (1, 1));
        assert_eq!(tally.record(ip(1), 0), (1, 0));
    }
}
