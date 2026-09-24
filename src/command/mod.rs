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

pub(crate) mod catalogue;
pub(crate) mod detections;
pub(crate) mod diff;
pub(crate) mod discover;
pub(crate) mod journal;
pub(crate) mod listen;
pub(crate) mod merge;
pub(crate) mod page;
pub(crate) mod read;
pub(crate) mod scan;

use zond_engine::cve::Catalogue;
use zond_engine::export::Redaction;
use zond_engine::import::report::{ReportFormat, ReportOptions};

use crate::export::Destination;
use zond_engine::journal::manifest::Plan;
use zond_engine::journal::paths;
use zond_engine::journal::store::{self, Journal, Retention};
use zond_engine::system::privilege::Privilege;
use zond_engine::{ScanEvent, ScanReport, ScanSession, ScanTask, ScopedIp, ZondConfig};

use std::collections::HashMap;

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

/// A vulnerability catalogue read off disk.
///
/// The whole file, through the engine's own reader, so a document that reaches a
/// scan is one the engine would accept anywhere else: the size ceiling, the
/// reserved-namespace rule and the version grammar are all its, not this
/// command's.
pub(crate) fn cve_catalogue(path: &std::path::Path) -> Result<Catalogue, Error> {
    let file = std::fs::File::open(path).map_err(|source| Error::Catalogue {
        path: path.to_path_buf(),
        source: source.into(),
    })?;

    Catalogue::read(&mut std::io::BufReader::new(file)).map_err(|source| Error::Catalogue {
        path: path.to_path_buf(),
        source,
    })
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

    // Not `create_dir_all`: under `sudo` that leaves the directory owned by
    // root, and every later run that needs no privileges — a listening phase
    // needs none at all — then finds a journal directory it cannot write to and
    // silently records nothing. The engine creates it and gives it away.
    if let Err(e) = store::prepare_root(&root) {
        tracing::warn!(
            "not recording this run: {} is not writable ({e})",
            root.display()
        );
        return None;
    }

    match Journal::create(&root, plan, Privilege::current(), summary) {
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
                // Under `-vv`. Once a machine is at its limit every scan prunes
                // one record, so this is a line per run about housekeeping the
                // user configured and does not act on, and `-v` is for the
                // decisions behind a result. Worth keeping for somebody watching
                // what the journal does.
                tracing::info!(
                    verbosity = 2,
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
/// `counted` is the unit the phase measures in, for the line that says what is
/// being continued. A sweep counts addresses and a port scan counts targets,
/// and "targets" reads as address-and-port pairs, which a sweep has none of. A
/// watch counts in nothing at all and is announced differently; see
/// [`continuation`].
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

    let (journal, checkpoint, plan) = Journal::reopen(&directory, Privilege::current())?;

    let total = journal.manifest().total_targets;
    let settled = u128::from(checkpoint.watermark) + checkpoint.settled_above.len() as u128;
    tracing::info!(
        "continuing {id}: {}",
        continuation(&plan, &journal, settled, total, counted)
    );

    Ok(Resumed {
        id,
        journal,
        plan,
        remaining: total.saturating_sub(settled),
    })
}

/// What continuing this record means, in the terms its own phase has.
///
/// **A watch settles nothing, so it cannot be announced as though it had.** The
/// arithmetic the other two are continued by — a cursor, a watermark, a total —
/// is arithmetic over an enumeration, and a listener enumerates nothing: it was
/// pointed at a link, and the link carries what it carries. Every one of those
/// numbers is therefore zero for it, and the line reading
/// `0 of 0 links already settled` said the opposite of what the phase is, on
/// every resume, in the one place a person is checking they named the right
/// record.
///
/// What a watch has instead is what its earlier sittings heard, which is the
/// whole of what reopening one buys: the findings are restored first, so the
/// report describes the week rather than tonight.
fn continuation(
    plan: &Plan,
    journal: &Journal,
    settled: u128,
    total: u128,
    counted: &'static str,
) -> String {
    if plan.links().is_some() {
        let machines = journal.restored().len();
        return match machines {
            0 => String::from("adding a sitting to a watch that has heard nobody yet"),
            1 => String::from("adding a sitting to a watch, with 1 machine already on record"),
            many => format!("adding a sitting to a watch, with {many} machines already on record"),
        };
    }

    format!("{settled} of {total} {counted} already settled")
}

/// What it means for the user to stop this particular run.
///
/// **The answer is not the same for every phase**, and the exit status is part
/// of this program's interface, so it is stated rather than assumed.
///
/// A sweep and a port scan have a plan and are working through it: stopping one
/// leaves ground uncovered, which is what code 130 is for. A watch asked to run
/// until it is stopped has no ground and no end of its own — being stopped is
/// the only way it can finish, and reporting that as an interruption would leave
/// `zond listen en0` with no way to succeed at all, so `zond listen en0 || alert`
/// would fire every time somebody pressed `q`.
///
/// A watch given `--for` is back in the first case. It was asked for ten minutes
/// and stopped at three, so it really was cut short, and a script sampling a
/// segment on a timer wants to know the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stopping {
    /// The run had work left, so stopping it cut it short.
    CutsShort,
    /// The run was asked to continue until stopped, so stopping it is how it
    /// ends.
    Completes,
}

/// Runs a scan the engine has already been asked for, and reports it.
///
/// Watches the run happen so a person sees hosts as they are found rather than
/// after a silence, stops cleanly when they ask it to, and says what the run
/// amounted to. See [`input`] for what counts as asking, and [`Stopping`] for
/// what this run takes that to mean.
///
/// `catalogue` is a vulnerability dataset the operator supplied, correlated over
/// the finished report before anything renders or is written. [`None`] leaves the
/// scan's own correlation — against the catalogue the engine ships — as the only
/// one, which is what a run that named no dataset asked for.
///
/// Here rather than inside the engine because a catalogue is not a scan setting:
/// it changes no packet and no timing, and the engine says so where it runs its
/// own correlation. What it needs is the finished report, which is a thing this
/// process owns and the engine does not.
async fn drive(
    session: ScanSession,
    task: ScanTask,
    destinations: &[Destination],
    redaction: Redaction,
    stopping: Stopping,
    catalogue: Option<&Catalogue>,
    renderer: &mut dyn Renderer,
) -> Result<Outcome, Error> {
    // Taken apart because holding the whole session would borrow it twice in
    // the `select!` below.
    let (hosts, mut events, handle, progress) = session.into_parts();
    crate::render::progress::planning(progress);
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
                    // Asked twice: leave now, giving up whatever is still in
                    // flight. Interrupted whatever the phase is, because this is
                    // the one path that abandons the run rather than winding it
                    // down — there are findings still unwritten either way.
                    return Ok(Outcome::Interrupted);
                }
                announced = true;
                renderer.interrupted()?;
            }
        }
    }

    let mut report = task.join().await?;

    // Before rendering and before export, so the terminal, the JSON and the
    // journal all say the same thing. A dataset an operator pointed at is
    // additional to the engine's own pass rather than instead of it: findings
    // deduplicate by claim, so an entry both catalogues carry records once.
    if let Some(catalogue) = catalogue {
        zond_engine::cve::correlate_report(&mut report, catalogue);
    }

    // The terminal first. A file that could not be written must not take the
    // findings with it, and by here they are already in hand.
    renderer.finished(&report)?;
    let written = crate::export::write_all(destinations, &report, redaction);

    // From the handle, not from whether the branch above ran. `select!` picks at
    // random between ready branches, and an abort closes the event stream, so
    // the loop can break before the request that caused it is ever read. The run
    // would then call itself complete having been cut short.
    let outcome = outcome(&report, handle.should_stop(), stopping);
    Ok(if written { outcome } else { Outcome::Partial })
}

/// Puts a finished report where the command was told to put it, and says
/// whether it landed.
///
/// **The terminal, or the files, and never both.** A scan does both, because
/// somebody is watching it happen and the file is for later. Nobody watches a
/// document be read or folded, so naming a file there is saying where the report
/// goes rather than asking for a second copy of it — and answering
/// `zond read latest -o out.json` with the whole report on standard output as
/// well means a shell full of a scan they asked to have put in a file.
///
/// Shared by [`read`] and [`merge`] because it is one rule, and a rule stated
/// twice is a rule that drifts.
pub(crate) fn deliver(
    report: &ScanReport,
    destinations: &[Destination],
    redaction: Redaction,
    renderer: &mut dyn Renderer,
) -> Result<bool, Error> {
    if destinations.is_empty() {
        renderer.finished(report)?;
        return Ok(true);
    }

    // Each file is named on standard error as it lands, which is the whole of
    // what such a run says.
    Ok(crate::export::write_all(destinations, report, redaction))
}

/// What the run amounted to.
///
/// The order matters and is not obvious. A run that was stopped may also have
/// had a strategy fail, and "interrupted" is the more useful of the two answers:
/// it says the results are short because somebody said so, which is actionable,
/// where "partial" invites the reader to look for a fault there was not.
///
/// The exception is a run whose stop *was* its ending — see [`Stopping`]. That
/// one is not interrupted at all, so a failure it did have is the only thing
/// left to report, and a watch that hit its host ceiling or could not open a
/// capture still exits `3` rather than `0`.
fn outcome(report: &ScanReport, stopped: bool, stopping: Stopping) -> Outcome {
    if stopped && stopping == Stopping::CutsShort {
        return Outcome::Interrupted;
    }

    concluded(report)
}

/// What a report amounts to for a command that ran no scan.
///
/// [`read`] and [`merge`] are handed reports somebody else measured. Nothing
/// there can have been interrupted, because nothing there was running — so the
/// only question left is the one the report answers about itself, which is
/// whether its own coverage fell short.
///
/// Its own and not this command's: a fold of scans that left ground uncovered
/// describes a network nobody finished looking at, and reporting otherwise
/// because the fold itself went fine would have the merged report claim more
/// than its sources did.
pub(crate) fn concluded(report: &ScanReport) -> Outcome {
    if fully_covered(report) {
        Outcome::Complete
    } else {
        Outcome::Partial
    }
}

/// Whether the report covers everything the run was asked to cover.
///
/// The engine's own [`is_partial`](ScanReport::is_partial), which counts every
/// way it records a run falling short: a strategy that failed, ground it
/// refused, a host a time budget cut short, an address discovery never
/// decided and a port left unasked. Any of them narrows the result below what
/// was asked, which is exactly what a `3` warns a script about.
///
/// An address with no route is deliberately *not* among them. The engine
/// keeps [`unroutable`](zond_engine::report::ScanPhase::unroutable) apart as
/// ground that was never coverable rather than coverage that fell short, and a
/// sweep of any range with a gap in it would otherwise never exit `0`.
fn fully_covered(report: &ScanReport) -> bool {
    !report.is_partial()
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
///
/// Keyed by the address the engine keyed the host under, zone and all. An IPv6
/// link-local names a different machine on every segment it is heard on, so
/// `fe80::1%en0` and `fe80::1%en1` are two hosts; keyed by the bare address they
/// would be one, and the second to answer would report the first's open ports as
/// having closed.
#[derive(Debug, Default)]
struct Tally {
    /// What each address has open.
    open: HashMap<ScopedIp, usize>,
    /// Their sum, carried rather than added up again on every event.
    total: usize,
}

impl Tally {
    /// Records what `ip` has open now, and returns how many addresses have
    /// answered and how many ports are open across them.
    fn record(&mut self, ip: ScopedIp, open: usize) -> (usize, usize) {
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use zond_engine::Zone;

    fn ip(last: u8) -> ScopedIp {
        ScopedIp::unscoped(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
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

    /// The same link-local address on two interfaces is two machines, and the
    /// tally has to count them as two.
    ///
    /// Keyed by the bare address they would collide: the second interface's host
    /// would overwrite the first's entry, so the host count would stall at one
    /// and the total would swing to whichever of them answered last. Both
    /// figures are what the line at the bottom of a scan reports.
    #[test]
    fn the_same_link_local_on_two_interfaces_is_two_hosts() {
        let mut tally = Tally::default();
        let addr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let en0 = ScopedIp::scoped(addr, Zone::new(1, "en0"));
        let en1 = ScopedIp::scoped(addr, Zone::new(2, "en1"));

        assert_eq!(tally.record(en0, 2), (1, 2));
        assert_eq!(tally.record(en1, 3), (2, 5));
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

    /// A report of one discovery phase, with whatever shortfalls the caller
    /// builds into it. The parts a coverage decision reads and nothing else.
    fn report_with(
        refusals: Vec<zond_engine::report::Refusal>,
        unroutable: Vec<IpAddr>,
        timed_out: Vec<IpAddr>,
    ) -> ScanReport {
        use zond_engine::model::exclusion::Exclusions;
        use zond_engine::model::parse::ip::to_set;
        use zond_engine::report::{PhaseParts, ScanKind, ScanPhase, ScanSettings, TargetScope};

        let mut scope = to_set(&["192.0.2.0/30"], None, None).expect("a range");
        let phase = ScanPhase::from_parts(PhaseParts {
            attachments: Vec::new(),
            kind: ScanKind::Discovery,
            started_at: std::time::SystemTime::UNIX_EPOCH,
            elapsed: std::time::Duration::from_secs(1),
            privilege: Some(Privilege::Connect),
            targets: TargetScope::from_ip_set(&mut scope, &Exclusions::none()),
            settings: ScanSettings::from(&ZondConfig::default()),
            failures: Vec::new(),
            refusals,
            unroutable,
            timed_out,
            reached_by_connect: Vec::new(),
            undecided: Vec::new(),
            probes: Vec::new(),
            origin: None,
        });
        ScanReport::recorded("test", vec![phase], Vec::<zond_engine::Host>::new())
    }

    /// A resume that decided everything its first sitting left open exits `0`.
    /// Its report still carries the stopped sitting's phase and that phase's
    /// own list of what it never decided, and a script told `3` would resume
    /// a job that is finished.
    #[test]
    fn a_resume_that_decided_what_the_first_sitting_left_is_complete() {
        use crate::render::test_support::screened;

        let mut resumed = screened("192.0.2.0/29", &["192.0.2.4-192.0.2.7"], "192.0.2.1");
        assert_eq!(
            concluded(&resumed),
            Outcome::Partial,
            "the first sitting alone"
        );
        resumed.merge(screened("192.0.2.4-192.0.2.7", &[], "192.0.2.1"));

        assert_eq!(concluded(&resumed), Outcome::Complete);
    }

    /// The three-way distinction the engine draws, mapped to the one bit a shell
    /// reads. A refusal and a timed-out host each narrow the coverage and so are
    /// partial; an unroutable address is ground that was never coverable and is
    /// not, which is the line 0.13 drew and this keeps.
    #[test]
    fn a_refusal_or_a_time_budget_is_partial_but_a_missing_route_is_not() {
        use zond_engine::report::{Refusal, ScannerKind};

        let clean = report_with(Vec::new(), Vec::new(), Vec::new());
        assert_eq!(concluded(&clean), Outcome::Complete);

        let refused = report_with(
            vec![Refusal::new(ScannerKind::Connect, "too large to sweep")],
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            concluded(&refused),
            Outcome::Partial,
            "a refusal narrows the coverage"
        );

        let unreachable = "192.0.2.9".parse::<IpAddr>().expect("an address");
        let no_route = report_with(Vec::new(), vec![unreachable], Vec::new());
        assert_eq!(
            concluded(&no_route),
            Outcome::Complete,
            "an address with no route was never coverable"
        );

        let cut_short = report_with(Vec::new(), Vec::new(), vec![unreachable]);
        assert_eq!(
            concluded(&cut_short),
            Outcome::Partial,
            "a host a budget cut short is narrower than what was asked"
        );
    }
}
