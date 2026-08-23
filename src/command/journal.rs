// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # `zond journal`
//!
//! What this machine has a record of: scans that finished, scans that did not,
//! and how far the ones that did not got.
//!
//! Nothing here scans anything, and nothing here takes a lock. A listing reads
//! what is on disk, so it can be run while a scan is in flight and will say that
//! one is.

use std::io::{self, Write};
use std::time::Duration;

use zond_engine::journal::paths;
use zond_engine::journal::store::{self, Entry, Retention};

use crate::cli::{JournalArgs, JournalCommand};
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::journal as render;
use crate::settings::Presentation;

/// Runs a journal command.
///
/// Synchronous, unlike its neighbours: nothing here waits on a network.
pub(crate) fn run(args: &JournalArgs, presentation: Presentation) -> Result<Outcome, Error> {
    let mut out = io::stdout().lock();

    match args.what.as_ref().unwrap_or(&JournalCommand::List) {
        JournalCommand::List => list(presentation, &mut out),
        JournalCommand::Show { id } => show(id, presentation, &mut out),
        JournalCommand::Prune {
            ids,
            all,
            completed,
            older_than,
            dry_run,
        } if ids.is_empty() => prune(
            &retention(*all, *completed, *older_than),
            *dry_run,
            presentation,
            &mut out,
        ),
        JournalCommand::Prune { ids, dry_run, .. } => remove(ids, *dry_run, presentation, &mut out),
    }
}

/// Every journal, newest first.
fn list(presentation: Presentation, out: &mut dyn Write) -> Result<Outcome, Error> {
    let entries = read()?;

    if entries.is_empty() {
        // To stderr, so `zond journal | wc -l` counts journals rather than a
        // sentence about there being none.
        tracing::info!("no scans on record");
        return Ok(Outcome::Complete);
    }

    render::list(&entries, presentation, out)?;
    Ok(Outcome::Complete)
}

/// One journal, in full.
fn show(id: &str, presentation: Presentation, out: &mut dyn Write) -> Result<Outcome, Error> {
    let entries = read()?;
    let entry = find(&entries, id)?;

    render::show(entry, presentation, out)?;
    Ok(Outcome::Complete)
}

/// Deletes the journals named, whatever their age.
///
/// Every id is resolved before anything is deleted, so a typo in the third of
/// three leaves the first two alone. Half a command is worse than none of it
/// when the half that ran cannot be undone.
fn remove(
    ids: &[String],
    dry_run: bool,
    presentation: Presentation,
    out: &mut dyn Write,
) -> Result<Outcome, Error> {
    let entries = read()?;
    let chosen: Vec<&Entry> = ids
        .iter()
        .map(|id| find(&entries, id))
        .collect::<Result<_, _>>()?;

    let mut pruned = store::Pruned::default();
    for entry in chosen {
        if dry_run {
            pruned.removed.push(entry.manifest.id.clone());
            continue;
        }

        match store::remove(&entry.directory) {
            Ok(()) => pruned.removed.push(entry.manifest.id.clone()),
            Err(error) => pruned.held.push(store::Held {
                id: entry.manifest.id.clone(),
                reason: error.to_string(),
            }),
        }
    }

    render::pruned(&pruned, dry_run, presentation, out)?;

    // Naming a journal that could not be deleted is a request that did not
    // happen, unlike a sweep passing one over.
    Ok(if pruned.held.is_empty() {
        Outcome::Complete
    } else {
        Outcome::Partial
    })
}

/// The journal `id` names, by its whole id or any prefix that names only one.
///
/// Prefixes because an id is twenty-six characters and nobody wants to type one
/// twice. An ambiguous prefix is refused rather than resolved to the first
/// match: the wrong scan deleted is not something a person gets back.
fn find<'a>(entries: &'a [Entry], id: &str) -> Result<&'a Entry, Error> {
    if let Some(exact) = entries.iter().find(|entry| entry.manifest.id == id) {
        return Ok(exact);
    }

    let mut matching = entries
        .iter()
        .filter(|entry| entry.manifest.id.starts_with(id));

    match (matching.next(), matching.next()) {
        (Some(only), None) => Ok(only),
        (Some(first), Some(second)) => Err(Error::AmbiguousJournal {
            id: id.to_owned(),
            first: first.manifest.id.clone(),
            second: second.manifest.id.clone(),
        }),
        _ => Err(Error::NoSuchJournal {
            id: id.to_owned(),
            known: entries.len(),
        }),
    }
}

/// Deletes what a policy no longer keeps.
fn prune(
    retention: &Retention,
    dry_run: bool,
    presentation: Presentation,
    out: &mut dyn Write,
) -> Result<Outcome, Error> {
    let root = root()?;

    let pruned = if dry_run {
        // The same selection the real sweep would make, without making it.
        // Asking the policy directly rather than pruning and undoing is the only
        // way a dry run can be honest about a journal it would have refused.
        let entries = read()?;
        let selected = retention.expired(&entries, std::time::SystemTime::now());

        store::Pruned {
            removed: selected
                .into_iter()
                .map(|index| entries[index].manifest.id.clone())
                .collect(),
            held: Vec::new(),
        }
    } else {
        store::prune(&root, retention)?
    };

    render::pruned(&pruned, dry_run, presentation, out)?;

    // A sweep that could not take everything it chose has not finished its job,
    // and a script scheduling it should be able to tell.
    Ok(if pruned.held.is_empty() {
        Outcome::Complete
    } else {
        Outcome::Partial
    })
}

/// The policy the flags describe.
///
/// `--all` means everything, which is the one way to remove an unfinished scan
/// deliberately. Everything else leaves unfinished work alone, because it is the
/// only copy of something somebody may still mean to continue.
fn retention(all: bool, completed: bool, older_than: Option<Duration>) -> Retention {
    if all {
        return Retention {
            completed_for: Some(Duration::ZERO),
            incomplete_for: Some(Duration::ZERO),
            keep_at_most: None,
        };
    }

    if completed {
        return Retention {
            completed_for: Some(Duration::ZERO),
            ..Retention::default()
        };
    }

    match older_than {
        Some(age) => Retention {
            completed_for: Some(age),
            ..Retention::default()
        },
        None => Retention::default(),
    }
}

/// Where the journals are, or why they cannot be found.
fn root() -> Result<std::path::PathBuf, Error> {
    paths::root().ok_or(Error::NoJournalDirectory)
}

/// Every journal on record.
///
/// A journal something is writing is included and says so. Listing takes no
/// lock, so this is safe to run mid-scan and useful precisely then.
fn read() -> Result<Vec<Entry>, Error> {
    Ok(store::list(&root()?)?)
}
