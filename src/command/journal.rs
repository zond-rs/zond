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

use crate::cli::{JournalArgs, JournalCommand, PageArgs};
use crate::command::page::{footer, paginate};
use crate::diagnostics::Verbosity;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::journal as render;
use crate::render::style::{Mark, Palette, Style};
use crate::settings::{self, EntryLimit, Presentation};
use zond_engine::journal::paths;
use zond_engine::journal::store::{self, Entry, Retention};

/// Runs a journal command.
///
/// Synchronous, unlike its neighbours: nothing here waits on a network.
pub(crate) fn run(
    args: &JournalArgs,
    presentation: Presentation,
    verbosity: Verbosity,
    palette: Palette,
) -> Result<Outcome, Error> {
    let mut out = io::stdout().lock();
    // The record stream's answer, not standard error's: `zond journal | less`
    // redirects this one alone. Inert in every mode but `standard`, which is the
    // only one that promises colour.
    let style = Style::records(presentation, palette);
    // Standard error's own answer, which is not standard output's: `zond journal
    // | less` redirects one and not the other. The same question a scan asks.
    let commentary = Commentary {
        style: Style::commentary(presentation, palette),
        verbosity,
    };

    match args.what.as_ref() {
        // Both spellings reach the same listing: `zond journal` carries the
        // paging itself, and `zond journal list` carries its own copy.
        None => list(&args.page, presentation, &mut out, style, commentary),
        Some(JournalCommand::List(page)) => list(page, presentation, &mut out, style, commentary),
        Some(JournalCommand::Show { id }) => show(id, presentation, &mut out, style),
        Some(JournalCommand::Prune {
            ids,
            all,
            completed,
            older_than,
            dry_run,
        }) if ids.is_empty() => prune(
            &retention(*all, *completed, *older_than)?,
            *dry_run,
            presentation,
            &mut out,
            style,
        ),
        Some(JournalCommand::Prune { ids, dry_run, .. }) => {
            remove(ids, *dry_run, presentation, &mut out, style)
        }
    }
}

/// Every journal, newest first, a page at a time.
fn list(
    page: &PageArgs,
    presentation: Presentation,
    out: &mut dyn Write,
    style: Style,
    commentary: Commentary,
) -> Result<Outcome, Error> {
    let entries = read()?;

    if entries.is_empty() {
        // To stderr, so `zond journal | wc -l` counts journals rather than a
        // sentence about there being none.
        commentary.remark("no scans on record");
        return Ok(Outcome::Complete);
    }

    let page = paginate(page, presentation, entries.len())?;
    // Numbered from where this page starts, so a row's number places it in the
    // whole listing rather than on the screen.
    render::list(
        &entries[page.shown.clone()],
        page.shown.start + 1,
        presentation,
        out,
        style,
    )?;

    // To stderr, like every other piece of commentary here: what is on standard
    // output is the records, and a note about there being more of them is not
    // one of the records.
    if let Some(footer) = footer(&page, entries.len(), "records") {
        commentary.blank();
        commentary.remark(&footer);
    }

    Ok(Outcome::Complete)
}

/// This command's own commentary stream.
///
/// A listing's records go to standard output and everything *about* the listing
/// goes to standard error, which is the split every renderer here keeps. It is
/// written directly rather than through `tracing`, for the same reason a scan's
/// narration is: `tracing` carries the *engine's* events, and a sentence about
/// how many pages this listing has is not one of them. It could not be painted
/// either, since the subscriber is installed before anyone knows whether this
/// run wants colour.
#[derive(Clone, Copy)]
struct Commentary {
    /// How standard error may be drawn on.
    style: Style,
    /// Whether this run says anything at all.
    verbosity: Verbosity,
}

impl Commentary {
    /// A blank line, to set what follows apart from the records above it.
    ///
    /// Its own call rather than a `\n` on the front of the next line. A painted
    /// line is escaped before it is wrapped, so a newline handed to a role comes
    /// out as the two characters `\` and `n`; see
    /// [`Style::paint`](crate::render::style::Style). That escaping is what stops
    /// a hostname a scanned host chose from clearing the screen, so the fix is to
    /// stop handing it whitespace to escape rather than to weaken it.
    fn blank(self) {
        if !self.verbosity.narrates() {
            return;
        }

        let _ = writeln!(io::stderr());
    }

    /// A line of commentary, drawn as the furniture it is.
    ///
    /// One line. Anything with a newline in it arrives at the terminal with that
    /// newline spelled out, which is [`blank`](Self::blank)'s reason for
    /// existing; the debug assertion is here because the symptom shows up in the
    /// output rather than at the call site.
    ///
    /// A closed standard error is not this command's problem. The records are
    /// already written, and failing the run over a note about them would throw
    /// away the answer to keep the footnote.
    fn remark(self, line: &str) {
        debug_assert!(
            !line.contains('\n'),
            "commentary is written a line at a time; use `blank` for the space"
        );

        if !self.verbosity.narrates() {
            return;
        }

        let _ = writeln!(io::stderr(), "{}", self.style.line(Mark::Info, line));
    }
}

/// The most records this machine keeps, or the built-in default.
fn configured_limit() -> Result<EntryLimit, Error> {
    let (settings, _) = settings::resolve()?;
    Ok(settings
        .journal_entry_limit()
        .unwrap_or(EntryLimit::DEFAULT))
}

/// One journal, in full.
fn show(
    id: &str,
    presentation: Presentation,
    out: &mut dyn Write,
    style: Style,
) -> Result<Outcome, Error> {
    let entries = read()?;
    let entry = find(&entries, id)?;

    render::show(entry, presentation, out, style)?;
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
    style: Style,
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
            Err(error) => pruned.held.push(store::Held::new(
                entry.manifest.id.clone(),
                error.to_string(),
            )),
        }
    }

    render::pruned(&pruned, dry_run, presentation, out, style)?;

    // Naming a journal that could not be deleted is a request that did not
    // happen, unlike a sweep passing one over.
    Ok(if pruned.held.is_empty() {
        Outcome::Complete
    } else {
        Outcome::Partial
    })
}

/// The word that names the most recent record wherever an id is taken.
///
/// An id is sixteen characters of base32 and the record somebody wants is
/// usually the one they just made. Spelled out rather than punctuated so that
/// it cannot collide with an id: the alphabet ids are minted in has no `t`.
pub(crate) const LATEST: &str = "latest";

/// Resolves [`LATEST`] to the id of the most recent record, and leaves anything
/// else as it was written.
///
/// For `--resume`, which reaches a journal by its directory rather than through
/// a listing and so cannot use [`find`]. Prefixes are not resolved here: a
/// resume takes a lock and scans a network, and the id it was given is checked
/// against the record it opens.
pub(crate) fn newest_if_latest(id: &str) -> Result<String, Error> {
    if id != LATEST {
        return Ok(id.to_owned());
    }

    let entries = read()?;
    entries
        .first()
        .map(|entry| entry.manifest.id.clone())
        .ok_or(Error::NoSuchJournal {
            id: id.to_owned(),
            known: 0,
        })
}

/// The journal `id` names, by its whole id, `latest`, or any prefix that names
/// only one.
///
/// Prefixes because an id is sixteen characters and nobody wants to type one
/// twice. An ambiguous prefix is refused rather than resolved to the first
/// match: the wrong scan deleted is not something a person gets back.
pub(crate) fn find<'a>(entries: &'a [Entry], id: &str) -> Result<&'a Entry, Error> {
    // The listing is newest first, so the most recent is the one at the front.
    if id == LATEST {
        return entries.first().ok_or(Error::NoSuchJournal {
            id: id.to_owned(),
            known: 0,
        });
    }

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
    style: Style,
) -> Result<Outcome, Error> {
    let root = root()?;

    let pruned = if dry_run {
        // The same selection the real sweep would make, without making it.
        // Asking the policy directly rather than pruning and undoing is the only
        // way a dry run can be honest about a journal it would have refused.
        let entries = read()?;
        let selected = retention.expired(&entries, std::time::SystemTime::now());

        let mut pruned = store::Pruned::default();
        pruned.removed = selected
            .into_iter()
            .map(|index| entries[index].manifest.id.clone())
            .collect();
        pruned
    } else {
        store::prune(&root, retention)?
    };

    render::pruned(&pruned, dry_run, presentation, out, style)?;

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
///
/// The count comes from `journal_entry_limit`, which is the same number a
/// recording run applies as it goes, so a sweep and a scan agree about how many
/// records this machine keeps rather than holding two opinions that differ by
/// whichever of them ran last. Ages are this command's own: nothing prunes by
/// time unless somebody asks for it here.
fn retention(all: bool, completed: bool, older_than: Option<Duration>) -> Result<Retention, Error> {
    let mut retention = Retention::default();
    if all {
        retention.completed_for = Some(Duration::ZERO);
        retention.incomplete_for = Some(Duration::ZERO);
        return Ok(retention);
    }

    retention.keep_at_most = configured_limit()?.cap();
    if completed {
        retention.completed_for = Some(Duration::ZERO);
    } else if let Some(age) = older_than {
        retention.completed_for = Some(age);
    }
    Ok(retention)
}

/// Where the journals are, or why they cannot be found.
fn root() -> Result<std::path::PathBuf, Error> {
    paths::root().ok_or(Error::NoJournalDirectory)
}

/// Every journal on record.
///
/// A journal something is writing is included and says so. Listing takes no
/// lock, so this is safe to run mid-scan and useful precisely then.
pub(crate) fn read() -> Result<Vec<Entry>, Error> {
    Ok(store::list(&root()?)?)
}
