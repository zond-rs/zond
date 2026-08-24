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

use crate::cli::{ExportArgs, JournalArgs, JournalCommand, PageArgs};
use crate::command;
use crate::diagnostics::Verbosity;
use crate::error::Error;
use crate::exit::Outcome;
use crate::export::Destination;
use crate::render::journal as render;
use crate::render::{Phase, renderer};
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
) -> Result<Outcome, Error> {
    // Before the lock below: `report` may write through a `Renderer`, which owns
    // its own handle on standard output.
    if let Some(JournalCommand::Report { id, export }) = args.what.as_ref() {
        return report(id, export, presentation, verbosity);
    }

    let mut out = io::stdout().lock();

    match args.what.as_ref() {
        // Both spellings reach the same listing: `zond journal` carries the
        // paging itself, and `zond journal list` carries its own copy.
        None => list(&args.page, presentation, &mut out),
        Some(JournalCommand::List(page)) => list(page, presentation, &mut out),
        Some(JournalCommand::Show { id }) => show(id, presentation, &mut out),
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
        ),
        Some(JournalCommand::Prune { ids, dry_run, .. }) => {
            remove(ids, *dry_run, presentation, &mut out)
        }
        Some(JournalCommand::Report { .. }) => unreachable!("handled above"),
    }
}

/// How many records a listing shows when nothing says otherwise.
///
/// A handful, because the ones anybody is looking for are the recent ones and
/// the listing is newest first. `--all` is one flag away, and `page_size` in
/// `cli.toml` moves the default for good.
const DEFAULT_PAGE_SIZE: usize = 10;

/// Every journal, newest first, a page at a time.
fn list(
    page: &PageArgs,
    presentation: Presentation,
    out: &mut dyn Write,
) -> Result<Outcome, Error> {
    let entries = read()?;

    if entries.is_empty() {
        // To stderr, so `zond journal | wc -l` counts journals rather than a
        // sentence about there being none.
        tracing::info!("no scans on record");
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
    )?;

    // To stderr, like every other piece of commentary here: what is on standard
    // output is the records, and a note about there being more of them is not
    // one of the records.
    if page.shown.len() < entries.len() {
        // A page you can actually go to rather than the flag's grammar: the
        // next one where there is one, the previous where this is the last. A
        // hint that names something which would fail is worse than none.
        let step = if page.number < page.of {
            format!("--page {} for the next", page.number + 1)
        } else {
            format!("--page {} for the previous", page.number - 1)
        };

        tracing::info!(
            "\npage {} of {}, {} records; {step}, --all for every one",
            page.number,
            page.of,
            entries.len()
        );
    }

    Ok(Outcome::Complete)
}

/// Which slice of the listing to show.
///
/// **`pipe` shows everything unless a limit is asked for.** Paging is a reading
/// affordance, and that mode's output is a stable interface — a program running
/// `zond journal --pipe` and silently receiving the first ten of forty records
/// would be worse served by the convenience than helped by it. Asking for a
/// limit there is still honoured, because then it was asked for.
/// Which slice a listing shows, and where that slice sits.
///
/// The number and the count travel with the range because the footer needs
/// them, and working them out again from the arguments would be a second place
/// that has to agree about what a page is.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Page {
    /// The records to show.
    shown: std::ops::Range<usize>,
    /// Which page this is, counting from one.
    number: usize,
    /// How many there are.
    of: usize,
}

fn paginate(page: &PageArgs, presentation: Presentation, total: usize) -> Result<Page, Error> {
    let size = match (page.all, page.limit, presentation) {
        (true, _, _) => None,
        (_, Some(0), _) => None,
        (_, Some(limit), _) => Some(limit),
        (_, None, Presentation::Pipe) => page.page.map(|_| DEFAULT_PAGE_SIZE),
        (_, None, _) => Some(configured_page_size()?),
    };

    let Some(size) = size.filter(|size| *size > 0) else {
        return Ok(Page {
            shown: 0..total,
            number: 1,
            of: 1,
        });
    };

    // Rounded up, and never zero: a listing with records in it has a first page
    // whatever the arithmetic says.
    let pages = total.div_ceil(size).max(1);
    let number = page.page.unwrap_or(1);
    if number == 0 || number > pages {
        return Err(Error::NoSuchPage {
            asked: number,
            pages,
        });
    }

    let from = (number - 1) * size;
    Ok(Page {
        shown: from..(from + size).min(total),
        number,
        of: pages,
    })
}

/// The page size this machine's settings ask for, or the built-in default.
fn configured_page_size() -> Result<usize, Error> {
    let (settings, _) = settings::resolve()?;
    Ok(settings.page_size().unwrap_or(DEFAULT_PAGE_SIZE))
}

/// The most records this machine keeps, or the built-in default.
fn configured_limit() -> Result<EntryLimit, Error> {
    let (settings, _) = settings::resolve()?;
    Ok(settings
        .journal_entry_limit()
        .unwrap_or(EntryLimit::DEFAULT))
}

/// One journal, in full.
fn show(id: &str, presentation: Presentation, out: &mut dyn Write) -> Result<Outcome, Error> {
    let entries = read()?;
    let entry = find(&entries, id)?;

    render::show(entry, presentation, out)?;
    Ok(Outcome::Complete)
}

/// One scan, printed the way it was printed when it ran — or written to the
/// files this was asked for, and then not printed.
///
/// The record holds the hosts a scan found and a phase per sitting, which is
/// everything the end of a run prints — so this rebuilds the report and hands
/// it to the same renderer, and the output is the same output. Nothing is
/// probed and the journal's lock is not taken, so this is safe to run against a
/// scan that is still going; what comes back is then everything written down as
/// of the last checkpoint.
///
/// **Naming a file replaces the terminal rather than adding to it.** A scan
/// prints as well as writes, because the person who started it is watching it
/// happen and the file is for later — but nobody is watching a record being
/// fetched. `zond journal report latest -o out.json` is somebody saying where
/// they want this, and answering it with the whole report on standard output as
/// well means a shell full of a scan they asked to have put in a file. What
/// they hear is which files were written.
///
/// The exit code follows the scan rather than the reading of it: a record of a
/// scan that left ground uncovered reports as partial, the same as the scan did.
fn report(
    id: &str,
    export: &ExportArgs,
    presentation: Presentation,
    verbosity: Verbosity,
) -> Result<Outcome, Error> {
    // Before the record is read, so a misspelt extension is answered at once
    // rather than after the findings are in hand.
    let destinations = Destination::resolve(
        &export.output,
        &export.output_as,
        export.output_all.as_deref(),
    )?;

    let entries = read()?;
    let entry = find(&entries, id)?;
    let report = store::report(&entry.directory)?;

    // From this machine's settings rather than from the record. A journal holds
    // what the scan saw, and whether to mask it on the way out is a decision
    // belonging to whoever is reading it now.
    let redaction = command::redaction(&command::engine_settings(None)?.config);

    let written = if destinations.is_empty() {
        let mut renderer = renderer(presentation, verbosity)?;
        renderer.started(
            Phase::Recorded {
                id: &entry.manifest.id,
                started_at: entry.manifest.created_at,
            },
            redaction,
        )?;
        renderer.finished(&report)?;
        true
    } else {
        // Each file is named on standard error as it lands, which is the whole
        // of what this run says.
        crate::export::write_all(&destinations, &report, redaction)
    };

    let outcome = command::outcome(&report, false);

    // A record that could not be written where it was asked is a request that
    // half happened, whatever the scan it describes amounted to.
    Ok(if written { outcome } else { Outcome::Partial })
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
///
/// The count comes from `journal_entry_limit`, which is the same number a
/// recording run applies as it goes — so a sweep and a scan agree about how many
/// records this machine keeps, rather than holding two opinions that differ by
/// whichever of them ran last. Ages are this command's own: nothing prunes by
/// time unless somebody asks for it here.
fn retention(all: bool, completed: bool, older_than: Option<Duration>) -> Result<Retention, Error> {
    if all {
        return Ok(Retention {
            completed_for: Some(Duration::ZERO),
            incomplete_for: Some(Duration::ZERO),
            keep_at_most: None,
        });
    }

    let standing = Retention {
        keep_at_most: configured_limit()?.cap(),
        ..Retention::default()
    };

    if completed {
        return Ok(Retention {
            completed_for: Some(Duration::ZERO),
            ..standing
        });
    }

    Ok(match older_than {
        Some(age) => Retention {
            completed_for: Some(age),
            ..standing
        },
        None => standing,
    })
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

    fn asked(limit: Option<usize>, page: Option<usize>, all: bool) -> PageArgs {
        PageArgs { limit, page, all }
    }

    /// A page is as long as the limit, and the last one is however much is left.
    /// The footer names which page this is, so a listing says where it sits
    /// rather than only that there is more.
    #[test]
    fn a_page_knows_its_number_and_how_many_there_are() {
        let minimal = Presentation::Minimal;

        let first = paginate(&asked(Some(10), None, false), minimal, 14).expect("a page");
        assert_eq!(first.number, 1);
        assert_eq!(first.of, 2);

        let last = paginate(&asked(Some(10), Some(2), false), minimal, 14).expect("a page");
        assert_eq!(last.number, 2);
        assert_eq!(last.of, 2);

        // A listing that fits is one page of one, which is what stops the
        // footer appearing at all.
        let whole = paginate(&asked(None, None, true), minimal, 14).expect("a page");
        assert_eq!((whole.number, whole.of), (1, 1));
        assert_eq!(whole.shown, 0..14);
    }

    #[test]
    fn a_page_covers_its_share_and_the_last_one_covers_the_remainder() {
        let minimal = Presentation::Minimal;

        assert_eq!(
            paginate(&asked(Some(10), None, false), minimal, 12)
                .expect("a page")
                .shown,
            0..10
        );
        assert_eq!(
            paginate(&asked(Some(10), Some(2), false), minimal, 12)
                .expect("a page")
                .shown,
            10..12
        );
        assert_eq!(
            paginate(&asked(Some(4), Some(3), false), minimal, 12)
                .expect("a page")
                .shown,
            8..12
        );
    }

    /// Asking for everything, or for no limit at all, gives the whole listing.
    #[test]
    fn everything_is_one_page() {
        for args in [asked(None, None, true), asked(Some(0), None, false)] {
            assert_eq!(
                paginate(&args, Presentation::Minimal, 12)
                    .expect("a page")
                    .shown,
                0..12
            );
        }
    }

    /// **`pipe` is a stable interface, so it is not truncated by a default.**
    ///
    /// A program running `zond journal --pipe` and silently receiving the first
    /// ten of forty records is worse served by the convenience than helped by
    /// it. A limit it asked for is still a limit it asked for.
    #[test]
    fn piping_lists_everything_unless_a_limit_was_asked_for() {
        assert_eq!(
            paginate(&asked(None, None, false), Presentation::Pipe, 40)
                .expect("a page")
                .shown,
            0..40,
            "no default may truncate the stable interface"
        );
        assert_eq!(
            paginate(&asked(Some(5), None, false), Presentation::Pipe, 40)
                .expect("a page")
                .shown,
            0..5
        );
        assert_eq!(
            paginate(&asked(None, Some(2), false), Presentation::Pipe, 40)
                .expect("a page")
                .shown,
            10..20,
            "asking for a page is asking for pages"
        );
    }

    /// A page that is not there is refused. Answering with nothing would read as
    /// "no scans on record", which is a different and more alarming thing.
    #[test]
    fn a_page_past_the_end_is_refused() {
        let refused = paginate(&asked(Some(10), Some(9), false), Presentation::Minimal, 12);

        let Err(Error::NoSuchPage {
            asked: wanted,
            pages,
        }) = refused
        else {
            panic!("a page past the end must be refused, not answered empty");
        };
        assert_eq!((wanted, pages), (9, 2));

        assert!(
            paginate(&asked(Some(10), Some(0), false), Presentation::Minimal, 12).is_err(),
            "pages count from one"
        );
    }

    /// A listing with records in it has a first page, whatever the arithmetic.
    #[test]
    fn a_short_listing_still_has_a_first_page() {
        assert_eq!(
            paginate(&asked(Some(10), Some(1), false), Presentation::Minimal, 3)
                .expect("a page")
                .shown,
            0..3
        );
    }
}
