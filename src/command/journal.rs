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
    if let Some(footer) = footer(&page, entries.len()) {
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

/// What a listing says about itself, or `None` where it showed everything.
///
/// Separated from the writing so it can be read back in a test. The command it
/// belongs to reads the real journal directory, so there is no unit test that
/// runs `list` end to end, which is how a `\n` on the front of this line once
/// reached a terminal and printed itself.
fn footer(page: &Page, records: usize) -> Option<String> {
    if page.shown.len() >= records {
        return None;
    }

    // A page you can actually go to rather than the flag's grammar: the next one
    // where there is one, the previous where this is the last. A hint that names
    // something which would fail is worse than none.
    let step = if page.number < page.of {
        format!("--page {} for the next", page.number + 1)
    } else {
        format!("--page {} for the previous", page.number - 1)
    };

    Some(format!(
        "page {} of {}, {records} records; {step}, --all for every one",
        page.number, page.of,
    ))
}

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

/// Which slice of the listing to show.
///
/// **`pipe` shows everything unless a limit is asked for.** Paging is a reading
/// affordance, and that mode's output is a stable interface. A program running
/// `zond journal --pipe` and silently receiving the first ten of forty records
/// would be worse served by the convenience than helped by it. Asking for a
/// limit there is still honoured, because then it was asked for.
fn paginate(page: &PageArgs, presentation: Presentation, total: usize) -> Result<Page, Error> {
    let size = match (page.all, page.limit, presentation) {
        // Everything, and `-n 0` as the other way of asking for it.
        (true, _, _) | (_, Some(0), _) => None,
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
            Err(error) => pruned.held.push(store::Held {
                id: entry.manifest.id.clone(),
                reason: error.to_string(),
            }),
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

    /// A page as the flags describe one.
    fn asked(limit: Option<usize>, page: Option<usize>, all: bool) -> PageArgs {
        PageArgs { limit, page, all }
    }

    /// Commentary is written one line at a time, and this is the line that
    /// forgot.
    ///
    /// A painted string is escaped before it is wrapped, which is what stops a
    /// hostname a scanned host chose from clearing the screen, so a `\n` handed
    /// to a role arrives at the terminal as the two characters `\` and `n`. The
    /// footer carried one on its front and printed it.
    #[test]
    fn no_line_of_commentary_carries_a_newline() {
        let paged = Page {
            shown: 0..10,
            number: 1,
            of: 4,
        };

        let line = footer(&paged, 38).expect("a page of four says so");

        assert!(
            !line.contains('\n'),
            "the footer would print its own newline: {line:?}"
        );
        assert!(line.starts_with("page 1 of 4, 38 records"), "{line:?}");
        assert!(line.contains("--page 2 for the next"), "{line:?}");
    }

    /// The last page points backwards, because a hint naming a page that does
    /// not exist is worse than no hint.
    #[test]
    fn the_last_page_offers_the_one_before_it() {
        let last = Page {
            shown: 30..38,
            number: 4,
            of: 4,
        };

        let line = footer(&last, 38).expect("a page of four says so");
        assert!(line.contains("--page 3 for the previous"), "{line:?}");
    }

    /// A listing that showed everything says nothing about itself.
    #[test]
    fn a_listing_that_fits_has_no_footer() {
        let whole = Page {
            shown: 0..38,
            number: 1,
            of: 1,
        };

        assert_eq!(footer(&whole, 38), None);
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

    /// **`pipe` is a stable interface, so no default truncates it.**
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
