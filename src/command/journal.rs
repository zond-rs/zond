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
use zond_engine::journal::store::{self, Entry, Listing, PassedOver, Retention, Unlisted};

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
            unreadable,
            dry_run,
        }) if ids.is_empty() => prune(
            &retention(*all, *completed, *older_than, *unreadable)?,
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
    let Listing {
        entries,
        passed_over,
        ..
    } = read()?;

    if entries.is_empty() {
        // To stderr, so `zond journal | wc -l` counts journals rather than a
        // sentence about there being none.
        commentary.remark("no scans on record");
        commentary.unlisted(&passed_over);
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
    commentary.unlisted(&passed_over);

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

    /// What the listing could not show.
    ///
    /// Records a newer build wrote, and links, are said once per reason: a
    /// machine that ran a newer build has every record that build wrote passed
    /// over for the same reason, and a line apiece buries the one fact and the
    /// one thing to do about it. With `-v` each is named as well. A record
    /// that cannot be read for any other reason is named every time, since
    /// each is its own problem with its own owner to act on it.
    fn unlisted(self, passed_over: &[PassedOver]) {
        if !self.verbosity.narrates() {
            return;
        }

        for line in unlisted_lines(passed_over, self.verbosity.explains()) {
            let _ = writeln!(io::stderr(), "{}", self.style.line(Mark::Warning, &line));
        }
    }
}

/// The lines saying what a listing passed over: a count for the records a
/// newer build wrote and one for links, each named too when `each`, and a
/// line of its own for every other record that could not be read.
fn unlisted_lines(passed_over: &[PassedOver], each: bool) -> Vec<String> {
    let named = |passed: &PassedOver| format!("{} not listed: {}", passed.name, passed.why);
    let newer: Vec<&PassedOver> = passed_over
        .iter()
        .filter(|passed| matches!(passed.why, Unlisted::NewerFormat { .. }))
        .collect();
    let links: Vec<&PassedOver> = passed_over
        .iter()
        .filter(|passed| passed.why == Unlisted::Link)
        .collect();

    let mut said = Vec::new();
    if !newer.is_empty() {
        let count = newer.len();
        said.push(format!(
            "{count} {} not listed: a newer zond's (zond j prune --unreadable)",
            crate::render::field::plural(count as u128, "record")
        ));
        if each {
            said.extend(newer.iter().map(|passed| named(passed)));
        }
    }
    if !links.is_empty() {
        let count = links.len();
        said.push(format!(
            "{count} {} in the journal directory not followed",
            crate::render::field::plural(count as u128, "link")
        ));
        if each {
            said.extend(links.iter().map(|passed| named(passed)));
        }
    }
    said.extend(
        passed_over
            .iter()
            .filter(|passed| matches!(passed.why, Unlisted::Unreadable(_)))
            .map(named),
    );
    said
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
    let id = newest_if_latest(id)?;
    let listing = read()?;
    let entry = find_in(&listing, &id)?;

    render::show(entry, presentation, out, style)?;
    Ok(Outcome::Complete)
}

/// Deletes the journals named, whatever their age.
///
/// Every id is resolved before anything is deleted, so a typo in the third of
/// three leaves the first two alone. Half a command is worse than none of it
/// when the half that ran cannot be undone.
///
/// A record this build cannot read is named by its directory, which is the
/// id it was written under, so one the listing only counted can still be
/// deleted by name. A link never is: see [`Unlisted::Link`].
fn remove(
    ids: &[String],
    dry_run: bool,
    presentation: Presentation,
    out: &mut dyn Write,
    style: Style,
) -> Result<Outcome, Error> {
    let listing = read()?;
    let chosen: Vec<(String, &std::path::Path)> = ids
        .iter()
        .map(|id| named(&listing, id))
        .collect::<Result<_, _>>()?;

    let mut pruned = store::Pruned::default();
    for (id, directory) in chosen {
        if dry_run {
            pruned.removed.push(id);
            continue;
        }

        match store::remove(directory) {
            Ok(()) => pruned.removed.push(id),
            Err(error) => pruned.held.push(store::Held::new(id, error.to_string())),
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
/// For `zond resume`, which reaches a journal by its directory rather than through
/// a listing and so cannot use [`find`]. Prefixes are not resolved here: a
/// resume takes a lock and scans a network, and the id it was given is checked
/// against the record it opens.
pub(crate) fn newest_if_latest(id: &str) -> Result<String, Error> {
    if id != LATEST {
        return Ok(id.to_owned());
    }

    read()?
        .entries
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

/// The readable record `id` names, or why the record it names cannot be read.
///
/// As [`find`], except that an id the listing passed over is not answered as
/// one nobody recorded: that would send a person to check an id that is
/// right, when what they need is the reason. Links are matched too, since a
/// link standing where a record would is named in the listing the same way.
pub(crate) fn find_in<'a>(listing: &'a Listing, id: &str) -> Result<&'a Entry, Error> {
    match find(&listing.entries, id) {
        Err(Error::NoSuchJournal { known, .. }) => {
            let exact = listing.passed_over.iter().find(|passed| passed.name == id);
            let mut prefixed = listing
                .passed_over
                .iter()
                .filter(|passed| passed.name.starts_with(id));
            let passed = exact.or_else(|| match (prefixed.next(), prefixed.next()) {
                (Some(only), None) => Some(only),
                _ => None,
            });
            Err(match passed {
                Some(passed) => Error::UnreadableJournal {
                    id: passed.name.clone(),
                    reason: passed.why.to_string(),
                },
                None => Error::NoSuchJournal {
                    id: id.to_owned(),
                    known,
                },
            })
        }
        other => other,
    }
}

/// The record `id` names for deletion, readable or not, as its id and its
/// directory.
///
/// A readable record is found as [`find`] finds one. Failing that, `id` is
/// matched against the directories the listing passed over, whole or by a
/// prefix that names only one, links excepted. A prefix naming one of each
/// is refused as ambiguous, for the reason [`find`] refuses any other.
fn named<'a>(listing: &'a Listing, id: &str) -> Result<(String, &'a std::path::Path), Error> {
    let readable = find(&listing.entries, id);
    let deletable = || {
        listing
            .passed_over
            .iter()
            .filter(|passed| passed.why != Unlisted::Link)
    };
    let unreadable: Vec<&PassedOver> = match deletable().find(|passed| passed.name == id) {
        Some(exact) => vec![exact],
        None => deletable()
            .filter(|passed| passed.name.starts_with(id))
            .collect(),
    };

    match (readable, unreadable.as_slice()) {
        (Ok(entry), []) => Ok((entry.manifest.id.clone(), entry.directory.as_path())),
        (Ok(entry), [passed, ..]) => Err(Error::AmbiguousJournal {
            id: id.to_owned(),
            first: entry.manifest.id.clone(),
            second: passed.name.clone(),
        }),
        (Err(Error::NoSuchJournal { .. }), [only]) => {
            Ok((only.name.clone(), only.directory.as_path()))
        }
        (Err(Error::NoSuchJournal { .. }), [first, second, ..]) => Err(Error::AmbiguousJournal {
            id: id.to_owned(),
            first: first.name.clone(),
            second: second.name.clone(),
        }),
        (Err(error), _) => Err(error),
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
        let listing = read()?;
        let selected = retention.expired(&listing.entries, std::time::SystemTime::now());

        let mut pruned = store::Pruned::default();
        pruned.removed = selected
            .into_iter()
            .map(|index| listing.entries[index].manifest.id.clone())
            .collect();
        if retention.unreadable {
            pruned.removed.extend(
                listing
                    .passed_over
                    .iter()
                    .filter(|passed| passed.why != Unlisted::Link)
                    .map(|passed| passed.name.clone()),
            );
        }
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
/// deliberately, and includes the records this build cannot read. Everything
/// else leaves unfinished work alone, because it is the only copy of something
/// somebody may still mean to continue.
///
/// `--unreadable` alone removes those records and nothing else: someone
/// clearing out what a newer build left has not asked for the ordinary sweep
/// as well. Beside `--completed` or `--older-than` it adds them to that sweep.
///
/// The count comes from `journal_entry_limit`, which is the same number a
/// recording run applies as it goes, so a sweep and a scan agree about how many
/// records this machine keeps rather than holding two opinions that differ by
/// whichever of them ran last. Ages are this command's own: nothing prunes by
/// time unless somebody asks for it here.
fn retention(
    all: bool,
    completed: bool,
    older_than: Option<Duration>,
    unreadable: bool,
) -> Result<Retention, Error> {
    let mut retention = Retention::default();
    if all {
        retention.completed_for = Some(Duration::ZERO);
        retention.incomplete_for = Some(Duration::ZERO);
        retention.unreadable = true;
        return Ok(retention);
    }
    if unreadable && !completed && older_than.is_none() {
        let mut retention = Retention::keep_everything();
        retention.unreadable = true;
        return Ok(retention);
    }
    retention.unreadable = unreadable;

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
pub(crate) fn read() -> Result<Listing, Error> {
    Ok(store::list(&root()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn passed(name: &str, why: Unlisted) -> PassedOver {
        PassedOver::new(name, PathBuf::from("/journals").join(name), why)
    }

    fn newer(name: &str) -> PassedOver {
        passed(name, Unlisted::NewerFormat { found: 2 })
    }

    fn listing(passed_over: Vec<PassedOver>) -> Listing {
        let mut listing = Listing::default();
        listing.passed_over = passed_over;
        listing
    }

    /// Ninety-eight records a newer build wrote are one line, not ninety-eight,
    /// links are another, and a record unreadable for any other reason is
    /// named, since each is its own problem.
    #[test]
    fn unlisted_records_are_counted_once_per_reason() {
        let mut passed_over: Vec<PassedOver> = (0..98)
            .map(|index| newer(&format!("06G{index:013}")))
            .collect();
        passed_over.push(passed("06LINKED00000000", Unlisted::Link));
        passed_over.push(passed(
            "06A",
            Unlisted::Unreadable("permission denied".into()),
        ));
        passed_over.push(passed(
            "06B",
            Unlisted::Unreadable("permission denied".into()),
        ));

        assert_eq!(
            unlisted_lines(&passed_over, false),
            [
                "98 records not listed: a newer zond's (zond j prune --unreadable)",
                "1 link in the journal directory not followed",
                "06A not listed: permission denied",
                "06B not listed: permission denied",
            ]
        );
        assert_eq!(
            unlisted_lines(&passed_over, true).len(),
            4 + 98 + 1,
            "with -v every one is named"
        );
    }

    /// A record the listing only counted can still be deleted by the name it
    /// was written under, whole or by an unambiguous prefix.
    #[test]
    fn an_unreadable_record_is_named_by_its_directory() {
        let listing = listing(vec![newer("06GAAAA"), newer("06GBBBB")]);

        let (id, directory) = named(&listing, "06GAAAA").expect("whole");
        assert_eq!(id, "06GAAAA");
        assert_eq!(directory, std::path::Path::new("/journals/06GAAAA"));
        assert_eq!(named(&listing, "06GB").expect("a prefix").0, "06GBBBB");
        assert!(matches!(
            named(&listing, "06G"),
            Err(Error::AmbiguousJournal { .. })
        ));
    }

    /// A link is never a record to delete, whatever it is named.
    #[test]
    fn a_link_is_never_named_for_deletion() {
        let listing = listing(vec![passed("06LINKED", Unlisted::Link)]);
        assert!(matches!(
            named(&listing, "06LINKED"),
            Err(Error::NoSuchJournal { .. })
        ));
    }

    /// `--unreadable` alone asks for those records and not for the ordinary
    /// sweep beside them; `--all` includes them.
    #[test]
    fn unreadable_alone_sweeps_nothing_else() {
        let alone = retention(false, false, None, true).expect("a policy");
        let mut expected = Retention::keep_everything();
        expected.unreadable = true;
        assert_eq!(alone, expected);

        assert!(
            retention(true, false, None, false)
                .expect("a policy")
                .unreadable
        );
    }
}
