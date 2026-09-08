// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A listing, a page at a time
//!
//! Two commands list more rows than a terminal holds: `zond journal`, which has
//! every scan this machine ever ran, and `zond detections`, which has the whole
//! corpus. Both cut the listing the same way, and both say the same thing under
//! it about where the cut fell, so the arithmetic and the sentence live here
//! rather than once per command.
//!
//! The flags are [`PageArgs`], declared beside the rest of the grammar. What a
//! page is worth is a setting, `page_size` in `cli.toml`, read here for the same
//! reason the identity is read in [`command`](super): only the commands that
//! list have an opinion about it.

use crate::cli::PageArgs;
use crate::error::Error;
use crate::settings::{self, Presentation};

/// How many rows a listing shows when nothing says otherwise.
///
/// A handful, because the ones anybody is looking for are usually at the front
/// of the listing. `--all` is one flag away, and `page_size` in `cli.toml` moves
/// the default for good.
pub(crate) const DEFAULT_PAGE_SIZE: usize = 10;

/// Which slice a listing shows, and where that slice sits.
///
/// The number and the count travel with the range because the footer needs
/// them, and working them out again from the arguments would be a second place
/// that has to agree about what a page is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Page {
    /// The rows to show.
    pub shown: std::ops::Range<usize>,
    /// Which page this is, counting from one.
    pub number: usize,
    /// How many there are.
    pub of: usize,
}

/// Which slice of the listing to show.
///
/// **`pipe` shows everything unless a limit is asked for.** Paging is a reading
/// affordance, and that mode's output is a stable interface. A program running
/// `zond journal --pipe` and silently receiving the first ten of forty records
/// would be worse served by the convenience than helped by it. Asking for a
/// limit there is still honoured, because then it was asked for.
pub(crate) fn paginate(
    page: &PageArgs,
    presentation: Presentation,
    total: usize,
) -> Result<Page, Error> {
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

    // Rounded up, and never zero: a listing with rows in it has a first page
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

/// What a listing says about itself, or `None` where it showed everything.
///
/// `noun` is what the rows are, plural: `records` for a journal, `detections`
/// for a corpus. The line is read under a listing whose shape already says what
/// it holds, so naming the rows costs a word and saves the reader working out
/// what the number counts.
///
/// Separated from the writing so it can be read back in a test. The commands
/// this belongs to read the real journal directory and compile a real corpus, so
/// there is no unit test that runs either listing end to end, which is how a
/// `\n` on the front of this line once reached a terminal and printed itself.
pub(crate) fn footer(page: &Page, total: usize, noun: &str) -> Option<String> {
    if page.shown.len() >= total {
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
        "page {} of {}, {total} {noun}; {step}, --all for every one",
        page.number, page.of,
    ))
}

/// The page size this machine's settings ask for, or the built-in default.
fn configured_page_size() -> Result<usize, Error> {
    let (settings, _) = settings::resolve()?;
    Ok(settings.page_size().unwrap_or(DEFAULT_PAGE_SIZE))
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

        let line = footer(&paged, 38, "records").expect("a page of four says so");

        assert!(
            !line.contains('\n'),
            "the footer would print its own newline: {line:?}"
        );
        assert!(line.starts_with("page 1 of 4, 38 records"), "{line:?}");
        assert!(line.contains("--page 2 for the next"), "{line:?}");
    }

    /// The rows are named by whoever is listing them, so the same line reads
    /// correctly under a corpus and under a journal.
    #[test]
    fn the_footer_names_what_it_counted() {
        let paged = Page {
            shown: 0..10,
            number: 1,
            of: 10,
        };

        let line = footer(&paged, 95, "detections").expect("a page of ten says so");
        assert!(line.contains("95 detections"), "{line:?}");
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

        let line = footer(&last, 38, "records").expect("a page of four says so");
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

        assert_eq!(footer(&whole, 38, "records"), None);
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
