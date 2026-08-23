// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Nmap's output spellings
//!
//! `-oX report.xml` and its siblings, for the hands that have typed them for
//! twenty years. They are rewritten into this program's own flags before the
//! command line is parsed, so nothing downstream has to know they exist.
//!
//! ## Why a rewrite rather than arguments
//!
//! They cannot be expressed as arguments. `-o` takes a file, so `-oX report`
//! *is* `-o` with the value `X` followed by a stray word — that is what a
//! short option with a value means, and no amount of declaring gets a parser to
//! read it the other way. Nmap's own parser is hand-written and has no such
//! constraint.
//!
//! So the tokens are rewritten here, where the rule is one table and can be
//! read: `-oX f` becomes `--output-as xml=f`. The rewrite is deliberately
//! narrow — a token matching `-o` followed by exactly one letter, and nothing
//! else — so `-o report.json` passes through untouched.
//!
//! ## The ones that are not built
//!
//! Nmap's normal (`-oN`) and grepable (`-oG`) outputs have no counterpart here
//! yet. They are recognised and refused by name rather than left to fail as an
//! unknown flag, because "not built yet" and "no such thing" send a person to
//! different places. [`Presentation`](crate::settings::Presentation) refuses its
//! own unbuilt modes on the same reasoning.

use std::ffi::OsString;

use crate::error::Error;

/// Rewrites nmap's output spellings into this program's own.
///
/// Every other token is passed through exactly as it arrived, including
/// anything after a `--`, which by convention is not ours to interpret.
pub(crate) fn rewrite<I>(arguments: I) -> Result<Vec<OsString>, Error>
where
    I: IntoIterator<Item = OsString>,
{
    let mut rewritten = Vec::new();
    let mut verbatim = false;
    let mut arguments = arguments.into_iter().peekable();

    while let Some(argument) = arguments.next() {
        if verbatim {
            rewritten.push(argument);
            continue;
        }
        if argument == "--" {
            verbatim = true;
            rewritten.push(argument);
            continue;
        }

        let Some(token) = argument.to_str() else {
            rewritten.push(argument);
            continue;
        };

        match spelling(token)? {
            // The file is the next token, and it has to be folded into this
            // one: `--output-as` takes a single value, so leaving the file
            // beside it would hand it to the parser as a target expression.
            Some(Rewrite::As(format)) => {
                rewritten.push(OsString::from("--output-as"));
                match arguments.next() {
                    Some(file) => {
                        let mut value = OsString::from(format);
                        value.push("=");
                        value.push(file);
                        rewritten.push(value);
                    }
                    // Nothing followed it. Left as a flag with no value, so the
                    // parser says what it needs rather than this guessing.
                    None => rewritten.push(OsString::from(format)),
                }
            }
            // `--output-all` takes one value too, and its base name is already
            // the next token.
            Some(Rewrite::All) => rewritten.push(OsString::from("--output-all")),
            None => rewritten.push(argument),
        }
    }

    Ok(rewritten)
}

/// What one of nmap's spellings becomes.
enum Rewrite {
    /// `--output-as`, with the format this letter names. The file follows as
    /// its own token, so it is joined to the format downstream.
    As(&'static str),
    /// `--output-all`, whose base name follows as its own token.
    All,
}

/// Reads one token as an nmap output spelling, if it is one.
fn spelling(token: &str) -> Result<Option<Rewrite>, Error> {
    let Some(letter) = token.strip_prefix("-o") else {
        return Ok(None);
    };
    if letter.chars().count() != 1 {
        return Ok(None);
    }

    Ok(Some(match letter {
        "X" => Rewrite::As("xml"),
        "J" => Rewrite::As("json"),
        "C" => Rewrite::As("csv"),
        "H" => Rewrite::As("html"),
        "L" => Rewrite::As("jsonl"),
        "A" => Rewrite::All,
        // Named rather than passed through to fail as an unknown flag: these
        // are formats this program means to have and does not yet, and a person
        // who typed one is better served by hearing which.
        "N" | "G" | "S" => {
            return Err(Error::FormatNotBuilt {
                spelling: token.to_owned(),
                known: crate::export::known_formats(),
            });
        }
        _ => return Ok(None),
    }))
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

    fn rewritten(arguments: &[&str]) -> Vec<String> {
        rewrite(arguments.iter().map(OsString::from))
            .expect("no unbuilt format")
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    /// The whole point: `-oX f` is not something a parser can be taught, so it
    /// is turned into something it already knows.
    #[test]
    fn nmaps_spellings_become_this_programs_own() {
        assert_eq!(
            rewritten(&["zond", "scan", "-oX", "out.txt"]),
            ["zond", "scan", "--output-as", "xml=out.txt"]
        );
        assert_eq!(
            rewritten(&["zond", "scan", "-oJ", "out"]),
            ["zond", "scan", "--output-as", "json=out"]
        );
        assert_eq!(
            rewritten(&["zond", "scan", "-oA", "engagement"]),
            ["zond", "scan", "--output-all", "engagement"]
        );
    }

    /// And `-o` itself must survive untouched, since it is the spelling most
    /// people will use.
    #[test]
    fn the_ordinary_output_flag_passes_through() {
        for arguments in [
            vec!["zond", "scan", "-o", "out.json"],
            vec!["zond", "scan", "--output", "out.json"],
            // Two letters is not one of nmap's forms, whatever it is.
            vec!["zond", "scan", "-oXX", "out"],
        ] {
            let expected: Vec<String> = arguments.iter().map(|a| (*a).to_owned()).collect();
            assert_eq!(rewritten(&arguments), expected);
        }
    }

    /// A format named but not built is refused by name. Passing it through to
    /// fail as an unknown flag would send somebody looking for a typo.
    #[test]
    fn a_format_that_is_not_built_is_refused_by_name() {
        for spelling in ["-oN", "-oG", "-oS"] {
            let refused = rewrite(["zond", "scan", spelling, "out"].iter().map(OsString::from));
            let Err(Error::FormatNotBuilt {
                spelling: named, ..
            }) = refused
            else {
                panic!("{spelling} must be refused by name");
            };
            assert_eq!(named, spelling);
        }
    }

    /// Nothing after `--` is ours to read, whatever it looks like.
    #[test]
    fn arguments_after_a_double_dash_are_left_alone() {
        assert_eq!(
            rewritten(&["zond", "scan", "--", "-oX", "out"]),
            ["zond", "scan", "--", "-oX", "out"]
        );
    }
}
