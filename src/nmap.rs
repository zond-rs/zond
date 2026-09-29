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
//! *is* `-o` with the value `X` followed by a stray word. That is what a short
//! option with a value means, and no amount of declaring gets a parser to read
//! it the other way. Nmap's own parser is hand-written and has no such
//! constraint.
//!
//! So the tokens are rewritten here, where the rule is one table and can be
//! read: `-oX f` becomes `--output-as xml=f`. The rewrite is deliberately
//! narrow, matching a token of `-o` followed by exactly one letter and nothing
//! else, so `-o report.json` passes through untouched.
//!
//! ## The rest of nmap's hands
//!
//! The same table carries the handful of nmap's other flags that no parser
//! can take as written, because each is a short flag of two letters or takes
//! its value in a shape of its own: `-Pn`, `-iL FILE`, `-sI ZOMBIE`,
//! `--excludefile`, `--max-retries` and the `--version-*` pair. The scan types
//! written `-sS`, `-sU` and so on need none of this: `-s` is a flag like any
//! other, and `S` its value. See [`ScanType`](crate::cli::ScanType).
//!
//! Where zond has nothing that means what nmap's flag means, the flag is
//! refused by name with what to write instead: `-T4` and `-A`, which are not
//! built yet, and `-f` and `-S`, which are spelled another way here.
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
    let mut arguments = arguments.into_iter();

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
            Some(Rewrite::Tokens(tokens)) => rewritten.extend(tokens.iter().map(OsString::from)),
            // nmap counts the retries after the first probe, and zond the
            // attempts including it, so the number moves by one on the way.
            Some(Rewrite::Retries) => {
                rewritten.push(OsString::from("--max-attempts"));
                if let Some(count) = arguments.next() {
                    rewritten.push(one_more(count));
                }
            }
            None => match token.strip_prefix("--max-retries=") {
                Some(count) => {
                    rewritten.push(OsString::from("--max-attempts"));
                    rewritten.push(one_more(OsString::from(count)));
                }
                None => rewritten.push(argument),
            },
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
    /// This program's own spelling, as whole tokens, with whatever value
    /// followed left to follow it.
    Tokens(&'static [&'static str]),
    /// `--max-attempts`, with nmap's retry count as the next token.
    Retries,
}

/// A retry count as an attempt count: the first probe, and that many more.
///
/// Anything that is not a count is passed through as it was written, for the
/// parser to refuse in its own words.
fn one_more(count: OsString) -> OsString {
    count
        .to_str()
        .and_then(|text| text.parse::<u8>().ok())
        .and_then(|retries| retries.checked_add(1))
        .map_or(count, |attempts| OsString::from(attempts.to_string()))
}

/// What to write instead of an nmap flag zond has no counterpart for, or
/// `None` for a token that is not one.
fn refused(token: &str) -> Option<&'static str> {
    // `-T4`, `-T 4` and `-Tinsane` alike, and nothing longer that merely
    // begins with the letter.
    let timing = token.strip_prefix("-T").is_some_and(|rest| {
        rest.is_empty()
            || (rest.len() == 1 && rest.bytes().all(|b| (b'0'..=b'5').contains(&b)))
            || [
                "paranoid",
                "sneaky",
                "polite",
                "normal",
                "aggressive",
                "insane",
            ]
            .contains(&rest)
    });
    if timing {
        return Some(
            "timing templates are not built yet; pace a scan with --effort and --max-rate",
        );
    }
    match token {
        "-A" => Some("it is not built yet; ask for its parts with -O -d --traceroute"),
        "-f" => Some("fragment probes with --mtu, a multiple of eight"),
        "-S" => Some("a probe leaves from its interface's own address; pick the interface with -e"),
        _ => None,
    }
}

/// Reads one token as an nmap spelling, if it is one.
fn spelling(token: &str) -> Result<Option<Rewrite>, Error> {
    if let Some(instead) = refused(token) {
        return Err(Error::NmapFlag {
            spelling: token.to_owned(),
            instead,
        });
    }
    let own: Option<&'static [&'static str]> = match token {
        "-Pn" => Some(&["--assume-up"]),
        "-iL" => Some(&["--input-file"]),
        "-sI" => Some(&["--idle-scan"]),
        "--excludefile" => Some(&["--exclude-file"]),
        "--version-all" => Some(&["--service-detection", "thorough"]),
        "--version-light" => Some(&["--service-detection", "banner"]),
        _ => None,
    };
    if let Some(tokens) = own {
        return Ok(Some(Rewrite::Tokens(tokens)));
    }
    if token == "--max-retries" {
        return Ok(Some(Rewrite::Retries));
    }

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

    /// nmap's other flags that no parser takes as written arrive as this
    /// program's own, with their values where the parser expects them.
    #[test]
    fn nmaps_other_spellings_become_this_programs_own() {
        assert_eq!(
            rewritten(&["zond", "s", "-Pn", "-iL", "scope.txt", "-sI", "192.0.2.9"]),
            [
                "zond",
                "s",
                "--assume-up",
                "--input-file",
                "scope.txt",
                "--idle-scan",
                "192.0.2.9"
            ]
        );
        assert_eq!(
            rewritten(&["zond", "s", "--max-retries", "2", "--version-all"]),
            [
                "zond",
                "s",
                "--max-attempts",
                "3",
                "--service-detection",
                "thorough"
            ]
        );
        assert_eq!(
            rewritten(&["zond", "s", "--max-retries=0"]),
            ["zond", "s", "--max-attempts", "1"]
        );
    }

    /// A flag zond has no counterpart for is refused by name, and one that
    /// merely begins with the same letter is left alone.
    #[test]
    fn nmaps_flags_without_a_counterpart_are_refused_by_name() {
        for spelling in ["-T4", "-T", "-Tinsane", "-A", "-f", "-S"] {
            let refused = rewrite(["zond", "s", spelling].iter().map(OsString::from));
            let Err(Error::NmapFlag {
                spelling: named, ..
            }) = refused
            else {
                panic!("{spelling} must be refused by name");
            };
            assert_eq!(named, spelling);
        }
        assert_eq!(rewritten(&["zond", "s", "-T9x"]), ["zond", "s", "-T9x"]);
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
