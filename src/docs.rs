// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The help that is not a flag
//!
//! `zond help`, `zond completions`, and the man pages a package installs. All
//! three are drawn from the definition the parser is built from, so none of
//! them can describe a flag the parser does not have.

use std::io::Write;
use std::path::Path;

use clap::CommandFactory;

use crate::cli::Cli;
use crate::error::Error;
use crate::exit::Outcome;
use crate::topics::{self, TOPICS};

/// `zond help`: a command's full help, a topic, or the list of both.
pub(crate) fn help(topic: &[String]) -> Result<Outcome, Error> {
    let mut command = Cli::command();
    command.build();

    let [first, rest @ ..] = topic else {
        command.print_long_help()?;
        println!("\n{}", topics::listed());
        return Ok(Outcome::Complete);
    };

    if rest.is_empty()
        && let Some(topic) = topics::find(first)
    {
        print!("{}", (topic.text)());
        return Ok(Outcome::Complete);
    }

    let mut found = &mut command;
    for name in topic {
        found = found
            .find_subcommand_mut(name)
            .ok_or_else(|| Error::UnknownHelp {
                asked: topic.join(" "),
                known: known(),
            })?;
    }
    found.print_long_help()?;
    Ok(Outcome::Complete)
}

/// The commands and topics `zond help` answers, for the refusal of one it
/// does not.
fn known() -> String {
    let command = Cli::command();
    command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .map(|subcommand| subcommand.get_name().to_owned())
        .chain(TOPICS.iter().map(|topic| topic.name.to_owned()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `zond completions`: the script for one shell, on standard output.
///
/// Rendered whole before any of it is written, because the generator panics
/// on a write that fails, and a reader that stops early, `| head`, is one.
pub(crate) fn completions(shell: clap_complete::Shell) -> Result<Outcome, Error> {
    let mut script = Vec::new();
    clap_complete::generate(shell, &mut Cli::command(), "zond", &mut script);
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&script)?;
    stdout.flush()?;
    Ok(Outcome::Complete)
}

/// `zond __generate DIR`: every man page and every completion script, for a
/// package build.
pub(crate) fn generate(directory: &Path) -> Result<Outcome, Error> {
    let man = directory.join("man");
    let completions = directory.join("completions");
    std::fs::create_dir_all(&man)?;
    std::fs::create_dir_all(&completions)?;

    let mut command = Cli::command()
        // This machine's settings paths are what `zond --help` prints; a page
        // installed for everybody names them the way a reader finds them.
        .after_long_help(crate::cli::GETTING_STARTED);
    command.build();
    pages(&command, &man, true)?;
    for topic in TOPICS {
        std::fs::write(
            man.join(format!("zond-{}.7", topic.name)),
            topic_page(topic),
        )?;
    }

    for shell in [
        clap_complete::Shell::Bash,
        clap_complete::Shell::Zsh,
        clap_complete::Shell::Fish,
        clap_complete::Shell::PowerShell,
        clap_complete::Shell::Elvish,
    ] {
        clap_complete::generate_to(shell, &mut Cli::command(), "zond", &completions)?;
    }
    Ok(Outcome::Complete)
}

/// Writes the page for `command` and for each of its commands, beneath it.
fn pages(command: &clap::Command, directory: &Path, root: bool) -> Result<(), Error> {
    for subcommand in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        pages(subcommand, directory, false)?;
    }

    let man = clap_mangen::Man::new(command.clone())
        .date(dated())
        .source(format!("zond {}", env!("CARGO_PKG_VERSION")))
        .manual("Zond Manual");
    let mut page = Vec::new();
    man.render(&mut page)?;
    let mut page = String::from_utf8(page).expect("roff is text");
    // clap_mangen heads what a command's help ends with EXTRA, which names the
    // tool's layout rather than what is there.
    page = page.replace(".SH EXTRA", ".SH NOTES");
    page.push_str(if root { ROOT_SECTIONS } else { SEE_ALSO });

    std::fs::write(directory.join(man.get_filename()), page)?;
    Ok(())
}

/// A topic as a section 7 page: its text kept as written.
fn topic_page(topic: &topics::Topic) -> String {
    let text = (topic.text)()
        .lines()
        .map(|line| {
            let escaped = line.replace('\\', "\\\\");
            if escaped.starts_with('.') || escaped.starts_with('\'') {
                format!("\\&{escaped}")
            } else {
                escaped
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        ".TH ZOND-{title} 7 \"{date}\" \"zond {version}\" \"Zond Manual\"\n\
         .SH NAME\nzond-{name} \\- {summary}\n\
         .SH DESCRIPTION\n.nf\n{text}\n.fi\n{SEE_ALSO}",
        name = topic.name,
        title = topic.name.to_uppercase(),
        date = dated(),
        version = env!("CARGO_PKG_VERSION"),
        summary = topic.summary,
    )
}

/// The date a page is stamped with, as `YYYY-MM-DD`.
///
/// `SOURCE_DATE_EPOCH` where the build sets it, so two builds of one release
/// write the same pages, and the day it is otherwise.
fn dated() -> String {
    let seconds = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|epoch| epoch.parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs())
        });
    civil(seconds)
}

/// The date `seconds` after 1970 began, as `YYYY-MM-DD`: days to a civil date
/// by Howard Hinnant's algorithm.
fn civil(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(0) + 719_468;
    let era = days.div_euclid(146_097);
    let of_era = days.rem_euclid(146_097);
    let year_of_era = (of_era - of_era / 1460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// What every page but the first ends with.
const SEE_ALSO: &str = ".SH SEE ALSO\nzond(1)\n";

/// What `zond(1)` ends with: what a manual page is expected to say and a
/// command's help has no heading for.
const ROOT_SECTIONS: &str = "\
.SH EXIT STATUS
.TP
0
Finished, and covered everything it was asked to.
.TP
1
Could not be carried out.
.TP
2
What was asked for was not usable.
.TP
3
Finished, but something it was asked to cover was not covered.
.TP
4
A comparison found changes. zond diff only.
.TP
130
Interrupted with Ctrl-C.
.SH FILES
.TP
~/.config/zond/cli.toml
How a run is shown. Under $XDG_CONFIG_HOME when that is set.
.TP
~/.config/zond/engine.toml
What a scan puts on the wire.
.TP
/etc/zond/cli.toml, /etc/zond/engine.toml
The same, for every user of the machine, beneath their own.
.SH ENVIRONMENT
.TP
NO_COLOR, CLICOLOR_FORCE, TERM
Read the way other tools read them, when --colour is auto.
.TP
COLORTERM
Whether the terminal takes a twenty-four bit accent colour.
.TP
XDG_CONFIG_HOME
Where the settings files are, when it is an absolute path.
.SH SEE ALSO
zond-targets(7), zond-ports(7), zond-output(7), zond-settings(7),
zond-exit-codes(7)
";

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

    /// What a package build installs is written without failing, and names
    /// the files the package metadata lists. A page that did not render, or a
    /// script written under another name, would otherwise surface only when a
    /// release was cut.
    #[test]
    fn a_package_build_writes_every_page_and_script_it_installs() {
        let directory =
            std::env::temp_dir().join(format!("zond-cli-generate-{}", std::process::id()));
        generate(&directory).expect("generated");

        for page in [
            "zond.1",
            "zond-scan.1",
            "zond-journal-prune.1",
            "zond-ports.7",
        ] {
            assert!(directory.join("man").join(page).is_file(), "{page}");
        }
        for script in ["zond.bash", "_zond", "zond.fish"] {
            assert!(
                directory.join("completions").join(script).is_file(),
                "{script}"
            );
        }

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The dates a page is stamped with, at the edges of the calendar
    /// arithmetic: the epoch, a leap day, and the last second of a year.
    #[test]
    fn a_page_is_dated_by_the_calendar() {
        assert_eq!(civil(0), "1970-01-01");
        assert_eq!(civil(951_782_400), "2000-02-29");
        assert_eq!(civil(1_798_761_599), "2026-12-31");
    }
}
