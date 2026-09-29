// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Help topics
//!
//! What `zond help <topic>` prints, and what the man pages carry as section 7:
//! the grammars and conventions several commands share, which no one command's
//! `--help` is the place for.
//!
//! A topic is a page of plain text, so the terminal and a man page can both
//! show it as written.

use crate::cli::{OUTPUT_FORMS, STOPPING, TARGET_FORMS};

/// One page of `zond help`.
pub(crate) struct Topic {
    /// What it is asked for by: `zond help targets`.
    pub(crate) name: &'static str,
    /// One line, for the list of topics.
    pub(crate) summary: &'static str,
    /// The page.
    pub(crate) text: fn() -> String,
}

/// Every topic, in the order they are listed.
pub(crate) const TOPICS: &[Topic] = &[
    Topic {
        name: "targets",
        summary: "the forms a target takes, and reading them from a file",
        text: targets,
    },
    Topic {
        name: "ports",
        summary: "the port grammar -p and --exclude-ports read",
        text: || PORTS.to_owned(),
    },
    Topic {
        name: "output",
        summary: "what goes to the terminal, what goes to a file, and how to stop",
        text: output,
    },
    Topic {
        name: "settings",
        summary: "the two settings files, how they layer, and profiles",
        text: || SETTINGS.to_owned(),
    },
    Topic {
        name: "exit-codes",
        summary: "what the exit status says about a run",
        text: || EXIT_CODES.to_owned(),
    },
];

/// The topic called `name`, if there is one.
pub(crate) fn find(name: &str) -> Option<&'static Topic> {
    TOPICS.iter().find(|topic| topic.name == name)
}

/// The list of topics, as `zond help` ends with it.
pub(crate) fn listed() -> String {
    use std::fmt::Write;

    let mut listed = String::from("Topics, for zond help <TOPIC>:\n");
    for topic in TOPICS {
        let _ = writeln!(listed, "  {:<12}{}", topic.name, topic.summary);
    }
    listed
}

fn targets() -> String {
    format!(
        "{TARGET_FORMS}
Several may be given, each may be a comma-separated list, and a port scan's
target may carry its own ports, as in 10.0.0.1:8080 or [2001:db8::1]:443.

From a file:
  -i scope.txt        targets from a file, one or more to a line
  -i -                targets from standard input
  --exclude-file FILE exclusions from a file

A file's targets are separated by spaces, commas or lines, and a # starts a
comment that runs to the end of its line. A file that names nothing is refused
rather than scanned.

lan names a network rather than the range it covers, so it also sends the
ICMPv6 all-nodes echo and reads this host's neighbour table.
"
    )
}

const PORTS: &str = "\
Port lists, as -p and --exclude-ports read them:
  22,80,443           a list
  1-1024              a range
  -p-                 every port there is
  -p-1024, -p9000-    a range open at one end
  u:53,161            UDP ports
  s:2905              SCTP ports
  u:53,t:22           a qualifier holds until the next one

The likeliest ports:
  -F                  the hundred TCP ports most likely to be listening
  --top-ports N       the N TCP ports most likely to be listening
  --top-ports-udp N   the same for UDP, from a list of 250

With no port flag, a scan probes default_ports from engine.toml, and the
thousand likeliest TCP ports when that says nothing either.

A service name where a number goes is refused with the numbers it runs on:
-p ssh is answered with 22.

A printer's raw-print ports, TCP 9100 to 9107, are found open and sent nothing
more, because a printer prints what arrives on them. --probe-print-ports probes
them like any other, and --exclude-ports 9100-9107 sends them nothing at all.
";

fn output() -> String {
    format!(
        "\
What goes where:
  Records go to standard output and everything else to standard error, in every
  presentation. zond discover lan > hosts.txt leaves a file of hosts and still
  shows the sweep happening.

Presentations:
  --fancy             a numbered block per host, for reading closely (default)
  --minimal           a tagged block per host, for a narrow terminal
  --pipe              tab-separated records for a program; fields are only
                      ever added at the end
{OUTPUT_FORMS}{STOPPING}"
    )
}

const SETTINGS: &str = "\
Two files, written on the first run with every key commented out:
  ~/.config/zond/cli.toml     how a run is shown
  ~/.config/zond/engine.toml  what a scan puts on the wire

On Windows they are under %APPDATA%\\zond. zond --help prints this machine's.

They layer, each over the one before:
  built-in defaults, /etc/zond/*.toml, the two files above, then the flags

A layer speaks only about the keys it mentions, so a flag left off cannot
cancel a setting that was written. exclude and exclude_ports add to one another
rather than one replacing the other.

Profiles:
  A [profiles.NAME] table in engine.toml is a named set of keys, and
  --profile NAME lays it over the file's defaults for one run.

Each key is described where it is written, in the files themselves.
";

const EXIT_CODES: &str = "\
Exit status:
  0    finished, and covered everything it was asked to
  1    could not be carried out
  2    what was asked for was not usable
  3    finished, but something it was asked to cover was not covered
  4    a comparison found changes (zond diff only)
  130  interrupted with Ctrl-C

Finding nothing is not a failure. 3 is the one worth knowing about: the run came
back narrower than what was asked for: a budget ran out, or something it was
asked about was left undecided.
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

    /// A topic and a command share one namespace, `zond help NAME`, so a topic
    /// named like a command would hide that command's help.
    #[test]
    fn no_topic_is_named_like_a_command() {
        use clap::CommandFactory;

        let command = crate::cli::Cli::command();
        for topic in TOPICS {
            assert!(
                command.find_subcommand(topic.name).is_none(),
                "{} is a command and a topic",
                topic.name
            );
        }
    }
}
