// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The command line
//!
//! The grammar, and the translation of it into what the engine takes.
//!
//! Both halves are here on purpose: a flag exists to change a scan, and the
//! place it changes one is [`EngineArgs::apply_to`]. Splitting them means every
//! new flag is declared in one place and forgotten in another.
//!
//! Both subcommands flatten the same [`EngineArgs`], so a setting they share is
//! declared once and cannot drift apart.

use clap::{ArgAction, Args, Parser, Subcommand};

use zond_engine::PortSet;
use zond_engine::ZondConfig;
use zond_engine::config::{OsDetection, ScanEffort, SendMode, ServiceDetection};
use zond_engine::model::technique::TcpScanTechnique;

use crate::diagnostics::Verbosity;
use crate::render::style::ColourChoice;
use crate::settings::Identity;
use crate::settings::Presentation;

/// The `zond` command line.
#[derive(Debug, Parser)]
#[command(
    name = "zond",
    version,
    about = "Find what is on a network.",
    long_about = "Find what is on a network.\n\n\
        Zond discovers which hosts on a network are alive. Discovery uses ARP \
        and ICMPv6 on the local segment and raw TCP elsewhere, which needs root; \
        without it the scan falls back to ordinary TCP connect attempts and says \
        so.",
    propagate_version = true,
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    /// How much to say while running.
    #[command(flatten)]
    pub output: OutputArgs,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// What `zond` was asked to do.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Find which hosts on a network are alive.
    #[command(visible_alias = "d")]
    Discover(DiscoverArgs),

    /// Find which ports are open on a network's hosts.
    #[command(visible_alias = "s")]
    Scan(ScanArgs),

    /// Look at the scans this machine has a record of.
    #[command(visible_alias = "j")]
    Journal(JournalArgs),

    /// Show what changed between two scans.
    Diff(DiffArgs),

    /// Fold several scans into one report.
    Merge(MergeArgs),

    /// Print a scan that is already written down.
    Read(ReadArgs),
}

/// Arguments to `zond read`.
#[derive(Debug, Args)]
#[command(after_help = read_help())]
pub(crate) struct ReadArgs {
    /// The scan to print: a file, or a record as `zond journal` lists them.
    ///
    /// Named the way either side of a comparison is. A name that is a file on
    /// disk is read as one, taking this engine's JSON or nmap's XML from its
    /// extension; anything else is taken for a record id, which may be shortened
    /// to any prefix that names only one, or `latest`.
    #[arg(value_name = "SCAN")]
    pub source: String,

    /// Where to write it, instead of the terminal.
    #[command(flatten)]
    pub export: ExportArgs,
}

/// What `zond read --help` ends with.
fn read_help() -> String {
    "\
Examples:
  zond read latest              print what the last scan found
  zond read merged.json         a folded report, and the documents it came from
  zond read theirs.xml          an nmap file, drawn the way this tool draws one
  zond read q1.xml -o q1.json   convert, since the writers are already there

Nothing is probed:
  Every one of these is already written down. A scan still being recorded prints
  what it has committed so far, which is a little behind what it has found.

Where it goes:
  The terminal, unless -o names a file, and then only the file. A scan prints as
  well as writes because you are watching it happen; nobody watches a document
  being read.

A folded report says what went into it:
  `zond merge` writes the name of every document it folds into the report, and
  those names survive being exported and folded again. Reading one back is what
  shows them."
        .to_string()
}

/// Arguments to `zond merge`.
#[derive(Debug, Args)]
#[command(after_help = merge_help())]
pub(crate) struct MergeArgs {
    /// The scans to fold together: files, or records as `zond journal` lists
    /// them.
    ///
    /// Named the same way either side of a comparison is. A name that is a file
    /// on disk is read as one, taking this engine's JSON or nmap's XML from its
    /// extension; anything else is taken for a record id, which may be shortened
    /// to any prefix that names only one, or `latest`.
    ///
    /// **The order they are given in does not matter.** A fold is ordered by
    /// each document's own clock, so there is no way to hand them over
    /// backwards.
    #[arg(value_name = "SCAN", num_args = 1.., required = true)]
    pub sources: Vec<String>,

    /// What makes two records the same host.
    ///
    /// `any` by default, which folds a machine whose primary address was
    /// re-picked between scans into one host. `hardware` follows one across a
    /// DHCP lease, and is what a segment with phones on it wants. `primary`
    /// treats the address itself as the thing being recorded, which is what
    /// folding scans of a public range means.
    ///
    /// [possible values: any, hardware, primary]
    #[arg(long, value_name = "HOW")]
    pub identity: Option<Identity>,

    /// Where to write the merged report, instead of the terminal.
    #[command(flatten)]
    pub export: ExportArgs,
}

/// What `zond merge --help` ends with.
fn merge_help() -> String {
    "\
Examples:
  zond merge chunk*.json           a range scanned in pieces, put back together
  zond merge q1.xml q2.xml q3.xml  a quarter of nmap files, neither written by zond
  zond merge baseline.json latest  an archived report and tonight's scan

What a merge answers:
  What is out there, given everything you know. Sources are folded oldest to
  newest, and where a newer one states something it wins. Where it says nothing
  the older answer stands, because absence is not a claim: a host missing from
  tonight's scan is not evidence the host went away.

  For what changed rather than what is there, use `zond diff`.

Fold everything at once:
  Give every document to one command. Merging in rounds folds each new source
  against a report already carrying an older source's clock, so a verdict the
  new one should have overturned survives it. `zond merge a b c` is not the same
  as merging a and b and then folding in c.

Where it goes:
  The terminal, unless -o names a file, and then only the file. Nobody is
  watching a merge happen the way they watch a scan, so naming a file is saying
  where you want this rather than asking for a copy."
        .to_string()
}

/// Arguments to `zond diff`.
#[derive(Debug, Args)]
#[command(after_help = diff_help())]
pub(crate) struct DiffArgs {
    /// The earlier scan: a file, or a record as `zond journal` lists them.
    ///
    /// A name that is a file on disk is read as one, taking this engine's JSON
    /// or nmap's XML from its extension. Anything else is taken for a record id,
    /// which may be shortened to any prefix that names only one, or `latest`.
    #[arg(value_name = "BEFORE")]
    pub before: String,

    /// The later scan, named the same way.
    #[arg(value_name = "AFTER")]
    pub after: String,

    /// What makes two records the same host.
    ///
    /// `any` by default, which follows a machine whose primary address was
    /// re-picked between scans. `hardware` follows one across a DHCP lease, and
    /// is what a segment with phones on it wants. `primary` treats the address
    /// itself as the thing being watched, which is what an external scan of a
    /// public range means.
    ///
    /// [possible values: any, hardware, primary]
    #[arg(long, value_name = "HOW")]
    pub identity: Option<Identity>,

    /// Write the comparison to FILE instead of printing it.
    ///
    /// The extension decides. `.json` is the document a pipeline ingests, every
    /// change as one fact with a field on each saying whether the other scan was
    /// known to have looked. `.html` is one self-contained page for whoever
    /// reads the nightly mail: no script, no request to anywhere, and it prints.
    /// Give the flag twice for both.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Vec<std::path::PathBuf>,
}

/// What `zond diff --help` ends with.
fn diff_help() -> String {
    "\
Examples:
  zond diff latest 20aa1f3c        two records on this machine
  zond diff baseline.json latest   an archived report against tonight's scan
  zond diff q1.xml q2.xml          two nmap files, neither written by zond

Identity:
  Two scans of a network with DHCP on it will key the same machine under
  different addresses. --identity hardware follows it by its hardware address,
  which does not move when the lease does.

Exit status:
  0  nothing changed
  4  something changed

  Only a change the other scan is known to have looked for counts towards 4. A
  scan of new ground turns up hosts nobody had checked before, and those are
  reported without being treated as findings about the network."
        .to_string()
}

/// Arguments to `zond journal`.
#[derive(Debug, Args)]
pub(crate) struct JournalArgs {
    /// What to do with them. Lists them when nothing is said.
    #[command(subcommand)]
    pub what: Option<JournalCommand>,

    /// How much of the listing to show at once.
    #[command(flatten)]
    pub page: PageArgs,
}

/// Where a run writes its report, besides the terminal.
///
/// Repeatable, so one run can leave a JSON document for a pipeline and an HTML
/// page for the person who asked for the scan. See [`export`](crate::export)
/// for how a destination becomes a format, and [`nmap`](crate::nmap) for the
/// spellings borrowed from there.
///
/// Besides the terminal for a scan, and *instead of* it for
/// [`Read`](Command::Read) and [`Merge`](Command::Merge). The difference is
/// whether anybody is watching the run that produces the report.
#[derive(Debug, Args, Default)]
pub(crate) struct ExportArgs {
    /// Write the report to FILE, in the format its extension names.
    ///
    /// `report.json`, `report.jsonl`, `report.csv`, `report.html` and
    /// `report.xml`, the last being nmap's XML, for the tools that already
    /// ingest it. Give the flag more than once for more than one file.
    ///
    /// An extension naming no format is refused rather than guessed at.
    #[arg(long, short = 'o', value_name = "FILE", action = ArgAction::Append)]
    pub output: Vec<std::path::PathBuf>,

    /// Write the report to FILE in the format you name: `--output-as json=out`.
    ///
    /// For a destination whose extension would say the wrong thing, or nothing
    /// at all. Repeatable, like `--output`.
    #[arg(long = "output-as", value_name = "FORMAT=FILE", action = ArgAction::Append)]
    pub output_as: Vec<crate::export::FormatAndPath>,

    /// Write every format this build can produce, each named after BASE.
    ///
    /// `--output-all engagement` leaves `engagement.json`, `engagement.csv`,
    /// and one of each of the rest.
    #[arg(long = "output-all", value_name = "BASE")]
    pub output_all: Option<std::path::PathBuf>,
}

/// How much of a listing to show at once.
///
/// **Not global.** They belong to listing, and the sibling subcommands already
/// spell two of these letters differently: `prune -n` is a dry run, and
/// `prune --all` deletes every record where here it shows them. A flag that
/// meant "show everything" on one subcommand and "delete everything" on the
/// next is not a convenience.
///
/// So the set is attached in the two places a listing happens: `zond journal`,
/// which lists when nothing else is asked, and `zond journal list`.
#[derive(Debug, Args, Default)]
pub(crate) struct PageArgs {
    /// How many records to list at once.
    ///
    /// Ten by default, newest first, which is the handful anybody is usually
    /// looking for. `page_size` in `cli.toml` changes that for every run, and
    /// 0 means no limit.
    #[arg(long, short = 'n', value_name = "COUNT", conflicts_with = "all")]
    pub limit: Option<usize>,

    /// Which page of them, counting from one.
    ///
    /// Pages are as long as `--limit`, so `--page 3` is the third ten unless
    /// you said otherwise.
    #[arg(long, value_name = "N", conflicts_with = "all")]
    pub page: Option<usize>,

    /// List every record, however many there are.
    #[arg(long, short = 'a')]
    pub all: bool,
}

/// What `zond journal` was asked to do.
#[derive(Debug, Subcommand)]
pub(crate) enum JournalCommand {
    /// List every scan this machine has a record of, newest first.
    #[command(visible_alias = "ls")]
    List(PageArgs),

    /// Show one record's own details: where it is, how far it got, what is
    /// holding it.
    ///
    /// The record, not the findings. `zond read <ID>` prints what the scan
    /// found.
    Show {
        /// Which one, as `zond journal` lists it.
        #[arg(value_name = "ID")]
        id: String,
    },

    /// Delete records: the ones named, or the ones no longer worth keeping.
    ///
    /// A scan that is running is never deleted. Named without any flag, given
    /// records go whatever their age. With no arguments at all, a finished scan
    /// is kept for a month and an unfinished one indefinitely, since an
    /// unfinished scan is the only copy of work you may still mean to continue.
    #[command(visible_alias = "rm")]
    Prune {
        /// Which to delete, as `zond journal` lists them.
        ///
        /// An id may be shortened to any prefix that names only one scan.
        #[arg(value_name = "ID", conflicts_with_all = ["all", "completed", "older_than"])]
        ids: Vec<String>,

        /// Delete every record, finished or not.
        #[arg(long, conflicts_with_all = ["completed", "older_than"])]
        all: bool,

        /// Delete every finished record, whatever its age.
        #[arg(long, conflicts_with = "older_than")]
        completed: bool,

        /// Delete finished records older than this, as `30d`, `12h` or `90m`.
        #[arg(long, value_name = "AGE", value_parser = age)]
        older_than: Option<std::time::Duration>,

        /// Say what would go without deleting anything.
        #[arg(long, short = 'n')]
        dry_run: bool,
    },
}

/// Parses an age as a count and a unit: `30d`, `12h`, `90m`, `45s`.
///
/// Written out rather than pulled in, on the same reasoning the engine gives for
/// its own small parsers: a dependency for four suffixes costs more than it
/// saves. Bare digits are refused, because `--older-than 30` reads as thirty of
/// something and there is no honest way to guess which.
fn age(input: &str) -> Result<std::time::Duration, String> {
    let (count, unit) = input.split_at(
        input
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("'{input}' has no unit; try '{input}d' for days"))?,
    );

    let count: u64 = count
        .parse()
        .map_err(|_| format!("'{input}' does not start with a number"))?;

    let seconds = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(format!("'{unit}' is not one of s, m, h, d")),
    };

    Ok(std::time::Duration::from_secs(count * seconds))
}

/// Arguments to `zond discover`.
#[derive(Debug, Args)]
#[command(after_help = discover_help())]
pub(crate) struct DiscoverArgs {
    /// What to scan: an address, a range, a CIDR block, a hostname, or `lan`.
    ///
    /// Several may be given, and each may itself be a comma-separated list.
    ///
    /// Not needed with `--resume`, which sweeps what the recorded run was
    /// sweeping.
    #[arg(value_name = "TARGET", required_unless_present = "resume", num_args = 1..)]
    pub targets: Vec<String>,

    /// Do not write down how far this sweep gets.
    ///
    /// Every sweep is recorded by default, because the moment you want to
    /// continue one is after it was cut short, and a flag you would have had to
    /// pass beforehand is a flag you did not pass. `zond journal` lists what is
    /// on record, `zond read <ID>` prints one back, and `zond journal prune`
    /// clears them out.
    ///
    /// A record holds the addresses you swept and what answered. It is written
    /// under your own home, readable only by you. This turns that off for one
    /// run; `journal = false` in `cli.toml` turns it off for all of them.
    #[arg(long, conflicts_with = "resume")]
    pub no_journal: bool,

    /// Continue the sweep with this id, asking only about what it did not settle.
    ///
    /// The addresses come from the record, so there is nothing to type but the
    /// id. An address that answered, or that was asked as many times as it was
    /// going to be, is not asked again; one whose probes were cut off mid-way is.
    ///
    /// `zond journal` lists what can be continued. A record's scope is fixed,
    /// so `--exclude` cannot be added to one: withholding an address the record
    /// counted would renumber every address after it.
    #[arg(long, value_name = "ID", conflicts_with_all = ["targets", "exclude"])]
    pub resume: Option<String>,

    /// Settings that change what the scan puts on the wire.
    #[command(flatten)]
    pub engine: EngineArgs,

    /// Where to write the report, besides the terminal.
    #[command(flatten)]
    pub export: ExportArgs,
}

/// Arguments to `zond scan`.
#[derive(Debug, Args)]
#[command(after_help = scan_help())]
pub(crate) struct ScanArgs {
    /// What to scan: an address, a range, a CIDR block, a hostname, or `lan`.
    ///
    /// A target may carry its own ports, as in `10.0.0.1:8080` or
    /// `[2001:db8::1]:443`, and keeps them. `--ports` supplies the rest.
    ///
    /// Not needed with `--resume`, which scans what the recorded scan was
    /// scanning. Given anyway, they must describe the same scan, or the resume
    /// is refused rather than continuing something else.
    #[arg(value_name = "TARGET", required_unless_present = "resume", num_args = 1..)]
    pub targets: Vec<String>,

    /// Which ports to probe: `22,80,443`, `1-1024`, `u:53` for UDP.
    ///
    /// A range may leave off either end. `-p-` is every port there is, `-p-1024`
    /// is everything up to 1024, and `-p9000-` is everything from it. The forms
    /// compose with the rest: `-p 22,u:-,9000-`.
    ///
    /// Defaults to `default_ports` in the settings file, and to the thousand
    /// ports most likely to be listening when that says nothing either.
    #[arg(
        short = 'p',
        long,
        value_name = "PORTS",
        conflicts_with = "top_ports",
        // `-p-` is the spelling everybody arrives with, and without this clap
        // reads the `-` as the start of another flag and refuses it.
        //
        // It costs one thing, and only on a typo: `-p` with its value left off
        // now swallows whatever follows instead of reporting a missing value.
        // What that produces is still an error naming the swallowed token,
        // "malformed port specification: '--service-detection'", which says what
        // happened plainly enough. The alternative is not supporting the
        // spelling at all.
        allow_hyphen_values = true
    )]
    pub ports: Option<PortSet>,

    /// Probe the N TCP ports most likely to be listening.
    ///
    /// The engine ranks them, most likely first, and this takes the first N.
    /// `--top-ports 100` is a quick pass over what answers on nearly everything;
    /// the default without any port flag is the whole ranked list, which is a
    /// thousand.
    ///
    /// TCP only, because a UDP port costs far more to classify and far more of
    /// them come back open|filtered whatever is done. Name UDP ports with
    /// `-p u:53,u:161` when you want them.
    #[arg(long, value_name = "N", conflicts_with = "ports")]
    pub top_ports: Option<usize>,

    /// Do not write down how far this scan gets.
    ///
    /// Every scan is recorded by default, because the moment you want to
    /// continue one is after it was cut short, and a flag you would have had to
    /// pass beforehand is a flag you did not pass. `zond journal` lists what is
    /// on record and prunes it.
    ///
    /// A record holds the addresses you scanned and what answered. It is written
    /// under your own home, readable only by you. This turns that off for one
    /// run; `journal = false` in `cli.toml` turns it off for all of them.
    #[arg(long, conflicts_with = "resume")]
    pub no_journal: bool,

    /// Continue the scan with this id, asking only about what it did not settle.
    ///
    /// The targets and ports come from the record, so there is nothing to type
    /// but the id. Naming them anyway is allowed and checked: a position in a
    /// record means nothing against a different plan, so a mismatch is refused
    /// rather than quietly scanning something else.
    ///
    /// `zond journal` lists what can be continued. A record's scope is fixed,
    /// so `--exclude` cannot be added to one: withholding an address the record
    /// counted would renumber every target after it.
    #[arg(long, value_name = "ID", conflicts_with = "exclude")]
    pub resume: Option<String>,

    /// Scan every target without checking first that anything is there.
    ///
    /// A scan normally probes each address for liveness, using the same probes
    /// `zond discover` sends against those addresses and no others, then skips
    /// the ones that answer nothing. An address nothing lives at costs a probe
    /// per port to learn that. This spends them anyway.
    ///
    /// For a host that is up and answering no knock: one behind a firewall that
    /// drops ICMP, and has nothing on the ports discovery tries.
    #[arg(long)]
    pub assume_up: bool,

    /// Which TCP segment a probe carries, and so what its answers mean.
    ///
    /// Only `syn` identifies an open port positively, and only `syn` has an
    /// unprivileged fallback; the rest need root and are refused without it
    /// rather than quietly substituted.
    ///
    /// [possible values: syn, fin, null, xmas, maimon, ack]
    #[arg(long, value_name = "TECHNIQUE")]
    pub tcp_technique: Option<TcpScanTechnique>,

    /// Settings that change what the scan puts on the wire.
    #[command(flatten)]
    pub engine: EngineArgs,

    /// Where to write the report, besides the terminal.
    #[command(flatten)]
    pub export: ExportArgs,
}

impl ScanArgs {
    /// Lays these flags over a configuration the settings files produced.
    pub(crate) fn apply_to(&self, config: &mut ZondConfig) {
        self.engine.apply_to(config);

        if self.assume_up {
            config.assume_up = true;
        }
        if let Some(technique) = self.tcp_technique {
            config.tcp_technique = technique;
        }
    }
}

/// The target grammar, shown under both subcommands.
///
/// Written out rather than left to the engine's documentation, because a person
/// who has just mistyped a range is not going to go and read a crate's docs, and
/// the shortened range in particular is not a form anybody guesses.
const TARGET_FORMS: &str = "\
Target forms:
  192.168.0.1        one address
  192.168.0.1-50     a range; the end continues the start's octets
  192.168.0.0/24     a CIDR block
  2001:db8::1        one IPv6 address
  2001:db8::/120     an IPv6 prefix
  fe80::1%en0        a link-local address, on a named interface
  one.one.one.one    a hostname, resolved before the scan (unless --no-dns)
  lan                this host's own segment

--exclude takes the same forms, and nothing named there is probed or reported.
";

/// How a run is stopped, shown under both subcommands.
const STOPPING: &str = "
Stopping a run:
  q, or Ctrl-C, stops the scan and reports what was found so far. Either again
  leaves without waiting for the probes still in flight. Reading a keypress
  needs a terminal; in a pipe or a script, Ctrl-C is the one that works.
";

/// The output-format help both scanning subcommands carry.
///
/// Shared rather than written twice: they take the same flags, and two copies
/// of a format list is two lists to keep in step.
const OUTPUT_FORMS: &str = "
Writing the report to a file:
  -o report.json          the extension names the format
  -o report.html -o r.csv  more than one file, one flag each
  --output-as json=out     when the extension would say the wrong thing
  --output-all engagement  every format, each under its own extension

Formats: json, jsonl, csv, html, and xml, the last being nmap's, for the tools
that already ingest it. Nmap's own spellings work too: -oX, -oJ, -oC, -oH, -oL
and -oA. A file is written as well as the terminal output, never instead of it,
and a destination that names no format is refused before the scan starts rather
than after it.
";

/// What is shown under `zond discover --help`, below the flags.
///
/// Assembled rather than written twice: the two subcommands share a target
/// grammar and differ in their examples, and one constant serving both is how
/// `zond discover --help` came to advertise a flag only `zond scan` has.
fn discover_help() -> String {
    [
        TARGET_FORMS,
        "
Examples:
  sudo zond discover 192.168.0.0/24
  sudo zond d 192.168.0.1-50
  sudo zond d lan
  sudo zond d 2001:db8::1,2001:db8::2
  sudo zond d one.one.one.one
  sudo zond d 10.0.0.0/16 --exclude 10.0.5.0/24
  sudo zond d lan -o hosts.json
",
        OUTPUT_FORMS,
        STOPPING,
        "
Discovery uses raw sockets when it can. Without root it falls back to TCP
connect attempts, which find fewer hosts; the summary says which one ran.",
    ]
    .concat()
}

/// What is shown under `zond scan --help`, below the flags.
fn scan_help() -> String {
    [
        TARGET_FORMS,
        "
Examples:
  sudo zond scan 192.168.0.150 -p 22,80,443
  sudo zond s 192.168.0.0/24 --top-ports 100
  sudo zond s 10.0.0.1:8080 lan -p 80,443
  sudo zond s 2001:db8::1 -p u:53
  sudo zond s 192.168.0.150 -p-            every port there is
  sudo zond s 192.168.0.150 -p 8000-       every port from 8000 up
  sudo zond s 10.0.0.0/24 --exclude 10.0.0.7 -p 22
  sudo zond s 192.168.0.150 -p 443 --traceroute
  sudo zond s 10.0.0.0/24 -p 22,443 -oA engagement

Given no port flag, a scan probes the thousand TCP ports most likely to be
listening, ranked by the engine rather than taken as a range. That is a
deliberate choice over 1-1024: most of what a machine listens on today is above
it, and much of what is below it has not been deployed this century.

A scan checks each target is there before probing its ports, and skips the ones
that answer nothing. --assume-up scans them anyway.
",
        OUTPUT_FORMS,
        STOPPING,
        "
Port scanning uses raw SYN probes when it can. Without root every port is tested
by completing a connection, which is slower and more visible; the summary says
which one ran.",
    ]
    .concat()
}

/// The settings that change what a scan does, as opposed to how it is shown.
///
/// Flattened into every subcommand that runs the engine, so a setting means the
/// same thing wherever it is written. The split follows the engine's own:
/// [`ZondConfig`] holds only what changes packets or timing, and anything about
/// rendering belongs to [`OutputArgs`] instead.
#[derive(Debug, Args)]
#[command(next_help_heading = "Scan settings")]
// A command-line flag *is* a bool, and there are more than three of them
// because this engine has more than three switches. The lint is aimed at a
// domain type whose bools should have been an enum; here they are independent
// options a caller sets in any combination, and clap derives the parser from
// exactly these fields.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct EngineArgs {
    /// Addresses this run may not probe, whatever the targets say.
    ///
    /// The same grammar targets take, meaning an address, a range, a CIDR
    /// block, a hostname, or `lan`, so a scope document transcribes the same way
    /// on either side. Repeat the flag, or write a comma-separated list.
    ///
    /// Nothing is addressed to an excluded host and nothing about one is
    /// reported, including a neighbour a segment sweep would otherwise learn
    /// about from an ARP reply. What it cannot promise is that an excluded
    /// machine on your own segment never sees a broadcast probe. Do not sweep
    /// the segment if that matters.
    ///
    /// Adds to `exclude` in engine.toml rather than replacing it.
    #[arg(long, value_name = "TARGET", action = ArgAction::Append)]
    pub exclude: Vec<String>,

    /// Send no DNS traffic, and report hosts by address alone.
    ///
    /// Discovered hosts are normally resolved to names in the background. A
    /// lookup goes to a resolver somebody operates, so on an engagement it can
    /// be the thing that announces the scan. A hostname written as a target is
    /// refused rather than dropped.
    #[arg(short = 'n', long)]
    pub no_dns: bool,

    /// Mask hostnames, hardware addresses and IPv6 host parts in the output.
    ///
    /// For results going somewhere that needs the shape of a network without
    /// knowing which device is which: a client, an auditor, a screenshot in an
    /// issue. The scan still finds everything, and only what leaves this process
    /// is masked.
    #[arg(long)]
    pub redact: bool,

    /// How hard the scan tries before it accepts silence as an answer.
    ///
    /// [possible values: single, fast, balanced, thorough]
    #[arg(long, value_name = "LEVEL")]
    pub effort: Option<ScanEffort>,

    /// Replace the attempt budget outright, whatever --effort implies.
    ///
    /// 1 disables retransmission.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..))]
    pub max_attempts: Option<u8>,

    /// Multiply how long the scan is willing to wait.
    ///
    /// Does not touch the shortest timeout a protocol allows. That floor is not
    /// a preference, it is what the protocol costs.
    #[arg(long, value_name = "FACTOR", value_parser = positive)]
    pub timeout_scale: Option<f64>,

    /// Spend the full probe budget on hosts that answer nothing at all.
    ///
    /// Thorough and expensive. Normally a silent host has its remaining budget
    /// cut so the scan can spend it somewhere that is answering.
    #[arg(long)]
    pub no_dampen: bool,

    /// The fastest discovery may put probes on the wire, in probes per second.
    ///
    /// A coverage control before it is a politeness one: on a policed path a
    /// burst loses most of its first attempt, so a lower rate buys coverage.
    #[arg(long, value_name = "PPS", value_parser = clap::value_parser!(u32).range(1..))]
    pub max_probe_rate: Option<u32>,

    /// How raw probes are placed on the wire.
    ///
    /// [possible values: auto, raw_socket, ethernet]
    #[arg(long, value_name = "MODE")]
    pub send_mode: Option<SendMode>,

    /// How far to go identifying the system behind each host.
    ///
    /// `passive` sends nothing of its own. `active` and above send probes, and
    /// have to be asked for.
    ///
    /// [possible values: off, passive, active, aggressive]
    #[arg(long, value_name = "LEVEL")]
    pub os_detection: Option<OsDetection>,

    /// Identify the system behind each host as thoroughly as this engine can.
    ///
    /// Shorthand for `--os-detection aggressive`: a series of SYNs to every host
    /// with a TCP port, a ping to every host without, and twice the samples
    /// `active` takes. Reach for it when the machine's operating system is
    /// already known and the point is to measure the stack.
    ///
    /// A separate flag rather than an optional value on `--os-detection`. An
    /// option that may or may not take a value would read
    /// `zond scan -O 192.0.2.1` as a level of `192.0.2.1` and scan nothing.
    #[arg(short = 'O', long, conflicts_with = "os_detection")]
    pub os_aggressive: bool,

    /// How far to go to identify what is listening behind each open port.
    ///
    /// `off` never connects: ports come back with a state and whatever name
    /// their number implies. It is the fastest, and the only level that leaves
    /// no trace in the target's application logs. `banner` connects and listens
    /// without sending, which is everything a service that greets on connect was
    /// going to say anyway. Reach for it with equipment that must not be sent
    /// anything it did not expect. `probe`, the default, also asks: each port
    /// gets the requests its service registered, and a port nothing recognises
    /// gets the one generic request worth asking of anything.
    ///
    /// Turning it down does not make an unknown port faster to scan. Asking is
    /// how a port is finished with quickly, and the alternative is waiting out a
    /// greeting that never comes.
    ///
    /// [possible values: off, banner, probe]
    #[arg(long, value_name = "LEVEL")]
    pub service_detection: Option<ServiceDetection>,

    /// Report port states and no service detail.
    ///
    /// Shorthand for `--service-detection off`. A separate flag because it is
    /// the one level people reach for by name: the scan that answers "what is
    /// open" without opening a connection to find out what is behind it.
    #[arg(long, conflicts_with = "service_detection")]
    pub no_service_detection: bool,

    /// Measure the route to each host that answered.
    ///
    /// Runs last, after the ports are known, because what reaches a host decides
    /// what its trace is made of. A host with an open TCP port is traced with
    /// SYNs to that port, which crosses filters no ping survives, and every
    /// other host with ICMP echoes. `zond scan` therefore traces better than
    /// `zond discover` does.
    ///
    /// Only hosts that answered are traced. A path is measured backwards from
    /// its far end and the far end's distance is read out of a reply, so a host
    /// that answered nothing has no path to measure.
    ///
    /// Needs root, like every other probe built by hand here.
    #[arg(long)]
    pub traceroute: bool,

    /// Use a named profile from the engine's settings file.
    ///
    /// Profiles are defined in `engine.toml` and layer on top of its defaults.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,
}

/// Reads a positive, finite multiplier.
///
/// Zero asks the scan to wait no time at all and a negative asks for less than
/// that. Refused here rather than discovered as a scan that finds nothing.
fn positive(text: &str) -> Result<f64, String> {
    let value: f64 = text
        .parse()
        .map_err(|_| format!("'{text}' is not a number"))?;

    if value.is_finite() && value > 0.0 {
        Ok(value)
    } else {
        Err(format!("'{text}' must be greater than zero"))
    }
}

impl EngineArgs {
    /// Lays these flags over a configuration the settings files produced.
    ///
    /// The last layer, and it only speaks about what was actually written: every
    /// flag is an `Option`, or a `bool` whose absence means nothing rather than
    /// `false`. An absent flag must not cancel a setting from a file, which is
    /// why the dampening flag is `--no-dampen` and not `--dampen`.
    ///
    /// [`segment_sweep`](ZondConfig::segment_sweep) is neither a flag nor a file
    /// entry. It comes from the targets, via
    /// [`Targets::apply_to`](crate::target::Targets::apply_to).
    ///
    /// **`--exclude` is not applied here either**, and it is the one flag that
    /// is not. Its values are addresses in the same grammar targets are written
    /// in, so turning them into a policy means resolving names and reading this
    /// host's interface table. That is asynchronous work against a resolver
    /// whose existence depends on the `no_dns` these very layers are still
    /// settling. It is resolved beside the targets in [`crate::target`] and
    /// written by the same `apply_to`, so the two halves of one grammar are
    /// parsed by one module rather than by two that could disagree.
    pub(crate) fn apply_to(&self, config: &mut ZondConfig) {
        if self.no_dns {
            config.no_dns = true;
        }
        if self.redact {
            config.redact = true;
        }
        if self.no_dampen {
            config.retry.dampen_silent_hosts = false;
        }
        if self.traceroute {
            config.traceroute = true;
        }
        if let Some(effort) = self.effort {
            config.retry.effort = effort;
        }
        if let Some(attempts) = self.max_attempts {
            config.retry.max_attempts = Some(attempts);
        }
        if let Some(scale) = self.timeout_scale {
            config.retry.timeout_scale = Some(scale);
        }
        if let Some(rate) = self.max_probe_rate {
            config.max_probe_rate = Some(rate);
        }
        if let Some(mode) = self.send_mode {
            config.send_mode = mode;
        }
        // Mutually exclusive at the parser, so there is no precedence to settle
        // here: a caller who writes both is told, rather than served whichever
        // this happens to check second.
        if self.os_aggressive {
            config.os_detection = OsDetection::Aggressive;
        }
        if self.no_service_detection {
            config.service_detection = ServiceDetection::Off;
        }
        if let Some(detection) = self.service_detection {
            config.service_detection = detection;
        }
        if let Some(detection) = self.os_detection {
            config.os_detection = detection;
        }
    }
}

/// How much a run says about itself while it happens.
///
/// Global, so `zond -v discover lan` and `zond discover -v lan` mean the same
/// thing.
#[derive(Debug, Args)]
#[command(next_help_heading = "Output")]
pub(crate) struct OutputArgs {
    /// Show more detail. Repeat for more still.
    #[arg(short = 'v', long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Show nothing but errors and the hosts found.
    #[arg(short = 'q', long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// How to draw this run. Overrides the settings file for one invocation.
    ///
    /// `fancy` is a numbered tree per host and the default; `minimal` is the
    /// terse tagged form; `pipe` is tab-separated records for a program.
    ///
    /// [possible values: pipe, minimal, fancy]
    #[arg(long, value_name = "MODE", global = true)]
    pub presentation: Option<Presentation>,

    /// Shorthand for `--presentation pipe`.
    ///
    /// Tab-separated records with every field a scan established, no padding and
    /// no heading.
    #[arg(long, global = true, conflicts_with = "presentation")]
    pub pipe: bool,

    /// Whether to colour the output.
    ///
    /// `auto` colours a terminal and leaves a redirected stream alone, reading
    /// `NO_COLOR`, `CLICOLOR_FORCE` and `TERM` the way every other tool that
    /// reads them does. The two streams are asked separately, so
    /// `zond discover lan | less` keeps its commentary coloured while the
    /// records go out plain.
    ///
    /// Box drawing is not on this switch. A file holds a box-drawing character
    /// perfectly well, so only `TERM=dumb` takes the tree away.
    ///
    /// [possible values: auto, always, never]
    #[arg(long = "colour", alias = "color", value_name = "WHEN", global = true)]
    pub colour: Option<ColourChoice>,
}

impl OutputArgs {
    /// The verbosity these arguments ask for.
    #[must_use]
    pub(crate) fn verbosity(&self) -> Verbosity {
        Verbosity::new(self.verbose, self.quiet)
    }

    /// The colour setting this run should use.
    ///
    /// The flag wins, then the file, then the built-in default, which is the
    /// order every other setting layers in.
    #[must_use]
    pub(crate) fn colour(&self, configured: Option<ColourChoice>) -> ColourChoice {
        self.colour.or(configured).unwrap_or_default()
    }

    /// The presentation to use, given what the settings files said.
    ///
    /// The flag wins, then the file, then the built-in default, which is the
    /// order every other setting layers in.
    #[must_use]
    pub(crate) fn presentation(&self, configured: Option<Presentation>) -> Presentation {
        if self.pipe {
            return Presentation::Pipe;
        }
        self.presentation.or(configured).unwrap_or_default()
    }
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
    use clap::CommandFactory;

    /// A clap derive can produce a definition that only panics at runtime: a
    /// duplicate id, or a conflict naming an argument that does not exist.
    #[test]
    fn the_command_definition_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn discover_accepts_its_short_alias_and_several_targets() {
        let cli = Cli::try_parse_from(["zond", "d", "10.0.0.1", "lan"]).expect("should parse");
        let Command::Discover(args) = cli.command else {
            panic!("d is the discover alias");
        };
        assert_eq!(args.targets, ["10.0.0.1", "lan"]);
    }

    #[test]
    fn verbosity_is_accepted_before_or_after_the_subcommand() {
        let before = Cli::try_parse_from(["zond", "-vv", "d", "lan"]).expect("should parse");
        let after = Cli::try_parse_from(["zond", "d", "-vv", "lan"]).expect("should parse");
        assert_eq!(before.output.verbose, 2);
        assert_eq!(after.output.verbose, 2);
    }

    #[test]
    fn quiet_and_verbose_together_are_refused() {
        assert!(Cli::try_parse_from(["zond", "-q", "-v", "d", "lan"]).is_err());
    }

    /// Flag over file over default, the order every setting layers in.
    #[test]
    fn the_presentation_flag_beats_the_settings_file() {
        let with_flag = Cli::try_parse_from(["zond", "--presentation", "minimal", "d", "lan"])
            .expect("should parse");
        assert_eq!(
            with_flag.output.presentation(Some(Presentation::Fancy)),
            Presentation::Minimal
        );

        let without = Cli::try_parse_from(["zond", "d", "lan"]).expect("should parse");
        assert_eq!(
            without.output.presentation(Some(Presentation::Fancy)),
            Presentation::Fancy,
            "with no flag the file decides"
        );
        assert_eq!(
            without.output.presentation(None),
            Presentation::default(),
            "with neither, the built-in default"
        );
    }

    #[test]
    fn the_pipe_shorthand_selects_the_pipe_mode() {
        let short = Cli::try_parse_from(["zond", "--pipe", "d", "lan"]).expect("should parse");
        assert_eq!(
            short.output.presentation(Some(Presentation::Fancy)),
            Presentation::Pipe
        );

        assert!(
            Cli::try_parse_from(["zond", "--pipe", "--presentation", "minimal", "d", "lan"])
                .is_err(),
            "two ways of naming a mode at once has no coherent meaning"
        );
    }

    #[test]
    fn an_absent_flag_does_not_overrule_the_settings_file() {
        let cli = Cli::try_parse_from(["zond", "d", "lan"]).expect("should parse");
        let Command::Discover(args) = cli.command else {
            panic!("d is the discover alias");
        };

        let mut from_file = ZondConfig {
            no_dns: true,
            ..ZondConfig::default()
        };
        args.engine.apply_to(&mut from_file);
        assert!(from_file.no_dns, "the flag was not given and said nothing");
    }

    #[test]
    fn the_flag_turns_the_setting_on_when_the_file_is_silent() {
        let cli = Cli::try_parse_from(["zond", "d", "-n", "lan"]).expect("should parse");
        let Command::Discover(args) = cli.command else {
            panic!("d is the discover alias");
        };

        let mut config = ZondConfig::default();
        args.engine.apply_to(&mut config);
        assert!(config.no_dns);
    }

    /// `-O` reaches the engine as the top level. The part worth pinning is that
    /// it does **not** eat the target that follows it.
    ///
    /// A flag rather than an option with an optional value, precisely so that
    /// cannot happen: turned into the latter, `zond scan -O 192.0.2.1` would
    /// read the address as a detection level, fail or scan nothing, and look
    /// like a bug somewhere else entirely.
    #[test]
    fn the_aggressive_shorthand_sets_the_level_without_eating_the_target() {
        let cli = Cli::try_parse_from(["zond", "s", "-O", "192.0.2.1"]).expect("should parse");
        let Command::Scan(args) = cli.command else {
            panic!("s is the scan alias");
        };
        assert_eq!(args.targets, ["192.0.2.1"]);

        let mut config = ZondConfig::default();
        args.engine.apply_to(&mut config);
        assert_eq!(config.os_detection, OsDetection::Aggressive);
    }

    /// Asking for both a shorthand and a level is asking for two different
    /// things at once. Refused at the parser, rather than served whichever the
    /// code happens to check second.
    #[test]
    fn the_shorthand_and_an_explicit_level_cannot_both_be_given() {
        assert!(
            Cli::try_parse_from(["zond", "s", "-O", "--os-detection", "passive", "192.0.2.1"])
                .is_err()
        );
    }

    #[test]
    fn a_target_is_required() {
        assert!(Cli::try_parse_from(["zond", "discover"]).is_err());
    }

    /// The comparison policy is parsed by the same `FromStr` a settings file
    /// uses, so what is checked here is only that the flag reaches the arguments.
    /// The spellings themselves are asserted beside
    /// [`Identity`](crate::settings::Identity).
    #[test]
    fn the_identity_flag_reaches_the_parsed_arguments() {
        let cli = Cli::try_parse_from(["zond", "diff", "--identity", "hardware", "a", "b"])
            .expect("should parse");
        let Command::Diff(args) = cli.command else {
            panic!("that is the diff command");
        };
        assert_eq!(args.identity, Some(Identity::Hardware));
    }
}
