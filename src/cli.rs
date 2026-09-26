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

use std::num::{NonZeroU8, NonZeroU32};

use zond_engine::config::{
    DetectionEnvelope, IdleScan, OsDetection, RAW_PRINT_PORTS, ScanEffort, ServiceDetection,
    TimeoutScale,
};
use zond_engine::evasion::EvasionProfile;
use zond_engine::model::mac::MacAddr;
use zond_engine::model::port::PortSetParseError;
use zond_engine::model::technique::{SctpScanTechnique, TcpScanTechnique};
use zond_engine::{PortSet, SendMode, ZondConfig};

use crate::diagnostics::Verbosity;
use crate::render::style::ColourChoice;
use crate::settings::Identity;
use crate::settings::Presentation;
use crate::settings::Risk;

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
///
// Each variant holds the arguments clap parsed for one subcommand, and a scan
// takes enough of them to make this enum a few hundred bytes wider than its
// smallest variant. It is built once, on the way out of `Cli::parse`, so boxing
// a variant would trade a heap allocation for a saving nothing measures.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Find which hosts on a network are alive.
    #[command(visible_alias = "d")]
    Discover(DiscoverArgs),

    /// Find which ports are open on a network's hosts.
    #[command(visible_alias = "s")]
    Scan(ScanArgs),

    /// Watch a link and record what it carries. Sends nothing.
    #[command(visible_alias = "l")]
    Listen(ListenArgs),

    /// Look at the scans this machine has a record of.
    #[command(visible_alias = "j")]
    Journal(JournalArgs),

    /// Show what changed between two scans.
    Diff(DiffArgs),

    /// Fold several scans into one report.
    Merge(MergeArgs),

    /// Print a scan that is already written down.
    Read(ReadArgs),

    /// Check the detections a scan would run, without scanning.
    Detections(DetectionsArgs),
}

impl Command {
    /// Whether this command watches the network rather than reading what an
    /// earlier one wrote down.
    ///
    /// The three that do produce a record of their own, and a record whose
    /// transcript does not say which build made it or when is one nobody can
    /// check a finding against a year later. The rest look things up: a stored
    /// scan carries its own provenance inside it, and a catalogue of detections
    /// is not a record of anything, so a build stamp on either is a line between
    /// the reader and what they asked for.
    pub(crate) const fn watches_the_network(&self) -> bool {
        matches!(
            self,
            Command::Discover(_) | Command::Scan(_) | Command::Listen(_)
        )
    }
}

/// Where a scan's detections come from, beyond the corpus this build ships.
///
/// Flattened into `zond scan`, which runs them, and into `zond detections`,
/// which compiles them and stops. Declared once so an author's `--detections`
/// means the same in the command that checks their work and the command that
/// uses it.
#[derive(Debug, Args)]
#[command(group = clap::ArgGroup::new("named_detections")
    .multiple(true)
    .args(["paths", "detections_bundle"]))]
pub(crate) struct DetectionArgs {
    /// A detection file, or a directory of them, to run alongside the built-in
    /// corpus. Repeatable.
    ///
    /// A detection is a TOML document: `[[step]]` for a declarative flow,
    /// `[compute]` for a sandboxed module, `[detection.host]` for a correlation
    /// across a host's ports. A module may keep its code in a sibling file and
    /// name it with `body`, and a directory is read one level deep for `.toml`
    /// and the bodies they reference.
    ///
    /// These are detections you wrote or chose. Somebody else's arrive as a
    /// signed bundle, through `--detections-bundle`.
    #[arg(long = "detections", value_name = "PATH", num_args = 1..)]
    pub paths: Vec<std::path::PathBuf>,

    /// A directory holding a signed detection bundle: somebody else's detections.
    ///
    /// The directory holds `manifest.toml`, the signature `manifest.toml.sig`
    /// beside it, and every source the manifest names. The manifest is checked
    /// against `--trust-key` before it is parsed and each source against the hash
    /// it records, so nothing is compiled that the key did not cover.
    #[arg(long, value_name = "DIR", requires = "trust_key")]
    pub detections_bundle: Option<std::path::PathBuf>,

    /// The public key a bundle must be signed by, as hex.
    ///
    /// Obtained from the publisher by some route other than the bundle. A
    /// signature names the key that made it, and trusting that one would accept
    /// anything anybody re-signed, so the key is named here or the bundle is not
    /// loaded.
    #[arg(long, value_name = "PATH")]
    pub trust_key: Option<std::path::PathBuf>,

    /// Run only the detections named here, leaving out the built-in corpus.
    ///
    /// For checking one detection against a host without the rest of the
    /// catalogue reporting alongside it.
    #[arg(long, requires = "named_detections")]
    pub only_named_detections: bool,
}

/// Arguments to `zond detections`.
#[derive(Debug, Args)]
#[command(after_help = detections_help())]
pub(crate) struct DetectionsArgs {
    /// What to do with them. Listing what a scan would run, when nothing says.
    #[command(subcommand)]
    pub action: Option<DetectionsAction>,

    /// Which detections to compile.
    #[command(flatten)]
    pub detections: DetectionArgs,

    /// Which of the compiled ones to list, and in what order.
    #[command(flatten)]
    pub catalogue: CatalogueArgs,

    /// How much of the listing to show at once.
    #[command(flatten)]
    pub page: PageArgs,
}

/// Which detections a listing shows, and in what order.
///
/// Attached to the listing rather than to [`DetectionArgs`], which every command
/// that runs detections flattens. Narrowing a catalogue is reading; narrowing
/// what a scan runs is `--detection` and the gates, and a flag that did both
/// would be a way to believe a check ran when nothing had compiled it.
///
/// Every condition here ANDs, and a repeatable one ORs within itself:
/// `--class exploit --class dos --service http` is the loud detections that
/// name HTTP.
#[derive(Debug, Args, Default)]
pub(crate) struct CatalogueArgs {
    /// List only detections whose id or title contains this text.
    ///
    /// Case-insensitive, and matched against both, so `--search redis` finds
    /// `redis-unauth` by the id you would name on a command line and finds
    /// anything whose title says Redis without you knowing what it is called.
    #[arg(long, value_name = "TEXT")]
    pub search: Option<String>,

    /// List only detections of this class. Repeatable.
    ///
    /// The class is what a detection will do to the target, and a corpus is read
    /// for that before anything else: `--class exploit --class dos` is the whole
    /// of what a scan will not run until an operator raises the ceiling.
    #[arg(long, value_name = "CLASS")]
    pub class: Vec<ClassName>,

    /// List only detections the named tier runs. Repeatable.
    ///
    /// `flow` for a declarative sequence of probes, `compute` for a sandboxed
    /// module, `host` for a correlation across a host's ports. Only `compute`
    /// records a tape, so this is also how to see what `replay` will have.
    #[arg(long, value_name = "TIER")]
    pub tier: Vec<TierName>,

    /// List only detections whose gate names this service.
    ///
    /// Matched against every service a gate names and against the protocol it
    /// asks the port to speak, so `--service http` finds the ones gated on the
    /// `http` service, the ones that accept it among several, and the ones
    /// written about anything speaking HTTP.
    #[arg(long, value_name = "NAME")]
    pub service: Option<String>,

    /// List only detections whose gate names this port.
    ///
    /// The number as the gate spells it, which is not every detection that can
    /// fire there: one gated on a service runs wherever that service was
    /// identified. Use it to find what a port number was written about.
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,

    /// The order to list them in. `id` by default.
    ///
    /// `class` is loudest first, the order the summary counts them in, so the
    /// detections an operator has to decide about come first. `tier` is the
    /// order the tiers run in, which is the order the corpus itself is in.
    #[arg(long, value_name = "FIELD", default_value = "id")]
    pub sort: SortBy,

    /// Reverse whatever order `--sort` asked for.
    #[arg(long)]
    pub reverse: bool,
}

/// A detection class, as a command line spells one.
///
/// Its own enum rather than the engine's `Class`, which is `non_exhaustive` and
/// carries no parser. What a build can be asked to filter on is the set of
/// classes it has a word for, and clap lists them in `--help` and completes
/// them in a shell for free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum ClassName {
    /// Sends nothing of its own; recombines ports the scan already settled.
    Derived,
    /// Reads bytes the scan already gathered.
    Passive,
    /// Speaks to the service, and asks it for nothing it would not tell anyone.
    ActiveBenign,
    /// Changes something on the target.
    ActiveMutating,
    /// Triggers a weakness to confirm it.
    Exploit,
    /// May take the service down.
    Dos,
}

impl ClassName {
    /// The engine's spelling of it.
    pub(crate) const fn class(self) -> zond_engine::detect::manifest::Class {
        use zond_engine::detect::manifest::Class;

        match self {
            ClassName::Derived => Class::Derived,
            ClassName::Passive => Class::Passive,
            ClassName::ActiveBenign => Class::ActiveBenign,
            ClassName::ActiveMutating => Class::ActiveMutating,
            ClassName::Exploit => Class::Exploit,
            ClassName::Dos => Class::Dos,
        }
    }
}

/// Which tier runs a detection, as a command line spells one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum TierName {
    /// A declarative sequence of probes and matches, carrying no code.
    Flow,
    /// A sandboxed module, reaching the network through granted verbs alone.
    Compute,
    /// A correlation across the ports of one host.
    Host,
}

impl TierName {
    /// The engine's spelling of it.
    pub(crate) const fn tier(self) -> zond_engine::detect::bundle::Tier {
        use zond_engine::detect::bundle::Tier;

        match self {
            TierName::Flow => Tier::Flow,
            TierName::Compute => Tier::Compute,
            TierName::Host => Tier::Host,
        }
    }
}

/// What a catalogue is ordered by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub(crate) enum SortBy {
    /// The id, alphabetically: the column the eye runs down.
    #[default]
    Id,
    /// The class, loudest first.
    Class,
    /// The tier, in the order the tiers run.
    Tier,
    /// The title, alphabetically.
    Title,
}

/// What `zond detections` was asked to do beyond listing.
///
/// The two halves of publishing a set for somebody else to run. Loading one is
/// `--detections-bundle`, a flag on a scan rather than a command, because
/// loading happens every run and publishing happens once.
#[derive(Debug, Subcommand)]
pub(crate) enum DetectionsAction {
    /// Run detections against one endpoint and print what they found.
    ///
    /// The author's inner loop: point a detection at a box, see whether it fires
    /// and what it saw, without waiting on a full scan. It scans the one endpoint,
    /// identifies the service its gate needs, and runs the detections at a raised
    /// ceiling, `exploit` by default, so a check written to confirm actually runs
    /// against the target you named. With `--detections` it runs your file alone;
    /// without, it runs the built-in corpus. Evidence is shown by default, since
    /// seeing what a detection decided on is the point.
    Test(TestArgs),

    /// Re-run a recorded scan's compute detections offline, to see what each saw.
    ///
    /// A compute detection reaches the network only through capabilities the scan
    /// recorded, so its run is a pure function of what those returned. Replaying
    /// the tape reproduces the finding with no target and no packet, which is the
    /// answer to "why did it fire" and the way to check one against the exact
    /// bytes it decided on. Findings print; a run that drew nothing is a line only
    /// under `-v`, the way a finding's evidence is.
    ///
    /// Only the compute tier records a tape. A flow (`redis-unauth`,
    /// `grafana-path-traversal`) runs live and leaves nothing to replay, so it
    /// does not appear here; `zond read` shows the findings of a whole scan. It
    /// re-runs against this build's shipped corpus, so a detection that has since
    /// changed or that came from `--detections` reports as unavailable rather than
    /// being reproduced by something else.
    Replay(ReplayArgs),

    /// Make a signing key, for publishing detections others will run.
    Keygen(KeygenArgs),

    /// Sign a directory of detections as a bundle others can load.
    Sign(SignArgs),
}

/// Arguments to `zond detections test`.
#[derive(Debug, Args)]
pub(crate) struct TestArgs {
    /// The endpoint to run the detections against, as `host:port`. An IPv6
    /// address is bracketed, `[::1]:443`. The host may be a name, which is
    /// resolved.
    ///
    /// Positional, the way `zond scan` and `zond read` name what they act on.
    #[arg(value_name = "HOST:PORT")]
    pub target: String,

    /// The detections to run, and nothing else. With none named, the built-in
    /// corpus runs instead, for a quick look at what fires against the endpoint.
    #[command(flatten)]
    pub detections: DetectionArgs,

    /// The most intrusive class to run, `exploit` by default so a check that
    /// triggers a weakness to confirm it actually fires. `zond scan` defaults to
    /// `passive`; a test is an explicit act against a chosen target, so it
    /// opens the ceiling instead of making you raise it.
    #[arg(long, value_name = "CLASS")]
    pub detection: Option<DetectionEnvelope>,
}

/// Arguments to `zond detections replay`.
#[derive(Debug, Args)]
pub(crate) struct ReplayArgs {
    /// The scan whose detections to replay: a record as `zond journal` lists them,
    /// which may be shortened to any prefix that names only one or given as
    /// `latest`, or a path to a journal directory.
    ///
    /// Named the way `zond read` names a scan, and required for the same reason:
    /// replaying is an act on one particular record, so the record is said rather
    /// than assumed.
    #[arg(value_name = "SCAN")]
    pub scan: String,

    /// Replay only the detection with this id, rather than every one recorded.
    #[arg(long, value_name = "ID")]
    pub only: Option<String>,
}

/// Arguments to `zond detections keygen`.
#[derive(Debug, Args)]
pub(crate) struct KeygenArgs {
    /// Where to write the key pair.
    ///
    /// Two files: the private key at this path, readable only by you, and the
    /// public key beside it as `.pub`, written as hex. Publish the second and
    /// keep the first. Neither is ever read by a scan.
    #[arg(value_name = "PATH")]
    pub path: std::path::PathBuf,
}

/// Arguments to `zond detections sign`.
#[derive(Debug, Args)]
pub(crate) struct SignArgs {
    /// The directory of detections to sign.
    ///
    /// Read the way `--detections` reads one: every `.toml` in it, and the bodies
    /// they reference. Nothing in it is modified.
    #[arg(value_name = "DIR")]
    pub directory: std::path::PathBuf,

    /// Where to write the bundle.
    ///
    /// A directory of its own, holding the manifest, its signature, and one
    /// self-contained document per detection: a module's code is written into the
    /// document that runs it, since a signature covers what a recipient hashes
    /// and a recipient hashes whole files. This is what gets distributed, and
    /// what `--detections-bundle` is pointed at.
    #[arg(long, value_name = "DIR")]
    pub out: std::path::PathBuf,

    /// The private key to sign with, as `keygen` wrote it.
    #[arg(long, value_name = "PATH")]
    pub key: std::path::PathBuf,

    /// What the bundle calls itself, which a report prints beside its findings.
    #[arg(long, value_name = "NAME")]
    pub name: String,

    /// The version of the set, so a recipient can tell two deliveries apart.
    #[arg(long, value_name = "VERSION", default_value = "1")]
    pub bundle_version: String,
}

/// What `zond detections --help` ends with.
fn detections_help() -> String {
    "\
Examples:
  zond detections                             the first page of the corpus this build ships
  zond detections --all                       every one of them
  zond detections --search redis              the ones about Redis, by id or by title
  zond detections --class exploit --class dos the loud ones, which a scan will not run
  zond detections --service http --sort class what is written for HTTP, loudest first
  zond detections --detections ./checks       compile a directory and list what is in it
  zond detections --detections ./checks --only-named-detections
                                              just yours, without the built-in corpus
  zond detections keygen ~/.zond/acme         a key to publish under
  zond detections sign ./checks --out ./acme-1 --key ~/.zond/acme --name acme
                                              a bundle others can load

What it does:
  Reads the detections, validates and compiles every one of them, and prints
  what a scan would run: the id, the tier, the intrusiveness class, and the gate
  that decides which ports it fires on. Nothing is sent anywhere.

  The class matters as much as the gate. A scan runs detections up to the
  ceiling `--detection` names, `passive` by default, so a detection above
  it is listed here and still does not run until an operator raises the ceiling.

Finding one:
  The corpus is long enough to page, ten at a time, `--page 2` for the next ten
  and `--all` for the lot. `--search`, `--class`, `--tier`, `--service` and
  `--port` narrow it, each one ANDing with the rest and a repeated one widening
  itself, and `--sort` orders what is left. None of them changes what a scan
  runs: this is reading, and `--pipe` hands the whole selection to a program
  unpaged.

Writing one:
  A detection is TOML. `[[step]]` makes it a flow: a bounded sequence of probes
  and matches ending in a finding, carrying no code. `[compute]` makes it a
  sandboxed module, which reaches the network only through the verbs its class
  is granted. Either way it declares an id, a `[detection.when]` gate and a
  `[detection.capabilities]` class.

Giving them to somebody else:
  `sign` writes a manifest naming every detection and the hash of its source,
  and a signature over that manifest. A recipient loads it with
  `--detections-bundle DIR --trust-key key.pub`, and the key has to reach them
  by some route other than the bundle: a signature names the key that made it,
  and trusting that one accepts anything anybody re-signed."
        .to_string()
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
    ///
    /// A named pipe is opened before the scan starts, so the scan waits there
    /// until something opens the pipe to read.
    #[arg(long = "output-as", value_name = "FORMAT=FILE", action = ArgAction::Append)]
    pub output_as: Vec<crate::export::FormatAndPath>,

    /// Write every format this build can produce, each named after BASE.
    ///
    /// `--output-all engagement` leaves `engagement.json`, `engagement.csv`,
    /// and one of each of the rest.
    #[arg(long = "output-all", value_name = "BASE")]
    pub output_all: Option<std::path::PathBuf>,
}

impl ExportArgs {
    /// Every file this run was told to write, with the format each names,
    /// opened and held until its report is written.
    ///
    /// Here rather than at each command because all four of them asked the same
    /// three-argument question and one of them could have got the order wrong
    /// without anything noticing. Call it before the work starts: see
    /// [`export`](crate::export) for why a misspelt extension or a missing
    /// directory is worth answering in the first second rather than the last,
    /// and why a report's file is safer held from then.
    pub(crate) fn destinations(
        &self,
    ) -> Result<Vec<crate::export::ReportFile>, crate::error::Error> {
        crate::export::Destination::resolve(
            &self.output,
            &self.output_as,
            self.output_all.as_deref(),
        )?
        .into_iter()
        .map(crate::export::Destination::open)
        .collect()
    }
}

/// How much of a listing to show at once.
///
/// **Not global.** They belong to listing, and the sibling subcommands already
/// spell two of these letters differently: `prune -n` is a dry run, and
/// `prune --all` deletes every record where here it shows them. A flag that
/// meant "show everything" on one subcommand and "delete everything" on the
/// next is not a convenience.
///
/// So the set is attached in the places a listing happens: `zond journal` and
/// `zond journal list`, which page the scans this machine has a record of, and
/// `zond detections`, which pages a corpus that has grown past a screen.
#[derive(Debug, Args, Default)]
pub(crate) struct PageArgs {
    /// How many rows to list at once.
    ///
    /// Ten by default, which is the handful anybody is usually looking for.
    /// `page_size` in `cli.toml` changes that for every run, and 0 means no
    /// limit.
    #[arg(long, short = 'n', value_name = "COUNT", conflicts_with = "all")]
    pub limit: Option<usize>,

    /// Which page of them, counting from one.
    ///
    /// Pages are as long as `--limit`, so `--page 3` is the third ten unless
    /// you said otherwise.
    #[arg(long, value_name = "N", conflicts_with = "all")]
    pub page: Option<usize>,

    /// List every row, however many there are.
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

/// The seconds one unit suffix stands for, or `None` for a suffix this program
/// does not know.
///
/// **One table, because a program with two answers about what `d` means has a
/// bug waiting in it.** `--older-than` and `--for` are both a count and a unit,
/// and they diverged: one took days and the other refused them, on a flag whose
/// own documentation talks about watches that run for days.
///
/// Written out rather than pulled in, on the same reasoning the engine gives for
/// its own small parsers: a dependency for four suffixes costs more than it
/// saves.
fn unit_seconds(unit: &str) -> Option<u64> {
    match unit {
        "s" => Some(1),
        "m" => Some(60),
        "h" => Some(60 * 60),
        "d" => Some(24 * 60 * 60),
        _ => None,
    }
}

/// Every unit suffix, for the message a rejected one gets.
const UNITS: &str = "s, m, h, d";

/// Parses an age as a count and a unit: `30d`, `12h`, `90m`, `45s`.
///
/// Bare digits are refused, unlike [`parse_duration`], because `--older-than 30`
/// reads as thirty of something and there is no honest way to guess which. A
/// watch's `--for` has an obvious default and this has none.
fn age(input: &str) -> Result<std::time::Duration, String> {
    let (count, unit) = input.split_at(
        input
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("'{input}' has no unit; try '{input}d' for days"))?,
    );

    let count: u64 = count
        .parse()
        .map_err(|_| format!("'{input}' does not start with a number"))?;

    let seconds = unit_seconds(unit).ok_or_else(|| format!("'{unit}' is not one of {UNITS}"))?;

    let seconds = count
        .checked_mul(seconds)
        .ok_or_else(|| format!("'{input}' is longer than this program can count"))?;

    Ok(std::time::Duration::from_secs(seconds))
}

/// Arguments to `zond listen`.
#[derive(Debug, Args)]
pub(crate) struct ListenArgs {
    /// Which link to listen on: an interface name, `%en0`, or `lan`.
    ///
    /// Several may be given. With none, every interface that is up.
    #[arg(value_name = "LINK", num_args = 0..)]
    pub links: Vec<String>,

    /// Stop after this long, rather than waiting to be told.
    ///
    /// Accepts a plain number of seconds, or a suffix: `30s`, `10m`, `4h`, `2d`.
    /// Without it the watch runs until `Ctrl-C` or `q`, which is what a sensor
    /// wants and what a bounded sample does not.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub r#for: Option<std::time::Duration>,

    /// Record every machine heard, not only the ones attached to these links.
    ///
    /// A link carrying traffic to anywhere else carries evidence about
    /// everywhere else: on a mirror port, every server a laptop connects to is
    /// a real host with a real open port. True, and not an inventory of this
    /// network — so by default it is left out. This asks for it, which is the
    /// question "what does this network depend on" rather than "what is on it".
    #[arg(long)]
    pub everything: bool,

    /// Do not write down what this watch hears.
    ///
    /// A watch is recorded by default, on the same reasoning a scan is: the
    /// moment you want what it heard is after it stopped. A watch's record is
    /// appended to rather than resumed — there is no progress to continue, so
    /// `--resume` adds another sitting to the same record.
    #[arg(long, conflicts_with = "resume")]
    pub no_journal: bool,

    /// Add a sitting to the watch with this id.
    ///
    /// The links come from the record. Nothing is skipped, because a watch
    /// settles nothing: what this buys is that the earlier sittings' findings
    /// are restored first, so the report describes the whole watch.
    #[arg(long, value_name = "ID", conflicts_with = "links")]
    pub resume: Option<String>,

    /// Continue the record even though its lock names a process that has
    /// stopped checkpointing.
    ///
    /// A record is locked while a run writes it, so two runs never write one.
    /// A lock whose process is gone is released on its own. One naming a
    /// process that is alive and silent is refused, because a hung run and a
    /// crashed one whose process number was handed to something else look
    /// the same from here. Once the process it names is known not to be the
    /// run, this takes the record over. A lock its run is still beating is
    /// refused whatever is passed.
    #[arg(long, requires = "resume")]
    pub take_over: bool,

    /// Settings that change what the watch reads.
    #[command(flatten)]
    pub engine: EngineArgs,

    /// Where to write the report, besides the terminal.
    #[command(flatten)]
    pub export: ExportArgs,
}

/// How long a watch runs, as it is written on the command line.
///
/// Seconds by default, so a bare number means what a person expects. The
/// suffixes are [`unit_seconds`]', which is the same table `--older-than` reads
/// — including `d`, because a watch left running for days is what this phase is
/// for and `--for 2d` used to be refused as not a length of time.
pub(crate) fn parse_duration(text: &str) -> Result<std::time::Duration, String> {
    let text = text.trim();

    // Split on the first thing that is not a digit, so an unknown suffix is
    // named rather than swallowed: taking only the last character read `4hh` as
    // a bare number and then failed to parse `4h` as one, which reported a
    // typo in the unit as a number that is not a number.
    let (digits, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(at) => (&text[..at], &text[at..]),
        None => (text, ""),
    };

    let value: u64 = digits
        .parse()
        .map_err(|_| format!("'{text}' is not a length of time: try 30s, 10m or 4h"))?;

    let multiplier = if unit.is_empty() {
        1
    } else {
        unit_seconds(unit)
            .ok_or_else(|| format!("'{unit}' is not one of {UNITS}: try 30s, 10m or 4h"))?
    };

    if value == 0 {
        return Err(String::from(
            "zero is not a length of time: try 30s, 10m or 4h",
        ));
    }

    // A span nobody will reach, and the arithmetic below would wrap into a
    // short one: `--for 99999999999999999999d` should be refused rather than
    // quietly become a watch of nine minutes.
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("'{text}' is longer than this program can count"))?;

    Ok(std::time::Duration::from_secs(seconds))
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
    /// So do the options it ran under. A flag that changes what the sweep asks,
    /// such as `--effort`, is refused; one that changes its pace, such as
    /// `--max-probe-rate`, applies to this sitting.
    ///
    /// `zond journal` lists what can be continued. A record's scope is fixed,
    /// so `--exclude` cannot be added to one: withholding an address the record
    /// counted would renumber every address after it.
    #[arg(long, value_name = "ID", conflicts_with_all = ["targets", "exclude"])]
    pub resume: Option<String>,

    /// Continue the record even though its lock names a process that has
    /// stopped checkpointing.
    ///
    /// A record is locked while a run writes it, so two runs never write one.
    /// A lock whose process is gone is released on its own. One naming a
    /// process that is alive and silent is refused, because a hung run and a
    /// crashed one whose process number was handed to something else look
    /// the same from here. Once the process it names is known not to be the
    /// run, this takes the record over. A lock its run is still beating is
    /// refused whatever is passed.
    #[arg(long, requires = "resume")]
    pub take_over: bool,

    /// Settings that change what the scan puts on the wire.
    #[command(flatten)]
    pub engine: EngineArgs,

    /// Where to write the report, besides the terminal.
    #[command(flatten)]
    pub export: ExportArgs,
}

/// Arguments to `zond scan`.
///
// Several independent on/off flags — `--assume-up`, `--tls-enum`,
// `--characterise` — so the count trips the bool-heavy-struct lint. Each is one
// switch a caller sets in any combination, and clap derives the parser from
// exactly these fields, the same shape [`EngineArgs`] carries.
#[allow(clippy::struct_excessive_bools)]
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

    /// Which ports to probe: `22,80,443`, `1-1024`, `u:53,161` for UDP,
    /// `s:2905` for SCTP.
    ///
    /// A qualifier holds until the next one, as in nmap, and `t:` switches back
    /// to TCP: `-p u:53,161,t:22`.
    ///
    /// A range may leave off either end. `-p-` is every port there is, `-p-1024`
    /// is everything up to 1024, and `-p9000-` is everything from it. The forms
    /// compose with the rest: `-p 22,9000-,u:-,s:2905`.
    ///
    /// Defaults to `default_ports` in the settings file, and to the thousand
    /// ports most likely to be listening when that says nothing either.
    #[arg(
        short = 'p',
        long,
        value_name = "PORTS",
        conflicts_with_all = ["top_ports", "top_ports_udp"],
        value_parser = port_set,
        // `-p-` is the spelling everybody arrives with, and without this clap
        // reads the `-` as the start of another flag and refuses it.
        //
        // It costs one thing, and only on a typo: `-p` with its value left off
        // now swallows whatever follows instead of reporting a missing value.
        // What that produces is still an error naming the swallowed token,
        // "'--service-detection' is not a port or a range", which says what
        // happened plainly enough. The alternative is not supporting the
        // spelling at all.
        allow_hyphen_values = true
    )]
    pub ports: Option<PortSet>,

    /// Correlate against a vulnerability catalogue on disk, beside the one this
    /// build ships.
    ///
    /// The shipped catalogue is a starting set, not a complete one. This is how
    /// a scan is pointed at real data: convert a feed once with
    /// `zond_engine::import::nvd` or `::kev` and name the result here.
    ///
    /// It is a file rather than a URL on purpose. A scan that fetched a dataset
    /// would depend on somebody else's server being up to say what it found, and
    /// a report nobody can reproduce next week is not evidence. Convert once,
    /// keep the file, and every re-run says the same thing.
    ///
    /// Findings deduplicate by claim, so an entry both catalogues carry is
    /// recorded once, and the report names which dataset concluded what.
    #[arg(long, value_name = "PATH")]
    pub cve_catalogue: Option<std::path::PathBuf>,

    /// Probe the N TCP ports most likely to be listening.
    ///
    /// The engine ranks them, most likely first, and this takes the first N.
    /// `--top-ports 100` is a quick pass over what answers on nearly everything;
    /// the default without any port flag is the whole ranked list, which is a
    /// thousand.
    ///
    /// TCP only. `--top-ports-udp` asks for the UDP list, and `-p u:53,u:161`
    /// names particular UDP ports.
    #[arg(long, value_name = "N", value_parser = port_count, conflicts_with = "ports")]
    pub top_ports: Option<usize>,

    /// Probe the N UDP ports most likely to be listening.
    ///
    /// Its own flag rather than something `--top-ports` quietly includes,
    /// because the two are not the same purchase. A UDP probe is answered only
    /// by a service that recognises the payload sent to it, or by an ICMP port
    /// unreachable the host is rate-limited to emitting roughly once a second,
    /// so each port costs far more to classify and far more of them come back
    /// open|filtered whatever is done. That is worth asking for out loud.
    ///
    /// The ranked UDP list is 250 ports long, and asking for more than it holds
    /// yields all of it. The two flags combine: `--top-ports 100
    /// --top-ports-udp 50` probes both lists, and either one on its own probes
    /// only its own transport.
    #[arg(long, value_name = "N", value_parser = port_count, conflicts_with = "ports")]
    pub top_ports_udp: Option<usize>,

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
    /// So do the options it ran under. A flag that changes what the scan asks,
    /// such as `--assume-up` or `--effort`, is refused; one that changes its
    /// pace, such as `--max-probe-rate`, applies to this sitting.
    ///
    /// `zond journal` lists what can be continued. A record's scope is fixed,
    /// so `--exclude` cannot be added to one: withholding an address the record
    /// counted would renumber every target after it.
    #[arg(long, value_name = "ID", conflicts_with = "exclude")]
    pub resume: Option<String>,

    /// Continue the record even though its lock names a process that has
    /// stopped checkpointing.
    ///
    /// A record is locked while a run writes it, so two runs never write one.
    /// A lock whose process is gone is released on its own. One naming a
    /// process that is alive and silent is refused, because a hung run and a
    /// crashed one whose process number was handed to something else look
    /// the same from here. Once the process it names is known not to be the
    /// run, this takes the record over. A lock its run is still beating is
    /// refused whatever is passed.
    #[arg(long, requires = "resume")]
    pub take_over: bool,

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
    /// rather than quietly substituted. `window` reads an ACK's reset for its
    /// window field, which some stacks set differently on an open port.
    ///
    /// [possible values: syn, fin, null, xmas, maimon, ack, window]
    #[arg(long, value_name = "TECHNIQUE")]
    pub tcp_technique: Option<TcpScanTechnique>,

    /// Which SCTP probe carries the scan, for the ports named `s:`.
    ///
    /// `init` attempts an association and is the only one that confirms a
    /// listener positively; `cookie-echo` sends an unminted cookie, which a
    /// closed port answers and an open one ignores. Both need root. Only the
    /// ports written as SCTP, `-p s:2905`, are probed this way.
    ///
    /// [possible values: init, cookie-echo]
    #[arg(long, value_name = "TECHNIQUE")]
    pub sctp_technique: Option<SctpScanTechnique>,

    /// Enumerate the TLS versions and cipher suites each TLS port accepts.
    ///
    /// A pass after service detection that costs a connection per suite a port
    /// accepts: a dozen or so for a current server, some 250 for an old one that
    /// accepts everything. --host-timeout bounds it. A deprecated version
    /// or a weak suite is reported as a finding against the port, and a version
    /// whose walk was cut short is marked unfinished.
    #[arg(long)]
    pub tls_enum: bool,

    /// Ports to send nothing at all, on any target: `9100-9107`, `u:161`.
    ///
    /// Written the way `-p` is, and taken out of it, so no probe reaches them:
    /// not the scan, not the liveness check before it, and not OS detection
    /// after it. The report names them. Repeat the flag, or write a list.
    ///
    /// A printer's raw-print ports are already sent nothing but the probe
    /// that finds them open; exclude them to skip that too, and not find the
    /// printers. Adds to `exclude_ports` in engine.toml.
    #[arg(
        long,
        value_name = "PORTS",
        value_parser = port_set,
        action = ArgAction::Append,
        allow_hyphen_values = true
    )]
    pub exclude_ports: Vec<PortSet>,

    /// Probe printers' raw-print ports, TCP 9100 to 9107, like any other port.
    ///
    /// A network printer prints whatever arrives on these ports, so by default
    /// they are found open, listened to, and sent nothing: no service probe, no
    /// detection and no TLS handshake, each of which would come out of the
    /// printer as a page of gibberish. With this they are probed like every
    /// other port, and a printer behind one will print what it is sent.
    #[arg(long)]
    pub probe_print_ports: bool,

    /// Characterise the filter in front of each host that answered.
    ///
    /// A last pass against the hosts that answered, sending a bad-checksum probe
    /// to an open port and a comparative one to a filtered port: what answers,
    /// and what it answers with, tells a stateful filter from a stateless one
    /// and a middlebox from the host itself. Needs root. Records its conclusion
    /// on the host rather than opening or closing any port.
    #[arg(long)]
    pub characterise: bool,

    /// Ask each host which IP protocols its stack takes delivery of.
    ///
    /// A comma-separated list of protocol numbers, as in `1,6,17,132` for ICMP,
    /// TCP, UDP and SCTP. Each host is sent one datagram per protocol and its
    /// answer — a reply, a protocol-unreachable, or silence — says whether the
    /// stack accepts it. Independent of the port scan: this asks what the host
    /// speaks, not what listens on it. Needs root.
    #[arg(long, value_name = "LIST", value_parser = ip_protocols)]
    pub ip_protocols: Option<std::collections::BTreeSet<u8>>,

    /// How intrusive a detection the scan may run against what it identifies.
    ///
    /// After a service is named, the detection corpus can probe it further for
    /// what is wrong with it, and this is the ceiling on how far that goes.
    /// `off` runs none at all; `passive`, the default, reads only what the scan
    /// already gathered and sends nothing of its own; `active-benign` opens a
    /// connection per check, which is what `-d` asks for; the classes above it,
    /// `active-mutating`, `exploit` and `dos`, change or degrade the target and
    /// run only when an operator names them here.
    ///
    /// Takes the step number as readily as the word, which is what `-d` passes.
    ///
    /// [possible values: off, passive, active-benign, active-mutating, exploit, dos]
    #[arg(long, value_name = "CLASS")]
    pub detection: Option<DetectionEnvelope>,

    /// How far to go past reading what the scan gathered, as a step from 0 to 5.
    ///
    /// `-d` on its own is `2`, which probes what the scan identified: the corpus
    /// asks a web port about three dozen products by name, one connection each,
    /// whether it is a Grafana with a traversable plugin path, a Vault left
    /// unsealed, a WordPress with a readable config backup. Each is a real
    /// finding on the box that runs that product and a wasted round trip on the
    /// box that does not, so it is asked for rather than assumed.
    ///
    /// The steps are the same scale `--detection` names in words, `0` off
    /// through `5` dos, so `-d=4` is `--detection exploit` and `-d=0` turns
    /// detections off entirely and leaves a scan its ports and services. Written
    /// with an equals sign: without one, `zond scan -d 192.0.2.1` would read the
    /// address as a step and scan nothing.
    ///
    /// [possible values: 0 off, 1 passive, 2 active-benign, 3 active-mutating,
    /// 4 exploit, 5 dos]
    #[arg(
        short = 'd',
        long = "detect",
        value_name = "N",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "active-benign",
        conflicts_with = "detection"
    )]
    pub detect: Option<DetectionEnvelope>,

    /// Which detections the scan runs, beyond the ones built in.
    #[command(flatten)]
    pub detections: DetectionArgs,

    /// Read the target's TCP ports off a third party's IP-ID counter.
    ///
    /// The idle, or zombie, scan: every probe is forged to come from the zombie,
    /// so the target never sees this host, and the ports it finds open are read
    /// from how the zombie's IP-ID moved. The zombie must be a host with a
    /// predictable counter and next to no other traffic. Name it as an address,
    /// or `IP:PORT` to say which of its ports to poll.
    ///
    /// Needs root, and forges nothing the target can trace back here. A loud,
    /// slow scan whose whole point is that the target learns the zombie's
    /// address and not this one.
    #[arg(long = "idle-scan", value_name = "ZOMBIE", value_parser = idle_scan)]
    pub idle_scan: Option<IdleScan>,

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
        if self.tls_enum {
            config.tls_enumeration = true;
        }
        if self.probe_print_ports {
            config
                .listen_only_ports
                .retain(|port| !RAW_PRINT_PORTS.contains(port));
        }
        for ports in &self.exclude_ports {
            config.excluded_ports = config.excluded_ports.union(ports);
        }
        if self.characterise {
            config.characterise = true;
        }
        if let Some(technique) = self.tcp_technique {
            config.tcp_technique = technique;
        }
        if let Some(technique) = self.sctp_technique {
            config.sctp_technique = technique;
        }
        if let Some(protocols) = &self.ip_protocols {
            config.ip_protocols.clone_from(protocols);
        }
        if let Some(envelope) = self.detection.or(self.detect) {
            config.detection = envelope;
        }
        if let Some(idle) = self.idle_scan {
            config.idle_scan = Some(idle);
        }
    }
}

/// Reads a zombie for the idle scan: an address, or `IP:PORT`.
///
/// The port is optional, and where it is given it says which of the zombie's own
/// ports to poll for the IP-ID; without it the engine picks one. An IPv6 zombie
/// with a port is written the way a target is, `[2001:db8::1]:80`, so the colons
/// in the address are not read as the separator.
fn idle_scan(text: &str) -> Result<IdleScan, String> {
    let text = text.trim();

    // `[addr]:port` first, so an IPv6 zombie's own colons are not mistaken for
    // the one that introduces the port.
    if let Some(rest) = text.strip_prefix('[') {
        let (addr, port) = rest
            .split_once("]:")
            .ok_or_else(|| format!("'{text}' is not a bracketed zombie: try [2001:db8::1]:80"))?;
        let zombie = parse_zombie_addr(addr)?;
        let port = parse_zombie_port(port)?;
        return Ok(IdleScan::new(zombie).with_port(port));
    }

    // A bare address with a trailing `:port`, told apart from an IPv6 address by
    // there being exactly one colon in it.
    if let Some((addr, port)) = text.rsplit_once(':')
        && addr.parse::<std::net::Ipv4Addr>().is_ok()
    {
        let zombie = std::net::IpAddr::V4(addr.parse().expect("just parsed as v4"));
        return Ok(IdleScan::new(zombie).with_port(parse_zombie_port(port)?));
    }

    Ok(IdleScan::new(parse_zombie_addr(text)?))
}

/// One zombie address, refused if it is not one.
fn parse_zombie_addr(text: &str) -> Result<std::net::IpAddr, String> {
    text.parse::<std::net::IpAddr>()
        .map_err(|_| format!("'{text}' is not an address a zombie can be"))
}

/// One zombie probe port.
fn parse_zombie_port(text: &str) -> Result<u16, String> {
    text.parse::<u16>()
        .map_err(|_| format!("'{text}' is not a port (0 to 65535)"))
}

/// The most port numbers a refusal suggests for a service name.
///
/// `http` is registered on dozens; the first few by prevalence are what a
/// person writing the name almost always means, and more would stop being a
/// hint.
const PORTS_SUGGESTED: usize = 3;

/// Reads `-p` and `--exclude-ports` in the engine's port grammar, answering a
/// service name written where a number goes with the numbers to write instead.
///
/// The grammar has no names, so it can only say that a name is not a number.
/// Which numbers `ssh` stands for is the signature corpus's to say, since it
/// names the services the engine identifies, and the corpus sits above the
/// grammar: so the suggestion is made here, where both are in reach.
///
/// A list naming no port is refused in the engine's words. The grammar reads
/// one as the empty set, which is how an empty set is written back, and a flag
/// is never typed to mean that: `-p ''` would scan nothing and exit 0 as though
/// nothing were there, and `--exclude-ports ''` would exclude nothing.
fn port_set(text: &str) -> Result<PortSet, String> {
    let set = PortSet::try_from(text).map_err(|error| match &error {
        PortSetParseError::ServiceName(written) => {
            let name = written
                .split_once(':')
                .map_or(written.as_str(), |(_, name)| name);
            let qualifier = &written[..written.len() - name.len()];
            let ports = ports_named(name);
            if ports.is_empty() {
                error.to_string()
            } else {
                let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
                format!(
                    "'{written}' is not a port number (write {qualifier}{} for {name})",
                    ports.join(",")
                )
            }
        }
        _ => error.to_string(),
    })?;
    if set.is_empty() {
        return Err(PortSetParseError::NoPorts.to_string());
    }
    Ok(set)
}

/// Reads a count of the likeliest ports to probe, refusing zero, which names
/// no port for the reason [`port_set`] refuses an empty list.
fn port_count(text: &str) -> Result<usize, String> {
    match text.parse::<usize>() {
        Ok(0) => Err("names no ports (write 100, or 1000 for the default)".to_string()),
        Ok(count) => Ok(count),
        Err(error) => Err(error.to_string()),
    }
}

/// The ports the signature corpus registers `name` on, most prevalent first,
/// at most [`PORTS_SUGGESTED`] of them.
fn ports_named(name: &str) -> Vec<u16> {
    let corpus = zond_engine::fingerprint::SignatureDb::global();
    let ranked = zond_engine::model::port::catalog::top_tcp(usize::MAX);
    let mut ports: Vec<u16> = corpus
        .indexed_ports()
        .filter(|&port| {
            corpus
                .service_name(port)
                .is_some_and(|registered| registered.eq_ignore_ascii_case(name))
        })
        .collect();
    ports.sort_by_key(|port| {
        (
            ranked
                .iter()
                .position(|ranked| ranked == port)
                .unwrap_or(usize::MAX),
            *port,
        )
    });
    ports.truncate(PORTS_SUGGESTED);
    ports
}

/// Reads a comma-separated list of IP protocol numbers into a set.
///
/// Numbers rather than names, the way `-sO` and the IANA registry name a
/// protocol: `1,6,17,132` is ICMP, TCP, UDP and SCTP. A name-to-number table
/// would be one this program had to keep in step with a registry it does not
/// own, and a misremembered name is a worse failure than a number a reader can
/// look up.
fn ip_protocols(text: &str) -> Result<std::collections::BTreeSet<u8>, String> {
    text.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse::<u8>()
                .map_err(|_| format!("'{entry}' is not an IP protocol number (0 to 255)"))
        })
        .collect()
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
  one.one.one.one    a hostname (with --no-dns, from the hosts file alone)
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
  sudo zond s 192.168.0.150 --top-ports-udp 50
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
Port scanning uses raw SYN probes when it can. Without root a TCP port is tested
by completing a connection, which is slower and more visible, and a technique
only raw probes can send is refused rather than downgraded; the summary says
which happened.",
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
    /// read from the hosts file, which sends nothing, and refused rather than
    /// dropped when the file does not list it.
    #[arg(short = 'n', long)]
    pub no_dns: bool,

    /// Mask host and domain names, hardware addresses and IPv6 host parts in
    /// the output.
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
    #[arg(long, value_name = "N")]
    pub max_attempts: Option<NonZeroU8>,

    /// Multiply how long the scan is willing to wait.
    ///
    /// Does not touch the shortest timeout a protocol allows. That floor is not
    /// a preference, it is what the protocol costs.
    #[arg(long, value_name = "FACTOR", value_parser = timeout_scale)]
    pub timeout_scale: Option<TimeoutScale>,

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
    #[arg(long, value_name = "PPS")]
    pub max_probe_rate: Option<NonZeroU32>,

    /// The slowest discovery may fall to, in probes per second.
    ///
    /// A floor, not a ceiling: it lifts a scan that pacing has slowed below it,
    /// and never speeds one past what `--max-probe-rate` allows. For a link whose
    /// round trips are long enough that the adaptive window crawls, where the
    /// operator would rather spend packets than wait.
    #[arg(long, value_name = "PPS")]
    pub min_probe_rate: Option<NonZeroU32>,

    /// Give up on a host that is still answering after this long.
    ///
    /// A wall-clock budget per host, spent across every phase it is in. A host
    /// that reaches it is left where it stands and named in the report as one
    /// the budget cut short, so a slow host cannot hold a scan open. Accepts a
    /// plain number of seconds or a suffix: `30s`, `10m`, `4h`.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub host_timeout: Option<std::time::Duration>,

    /// Give up on the whole scan after this long.
    ///
    /// The same budget for the run as a whole. Every host still outstanding when
    /// it expires is left where it stands and named in the report, and the run
    /// exits 3 rather than as interrupted. Accepts a plain number of seconds or
    /// a suffix: `30s`, `10m`, `4h`.
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub scan_timeout: Option<std::time::Duration>,

    /// How raw probes are placed on the wire.
    ///
    /// [possible values: auto, raw_socket, ethernet]
    #[arg(long, value_name = "MODE")]
    pub send_mode: Option<SendMode>,

    /// Send probes to routed targets from this interface, whatever the
    /// routing table says.
    ///
    /// The escape from a full-tunnel VPN: pinned to a LAN interface, a scan of
    /// a routed target leaves from that interface's address rather than the
    /// tunnel the default route points down, and so do the connections that
    /// follow its probes. Named by interface, not address; the interface's own
    /// addresses become the source, one per family, and only for the families
    /// it holds one of: on an interface with no IPv6 address, IPv6 targets
    /// still go by the routing table, VPN included, and the run says so. A
    /// target on a segment or in a tunnel's own prefix is always reached by
    /// that link. Name lookups are not pinned: they ask the system's resolvers
    /// by the routing table, so add `-n` to keep them off the tunnel.
    ///
    /// On Linux a run without root needs kernel 5.7 or later to pin its
    /// connections; an older kernel refuses them, and their targets are
    /// reported unreachable rather than scanned through the tunnel.
    #[arg(long, value_name = "NAME")]
    pub send_interface: Option<String>,

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
    /// gets the one generic request worth asking of anything. `thorough` goes
    /// one step further, and only for a port that answered none of that: it
    /// puts the questions other services registered to it, likeliest first. A
    /// Redis moved to 8443 answers `PING` and nothing else, so nothing below
    /// this level ever finds it.
    ///
    /// Turning it down does not make an unknown port faster to scan. Asking is
    /// how a port is finished with quickly, and the alternative is waiting out a
    /// greeting that never comes.
    ///
    /// [possible values: off, banner, probe, thorough]
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

    /// What the scan is allowed to change about the packets it sends.
    #[command(flatten)]
    pub evasion: EvasionArgs,
}

/// What a scan may change about the packets it sends, to get past a filter or to
/// hide which host is asking.
///
/// A group of its own because they share a purpose and a caveat: every one of
/// them needs raw sockets, and a scan that cannot build its own packets cannot
/// honour any of them. The engine refuses a profile no strategy in the plan
/// could carry when the scan is asked for, rather than sending something weaker
/// and not saying so, so a flag here that the run cannot honour is an error and
/// not a silent downgrade.
///
/// Layered onto the profile the settings produced, each flag speaking only about
/// what was written, the way [`EngineArgs`] is.
#[derive(Debug, Args)]
#[command(next_help_heading = "Evasion")]
pub(crate) struct EvasionArgs {
    /// Set the probes' hop limit, rather than this host's default.
    ///
    /// A probe crafted to expire in the path, or one built to look like traffic
    /// from a particular distance. Refused at zero, which is a packet that never
    /// leaves the first hop. The service, TLS and detection connections that
    /// follow a probe keep this host's default.
    #[arg(long, value_name = "HOPS")]
    pub ttl: Option<u8>,

    /// Send every probe from this source port.
    ///
    /// A filter that trusts a port such as 53 or 88 lets a probe wearing it back
    /// in. One port for every probe, since the answers must come back to it. The
    /// service, TLS and detection connections that follow leave from ports the
    /// system picks: one port cannot hold several connections to one target
    /// port at once.
    #[arg(long = "source-port", visible_alias = "g", value_name = "PORT")]
    pub source_port: Option<u16>,

    /// Mingle the real probes with decoys from these addresses.
    ///
    /// Repeat the flag or comma-join them. The target sees probes from every
    /// address at once and cannot tell which one is asking, at the cost of one
    /// full scan's traffic per decoy. Addresses that are alive make better cover
    /// than empty ones, which a defender can rule out.
    #[arg(long = "decoy", value_name = "IP", value_delimiter = ',', action = ArgAction::Append)]
    pub decoys: Vec<std::net::IpAddr>,

    /// Fragment every crafted probe to this MTU, in bytes.
    ///
    /// A stateless filter that judges only the first fragment can be slipped a
    /// probe whose flags land in a later one. A multiple of eight, and no
    /// smaller than one IP header plus the transport's first bytes, which the
    /// engine enforces and refuses below.
    #[arg(long = "mtu", value_name = "MTU")]
    pub fragment: Option<u16>,

    /// Append this many bytes of padding to each crafted probe.
    ///
    /// A blunt shape change: a scan whose every packet is a fixed odd length is
    /// less like the fingerprint a signature is looking for.
    #[arg(long = "data-length", value_name = "LEN")]
    pub padding: Option<u16>,

    /// Give every crafted TCP probe a deliberately wrong checksum.
    ///
    /// A conformant host drops it unread, so anything that answers was not the
    /// host: a middlebox in the path replying without validating. A probe rather
    /// than an evasion, and it shares the machinery, which is why it is here.
    #[arg(long = "badsum")]
    pub bad_checksum: bool,

    /// Send crafted frames from this hardware address.
    ///
    /// Only reaches the wire on the local segment, where the scan builds its own
    /// Ethernet frames; a routed probe carries this host's real address whatever
    /// is set here.
    #[arg(long = "spoof-mac", value_name = "MAC")]
    pub spoof_mac: Option<MacAddr>,

    /// Set the TCP flags on every port probe by name or number.
    ///
    /// Names concatenated or joined by `+`, as in `SYNFIN` or `SYN+FIN`, from
    /// `FIN SYN RST PSH ACK URG ECE CWR`; or a number, decimal or `0x`-hex. What
    /// a reply means is read the way the closest standard technique reads it, so
    /// an answer is still a verdict rather than a raw packet.
    #[arg(long = "scanflags", value_name = "FLAGS", value_parser = scan_flags)]
    pub flags: Option<u8>,
}

impl EvasionArgs {
    /// Lays these flags over the evasion profile the settings produced.
    ///
    /// Each is optional or a `bool` whose absence says nothing, so a flag left
    /// off never cancels one a profile set. The builder is folded rather than
    /// rebuilt, so a value from the settings file that no flag here touches
    /// survives.
    fn apply_to(&self, evasion: &mut EvasionProfile) {
        let mut built = evasion.clone();

        if let Some(ttl) = self.ttl {
            built = built.with_ttl(ttl);
        }
        if let Some(port) = self.source_port {
            built = built.with_source_port(port);
        }
        if !self.decoys.is_empty() {
            built = built.with_decoys(self.decoys.clone());
        }
        if let Some(mtu) = self.fragment {
            built = built.with_fragment(mtu);
        }
        if let Some(length) = self.padding {
            built = built.with_padding(length);
        }
        if self.bad_checksum {
            built = built.with_bad_tcp_checksum(true);
        }
        if let Some(mac) = self.spoof_mac {
            built = built.with_spoof_mac(mac);
        }
        if let Some(flags) = self.flags {
            built = built.with_flags(flags);
        }

        *evasion = built;
    }
}

/// Reads a set of TCP flags, by name or by number.
///
/// A number, decimal or `0x`-hex, is taken as the byte itself. Otherwise the
/// input is read as flag names — concatenated like `SYNFIN` or joined by `+`,
/// `,` or spaces — each a three-letter abbreviation from the eight a TCP header
/// carries. The two forms cover the two kinds of person who reach for this: one
/// who knows the bit they want, and one who knows the flags by name.
fn scan_flags(text: &str) -> Result<u8, String> {
    let trimmed = text.trim();

    // A number wins where the whole input is one, hex or decimal, so `0x12` and
    // `18` reach the same byte the names `SYNFIN` do.
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u8::from_str_radix(hex, 16)
            .map_err(|_| format!("'{trimmed}' is not a byte in hex (0x00 to 0xff)"));
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return trimmed
            .parse::<u8>()
            .map_err(|_| format!("'{trimmed}' is not a flag byte (0 to 255)"));
    }

    // Names. Every TCP flag abbreviates to three letters, so the input is read
    // three at a time once its separators are gone, and each chunk is one flag.
    let bit = |flag: &str| match flag {
        "FIN" => Some(0x01),
        "SYN" => Some(0x02),
        "RST" => Some(0x04),
        "PSH" => Some(0x08),
        "ACK" => Some(0x10),
        "URG" => Some(0x20),
        "ECE" => Some(0x40),
        "CWR" => Some(0x80),
        _ => None,
    };

    let cleaned: String = trimmed
        .to_ascii_uppercase()
        .chars()
        .filter(|c| !matches!(c, '+' | ',' | ' ' | '-'))
        .collect();

    if cleaned.is_empty() || !cleaned.len().is_multiple_of(3) {
        return Err(format!(
            "'{text}' is not a set of TCP flags: name them like SYNFIN, or give a number"
        ));
    }

    let mut flags = 0u8;
    for chunk in cleaned.as_bytes().chunks(3) {
        let name = std::str::from_utf8(chunk).expect("ascii uppercase stays utf-8");
        match bit(name) {
            Some(value) => flags |= value,
            None => {
                return Err(format!(
                    "'{name}' is not a TCP flag: expected one of FIN SYN RST PSH ACK URG ECE CWR"
                ));
            }
        }
    }

    Ok(flags)
}

/// Reads a positive, finite multiplier into the engine's [`TimeoutScale`].
///
/// Zero asks the scan to wait no time at all and a negative asks for less than
/// that; a NaN compares false against every bound. [`TimeoutScale::new`] is the
/// engine's own gate for exactly these, so refusing them here means the value
/// that reaches the config is one the engine promised it could honour, refused
/// at the edge rather than discovered as a scan that finds nothing.
fn timeout_scale(text: &str) -> Result<TimeoutScale, String> {
    let value: f64 = text
        .parse()
        .map_err(|_| format!("'{text}' is not a number"))?;

    TimeoutScale::new(value).ok_or_else(|| format!("'{text}' must be greater than zero"))
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
        if let Some(rate) = self.min_probe_rate {
            config.min_probe_rate = Some(rate);
        }
        if let Some(budget) = self.host_timeout {
            config.host_timeout = Some(budget);
        }
        if let Some(budget) = self.scan_timeout {
            config.scan_timeout = Some(budget);
        }
        if let Some(mode) = self.send_mode {
            config.send_mode = mode;
        }
        if let Some(name) = &self.send_interface {
            let sources = source_addresses_of(name);
            if !sources.is_empty() {
                config.send_source = sources;
            }
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
        self.evasion.apply_to(&mut config.evasion);
    }
}

impl EngineArgs {
    /// Warns, once the targets are known, about a family among `targets` that
    /// `--send-interface` pins nothing for; see [`unpinned_family`].
    pub(crate) fn warn_unpinned(
        &self,
        config: &ZondConfig,
        targets: impl IntoIterator<Item = std::net::IpAddr>,
    ) {
        let Some(name) = &self.send_interface else {
            return;
        };
        let held: Vec<zond_engine::system::interface::LinkAddress> =
            zond_engine::system::interface::interfaces()
                .into_iter()
                .filter(|link| link.is_up() && !link.is_loopback())
                .flat_map(|link| link.addresses().to_vec())
                .collect();
        if let Some(family) = unpinned_family(&config.send_source, &held, targets) {
            tracing::warn!(
                "{family} targets not pinned: {name} has no {family} (--send-interface)"
            );
        }
    }
}

/// The family of the first of `targets` that a forced source would carry but
/// `forced` holds none for, named for the console.
///
/// A source speaks for its own family only, so a target of a family the
/// interface holds no address of leaves by the routing table, through the VPN
/// the flag was given to avoid. Asked only of the run's own targets, since an
/// interface without IPv6 is the common case and an IPv4 scan loses nothing
/// by it. Loopback and link-local targets, and an IPv4 address written inside
/// IPv6, are no interface's to pin and are passed over. So is a target inside
/// a prefix `held` by one of this host's links: that link is its one route,
/// and the engine sends it there whatever is forced. Nothing forced is nothing
/// to fall short of.
fn unpinned_family(
    forced: &[std::net::IpAddr],
    held: &[zond_engine::system::interface::LinkAddress],
    targets: impl IntoIterator<Item = std::net::IpAddr>,
) -> Option<&'static str> {
    use std::net::IpAddr;

    if forced.is_empty() {
        return None;
    }
    let pinned = |v4: bool| forced.iter().any(|source| source.is_ipv4() == v4);
    let (pin_v4, pin_v6) = (pinned(true), pinned(false));
    targets
        .into_iter()
        .filter(|ip| !held.iter().any(|prefix| prefix.contains(ip)))
        .find(|ip| match ip {
            IpAddr::V4(v4) => !pin_v4 && !v4.is_loopback() && !v4.is_link_local(),
            IpAddr::V6(v6) => {
                !pin_v6
                    && !v6.is_loopback()
                    && !v6.is_unicast_link_local()
                    && v6.to_ipv4_mapped().is_none()
            }
        })
        .map(|ip| if ip.is_ipv4() { "IPv4" } else { "IPv6" })
}

/// The addresses `--send-interface` forces a scan's probes to leave from: the
/// named interface's own, one per family, skipping the loopback and link-local
/// ones no routed target can be reached from. Empty when the name matches no
/// interface or the interface holds nothing usable, which is said in a line
/// naming the interfaces that would serve.
fn source_addresses_of(name: &str) -> Vec<std::net::IpAddr> {
    let links = zond_engine::system::interface::interfaces();
    let sources = links
        .iter()
        .find(|link| link.name() == name)
        .map(sendable_from)
        .unwrap_or_default();

    if sources.is_empty() {
        let reason = if links.iter().any(|link| link.name() == name) {
            "no routable address"
        } else {
            "no such interface"
        };
        let candidates: Vec<String> = links
            .iter()
            .filter(|link| link.is_up() && !sendable_from(link).is_empty())
            .map(|link| link.name().to_owned())
            .collect();
        tracing::warn!(
            "--send-interface {name} ignored: {reason} ({})",
            crate::target::try_instead(&candidates)
        );
    }
    sources
}

/// The addresses a probe can be sent from on `link`, one per family: the
/// first of each that is neither loopback nor link-local, since no routed
/// target can be reached from those.
fn sendable_from(link: &zond_engine::system::interface::Link) -> Vec<std::net::IpAddr> {
    use std::net::IpAddr;

    let mut v4 = None;
    let mut v6 = None;
    for held in link.addresses() {
        match held.address() {
            IpAddr::V4(addr) if v4.is_none() && !addr.is_loopback() && !addr.is_link_local() => {
                v4 = Some(IpAddr::V4(addr));
            }
            IpAddr::V6(addr)
                if v6.is_none() && !addr.is_loopback() && !addr.is_unicast_link_local() =>
            {
                v6 = Some(IpAddr::V6(addr));
            }
            _ => {}
        }
    }
    v4.into_iter().chain(v6).collect()
}

/// How much a run says about itself while it happens.
///
/// Global, so `zond -v discover lan` and `zond discover -v lan` mean the same
/// thing.
// Several independent on/off switches, so the count trips the bool-heavy-struct
// lint for the reason [`ScanArgs`] does: each is one flag a caller sets in any
// combination, and clap derives the parser from exactly these fields.
#[allow(clippy::struct_excessive_bools)]
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

    /// Show the evidence behind every verdict.
    ///
    /// A port says which packet settled it, `SYN/ACK`, `RST`, `ICMP prohibited`
    /// or `no reply`, with the TTL it carried and the round trip it took. A host
    /// says what was observed and, where an ICMP error came from a router rather
    /// than the host itself, which router.
    ///
    /// This separates two verdicts that read alike. A port reported `filtered`
    /// because a firewall said so and one reported `filtered` because nothing
    /// came back are the same word and different findings, and only one of them
    /// is somebody's policy.
    ///
    /// On a live SYN scan it also asks the capture to keep ICMP errors, which
    /// that technique otherwise ignores because its verdict does not need them.
    /// An ICMP error names no ports, so the kernel filter cannot narrow it and
    /// every ICMP packet on every captured link is copied into userspace. That
    /// is the cost of telling a refusal from a silence, and it is paid only when
    /// this is set.
    ///
    /// Works on a scan, on a record, and on a file, including one nmap wrote,
    /// whose own reasons are read back. Not on `--pipe`, whose fields are a
    /// stable interface; a program reads the JSON, which carries all of it
    /// unconditionally.
    #[arg(long = "reason", global = true)]
    pub reason: bool,

    /// The lowest grade of finding to draw.
    ///
    /// A scan turns up more than most runs want to read. `missing HTTP security
    /// headers` is true of most web servers and says the same thing on each, so
    /// a sweep of forty of them is forty rows nobody reads. The floor is
    /// `medium` unless this or `risk` in `cli.toml` says otherwise.
    ///
    /// The count beside a host is never filtered. A host with five findings and
    /// a floor that draws three still says `5 risks`, and the block says how
    /// many it held back: a finding out of sight must not also be out of the
    /// total.
    ///
    /// `info` draws everything. Not on `--pipe` or the exports, which carry
    /// every finding whatever this says.
    ///
    /// [possible values: info, low, medium, high, critical]
    #[arg(long = "risk", global = true, value_name = "GRADE")]
    pub risk: Option<Risk>,

    /// Show what to do about each finding.
    ///
    /// A detection that carries advice hangs it under the finding: which
    /// version to upgrade to, which setting to turn off. Off by default because
    /// it is the one line in a scan addressed to somebody who has stopped
    /// reading and started working, and most of a scan is read before anything
    /// is done about it.
    ///
    /// Spelled `remedy` rather than `fix`, which on a scanner reads as an offer
    /// to make the change rather than to describe it. This tool sends probes and
    /// nothing else.
    #[arg(long = "remedy", global = true)]
    pub remedy: bool,

    /// Show what each detection saw.
    ///
    /// A finding hangs the bytes it was drawn from underneath it: which headers
    /// were absent, which version the banner gave back. It is what separates a
    /// finding worth acting on from one worth arguing with.
    ///
    /// Its own flag rather than part of `--reason`, which answers the same
    /// question about a port's verdict: somebody triaging findings does not want
    /// every port's packet along with them.
    #[arg(long = "evidence", global = true)]
    pub evidence: bool,
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

    /// A service name where a port goes is answered with the numbers to
    /// write, behind the qualifier it was written with, so the hint can be
    /// pasted where the name was. A name the corpus does not know keeps the
    /// grammar's own refusal.
    #[test]
    fn a_service_name_for_a_port_is_answered_with_its_numbers() {
        let ssh = port_set("ssh").expect_err("a name");
        assert!(
            ssh.starts_with("'ssh' is not a port number (write 22"),
            "{ssh}"
        );
        assert!(ssh.ends_with(" for ssh)"), "{ssh}");

        let snmp = port_set("22,U:snmp").expect_err("a name");
        assert!(snmp.contains("(write U:161"), "{snmp}");

        let unknown = port_set("zz-nothing").expect_err("a name");
        assert!(
            unknown.contains("is a name, not a port number"),
            "{unknown}"
        );

        assert!(port_set("22,u:53").is_ok());
    }
    use clap::CommandFactory;

    /// A clap derive can produce a definition that only panics at runtime: a
    /// duplicate id, or a conflict naming an argument that does not exist.
    #[test]
    fn the_command_definition_is_well_formed() {
        Cli::command().debug_assert();
    }

    /// An interface holding only IPv4 pins nothing for IPv6, so a run with a
    /// routed IPv6 target is told that target goes by the routing table rather
    /// than left to believe every probe leaves by the interface. A run with no
    /// such target is told nothing: loopback and link-local targets are no
    /// interface's, and an IPv4 scan loses nothing to the missing family.
    #[test]
    fn a_family_the_interface_cannot_pin_is_named_only_when_a_target_needs_it() {
        let ip = |text: &str| text.parse::<std::net::IpAddr>().expect("a literal");
        let lan_v4 = [ip("192.0.2.10")];

        assert_eq!(
            unpinned_family(&lan_v4, &[], [ip("198.51.100.1"), ip("2001:db8::1")]),
            Some("IPv6")
        );
        assert_eq!(unpinned_family(&lan_v4, &[], [ip("198.51.100.1")]), None);
        assert_eq!(
            unpinned_family(
                &lan_v4,
                &[],
                [ip("::1"), ip("fe80::1"), ip("::ffff:192.0.2.1")]
            ),
            None,
            "no interface's to pin"
        );
        assert_eq!(
            unpinned_family(&[ip("2001:db8::10")], &[], [ip("198.51.100.1")]),
            Some("IPv4")
        );
        assert_eq!(
            unpinned_family(
                &[ip("192.0.2.10"), ip("2001:db8::10")],
                &[],
                [ip("2001:db8::1")]
            ),
            None
        );
        assert_eq!(
            unpinned_family(&[], &[], [ip("2001:db8::1")]),
            None,
            "nothing forced"
        );
    }

    /// A target inside a prefix one of this host's links holds is sent by that
    /// link whatever is forced, so it goes nowhere near the routing table the
    /// warning is about. An IPv6 neighbour on the LAN, scanned with the flag
    /// naming an interface that holds only IPv4, is told nothing; a routed
    /// IPv6 target beside it still is.
    #[test]
    fn an_on_link_target_is_not_warned_about() {
        use zond_engine::system::interface::LinkAddress;

        let ip = |text: &str| text.parse::<std::net::IpAddr>().expect("a literal");
        let lan_v4 = [ip("192.0.2.10")];
        let held = [LinkAddress::new(ip("2001:db8:1::10"), 64)];

        assert_eq!(
            unpinned_family(&lan_v4, &held, [ip("2001:db8:1::20")]),
            None,
            "on-link"
        );
        assert_eq!(
            unpinned_family(&lan_v4, &held, [ip("2001:db8:1::20"), ip("2001:db8:2::1")]),
            Some("IPv6"),
            "routed"
        );
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

        let mut from_file = ZondConfig::default();
        from_file.no_dns = true;
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

    /// `-d` walks the same scale `--detection` names in words, and bare it is the
    /// step that probes what the scan identified.
    ///
    /// The default reads what the scan already gathered and sends nothing, so a
    /// run without this flag is a run whose detections cost no round trips. The
    /// corpus asks a web port about three dozen products by name, one connection
    /// each, and that is a question worth being asked for rather than assumed.
    #[test]
    fn the_detect_step_walks_the_scale_and_does_not_eat_the_target() {
        use zond_engine::model::finding::DetectionClass;

        let ceiling = |args: &[&str]| {
            let cli = Cli::try_parse_from(args).expect("should parse");
            let Command::Scan(scan) = cli.command else {
                panic!("s is the scan alias");
            };
            assert_eq!(scan.targets, ["192.0.2.1"], "the target was eaten");
            let mut config = ZondConfig::default();
            scan.apply_to(&mut config);
            config.detection
        };

        assert!(
            !ceiling(&["zond", "s", "192.0.2.1"]).permits(DetectionClass::ActiveBenign),
            "a scan probes the services it found without being asked to"
        );
        assert_eq!(
            ceiling(&["zond", "s", "-d", "192.0.2.1"]),
            DetectionEnvelope::up_to(DetectionClass::ActiveBenign),
            "bare -d is the step that probes"
        );
        assert_eq!(
            ceiling(&["zond", "s", "-d=0", "192.0.2.1"]),
            DetectionEnvelope::none(),
            "the bottom of the scale runs nothing"
        );
        assert_eq!(
            ceiling(&["zond", "s", "-d=4", "192.0.2.1"]),
            DetectionEnvelope::up_to(DetectionClass::Exploit),
        );

        // The same steps `--detection` names in words, so the two spellings of
        // one dial cannot drift apart.
        for (step, class) in DetectionClass::ALL.into_iter().enumerate() {
            let numbered = format!("-d={}", step + 1);
            assert_eq!(
                ceiling(&["zond", "s", &numbered, "192.0.2.1"]),
                ceiling(&["zond", "s", "--detection", class.label(), "192.0.2.1"]),
                "{numbered} and --detection {} are not the same step",
                class.label()
            );
        }

        assert!(
            Cli::try_parse_from(["zond", "s", "-d=9", "192.0.2.1"]).is_err(),
            "a step past the top of the scale was accepted"
        );
    }

    /// `-d` and a ceiling named outright are two ways of saying the same thing,
    /// and giving both says two things at once. Refused at the parser.
    #[test]
    fn the_detect_step_and_an_explicit_ceiling_cannot_both_be_given() {
        assert!(
            Cli::try_parse_from(["zond", "s", "-d", "--detection", "exploit", "192.0.2.1"])
                .is_err()
        );
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

    /// The two top-ports flags are independent: either may be given alone, and
    /// given together they are two decisions rather than one overwriting the
    /// other. Neither shares a run with `-p`, which names the whole port set
    /// itself.
    #[test]
    fn the_top_ports_flags_stand_alone_or_together_but_not_beside_a_port_list() {
        let both = Cli::try_parse_from([
            "zond",
            "s",
            "10.0.0.1",
            "--top-ports",
            "100",
            "--top-ports-udp",
            "50",
        ])
        .expect("should parse");
        let Command::Scan(args) = both.command else {
            panic!("s is the scan alias");
        };
        assert_eq!(args.top_ports, Some(100));
        assert_eq!(args.top_ports_udp, Some(50));

        let udp_only = Cli::try_parse_from(["zond", "s", "10.0.0.1", "--top-ports-udp", "250"])
            .expect("parses");
        let Command::Scan(args) = udp_only.command else {
            panic!("s is the scan alias");
        };
        assert_eq!(args.top_ports, None);
        assert_eq!(args.top_ports_udp, Some(250));

        assert!(
            Cli::try_parse_from(["zond", "s", "10.0.0.1", "-p", "22", "--top-ports-udp", "50"])
                .is_err(),
            "a port list and a ranked list are two answers to the same question"
        );
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

    /// Both flags that take a length of time read the same units.
    ///
    /// They did not, and the divergence was in the direction that matters: a
    /// watch is the one phase documented as running for days, and `--for 2d` was
    /// the one spelling refused — reported as "not a length of time", which is
    /// the least helpful thing to say about a unit the program next door
    /// accepts. One table now answers for both, and this is what stops a unit
    /// being added to one of them again.
    #[test]
    fn a_length_of_time_means_the_same_thing_to_every_flag_that_takes_one() {
        for (written, expected) in [("45s", 45), ("10m", 600), ("4h", 14_400), ("2d", 172_800)] {
            assert_eq!(
                parse_duration(written).map(|d| d.as_secs()),
                Ok(expected),
                "--for {written}"
            );
            assert_eq!(
                age(written).map(|d| d.as_secs()),
                Ok(expected),
                "--older-than {written}"
            );
        }
    }

    /// A bare number is seconds for a watch and refused for an age, which is the
    /// one place the two are meant to differ.
    ///
    /// `--for 30` reads as thirty seconds and there is nothing else it could
    /// sensibly be. `--older-than 30` reads as thirty of *something*, and
    /// guessing would silently delete records on a scale nobody asked for.
    #[test]
    fn a_bare_number_is_a_watchs_seconds_and_never_an_age() {
        assert_eq!(parse_duration("30").map(|d| d.as_secs()), Ok(30));
        assert!(
            age("30").is_err(),
            "thirty of what? there is no honest guess"
        );
    }

    /// A unit this program does not know is named, rather than reported as a
    /// number that is not a number.
    ///
    /// Which is what splitting on the last character produced: `4hh` had its
    /// final `h` taken as the unit, leaving `4h` to be parsed as digits, so a
    /// typo in the suffix came back as "'4hh' is not a length of time". The
    /// split is on the first non-digit now, so the whole suffix is what gets
    /// quoted back.
    #[test]
    fn an_unknown_unit_is_named_rather_than_blamed_on_the_number() {
        let refused = parse_duration("4hh").expect_err("hh is not a unit");
        assert!(
            refused.contains("'hh'"),
            "the suffix is what was wrong: {refused}"
        );

        let refused = parse_duration("10w").expect_err("weeks are not a unit here");
        assert!(refused.contains("'w'"), "{refused}");
    }

    /// Neither a watch of no time nor one longer than the arithmetic holds.
    ///
    /// The overflow is the one worth the line, and it is not the obvious one. A
    /// count too large to be a number at all is refused when it is parsed; a
    /// count that *is* a number and overflows only once its unit is applied gets
    /// that far, and `value * multiplier` wraps — so `--for 1000000000000000000d`
    /// would quietly become a watch of a few hours. Both flags do the same
    /// multiplication and both are checked.
    #[test]
    fn a_span_of_zero_or_of_more_than_can_be_counted_is_refused() {
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("0m").is_err(), "nor zero of a larger unit");

        // Fits in the count, does not fit once it is days.
        let refused = parse_duration("1000000000000000000d").expect_err("that is not a span");
        assert!(
            refused.contains("longer than"),
            "refused for the right reason: {refused}"
        );
        let refused = age("1000000000000000000d").expect_err("nor is it an age");
        assert!(refused.contains("longer than"), "{refused}");

        // And a count that is not a number at all is still refused, just
        // earlier and for a different reason.
        assert!(parse_duration("99999999999999999999999d").is_err());
    }

    /// The scan-flag reader answers to a name, a concatenation and a number, and
    /// the three that mean the same byte agree.
    #[test]
    fn scan_flags_read_by_name_or_by_number() {
        let syn_fin = 0x02 | 0x01;
        assert_eq!(scan_flags("SYNFIN"), Ok(syn_fin));
        assert_eq!(scan_flags("syn+fin"), Ok(syn_fin));
        assert_eq!(scan_flags("18"), Ok(0x12));
        assert_eq!(scan_flags("0x12"), Ok(0x12));

        // A three-letter chunk that is not a flag is named, and a length that is
        // not a whole number of flags is refused rather than half-read.
        assert!(scan_flags("SYNXYZ").is_err());
        assert!(scan_flags("SY").is_err());
    }

    /// The zombie reader tells an IPv4 port apart from an IPv6 address's colons,
    /// and keeps the probe port where one is given.
    #[test]
    fn an_idle_zombie_reads_its_address_and_optional_port() {
        let bare = idle_scan("192.0.2.9").expect("a bare v4 zombie");
        assert_eq!(
            bare.zombie,
            "192.0.2.9".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(bare.zombie_port, None);

        let ported = idle_scan("192.0.2.9:80").expect("a v4 zombie with a port");
        assert_eq!(ported.zombie_port, Some(80));

        // An IPv6 zombie's colons are its own; a port needs the bracket form.
        let v6 = idle_scan("2001:db8::1").expect("a bare v6 zombie");
        assert_eq!(
            v6.zombie,
            "2001:db8::1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(v6.zombie_port, None);

        let v6_ported = idle_scan("[2001:db8::1]:443").expect("a bracketed v6 zombie");
        assert_eq!(
            v6_ported.zombie,
            "2001:db8::1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(v6_ported.zombie_port, Some(443));
    }

    /// An evasion flag reaches the config, and an absent one leaves what a
    /// profile set alone.
    #[test]
    fn evasion_flags_layer_onto_the_profile() {
        let cli = Cli::try_parse_from([
            "zond",
            "s",
            "192.0.2.1",
            "--ttl",
            "7",
            "--decoy",
            "10.0.0.5,10.0.0.6",
            "--badsum",
        ])
        .expect("should parse");
        let Command::Scan(args) = cli.command else {
            panic!("s is the scan alias");
        };

        let mut config = ZondConfig::default();
        args.apply_to(&mut config);

        assert_eq!(config.evasion.ttl, Some(7));
        assert_eq!(config.evasion.decoys.len(), 2);
        assert!(config.evasion.bad_tcp_checksum);
        // Nothing touched the source port, so it stays unset rather than zeroed.
        assert_eq!(config.evasion.source_port, None);
    }

    /// The scan-only knobs reach the config they name.
    #[test]
    fn the_scan_knobs_reach_the_config() {
        let cli = Cli::try_parse_from([
            "zond",
            "s",
            "192.0.2.1",
            "--tls-enum",
            "--characterise",
            "--sctp-technique",
            "cookie-echo",
            "--ip-protocols",
            "1,6,132",
            "--detection",
            "exploit",
            "--min-probe-rate",
            "50",
            "--scan-timeout",
            "10m",
        ])
        .expect("should parse");
        let Command::Scan(args) = cli.command else {
            panic!("s is the scan alias");
        };

        let mut config = ZondConfig::default();
        args.apply_to(&mut config);

        assert!(config.tls_enumeration);
        assert!(config.characterise);
        assert_eq!(config.sctp_technique, SctpScanTechnique::CookieEcho);
        assert_eq!(config.ip_protocols, [1u8, 6, 132].into_iter().collect());
        assert_eq!(
            config.detection,
            DetectionEnvelope::up_to(zond_engine::model::finding::DetectionClass::Exploit)
        );
        assert_eq!(
            config.min_probe_rate,
            Some(std::num::NonZeroU32::new(50).unwrap())
        );
        assert_eq!(
            config.scan_timeout,
            Some(std::time::Duration::from_secs(600))
        );
    }

    /// A port list that names no port is refused where it is typed, whichever
    /// flag carries it, and says what to write instead.
    ///
    /// Accepted, `-p ''` or `--top-ports 0` plans a scan of nothing, which runs,
    /// probes nothing and exits 0 under a summary of zeros that reads as a
    /// network with nothing on it. An empty `--exclude-ports` excludes nothing,
    /// so it is the same slip: a variable that expanded to nothing.
    #[test]
    fn a_port_list_naming_no_port_is_refused_by_every_flag_that_takes_one() {
        for args in [
            &["-p", ""][..],
            &["-p", ","],
            &["-p", " , "],
            &["--top-ports", "0"],
            &["--top-ports-udp", "0"],
            &["--exclude-ports", ""],
            &["--exclude-ports", ","],
        ] {
            let line = [&["zond", "s", "192.0.2.1"][..], args].concat();
            let error = Cli::try_parse_from(&line)
                .err()
                .unwrap_or_else(|| panic!("{args:?} was accepted"));
            assert!(
                error.to_string().contains("names no ports"),
                "{args:?}: {error}"
            );
        }

        let cli = Cli::try_parse_from(["zond", "s", "192.0.2.1", "--top-ports", "1"]);
        assert!(cli.is_ok(), "one port is a port list");
    }

    /// `--exclude-ports` adds to what the settings file excluded, across
    /// every time it is given, and takes the `-p` grammar.
    ///
    /// Replacing the file's set would send to a port an administrator kept
    /// out, and a second flag replacing the first would do the same to the
    /// user's own.
    #[test]
    fn excluded_ports_add_to_the_settings_and_to_each_other() {
        let cli = Cli::try_parse_from([
            "zond",
            "s",
            "192.0.2.1",
            "--exclude-ports",
            "9100-9107",
            "--exclude-ports",
            "U:161",
        ])
        .expect("should parse");
        let Command::Scan(args) = cli.command else {
            panic!("a scan");
        };
        let mut config = ZondConfig::default();
        config.excluded_ports = "22".parse().expect("a port");
        args.apply_to(&mut config);

        assert_eq!(config.excluded_ports.to_string(), "22,9100-9107,u:161");
    }

    /// A printer's raw-print ports are sent nothing unless the flag says
    /// otherwise, and the flag frees those ports and no others.
    ///
    /// The default is what keeps a scan of a network with a printer on it from
    /// printing, so a parse that cleared it without being asked would print.
    #[test]
    fn the_printers_ports_are_probed_only_when_asked() {
        let parse = |args: &[&str]| {
            let cli = Cli::try_parse_from(args).expect("should parse");
            let Command::Scan(args) = cli.command else {
                panic!("s is the scan alias");
            };
            let mut config = ZondConfig::default();
            config.listen_only_ports.insert(502);
            args.apply_to(&mut config);
            config.listen_only_ports
        };

        let held = parse(&["zond", "s", "192.0.2.1"]);
        assert!(RAW_PRINT_PORTS.iter().all(|port| held.contains(port)));

        let held = parse(&["zond", "s", "192.0.2.1", "--probe-print-ports"]);
        assert_eq!(held, [502].into_iter().collect());
    }
}
