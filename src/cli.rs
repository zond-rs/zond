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
use zond_engine::config::{OsDetection, ScanEffort, SendMode};
use zond_engine::model::technique::TcpScanTechnique;

use crate::diagnostics::Verbosity;
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
}

/// Arguments to `zond discover`.
#[derive(Debug, Args)]
#[command(after_help = discover_help())]
pub(crate) struct DiscoverArgs {
    /// What to scan: an address, a range, a CIDR block, a hostname, or `lan`.
    ///
    /// Several may be given, and each may itself be a comma-separated list.
    #[arg(value_name = "TARGET", required = true, num_args = 1..)]
    pub targets: Vec<String>,

    /// Settings that change what the scan puts on the wire.
    #[command(flatten)]
    pub engine: EngineArgs,
}

/// Arguments to `zond scan`.
#[derive(Debug, Args)]
#[command(after_help = scan_help())]
pub(crate) struct ScanArgs {
    /// What to scan: an address, a range, a CIDR block, a hostname, or `lan`.
    ///
    /// A target may carry its own ports — `10.0.0.1:8080`, or
    /// `[2001:db8::1]:443` — and keeps them; `--ports` supplies the rest.
    #[arg(value_name = "TARGET", required = true, num_args = 1..)]
    pub targets: Vec<String>,

    /// Which ports to probe: `22,80,443`, `1-1024`, `u:53` for UDP.
    ///
    /// Defaults to `default_ports` in the settings file, and to the well-known
    /// range when that says nothing either.
    #[arg(short = 'p', long, value_name = "PORTS")]
    pub ports: Option<PortSet>,

    /// Scan every target without checking first that anything is there.
    ///
    /// A scan normally probes each address for liveness — the same probes
    /// `zond discover` sends, against those addresses only — and skips the ones
    /// that answer nothing, because an address nothing lives at costs a probe
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
";

/// How a run is stopped, shown under both subcommands.
const STOPPING: &str = "
Stopping a run:
  q, or Ctrl-C, stops the scan and reports what was found so far. Either again
  leaves without waiting for the probes still in flight. Reading a keypress
  needs a terminal; in a pipe or a script, Ctrl-C is the one that works.
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
",
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
  sudo zond s 192.168.0.0/24 -p 1-1024
  sudo zond s 10.0.0.1:8080 lan -p 80,443
  sudo zond s 2001:db8::1 -p u:53

A scan checks each target is there before probing its ports, and skips the ones
that answer nothing. --assume-up scans them anyway.
",
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
pub(crate) struct EngineArgs {
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
    /// knowing which device is which — a client, an auditor, a screenshot in an
    /// issue. The scan still finds everything; only what leaves this process is
    /// masked.
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
    /// Does not touch the shortest timeout a protocol allows: that floor is not
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
    /// `passive` sends nothing of its own. `active` and above send probes and
    /// have to be asked for.
    ///
    /// [possible values: off, passive, active, aggressive]
    #[arg(long, value_name = "LEVEL")]
    pub os_detection: Option<OsDetection>,

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
    /// `false`. An absent flag must not cancel a setting from a file — which is
    /// why the dampening flag is `--no-dampen` and not `--dampen`.
    ///
    /// [`segment_sweep`](ZondConfig::segment_sweep) is neither a flag nor a file
    /// entry; it comes from the targets, via
    /// [`Targets::apply_to`](crate::target::Targets::apply_to).
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
    /// `pipe` and `minimal` are built; `standard` and `fancy` are named and
    /// refused rather than quietly served as something else.
    ///
    /// [possible values: pipe, minimal, standard, fancy]
    #[arg(long, value_name = "MODE", global = true)]
    pub presentation: Option<Presentation>,

    /// Shorthand for `--presentation pipe`.
    ///
    /// Tab-separated records with every field a scan established, no padding and
    /// no heading.
    #[arg(long, global = true, conflicts_with = "presentation")]
    pub pipe: bool,
}

impl OutputArgs {
    /// The verbosity these arguments ask for.
    #[must_use]
    pub(crate) fn verbosity(&self) -> Verbosity {
        Verbosity::new(self.verbose, self.quiet)
    }

    /// The presentation to use, given what the settings files said.
    ///
    /// The flag wins, then the file, then the built-in default — the same order
    /// every other setting layers in.
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

    /// A clap derive can produce a definition that only panics at runtime — a
    /// duplicate id, a conflict naming an argument that does not exist.
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
        let with_flag = Cli::try_parse_from(["zond", "--presentation", "fancy", "d", "lan"])
            .expect("should parse");
        assert_eq!(
            with_flag.output.presentation(Some(Presentation::Minimal)),
            Presentation::Fancy
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

    #[test]
    fn a_target_is_required() {
        assert!(Cli::try_parse_from(["zond", "discover"]).is_err());
    }
}
