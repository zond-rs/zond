// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a target expression stands for
//!
//! Turning what someone typed on the command line into the addresses a scan will
//! probe.
//!
//! Almost none of that happens here. [`zond_engine::resolve::for_discovery`] is
//! one call that parses the expressions, reads this host's interface table for
//! `lan` and for the `%interface` suffix, resolves any hostnames, and works out
//! whether a segment sweep was asked for. This module supplies the two things
//! that are genuinely a front end's to decide, and nothing else:
//!
//! - **Whether names may be looked up at all.** Resolving `one.one.one.one`
//!   sends a query to a resolver somebody operates, which on an engagement can
//!   be the thing that announces the scan. `-n` forbids it, and that is a policy
//!   the engine cannot hold for us.
//! - **How much one run may sweep.** See [`MAX_IPV4_ADDRESSES`].
//!
//! The engine refuses what *cannot be done* — a range no strategy can walk.
//! This module refuses what is merely *unreasonable*, which is a judgement about
//! a person's time, and it holds that judgement to IPv4: a privileged sweep of
//! an on-link IPv6 `/64` is one packet, not eighteen quintillion probes.
//!
//! ## One phase is resolved for us, the other is assembled here
//!
//! [`resolve::for_discovery`] is a single call: it wires this host's interface
//! table for `lan` and `%en0`, resolves names, and works out whether a network
//! was named. The engine offers no such call for a port scan, so [`resolve_ports`]
//! assembles the same pieces by hand — the same context, the same keyword test.
//!
//! [`Asked`] is where the two phases meet. Whatever the expressions settle is
//! held and written in one place, so the phases cannot answer it differently.

use std::fmt;

use zond_engine::model::parse::ip::{Keyword, ResolverFn, ZoneResolverFn, names_keyword};
use zond_engine::model::parse::target::{self as engine_parse, TargetContext, TargetParseError};
use zond_engine::resolve;
use zond_engine::system::interface;
use zond_engine::{IpSet, PortSet, Resolver, TargetMap, ZondConfig};

/// The most IPv4 addresses one run will accept: a `/12` exactly.
///
/// IPv4 is swept one address at a time, and a range can be written down far
/// faster than it can be walked — `10.0.0.0/8` is sixteen million addresses and
/// hours of probing. A guard against a mistyped prefix, not a policy about how
/// much anyone may scan. IPv6 is not bounded here; see the module docs.
pub(crate) const MAX_IPV4_ADDRESSES: u128 = 1 << 20;

/// A target expression that could not be turned into addresses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum TargetError {
    /// The expression is not one the engine's grammar accepts, or names
    /// something this host cannot resolve.
    #[error("{0}")]
    Parse(#[from] TargetParseError),

    /// The expression is a hostname, and this run was told to send no DNS.
    ///
    /// Separate from the parse errors so the message can name what is
    /// responsible. The engine says only that no host lookup was supplied, which
    /// is not what the person did.
    #[error(
        "'{expression}' is a hostname, and this run may not send DNS — from \
         --no-dns, or `no_dns` in engine.toml. Give its address instead, or \
         allow DNS."
    )]
    NameNeedsDns {
        /// The expression as it was written.
        expression: String,
    },

    /// The expression is well formed and names more IPv4 addresses than one run
    /// will take. See [`MAX_IPV4_ADDRESSES`].
    #[error(
        "{expression} covers {requested} IPv4 addresses, more than one run will \
         sweep (the limit is {limit}). Give a smaller prefix, a range, or the \
         specific addresses you mean."
    )]
    TooLarge {
        /// The expressions as they were written.
        expression: String,
        /// How many IPv4 addresses they cover.
        requested: u128,
        /// The limit they exceeded.
        limit: u128,
    },

    /// The expression is well formed and names more probes than one port scan
    /// will spend. See [`MAX_PROBES`].
    #[error(
        "{expression} comes to {requested} probes, more than one scan will spend \
         (the limit is {limit}). Narrow the addresses, the ports, or both."
    )]
    TooManyProbes {
        /// The expressions as they were written.
        expression: String,
        /// How many probes they come to.
        requested: u128,
        /// The limit they exceeded.
        limit: u128,
    },
}

/// What a run was asked about, and what the asking settles.
///
/// Held by both phases. They resolve to different things — a set of addresses,
/// or a map of addresses to ports — but they are asked in the same words, and
/// the words decide the same settings.
#[derive(Debug, Clone)]
struct Asked {
    expressions: Vec<String>,
    segment_sweep: bool,
}

impl Asked {
    /// From the expressions alone, working out for itself what they settle.
    ///
    /// What the port scan uses, because nothing resolved it on the way — where
    /// a sweep is handed the answer by [`resolve::for_discovery`] and passes it
    /// to [`new`](Self::new) rather than deriving it twice.
    fn from_expressions<S: AsRef<str>>(expressions: &[S]) -> Self {
        Self::new(expressions, names_keyword(expressions, Keyword::Lan))
    }

    /// The expressions as written, trimmed, with what they imply.
    fn new<S: AsRef<str>>(expressions: &[S], segment_sweep: bool) -> Self {
        Self {
            expressions: expressions
                .iter()
                .map(|expression| expression.as_ref().trim().to_owned())
                .collect(),
            segment_sweep,
        }
    }

    /// Writes what these targets imply into `cfg`.
    ///
    /// A mirror of the engine's
    /// [`DiscoveryTargets::apply_to`](zond_engine::resolve::DiscoveryTargets::apply_to),
    /// which the port
    /// scan has no equivalent of. **If the engine's ever writes a second
    /// setting, this is the one place here that has to hear about it** — and it
    /// is one place rather than two so that it cannot be half-heard.
    fn apply_to(&self, cfg: &mut ZondConfig) {
        cfg.segment_sweep = self.segment_sweep;
    }
}

impl fmt::Display for Asked {
    /// The expressions as they were written, which is what the user recognises.
    /// The set they expanded to can be millions of addresses and is never what a
    /// header line should print.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.expressions.join(", "))
    }
}

/// What a discovery sweep was asked to cover.
#[derive(Debug, Clone)]
pub(crate) struct Targets {
    asked: Asked,
    ips: IpSet,
}

impl Targets {
    /// Takes the addresses, for handing to the engine.
    #[must_use]
    pub(crate) fn into_ips(self) -> IpSet {
        self.ips
    }

    /// How many addresses this covers.
    #[must_use]
    pub(crate) fn len(&self) -> u128 {
        self.ips.len()
    }

    /// Writes what these targets imply into `cfg`.
    pub(crate) fn apply_to(&self, cfg: &mut ZondConfig) {
        self.asked.apply_to(cfg);
    }
}

impl fmt::Display for Targets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.asked.fmt(f)
    }
}

/// Resolves target expressions against this host.
///
/// `resolve_names` is the DNS policy: with it, a hostname is looked up and
/// becomes the addresses it stands for; without it, a hostname is refused rather
/// than quietly dropped, because a scan that covers less than its input said it
/// covers is a wrong answer that looks like a right one.
pub(crate) async fn resolve<S: AsRef<str>>(
    expressions: &[S],
    resolve_names: bool,
) -> Result<Targets, TargetError> {
    // Constructing one reads the host's resolver configuration, which a run
    // forbidden from sending DNS should not touch at all.
    let resolver = resolve_names.then(Resolver::from_system);

    let discovery = resolve::for_discovery(expressions, resolver.as_ref())
        .await
        .map_err(name_needs_dns)?;

    // The engine worked out whether a network was named; this does not ask the
    // question a second time and risk a second answer.
    let asked = Asked::new(expressions, discovery.segment_sweep());

    let requested = discovery.ips().v4_len();
    if requested > MAX_IPV4_ADDRESSES {
        return Err(TargetError::TooLarge {
            expression: asked.to_string(),
            requested,
            limit: MAX_IPV4_ADDRESSES,
        });
    }

    Ok(Targets {
        asked,
        ips: discovery.into_ips(),
    })
}

/// Restates the engine's "no host lookup was supplied" as the flag that caused
/// it, which is the sentence a user can act on.
fn name_needs_dns(error: TargetParseError) -> TargetError {
    match error {
        TargetParseError::NoHostLookup(expression) => TargetError::NameNeedsDns { expression },
        other => TargetError::Parse(other),
    }
}

/// The most probes one port scan will accept: four million.
///
/// Cost is addresses times ports, and the product grows in a way the two numbers
/// separately do not look like — a `/16` is a reasonable sweep, and a `/16` on a
/// thousand ports is sixty-seven million probes. The same guard as
/// [`MAX_IPV4_ADDRESSES`], applied to the number that decides how long a scan
/// takes.
pub(crate) const MAX_PROBES: u128 = 1 << 22;

/// What a port scan was asked to cover.
///
/// A separate type from [`Targets`] because an expression may carry its own
/// ports, so a run is a set of (addresses, ports) units rather than one list and
/// one port set.
#[derive(Debug, Clone)]
pub(crate) struct ScanTargets {
    asked: Asked,
    map: TargetMap,
}

impl ScanTargets {
    /// The map to hand the engine.
    #[must_use]
    pub(crate) fn into_map(self) -> TargetMap {
        self.map
    }

    /// How many probes this comes to: addresses times ports, across every unit.
    #[must_use]
    pub(crate) fn probes(&self) -> u128 {
        self.map.gross_targets().unwrap_or(u128::MAX)
    }

    /// How many addresses this covers.
    #[must_use]
    pub(crate) fn hosts(&self) -> u128 {
        self.map.gross_ips().unwrap_or(u128::MAX)
    }

    /// Writes what these targets imply into `cfg`.
    pub(crate) fn apply_to(&self, cfg: &mut ZondConfig) {
        self.asked.apply_to(cfg);
    }
}

impl fmt::Display for ScanTargets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.asked.fmt(f)
    }
}

/// The lookups a target expression may need from this host: what `lan` stands
/// for, and which interface a `%zone` names.
///
/// The engine wires these itself for a discovery sweep. There is no equivalent
/// entry point for a port scan, so this is the front end assembling the same
/// context — see the module documentation.
fn host_context() -> TargetContext<'static> {
    const KEYWORDS: ResolverFn<'static> = &interface::resolve_keyword;
    const ZONES: ZoneResolverFn<'static> = &interface::resolve_zone;

    TargetContext {
        keywords: Some(KEYWORDS),
        zones: Some(ZONES),
        hosts: None,
    }
}

/// Resolves target expressions into addresses and the ports to try on each.
///
/// `ports` is the *default*: an expression naming its own — `10.0.0.1:8080`, or
/// `[2001:db8::1]:443` — keeps them, and everything else gets these.
pub(crate) async fn resolve_ports<S: AsRef<str>>(
    expressions: &[S],
    ports: PortSet,
    resolve_names: bool,
) -> Result<ScanTargets, TargetError> {
    let context = host_context();

    let map = match resolve_names.then(Resolver::from_system) {
        Some(resolver) => resolve::to_target_map(expressions, ports, &context, &resolver)
            .await
            .map_err(name_needs_dns)?,
        None => {
            engine_parse::to_target_map(expressions, ports, &context).map_err(name_needs_dns)?
        }
    };

    // The same question the engine answers for a sweep, asked the same way.
    let targets = ScanTargets {
        asked: Asked::from_expressions(expressions),
        map,
    };

    let requested = targets.probes();
    if requested > MAX_PROBES {
        return Err(TargetError::TooManyProbes {
            expression: targets.to_string(),
            requested,
            limit: MAX_PROBES,
        });
    }

    Ok(targets)
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
    use std::net::{IpAddr, Ipv4Addr};

    /// Literal addresses need no lookups, so every test here runs without a
    /// network and without an interface table. What `lan` means is the engine's
    /// to test.
    async fn offline<S: AsRef<str>>(expressions: &[S]) -> Result<Targets, TargetError> {
        resolve(expressions, false).await
    }

    #[tokio::test]
    async fn a_cidr_block_covers_every_address_in_it() {
        let targets = offline(&["192.168.0.0/24"])
            .await
            .expect("a well-formed block");
        assert_eq!(targets.len(), 256);
        assert!(
            targets
                .into_ips()
                .contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255)))
        );
    }

    /// If this stopped meaning `.1` through `.50`, a scan would silently cover a
    /// different range than the one asked about.
    #[tokio::test]
    async fn a_shortened_range_ends_where_its_last_octets_say() {
        let targets = offline(&["192.168.0.1-50"])
            .await
            .expect("a well-formed range");
        assert_eq!(targets.len(), 50);

        let ips = targets.into_ips();
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 50))));
        assert!(!ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 51))));
    }

    #[tokio::test]
    async fn several_expressions_and_comma_separated_lists_are_one_set() {
        let targets = offline(&["10.0.0.1,10.0.0.2", "10.0.0.3"])
            .await
            .expect("well-formed");
        assert_eq!(targets.len(), 3);
    }

    #[tokio::test]
    async fn an_ipv6_address_and_prefix_are_targets_like_any_other() {
        let single = offline(&["2001:db8::1"])
            .await
            .expect("a well-formed address");
        assert_eq!(single.len(), 1);

        let prefix = offline(&["2001:db8::/120"])
            .await
            .expect("a well-formed prefix");
        assert_eq!(prefix.len(), 256);
    }

    /// Both phases write the same setting from the same words. They are two
    /// types because they resolve to different things, not because they settle
    /// different questions — and only one of them has an engine call that does
    /// the settling for it.
    #[test]
    fn both_phases_write_the_same_settings() {
        for sweep in [false, true] {
            let asked = Asked::new(&["lan"], sweep);

            let discovery = Targets {
                asked: asked.clone(),
                ips: IpSet::new(),
            };
            let port_scan = ScanTargets {
                asked,
                map: TargetMap::default(),
            };

            let mut from_discovery = ZondConfig::default();
            let mut from_port_scan = ZondConfig::default();
            discovery.apply_to(&mut from_discovery);
            port_scan.apply_to(&mut from_port_scan);

            assert_eq!(from_discovery.segment_sweep, sweep);
            assert_eq!(from_port_scan.segment_sweep, sweep);
        }
    }

    /// The derivation a port scan does for itself, since nothing resolved it on
    /// the way. Needs no interface table: it reads the words, not the network.
    #[test]
    fn a_port_scan_reads_the_sweep_out_of_the_expressions() {
        assert!(Asked::from_expressions(&["lan"]).segment_sweep);
        assert!(Asked::from_expressions(&["LAN"]).segment_sweep, "case");
        assert!(
            Asked::from_expressions(&["10.0.0.1,lan"]).segment_sweep,
            "a comma-separated list is still a list of targets"
        );
        assert!(!Asked::from_expressions(&["10.0.0.0/24"]).segment_sweep);
    }

    /// A setting a lower layer wrote must not survive targets that say otherwise:
    /// `segment_sweep` comes from what was typed, so it is written either way
    /// rather than only when true.
    #[test]
    fn targets_that_name_no_network_turn_the_sweep_off_again() {
        let mut config = ZondConfig {
            segment_sweep: true,
            ..ZondConfig::default()
        };

        Asked::new(&["10.0.0.1"], false).apply_to(&mut config);
        assert!(!config.segment_sweep);
    }

    /// What is quoted back is what was typed, not what it expanded to.
    #[tokio::test]
    async fn a_message_quotes_the_expressions_back() {
        let targets = offline(&[" 10.0.0.1 ", "192.168.0.0/30"])
            .await
            .expect("well-formed");

        assert_eq!(targets.to_string(), "10.0.0.1, 192.168.0.0/30");
        assert_eq!(targets.len(), 5, "one address plus a /30");
    }

    #[tokio::test]
    async fn something_that_is_not_a_target_is_refused() {
        assert!(matches!(
            offline(&["192.168.0.300"]).await,
            Err(TargetError::Parse(_))
        ));
    }

    /// The message has to name the flag: told only that "no host lookup was
    /// supplied", a user goes looking for a lookup to supply.
    #[tokio::test]
    async fn a_hostname_under_no_dns_names_the_flag_responsible() {
        let refused = offline(&["one.one.one.one"]).await;

        let Err(error @ TargetError::NameNeedsDns { .. }) = refused else {
            panic!("a hostname cannot be resolved with DNS forbidden");
        };
        let message = error.to_string();
        assert!(message.contains("one.one.one.one"), "got {message:?}");
        assert!(message.contains("--no-dns"), "got {message:?}");
        assert!(message.contains("engine.toml"), "got {message:?}");
    }

    /// The limit is exactly a `/12`, not one address short of it.
    #[tokio::test]
    async fn the_largest_accepted_ipv4_range_is_accepted() {
        let accepted = offline(&["10.0.0.0/12"])
            .await
            .expect("a /12 is within the limit");
        assert_eq!(accepted.len(), MAX_IPV4_ADDRESSES);
    }

    #[tokio::test]
    async fn an_ipv4_range_beyond_the_limit_is_refused() {
        let refused = offline(&["10.0.0.0/8"]).await;

        let Err(TargetError::TooLarge { requested, .. }) = refused else {
            panic!("a /8 is more than one run will sweep");
        };
        assert_eq!(requested, 1 << 24);
    }

    /// A `/64` is not refused here: with root on the local segment it is one
    /// all-nodes echo rather than a walk.
    #[tokio::test]
    async fn a_large_ipv6_prefix_is_left_for_the_engine_to_judge() {
        let accepted = offline(&["2001:db8::/64"])
            .await
            .expect("this is the engine's call, not this module's");
        assert_eq!(accepted.len(), 1u128 << 64);
    }
}
