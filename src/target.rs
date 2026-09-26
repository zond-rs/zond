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
//! ## Exclusions are resolved here too
//!
//! `--exclude` takes the same grammar as a target, so it is parsed by the same
//! module: one place decides what `10.0.0.0/24`, `lan` and `%en0` mean, and the
//! two halves of a scope cannot come out meaning different things. It also
//! shares the DNS policy, since resolving a name to exclude sends exactly the
//! query resolving a name to scan does.
//!
//! **What is measured here is the scan after the exclusions, and what is handed
//! to the engine is the scan before them.** The size guards and the header line
//! are about how long a run will take and how much it covers, which is the
//! narrowed number; the engine is given the full set and its own policy so that
//! it performs the subtraction itself and its report says what the subtraction
//! cost. Narrowing here as well would leave every report this program produces
//! claiming a policy withheld nothing.
//!
//! The engine refuses what *cannot be done*, such as a range no strategy can
//! walk. This module refuses what is merely *unreasonable*, which is a judgement
//! about a person's time, and it holds that judgement to IPv4: a privileged
//! sweep of an on-link IPv6 `/64` is one packet, not eighteen quintillion
//! probes.
//!
//! ## One phase is resolved for us, the other is assembled here
//!
//! [`resolve::for_discovery`] is a single call: it wires this host's interface
//! table for `lan` and `%en0`, resolves names, and works out whether a network
//! was named. The engine offers no such call for a port scan, so
//! [`resolve_ports`] assembles the same pieces by hand, from the same context
//! and the same keyword test.
//!
//! [`Asked`] is where the two phases meet. Whatever the expressions settle is
//! held and written in one place, so the phases cannot answer it differently.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use zond_engine::model::parse::ip::{
    IpParseError, Keyword, ResolverFn, ZoneResolverFn, names_keyword,
};
use zond_engine::model::parse::target::{TargetContext, TargetParseError};
use zond_engine::resolve;
use zond_engine::system::interface;
use zond_engine::{Exclusions, IpSet, PortSet, Resolver, TargetMap, ZondConfig};

/// The most IPv4 addresses one run will accept: a `/12` exactly.
///
/// IPv4 is swept one address at a time, and a range can be written down far
/// faster than it can be walked: `10.0.0.0/8` is sixteen million addresses and
/// hours of probing. This is a guard against a mistyped prefix, not a policy
/// about how much anyone may scan. IPv6 is not bounded here; see the module
/// documentation.
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
        "'{expression}' is a hostname, and this run may not send DNS, because of \
         --no-dns or `no_dns` in engine.toml. Give its address instead, or allow \
         DNS."
    )]
    NameNeedsDns {
        /// The expression as it was written.
        expression: String,
    },

    /// A link-local target named an interface this machine does not have.
    ///
    /// Restated with the interfaces it could have named, which the engine's
    /// error cannot carry: the lookup it asks answers one name and lists none.
    #[error("'{expression}': no interface named {name} ({})", try_instead(.candidates))]
    UnknownInterface {
        /// The expression as it was written.
        expression: String,
        /// The interface it named.
        name: String,
        /// The interfaces that are up, reach a segment with neighbours on it
        /// and hold a link-local IPv6 address, which is what a scoped target
        /// is sent out of.
        candidates: Vec<String>,
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

    /// The exclusions cover every address the targets name, leaving nothing.
    ///
    /// Reported rather than run, because a scan of no addresses is not a
    /// finding and the shape of the mistake is usually a typo in the exclusion
    /// rather than a scope that genuinely excludes itself.
    #[error(
        "every address {expression} names is excluded, so there is nothing to \
         scan. Check --exclude, and `exclude` in engine.toml."
    )]
    EverythingExcluded {
        /// The target expressions as they were written.
        expression: String,
    },

    /// The excluded ports cover every port the targets would be asked on,
    /// leaving nothing to send.
    ///
    /// Reported rather than run for the reason
    /// [`EverythingExcluded`](Self::EverythingExcluded) is: a scan that asked
    /// nothing reads as one that found nothing.
    #[error("every port {expression} is asked on is excluded (--exclude-ports)")]
    EveryPortExcluded {
        /// The target expressions as they were written.
        expression: String,
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
/// Held by both phases. They resolve to different things, a set of addresses or
/// a map of addresses to ports, but they are asked in the same words, and the
/// words decide the same settings.
#[derive(Debug, Clone)]
struct Asked {
    expressions: Vec<String>,
    segment_sweep: bool,
    exclusions: Exclusions,
}

impl Asked {
    /// From the expressions alone, working out for itself what they settle.
    ///
    /// What the port scan uses, because nothing resolved it on the way. A sweep
    /// is handed the answer by [`resolve::for_discovery`] and passes it to
    /// [`new`](Self::new) rather than deriving it twice.
    fn from_expressions<S: AsRef<str>>(expressions: &[S], exclusions: Exclusions) -> Self {
        Self::new(
            expressions,
            names_keyword(expressions, Keyword::Lan),
            exclusions,
        )
    }

    /// The expressions as written, trimmed, with what they imply.
    fn new<S: AsRef<str>>(expressions: &[S], segment_sweep: bool, exclusions: Exclusions) -> Self {
        Self {
            expressions: expressions
                .iter()
                .map(|expression| expression.as_ref().trim().to_owned())
                .collect(),
            segment_sweep,
            exclusions,
        }
    }

    /// Writes what these targets imply into `cfg`.
    ///
    /// A mirror of the engine's
    /// [`DiscoveryTargets::apply_to`](zond_engine::resolve::DiscoveryTargets::apply_to),
    /// which the port scan has no equivalent of. **If the engine's ever writes a
    /// second setting, this is the one place here that has to hear about it.**
    /// It is one place rather than two so that it cannot be half-heard.
    fn apply_to(&self, cfg: &mut ZondConfig) {
        cfg.segment_sweep = self.segment_sweep;

        // Added rather than assigned, which is the opposite of the line above
        // and deliberate. `segment_sweep` is what the target expression means,
        // so targets naming no network have to turn it back off; an exclusion
        // is a thing somebody forbade, and a layer that could cancel one is a
        // layer that can put a forbidden range back into a scan. The engine
        // makes the same argument at `Exclusions::extend`, where a settings
        // file must not be able to drop the range above it.
        cfg.exclusions.extend(&self.exclusions);
    }
}

/// How much of a header line the target expressions may take, in characters.
///
/// The first is always shown, since it is what the user checks they typed;
/// the rest are counted once they would run past this, so the line stays one
/// short line however many targets were named.
const EXPRESSIONS_SHOWN: usize = 24;

impl fmt::Display for Asked {
    /// The expressions as they were written, which is what the user recognises.
    /// The set they expanded to can be millions of addresses and is never what a
    /// header line should print. Capped at [`EXPRESSIONS_SHOWN`], the rest
    /// counted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut written = 0;
        for (index, expression) in self.expressions.iter().enumerate() {
            if index > 0 {
                if written + 2 + expression.len() > EXPRESSIONS_SHOWN {
                    return write!(f, ", +{} more", self.expressions.len() - index);
                }
                f.write_str(", ")?;
                written += 2;
            }
            f.write_str(expression)?;
            written += expression.len();
        }
        Ok(())
    }
}

/// What a discovery sweep was asked to cover.
#[derive(Debug, Clone)]
pub(crate) struct Targets {
    asked: Asked,
    ips: IpSet,
    remaining: u128,
}

impl Targets {
    /// The addresses a resumed sweep has left, from the plan its record held.
    ///
    /// `remaining` rather than the plan's own size: a sweep with four hundred
    /// addresses left should not announce sixty-five thousand. `label` is what
    /// the header line shows, since there are no expressions. Nobody typed
    /// anything but an id.
    ///
    /// The exclusions are empty because the record's plan already has them
    /// applied; saying so again would report a policy withholding what it
    /// withheld a sitting ago.
    #[must_use]
    pub(crate) fn resumed(ips: IpSet, remaining: u128, label: String) -> Self {
        Self {
            asked: Asked {
                expressions: vec![label],
                segment_sweep: false,
                exclusions: Exclusions::none(),
            },
            ips,
            remaining,
        }
    }

    /// Takes the addresses, for handing to the engine.
    ///
    /// The full set, before exclusions. The engine is given the policy too and
    /// applies it itself; see the module documentation for why it is not
    /// applied twice.
    #[must_use]
    pub(crate) fn into_ips(self) -> IpSet {
        self.ips
    }

    /// The same addresses, borrowed.
    ///
    /// For what has to read the plan before the sweep takes it, such as a
    /// journal recording what this run was pointed at.
    #[must_use]
    pub(crate) fn ips(&self) -> &IpSet {
        &self.ips
    }

    /// How many addresses this run will actually walk.
    ///
    /// After exclusions, which is what a header line saying how much ground is
    /// about to be covered has to mean.
    #[must_use]
    pub(crate) fn len(&self) -> u128 {
        self.remaining
    }

    /// What the exclusion policy keeps out of this run, if anything.
    #[must_use]
    pub(crate) fn exclusions(&self) -> &Exclusions {
        &self.asked.exclusions
    }

    /// How many addresses the exclusions take out of what was named.
    #[must_use]
    pub(crate) fn excluded(&self) -> u128 {
        self.ips.len().saturating_sub(self.remaining)
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
pub(crate) async fn resolve<S: AsRef<str>, E: AsRef<str>>(
    expressions: &[S],
    exclude: &[E],
    inherited: &Exclusions,
    resolve_names: bool,
) -> Result<Targets, TargetError> {
    // Resolving with one reads the host's resolver configuration and asks its
    // servers, which a run forbidden from sending DNS should not touch at all.
    // Shared by both halves of the grammar: a name to keep out costs the same
    // query as a name to scan.
    let resolver = resolve_names.then(Resolver::from_system);

    let discovery = resolve::for_discovery(expressions, resolver.as_ref())
        .await
        .map_err(restate)?;
    let exclusions = inherit(inherited, exclude, resolver.as_ref()).await?;

    // The engine worked out whether a network was named; this does not ask the
    // question a second time and risk a second answer.
    let asked = Asked::new(expressions, discovery.segment_sweep(), exclusions);

    let ips = discovery.into_ips();

    // A measurement, on a copy, and then discarded. What the guard and the
    // header both want is the ground this run will actually cover, and the
    // engine wants the set as it was named. So the subtraction is performed here
    // to be counted and there to be enforced.
    let mut walked = ips.clone();
    asked.exclusions.withhold(&mut walked);
    let remaining = walked.len();

    if remaining == 0 && !ips.is_empty() {
        return Err(TargetError::EverythingExcluded {
            expression: asked.to_string(),
        });
    }

    let requested = walked.v4_len();
    if requested > MAX_IPV4_ADDRESSES {
        return Err(TargetError::TooLarge {
            expression: asked.to_string(),
            requested,
            limit: MAX_IPV4_ADDRESSES,
        });
    }

    Ok(Targets {
        asked,
        ips,
        remaining,
    })
}

/// The whole exclusion policy in force: what the settings files already
/// forbade, plus what this command line adds.
///
/// **Both layers, not just the flag.** The counts this module produces are what
/// the run will cover and what the size guards are checked against, and the
/// ranges it holds are what the header prints for somebody to check against a
/// scope document. A policy assembled from the flag alone would under-report
/// both, giving a scan whose header omitted a range that was nonetheless in
/// force. That is the one kind of wrong this feature exists to prevent, and the
/// engine applies the union either way, so the discrepancy would be silent.
///
/// Unions rather than replaces, for the reason
/// [`Exclusions::extend`](zond_engine::Exclusions::extend) gives.
async fn inherit<E: AsRef<str>>(
    inherited: &Exclusions,
    exclude: &[E],
    resolver: Option<&Resolver>,
) -> Result<Exclusions, TargetError> {
    let mut exclusions = inherited.clone();
    exclusions.extend(
        &resolve::for_exclusion(exclude, resolver)
            .await
            .map_err(restate)?,
    );
    Ok(exclusions)
}

/// The hint closing a message about an interface that does not exist: the
/// ones that do and would serve, or that none does.
pub(crate) fn try_instead(candidates: &[String]) -> String {
    if candidates.is_empty() {
        "none here would serve".to_owned()
    } else {
        format!("try {}", candidates.join(", "))
    }
}

/// Restates what the engine can only say in its own terms as what the user
/// can act on: "no host lookup was supplied" as the flag that caused it, and
/// an unknown interface with the ones this machine has.
fn restate(error: TargetParseError) -> TargetError {
    match error {
        TargetParseError::NoHostLookup(expression) => TargetError::NameNeedsDns { expression },
        TargetParseError::Address {
            expression,
            source: IpParseError::UnknownInterface(name),
        } => {
            let candidates = interface::interfaces()
                .into_iter()
                .filter(|link| {
                    link.is_up()
                        && link.is_broadcast()
                        && link.addresses().iter().any(|held| {
                            matches!(held.address(), IpAddr::V6(v6) if v6.is_unicast_link_local())
                        })
                })
                .map(|link| link.name().to_owned())
                .collect();
            TargetError::UnknownInterface {
                expression,
                name,
                candidates,
            }
        }
        other => TargetError::Parse(other),
    }
}

/// The most probes one port scan will accept: four million.
///
/// Cost is addresses times ports, and the product grows in a way neither number
/// looks like on its own: a `/16` is a reasonable sweep, and a `/16` on a
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
    /// The name each address was reached by, where an expression named a
    /// host; see [`ZondConfig::target_names`].
    names: BTreeMap<IpAddr, String>,
    probes: u128,
    hosts: u128,
}

impl ScanTargets {
    /// The targets a resumed scan has left, from the plan its record held.
    ///
    /// `remaining` rather than the plan's own size: a run that has sixty
    /// thousand ports left should not announce sixty-five thousand. `label` is
    /// what the header line shows, since there are no expressions. Nobody typed
    /// anything but an id.
    #[must_use]
    pub(crate) fn resumed(map: TargetMap, remaining: u128, label: String) -> Self {
        let hosts = map.gross_ips().unwrap_or(u128::MAX);

        Self {
            asked: Asked {
                expressions: vec![label],
                segment_sweep: false,
                exclusions: Exclusions::none(),
            },
            probes: remaining,
            hosts,
            map,
            // A resumed scan's names come back with its options.
            names: BTreeMap::new(),
        }
    }

    /// The map to hand the engine.
    ///
    /// Before exclusions, for the reason [`Targets::into_ips`] gives.
    #[must_use]
    pub(crate) fn into_map(self) -> TargetMap {
        self.map
    }

    /// The same map, borrowed.
    ///
    /// For what has to read the plan before the scan takes it, such as a journal
    /// checking that this is the plan it was written against.
    #[must_use]
    pub(crate) fn map(&self) -> &TargetMap {
        &self.map
    }

    /// How many probes this run will actually spend: addresses times ports,
    /// across every unit, once the exclusions are out of it.
    #[must_use]
    pub(crate) fn probes(&self) -> u128 {
        self.probes
    }

    /// How many addresses this run will actually cover.
    #[must_use]
    pub(crate) fn hosts(&self) -> u128 {
        self.hosts
    }

    /// What the exclusion policy keeps out of this run, if anything.
    #[must_use]
    pub(crate) fn exclusions(&self) -> &Exclusions {
        &self.asked.exclusions
    }

    /// How many addresses the exclusions take out of what was named.
    #[must_use]
    pub(crate) fn excluded(&self) -> u128 {
        self.map
            .gross_ips()
            .unwrap_or(u128::MAX)
            .saturating_sub(self.hosts)
    }

    /// Writes what these targets imply into `cfg`, the names each address
    /// was reached by among them.
    pub(crate) fn apply_to(&self, cfg: &mut ZondConfig) {
        self.asked.apply_to(cfg);
        cfg.target_names = self.names.clone();
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
/// context. See the module documentation.
fn host_context() -> TargetContext<'static> {
    const KEYWORDS: ResolverFn<'static> = &interface::resolve_keyword;
    const ZONES: ZoneResolverFn<'static> = &interface::resolve_zone;

    TargetContext::new()
        .with_keywords(KEYWORDS)
        .with_zones(ZONES)
}

/// Resolves target expressions into addresses and the ports to try on each.
///
/// `ports` is the *default*. An expression naming its own, as in
/// `10.0.0.1:8080` or `[2001:db8::1]:443`, keeps them, and everything else gets
/// these. `excluded_ports` is what the scan will send nothing to, counted out
/// of the probes here as the engine takes it out of the plan there.
pub(crate) async fn resolve_ports<S: AsRef<str>, E: AsRef<str>>(
    expressions: &[S],
    exclude: &[E],
    inherited: &Exclusions,
    ports: PortSet,
    excluded_ports: &PortSet,
    resolve_names: bool,
) -> Result<ScanTargets, TargetError> {
    let context = host_context();
    let resolver = resolve_names.then(Resolver::from_system);

    let planned = resolve::for_port_scan(expressions, ports, &context, resolver.as_ref())
        .await
        .map_err(restate)?;
    let names = planned.names().clone();
    let map = planned.into_map();

    let exclusions = inherit(inherited, exclude, resolver.as_ref()).await?;

    // Measured on a copy and discarded, exactly as the sweep does it: a probe
    // count is what the run will cost, and a run does not pay for a target it
    // has been forbidden to send.
    let mut walked = map.clone();
    exclusions.withhold_targets(&mut walked);
    let addressed = !walked.is_empty();
    walked.withhold_ports(excluded_ports);

    // The same question the engine answers for a sweep, asked the same way.
    let targets = ScanTargets {
        asked: Asked::from_expressions(expressions, exclusions),
        probes: walked.gross_targets().unwrap_or(u128::MAX),
        hosts: walked.gross_ips().unwrap_or(u128::MAX),
        map,
        names,
    };

    if !addressed && !targets.map.is_empty() {
        return Err(TargetError::EverythingExcluded {
            expression: targets.to_string(),
        });
    }
    if targets.hosts == 0 && addressed {
        return Err(TargetError::EveryPortExcluded {
            expression: targets.to_string(),
        });
    }

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

    /// A header names what was typed and stays one short line however many
    /// targets that was: the first expression always, the rest while they
    /// fit, and a count of what did not.
    #[test]
    fn a_long_target_list_is_cut_to_a_count() {
        let asked =
            |expressions: &[&str]| Asked::new(expressions, false, Exclusions::none()).to_string();

        assert_eq!(asked(&["192.0.2.1", "192.0.2.9"]), "192.0.2.1, 192.0.2.9");
        assert_eq!(
            asked(&["192.0.2.10-192.0.2.19", "192.0.2.2"]),
            "192.0.2.10-192.0.2.19, +1 more"
        );
        assert_eq!(
            asked(&["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]),
            "192.0.2.1, 192.0.2.2, +2 more"
        );
    }
    use std::net::{IpAddr, Ipv4Addr};

    /// Literal addresses need no lookups, so every test here runs without a
    /// network and without an interface table. What `lan` means is the engine's
    /// to test.
    async fn offline<S: AsRef<str>>(expressions: &[S]) -> Result<Targets, TargetError> {
        resolve(expressions, NOTHING, &Exclusions::none(), false).await
    }

    /// An empty exclusion list, spelled so the element type is settled.
    const NOTHING: &[&str] = &[];

    /// The same, with a policy.
    async fn offline_excluding(
        expressions: &[&str],
        exclude: &[&str],
    ) -> Result<Targets, TargetError> {
        resolve(expressions, exclude, &Exclusions::none(), false).await
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
    /// different questions, and only one of them has an engine call that does
    /// the settling for it.
    #[test]
    fn both_phases_write_the_same_settings() {
        let excluded: IpSet = "10.0.5.0/24".parse().expect("a valid range");

        for sweep in [false, true] {
            let asked = Asked::new(&["lan"], sweep, Exclusions::new(excluded.clone()));

            let discovery = Targets {
                asked: asked.clone(),
                ips: IpSet::new(),
                remaining: 0,
            };
            let port_scan = ScanTargets {
                asked,
                map: TargetMap::default(),
                names: BTreeMap::new(),
                probes: 0,
                hosts: 0,
            };

            let mut from_discovery = ZondConfig::default();
            let mut from_port_scan = ZondConfig::default();
            discovery.apply_to(&mut from_discovery);
            port_scan.apply_to(&mut from_port_scan);

            assert_eq!(from_discovery.segment_sweep, sweep);
            assert_eq!(from_port_scan.segment_sweep, sweep);

            let forbidden = IpAddr::V4(Ipv4Addr::new(10, 0, 5, 7));
            assert!(from_discovery.exclusions.excludes(&forbidden));
            assert!(from_port_scan.exclusions.excludes(&forbidden));
        }
    }

    /// What is measured is the run after the exclusions; what is handed over is
    /// the run before them.
    ///
    /// Both halves matter and neither implies the other. The count is what the
    /// header prints and what the size guard is checked against, so it has to be
    /// the ground actually covered. The set is what the engine receives, so that
    /// the engine performs the subtraction itself and its report can say what
    /// the policy cost. Narrowing here as well would leave every report this
    /// program writes claiming a policy withheld nothing.
    #[tokio::test]
    async fn a_run_is_counted_after_exclusions_and_handed_over_before_them() {
        let targets = offline_excluding(&["192.168.0.0/24"], &["192.168.0.128/25"])
            .await
            .expect("well-formed");

        assert_eq!(targets.len(), 128, "half the block is withheld");
        assert_eq!(targets.excluded(), 128);

        let ips = targets.into_ips();
        assert_eq!(ips.len(), 256, "the engine is given what was named");
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 200))));
    }

    /// An exclusion is written the way a target is, and several may be given.
    #[tokio::test]
    async fn exclusions_take_the_same_grammar_as_targets() {
        let targets = offline_excluding(
            &["10.0.0.0/24"],
            &["10.0.0.1", "10.0.0.16-31", "10.0.0.128/25"],
        )
        .await
        .expect("well-formed");

        assert_eq!(targets.len(), 256 - 1 - 16 - 128);

        let policy = targets.exclusions();
        for forbidden in ["10.0.0.1", "10.0.0.20", "10.0.0.200"] {
            assert!(
                policy.excludes(&forbidden.parse().expect("literal")),
                "{forbidden} was excluded"
            );
        }
        assert!(!policy.excludes(&"10.0.0.2".parse().expect("literal")));
    }

    /// The size guard is about how long a run takes, so it is checked against
    /// what the run will walk.
    ///
    /// A `/8` is refused, and a `/8` with all but a `/12` of it excluded is not,
    /// because the second one is a `/12` of probing however it was written.
    /// Checking the guard before the subtraction would refuse a run whose cost
    /// is within the limit, which is the guard answering a question nobody
    /// asked.
    #[tokio::test]
    async fn the_size_guard_counts_what_will_actually_be_swept() {
        assert!(matches!(
            offline(&["10.0.0.0/8"]).await,
            Err(TargetError::TooLarge { .. })
        ));

        // Everything above 10.15.255.255 excluded, leaving exactly a /12.
        let narrowed = offline_excluding(&["10.0.0.0/8"], &["10.16.0.0-10.255.255.255"])
            .await
            .expect("what is left is within the limit");
        assert_eq!(narrowed.len(), MAX_IPV4_ADDRESSES);
    }

    /// Excluding everything is a mistake, not a scan of nothing.
    ///
    /// The likely cause is a typo in the exclusion rather than a scope that
    /// genuinely excludes itself, and a run that swept zero addresses and
    /// reported no hosts would look exactly like a network with nothing on it.
    #[tokio::test]
    async fn a_policy_that_covers_every_target_is_refused() {
        let refused = offline_excluding(&["192.168.0.0/24"], &["192.168.0.0/16"]).await;

        let Err(error @ TargetError::EverythingExcluded { .. }) = refused else {
            panic!("a run with nothing left to scan is an error");
        };
        let message = error.to_string();
        assert!(message.contains("192.168.0.0/24"), "got {message:?}");
        assert!(message.contains("--exclude"), "got {message:?}");
    }

    /// A run forbidden from sending DNS may not resolve a name to exclude
    /// either, and is told which flag is responsible.
    ///
    /// Resolving a name to keep out sends exactly the query resolving a name to
    /// scan does, so the policy has to cover both halves of the grammar. Dropped
    /// quietly it would be worse here than for a target: an unresolved exclusion
    /// does not narrow a scan, it widens one.
    #[tokio::test]
    async fn a_hostname_to_exclude_is_refused_when_dns_is_forbidden() {
        let refused = offline_excluding(&["10.0.0.0/24"], &["db.internal"]).await;

        let Err(error @ TargetError::NameNeedsDns { .. }) = refused else {
            panic!("a name cannot be resolved with DNS forbidden");
        };
        assert!(error.to_string().contains("db.internal"));
    }

    /// Excluded ports are counted out of what a scan will cost, a target's
    /// own ports among them, and a scan they leave nothing to ask is refused
    /// rather than run.
    ///
    /// A header counting a port the scan will send nothing to overstates the
    /// run, and a run that asked nothing reads as one that found nothing.
    #[tokio::test]
    async fn excluded_ports_are_counted_out_and_excluding_every_one_is_refused() {
        let excluded: PortSet = "9100-9107".parse().expect("a valid port set");

        let targets = resolve_ports(
            &["192.0.2.0/30", "198.51.100.7:9100"],
            &[] as &[&str],
            &Exclusions::none(),
            "22,9100".parse().expect("a valid port set"),
            &excluded,
            false,
        )
        .await
        .expect("well-formed");
        assert_eq!(targets.probes(), 4, "four addresses on 22 alone");
        assert_eq!(targets.hosts(), 4, "the one asked only 9100 is not a host");

        let refused = resolve_ports(
            &["192.0.2.1"],
            &[] as &[&str],
            &Exclusions::none(),
            "9100,9101".parse().expect("a valid port set"),
            &excluded,
            false,
        )
        .await;
        let Err(error @ TargetError::EveryPortExcluded { .. }) = refused else {
            panic!("a scan with every port excluded must be refused");
        };
        assert!(error.to_string().contains("--exclude-ports"), "{error}");
    }

    /// A port scan is counted the same way, in probes rather than addresses.
    #[tokio::test]
    async fn a_port_scan_spends_no_probes_on_an_excluded_address() {
        let targets = resolve_ports(
            &["10.0.0.0/24"],
            &["10.0.0.128/25"],
            &Exclusions::none(),
            "22,80".parse().expect("a valid port set"),
            &PortSet::new(),
            false,
        )
        .await
        .expect("well-formed");

        assert_eq!(targets.hosts(), 128);
        assert_eq!(targets.probes(), 256, "128 addresses on two ports");
        assert_eq!(targets.excluded(), 128);
        assert_eq!(
            targets.into_map().gross_ips().expect("small"),
            256,
            "the engine is given what was named"
        );
    }

    /// The derivation a port scan does for itself, since nothing resolved it on
    /// the way. Needs no interface table: it reads the words, not the network.
    #[test]
    fn a_port_scan_reads_the_sweep_out_of_the_expressions() {
        assert!(Asked::from_expressions(&["lan"], Exclusions::none()).segment_sweep);
        assert!(
            Asked::from_expressions(&["LAN"], Exclusions::none()).segment_sweep,
            "case"
        );
        assert!(
            Asked::from_expressions(&["10.0.0.1,lan"], Exclusions::none()).segment_sweep,
            "a comma-separated list is still a list of targets"
        );
        assert!(!Asked::from_expressions(&["10.0.0.0/24"], Exclusions::none()).segment_sweep);
    }

    /// A setting a lower layer wrote must not survive targets that say otherwise:
    /// `segment_sweep` comes from what was typed, so it is written either way
    /// rather than only when true.
    #[test]
    fn targets_that_name_no_network_turn_the_sweep_off_again() {
        let mut config = ZondConfig::default();
        config.segment_sweep = true;

        Asked::new(&["10.0.0.1"], false, Exclusions::none()).apply_to(&mut config);
        assert!(!config.segment_sweep);
    }

    /// An interface name that matches nothing is a typo, and the correction
    /// is on this machine: the message names what it could have been rather
    /// than leaving its author to go and look.
    #[tokio::test]
    async fn an_unknown_interface_is_answered_with_the_ones_that_would_serve() {
        let error = offline(&["fe80::1%zz-no-such-link"])
            .await
            .expect_err("no such interface");

        assert!(
            matches!(&error, TargetError::UnknownInterface { name, .. } if name == "zz-no-such-link"),
            "{error:?}"
        );
        let said = error.to_string();
        assert!(
            said.starts_with("'fe80::1%zz-no-such-link': no interface named zz-no-such-link ("),
            "{said}"
        );

        assert_eq!(
            try_instead(&["eth0".to_owned(), "eth1".to_owned()]),
            "try eth0, eth1"
        );
        assert_eq!(try_instead(&[]), "none here would serve");
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
