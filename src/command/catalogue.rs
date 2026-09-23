// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Choosing from the catalogue
//!
//! Which detections `zond detections` lists, and in what order.
//!
//! The corpus this build ships is ninety-odd and grows with every release, so
//! the listing stopped being something anybody reads end to end. The flags are
//! [`CatalogueArgs`]; this is what they mean against a
//! [`DetectionSummary`].
//!
//! Nothing here changes what a scan runs. Compiling is
//! [`corpus`](super::detections::corpus) and running is the engine's, and a
//! filter that reduced either would be a way to believe a check ran when nothing
//! had loaded it.
//!
//! ## A filter matches what the listing shows
//!
//! `--service` and `--port` are read against the gate as the catalogue draws it,
//! so a row that comes back is a row whose own second line explains why. That is
//! narrower than "would fire here": a detection gated on `service=redis` runs
//! wherever the scan identified Redis, whatever port it was on, and answering
//! `--port 6379` with it would be answering a question about a number with a
//! decision about a name. The listing prints the gate; a reader takes it from
//! there.

use zond_engine::detect::Gate;
use zond_engine::detect::corpus::DetectionSummary;
use zond_engine::detect::manifest::Class;

use crate::cli::{CatalogueArgs, SortBy};

/// The detections a listing shows, in the order it shows them.
///
/// Filtered first and sorted after, since sorting what was thrown away is work
/// for nobody.
pub(crate) fn select(
    listing: Vec<DetectionSummary>,
    args: &CatalogueArgs,
) -> Vec<DetectionSummary> {
    let mut chosen: Vec<DetectionSummary> = listing
        .into_iter()
        .filter(|detection| fits(detection, args))
        .collect();

    sort(&mut chosen, args.sort);
    if args.reverse {
        chosen.reverse();
    }

    chosen
}

/// Whether one detection answers every condition that was given.
///
/// Conditions AND and a repeated one ORs within itself, which is how a person
/// reads a line of flags: each one narrows, and naming a thing twice widens what
/// that one flag admits.
fn fits(detection: &DetectionSummary, args: &CatalogueArgs) -> bool {
    if let Some(text) = &args.search {
        let text = text.to_lowercase();
        if !detection.id.to_lowercase().contains(&text)
            && !detection.title.to_lowercase().contains(&text)
        {
            return false;
        }
    }

    if !args.class.is_empty()
        && !args
            .class
            .iter()
            .any(|class| class.class() == detection.class)
    {
        return false;
    }

    if !args.tier.is_empty() && !args.tier.iter().any(|tier| tier.tier() == detection.tier) {
        return false;
    }

    if let Some(service) = &args.service
        && !names_service(&detection.gate, service)
    {
        return false;
    }

    if let Some(port) = args.port
        && !names_port(&detection.gate, port)
    {
        return false;
    }

    true
}

/// Whether a gate names this service, ignoring case as a service name is
/// matched everywhere else.
///
/// Every place a name can appear: the one service a port rule asks for, the set
/// it accepts among several, the protocol it asks the port to speak, and the
/// services a host correlation waits for. A detection written about anything
/// speaking HTTP is one of the answers to "what is there for HTTP", and leaving
/// `speaks` out would hide most of the corpus from the question it is most
/// often asked.
fn names_service(gate: &Gate, service: &str) -> bool {
    let same = |candidate: &str| candidate.eq_ignore_ascii_case(service);

    match gate {
        Gate::Port(rule) => {
            rule.service.as_deref().is_some_and(same)
                || rule.services.iter().any(|name| same(name))
                || rule.speaks.as_deref().is_some_and(same)
        }
        Gate::Host { services, .. } => services.iter().any(|name| same(name)),
        // A tier added later gates on something this build has not seen, so it
        // cannot be said to name the service. It still lists; it just does not
        // answer this question.
        _ => false,
    }
}

/// Whether a gate names this port number.
fn names_port(gate: &Gate, port: u16) -> bool {
    match gate {
        Gate::Port(rule) => rule.port == Some(port) || rule.ports.contains(&port),
        Gate::Host { ports_open, .. } => ports_open.contains(&port),
        _ => false,
    }
}

/// Orders the listing, with the id breaking every tie.
///
/// The id is the tie-break rather than the corpus's own order because a
/// catalogue sorted by class is read as a block per class, and a block whose
/// rows sit in whatever order the tiers happened to compile them in is one the
/// eye cannot run down. Sorting is stable, so `--sort tier` alone still gives
/// the order the tiers run.
fn sort(detections: &mut [DetectionSummary], by: SortBy) {
    match by {
        SortBy::Id => detections.sort_by(|left, right| left.id.cmp(&right.id)),
        SortBy::Class => detections.sort_by(|left, right| {
            loudness(right.class)
                .cmp(&loudness(left.class))
                .then_with(|| left.id.cmp(&right.id))
        }),
        SortBy::Tier => detections.sort_by(|left, right| {
            running_order(left.tier)
                .cmp(&running_order(right.tier))
                .then_with(|| left.id.cmp(&right.id))
        }),
        SortBy::Title => detections.sort_by(|left, right| {
            left.title
                .to_lowercase()
                .cmp(&right.title.to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        }),
    }
}

/// Where a class sits on the ramp, most intrusive highest.
///
/// The same ordering [`render::detections::summary`](crate::render::detections)
/// counts in, so a listing sorted by class and the line under it agree about
/// which end is the loud one. Spelled rather than derived from the declaration
/// order, because `Class` carries no ordering of its own.
fn loudness(class: Class) -> u8 {
    match class {
        Class::Derived => 0,
        Class::Passive => 1,
        Class::ActiveBenign => 2,
        Class::ActiveMutating => 3,
        Class::Exploit => 4,
        Class::Dos => 5,
        // A class a newer engine declares that this build has no place for.
        // Sorted above everything named here: an unknown intrusiveness is not a
        // safe one, and a listing that filed it at the quiet end would be the
        // wrong way to be wrong about it.
        _ => u8::MAX,
    }
}

/// Where a tier sits in the order the tiers run, which is the order the corpus
/// itself comes in.
fn running_order(tier: zond_engine::detect::bundle::Tier) -> u8 {
    use zond_engine::detect::bundle::Tier;

    match tier {
        Tier::Flow => 0,
        Tier::Compute => 1,
        Tier::Host => 2,
        // A tier a newer engine runs. Last, where an unrecognised thing does
        // least harm to a reader looking for a familiar one.
        _ => u8::MAX,
    }
}

/// What was asked for, as the flags that asked it.
///
/// Read back to a person whose filter matched nothing, so the answer is "these
/// conditions found none" rather than a bare absence they have to reconstruct
/// the cause of. Empty when nothing was asked, which is the case where the
/// corpus itself is what came back empty.
pub(crate) fn asked_for(args: &CatalogueArgs) -> String {
    let mut parts = Vec::new();

    if let Some(text) = &args.search {
        parts.push(format!("--search {text}"));
    }
    for class in &args.class {
        parts.push(format!("--class {}", class.class().label()));
    }
    for tier in &args.tier {
        parts.push(format!("--tier {}", tier.tier().name()));
    }
    if let Some(service) = &args.service {
        parts.push(format!("--service {service}"));
    }
    if let Some(port) = args.port {
        parts.push(format!("--port {port}"));
    }

    parts.join(" ")
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

    use zond_engine::detect::Detections;
    use zond_engine::detect::bundle::Tier;

    use crate::cli::{ClassName, TierName};

    /// The corpus this build ships, which is what the command lists.
    ///
    /// Built rather than invented: `DetectionSummary` is `non_exhaustive`, so
    /// nothing outside the engine can construct one, and what is asserted here
    /// is the behaviour of the filter rather than the content of any entry.
    fn corpus() -> Vec<DetectionSummary> {
        let listing = Detections::default().listing();
        assert!(listing.len() > 1, "a corpus of one filters trivially");
        listing
    }

    /// Nothing asked for is nothing taken away, and the default order is the id.
    #[test]
    fn an_empty_filter_keeps_the_whole_corpus_in_order() {
        let whole = corpus();
        let shown = select(whole.clone(), &CatalogueArgs::default());

        assert_eq!(shown.len(), whole.len());

        let ids: Vec<&str> = shown.iter().map(|one| one.id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "the default order is the id");
    }

    /// The search reads the id and the title, so a detection is found by the
    /// name you would type and by the words you would describe it with.
    #[test]
    fn the_search_reads_both_the_id_and_the_title() {
        let whole = corpus();

        let by_id = select(
            whole.clone(),
            &CatalogueArgs {
                search: Some("REDIS".to_owned()),
                ..CatalogueArgs::default()
            },
        );
        assert!(
            by_id.iter().any(|one| one.id.contains("redis")),
            "an id is matched whatever the case it was typed in"
        );

        for one in &by_id {
            assert!(
                one.id.to_lowercase().contains("redis")
                    || one.title.to_lowercase().contains("redis"),
                "{} matches neither field",
                one.id
            );
        }
    }

    /// Naming a class twice widens that one condition, and naming a class and a
    /// tier narrows across both.
    #[test]
    fn conditions_or_within_themselves_and_and_across() {
        let whole = corpus();

        let quiet = select(
            whole.clone(),
            &CatalogueArgs {
                class: vec![ClassName::Passive, ClassName::Derived],
                ..CatalogueArgs::default()
            },
        );
        assert!(
            quiet
                .iter()
                .all(|one| one.class == Class::Passive || one.class == Class::Derived),
            "a class outside the two named came back"
        );
        assert!(
            quiet.iter().any(|one| one.class == Class::Derived),
            "the corpus has no derived detection, so the OR is untested"
        );

        let and = select(
            whole,
            &CatalogueArgs {
                class: vec![ClassName::Passive, ClassName::Derived],
                tier: vec![TierName::Host],
                ..CatalogueArgs::default()
            },
        );
        assert!(
            and.iter().all(|one| one.tier == Tier::Host),
            "the tier did not narrow what the class admitted"
        );
        assert!(and.len() < quiet.len(), "the tier narrowed nothing");
    }

    /// A gate that names a service answers for it however the gate spells it:
    /// the one service it asks for, the set it accepts, or the protocol it asks
    /// the port to speak.
    #[test]
    fn a_service_is_matched_wherever_a_gate_names_one() {
        let http = select(
            corpus(),
            &CatalogueArgs {
                service: Some("http".to_owned()),
                ..CatalogueArgs::default()
            },
        );

        assert!(!http.is_empty(), "nothing in the corpus names http");
        for one in &http {
            assert!(
                names_service(&one.gate, "HTTP"),
                "{} is a false match",
                one.id
            );
        }

        let speaking = http
            .iter()
            .filter(|one| match &one.gate {
                Gate::Port(rule) => rule.speaks.as_deref() == Some("http"),
                _ => false,
            })
            .count();
        assert!(speaking > 0, "`speaks` was left out of the match");
    }

    /// A port is matched where the gate names the number, which is what the
    /// listing shows beside it.
    #[test]
    fn a_port_is_matched_where_the_gate_names_the_number() {
        let whole = corpus();
        let named: Vec<u16> = whole
            .iter()
            .filter_map(|one| match &one.gate {
                Gate::Host { ports_open, .. } => ports_open.first().copied(),
                _ => None,
            })
            .collect();
        let port = *named.first().expect("a host gate names ports");

        let shown = select(
            whole,
            &CatalogueArgs {
                port: Some(port),
                ..CatalogueArgs::default()
            },
        );

        assert!(!shown.is_empty(), "the port a gate names matched nothing");
        for one in &shown {
            assert!(names_port(&one.gate, port), "{} is a false match", one.id);
        }
    }

    /// Sorting by class puts the loud end first, which is the end an operator
    /// has to decide about, and the same end the summary counts from.
    #[test]
    fn sorting_by_class_is_loudest_first() {
        let shown = select(
            corpus(),
            &CatalogueArgs {
                sort: SortBy::Class,
                ..CatalogueArgs::default()
            },
        );

        let ramp: Vec<u8> = shown.iter().map(|one| loudness(one.class)).collect();
        assert!(
            ramp.windows(2).all(|pair| pair[0] >= pair[1]),
            "the classes are not loudest first: {ramp:?}"
        );
        assert!(
            ramp.first() != ramp.last(),
            "the corpus is all one class, so the order is untested"
        );
    }

    /// A tie inside a sorted block is broken by the id, so a block reads as a
    /// column rather than as whatever order the tiers compiled it in.
    #[test]
    fn a_block_of_one_class_is_ordered_by_id() {
        let shown = select(
            corpus(),
            &CatalogueArgs {
                sort: SortBy::Class,
                ..CatalogueArgs::default()
            },
        );

        for pair in shown.windows(2) {
            if pair[0].class == pair[1].class {
                assert!(
                    pair[0].id <= pair[1].id,
                    "{} sits before {} in its own block",
                    pair[0].id,
                    pair[1].id
                );
            }
        }
    }

    /// `--sort tier` is the order the tiers run, which is the order the corpus
    /// arrives in.
    #[test]
    fn sorting_by_tier_follows_the_running_order() {
        let shown = select(
            corpus(),
            &CatalogueArgs {
                sort: SortBy::Tier,
                ..CatalogueArgs::default()
            },
        );

        let order: Vec<u8> = shown.iter().map(|one| running_order(one.tier)).collect();
        assert!(
            order.windows(2).all(|pair| pair[0] <= pair[1]),
            "the tiers are out of running order: {order:?}"
        );
    }

    /// Reversing turns the listing round rather than changing what is in it.
    #[test]
    fn reversing_keeps_the_same_rows() {
        let forwards = select(corpus(), &CatalogueArgs::default());
        let backwards = select(
            corpus(),
            &CatalogueArgs {
                reverse: true,
                ..CatalogueArgs::default()
            },
        );

        let mut turned: Vec<&str> = backwards.iter().map(|one| one.id.as_str()).collect();
        turned.reverse();
        let straight: Vec<&str> = forwards.iter().map(|one| one.id.as_str()).collect();
        assert_eq!(turned, straight);
    }

    /// What matched nothing is read back as the flags that asked it, so an
    /// empty listing is an answer rather than an absence.
    #[test]
    fn the_conditions_are_read_back_as_they_were_asked() {
        let line = asked_for(&CatalogueArgs {
            search: Some("grafana".to_owned()),
            class: vec![ClassName::Dos],
            port: Some(3000),
            ..CatalogueArgs::default()
        });

        assert_eq!(line, "--search grafana --class dos --port 3000");
        assert!(asked_for(&CatalogueArgs::default()).is_empty());
    }
}
