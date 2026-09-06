// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The corpus as a catalogue
//!
//! ```text
//!   grafana-path-traversal         exploit        Grafana plugin path traversal
//!                                                  engine 0.14 · service=http|grafana · proto=tcp
//!   redis-unauth-access            active-benign  Unauthenticated Redis access
//!                                                  engine 0.14 · service=redis · proto=tcp
//!   http-missing-security-headers  passive        Missing HTTP security headers
//!                                                  engine 0.14 · speaks=http
//!   domain-controller              derived        Windows domain controller
//!                                                  engine 0.14 · open=88,389,445
//!
//! • 5 detections: 1 exploit, 2 active-benign, 1 passive, 1 derived
//! ```
//!
//! Two lines each: what it is on the first, how it works on the second. The
//! first carries the three things a person is looking one up for — the id they
//! would name on a command line, what it will do to the target, and what it
//! finds. The second is faint because it answers a question asked later.
//!
//! ## The class is the column that gets the hue
//!
//! A catalogue of detections is read for one thing before any other: what will
//! this do to the machine I point it at. [`Class`] is a five-step ramp saying
//! exactly that, from a detection that sends nothing to one the service may not
//! survive, and it takes the same inks a certificate's expiry and a finding's
//! severity already take. Nothing else here is coloured, so the column reads as
//! a band rather than as five words of different lengths — the same argument
//! [`fancy::findings`](super::fancy) makes about severity.
//!
//! It paints from [`Class`] rather than through
//! [`by_urgency`](Style::by_urgency), which is the one thing here that does not
//! reuse the scale. `active-benign` has no urgency and is still a value the
//! corpus established, so it wants [`plain`](Style::plain); `by_urgency` sends
//! an absent urgency to [`plainly`](Style::plainly), which paints nothing at all
//! and would leave one token on a coloured line in whatever foreground the
//! terminal happens to use.
//!
//! **Every detection sits somewhere on the ramp**, including a host
//! correlation, which declares [`Derived`](Class::Derived): it recombines ports
//! a scan already settled and sends nothing of its own, one rung below `passive`,
//! which at least reads bytes the scan gathered. So this module draws
//! [`Class::label`] and nothing else, and there is no case here where the column
//! is blank.
//!
//! ## Two left edges, not one and a river
//!
//! The class starts in a column rather than ending in one. Right-aligning it
//! gives the ramp a clean right edge, which buys nothing — the title column is
//! fixed either way — and costs a widening gap after every id shorter than the
//! longest, which is a river running down the middle of the listing. Left, the
//! eye has two edges to run down, and it is what
//! [`fancy::findings`](super::fancy) does with the severity token this borrows
//! its colours from.
//!
//! ## The build, not the tier and not the detection's own version
//!
//! The second line opens with the engine that compiled the corpus, at major and
//! minor. `flow 1.0.0` and `compute 1.0.0` said two things badly: the tier is how
//! a detection is implemented rather than anything a person looks one up for, and
//! the built-in corpus is versioned with the engine, so a per-detection `1.0.0`
//! was three digits that never moved. The build stamp is what actually answers
//! "which corpus is this".
//!
//! Neither is lost. `pipe` still carries the tier, the detection's own version
//! and its content hash, which is where a program looking for any of the three
//! should be reading them from anyway.
//!
//! ## `pipe` is not this
//!
//! One tab-separated line per detection, no padding, every field on it. That is
//! the stable interface and it does not change shape because a title got long.

use std::io::{self, Write};

use zond_engine::detect::Gate;
use zond_engine::detect::corpus::DetectionSummary;
use zond_engine::detect::manifest::Class;
use zond_engine::report::ENGINE_VERSION;

use crate::diagnostics::Verbosity;
use crate::render::block;
use crate::render::field;
use crate::render::style::Style;
use crate::settings::Presentation;

/// The margin a listing opens with.
const GUTTER: usize = 2;

/// What separates one column from the next, as everywhere else.
const GAP: usize = block::GAP;

/// Writes the catalogue in the presentation this run draws in.
pub(crate) fn list(
    detections: &[DetectionSummary],
    presentation: Presentation,
    verbosity: Verbosity,
    out: &mut dyn Write,
    style: Style,
) -> io::Result<()> {
    match presentation {
        Presentation::Pipe => piped(detections, out),
        _ => drawn(detections, verbosity, out, style),
    }
}

/// One tab-separated line per detection: the stable interface.
fn piped(detections: &[DetectionSummary], out: &mut dyn Write) -> io::Result<()> {
    for detection in detections {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            detection.id,
            detection.version,
            tier(detection),
            detection.class.label(),
            gate(&detection.gate).join(" "),
            detection.title,
            detection.content_hash
        )?;
    }

    Ok(())
}

/// The catalogue, drawn.
fn drawn(
    detections: &[DetectionSummary],
    verbosity: Verbosity,
    out: &mut dyn Write,
    style: Style,
) -> io::Result<()> {
    // Measured across the whole catalogue, because the alignment worth having is
    // the one between entries: an id column a reader runs down, and a class
    // column that reads as a ramp rather than as words of five different widths.
    let widest = |measure: &dyn Fn(&DetectionSummary) -> usize| {
        detections.iter().map(measure).max().unwrap_or(0)
    };

    let id_width = widest(&|detection| detection.id.chars().count());
    let class_width = widest(&|detection| detection.class.label().chars().count());

    let title_column = GUTTER + id_width + GAP + class_width + GAP;
    let room = crate::render::width().saturating_sub(title_column).max(24);

    for detection in detections {
        let mut line = String::new();
        line.push_str(&" ".repeat(GUTTER));
        line.push_str(&style.strong(&detection.id));

        // Painted trimmed and padded after, so no escape sequence ever wraps a
        // run of spaces: what the terminal measures is exactly what the widths
        // were computed from.
        let label = detection.class.label();
        line.push_str(&" ".repeat(id_width - detection.id.chars().count() + GAP));
        line.push_str(&intrusiveness(style, detection.class, label));
        line.push_str(&" ".repeat(class_width - label.chars().count()));

        let folded = field::wrap(&detection.title, room);
        for (index, piece) in folded.iter().enumerate() {
            if index == 0 {
                line.push_str(&" ".repeat(GAP));
                line.push_str(&style.plain(piece));
                writeln!(out, "{line}")?;
            } else {
                writeln!(out, "{}{}", " ".repeat(title_column), style.plain(piece))?;
            }
        }

        // How it works and when it fires, under what it finds: a question asked
        // after the one the first line answers, and faint for the same reason a
        // label is.
        let mut how = vec![format!("engine {}", major_minor(ENGINE_VERSION))];
        how.extend(gate(&detection.gate));
        writeln!(
            out,
            "{}{}",
            " ".repeat(title_column),
            style.faint(&how.join(" \u{b7} "))
        )?;

        // What the bytes deciding its behaviour hash to. The one field that
        // answers "is this the detection I signed", so it waits for the flag
        // that asks for the working behind anything.
        if verbosity.explains() {
            writeln!(
                out,
                "{}{}",
                " ".repeat(title_column),
                style.faint(&detection.content_hash)
            )?;
        }
    }

    Ok(())
}

/// `label`, painted by what the detection it names will do to the target.
///
/// The same inks a certificate's expiry and a finding's severity take, rather
/// than a scale invented here. `exploit` and `dos` share the loudest because
/// there are three loud inks and five classes; the word beside the colour is
/// what tells them apart, as it is everywhere else in this crate.
fn intrusiveness(style: Style, class: Class, label: &str) -> String {
    match class {
        // `passive` and `derived` both send nothing, so both recede. Two rungs
        // sharing an ink is not two rungs sharing a meaning: the word beside the
        // colour is what separates them, here as everywhere else in this crate.
        Class::Derived | Class::Passive => style.faint(label),
        Class::ActiveMutating => style.caution(label),
        Class::Exploit | Class::Dos => style.alarm(label),
        // `active-benign`, and a class a newer engine declares that this build
        // has no place for: something the corpus established, in the ink for
        // that. Not a reason to shout, and not a reason to go unpainted.
        _ => style.plain(label),
    }
}

/// What the catalogue came to, for the commentary stream.
///
/// The count, then what it is made of, worst first — the same ordering the risks
/// under a host take, and for the same reason: somebody deciding whether to point
/// this corpus at a network is asking what the loudest thing in it is before they
/// ask anything else.
///
/// A corpus of one class says so in a clause rather than repeating its own total,
/// since `40 detections: 40 passive` is a number printed twice.
pub(crate) fn summary(detections: &[DetectionSummary]) -> String {
    let total = detections.len();
    let counted = format!(
        "{total} {}",
        if total == 1 {
            "detection"
        } else {
            "detections"
        }
    );

    let mut tally: Vec<(Class, usize)> = Vec::new();
    for detection in detections {
        match tally
            .iter()
            .position(|(class, _)| *class == detection.class)
        {
            Some(at) => tally[at].1 += 1,
            None => tally.push((detection.class, 1)),
        }
    }
    tally.sort_by_key(|(class, _)| std::cmp::Reverse(rank(*class)));

    match tally.as_slice() {
        [] => counted,
        [(class, _)] => format!("{counted}, all {}", class.label()),
        _ => {
            let parts: Vec<String> = tally
                .iter()
                .map(|(class, count)| format!("{count} {}", class.label()))
                .collect();
            format!("{counted}: {}", parts.join(", "))
        }
    }
}

/// Where a class sits on the ramp, most intrusive highest.
///
/// Spelled here rather than derived from the declaration order, because [`Class`]
/// carries no ordering of its own and a summary that sorted by however the enum
/// happens to be written would be sorting by an accident.
fn rank(class: Class) -> u8 {
    match class {
        Class::Derived => 0,
        Class::Passive => 1,
        Class::ActiveBenign => 2,
        Class::ActiveMutating => 3,
        Class::Exploit => 4,
        Class::Dos => 5,
        // A class a newer engine declares that this build has no place for.
        // Ranked above everything named here rather than below: an unknown
        // intrusiveness is not a safe one, and a summary that filed it at the
        // quiet end would be the wrong way to be wrong about it.
        _ => u8::MAX,
    }
}

/// A version with its patch component dropped.
///
/// Everything before the second dot, so `0.14.0` and `0.14.0-rc1` both read
/// `0.14`. A patch release changes no detection's behaviour, so the digit that
/// moves for one is a digit on every line of the listing saying nothing.
fn major_minor(version: &str) -> &str {
    match version.match_indices('.').nth(1) {
        Some((at, _)) => &version[..at],
        None => version,
    }
}

/// Which tier runs it, in the engine's own spelling.
fn tier(detection: &DetectionSummary) -> &'static str {
    detection.tier.name()
}

/// A gate as the parts that must all hold, each already spelled `key=value`.
///
/// Returned apart rather than joined, because the two presentations join them
/// differently: `pipe` needs one field and the drawn catalogue reads better with
/// a separator between the conditions.
pub(crate) fn gate(gate: &Gate) -> Vec<String> {
    let mut parts = Vec::new();

    match gate {
        Gate::Port(rule) => {
            if let Some(service) = &rule.service {
                parts.push(format!("service={service}"));
            }
            if !rule.services.is_empty() {
                parts.push(format!("service={}", rule.services.join("|")));
            }
            if let Some(speaks) = &rule.speaks {
                parts.push(format!("speaks={speaks}"));
            }
            if let Some(port) = rule.port {
                parts.push(format!("port={port}"));
            }
            if !rule.ports.is_empty() {
                parts.push(format!("port={}", numbers(&rule.ports)));
            }
            if let Some(protocol) = &rule.protocol {
                parts.push(format!("proto={protocol}"));
            }
            if parts.is_empty() {
                parts.push("any port".to_owned());
            }
        }
        Gate::Host {
            ports_open,
            services,
        } => {
            if !ports_open.is_empty() {
                parts.push(format!("open={}", numbers(ports_open)));
            }
            if !services.is_empty() {
                parts.push(format!("service={}", services.join("+")));
            }
        }
        // `Gate` is non-exhaustive: a tier added later gates on something this
        // has not seen, and a listing says so rather than stopping the build.
        _ => parts.push("an unknown condition".to_owned()),
    }

    parts
}

/// Port numbers, comma separated.
fn numbers(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
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

    use std::collections::BTreeSet;

    use zond_engine::detect::Detections;

    use crate::render::style::{ColourChoice, Palette};

    /// The corpus this build ships, which is what the command draws.
    ///
    /// Built rather than invented: `DetectionSummary` is `non_exhaustive`, so
    /// nothing outside the engine can construct one, and the assertions here are
    /// about the shape of a listing rather than about any entry in it.
    fn corpus() -> Vec<DetectionSummary> {
        let listing = Detections::default().listing();
        assert!(
            listing.len() > 1,
            "the built-in corpus is what these tests are measured against"
        );
        listing
    }

    fn rendered(
        detections: &[DetectionSummary],
        presentation: Presentation,
        verbosity: Verbosity,
        style: Style,
    ) -> String {
        let mut out = Vec::new();
        list(detections, presentation, verbosity, &mut out, style).expect("a vector cannot fail");
        String::from_utf8(out).expect("the renderer writes text")
    }

    /// A catalogue as a terminal gets it, unpainted so the layout is what reads.
    fn drawn_bare(detections: &[DetectionSummary]) -> String {
        rendered(
            detections,
            Presentation::Fancy,
            Verbosity::default(),
            Style::bare(),
        )
    }

    /// The columns are measured across the catalogue, so entries whose ids and
    /// classes are of very different lengths still start their titles in one
    /// place — which is the column the eye runs down.
    #[test]
    fn every_title_starts_in_one_column() {
        let listing = corpus();
        let text = drawn_bare(&listing);

        let columns: BTreeSet<usize> = listing
            .iter()
            .map(|detection| {
                text.lines()
                    .find_map(|line| line.find(detection.title.as_str()))
                    .unwrap_or_else(|| panic!("no title drawn for {}: {text}", detection.id))
            })
            .collect();

        assert_eq!(columns.len(), 1, "the titles are not in one column: {text}");
    }

    /// Two lines an entry: what it is, then how it works. The second starts in
    /// the title's column, so a block of two reads as one thing.
    #[test]
    fn how_it_works_hangs_under_what_it_finds() {
        let listing = corpus();
        let text = drawn_bare(&listing);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(
            lines.len(),
            listing.len() * 2,
            "an entry is two lines: {text}"
        );

        let title_column = lines[0]
            .find(listing[0].title.as_str())
            .unwrap_or_else(|| unreachable!());

        for (index, detection) in listing.iter().enumerate() {
            let how = lines[index * 2 + 1];
            assert_eq!(
                how.len() - how.trim_start().len(),
                title_column,
                "the second line of {} does not start in the title's column: {text}",
                detection.id
            );
            assert!(
                how.contains(&format!("engine {}", major_minor(ENGINE_VERSION))),
                "the second line of {} does not stamp the build: {text}",
                detection.id
            );
        }
    }

    /// Every entry carries a class, host correlations included: the engine gives
    /// them [`Class::Derived`], so there is no row here where the column is a
    /// blank for a reader to interpret.
    #[test]
    fn every_entry_carries_a_class() {
        let listing = corpus();
        let text = drawn_bare(&listing);
        let lines: Vec<&str> = text.lines().collect();

        for (index, detection) in listing.iter().enumerate() {
            let drawn = lines[index * 2];
            assert!(
                drawn.contains(detection.class.label()),
                "{} is drawn without its class: {drawn:?}",
                detection.id
            );
        }

        assert!(
            listing
                .iter()
                .any(|detection| detection.class == Class::Derived),
            "no host correlation in the corpus, so `derived` is untested: {text}"
        );
    }

    /// The summary counts the catalogue and says what it is made of, loudest
    /// first, so somebody deciding whether to point this at a network reads the
    /// worst thing in it before anything else.
    #[test]
    fn the_summary_counts_worst_first() {
        let listing = corpus();
        let line = summary(&listing);

        assert!(
            line.starts_with(&format!("{} detections", listing.len())),
            "{line}"
        );

        let mut ranks: Vec<u8> = Vec::new();
        for class in [
            Class::Dos,
            Class::Exploit,
            Class::ActiveMutating,
            Class::ActiveBenign,
            Class::Passive,
            Class::Derived,
        ] {
            if let Some(at) = line.find(class.label()) {
                // Every class that appears is preceded by its count, and they
                // appear in the order this loop walks: loudest first.
                ranks.push(rank(class));
                assert!(at > 0, "{line}");
            }
        }

        assert!(
            ranks.len() > 1,
            "the corpus has one class, so order is untested: {line}"
        );
        assert!(
            ranks.windows(2).all(|pair| pair[0] > pair[1]),
            "the classes are not loudest-first: {line}"
        );
    }

    /// A corpus of one class says so in a clause rather than printing its own
    /// total twice.
    #[test]
    fn one_class_is_said_once() {
        let listing = corpus();
        let quiet: Vec<DetectionSummary> = listing
            .iter()
            .filter(|detection| detection.class == Class::Passive)
            .cloned()
            .collect();

        assert!(
            !quiet.is_empty(),
            "the corpus has no passive detection to fold"
        );
        let line = summary(&quiet);
        assert!(line.ends_with(", all passive"), "{line}");
        assert!(!line.contains(':'), "the total was printed twice: {line}");
    }

    /// An empty catalogue is a count and nothing else, rather than a count and a
    /// colon with nothing after it.
    #[test]
    fn an_empty_catalogue_says_only_its_count() {
        assert_eq!(summary(&[]), "0 detections");
    }

    /// A patch component is a digit that moves for a release changing no
    /// detection's behaviour, so it is not on a line a person reads.
    #[test]
    fn a_version_is_shown_to_major_and_minor() {
        assert_eq!(major_minor("0.14.0"), "0.14");
        assert_eq!(major_minor("0.14.0-rc1"), "0.14");
        assert_eq!(major_minor("1.2"), "1.2");
        assert_eq!(major_minor("7"), "7");
    }

    /// The tier and the detection's own version are still on the stable stream,
    /// which is where a program looking for either should read them.
    #[test]
    fn pipe_still_carries_the_tier_and_the_detections_own_version() {
        let listing = corpus();
        let text = rendered(
            &listing,
            Presentation::Pipe,
            Verbosity::default(),
            Style::bare(),
        );

        for (line, detection) in text.lines().zip(&listing) {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields[1], detection.version, "{line}");
            assert_eq!(fields[2], detection.tier.name(), "{line}");
        }
    }

    /// `pipe` spells the class the same way, since there is no longer an absence
    /// for the two streams to spell differently.
    #[test]
    fn pipe_spells_the_class_the_same_way() {
        let listing = corpus();
        let text = rendered(
            &listing,
            Presentation::Pipe,
            Verbosity::default(),
            Style::bare(),
        );

        for (line, detection) in text.lines().zip(&listing) {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(
                fields[3],
                detection.class.label(),
                "{} carries a class it has not: {line}",
                detection.id
            );
        }
    }

    /// What the bytes deciding a detection's behaviour hash to is provenance,
    /// and provenance waits for the flag that asks for the working behind
    /// anything.
    #[test]
    fn the_content_hash_waits_for_detail() {
        let listing = corpus();
        let hash = listing[0].content_hash.as_str();

        let quiet = drawn_bare(&listing);
        assert!(!quiet.contains(hash), "{quiet}");

        let asked = rendered(
            &listing,
            Presentation::Fancy,
            Verbosity::new(1, false),
            Style::bare(),
        );
        assert!(asked.contains(hash), "{asked}");
    }

    /// `pipe` is a different audience: one line per detection, tab separated, no
    /// padding, and every field on it whatever the terminal is.
    #[test]
    fn pipe_writes_one_unpadded_line_per_detection() {
        let listing = corpus();
        let text = rendered(
            &listing,
            Presentation::Pipe,
            Verbosity::default(),
            Style::bare(),
        );

        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), listing.len(), "one line each: {text}");

        for line in &lines {
            assert_eq!(line.matches('\t').count(), 6, "seven fields: {line}");
            assert_eq!(line.trim_end(), *line, "nothing is padded: {line:?}");
            assert!(!line.starts_with(' '), "nothing is indented: {line:?}");
        }
    }

    /// The class is the one column carrying a hue, and it carries the ink its
    /// intrusiveness asks for rather than whatever the terminal defaults to.
    #[test]
    fn the_class_column_carries_the_ink_its_class_asks_for() {
        let listing = corpus();
        let style = Style::detect(Palette::when(ColourChoice::Always), true);
        let text = rendered(&listing, Presentation::Fancy, Verbosity::default(), style);

        let mut inks = BTreeSet::new();
        for detection in &listing {
            let class = detection.class;
            let painted = intrusiveness(style, class, class.label());
            assert!(
                text.contains(&painted),
                "{} is not painted for {}: {text}",
                class.label(),
                detection.id
            );
            inks.insert(painted);
        }

        assert!(
            inks.len() > 1,
            "every class in the corpus came out the same: {text}"
        );
    }
}
