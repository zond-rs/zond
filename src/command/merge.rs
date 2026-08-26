// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # `zond merge`
//!
//! Several scans in, one report out. Nothing is probed and nothing is contacted:
//! every source is already written down, and this reads them.
//!
//! ## Any number of them, and all at once
//!
//! A `/16` scanned in eight chunks is eight documents, and a comparison's two
//! sides are the wrong shape for that. So this takes as many as it is given, and
//! it takes them in one command deliberately: the engine folds each source
//! against every other, and merging in rounds folds a new source against a
//! report already carrying an older one's clock. See
//! [`merge`](zond_engine::merge) for what that costs.
//!
//! Two is the minimum. One source is not a fold, and accepting it would let
//! `zond merge chunk*.json` report success on a glob that matched a single
//! file. What that person wanted is [`read`](super::read), and the refusal says
//! so rather than restating the grammar at them.
//!
//! ## Each source may be a file or a record
//!
//! The same rule [`diff`](super::diff) uses, through the same resolver: a name
//! that is a file on disk is read as one, and anything else is taken for a
//! record on this machine. That is what lets an archived nmap file, last night's
//! record and a report from another team go into one command without a flag
//! saying which is which.
//!
//! ## A source that cannot be read ends the command
//!
//! A merge answers what is out there given everything known. A merge that
//! quietly skipped a document it could not open would answer a different
//! question and look no different doing it: the report would state a smaller
//! network with no sign that anything was missing. So one bad source fails the
//! whole command, by name.
//!
//! ## Where the report goes
//!
//! The terminal, unless a file is named, and then only the file. That is
//! [`read`](super::read)'s rule rather than a scan's, and for its reason: a
//! scan prints as well as writes because somebody is watching it happen and the
//! file is for later. Nobody watches a merge happen. Naming a file is saying
//! where this goes.
//!
//! What is said on standard error either way is which documents went in, in the
//! order they were folded. A merged report is only as good as its sources, and
//! that line is how a reader checks them.

use std::io::IsTerminal;

use zond_engine::ScanReport;
use zond_engine::merge::{Merge, MergeOptions};

use crate::cli::MergeArgs;
use crate::command;
use crate::diagnostics::Verbosity;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::merge as render;
use crate::render::style::{Palette, Style};
use crate::render::{MergeSource, Phase, renderer};
use crate::settings::{Identity, Presentation};

/// Folds the scans named into one report, and puts it where it was asked for.
pub(crate) fn run(
    args: &MergeArgs,
    presentation: Presentation,
    verbosity: Verbosity,
    palette: Palette,
    reasons: bool,
) -> Result<Outcome, Error> {
    // Before a single source is read: a misspelt extension is answered at once
    // rather than after every document is in hand. `diff` does the same for its
    // two, and with eight the difference is one message against eight files'
    // worth of reading thrown away.
    let destinations = args.export.destinations()?;

    // Before the documents are read, since nothing about one of them decides
    // this. Refused here rather than by the grammar so the message can point at
    // the command that prints a single report; see `Error::NotAFold`.
    if args.sources.len() < 2 {
        return Err(Error::NotAFold {
            named: args.sources.first().cloned().unwrap_or_default(),
        });
    }

    // In the order they were named, and every one of them before any is folded.
    // A failure here is the whole command; see the module.
    let sources: Vec<(String, ScanReport)> = args
        .sources
        .iter()
        .map(|name| command::scan_named(name))
        .collect::<Result<_, _>>()?;

    // From this machine's settings rather than from any source. What a scan saw
    // is in the document; whether to mask it on the way out belongs to whoever
    // is reading it now.
    let redaction = command::redaction(&command::engine_settings(None)?.config);

    let mut renderer = renderer(presentation, verbosity, palette, reasons);

    // Borrowed from `sources`, which the fold below consumes. Narrated first,
    // which is the order it reads in anyway: what is about to happen, then what
    // happened.
    {
        let mut described = described(&sources);
        // The order the engine will fold in, so the line does not describe a
        // sequence other than the one that produced the report underneath it.
        described.sort_by_key(|source| source.observed_at);
        renderer.started(
            Phase::Merged {
                sources: &described,
            },
            redaction,
        )?;
    }

    let mut merge = Merge::new(fold(args, command::configured_identity()?));
    for (name, report) in sources {
        // Always `add_from`. `add` is for a report this process just produced,
        // and nothing here produces one: every source was read from somewhere,
        // and the name it was read under is what the merged report attributes
        // its phases to.
        merge.add_from(name, report);
    }
    let report = merge.finish();

    let written = command::deliver(&report, &destinations, redaction, renderer.as_mut())?;

    // Only where the report reached a terminal. Somebody who redirected it has
    // already answered the question this line asks, and somebody who named a
    // file has answered it twice over.
    if destinations.is_empty() && verbosity.narrates() && std::io::stdout().is_terminal() {
        render::printed(
            &mut std::io::stderr(),
            Style::commentary(presentation, palette),
        )?;
    }

    // The sources' own verdict, carried through. A fold of scans that left
    // ground uncovered describes a network nobody finished looking at, and
    // saying otherwise because the fold itself went fine would be the merged
    // report claiming more than its sources did.
    let outcome = command::outcome(&report, false);

    // A report that could not be written where it was asked is a request that
    // half happened, whatever the sources amounted to.
    Ok(if written { outcome } else { Outcome::Partial })
}

/// What each source amounts to, before the fold takes them apart.
///
/// Read here rather than from the merged report because the merged report no
/// longer has it: phases carry their origin, but the hosts have been folded
/// together and no source's own count survives that.
fn described(sources: &[(String, ScanReport)]) -> Vec<MergeSource<'_>> {
    sources
        .iter()
        .map(|(name, report)| MergeSource {
            name,
            engine_version: report.engine_version(),
            observed_at: report.observed_at(),
            hosts: Some(report.host_count()),
        })
        .collect()
}

/// What this fold was asked to assume.
///
/// The one thing about a merge a caller has to decide is what makes two records
/// the same host; everything else the engine settles. Separated from [`run`] so
/// the flag's effect can be asserted without a file on disk.
fn fold(args: &MergeArgs, configured: Option<Identity>) -> MergeOptions {
    // The flag wins, then the file, then the built-in default, which is the
    // order every other setting layers in.
    let identity = args.identity.or(configured).unwrap_or_default();
    MergeOptions::new().with_identity(identity.into())
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
    use zond_engine::diff::HostIdentity;
    use zond_engine::model::mac::MacAddr;

    use super::*;
    use crate::cli::ExportArgs;
    use crate::render::test_support::{host, recorded_at, scoped, scoped_at};

    fn asked(identity: Option<Identity>) -> MergeArgs {
        MergeArgs {
            sources: vec!["a".to_string(), "b".to_string()],
            identity,
            export: ExportArgs::default(),
        }
    }

    #[test]
    fn the_flag_names_the_engines_policy() {
        assert_eq!(
            fold(&asked(None), None).identity(),
            HostIdentity::AnyAddress
        );
        assert_eq!(
            fold(&asked(Some(Identity::Hardware)), None).identity(),
            HostIdentity::Hardware
        );
        assert_eq!(
            fold(&asked(Some(Identity::Primary)), None).identity(),
            HostIdentity::PrimaryAddress
        );
    }

    /// The flag wins over the file, and the file over the default, which is the
    /// order every other setting layers in.
    #[test]
    fn the_flag_wins_over_the_file_and_the_file_over_the_default() {
        assert_eq!(
            fold(&asked(None), Some(Identity::Hardware)).identity(),
            HostIdentity::Hardware,
            "the file, where the command line said nothing"
        );
        assert_eq!(
            fold(&asked(Some(Identity::Primary)), Some(Identity::Hardware)).identity(),
            HostIdentity::PrimaryAddress,
            "the flag, over a file that said otherwise"
        );
    }

    /// The flag has to reach the fold, not merely parse.
    ///
    /// A machine whose lease moved between two scans shares no address across
    /// them, so only the hardware policy folds it into one host. Under the
    /// default the merged report holds it twice, which is a report claiming two
    /// machines where there is one.
    #[test]
    fn hardware_folds_a_machine_whose_lease_moved_into_one_host() {
        let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3);

        let mut earlier = host(10);
        earlier.record_mac(mac);
        let mut later = host(60);
        later.record_mac(mac);

        let (earlier, later) = (
            scoped(vec![earlier], "192.0.2.0/24"),
            scoped(vec![later], "192.0.2.0/24"),
        );

        let merged = |options: MergeOptions| {
            let mut merge = Merge::new(options);
            merge.add_from("earlier", earlier.clone());
            merge.add_from("later", later.clone());
            merge.finish().host_count()
        };

        assert_eq!(merged(fold(&asked(None), None)), 2);
        assert_eq!(merged(fold(&asked(Some(Identity::Hardware)), None)), 1);
    }

    // -----------------------------------------------------------------------
    // What the commentary says went in
    // -----------------------------------------------------------------------

    /// The line above a merged report has to describe the fold that produced it,
    /// so the sources are ordered by the same clock the engine folds by.
    ///
    /// Read off the reports themselves rather than off the command line, because
    /// the command line's order is nobody's claim about time: `zond merge
    /// tonight.json q1.xml` is a reasonable thing to type.
    #[test]
    fn sources_are_described_by_their_own_clocks_not_the_order_typed() {
        let old = scoped(vec![host(1)], "192.0.2.0/24");
        let new = scoped_at(
            vec![host(1), host(2)],
            "192.0.2.0/24",
            recorded_at() + std::time::Duration::from_secs(86_400),
        );

        let sources = vec![("new".to_string(), new), ("old".to_string(), old)];
        let mut described = described(&sources);
        described.sort_by_key(|source| source.observed_at);

        let named: Vec<&str> = described.iter().map(|source| source.name).collect();
        assert_eq!(named, ["old", "new"], "the fold reads oldest first");
    }

    /// Each source's host count is its own, taken before the fold: after it,
    /// hosts that appear in two documents are one host and no source's figure
    /// survives.
    #[test]
    fn a_sources_host_count_is_the_one_it_came_in_with() {
        let sources = vec![
            ("one".to_string(), scoped(vec![host(1)], "192.0.2.0/24")),
            (
                "two".to_string(),
                scoped(vec![host(1), host(2)], "192.0.2.0/24"),
            ),
        ];

        let counts: Vec<Option<usize>> = described(&sources)
            .iter()
            .map(|source| source.hosts)
            .collect();
        assert_eq!(counts, [Some(1), Some(2)]);
    }
}
