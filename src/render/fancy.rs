// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A numbered block per host, for reading
//!
//! ```text
//! • recording this run as 06G3JC56RSVTRBTR        <- stderr
//! • discovering 1024 addresses (192.0.2.0/22)     <- stderr
//!                                                 <- stdout, from here
//!   1  192.0.2.1  router.example    1.10 ms   2 open  1 risk
//!      hardware  00:00:5e:00:53:01  Icann, Iana
//!      system    Linux 6.x [84%]
//!      answered  ARP  NDP
//!      also      2001:db8::1
//!      path      1  192.0.2.254  0.90ms
//!                2  *
//!      ports     1000 probed, 996 closed
//!                22/tcp   open      ssh    OpenSSH 9.6
//!                443/tcp  open      https  nginx 1.24
//!                           tls     1.3            X25519  alpn h2, http/1.1
//!                          cert     router.example  expires in 12d
//!                5/tcp    filtered
//!      risks     MED  443/tcp  the certificate is close to expiry
//!
//!   2  192.0.2.44
//!
//!   3  192.0.2.51                             Filtered
//!      answered  ARP
//!
//! • 3 hosts up of 1024 addresses in 4.12s         <- stderr
//! ```
//!
//! ## What this module decides, and what it does not
//!
//! The shape is [`block`]'s: the six line types, the columns
//! measured across the whole listing, and what a handle and an identity look
//! like. What is decided here is which facts a host has, in what order, and what
//! colour each one takes. Those are the judgements that need to know what a port
//! and a certificate are, which is exactly what `block` is kept ignorant of.
//!
//! ## `ports` is late on purpose, and `risks` is last
//!
//! `ports` is the longest child, and a long value is cheapest at the bottom of a
//! block: its continuation lines run down into empty space rather than pushing
//! the rest of the facts away from the header they belong to. `risks` follows
//! it, because a finding is a conclusion drawn from everything above it.
//!
//! What a table left out is drawn at its *head* rather than its foot. It is the
//! table's scope and not a footnote to it: nine rows mean something different
//! once you know they are nine of a thousand, and a count arriving afterwards
//! has already been read past — with nothing between it and the findings.
//!
//! ## What a block pays for
//!
//! Only what it has. Every child is conditional, so a host nothing was learned
//! about is its header line alone, which is what keeps a sweep of a mostly empty
//! `/22` from being two hundred near-identical blocks. There are no
//! placeholders.
//!
//! ## The header carries what a listing is scanned for
//!
//! Which machine, what it calls itself, how far away it is, and what came of it,
//! on one line. The fastest round trip rides here in a column of its own rather
//! than taking a row; what the round trips did *apart* from the fastest is a
//! separate fact, and waits for `-v`.
//!
//! ## The number is the handle
//!
//! A host opens with its place in the listing, right-aligned to the width of the
//! largest, so the numbers form a straight column whatever the run turned up and
//! a person can say "look at four" about a screen neither of you can point at.
//! Every label beneath then starts in the column the address starts in.
//!
//! **Colour never carries a fact by itself.** See [`style`](super::style): every
//! state a colour marks is also a word, and a host that is anything other than
//! up says so on its header line.

use std::io::{self, BufWriter, Write};

use zond_engine::export::Redaction;
use zond_engine::model::finding::Severity;
use zond_engine::record::wire;
use zond_engine::{Host, HostStatus, PortState, ScanReport};

use crate::diagnostics::Verbosity;
use crate::render::block::{self, Block, Child, Detail, Header, Row};
use crate::render::narrate::Narrator;
use crate::render::progress::{self, Counting};
use crate::render::style::{Palette, Style};
use crate::render::{Phase, Renderer, field};

/// The tree renderer.
pub(crate) struct FancyRenderer {
    records: Box<dyn Write>,
    narrator: Narrator,
    reader: field::Reader,
    /// The record stream's own style, which is not the commentary stream's:
    /// `zond discover lan | less` redirects one and not the other.
    style: Style,
    /// Decides whether a block shows the working behind its operating-system
    /// finding and behind a certificate.
    verbosity: Verbosity,
    /// How many columns the record stream has to fold a long value to.
    ///
    /// Held rather than asked for at drawing time, so that a renderer built over
    /// a vector draws the same thing whatever window the test happens to run in.
    width: usize,
    /// What this run asked to be shown beyond the basics.
    ///
    /// Apart from `verbosity` because the axes answer different readers, and
    /// resolved by the caller rather than derived here: the flags and the
    /// settings file layer in one place, and a renderer that worked any of it
    /// out again would be a second place for the two to disagree.
    showing: field::Showing,
}

impl FancyRenderer {
    /// Writing to this process's own streams.
    #[must_use]
    pub(crate) fn to_terminal(
        verbosity: Verbosity,
        palette: Palette,
        showing: field::Showing,
    ) -> Self {
        // Records are buffered, since they arrive as thousands of lines in one
        // burst at the end. Commentary is not: a progress line held in a buffer
        // is not progress.
        Self {
            width: super::width(),
            ..Self::new(
                Box::new(BufWriter::new(io::stdout())),
                Box::new(io::stderr()),
                verbosity,
                Style::for_stdout(palette),
                Style::for_stderr(palette),
            )
            .showing(showing)
        }
    }

    /// The same renderer, told what to show beyond the basics.
    ///
    /// Apart from [`new`](Self::new) because every test that builds one wants
    /// the default, and threading a further argument through all of them to say
    /// so would obscure the two that are about writing somewhere.
    #[must_use]
    pub(crate) fn showing(mut self, showing: field::Showing) -> Self {
        self.showing = showing;
        self
    }

    /// Writing wherever the caller says, which is how this is tested.
    #[must_use]
    pub(crate) fn new(
        records: Box<dyn Write>,
        narration: Box<dyn Write>,
        verbosity: Verbosity,
        style: Style,
        narration_style: Style,
    ) -> Self {
        Self {
            records,
            narrator: Narrator::new(narration, verbosity, narration_style),
            reader: field::Reader::default(),
            style,
            verbosity,
            width: super::ASSUMED_WIDTH,
            showing: field::Showing::default(),
        }
    }
}

/// What the line at the bottom counts for a run of this kind.
///
/// A sweep is asking who is there, so it counts hosts. A port scan was handed
/// its hosts and is asking what is open, so counting them again would be
/// counting its own input back.
///
/// `None` for a record read off disk or a fold of several: nothing is running,
/// so there is nothing for a line at the bottom to say about it.
fn counting(phase: Phase<'_>) -> Option<Counting> {
    match phase {
        // One arm, because a watch is asking the sweep's question — who is
        // there — and only asks it differently, by waiting rather than probing.
        // What the line at the bottom counts follows from the question and not
        // from how it was put.
        Phase::Discovery { .. } | Phase::Listen { .. } => Some(Counting::Hosts),
        Phase::PortScan { .. } => Some(Counting::Ports),
        Phase::Recorded { .. } | Phase::Merged { .. } | Phase::Folded { .. } => None,
    }
}

/// The line a block opens with: which machine this is, and what came of it.
fn header(style: Style, reader: field::Reader, host: &Host, at: usize) -> Header {
    Header {
        at: Some(at),
        // A scan does not sort its hosts into kinds; what came of one trails it.
        tag: None,
        identity: reader.primary(host),
        // The name says which machine this is, so it belongs with the address
        // rather than among the things that were learned about it.
        name: reader.hostname(host),
        verdict: verdict(style, host),
    }
}

/// What came of the host, in the fewest words that say it.
///
/// Nothing at all for a host that is simply up and had no ports probed, which is
/// every host in an ordinary discovery sweep. The block existing has already
/// said it.
fn verdict(style: Style, host: &Host) -> Option<String> {
    let mut parts = Vec::new();

    if !field::is_up(host) {
        let status = field::status(host);
        parts.push(match host.status() {
            HostStatus::Filtered => style.caution(&status),
            _ => style.faint(&status),
        });
    }

    if let Some((open, _probed)) = field::open_ports(host) {
        parts.push(if open == 0 {
            style.faint("no open ports")
        } else {
            style.good(&format!("{open} open"))
        });
    }

    // What is wrong with this host, on the line that says which host it is.
    // Findings are the reason a scan was run and they were only readable by
    // reading the block; a count here is what lets a sweep be scanned for the
    // hosts worth opening. Coloured by the worst grade present, and the count and
    // the word are both spelled, so the colour only ranks what the text says.
    if let Some((count, worst)) = field::host_risks(host) {
        let counted = format!("{count} {}", if count == 1 { "risk" } else { "risks" });
        parts.push(style.by_urgency(field::severity_urgency(worst), &counted));
    }

    // A column between them rather than a comma. Two reasons, and the second is
    // the one that decided it: these are separate measurements and not a list,
    // so they take the same gap the address and the name beside them take — and a
    // comma is an unpainted character between two painted ones, which is exactly
    // the thing `block` stopped drawing when the rules came out. It arrived in
    // whatever the terminal's default foreground happened to be, which on a good
    // many themes is brighter than anything in the palette.
    (!parts.is_empty()).then(|| parts.join(&" ".repeat(block::GAP)))
}

/// The facts this host has, in the order they are drawn.
///
/// `ports` last, and not by accident: it is the longest, and the longest value
/// is the one whose continuation lines are cheapest at the bottom of a block.
fn children<'a>(
    style: Style,
    reader: field::Reader,
    host: &'a Host,
    listing: &field::PortListing,
    verbosity: Verbosity,
    showing: field::Showing,
) -> Vec<Child<'a>> {
    let mut children = Vec::new();

    // The vendor was read out of the hardware address, so it is shown against
    // it, and faintly, because it qualifies that address rather than competing
    // with it. Spelled the way a person says it: see `field::spoken_vendor`.
    if let Some(macs) = reader.macs(host) {
        let line = match field::vendor(host) {
            Some(vendor) => format!(
                "{}  {}",
                style.plain(&macs),
                style.faint(field::spoken_vendor(vendor))
            ),
            None => style.plain(&macs),
        };
        children.push(Child::one("hardware", line));
    }

    // What the machine calls itself, and the domain it says it belongs to,
    // under the hardware because both say which box this is. Apart from the
    // name in the header, which is what name resolution answered: this is the
    // machine's own account, and a domain is not a name for the address. The
    // kind is faint, since it qualifies the name rather than competing with it,
    // and in a column of its own, so a reader runs down the names alone.
    let stated = reader.names(host);
    let width = stated
        .iter()
        .map(|(name, _)| name.chars().count())
        .max()
        .unwrap_or(0);
    let names: Vec<String> = stated
        .into_iter()
        .map(|(name, kind)| {
            let pad = " ".repeat(width - name.chars().count() + 2);
            format!("{}{pad}{}", style.plain(&name), style.faint(kind))
        })
        .collect();
    if !names.is_empty() {
        children.push(Child::many("names", names));
    }

    // Directly under the hardware, because the two answer the same question from
    // different sides: what this box is, and what it does. A role is also the
    // one finding here the engine can make without probing, since a router
    // advertisement arrives unasked, so a host may carry one and nothing else.
    if let Some(roles) = field::roles(host) {
        children.push(Child::one("roles", style.plain(&roles)));
    }

    if let Some(os) = field::os(host) {
        children.push(Child::one("system", style.plain(&os)));
    }

    // What the scan concluded is in front of the host, where it drew a
    // conclusion. Beside `system` because the two answer neighbouring
    // questions — what this box is, and what stands between it and the scan —
    // and cautioned, because a filter is why a port reads as it does. Drawn from
    // `--characterise` and from the stateless-filter probe alike; this shows
    // whatever the host carries, whichever produced it.
    if let Some(filtering) = field::filtering(host) {
        children.push(Child::one("filter", style.caution(&filtering)));
    }

    // Directly under `system` because it is that line's working: the shape of
    // each reply the verdict was drawn from. Only under detail, because a person
    // using the finding wants the finding and a person checking it wants this.
    if verbosity.explains()
        && let Some(working) = field::os_evidence(host)
    {
        children.push(Child::one("evidence", style.plain(&working)));
    }

    // One line per piece of evidence under `--reason`, because the long form
    // carries what was observed and who sent it, and those do not fit beside
    // each other on one line. The label stays: it is the same question answered
    // at two depths, not two questions.
    if showing.reasons {
        let detailed = field::answered_in_detail(reader, host);
        if !detailed.is_empty() {
            children.push(Child::many(
                "answered",
                detailed.iter().map(|line| style.plain(line)).collect(),
            ));
        }
    } else if let Some(answered) = field::answered(host) {
        children.push(Child::one("answered", style.plain(&answered)));
    }

    // Under `answered`, because the reply that came back and how long it took are
    // one subject read at two depths. A row rather than a figure on the header:
    // the header says which host this is and what came of it, and a measurement
    // squeezed between the name and the verdict is a third thing competing with
    // both. Three figures where the round trips disagreed and one where they did
    // not, since then two of the three would be the same number again.
    if let Some(latency) = field::latency(host) {
        children.push(Child::one("latency", style.plain(&latency)));
    }

    // The further addresses only. The primary is already on the header line, and
    // a link-local the host derived from the hardware address two lines up is
    // that address written again, and `-v` keeps it. See
    // `Reader::other_addresses`.
    //
    // Drawn as the block is written rather than gathered here, since a host
    // can answer at more addresses than it is worth holding a line for each.
    let all = verbosity.explains();
    if reader.other_addresses(host, all).next().is_some() {
        children.push(Child::drawn("also", move || {
            reader
                .other_addresses(host, all)
                .map(move |address| style.plain(&address))
        }));
    }

    // Above the ports because it is about how this host was reached rather than
    // what was found on it. Built from the parts rather than the finished line,
    // so the step number is furniture and the router is a finding.
    let path = field::hops(reader, host);
    if !path.is_empty() {
        children.push(Child::many(
            "path",
            path.iter()
                .map(|hop| {
                    let mut line =
                        format!("{}  {}", style.faint(&hop.step), style.plain(&hop.address));
                    if let Some(detail) = &hop.detail {
                        line.push_str("  ");
                        line.push_str(&style.faint(detail));
                    }
                    line
                })
                .collect(),
        ));
    }

    if !listing.rows.is_empty() || !listing.notes.is_empty() {
        children.push(ports(style, listing));
    }

    // Which IP protocols the host's stack takes delivery of, from
    // `--ip-protocols`. Beside the ports rather than among them, because it
    // answers a different question — what the host speaks, not what listens on
    // it — and one line per protocol, the way `also` and `path` list their
    // members.
    let protocols = field::ip_protocols(host);
    if !protocols.is_empty() {
        children.push(Child::many(
            "ip",
            protocols.iter().map(|line| style.plain(line)).collect(),
        ));
    }

    // Last, and under everything the scan measured, because a finding is a
    // conclusion drawn from all of it: what a known vulnerability or a detection
    // says is wrong with this host or one of its ports. The severity carries the
    // colour, so the eye lands on the worst line first; the rest of the line is
    // plain, the subject included, so nothing competes with the verdict.
    let risks = field::findings(host, showing.risk);
    if !risks.rows.is_empty() || risks.withheld > 0 {
        children.push(findings(style, &risks, verbosity, showing));
    }

    children
}

/// The `risks` child: one line per finding, worst first, in columns.
///
/// A child like any other. The severity leads as a short token and is the only
/// part coloured, so the column the eye runs down is a band of colour rather
/// than five words of different lengths; the subject sits beside it saying
/// *where*, in the same ink as the title because it is the one column tying a
/// finding back to the port table above it and furniture is not what it is.
/// Citations trail the title
/// in a column of their own, and the confidence follows only where the finding
/// is short of certain. The fix and the full port list hang off the line under
/// `-v`, the way a certificate's working does, because a person triaging wants
/// the finding and a person acting on it wants the rest. What the detection
/// actually saw hangs under `--reason` instead, which is the flag for the
/// evidence behind a verdict rather than the working behind a conclusion.
fn findings(
    style: Style,
    listing: &field::FindingListing,
    verbosity: Verbosity,
    showing: field::Showing,
) -> Child<'static> {
    let mut rows = Vec::new();
    let views = &listing.rows;

    // What the floor kept back, at the head of the child the way a port table's
    // scope sits at the head of its own. A finding out of sight must not also be
    // out of the count: the header still totals every one of them, and this says
    // how many of that total are not drawn below.
    if listing.withheld > 0 {
        rows.push(Row::plain(style.faint(&format!(
            "{} below {}, --risk {} to see {}",
            listing.withheld,
            showing.risk,
            wire::severity_name(Severity::Info),
            if listing.withheld == 1 { "it" } else { "them" }
        ))));
    }

    for view in views {
        // Every column is painted trimmed and padded after, so no escape
        // sequence ever wraps a run of spaces: what the terminal measures is
        // exactly what the widths were computed from.
        let token = view.token.trim_end();
        let subject = view.subject.trim_end();

        let mut line = format!(
            "{}{}  {}{}  {}",
            style.by_urgency(field::severity_urgency(view.severity), token),
            " ".repeat(view.token.len() - token.len()),
            style.plain(subject),
            " ".repeat(view.subject.chars().count() - subject.chars().count()),
            style.plain(&view.title)
        );

        if let Some(reference) = &view.reference {
            line.push_str(&" ".repeat(view.pad));
            line.push_str("  ");
            line.push_str(&style.faint(reference));
        }

        if let Some(confidence) = view.confidence {
            if view.reference.is_none() {
                line.push_str(&" ".repeat(view.pad));
            }
            line.push_str("  ");
            line.push_str(&style.faint(&format!("~{confidence}")));
        }

        // Raw, not painted: a `Detail` carries text and the block paints it,
        // which is also what lets the block measure it. Painting here would hand
        // the block escape bytes to escape again, and they would be drawn.
        let mut detail = Vec::new();
        // Always, not behind a flag. A correlated finding says a host has
        // forty-four known vulnerabilities and the first question is which; an
        // answer that needs a second run with a flag on is not an answer. It is
        // one line because it is capped, which is the whole reason it can be
        // shown by default.
        if let Some(cves) = &view.cves {
            detail.push(Detail::new("cve", cves.clone()));
        }
        if showing.excerpts
            && let Some(seen) = &view.evidence
        {
            detail.push(Detail::new("evidence", seen.clone()));
        }
        if verbosity.explains()
            && let Some(ports) = &view.ports
        {
            detail.push(Detail::new("on", ports.clone()));
        }
        if showing.remedies
            && let Some(remediation) = &view.remediation
        {
            detail.push(Detail::new("remedy", remediation.clone()));
        }

        rows.push(Row::with_detail(line, detail));
    }

    let title_column = views.first().map_or(0, |view| {
        view.token.chars().count() + block::GAP + view.subject.chars().count() + block::GAP
    });

    Child::rows("risks", rows).details_at(title_column)
}

/// The `ports` child: a table, and whatever hangs off one of its rows.
///
/// A child like any other, which is the whole point: the table is what this
/// value happens to be, not a section of its own.
fn ports(style: Style, listing: &field::PortListing) -> Child<'static> {
    let mut rows = Vec::new();

    // The renderer's own notes, about what this table covers and what it decided
    // not to enumerate. First, because they are its scope rather than a footnote
    // to it: nine rows mean something different once you know they are nine of a
    // thousand, and a count arriving afterwards has already been read past.
    // Faint, and with nothing in the column the port numbers are bold in, which
    // is what makes them read as this program talking rather than as more ports.
    for note in &listing.notes {
        rows.push(Row::plain(style.faint(note)));
    }

    for row in &listing.rows {
        // Every column is painted trimmed and padded after, so no escape
        // sequence ever wraps a run of spaces: what the terminal measures is
        // exactly what the widths were computed from.
        let endpoint = row.port.trim_end();
        let word = row.state.trim_end();

        let mut text = format!(
            "{}{}  {}",
            style.strong(endpoint),
            " ".repeat(row.port.len() - endpoint.len()),
            state(style, row)
        );

        if let Some(service) = &row.service {
            let name = service.trim_end();
            text.push_str(&" ".repeat(row.state.len() - word.len()));
            text.push_str("  ");

            // Faint where the engine looked the name up from the port number,
            // plain where a probe established it. The palette already said which
            // ink belongs to what a scan established; drawing a guess in it was
            // this crate claiming more than the engine had.
            text.push_str(&if row.inferred {
                style.faint(name)
            } else {
                style.plain(name)
            });

            // A column of its own, because what kind of thing a port is and what
            // is answering on it are two facts. They used to be one string
            // joined by a space, which is also the character inside
            // `Epson_IPP-Server 2.0.0`, so nothing separated them.
            if let Some(product) = &row.product {
                text.push_str(&" ".repeat(service.chars().count() - name.chars().count()));
                text.push_str("  ");
                text.push_str(&style.plain(product));
            }
        }

        rows.push(Row::with_detail(
            text,
            row.detail.iter().map(hanging).collect(),
        ));
    }

    Child::rows("ports", rows).details_at(service_column(listing))
}

/// How far into a port row its description begins.
///
/// What hangs off a row belongs under that description rather than in a column
/// of its own, so a certificate sits under the service it was presented for.
/// Read off the first row, since every row in a listing is padded alike.
fn service_column(listing: &field::PortListing) -> usize {
    listing.rows.first().map_or(0, |row| {
        row.port.chars().count() + block::GAP + row.state.chars().count() + block::GAP
    })
}

/// A port's state, coloured by what it is.
fn state(style: Style, row: &field::PortRow) -> String {
    let word = row.state.trim_end();

    match row.verdict {
        PortState::Open => style.good(word),
        PortState::Filtered | PortState::OpenFiltered => style.caution(word),
        _ => style.faint(word),
    }
}

/// A fact hanging off a port, in the block's own grammar one level in.
fn hanging(detail: &field::PortDetail) -> Detail {
    let carried = Detail::new(detail.label, detail.value.clone());

    match &detail.note {
        Some(note) => carried.noted(note.clone(), detail.urgency),
        None => carried,
    }
}

impl Renderer for FancyRenderer {
    fn started(&mut self, phase: Phase<'_>, redaction: Redaction) -> io::Result<()> {
        self.reader = field::Reader::new(redaction);
        self.narrator.started(phase, redaction)?;

        if let Some(counting) = counting(phase) {
            progress::start(counting, self.style);
        }

        Ok(())
    }

    fn progressed(&mut self, hosts: usize, open: usize) -> io::Result<()> {
        progress::seen(hosts, open);
        Ok(())
    }

    fn budget_spent(&mut self) {
        self.narrator.budget_spent();
    }

    fn interrupted(&mut self) -> io::Result<()> {
        progress::stop();
        self.narrator.interrupted()
    }

    fn finished(&mut self, report: &ScanReport) -> io::Result<()> {
        // Before a single record is written: the answer goes where the line was.
        progress::stop();

        let hosts = field::sorted_hosts(report);
        let trustworthy = field::silence_means_something(report);

        // Once, for the whole listing: a host whose highest port is `9100/tcp`
        // and one whose highest is `80/tcp` used to put `open` in different
        // columns, because each measured its own table.
        let listings = field::port_listings(&hosts, trustworthy, self.showing);

        // Every block is built before any of it is drawn, because the columns
        // are measured across the listing: a handle right-aligned to the widest,
        // a verdict in a column the longest name allows. See `block::Columns`.
        let blocks: Vec<Block> = hosts
            .iter()
            .zip(listings.iter())
            .enumerate()
            .map(|(index, (host, listing))| Block {
                header: header(self.style, self.reader, host, index + 1),
                children: children(
                    self.style,
                    self.reader,
                    host,
                    listing,
                    self.verbosity,
                    self.showing,
                ),
            })
            .collect();

        // The separator belongs to the listing, so it goes on the record stream.
        // Above the first block only if there is commentary to separate it from.
        let narrates = self.narrator.narrates();
        block::write_all(
            &mut self.records,
            self.style,
            &blocks,
            self.width,
            |out, index| {
                if index > 0 || narrates {
                    writeln!(out)?;
                }
                Ok(())
            },
        )?;

        self.records.flush()?;
        self.narrator.summary(report)
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
    use crate::render::test_support::{Capture, host, opener, painting, strip_escapes};

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use zond_engine::model::confidence::Confidence;
    use zond_engine::model::finding::{
        DetectionClass, DetectionId, Excerpt, Finding, Reference, Severity, Version,
    };
    use zond_engine::model::host::OsFingerprint;
    use zond_engine::model::host::path::Hop;
    use zond_engine::model::host::status::{StatusProtocol, StatusReason};
    use zond_engine::model::ip::scoped::Zone;
    use zond_engine::model::port::security::{CertificateInfo, Security};
    use zond_engine::model::tls::{
        CipherSuite, Interruption, TlsSupport, TlsVersion, UnfinishedVersion, VersionSupport,
    };
    use zond_engine::{Port, Protocol, Service};

    use std::str::FromStr;

    use crate::settings::Risk;

    /// The block a plain run writes: no colour, no detail asked for. Asserting
    /// on this reads the layout rather than a wall of escapes.
    fn block(host: &Host) -> String {
        rendered(field::Reader::default(), host, Verbosity::default())
    }

    /// The block a run asked for detail writes.
    fn explained(host: &Host) -> String {
        rendered(field::Reader::default(), host, Verbosity::new(1, false))
    }

    fn rendered(reader: field::Reader, host: &Host, verbosity: Verbosity) -> String {
        drawn(Style::bare(), reader, host, verbosity)
    }

    /// A host with one finding carrying both an excerpt and advice, which is the
    /// pair the two flags each reach for one of.
    fn with_evidence_and_remedy() -> Host {
        let mut host = host(9);
        host.add_port(Port::new(443, Protocol::Tcp, PortState::Open));
        host.add_port_finding(
            443,
            Protocol::Tcp,
            finding(
                "zond:http/missing-security-headers",
                "missing 4 of 4 HTTP security headers",
                Severity::Medium,
                Confidence::Certain,
            )
            .with_excerpt(Excerpt::new("missing: strict-transport-security"))
            .with_remediation("set the four headers at the reverse proxy"),
        );
        host
    }

    /// The block a run asking for `showing` writes.
    ///
    /// Every helper here draws from the floor up: these tests are about the
    /// shape of a listing, and a fixture graded below the default floor would
    /// otherwise go missing from the thing being measured.
    fn shown(host: &Host, showing: field::Showing) -> String {
        drawn_showing(
            Style::bare(),
            field::Reader::default(),
            host,
            Verbosity::default(),
            showing,
        )
    }

    /// One host as a listing of one, which is how a block is measured: the
    /// columns come from the whole listing, so there is no drawing a block
    /// outside of one.
    fn drawn(style: Style, reader: field::Reader, host: &Host, verbosity: Verbosity) -> String {
        drawn_showing(
            style,
            reader,
            host,
            verbosity,
            field::Showing {
                certificates: verbosity.explains(),
                ..Default::default()
            },
        )
    }

    /// The same, for the tests about what `--reason` adds.
    fn drawn_showing(
        style: Style,
        reader: field::Reader,
        host: &Host,
        verbosity: Verbosity,
        showing: field::Showing,
    ) -> String {
        // From the floor up. These tests are about the shape of a listing, and a
        // fixture graded below the default floor would otherwise go missing from
        // the thing being measured. The floor has tests of its own.
        let showing = field::Showing {
            risk: Risk::everything(),
            ..showing
        };

        let listing = field::port_listings(&[host], true, showing);
        let blocks = vec![Block {
            header: header(style, reader, host, 1),
            children: children(style, reader, host, &listing[0], verbosity, showing),
        }];

        let mut out = Vec::new();
        block::write_all(&mut out, style, &blocks, WIDTH, |_, _| Ok(()))
            .expect("a vector cannot fail");
        String::from_utf8(out).expect("the renderer writes text")
    }

    /// A whole listing, measured together the way a run measures one.
    fn listing(hosts: &[&Host]) -> String {
        let style = Style::bare();
        let reader = field::Reader::default();

        let blocks: Vec<Block> = hosts
            .iter()
            .enumerate()
            .map(|(index, host)| Block {
                header: header(style, reader, host, index + 1),
                children: Vec::new(),
            })
            .collect();

        let mut out = Vec::new();
        block::write_all(&mut out, style, &blocks, WIDTH, |_, _| Ok(()))
            .expect("a vector cannot fail");
        String::from_utf8(out).expect("the renderer writes text")
    }

    /// The width every test draws at, so a test's expectations do not depend on
    /// the window it happens to run in.
    const WIDTH: usize = crate::render::ASSUMED_WIDTH;

    /// The column every value in a one-block listing begins in.
    fn value_column(host: &Host) -> usize {
        let style = Style::bare();
        let showing = field::Showing::default();
        let listing = field::port_listings(&[host], true, showing);

        block::Columns::of(
            &[Block {
                header: header(style, field::Reader::default(), host, 1),
                children: children(
                    style,
                    field::Reader::default(),
                    host,
                    &listing[0],
                    Verbosity::default(),
                    showing,
                ),
            }],
            WIDTH,
        )
        .value_column()
    }

    /// The same block, painted, for the tests about colour.
    fn painted(host: &Host) -> String {
        drawn(
            painting(),
            field::Reader::default(),
            host,
            Verbosity::default(),
        )
    }

    fn furnished() -> Host {
        let mut host = host(1);
        host.add_ip("fe80::1".parse().expect("a valid address"));
        host.set_zone(Zone::new(4, "en0"));
        host.add_rtt(Duration::from_micros(1_420));
        host.add_reason(StatusReason::new(StatusProtocol::Arp, "reply"));
        host.add_reason(StatusReason::new(StatusProtocol::Ndp, "advertisement"));
        host.record_mac("00:00:5e:00:53:01".parse().expect("a valid address"));
        host.set_hostname(Some("router.example".to_owned()));
        host.record_hop(Hop::answered(
            1,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)),
            Some(Duration::from_micros(900)),
        ));
        host.record_hop(Hop::silent(2));
        host
    }

    /// A host serving TLS on 443, with a certificate ending at `expiry`.
    fn serving_tls(expiry: std::time::SystemTime) -> Host {
        let mut host = host(30);
        let certificate = CertificateInfo::new(
            "printer.example",
            "Let's Encrypt R3",
            std::time::SystemTime::now() - Duration::from_secs(400 * 86_400),
            expiry,
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        );
        host.add_port(
            Port::new(443, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("https", 100).with_product("nginx"))
                .with_security(
                    Security::new()
                        .with_tls_version("1.3")
                        .with_cipher_suite("X25519")
                        .with_alpn("h2")
                        .with_certificate(certificate),
                ),
        );
        host
    }

    /// A host serving TLS 1.3 on 443, whose enumeration established `support`.
    fn enumerated(support: TlsSupport) -> Host {
        let mut host = host(31);
        host.add_port(
            Port::new(443, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("https", 100).with_product("nginx"))
                .with_security(
                    Security::new()
                        .with_tls_version("TLSv1.3")
                        .with_cipher_suite("TLS_AES_256_GCM_SHA384")
                        .with_support(support),
                ),
        );
        host
    }

    /// What an endpoint accepting one TLS 1.2 suite is recorded as accepting.
    fn accepting_tls12() -> TlsSupport {
        let suite = CipherSuite::from_code(0xC02F).expect("a suite the registry carries");
        TlsSupport::new().accepting(VersionSupport::new(
            TlsVersion::Tls12,
            vec![suite],
            Vec::new(),
        ))
    }

    /// A finding of `severity` about `title`, from a detection named `id`.
    fn finding(id: &str, title: &str, severity: Severity, confidence: Confidence) -> Finding {
        let detection = DetectionId::new(id, Version::new(1, 0, 0), "")
            .expect("a non-empty id is a valid detection id");
        Finding::new(
            detection,
            title,
            severity,
            confidence,
            DetectionClass::Passive,
        )
        .expect("a non-empty title is a valid finding")
    }

    /// A host carrying a critical port finding and a medium host finding, for
    /// the block that draws risks.
    fn at_risk() -> Host {
        let mut host = host(7);
        host.add_port(Port::new(443, Protocol::Tcp, PortState::Open));
        host.add_port_finding(
            443,
            Protocol::Tcp,
            finding(
                "zond:cve/CVE-2021-44228",
                "Log4Shell remote code execution",
                Severity::Critical,
                Confidence::Certain,
            )
            .with_reference(Reference::cve("CVE-2021-44228").expect("a well-formed CVE id")),
        );
        host.add_finding(finding(
            "zond:host/telnet-exposed",
            "Telnet is reachable",
            Severity::Medium,
            Confidence::Probable,
        ));
        host
    }

    /// The same detection firing on several ports of one host, which is the case
    /// the listing folds.
    fn repeated(ports: &[u16], severity: Severity, confidence: Confidence) -> Host {
        let mut host = host(9);
        for number in ports {
            host.add_port(Port::new(*number, Protocol::Tcp, PortState::Open));
            host.add_port_finding(
                *number,
                Protocol::Tcp,
                finding(
                    "zond:http/missing-security-headers",
                    "missing HTTP security headers",
                    severity,
                    confidence,
                )
                .with_reference(Reference::cwe(693)),
            );
        }
        host
    }

    /// The worst finding leads, its severity and subject in the line, and the
    /// CVEs it cites on a line beneath.
    ///
    /// Beneath rather than beside: a correlated finding cites every CVE it
    /// matched, and forty-four identifiers on a row buries the finding they
    /// belong to and every row under it. The row keeps the shape every other row
    /// has — severity, subject, title, weakness class — and the identifiers get
    /// their own line, capped and worst first.
    #[test]
    fn a_finding_is_drawn_worst_first_with_its_subject_and_its_cves_beneath() {
        let text = block(&at_risk());

        // Past the header, which carries a risk count of its own now.
        let risks: Vec<&str> = text
            .lines()
            .skip(1)
            .skip_while(|line| !line.contains("risks"))
            .collect();

        assert!(
            risks[0].contains("CRIT")
                && risks[0].contains("443/tcp")
                && risks[0].contains("Log4Shell"),
            "the critical port finding should lead, with its subject: {text}"
        );
        assert!(
            !risks[0].contains("CVE-2021-44228"),
            "the identifiers are not on the row: {text}"
        );
        assert!(
            risks[1].contains("cve") && risks[1].contains("CVE-2021-44228"),
            "they are on the line under it: {text}"
        );
        assert!(
            risks.iter().any(|line| line.contains("MED")
                && line.contains("Telnet")
                && line.contains("host")
                && !line.contains("/tcp")),
            "the host finding is about the host rather than a port: {text}"
        );
        assert!(
            text.find("CRIT").expect("critical is drawn")
                < text.find("MED").expect("medium is drawn"),
            "the worse finding comes first: {text}"
        );
    }

    /// Every severity token starts and ends in one column, so the colour the eye
    /// runs down is a band rather than five words of different lengths.
    #[test]
    fn severity_tokens_share_a_column() {
        let text = block(&at_risk());

        let risks: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("CRIT") || line.contains("MED"))
            .collect();
        assert_eq!(risks.len(), 2, "both findings are drawn: {text}");

        let tokens: Vec<usize> = risks
            .iter()
            .map(|line| {
                line.find("CRIT")
                    .or_else(|| line.find("MED"))
                    .expect("the line was chosen for carrying one")
            })
            .collect();
        assert_eq!(
            tokens[0], tokens[1],
            "the tokens start in one column: {text}"
        );

        let subjects: Vec<usize> = risks
            .iter()
            .map(|line| {
                line.find("443/tcp")
                    .or_else(|| line.find("host"))
                    .expect("every row says what it is about")
            })
            .collect();
        assert_eq!(
            subjects[0], subjects[1],
            "the subjects start in one column: {text}"
        );

        let titles: Vec<usize> = risks
            .iter()
            .map(|line| {
                line.find("Log4Shell")
                    .or_else(|| line.find("Telnet"))
                    .expect("every row carries its title")
            })
            .collect();
        assert_eq!(
            titles[0], titles[1],
            "the titles start in one column: {text}"
        );
    }

    /// The floor holds a grade back from the listing without holding it back
    /// from the count. A finding out of sight must not also be out of the total.
    #[test]
    fn a_finding_below_the_floor_is_held_back_but_still_counted() {
        let host = at_risk();

        let drawn = |floor: Risk| {
            let showing = field::Showing {
                risk: floor,
                ..Default::default()
            };
            let style = Style::bare();
            let reader = field::Reader::default();
            let listing = field::port_listings(&[&host], true, showing);
            let blocks = vec![Block {
                header: header(style, reader, &host, 1),
                children: children(
                    style,
                    reader,
                    &host,
                    &listing[0],
                    Verbosity::default(),
                    showing,
                ),
            }];

            let mut out = Vec::new();
            block::write_all(&mut out, style, &blocks, WIDTH, |_, _| Ok(()))
                .expect("a vector cannot fail");
            String::from_utf8(out).expect("the renderer writes text")
        };

        let everything = drawn(Risk::everything());
        assert!(everything.contains("Log4Shell"), "{everything}");
        assert!(everything.contains("Telnet"), "{everything}");

        // `at_risk` carries one critical and one medium, so a high floor draws
        // the first and holds the second.
        let raised = drawn(Risk::from_str("high").expect("a grade"));
        assert!(raised.contains("Log4Shell"), "{raised}");
        assert!(
            !raised.contains("Telnet"),
            "the floor did not hold: {raised}"
        );
        assert!(
            raised.contains("1 below high"),
            "the block does not say what it held back: {raised}"
        );

        // And the header still totals both, whatever the floor draws.
        for text in [&everything, &raised] {
            assert!(
                text.lines()
                    .next()
                    .is_some_and(|line| line.contains("2 risks")),
                "the count was filtered along with the listing: {text}"
            );
        }
    }

    /// A floor that holds everything back still draws the child, because the
    /// alternative is a host that silently reports nothing.
    #[test]
    fn a_host_whose_findings_are_all_below_the_floor_still_says_so() {
        let mut host = host(12);
        host.add_finding(finding(
            "zond:host/telnet-exposed",
            "Telnet is reachable",
            Severity::Low,
            Confidence::Certain,
        ));

        let showing = field::Showing {
            risk: Risk::from_str("critical").expect("a grade"),
            ..Default::default()
        };
        let style = Style::bare();
        let reader = field::Reader::default();
        let listing = field::port_listings(&[&host], true, showing);
        let blocks = vec![Block {
            header: header(style, reader, &host, 1),
            children: children(
                style,
                reader,
                &host,
                &listing[0],
                Verbosity::default(),
                showing,
            ),
        }];

        let mut out = Vec::new();
        block::write_all(&mut out, style, &blocks, WIDTH, |_, _| Ok(()))
            .expect("a vector cannot fail");
        let text = String::from_utf8(out).expect("the renderer writes text");

        assert!(text.contains("1 risk"), "{text}");
        assert!(text.contains("1 below critical"), "{text}");
    }

    /// A verbose title does not take its own citation out of the column.
    ///
    /// The column used to be capped at forty-six characters without the titles
    /// being capped, so a detection that wrote a long sentence carried its
    /// reference past everybody else's — and the column the cap existed to
    /// protect was ragged exactly where it mattered.
    #[test]
    fn a_long_title_does_not_break_the_citation_column() {
        let mut host = host(11);
        host.add_port(Port::new(443, Protocol::Tcp, PortState::Open));
        host.add_port_finding(
            443,
            Protocol::Tcp,
            finding(
                "zond:http/unauthenticated-interface",
                "the printer's web interface answers without a password at all",
                Severity::Medium,
                Confidence::Certain,
            )
            .with_reference(Reference::cwe(306)),
        );
        host.add_port_finding(
            443,
            Protocol::Tcp,
            finding(
                "zond:http/missing-security-headers",
                "missing 2 of 4 HTTP security headers",
                Severity::Low,
                Confidence::Certain,
            )
            .with_reference(Reference::cwe(693)),
        );

        let text = block(&host);
        let citation = |needle: &str| {
            text.lines()
                .find(|line| line.contains(needle))
                .and_then(|line| line.find("CWE-"))
                .unwrap_or_else(|| panic!("no citation beside {needle}: {text}"))
        };

        assert_eq!(
            citation("without a password"),
            citation("missing 2 of 4"),
            "a title past the old cap took its citation with it: {text}"
        );
    }

    /// One detection firing on three ports is one weakness in three places, so it
    /// draws one row naming them rather than three repeating a sentence.
    #[test]
    fn alike_findings_fold_into_one_row() {
        let text = block(&repeated(
            &[80, 443, 631],
            Severity::Medium,
            Confidence::Certain,
        ));

        let risks: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("missing HTTP security headers"))
            .collect();

        assert_eq!(risks.len(), 1, "the three claims fold into one row: {text}");
        assert!(
            risks[0].contains("80, 443, 631/tcp"),
            "the row names every port, and the shared protocol once: {text}"
        );
    }

    /// Past a few ports the column would grow wider than everything beside it, so
    /// the row counts them and `-v` spells them.
    #[test]
    fn a_folded_row_past_a_few_ports_counts_them() {
        let host = repeated(&[80, 443, 631, 8080], Severity::Low, Confidence::Certain);
        let text = block(&host);

        assert!(
            text.contains("4 ports"),
            "the subject counts what it will not spell: {text}"
        );
        assert!(
            !text.contains("80, 443, 631, 8080/tcp"),
            "and does not spell it: {text}"
        );

        let detailed = explained(&host);
        assert!(
            detailed.contains("on") && detailed.contains("80, 443, 631, 8080/tcp"),
            "-v hangs the ports the row would not spell: {detailed}"
        );
    }

    /// A confidence that is the same on every line is a word nobody reads, so
    /// only a finding short of certain says how sure it is.
    #[test]
    fn only_an_uncertain_finding_says_how_sure_it_is() {
        let certain = block(&repeated(&[80], Severity::Medium, Confidence::Certain));
        assert!(
            !certain.contains("certain"),
            "a certain finding spends no columns saying so: {certain}"
        );

        let probable = block(&repeated(&[80], Severity::Medium, Confidence::Probable));
        assert!(
            probable.contains("~probable"),
            "anything short of certain says which: {probable}"
        );
    }

    /// Two ports the same detection graded differently are two findings, however
    /// alike they read.
    #[test]
    fn findings_graded_differently_stay_apart() {
        let mut host = repeated(&[80], Severity::Medium, Confidence::Certain);
        host.add_port(Port::new(443, Protocol::Tcp, PortState::Open));
        host.add_port_finding(
            443,
            Protocol::Tcp,
            finding(
                "zond:http/missing-security-headers",
                "missing HTTP security headers",
                Severity::Low,
                Confidence::Certain,
            )
            .with_reference(Reference::cwe(693)),
        );

        let text = block(&host);
        let risks: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("missing HTTP security headers"))
            .collect();

        assert_eq!(risks.len(), 2, "the two grades stay apart: {text}");
        assert!(
            risks[0].contains("MED") && risks[1].contains("LOW"),
            "and the worse one leads: {text}"
        );
    }

    /// A title carrying a control character is escaped before it is measured,
    /// so the columns beside it stay where the widths said they would.
    #[test]
    fn a_title_is_measured_after_escaping() {
        let mut host = repeated(&[80], Severity::Medium, Confidence::Certain);
        host.add_port(Port::new(443, Protocol::Tcp, PortState::Open));
        host.add_port_finding(
            443,
            Protocol::Tcp,
            finding(
                "zond:http/banner",
                "banner said\nmissing HTTP secu",
                Severity::Low,
                Confidence::Certain,
            )
            .with_reference(Reference::cwe(200)),
        );

        let text = block(&host);
        assert!(
            !text.contains("banner said\nmissing"),
            "the newline never reaches the terminal: {text}"
        );

        let citations: Vec<usize> = text.lines().filter_map(|line| line.find("CWE-")).collect();
        assert_eq!(citations.len(), 2, "both rows cite something: {text}");
        assert_eq!(
            citations[0], citations[1],
            "the escaped title is two columns wider than it is stored, and the \
             citations still share a column: {text}"
        );
    }

    /// What a detection saw waits for `--evidence`, and for that flag alone:
    /// `--reason` answers the same question about a port's verdict, and somebody
    /// triaging findings does not want every port's packet along with them.
    #[test]
    fn what_a_detection_saw_waits_for_its_own_flag() {
        let host = with_evidence_and_remedy();

        let text = block(&host);
        assert!(
            !text.contains("evidence") && !text.contains("strict-transport-security"),
            "a plain run draws the verdicts alone: {text}"
        );

        let reasoned = shown(
            &host,
            field::Showing {
                reasons: true,
                ..Default::default()
            },
        );
        assert!(
            !reasoned.contains("strict-transport-security"),
            "--reason is about ports, and does not carry this: {reasoned}"
        );

        let asked = shown(
            &host,
            field::Showing {
                excerpts: true,
                ..Default::default()
            },
        );
        assert!(
            asked.contains("evidence") && asked.contains("strict-transport-security"),
            "--evidence draws it: {asked}"
        );
        assert!(
            !asked.contains("reverse proxy"),
            "and not the remedy, which is asked for separately: {asked}"
        );
    }

    /// The advice a finding carries is addressed to somebody who has stopped
    /// reading the scan and started working, so it waits to be asked for, and
    /// `-v` is not the asking: that flag is the working behind a conclusion.
    #[test]
    fn a_findings_remedy_waits_for_its_own_flag() {
        let host = with_evidence_and_remedy();

        assert!(!block(&host).contains("reverse proxy"), "{}", block(&host));
        assert!(
            !explained(&host).contains("reverse proxy"),
            "-v is not what asks: {}",
            explained(&host)
        );

        let asked = shown(
            &host,
            field::Showing {
                remedies: true,
                ..Default::default()
            },
        );
        assert!(
            asked.contains("remedy") && asked.contains("reverse proxy"),
            "--remedy draws it: {asked}"
        );
    }

    /// A detail carries text and the block paints it. Painting it here too hands
    /// the block escape bytes to escape, and `\x1b[38;2;…m` is drawn in the
    /// middle of the line.
    #[test]
    fn a_hanging_detail_is_painted_once() {
        let mut host = host(9);
        host.add_port(Port::new(443, Protocol::Tcp, PortState::Open));
        host.add_port_finding(
            443,
            Protocol::Tcp,
            finding(
                "zond:http/missing-security-headers",
                "missing 4 of 4 HTTP security headers",
                Severity::Medium,
                Confidence::Certain,
            )
            .with_excerpt(Excerpt::new("missing: strict-transport-security"))
            .with_remediation("set the four headers at the reverse proxy"),
        );

        let text = drawn_showing(
            painting(),
            field::Reader::default(),
            &host,
            Verbosity::new(1, false),
            field::Showing {
                excerpts: true,
                remedies: true,
                ..Default::default()
            },
        );

        assert!(
            !text.contains("\\x1b"),
            "an escape sequence was drawn rather than obeyed: {text:?}"
        );
        assert!(
            text.contains("missing: strict-transport-security"),
            "and the value survived: {text:?}"
        );
        assert!(
            text.contains("set the four headers at the reverse proxy"),
            "the remedy too: {text:?}"
        );
    }

    /// An excerpt is bounded at two kilobytes and may carry newlines, and a row
    /// is one line. Runs of whitespace close up and the rest is cut.
    #[test]
    fn a_long_excerpt_is_flattened_and_folded() {
        let mut host = host(9);
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Open));
        host.add_port_finding(
            80,
            Protocol::Tcp,
            finding(
                "zond:http/banner",
                "server banner",
                Severity::Info,
                Confidence::Certain,
            )
            .with_excerpt(Excerpt::new(format!(
                "HTTP/1.1 200 OK\r\nServer: {}",
                "x".repeat(200)
            ))),
        );

        let text = shown(
            &host,
            field::Showing {
                excerpts: true,
                ..Default::default()
            },
        );
        let line = text
            .lines()
            .find(|line| line.contains("evidence"))
            .expect("the evidence hangs under the row");

        assert!(line.contains("HTTP/1.1 200 OK Server:"), "{text}");

        // Nothing is cut. A run that asked for the evidence asked for the
        // evidence, and the terminal's width is what decides where it folds.
        assert!(!text.contains('…'), "the excerpt was cut: {text}");
        assert!(
            text.contains(&"x".repeat(200)),
            "the excerpt lost its tail: {text}"
        );

        // The header line the flattening left is inside the width; the run of
        // two hundred x's is one word, and a word longer than the room it has
        // takes its own line rather than being broken where nobody can paste it.
        assert!(
            line.chars().count() <= crate::render::ASSUMED_WIDTH,
            "the folded line overran: {text}"
        );
    }

    /// The severity, and only the severity, carries the colour.
    #[test]
    fn only_the_severity_of_a_finding_is_painted() {
        let text = painted(&at_risk());
        let alarm = painting().alarm("CRIT");

        assert!(text.contains(&alarm), "the severity is coloured: {text}");
        assert!(
            !text.contains(&painting().alarm("Log4Shell")),
            "nothing but the severity is coloured: {text}"
        );
    }

    /// A filtering conclusion and the IP protocols a stack accepts each draw
    /// their own line, spelled for a person rather than in the wire's casing.
    #[test]
    fn a_filter_and_the_ip_protocols_a_stack_accepts_are_drawn() {
        use zond_engine::model::host::Filtering;
        use zond_engine::model::host::protocol::IpProtocolState;

        let mut host = host(9);
        host.add_filtering(Filtering::StatefulFilter);
        host.record_ip_protocol(6, IpProtocolState::Open);
        host.record_ip_protocol(132, IpProtocolState::Filtered);

        let text = block(&host);

        assert!(
            text.contains("filter") && text.contains("stateful filter"),
            "the filter conclusion is spelled for a person: {text}"
        );
        assert!(
            text.contains("6 tcp  accepted") && text.contains("132 sctp  filtered"),
            "each IP protocol reads as number, name and verdict: {text}"
        );
    }

    /// The shape the whole design rests on. If this drifts, everything else in
    /// this module is asserting on a layout nobody chose.
    #[test]
    fn a_furnished_host_reads_as_a_block() {
        assert_eq!(
            block(&furnished()),
            "  1  192.0.2.1  router.example
     hardware  00:00:5e:00:53:01  Icann, Iana Department
     answered  ARP  NDP
     latency   1.42ms
     also      fe80::1%en0
     path      1  192.0.2.254  0.90ms
               2  *
"
        );
    }

    /// A value that continues onto another line lands in the column its first
    /// line started in, and carries nothing in front of it.
    #[test]
    fn a_continued_value_keeps_the_column_and_nothing_else() {
        let text = block(&furnished());
        let second_hop = text
            .lines()
            .skip_while(|line| !line.contains("path"))
            .nth(1)
            .expect("the second hop");

        assert!(
            second_hop.starts_with(&" ".repeat(value_column(&furnished()))),
            "something survived into the continuation: {second_hop:?}"
        );
    }

    /// Every value begins in the same column, whatever the label above it was.
    /// That column is what lets an eye run down them.
    #[test]
    fn every_label_lines_its_value_up_with_the_others() {
        let text = block(&furnished());

        let column = value_column(&furnished());

        for line in text.lines().skip(1) {
            let value = line
                .char_indices()
                .nth(column)
                .map(|(index, _)| &line[index..]);
            if let Some(value) = value {
                assert!(
                    !value.starts_with(' '),
                    "value does not begin at column {column}: {line:?}"
                );
            }
        }
    }

    /// What a host *does* is a finding like any other, and until now the only
    /// place it reached the screen was a comparison saying it had changed.
    #[test]
    fn a_role_the_scan_established_reaches_the_block() {
        use zond_engine::model::host::NetworkRole;

        let mut router = furnished();
        router.add_network_role(NetworkRole::Router);
        router.add_network_role(NetworkRole::DnsServer);

        assert!(
            block(&router).contains("roles     router  DNS"),
            "{}",
            block(&router)
        );
    }

    /// A router advertisement arrives without being asked for, so a host can
    /// carry a role and nothing else at all.
    #[test]
    fn a_host_known_only_by_its_role_still_draws_a_block() {
        use zond_engine::model::host::NetworkRole;

        let mut only = host(44);
        only.add_network_role(NetworkRole::Router);

        assert_eq!(block(&only), "  1  192.0.2.44\n     roles  router\n");
    }

    /// A listing that measured nothing at all says nothing about latency.
    #[test]
    fn a_listing_that_timed_nothing_says_nothing() {
        let text = listing(&[&host(1), &host(2)]);

        assert_eq!(text, "  1  192.0.2.1\n  2  192.0.2.2\n");
    }

    /// A host nothing was learned about is its header alone. This is what keeps
    /// a sweep of a mostly empty range from being a wall of near-identical
    /// blocks.
    #[test]
    fn a_host_with_nothing_known_is_one_line() {
        assert_eq!(block(&host(44)), "  1  192.0.2.44\n");
    }

    /// A discovery sweep probes no ports, so the header says nothing about
    /// them: "no open ports" would read as a finding rather than as nothing
    /// having been asked.
    #[test]
    fn a_host_with_no_ports_probed_claims_nothing_about_them() {
        let text = block(&furnished());
        assert!(!text.contains("open"), "{text}");
    }

    #[test]
    fn the_header_counts_the_open_ports() {
        let text = block(&serving_tls(away(400)));
        assert!(text.starts_with("  1  192.0.2.30   1 open\n"), "{text}");
    }

    /// A host whose ports were all shut says so, rather than leaving a reader to
    /// infer it from a missing line.
    #[test]
    fn a_host_with_nothing_open_says_so() {
        let mut host = host(7);
        host.add_port(Port::new(80, Protocol::Tcp, PortState::Closed));

        assert!(block(&host).contains("no open ports"), "{}", block(&host));
    }

    /// TLS and the certificate hang off the port that negotiated them, in that
    /// port's own columns: the value under the service it was presented for, and
    /// the second field in a column of its own so expiries compare down a
    /// listing without being read.
    #[test]
    fn a_certificate_hangs_off_the_port_that_served_it() {
        let text = block(&serving_tls(away(12)));

        let line = |needle: &str| {
            text.lines()
                .find(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("no line carrying {needle}: {text}"))
        };
        let at = |needle: &str| line(needle).find(needle).unwrap_or_else(|| unreachable!());

        // The service column, which is where a detail's value belongs: what the
        // handshake was and what the certificate is named are both facts about
        // the thing `https` names.
        assert_eq!(
            at("https"),
            at("1.3"),
            "the tls value is not in the service column: {text}"
        );
        assert_eq!(
            at("https"),
            at("printer.example"),
            "the certificate is not in the service column: {text}"
        );

        // And their second fields share a column of their own.
        assert_eq!(
            at("X25519"),
            at("expires in 12d"),
            "a detail's second field is not a column: {text}"
        );

        // Indented past the column the port numbers stand in, which is what
        // marks them as belonging to 443 rather than being ports themselves.
        // No glyph does that work any more, so the indent has to.
        let port_column = at("443/tcp");

        let hanging: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("tls ") || line.contains("cert "))
            .collect();
        assert_eq!(hanging.len(), 2, "{text}");

        for line in &hanging {
            let label = line.len() - line.trim_start().len();
            assert!(
                label > port_column,
                "detail is not indented past the port column: {line:?}"
            );
        }
    }

    /// An end that is `days` away, or behind us when `days` is negative.
    fn away(days: i64) -> std::time::SystemTime {
        let offset = Duration::from_secs(days.unsigned_abs() * 86_400);
        if days < 0 {
            std::time::SystemTime::now() - offset
        } else {
            std::time::SystemTime::now() + offset
        }
    }

    /// A certificate past its end is not merely coloured. The words say it, so
    /// the finding survives being piped to a file.
    #[test]
    fn an_expired_certificate_says_so_in_words() {
        let text = block(&serving_tls(away(-9)));
        assert!(text.contains("expired 9d ago"), "{text}");
    }

    /// The colour is the second signal, not the only one. A certificate inside
    /// the horizon is cautioned and one well outside it is not.
    #[test]
    fn only_a_certificate_near_its_end_is_coloured() {
        let soon = painted(&serving_tls(away(12)));
        let later = painted(&serving_tls(away(400)));

        let caution = opener(Style::caution);

        assert!(
            soon.contains(&format!("{caution}expires in 12d")),
            "{soon:?}"
        );
        assert!(
            !later.contains(&format!("{caution}expires in")),
            "{later:?}"
        );
        assert!(later.contains("expires in 400d"), "{later:?}");
    }

    /// The working behind a certificate is for somebody checking it, and noise
    /// to somebody reading past it.
    #[test]
    fn a_certificates_issuer_and_fingerprint_wait_for_detail() {
        let host = serving_tls(away(90));

        assert!(!block(&host).contains("Let's Encrypt"), "{}", block(&host));
        assert!(
            explained(&host).contains("issuer  Let's Encrypt R3"),
            "{}",
            explained(&host)
        );
    }

    /// A TLS walk cut short says so under its port, and says why.
    ///
    /// Drawn like a finished walk, what a version accepted before the cut
    /// reads as everything it accepts, and a version never settled reads as
    /// refused. One line per cause, because the cause is what a reader acts
    /// on, with the versions under the one the handshake negotiated.
    #[test]
    fn an_unfinished_tls_walk_hangs_off_its_port_with_why() {
        let support = accepting_tls12()
            .leaving_unfinished(UnfinishedVersion::new(
                TlsVersion::Tls10,
                Interruption::Unanswered,
            ))
            .leaving_unfinished(UnfinishedVersion::new(
                TlsVersion::Tls11,
                Interruption::Stopped,
            ))
            .leaving_unfinished(UnfinishedVersion::new(
                TlsVersion::Tls12,
                Interruption::Stopped,
            ));
        let text = block(&enumerated(support));

        let line = |needle: &str| {
            text.lines()
                .find(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("no line carrying {needle}: {text}"))
        };
        let at = |needle: &str| line(needle).find(needle).unwrap_or_else(|| unreachable!());

        assert_eq!(
            line("TLSv1.0").trim(),
            "suites  TLSv1.0  unfinished, unanswered",
            "{text}"
        );
        assert_eq!(
            line("TLSv1.1").trim(),
            "suites  TLSv1.1 TLSv1.2  unfinished, stopped",
            "{text}"
        );
        assert_eq!(
            at("TLSv1.3"),
            at("TLSv1.0"),
            "the versions are not in the column the negotiated one is: {text}"
        );
    }

    /// A walk that finished hangs nothing. Its findings are the whole answer,
    /// and a line on every enumerated port saying so is one a reader learns to
    /// skip on the port where it would have said otherwise.
    #[test]
    fn a_finished_tls_walk_hangs_nothing_off_its_port() {
        let text = block(&enumerated(accepting_tls12()));

        assert!(!text.contains("suites"), "{text}");
        assert!(!text.contains("unfinished"), "{text}");
    }

    /// The working behind an operating-system finding, on the same rule.
    #[test]
    fn the_working_behind_an_os_finding_appears_only_under_detail() {
        let mut host = furnished();
        host.set_os(
            OsFingerprint::new("Linux", 65)
                .with_family("Linux")
                .with_generation("6.x")
                .with_evidence("syn-ack hops>=64 opts=M,S,T,N,W id=zero isn=hashed"),
        );

        assert!(block(&host).contains("Linux 6.x"), "{}", block(&host));
        assert!(!block(&host).contains("isn=hashed"), "{}", block(&host));
        assert!(
            explained(&host).contains("isn=hashed"),
            "{}",
            explained(&host)
        );
    }

    /// A host answering at one address has nothing to add below its header.
    #[test]
    fn one_address_gets_no_list_of_its_own() {
        let mut host = host(1);
        host.add_rtt(Duration::from_micros(8_200));

        assert!(!block(&host).contains("Also"), "{}", block(&host));
    }

    /// The round trips take a row of their own, under what answered. The header
    /// says which host this is and what came of it, and a measurement between
    /// the name and the verdict competes with both.
    #[test]
    fn the_round_trips_take_a_row_under_what_answered() {
        let text = block(&furnished());
        let opening = text.lines().next().expect("a header");

        assert!(
            !opening.contains("1.42"),
            "the header carries no measurement: {text}"
        );
        assert!(text.contains("latency   1.42ms"), "{text}");

        let lines: Vec<&str> = text.lines().collect();
        let answered = lines
            .iter()
            .position(|line| line.contains("answered"))
            .expect("a host that answered");
        let latency = lines
            .iter()
            .position(|line| line.contains("latency"))
            .expect("a host that was timed");
        assert_eq!(latency, answered + 1, "the row follows `answered`: {text}");
    }

    /// What the round trips did *apart* from the fastest is the same fact read
    /// deeper: a host whose fastest reply is 8 ms and slowest 1.2 s is not 8 ms
    /// away. One row either way, since the row is now the only place they are
    /// said at all.
    #[test]
    fn round_trips_that_disagree_are_spelled_out() {
        let mut spread = host(1);
        spread.add_rtt(Duration::from_micros(1_100));
        spread.add_rtt(Duration::from_micros(1_510));
        spread.add_rtt(Duration::from_micros(2_030));

        let text = block(&spread);
        assert!(text.contains("latency  min/avg/max"), "{text}");
        assert!(text.contains("1.10 / 1.55 / 2.03 ms"), "{text}");
    }

    /// Round trips that differ by microseconds are not the same duration and are
    /// the same figure at the precision the row draws, and a row reading
    /// `6.96 / 6.96 / 6.96 ms` claims a spread it is not showing. What a reader
    /// can see decides.
    #[test]
    fn round_trips_that_differ_below_the_precision_drawn_are_one_figure() {
        let mut host = host(1);
        host.add_rtt(Duration::from_micros(6_960));
        host.add_rtt(Duration::from_micros(6_961));
        host.add_rtt(Duration::from_micros(6_962));

        let text = block(&host);

        assert!(
            !text.contains("min/avg/max"),
            "three figures that read the same are one figure: {text}"
        );
        assert!(text.contains("latency  6.96ms"), "{text}");
    }

    /// A host whose round trips all agreed says the one number, because two of
    /// the three figures would be that number again.
    #[test]
    fn round_trips_that_agree_are_one_figure() {
        let text = block(&furnished());

        assert!(text.contains("latency   1.42ms"), "{text}");
        assert!(!text.contains("min/avg/max"), "{text}");
    }

    /// A host the scan overheard rather than timed has no row, rather than a row
    /// standing in for a measurement nobody took.
    #[test]
    fn a_host_that_was_never_timed_has_no_latency_row() {
        assert!(!block(&host(2)).contains("latency"), "{}", block(&host(2)));
    }

    /// Protocol names are acronyms, not words, and they are written as such.
    #[test]
    fn the_protocols_a_host_answered_on_are_written_as_names() {
        let text = block(&furnished());

        assert!(text.contains("answered  ARP  NDP"), "{text}");
        assert!(!text.contains("arp, ndp"), "{text}");
    }

    /// The primary is on the header line already. Repeating it below puts one
    /// string on the screen twice, which, once the two are coloured by family,
    /// reads as two findings rather than one machine.
    #[test]
    fn the_primary_address_is_not_repeated_below_the_header() {
        let text = block(&furnished());

        assert_eq!(
            text.matches("192.0.2.1\n").count(),
            0,
            "the primary is listed again: {text}"
        );
        assert!(text.contains("also      fe80::1%en0"), "{text}");
    }

    /// The status is a word on the header line, so nothing about a host's
    /// reachability rests on the paint.
    #[test]
    fn a_filtered_host_says_so_without_colour() {
        let mut filtered = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        filtered.set_status(zond_engine::HostStatus::Filtered);

        let text = block(&filtered);
        assert!(text.starts_with("  1  "), "{text}");
        assert!(text.contains("Filtered"), "{text}");
    }

    #[test]
    fn redaction_masks_the_name_the_hardware_and_the_address() {
        let masked = rendered(
            field::Reader::new(Redaction::Standard),
            &furnished(),
            Verbosity::default(),
        );

        assert!(!masked.contains("router.example"), "{masked}");
        assert!(!masked.contains("00:00:5e:00:53:01"), "{masked}");
    }

    /// Redaction is off unless asked for. A scan holds what it found.
    #[test]
    fn nothing_is_masked_by_default() {
        let plain = block(&furnished());
        assert!(plain.contains("router.example"), "{plain}");
        assert!(plain.contains("00:00:5e:00:53:01"), "{plain}");
    }

    /// The point of the palette: which field a value belongs to is said by the
    /// label beside it, so hue is free to say something else. What it says is
    /// rank. The address the block is about is the one bold thing on the screen,
    /// everything the scan established shares one colour, and the furniture and
    /// the qualifiers share another.
    #[test]
    fn rank_rather_than_hue_separates_the_fields() {
        let text = painted(&furnished());

        let strong = opener(Style::strong);
        let plain = opener(Style::plain);
        let faint = opener(Style::faint);
        let accent = opener(Style::accent);

        for (sequence, value, what) in [
            (&strong, "192.0.2.1", "the address the block is about"),
            (&accent, "router.example", "the name the network gave back"),
            (&plain, "00:00:5e:00:53:01", "the hardware address"),
            (&plain, "1.42ms", "a measurement"),
            (&plain, "ARP  NDP", "what answered"),
            (&plain, "fe80::1%en0", "a further address"),
            (&plain, "192.0.2.254", "a router partway along the path"),
            (&faint, "hardware", "a label"),
            (
                &faint,
                "Icann, Iana Department",
                "the vendor, which qualifies the address beside it",
            ),
        ] {
            assert!(
                text.contains(&format!("{sequence}{value}")),
                "{what}: {text:?}"
            );
        }

        // Five findings, one colour. That is the change, and a role creeping
        // back per field is what this is here to catch.
        assert_ne!(strong, plain);
        assert_ne!(plain, faint);
        assert_ne!(accent, plain);
    }

    /// A version six address announces itself, having colons and hexadecimal in
    /// it, so a second hue spent saying so is a hue spent twice, and the two
    /// loudest entries in the palette used to go on exactly that. What a reader
    /// needs told apart is the address the block is *about* from the further
    /// ones it also answers at, and that is rank rather than family: a hop's
    /// version four address and a further version six address are the same kind
    /// of thing and now look it.
    #[test]
    fn an_address_is_not_coloured_by_its_family() {
        let text = painted(&furnished());

        let strong = opener(Style::strong);
        let plain = opener(Style::plain);

        assert!(text.contains(&format!("{strong}192.0.2.1")), "{text:?}");
        assert!(text.contains(&format!("{plain}fe80::1%en0")), "{text:?}");
        assert!(text.contains(&format!("{plain}192.0.2.254")), "{text:?}");
    }

    /// Furniture and findings never swap places.
    ///
    /// Labels, brackets, leaders, a hop's index and a qualifier are furniture; an
    /// address, a hardware address, a name, a measurement and a protocol list are
    /// not. A finding drawn as furniture is a finding a person has to read rather
    /// than scan, which was the whole complaint the palette exists to answer.
    #[test]
    fn nothing_a_scan_found_is_drawn_as_furniture() {
        let text = painted(&furnished());
        let faint = opener(Style::faint);

        assert!(
            text.contains(&faint),
            "this block drew no furniture at all, so the loop below proves nothing: {text:?}"
        );

        for finding in [
            "192.0.2.1",
            "router.example",
            "00:00:5e:00:53:01",
            "1.42",
            "ARP  NDP",
            "fe80::1%en0",
            "192.0.2.254",
        ] {
            assert!(
                !text.contains(&format!("{faint}{finding}")),
                "a finding was drawn as furniture: {finding}"
            );
        }
    }

    /// A label is furniture and its value is not. That is the distinction the
    /// leader dots used to draw with punctuation, and the reason they are not
    /// needed to draw it.
    #[test]
    fn a_label_is_furniture_and_its_value_is_not() {
        let text = painted(&furnished());

        let faint = opener(Style::faint);
        let plain = opener(Style::plain);

        assert_ne!(faint, plain);
        assert!(text.contains(&format!("{faint}hardware")), "{text:?}");
        assert!(
            text.contains(&format!("{plain}00:00:5e:00:53:01")),
            "{text:?}"
        );
    }

    /// The two palettes never contend for one piece of text. An address says
    /// which machine this is; a verdict says how it answered. A host being
    /// filtered must not repaint its address, or the colour stops meaning "this
    /// is an address" and starts meaning nothing in particular.
    #[test]
    fn a_verdict_does_not_repaint_an_identifier() {
        let mut filtered = Host::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        filtered.set_status(HostStatus::Filtered);
        filtered.set_hostname(Some("router.example".to_owned()));

        let text = painted(&filtered);
        assert!(
            text.contains(&format!("{}192.0.2.9", opener(Style::strong))),
            "{text:?}"
        );
        assert!(
            text.contains(&format!("{}router.example", opener(Style::accent))),
            "{text:?}"
        );
        assert!(
            text.contains(&format!("{}Filtered", opener(Style::caution))),
            "the verdict keeps its own colour: {text:?}"
        );
    }

    /// Padding is measured on the text, not on the painted text. A painted
    /// string is longer than it looks, and padding inside the escape codes is
    /// padding the terminal cannot see.
    #[test]
    fn colour_does_not_move_the_columns() {
        let mut host = host(30);
        host.add_port(
            Port::new(22, Protocol::Tcp, PortState::Open)
                .with_service(Service::new("ssh", 100).with_product("OpenSSH")),
        );
        host.add_port(Port::new(5, Protocol::Tcp, PortState::Filtered));

        let bare = block(&host);
        let coloured = painted(&host);

        let stripped: String = strip_escapes(&coloured);
        assert_eq!(stripped, bare, "colour changed the layout");
    }

    /// Everything a scanned host chose is escaped before it is painted, so a
    /// value cannot carry an escape sequence of its own into the terminal.
    #[test]
    fn a_painted_value_is_still_escaped() {
        let mut scanned = host(1);
        scanned.set_hostname(Some("evil\x1b[2J".to_owned()));

        let text = painted(&scanned);
        assert!(!text.contains("\x1b[2J"), "{text:?}");
        assert!(text.contains("\\x1b[2J"), "{text:?}");
    }

    fn renderer(verbosity: Verbosity) -> (FancyRenderer, Capture, Capture) {
        let records = Capture::default();
        let narration = Capture::default();
        let renderer = FancyRenderer::new(
            Box::new(records.clone()),
            Box::new(narration.clone()),
            verbosity,
            Style::bare(),
            Style::bare(),
        );
        (renderer, records, narration)
    }

    /// Commentary is furniture, and drawn as it.
    ///
    /// What is on standard output is the records; a sentence about how the run
    /// went is not one of them. It used to go out unpainted, which left it at
    /// the terminal's own foreground: brighter than every finding it was talking
    /// about, and the one thing on the screen louder than the addresses.
    #[test]
    fn commentary_is_drawn_as_furniture_and_not_left_bare() {
        let records = Capture::default();
        let narration = Capture::default();
        let mut renderer = FancyRenderer::new(
            Box::new(records.clone()),
            Box::new(narration.clone()),
            Verbosity::default(),
            Style::bare(),
            painting(),
        );

        renderer.interrupted().expect("capture cannot fail");

        let said = narration.text();
        assert!(
            said.starts_with(&opener(Style::faint)),
            "commentary went out unpainted: {said:?}"
        );
        assert!(said.contains("interrupted"), "{said:?}");
    }

    /// Each kind of run counts what it is for, and a record read off disk counts
    /// nothing because nothing is running.
    #[test]
    fn each_phase_counts_what_that_run_is_asking() {
        use crate::target::{ScanTargets, Targets};
        use zond_engine::PortSet;
        use zond_engine::model::target::{TargetMap, TargetSet};

        let ips = "192.0.2.0/30"
            .parse::<zond_engine::IpSet>()
            .expect("a range");
        let swept = Targets::resumed(ips.clone(), 4, "192.0.2.0/30".to_owned());

        let mut plan = TargetMap::new();
        plan.add_unit(TargetSet::new(
            ips,
            "80".parse::<PortSet>().expect("a port"),
        ));
        let scanned = ScanTargets::resumed(plan, 4, "192.0.2.0/30 on 1 port".to_owned());

        assert_eq!(
            counting(Phase::Discovery {
                targets: &swept,
                resumable: true
            }),
            Some(Counting::Hosts)
        );
        assert_eq!(
            counting(Phase::PortScan {
                targets: &scanned,
                resumable: true
            }),
            Some(Counting::Ports)
        );
        assert_eq!(
            counting(Phase::Recorded {
                id: "01AAA",
                started_at: Some(std::time::SystemTime::UNIX_EPOCH),
                produced_by: "0.13.0",
            }),
            None,
            "a record read off disk has nothing running to count"
        );
    }

    #[test]
    fn quiet_narrates_nothing() {
        let (mut renderer, _records, narration) = renderer(Verbosity::new(0, true));
        renderer.progressed(1, 0).expect("capture cannot fail");
        renderer.interrupted().expect("capture cannot fail");
        assert_eq!(narration.text(), "");
    }

    /// Counted from one, because a listing a person reads off a screen is.
    #[test]
    fn the_numbering_starts_at_one() {
        let text = block(&furnished());
        let opening = text.lines().next().expect("a header");

        assert!(opening.trim_start().starts_with('1'), "{opening:?}");
    }
}

#[cfg(test)]
mod hostile {
    use super::*;
    use crate::render::test_support::host;

    /// A block is line-oriented, so a newline in a value a host chose would put
    /// a fact in it that no scan produced. The grammar is plain columns rather
    /// than glyphs, which makes a forgery *easier* to write and no easier to
    /// land: escaping happens before anything is placed.
    #[test]
    fn a_hostname_a_host_chose_cannot_forge_a_fact() {
        let mut scanned = host(1);
        scanned.set_hostname(Some("evil\n     ports     443/tcp  open".to_owned()));

        let style = Style::bare();
        let reader = field::Reader::default();
        let showing = field::Showing::default();
        let listing = field::port_listings(&[&scanned], false, showing);
        let blocks = vec![Block {
            header: header(style, reader, &scanned, 1),
            children: children(
                style,
                reader,
                &scanned,
                &listing[0],
                Verbosity::default(),
                showing,
            ),
        }];

        let mut out = Vec::new();
        block::write_all(
            &mut out,
            style,
            &blocks,
            crate::render::ASSUMED_WIDTH,
            |_, _| Ok(()),
        )
        .expect("a vector cannot fail");

        let text = String::from_utf8(out).expect("the renderer writes text");
        assert_eq!(
            text.lines().count(),
            1,
            "a value a host chose forged a line: {text}"
        );
        assert!(text.contains("\\n"), "{text}");
    }
}
