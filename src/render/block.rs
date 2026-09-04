// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The shape everything is drawn in
//!
//! ```text
//! 1  192.0.2.1  router.example    1.42 ms   2 open
//!    hardware  00:00:5e:00:53:01  Icann, Iana
//!    also      2001:db8::1
//!              fe80::1%en0
//!    ports     22/tcp   open      ssh    OpenSSH 9.6
//!              443/tcp  open      https  nginx 1.24
//!                cert   router.example  expires in 12d
//!              996 closed ports not listed
//! ```
//!
//! Six line types, and that is the whole language:
//!
//! | Line | What it is |
//! |---|---|
//! | header | which record this is, how far away, and what came of it |
//! | fact | a faint label and the value beside it |
//! | continuation | the same fact, on another line |
//! | table row | a fact whose value is a table, one row of it |
//! | detail | something belonging to one row of that table |
//! | note | what the renderer decided not to enumerate |
//!
//! A scan draws a host this way, `zond diff` draws a change this way and
//! `zond journal show` draws a record this way, so the three read as one program
//! rather than three.
//!
//! ## Ports are not a seventh thing
//!
//! `ports` is a [`Child`] like `also` or `path`, one whose value happens to be a
//! table. It therefore begins in the column every other value begins in, and
//! nothing was added to the grammar to draw it. That is the whole reason this
//! module has no idea what a port is.
//!
//! ## Depth is an indent and a weight, not a glyph
//!
//! A [`Detail`] sits [`DETAIL_INDENT`] columns into the value column and takes
//! the same faint-label-plain-value shape as a fact two levels out. What marks
//! it as subordinate is that the column carrying the weight above it, the port
//! number, is empty on its line.
//!
//! There are no box-drawing characters here at all, which is why there is no
//! gate for a terminal that cannot draw one. A `├─` that means "this hangs off
//! the line above" is a glyph spent saying what an indent already said, and the
//! rules were never painted in the first place: the module they lived in
//! documented them as grey and emitted them in whatever the terminal's default
//! foreground happened to be.
//!
//! ## The listing is measured before any of it is drawn
//!
//! [`Columns::of`] takes every block at once, because the alignments worth
//! having are the ones *between* blocks: a handle right-aligned to the width of
//! the largest, so every identity starts in one column; a latency right-aligned
//! and decimal-aligned, so two of them compare at a glance without being read.
//! A block drawn in ignorance of its neighbours cannot have either, which is
//! what made the old header line ragged.
//!
//! **A name is deliberately not aligned.** Padding every name to the widest
//! would push the latency off a narrow terminal the moment one host is called
//! something long, and a name is looked up rather than compared, so the column
//! would buy nothing. Aligning what is compared and leaving what is not is the
//! difference between this and a table.
//!
//! ## Widths are measured before paint, never after
//!
//! A painted string is longer than it looks. [`Line`] carries its own plain
//! width so that every column here is measured on the text and never on the
//! escape codes around it.

use std::io::{self, Write};

use crate::render::field::Urgency;
use crate::render::style::Style;

/// The margin a block opens with, before its handle.
const GUTTER: usize = 2;

/// What separates a handle from an identity, and a label from its value.
///
/// Two rather than one, because one space is a word break and two is a column.
const GAP: usize = 2;

/// How far a detail sits into the value column it hangs under.
///
/// Two: short enough to read as "this belongs to the line above", long enough
/// not to be taken for another row of the value itself.
const DETAIL_INDENT: usize = 2;

/// What separates a mark from the identity it classifies.
///
/// One, not [`GAP`]: the mark is a property of the record rather than a column
/// beside it, and two spaces would read as two fields where there is one thing
/// with a mark on it.
const MARK_GAP: usize = 1;

/// How far a verdict sits from the identity before it.
///
/// Three, so that the gap is visibly wider than the one between a label and its
/// value, and the verdict reads as its own column rather than as something
/// appended to the name.
const VERDICT_GAP: usize = 3;

// ─────────────────────────────────────────────────────────────────────────────
// What a block is made of
// ─────────────────────────────────────────────────────────────────────────────

/// A one-word classification, and how wide it actually is.
///
/// The width travels with it because the text is already painted and a painted
/// string is longer than it looks. Padding it as a string pads it by the length
/// of its escape sequence, which differs between roles: twenty-four bit green is
/// one character longer than twenty-four bit amber, so a `+` and a `~` padded
/// that way land one column apart.
#[derive(Debug, Clone)]
pub(crate) struct Tag {
    /// The mark, already painted.
    pub painted: String,
    /// How many columns it occupies once the terminal has read it.
    pub width: usize,
}

/// The line a block opens with: which record this is, and what came of it.
///
/// Everything the columns are measured from is stored as plain text and painted
/// here, so that the grammar decides what a handle and an identity look like
/// rather than each caller deciding again. The verdict arrives already painted
/// because its colour is a domain judgement about open, filtered or gone, and
/// this module has no business knowing which.
#[derive(Debug, Clone)]
pub(crate) struct Header {
    /// Which record this is in its listing, counted from one.
    ///
    /// `None` where the record stands alone. `zond journal show` draws one
    /// record, and a handle for counting it among the others is a column spent
    /// on a listing that has no others. A listing where nothing is numbered
    /// reserves no room for numbering.
    pub at: Option<usize>,
    /// What kind of record this is, where a listing sorts into kinds.
    ///
    /// Already painted, padded by the caller, and placed between the handle and
    /// the identity. A comparison uses it: `gone`, `arrived` and `changed`
    /// classify a row rather than summarising it, and a reader running down a
    /// comparison is looking for one of the three.
    ///
    /// Distinct from [`verdict`](Self::verdict), which trails. `2 open` is what
    /// came *of* a host and is read after knowing which host it was; a tag is
    /// read before.
    ///
    /// It stands to the left of everything else in the block, in a column of its
    /// own: the identity and the labels beneath it all begin past it, so a
    /// block reads as one thing with a mark on it rather than as a mark and a
    /// block beside each other.
    pub tag: Option<Tag>,
    /// What the record is about: an address, or a record's identifier.
    pub identity: String,
    /// The name beside it, where the network gave one back.
    pub name: Option<String>,
    /// How far away it is.
    /// What came of it, already painted.
    pub verdict: Option<String>,
}

impl Header {
    /// A header that is a handle and an identity, and nothing else.
    pub(crate) fn numbered(at: usize, identity: String) -> Self {
        Self {
            at: Some(at),
            tag: None,
            identity,
            name: None,
            verdict: None,
        }
    }

    /// A header for a record that stands on its own, with no handle.
    pub(crate) fn alone(identity: String) -> Self {
        Self {
            at: None,
            ..Self::numbered(1, identity)
        }
    }

    /// The same, with a name beside the identity.
    #[must_use]
    pub(crate) fn named(self, name: Option<String>) -> Self {
        Self { name, ..self }
    }

    /// The same, with what kind of record it is: one word, already painted, and
    /// `width` columns wide once drawn.
    ///
    /// The width is the caller's to state rather than this module's to measure,
    /// for the reason [`Tag`] gives.
    #[must_use]
    pub(crate) fn tagged(self, painted: Option<String>, width: usize) -> Self {
        Self {
            tag: painted.map(|painted| Tag { painted, width }),
            ..self
        }
    }
}

/// A labelled fact.
#[derive(Debug, Clone)]
pub(crate) struct Child {
    /// What the value is, in the label column.
    pub label: &'static str,
    /// The value, one entry per line.
    pub rows: Vec<Row>,
}

impl Child {
    /// A fact that fits on one line.
    pub(crate) fn one(label: &'static str, text: String) -> Self {
        Self {
            label,
            rows: vec![Row::plain(text)],
        }
    }

    /// A fact that is a list.
    pub(crate) fn many(label: &'static str, texts: Vec<String>) -> Self {
        Self {
            label,
            rows: texts.into_iter().map(Row::plain).collect(),
        }
    }

    /// A fact whose lines carry detail of their own.
    pub(crate) fn rows(label: &'static str, rows: Vec<Row>) -> Self {
        Self { label, rows }
    }
}

/// One line of a child's value, and anything hanging off it.
#[derive(Debug, Clone)]
pub(crate) struct Row {
    /// The line, already painted. Nothing is measured from it, because nothing
    /// is placed after it.
    pub text: String,
    /// What belongs to this line and to no other.
    pub detail: Vec<Detail>,
}

impl Row {
    /// A line with nothing hanging off it.
    pub(crate) fn plain(text: String) -> Self {
        Self {
            text,
            detail: Vec::new(),
        }
    }

    /// A line with detail hanging under it.
    pub(crate) fn with_detail(text: String, detail: Vec<Detail>) -> Self {
        Self { text, detail }
    }
}

/// A fact belonging to one row of a child's value.
///
/// The block's own grammar, one level in: a faint label and a plain value, with
/// an optional part whose colour says something. Split rather than joined so the
/// colouring does not have to find the interesting phrase by searching a
/// finished sentence for it.
#[derive(Debug, Clone)]
pub(crate) struct Detail {
    /// What the value is.
    pub label: &'static str,
    /// The value.
    pub value: String,
    /// The part whose colour says something, where there is one.
    pub note: Option<String>,
    /// How that part should read.
    pub urgency: Urgency,
}

impl Detail {
    /// A detail that is a label and a value.
    pub(crate) fn new(label: &'static str, value: String) -> Self {
        Self {
            label,
            value,
            note: None,
            urgency: Urgency::None,
        }
    }

    /// The same, with a part that carries a warning.
    pub(crate) fn noted(self, note: String, urgency: Urgency) -> Self {
        Self {
            note: Some(note),
            urgency,
            ..self
        }
    }
}

/// One record, ready to draw.
#[derive(Debug, Clone)]
pub(crate) struct Block {
    /// The line it opens with.
    pub header: Header,
    /// The facts under it, in the order they are drawn.
    pub children: Vec<Child>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Where the columns fall
// ─────────────────────────────────────────────────────────────────────────────

/// Where every column of a listing falls.
///
/// Measured from the whole listing at once. See the module's note on why: the
/// alignments worth having are the ones between blocks, and a block drawn in
/// ignorance of its neighbours cannot have them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Columns {
    /// How many digits the largest handle takes.
    number_width: usize,
    /// The column a mark begins in, where the listing has them.
    tag_column: usize,
    /// The column an identity and a label both begin in.
    ///
    /// Past the mark where there is one, so everything the block says about a
    /// record lines up under the record itself.
    label_column: usize,
    /// How wide the label field is.
    label_width: usize,
    /// How wide a detail's own label field is.
    detail_label_width: usize,
    /// The column a verdict begins in.
    verdict_column: usize,
}

impl Columns {
    /// The columns this listing draws in.
    #[must_use]
    pub(crate) fn of(blocks: &[Block]) -> Self {
        let widest = |counts: &mut dyn Iterator<Item = usize>| counts.max().unwrap_or(0);

        // A listing where nothing is numbered reserves no room for numbering,
        // rather than reserving a column and leaving it blank.
        let number_width = blocks
            .iter()
            .filter_map(|block| block.header.at)
            .max()
            .map_or(0, |at| at.to_string().chars().count());

        let tag_column = if number_width == 0 {
            GUTTER
        } else {
            GUTTER + number_width + GAP
        };

        // Padded by the caller, which is the only place that knows the words;
        // this measures what it was handed.
        let tag_width = widest(
            &mut blocks
                .iter()
                .filter_map(|block| block.header.tag.as_ref())
                .map(|tag| tag.width),
        );

        let label_column = if tag_width == 0 {
            tag_column
        } else {
            tag_column + tag_width + MARK_GAP
        };

        let label_width = widest(
            &mut blocks
                .iter()
                .flat_map(|block| block.children.iter())
                .map(|child| child.label.chars().count()),
        );

        let detail_label_width = widest(
            &mut blocks
                .iter()
                .flat_map(|block| block.children.iter())
                .flat_map(|child| child.rows.iter())
                .flat_map(|row| row.detail.iter())
                .map(|detail| detail.label.chars().count()),
        );

        // Where the identities and names of this listing stop. The verdict
        // follows a gap past the longest of them, so it is as tight as the
        // listing allows rather than at some column chosen in advance.
        let identity_end = widest(&mut blocks.iter().map(|block| {
            label_column
                + block.header.identity.chars().count()
                + block
                    .header
                    .name
                    .as_ref()
                    .map_or(0, |name| GAP + name.chars().count())
        }));

        Self {
            number_width,
            tag_column,
            label_column,
            label_width,
            detail_label_width,
            verdict_column: identity_end + VERDICT_GAP,
        }
    }

    /// The column every value in a block begins in.
    #[must_use]
    pub(crate) fn value_column(self) -> usize {
        self.label_column + self.label_width + GAP
    }

    /// The column a detail's own value begins in.
    #[must_use]
    pub(crate) fn detail_value_column(self) -> usize {
        self.value_column() + DETAIL_INDENT + self.detail_label_width + GAP
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Drawing
// ─────────────────────────────────────────────────────────────────────────────

/// A line under construction, which knows how wide it is without its paint.
///
/// Every column in this module is placed through [`pad_to`](Self::pad_to) or
/// [`ending_at`](Self::ending_at) rather than by counting spaces at the call
/// site, so there is one piece of arithmetic to get right instead of one per
/// line type.
struct Line {
    text: String,
    width: usize,
}

impl Line {
    /// An empty line.
    fn new() -> Self {
        Self {
            text: String::new(),
            width: 0,
        }
    }

    /// Adds `painted`, which occupies `width` columns.
    ///
    /// `width` is the *plain* width, which is why it is passed rather than
    /// measured: `painted` is longer than it looks.
    fn push(&mut self, painted: &str, width: usize) {
        self.text.push_str(painted);
        self.width += width;
    }

    /// Adds something nothing is placed after, so its width does not matter.
    fn end_with(&mut self, painted: &str) {
        self.text.push_str(painted);
    }

    /// Adds spaces until the line is `column` wide.
    ///
    /// Never fewer than one, so two values cannot end up touching even if a
    /// column was measured from a listing this line does not belong to.
    fn pad_to(&mut self, column: usize) {
        let spaces = column.saturating_sub(self.width).max(1);
        self.push(&" ".repeat(spaces), spaces);
    }

    /// Adds spaces until the line is `column` wide, or none at all.
    ///
    /// For the margin at the start of a line, where there is nothing to keep
    /// apart from anything.
    fn indent_to(&mut self, column: usize) {
        let spaces = column.saturating_sub(self.width);
        self.push(&" ".repeat(spaces), spaces);
    }

    /// The finished line.
    fn finish(self) -> String {
        self.text
    }
}

/// Writes one block in `columns`.
pub(crate) fn write(
    out: &mut dyn Write,
    style: Style,
    columns: Columns,
    block: &Block,
) -> io::Result<()> {
    writeln!(out, "{}", header(style, columns, &block.header))?;

    for child in &block.children {
        for (index, row) in child.rows.iter().enumerate() {
            let mut line = Line::new();
            line.indent_to(columns.label_column);

            // Only the first row of a value carries the label; the rest are the
            // same fact continued, and a label repeated down a list is a label
            // that has stopped meaning anything.
            if index == 0 {
                let label = child.label;
                line.push(&style.faint(label), label.chars().count());
            }

            line.indent_to(columns.value_column());
            line.end_with(&row.text);
            writeln!(out, "{}", line.finish())?;

            for detail in &row.detail {
                writeln!(out, "{}", hanging(style, columns, detail))?;
            }
        }
    }

    Ok(())
}

/// Writes every block of a listing, separated by a blank line.
///
/// The separator belongs between records rather than after each one, so a
/// listing does not end on an empty line. The caller decides whether anything
/// precedes the first block.
pub(crate) fn write_all(
    out: &mut dyn Write,
    style: Style,
    blocks: &[Block],
    mut before_each: impl FnMut(&mut dyn Write, usize) -> io::Result<()>,
) -> io::Result<()> {
    let columns = Columns::of(blocks);

    for (index, block) in blocks.iter().enumerate() {
        before_each(out, index)?;
        write(out, style, columns, block)?;
    }

    Ok(())
}

/// The line a block opens with.
fn header(style: Style, columns: Columns, header: &Header) -> String {
    let mut line = Line::new();
    line.indent_to(GUTTER);

    // The handle is furniture: it is how a person says "look at four" out loud,
    // not something the scan found. Right-aligned rather than zero-padded,
    // because a column of digits is what the padding was faking.
    if let Some(at) = header.at {
        let number = format!("{:>width$}", at, width = columns.number_width);
        line.push(&style.faint(&number), number.chars().count());
    }

    if let Some(tag) = &header.tag {
        line.indent_to(columns.tag_column);
        line.push(&tag.painted, tag.width);
    }

    line.indent_to(columns.label_column);
    line.push(
        &style.strong(&header.identity),
        header.identity.chars().count(),
    );

    if let Some(name) = &header.name {
        line.pad_to(line.width + GAP);
        line.push(&style.accent(name), name.chars().count());
    }

    if let Some(verdict) = &header.verdict {
        line.pad_to(columns.verdict_column);
        line.end_with(verdict);
    }

    line.finish()
}

/// A detail line: the block's own grammar, one level in.
fn hanging(style: Style, columns: Columns, detail: &Detail) -> String {
    let mut line = Line::new();
    line.indent_to(columns.value_column() + DETAIL_INDENT);
    line.push(&style.faint(detail.label), detail.label.chars().count());

    line.indent_to(columns.detail_value_column());
    line.push(&style.plain(&detail.value), detail.value.chars().count());

    if let Some(note) = &detail.note {
        line.push("  ", GAP);
        line.end_with(&style.by_urgency(detail.urgency, note));
    }

    line.finish()
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
mod tests;
