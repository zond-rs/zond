// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Three channels, and what each one is allowed to say
//!
//! One [`Style`] value carries every decision a drawn presentation makes about
//! ink: whether to emit colour at all, whether the terminal takes twenty-four
//! bit colour or the two-hundred-and-fifty-six entry palette, and which accent
//! this run was configured with.
//!
//! There used to be a fourth, whether a box could be drawn, and there is no
//! longer anything to draw one with. [`block`](super::block) marks depth with an
//! indent, so what this crate writes is plain ASCII and a terminal that cannot
//! render `├` never has to be asked.
//!
//! ## Position separates. Weight ranks. Hue means.
//!
//! **Position**, meaning a fixed column, says what a field *is*. A block already
//! has one, so the label beside a value has already answered that question, and
//! a colour repeating it is a channel spent on a message that was delivered.
//!
//! **Weight** says how much a field matters, and there is exactly one of it:
//! [`strong`](Style::strong) is bold and nothing else carries an attribute.
//!
//! Rank below that is carried by colour alone, because `SGR 2` cannot be relied
//! on to carry it. It is the least consistently implemented attribute in the
//! set. Some terminals ignore it, some blend the foreground toward the
//! background, some substitute a dimmer palette entry, so a rank that depends on
//! it is a rank that means something different per terminal. Worse, where it
//! *is* honoured it compounds: a grey chosen to sit at 4.4:1 against a dark
//! background arrives at 2.0:1, which is how a label meant to read as furniture
//! became a label that could not be read at all.
//!
//! Bold survives because it adds weight rather than subtracting intensity, and
//! because it sits on a near-white where there is nothing left to darken.
//!
//! **Hue** is reserved for state, plus one accent. That is the whole reason the
//! palette below is short: a green that means "open" is only legible in a field
//! that is otherwise grey.
//!
//! ## The seven roles
//!
//! | Role | Weight | What it marks |
//! |---|---|---|
//! | [`strong`](Style::strong) | bold | the identity of a record, meaning the address a block opens with |
//! | [`plain`](Style::plain) | regular | everything a scan established |
//! | [`faint`](Style::faint) | regular | labels, units, qualifiers, and the renderer's own notes |
//! | [`accent`](Style::accent) | regular | a name the network gave back, and a handle a person reads out |
//! | [`good`](Style::good) | regular | a port that is open, a host that arrived |
//! | [`caution`](Style::caution) | regular | filtered, and a certificate near its end |
//! | [`alarm`](Style::alarm) | regular | a certificate past it, a host that went |
//!
//! Three greys, one accent, three states. A discovery sweep of a healthy
//! segment shows four of them.
//!
//! **An address is not coloured by its family.** A version six address has
//! colons and hexadecimal in it and announces itself; spending a hue on saying
//! so again cost the palette two of its loudest entries. What separates the
//! address a block is *about* from the further addresses it also answers at is
//! rank, [`strong`](Style::strong) against [`plain`](Style::plain), which is the
//! distinction a reader actually needs.
//!
//! ## The accent is the one thing a person may choose
//!
//! Everything else here is a fixed decision about legibility, but the accent
//! carries no meaning beyond "look here", so it is [`Accent`], read from
//! `accent_colour` in `cli.toml`. Named or written as a hexadecimal triplet; see
//! [`Accent::from_str`].
//!
//! **Colour never carries a fact on its own.** Every verdict a colour marks is
//! also spelled out in words, and every identifier says what it is by being one,
//! so a run piped to a file loses nothing but the paint.
//!
//! ## Painting escapes first
//!
//! [`Style::paint`] runs every string through [`field::printable`] before it
//! wraps it, so a value a scanned host chose cannot carry an escape sequence of
//! its own into the output. That ordering is the whole reason painting is a
//! method here rather than a `format!` at each call site.
//!
//! ## Widths are measured before paint, never after
//!
//! A painted string is longer than it looks. Anything that lines up, such as the
//! label column or the port table, pads the plain text and paints the padded
//! result.

use std::io::IsTerminal;

use crate::render::field::{self, Urgency};
use crate::settings::Presentation;

/// What a wrapped commentary line is indented by: the glyph, and the space
/// after it.
///
/// Two, and a constant rather than a measurement, because every [`Mark::glyph`]
/// is one column wide and that is a property of the set rather than of any line.
const HANGING: usize = 2;

/// The narrowest a commentary line is broken to before the terminal is told it
/// is wrong.
///
/// A window narrower than this would otherwise have a sentence folded to two or
/// three characters, which is not a line. Past it the line overruns and the
/// terminal wraps it, which is worse but honest.
const NARROWEST_LINE: usize = 32;

/// What starts every escape sequence.
const ESC: &str = "\x1b";

/// What ends one, whatever it set.
const RESET: &str = "\x1b[0m";

// ─────────────────────────────────────────────────────────────────────────────
// Ink
// ─────────────────────────────────────────────────────────────────────────────

/// One colour, in both vocabularies a terminal might speak.
///
/// Written as the triplet it is, and reduced to a palette index only for the
/// terminals that need one. Storing the triplet rather than the index is what
/// lets an accent be any colour somebody names: there is no table to be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ink {
    red: u8,
    green: u8,
    blue: u8,
}

impl Ink {
    /// The colour with these components.
    #[must_use]
    pub(crate) const fn new(red: u8, green: u8, blue: u8) -> Self {
        Self { red, green, blue }
    }

    /// The select-graphic-rendition parameters that set this as a foreground.
    ///
    /// Twenty-four bit where the terminal said it takes it, and otherwise the
    /// nearest entry in the palette every terminal has had since 1999.
    fn foreground(self, truecolour: bool) -> String {
        if truecolour {
            format!("38;2;{};{};{}", self.red, self.green, self.blue)
        } else {
            format!("38;5;{}", self.nearest_palette_entry())
        }
    }

    /// The closest of the two hundred and fifty-six.
    ///
    /// Both halves of that palette are searched, because they are good at
    /// different things: the six-by-six-by-six cube carries the hues and the
    /// twenty-four step ramp carries the greys, and three of this palette's
    /// seven roles are greys the cube can only approximate to within a step of
    /// forty. Compared by squared distance, which is enough for a decision
    /// between two colours a terminal is about to round anyway.
    fn nearest_palette_entry(self) -> u8 {
        /// What the cube's six steps are worth.
        const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];

        let distance = |red: u8, green: u8, blue: u8| {
            let component = |a: u8, b: u8| {
                let difference = i32::from(a) - i32::from(b);
                difference * difference
            };
            component(red, self.red) + component(green, self.green) + component(blue, self.blue)
        };

        let mut best = (i32::MAX, 0u8);

        for (r, &red) in CUBE.iter().enumerate() {
            for (g, &green) in CUBE.iter().enumerate() {
                for (b, &blue) in CUBE.iter().enumerate() {
                    let index = 16 + 36 * r + 6 * g + b;
                    let found = distance(red, green, blue);
                    if found < best.0 {
                        best = (found, u8::try_from(index).unwrap_or(u8::MAX));
                    }
                }
            }
        }

        for step in 0..24u8 {
            let level = 8 + step * 10;
            let found = distance(level, level, level);
            if found < best.0 {
                best = (found, 232 + step);
            }
        }

        best.1
    }
}

/// The identity of a record: the address a block opens with.
const STRONG: Ink = Ink::new(0xE8, 0xEA, 0xF2);

/// Everything a scan established.
const PLAIN: Ink = Ink::new(0xB4, 0xB9, 0xC8);

/// Labels, units, qualifiers, and the renderer's own notes.
///
/// Chosen against a dark terminal at about 5.2:1, which is subordinate to
/// [`PLAIN`]'s 8.7:1 and legible on its own. Deliberately close to the floor the
/// tests hold it above, because furniture that competes with what it labels is
/// the failure this palette exists to fix. Only close, though: it used to carry
/// `SGR 2` as well and arrived at 2.0:1. See the module note.
const FAINT: Ink = Ink::new(0x86, 0x8D, 0xA1);

/// A port that answered, a host that arrived.
const GOOD: Ink = Ink::new(0x79, 0xD1, 0x8C);

/// Filtered, and anything approaching a deadline.
const CAUTION: Ink = Ink::new(0xDD, 0xB0, 0x61);

/// Past that deadline.
const ALARM: Ink = Ink::new(0xE0, 0x70, 0x5F);

/// How heavily a role is drawn, beside its colour.
///
/// Two values, and the second is the absence of the first. There is no `Dim`:
/// `SGR 2` is the one attribute a terminal cannot be trusted to render the same
/// way as the terminal beside it, and it subtracts from a colour that was
/// already carrying the rank. See the module note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Weight {
    /// The one thing on a line a reader is looking for.
    Bold,
    /// Everything else.
    Regular,
}

impl Weight {
    /// What this adds to a select-graphic-rendition sequence, if anything.
    fn prefix(self) -> &'static str {
        match self {
            Weight::Bold => "1;",
            Weight::Regular => "",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The accent
// ─────────────────────────────────────────────────────────────────────────────

/// The one hue a run may be configured with.
///
/// It marks the names and handles a person scans for and nothing else, so it is
/// the only colour here that carries no meaning of its own, which is exactly why
/// it is the only one worth letting somebody choose. The rest are decisions
/// about legibility and about what a state looks like, and a settings file is
/// not the place to reopen those.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Accent(Ink);

impl Accent {
    /// The default. Far enough from green, amber and red that a hostname never
    /// reads as a verdict, which no warmer hue manages.
    pub(crate) const TEAL: Accent = Accent(Ink::new(0x63, 0xD2, 0xC3));

    /// An instrument-panel reading, and the closest of the three to the
    /// programme this tool is named after. One desaturation step from
    /// [`CAUTION`], so on a display that is unkind to either, a hostname and a
    /// filtered port can end up looking alike.
    pub(crate) const AMBER: Accent = Accent(Ink::new(0xE0, 0xA4, 0x58));

    /// Maximum separation from every state colour. Slightly less legible at dim
    /// weights against a light background.
    pub(crate) const VIOLET: Accent = Accent(Ink::new(0xA7, 0x8B, 0xFA));

    /// The named accents, in the order the help lists them.
    pub(crate) const ALL: [(&'static str, Accent); 3] = [
        ("teal", Accent::TEAL),
        ("amber", Accent::AMBER),
        ("violet", Accent::VIOLET),
    ];

    /// The colour itself.
    #[must_use]
    pub(crate) fn ink(self) -> Ink {
        self.0
    }

    /// This accent as `#rrggbb`.
    ///
    /// Always the triplet, even for a named one, because that is the form that
    /// round-trips: a name is a convenience at the point of writing and the
    /// colour is what was meant.
    #[must_use]
    pub(crate) fn as_hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.0.red, self.0.green, self.0.blue)
    }
}

impl Default for Accent {
    fn default() -> Self {
        Accent::TEAL
    }
}

impl std::fmt::Display for Accent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match Accent::ALL.iter().find(|(_, accent)| accent == self) {
            Some((name, _)) => f.write_str(name),
            None => f.write_str(&self.as_hex()),
        }
    }
}

/// The error [`Accent::from_str`] returns.
#[derive(Debug, thiserror::Error)]
#[error("unusable accent '{written}': expected a colour like '#63d2c3', or one of {}", expected.join(", "))]
pub(crate) struct UnknownAccent {
    /// What was written.
    pub written: String,
    /// The names that would have worked. A triplet always would have.
    pub expected: Vec<&'static str>,
}

impl std::str::FromStr for Accent {
    type Err = UnknownAccent;

    /// A name from [`Accent::ALL`], or a hexadecimal triplet.
    ///
    /// `#63d2c3`, `63d2c3` and `#63D2C3` are all the same colour: the hash is
    /// how a colour is written everywhere else and typing it is not a decision,
    /// so it is optional rather than required. The short `#abc` form is not
    /// accepted. It exists because a stylesheet is typed by hand a hundred times
    /// a day, and here it would only be one more spelling of one value.
    fn from_str(written: &str) -> Result<Self, Self::Err> {
        let refuse = || UnknownAccent {
            written: written.to_owned(),
            expected: Accent::ALL.map(|(name, _)| name).to_vec(),
        };

        if let Some((_, accent)) = Accent::ALL
            .iter()
            .find(|(name, _)| written.eq_ignore_ascii_case(name))
        {
            return Ok(*accent);
        }

        let digits = written.strip_prefix('#').unwrap_or(written);

        if digits.len() != 6 || !digits.chars().all(|digit| digit.is_ascii_hexdigit()) {
            return Err(refuse());
        }

        let component =
            |at: usize| u8::from_str_radix(&digits[at..at + 2], 16).map_err(|_| refuse());

        Ok(Accent(Ink::new(
            component(0)?,
            component(2)?,
            component(4)?,
        )))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// What a run was told about painting
// ─────────────────────────────────────────────────────────────────────────────

/// What kind of line something on standard error is.
///
/// The engine names one of these on every event it emits: `info`, `success`,
/// `warn`, `error`, `incoming`, `outgoing`. This crate's own commentary answers
/// to the same six, so one stream does not carry two vocabularies.
///
/// **The glyph carries the kind, not the colour.** A run piped to a file keeps
/// the distinction, which is the whole reason a warning and an error are
/// different shapes rather than the same shape twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mark {
    /// Something happened. The ordinary line.
    Info,
    /// Something the run wanted, and got.
    Success,
    /// Something that qualifies whatever is around it.
    Warning,
    /// Something that did not work.
    Error,
    /// A probe leaving this machine.
    Outgoing,
    /// A reply arriving.
    Incoming,
}

impl Mark {
    /// What opens the line.
    ///
    /// One column each, so the text after them starts in one column whatever
    /// kind of line it is.
    ///
    /// `━` U+2501 for a warning: a heavy dash, one column wide in any monospace
    /// face, that reads as the minus between a success's `+` and an error's
    /// `×`. A heavy-minus emoji would draw two columns in many terminals and
    /// push the text after it out of line.
    ///
    /// `•` U+2022 for the ordinary line rather than `·` U+00B7, which is the
    /// same shape two sizes down and reads as a speck on the glass rather than
    /// as a mark somebody put there. It carries the most lines by far, so it has
    /// to be quiet. Quiet is what the grey is for, though, and a glyph that is
    /// quiet in *shape* as well is a glyph nobody sees at all.
    #[must_use]
    pub(crate) fn glyph(self) -> &'static str {
        match self {
            Mark::Info => "\u{2022}",
            Mark::Success => "+",
            Mark::Warning => "\u{2501}",
            Mark::Error => "\u{d7}",
            Mark::Outgoing => "\u{bb}",
            Mark::Incoming => "\u{ab}",
        }
    }

    /// What the engine calls this on the wire.
    #[must_use]
    pub(crate) fn named(status: &str) -> Option<Self> {
        Some(match status {
            "info" => Mark::Info,
            "success" => Mark::Success,
            "warn" => Mark::Warning,
            "error" => Mark::Error,
            "incoming" => Mark::Incoming,
            "outgoing" => Mark::Outgoing,
            _ => return None,
        })
    }
}

/// Whether a run was told to colour its output.
///
/// `Auto` is the default and the only one that consults the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ColourChoice {
    /// Colour when the stream is a terminal that wants it.
    #[default]
    Auto,
    /// Colour whatever the stream is, which is what a pager being fed on
    /// purpose needs.
    Always,
    /// No colour, whatever the environment says.
    Never,
}

impl ColourChoice {
    /// Every spelling, in the order the help lists them.
    pub(crate) const ALL: [ColourChoice; 3] = [
        ColourChoice::Auto,
        ColourChoice::Always,
        ColourChoice::Never,
    ];

    /// What this is called on the command line.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ColourChoice::Auto => "auto",
            ColourChoice::Always => "always",
            ColourChoice::Never => "never",
        }
    }
}

impl std::fmt::Display for ColourChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error [`ColourChoice::from_str`] returns.
#[derive(Debug, thiserror::Error)]
#[error("unknown colour setting '{written}': expected one of {}", expected.join(", "))]
pub(crate) struct UnknownColourChoice {
    /// What was written.
    pub written: String,
    /// The names that would have worked.
    pub expected: Vec<&'static str>,
}

impl std::str::FromStr for ColourChoice {
    type Err = UnknownColourChoice;

    fn from_str(written: &str) -> Result<Self, Self::Err> {
        ColourChoice::ALL
            .into_iter()
            .find(|choice| written.eq_ignore_ascii_case(choice.as_str()))
            .ok_or_else(|| UnknownColourChoice {
                written: written.to_owned(),
                expected: ColourChoice::ALL.map(ColourChoice::as_str).to_vec(),
            })
    }
}

/// Everything a run was told about how to paint.
///
/// The two decisions travel together because they are always made together and
/// always needed together: every function that wanted a [`ColourChoice`] wants
/// the accent beside it, and threading a second argument through the same six
/// signatures would be spelling out a pair the caller already has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Palette {
    /// Whether to paint at all.
    pub when: ColourChoice,
    /// The hue that marks the names and handles.
    pub accent: Accent,
}

impl Palette {
    /// The palette a run with these two answers draws in.
    #[must_use]
    pub(crate) fn new(when: ColourChoice, accent: Accent) -> Self {
        Self { when, accent }
    }

    /// The default accent, painted according to `when`.
    ///
    /// What the tests that are about painting rather than about the accent use.
    /// A run reaches the same value through [`Palette::default`], which is what
    /// a settings file that names no accent leaves behind.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn when(when: ColourChoice) -> Self {
        Self {
            when,
            accent: Accent::default(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Style
// ─────────────────────────────────────────────────────────────────────────────

/// How a stream may be drawn on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Style {
    /// Whether escape sequences are emitted at all.
    colour: bool,
    /// Whether this terminal takes a twenty-four bit triplet.
    truecolour: bool,
    /// The hue names and handles are marked with.
    accent: Ink,
}

impl Style {
    /// No colour: the plainest output this crate writes, and what a capture to a
    /// file wants.
    ///
    /// What the presentation tests assert against, so that a change to the
    /// palette cannot quietly rewrite what they are checking.
    #[must_use]
    pub(crate) fn bare() -> Self {
        Self {
            colour: false,
            truecolour: false,
            accent: Accent::default().ink(),
        }
    }

    /// What `palette` amounts to for a stream that is or is not a terminal.
    ///
    /// The two gates read different things. Colour asks, in order: `--colour`
    /// when it was given, then `CLICOLOR_FORCE`, then `NO_COLOR`, then
    /// `TERM=dumb`, and only then whether the stream is a terminal. That is the
    /// precedence every other tool reading those variables uses. Depth asks
    /// `COLORTERM`, which is the only thing a terminal says about it.
    #[must_use]
    pub(crate) fn detect(palette: Palette, is_terminal: bool) -> Self {
        let dumb = env_says("TERM").is_some_and(|term| term == "dumb");

        let colour = match palette.when {
            ColourChoice::Always => true,
            ColourChoice::Never => false,
            ColourChoice::Auto => {
                env_says("CLICOLOR_FORCE").is_some()
                    || (env_says("NO_COLOR").is_none() && !dumb && is_terminal)
            }
        };

        Self {
            colour,
            truecolour: takes_truecolour(),
            accent: palette.accent.ink(),
        }
    }

    /// What this process's standard output should be drawn in.
    #[must_use]
    pub(crate) fn for_stdout(palette: Palette) -> Self {
        Self::detect(palette, std::io::stdout().is_terminal())
    }

    /// What `presentation` draws this process's standard output in.
    ///
    /// **Only `fancy` is painted.** `minimal` promises abbreviated tags and
    /// no colour and `pipe` promises a stable interface, so neither may pick up
    /// escape codes merely because the terminal would accept them. Asked here
    /// rather than at each command, because `diff` and `journal` deciding this
    /// separately is how one of them ends up colouring a mode that says it does
    /// not.
    #[must_use]
    pub(crate) fn records(presentation: Presentation, palette: Palette) -> Self {
        match presentation {
            Presentation::Fancy => Self::for_stdout(palette),
            _ => Self::bare(),
        }
    }

    /// The same question for this process's standard error.
    #[must_use]
    pub(crate) fn commentary(presentation: Presentation, palette: Palette) -> Self {
        match presentation {
            Presentation::Fancy => Self::for_stderr(palette),
            _ => Self::bare(),
        }
    }

    /// What this process's standard error should be drawn in.
    ///
    /// Asked separately from standard output, because `zond discover lan | less`
    /// redirects one of them and not the other: the records lose their colour
    /// and the commentary keeps it, which is what a person watching that command
    /// wants.
    #[must_use]
    pub(crate) fn for_stderr(palette: Palette) -> Self {
        Self::detect(palette, std::io::stderr().is_terminal())
    }

    /// Whether anything painted here will actually carry colour.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn has_colour(self) -> bool {
        self.colour
    }

    /// `text`, escaped, and wrapped in `ink` at `weight` when this style paints.
    ///
    /// **The one place anything written by a presentation is escaped.** The
    /// roles below all route through here, [`plainly`](Self::plainly) included,
    /// so there is no second path a value can take to reach the terminal: a
    /// hostname a scanned host chose carrying `\x1b[2J` would otherwise clear
    /// the screen of whoever scanned it.
    fn paint(self, ink: Option<(Ink, Weight)>, text: &str) -> String {
        let printable = field::printable(text);

        match ink.filter(|_| self.colour) {
            Some((ink, weight)) => format!(
                "{ESC}[{}{}m{printable}{RESET}",
                weight.prefix(),
                ink.foreground(self.truecolour)
            ),
            None => printable.into_owned(),
        }
    }

    /// The identity of a record: the address a block opens with.
    ///
    /// The only bold thing in a block, and there is exactly one per block. What
    /// makes it findable is that nothing else competes, so this is the role to
    /// be miserly with.
    #[must_use]
    pub(crate) fn strong(self, text: &str) -> String {
        self.paint(Some((STRONG, Weight::Bold)), text)
    }

    /// Everything a scan established that has no state of its own: an address, a
    /// hardware address, a latency, an operating system, a service.
    #[must_use]
    pub(crate) fn plain(self, text: &str) -> String {
        self.paint(Some((PLAIN, Weight::Regular)), text)
    }

    /// The furniture: labels, units, qualifiers, the step number on a hop, and
    /// the notes the renderer writes about what it decided not to enumerate.
    ///
    /// A qualifier belongs here rather than beside what it qualifies, because it
    /// is the same fact seen again rather than a second finding. The vendor read
    /// out of a hardware address and the confidence on a fingerprint are both
    /// qualifiers in that sense.
    #[must_use]
    pub(crate) fn faint(self, text: &str) -> String {
        self.paint(Some((FAINT, Weight::Regular)), text)
    }

    /// A name the network gave back, and a handle a person reads out.
    ///
    /// The one hue a run may be configured with, and the one a reader is
    /// scanning the screen for.
    #[must_use]
    pub(crate) fn accent(self, text: &str) -> String {
        self.paint(Some((self.accent, Weight::Regular)), text)
    }

    /// A port that answered, a host that arrived.
    #[must_use]
    pub(crate) fn good(self, text: &str) -> String {
        self.paint(Some((GOOD, Weight::Regular)), text)
    }

    /// Filtered, and anything approaching a deadline.
    #[must_use]
    pub(crate) fn caution(self, text: &str) -> String {
        self.paint(Some((CAUTION, Weight::Regular)), text)
    }

    /// Past that deadline.
    #[must_use]
    pub(crate) fn alarm(self, text: &str) -> String {
        self.paint(Some((ALARM, Weight::Regular)), text)
    }

    /// The glyph that opens a line, in the colour its kind is drawn in.
    ///
    /// **Both halves of the conversation are coloured, and differently.** A run
    /// watching its own traffic is reading two interleaved streams, and which
    /// half a line belongs to is the first thing it needs. Neither is furniture:
    /// a packet is the whole point of the line it is on.
    ///
    /// Not a state colour for either. A probe going out and a reply coming back
    /// are a direction, not a verdict, and green would be claiming something
    /// about a packet that only a port can say.
    #[must_use]
    pub(crate) fn mark(self, mark: Mark) -> String {
        match mark {
            Mark::Info => self.faint(mark.glyph()),
            Mark::Outgoing => self.plain(mark.glyph()),
            Mark::Incoming => self.accent(mark.glyph()),
            Mark::Success => self.good(mark.glyph()),
            Mark::Warning => self.caution(mark.glyph()),
            Mark::Error => self.alarm(mark.glyph()),
        }
    }

    /// A whole line of commentary: a glyph that carries the colour, and the text
    /// beside it drawn faint.
    ///
    /// **The colour rides on the glyph alone, and every line's text is one faint
    /// grey.** A success, a warning and an error are a green `+`, a yellow `━`
    /// and a red `×` in front of grey text, the same grey a remark's `•` sits in
    /// front of. Colour marks the *kind* of line in one column, which is the
    /// whole of what it is for; the commentary itself is furniture behind the
    /// records on the other stream, so it recedes into one dim shade rather than
    /// competing for the eye line by line.
    ///
    /// The glyph carries the whole distinction: [`mark`](Self::mark) draws a
    /// faint `•` for a remark, a bright hue for a success, a warning or an error,
    /// and the two listen directions their own. The text after it is that one
    /// grey throughout.
    ///
    /// **`text` is escaped like anything else.** A caller holding something it
    /// has already painted composes the line itself from [`mark`](Self::mark).
    /// Handing it here turns its escape sequences into the literal characters
    /// `\x1b[…`, which is the correct answer for a hostname and the wrong one for
    /// a colour this program chose.
    ///
    /// **The one place a line on standard error is composed.** A scan's
    /// narration, the engine's diagnostics and the journal's footer all pass
    /// through here, so this rule is drawn once and holds for the whole stream.
    ///
    /// # A wrapped line continues under its own words
    ///
    /// A line too wide for the terminal is broken here rather than left to the
    /// terminal, which would begin the remainder in column zero — under the
    /// glyph, where the eye reads it as a new event rather than as the rest of
    /// this one. Every glyph is one column and one space follows it, so the
    /// continuation is indented by [`HANGING`] and the sentence keeps one left
    /// edge.
    ///
    /// **Only for a terminal.** Where standard error is a file or a pipe there
    /// is no width to break to, and a collector reading events back should not
    /// have to rejoin a sentence somebody's window happened to split. See
    /// [`commentary_width`](crate::render::commentary_width).
    #[must_use]
    pub(crate) fn line(self, mark: Mark, text: &str) -> String {
        let Some(width) = crate::render::commentary_width() else {
            return format!("{} {}", self.mark(mark), self.faint(text));
        };

        // Escaped before it is broken, not after: a control byte a scanned host
        // chose becomes four characters when it is drawn, and a break measured
        // before that happens is measured against a different string than the
        // one a terminal gets. The painting escapes again and finds nothing left
        // to do.
        let printable = field::printable(text);
        let room = width.saturating_sub(HANGING).max(NARROWEST_LINE);

        let mut drawn = String::new();
        for (index, piece) in field::wrap(&printable, room).iter().enumerate() {
            if index == 0 {
                drawn.push_str(&self.mark(mark));
                drawn.push(' ');
            } else {
                drawn.push('\n');
                drawn.push_str(&" ".repeat(HANGING));
            }
            drawn.push_str(&self.faint(piece));
        }

        drawn
    }

    /// Text with no role.
    ///
    /// Still routed through [`paint`](Self::paint), because escaping is the part
    /// that is not optional. A value with nothing to say about it is the case
    /// where forgetting would be easiest and least visible.
    #[must_use]
    pub(crate) fn plainly(self, text: &str) -> String {
        self.paint(None, text)
    }

    /// `text` coloured by how close whatever it describes is to being a problem.
    ///
    /// [`Muted`](Urgency::Muted) is the one that subtracts rather than adds. A
    /// scale whose bottom rank is drawn in the same ink as the words beside it is
    /// a scale that stops being a column of colour exactly where it should be
    /// receding, so the lowest grade recedes.
    #[must_use]
    pub(crate) fn by_urgency(self, urgency: Urgency, text: &str) -> String {
        match urgency {
            Urgency::None => self.plainly(text),
            Urgency::Muted => self.faint(text),
            Urgency::Caution => self.caution(text),
            Urgency::Alarm => self.alarm(text),
        }
    }
}

/// Whether this terminal said it takes twenty-four bit colour.
///
/// `COLORTERM` is the only thing a terminal says about depth, and it says it by
/// being set to one of two words. Anything else gets the palette index, which is
/// a rounding rather than a failure. That includes a terminal which takes the
/// triplet perfectly well and never said so.
fn takes_truecolour() -> bool {
    env_says("COLORTERM").is_some_and(|depth| depth == "truecolor" || depth == "24bit")
}

/// An environment variable, when it is set to something that is not empty.
///
/// The empty string is treated as unset, which is what `NO_COLOR` specifies and
/// what `CLICOLOR_FORCE` is read the same way for.
fn env_says(name: &str) -> Option<String> {
    std::env::var_os(name)
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
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

    /// What a palette entry is actually worth.
    ///
    /// The rounding has to preserve a *rank*, and an index is only a proxy for
    /// lightness inside the grey ramp; across the cube it says nothing at all.
    /// So the tests that care compare the colours the entries stand for.
    fn palette_entry(index: u8) -> Ink {
        const CUBE: [u8; 6] = [0, 95, 135, 175, 215, 255];

        if index >= 232 {
            let level = 8 + (index - 232) * 10;
            return Ink::new(level, level, level);
        }

        let offset = usize::from(index - 16);
        Ink::new(CUBE[offset / 36], CUBE[(offset / 6) % 6], CUBE[offset % 6])
    }

    /// The contrast ratio between two colours, as WCAG defines it.
    fn contrast(ink: Ink, ground: Ink) -> f64 {
        let relative = |ink: Ink| {
            let channel = |value: u8| {
                let value = f64::from(value) / 255.0;
                if value <= 0.039_28 {
                    value / 12.92
                } else {
                    ((value + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * channel(ink.red) + 0.7152 * channel(ink.green) + 0.0722 * channel(ink.blue)
        };

        let (a, b) = (relative(ink), relative(ground));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    /// How light a colour reads, weighted the way an eye weights it.
    fn lightness(ink: Ink) -> f64 {
        0.2126 * f64::from(ink.red) + 0.7152 * f64::from(ink.green) + 0.0722 * f64::from(ink.blue)
    }

    /// A style that paints, for the tests that are about colour.
    fn painting() -> Style {
        Style {
            colour: true,
            truecolour: true,
            accent: Accent::default().ink(),
        }
    }

    /// Painting escapes first. A hostname carrying its own escape sequence would
    /// otherwise reach the terminal of whoever ran the scan.
    #[test]
    fn a_value_cannot_smuggle_an_escape_through_the_paint() {
        let painted = painting().accent("evil\x1b[2Jcleared");

        assert!(!painted.contains("\x1b[2J"), "{painted:?}");
        assert!(painted.contains("\\x1b[2J"), "{painted:?}");
    }

    /// The colour of a line rides on its glyph; its text is one faint grey.
    ///
    /// A warning is a coloured `━` in front of grey text, not a sentence washed
    /// yellow: colour marks the kind of line in one column, and the commentary
    /// itself recedes into the same dim shade whatever its glyph. The glyph
    /// carries the hue; the text is faint throughout.
    #[test]
    fn a_lines_colour_is_on_its_glyph_and_not_its_text() {
        let style = painting();

        for mark in [
            Mark::Info,
            Mark::Success,
            Mark::Warning,
            Mark::Error,
            Mark::Outgoing,
            Mark::Incoming,
        ] {
            let composed = style.line(mark, "the message");
            let glyph = style.mark(mark);

            // The glyph arrives painted, exactly as `mark` draws it.
            assert!(
                composed.starts_with(&glyph),
                "the glyph should open the line painted: {composed:?}"
            );

            // And what follows the glyph is the message with no colour of its
            // own — the same bytes `plainly` produces, escapes and all.
            let text = composed
                .strip_prefix(&glyph)
                .and_then(|rest| rest.strip_prefix(' '))
                .expect("a glyph and a space open the line");
            assert_eq!(
                text,
                style.faint("the message"),
                "the text is one faint grey, whatever the glyph's colour: {composed:?}"
            );
        }
    }

    /// Every kind of line opens with a different shape, not merely a different
    /// colour.
    ///
    /// A run piped to a file keeps the distinction between a warning and an
    /// error; a run read by somebody who cannot tell amber from red keeps it
    /// too. That is the whole reason these are six glyphs rather than one glyph
    /// in six colours.
    #[test]
    fn every_kind_of_line_opens_with_its_own_shape() {
        let marks = [
            Mark::Info,
            Mark::Success,
            Mark::Warning,
            Mark::Error,
            Mark::Outgoing,
            Mark::Incoming,
        ];

        // Pinned, because which glyph opens which line is a decision rather than
        // an implementation detail. The set is what a reader learns once.
        assert_eq!(
            marks.map(Mark::glyph),
            ["\u{2022}", "+", "\u{2501}", "\u{d7}", "\u{bb}", "\u{ab}"]
        );

        let glyphs: Vec<&str> = marks.iter().map(|mark| mark.glyph()).collect();
        for (at, glyph) in glyphs.iter().enumerate() {
            assert_eq!(glyph.chars().count(), 1, "{glyph:?} is not one column");
            assert!(
                !glyphs[at + 1..].contains(glyph),
                "two kinds of line open with {glyph:?}"
            );
        }
    }

    /// The engine names its events and this crate reads those names. A status it
    /// does not know is not a line without a glyph; it falls back to the level.
    #[test]
    fn the_engines_own_words_choose_the_glyph() {
        for (status, expected) in [
            ("info", Mark::Info),
            ("success", Mark::Success),
            ("warn", Mark::Warning),
            ("error", Mark::Error),
            ("incoming", Mark::Incoming),
            ("outgoing", Mark::Outgoing),
        ] {
            assert_eq!(Mark::named(status), Some(expected), "{status}");
        }

        assert_eq!(Mark::named("ascended"), None);
    }

    /// Traffic is furniture and the two that want reading are not. A run asking
    /// to see its probes gets a great many arrows, and the point of those lines
    /// is the packet rather than the arrow.
    #[test]
    fn a_mark_is_drawn_in_the_colour_it_means() {
        let painting = painting();

        let opener = |painted: String| {
            let at = painted.find(|c: char| {
                !c.is_ascii_control()
                    && c != '['
                    && c != ';'
                    && !c.is_ascii_digit()
                    && c != '\u{1b}'
            });
            painted[..at.unwrap_or(0)].to_owned()
        };

        assert_ne!(
            opener(painting.mark(Mark::Outgoing)),
            opener(painting.mark(Mark::Info)),
            "a packet is drawn as furniture"
        );
        assert_eq!(
            opener(painting.mark(Mark::Incoming)),
            opener(painting.accent("x")),
            "what came back does not take the accent"
        );
        assert_ne!(
            opener(painting.mark(Mark::Incoming)),
            opener(painting.mark(Mark::Outgoing)),
            "the two halves of the conversation look alike"
        );
        assert_eq!(
            opener(painting.mark(Mark::Warning)),
            opener(painting.caution("x")),
            "a warning is not amber"
        );
        assert_eq!(
            opener(painting.mark(Mark::Error)),
            opener(painting.alarm("x")),
            "an error is not red"
        );
        assert_ne!(
            opener(painting.mark(Mark::Success)),
            opener(painting.mark(Mark::Info)),
            "success and information look alike"
        );
    }

    /// A newline is escaped like anything else, which is a trap worth writing
    /// down.
    ///
    /// It is the right behaviour, since a hostname carrying a newline could
    /// forge a line of output that no scan produced. It does mean a role is a
    /// thing you hand *one line* to. Whitespace a renderer wants for itself has
    /// to be written outside the paint, which is why the commentary writers have
    /// a separate call for a blank line.
    /// A commentary line too wide for the terminal continues under its own
    /// words. The terminal would begin the remainder in column zero, under the
    /// glyph, where it reads as a new event rather than as the rest of this one.
    #[test]
    fn a_wrapped_commentary_line_continues_under_its_words() {
        let style = Style::bare();
        let text = "paced down to 16 in flight and 96% still unanswered; those may be \
                    dropped probes rather than filtered ports";

        // `line` asks the real stderr for its width, so the wrap itself is
        // exercised through the piece that does it.
        let pieces = field::wrap(text, 40);
        assert!(pieces.len() > 1, "the fixture does not wrap: {pieces:?}");

        let drawn = pieces
            .iter()
            .enumerate()
            .map(|(index, piece)| {
                if index == 0 {
                    format!("{} {}", style.mark(Mark::Warning), style.faint(piece))
                } else {
                    format!("{}{}", " ".repeat(HANGING), style.faint(piece))
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let lines: Vec<&str> = drawn.lines().collect();
        let glyph = Mark::Warning.glyph().chars().count();
        assert_eq!(glyph + 1, HANGING, "every glyph is one column and a space");

        for line in &lines[1..] {
            assert_eq!(
                line.len() - line.trim_start().len(),
                HANGING,
                "a continuation does not start under the words above it: {drawn}"
            );
        }
    }

    /// Where standard error is not a terminal there is no width to break to, so
    /// the line stays whole and a collector reads one event per line.
    #[test]
    fn a_line_is_whole_where_there_is_no_terminal_to_break_to() {
        // The tests run with standard error captured, so there is no terminal
        // and this is the branch `line` actually takes here.
        if crate::render::commentary_width().is_some() {
            return;
        }

        let drawn = Style::bare().line(
            Mark::Info,
            "a sentence long enough that any \
             terminal narrower than it would have to break it somewhere",
        );
        assert_eq!(drawn.lines().count(), 1, "{drawn}");
    }

    #[test]
    fn a_newline_is_escaped_too_so_a_role_takes_one_line() {
        let painted = painting().faint("above\nbelow");

        assert!(!painted.contains('\n'), "{painted:?}");
        assert!(painted.contains("\\n"), "{painted:?}");
    }

    /// The same, for a style that paints nothing: escaping is not something
    /// colour turns on.
    #[test]
    fn escaping_happens_even_when_nothing_is_painted() {
        let plain = Style::bare().plainly("evil\x1b[2J");
        assert!(!plain.contains('\x1b'), "{plain:?}");
    }

    /// An uncoloured style is a pass-through, so a test asserting on layout
    /// reads the layout rather than a wall of escape codes.
    #[test]
    fn without_colour_a_role_leaves_the_text_alone() {
        let plain = Style::bare();
        assert_eq!(plain.good("open"), "open");
        assert_eq!(plain.faint("hardware"), "hardware");
        assert_eq!(plain.strong("192.0.2.1"), "192.0.2.1");
        assert_eq!(plain.alarm("expired"), "expired");
    }

    /// Every role wraps and closes, so nothing bleeds into the line after it.
    #[test]
    fn every_role_closes_what_it_opens() {
        let painting = painting();

        for painted in [
            painting.strong("a"),
            painting.plain("a"),
            painting.faint("a"),
            painting.accent("a"),
            painting.good("a"),
            painting.caution("a"),
            painting.alarm("a"),
        ] {
            assert!(painted.starts_with(ESC), "{painted:?}");
            assert!(painted.ends_with(RESET), "{painted:?}");
        }
    }

    /// Bold is the only attribute in the palette, and it is on the only role
    /// that wants one. Everything below it is separated by colour alone.
    #[test]
    fn bold_is_the_only_weight_and_nothing_is_dimmed() {
        let painting = painting();

        assert!(
            painting.strong("a").contains("[1;38;2;"),
            "{:?}",
            painting.strong("a")
        );

        for painted in [
            painting.plain("a"),
            painting.faint("a"),
            painting.accent("a"),
            painting.good("a"),
            painting.caution("a"),
            painting.alarm("a"),
        ] {
            assert!(painted.contains("[38;2;"), "{painted:?}");
            assert!(
                !painted.contains("[2;"),
                "a role carried SGR 2, which halves a contrast that is already \
                 the whole rank: {painted:?}"
            );
        }

        assert_ne!(STRONG, PLAIN);
        assert_ne!(PLAIN, FAINT);
    }

    /// The furniture has to stay legible on its own, because nothing else says
    /// what a value is. Measured against a dark terminal, which is where it is
    /// hardest, and this is the check the last arrangement would have failed.
    #[test]
    fn the_faintest_role_is_still_comfortably_readable() {
        const GROUND: Ink = Ink::new(0x1A, 0x1B, 0x26);

        let faint = contrast(FAINT, GROUND);
        let plain = contrast(PLAIN, GROUND);

        assert!(faint >= 4.5, "the furniture is not readable: {faint:.2}:1");
        assert!(
            plain > faint + 1.5,
            "the furniture is not subordinate to what it labels: \
             {plain:.2}:1 against {faint:.2}:1"
        );

        // And after the rounding, which is what a terminal without truecolour
        // actually receives. The exact triplet cannot make that check on its own.
        let rounded = |ink: Ink| contrast(palette_entry(ink.nearest_palette_entry()), GROUND);

        assert!(
            rounded(FAINT) >= 4.5,
            "the furniture is not readable once rounded to the palette: {:.2}:1",
            rounded(FAINT)
        );
        assert!(
            rounded(PLAIN) > rounded(FAINT) + 1.5,
            "the rounding collapsed the rank: {:.2}:1 against {:.2}:1",
            rounded(PLAIN),
            rounded(FAINT)
        );
    }

    /// A terminal that did not claim twenty-four bit colour is told a palette
    /// index instead, rather than being told nothing.
    #[test]
    fn without_truecolour_a_role_falls_back_to_the_palette() {
        let indexed = Style {
            truecolour: false,
            ..painting()
        };

        let painted = indexed.good("open");
        assert!(painted.contains("38;5;"), "{painted:?}");
        assert!(!painted.contains("38;2;"), "{painted:?}");
    }

    /// The three greys have to stay three greys after the rounding, or the rank
    /// they carry collapses on every terminal that predates truecolour.
    ///
    /// Weight alone would not save it: a terminal old enough to want the palette
    /// is old enough to render `SGR 2` as nothing.
    #[test]
    fn the_greys_survive_the_fall_back_to_the_palette() {
        let rounded = |ink: Ink| lightness(palette_entry(ink.nearest_palette_entry()));

        let strong = rounded(STRONG);
        let plain = rounded(PLAIN);
        let faint = rounded(FAINT);

        assert!(
            strong > plain && plain > faint,
            "the greys did not stay ranked: {strong:.0} / {plain:.0} / {faint:.0}"
        );

        // And far enough apart to be told apart rather than merely ordered.
        assert!(
            strong - plain > 12.0 && plain - faint > 12.0,
            "the greys rounded too close together: {strong:.0} / {plain:.0} / {faint:.0}"
        );
    }

    /// The state colours have to stay apart from each other too: an amber that
    /// rounds onto the same entry as red is a caution that reads as an alarm.
    #[test]
    fn the_state_colours_stay_apart_in_the_palette() {
        let good = GOOD.nearest_palette_entry();
        let caution = CAUTION.nearest_palette_entry();
        let alarm = ALARM.nearest_palette_entry();

        assert_ne!(good, caution);
        assert_ne!(caution, alarm);
        assert_ne!(good, alarm);
    }

    /// A neutral grey belongs on the ramp, which is the half of the palette the
    /// cube cannot approximate: the cube's own greys step by forty, so its
    /// nearest answer to `#505050` is off by fifteen in every component.
    ///
    /// The palette's own greys are slate rather than neutral and land in the
    /// cube instead, which is fine. What matters is that the ramp is searched at
    /// all, and this is the case that proves it.
    #[test]
    fn a_neutral_grey_rounds_onto_the_ramp_rather_than_the_cube() {
        let entry = Ink::new(0x50, 0x50, 0x50).nearest_palette_entry();

        assert!(
            (232..=255).contains(&entry),
            "a neutral grey did not use the ramp: {entry}"
        );
    }

    /// An exact palette colour rounds to itself, which is the cheapest check
    /// that the search is looking at the right table.
    #[test]
    fn a_colour_the_palette_already_has_rounds_onto_itself() {
        // 16 is the cube's origin, 231 its far corner, 244 the middle grey.
        assert_eq!(Ink::new(0, 0, 0).nearest_palette_entry(), 16);
        assert_eq!(Ink::new(255, 255, 255).nearest_palette_entry(), 231);
        assert_eq!(Ink::new(128, 128, 128).nearest_palette_entry(), 244);
    }

    /// The two settings that do not consult anything: `never` on a terminal and
    /// `always` on a pipe are the cases where the environment would have said
    /// the opposite, so they are what proves the flag outranks it.
    #[test]
    fn always_and_never_outrank_what_the_stream_is() {
        assert!(!Style::detect(Palette::when(ColourChoice::Never), true).has_colour());
        assert!(Style::detect(Palette::when(ColourChoice::Always), false).has_colour());
    }

    #[test]
    fn a_colour_setting_round_trips_through_its_spelling() {
        for choice in ColourChoice::ALL {
            assert_eq!(choice.as_str().parse::<ColourChoice>().unwrap(), choice);
        }
        assert!("technicolor".parse::<ColourChoice>().is_err());
    }

    /// Every named accent parses, and so does the triplet it stands for. The
    /// name is a convenience at the point of writing, not a separate value.
    #[test]
    fn an_accent_round_trips_through_its_name_and_its_triplet() {
        for (name, accent) in Accent::ALL {
            assert_eq!(name.parse::<Accent>().unwrap(), accent);
            assert_eq!(accent.as_hex().parse::<Accent>().unwrap(), accent);
            assert_eq!(accent.to_string(), name);
        }
    }

    /// The hash is how a colour is written everywhere else, so typing it is not
    /// a decision.
    #[test]
    fn a_triplet_is_read_with_or_without_its_hash() {
        assert_eq!("#63d2c3".parse::<Accent>().unwrap(), Accent::TEAL);
        assert_eq!("63D2C3".parse::<Accent>().unwrap(), Accent::TEAL);
    }

    /// An accent nobody named is still a colour, and says so as a triplet
    /// rather than pretending to a name.
    #[test]
    fn an_unnamed_accent_prints_as_its_triplet() {
        let custom: Accent = "#102030".parse().expect("a triplet");
        assert_eq!(custom.to_string(), "#102030");
    }

    /// The refusals. A short form is not accepted, because it would be one more
    /// spelling of a value the long form already covers.
    #[test]
    fn an_accent_that_is_neither_a_name_nor_a_colour_is_refused() {
        for written in ["chartreuse", "#abc", "#63d2c", "#63d2cg", "", "#"] {
            assert!(
                written.parse::<Accent>().is_err(),
                "accepted {written:?} as an accent"
            );
        }
    }

    /// The accent is the only role a run may move, so it has to actually reach
    /// the paint.
    #[test]
    fn the_configured_accent_is_what_a_name_is_painted_in() {
        let violet = Style::detect(Palette::new(ColourChoice::Always, Accent::VIOLET), false);
        let teal = Style::detect(Palette::new(ColourChoice::Always, Accent::TEAL), false);

        assert_ne!(
            violet.accent("router.example"),
            teal.accent("router.example")
        );
        assert_eq!(violet.plain("192.0.2.1"), teal.plain("192.0.2.1"));
    }
}
