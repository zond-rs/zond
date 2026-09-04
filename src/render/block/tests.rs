// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The geometry, asserted against the drawing it is supposed to produce.
//!
//! In its own file because it is arithmetic and nothing else: every test here
//! uses an unpainted [`Style`], so what is being read is the layout rather than
//! a wall of escape codes. That also lets this file be compiled against a stub
//! `Style` on its own, which is how the columns were checked while the engine
//! next door was mid-change.

use super::*;
use crate::render::test_support::strip_escapes;

/// The unpainted style every layout test draws in.
fn bare() -> Style {
    Style::bare()
}

/// One block, drawn on its own.
fn drawn(block: &Block) -> String {
    listing(std::slice::from_ref(block))
}

/// A whole listing, blank-separated the way a run writes it.
fn listing(blocks: &[Block]) -> String {
    let mut out = Vec::new();
    write_all(&mut out, bare(), blocks, |out, index| {
        if index > 0 {
            writeln!(out)?;
        }
        Ok(())
    })
    .expect("a vector cannot fail");
    String::from_utf8(out).expect("the renderer writes text")
}

/// A header with an address and a name.
fn host(at: usize, identity: &str, name: Option<&str>) -> Header {
    Header {
        at: Some(at),
        tag: None,
        identity: identity.to_owned(),
        name: name.map(ToOwned::to_owned),
        verdict: None,
    }
}

/// A fact, as a caller builds one.
fn fact(label: &'static str, value: &str) -> Child {
    Child::one(label, bare().plain(value))
}

/// A fact that is a list.
fn facts(label: &'static str, values: &[&str]) -> Child {
    Child::many(
        label,
        values.iter().map(|value| bare().plain(value)).collect(),
    )
}

/// One row of a port table, with its own columns already padded.
///
/// Hand-built here because the port table's internal alignment belongs to
/// whoever knows what a port is, not to this module, which is exactly the
/// separation these tests are checking.
fn port(port: &str, state: &str, service: Option<(&str, &str)>) -> String {
    let described = match service {
        Some((service, product)) => format!("  {service:<5}  {product}"),
        None => String::new(),
    };

    format!("{port:<7}  {state:<8}{described}")
        .trim_end()
        .to_owned()
}

// ─────────────────────────────────────────────────────────────────────────────

/// The shape the whole program rests on. If this drifts, everything else here
/// is asserting on a layout nobody chose.
#[test]
fn a_sweep_reads_as_one_listing() {
    let blocks = vec![
        Block {
            header: host(1, "192.168.0.1", Some("kabelbox.local")),
            children: vec![
                fact("hardware", "c8:52:61:c7:05:94  Arris"),
                fact("roles", "router  dns  dhcp"),
                fact("answered", "arp  icmp  ndp"),
                facts(
                    "also",
                    &[
                        "2a02:908:8c1:b880::1",
                        "2a02:908:8c1:b880:ca52:61ff:fec7:594",
                    ],
                ),
            ],
        },
        Block {
            header: host(2, "192.168.0.30", Some("EPSON928262")),
            children: vec![
                fact("hardware", "dc:cd:2f:92:82:62  Seiko Epson"),
                fact("answered", "arp  icmp  ndp"),
            ],
        },
        Block {
            header: host(3, "192.168.0.101", Some("LGwebOSTV.local")),
            children: vec![
                fact("hardware", "28:87:61:53:ef:8e"),
                fact("answered", "arp  icmp"),
            ],
        },
        Block {
            header: host(4, "192.168.0.150", Some("RaspberryPi")),
            children: vec![
                fact("hardware", "2c:cf:67:27:15:bc  Raspberry Pi"),
                fact("system", "Linux  55%"),
                fact("answered", "arp  icmp  ndp"),
                fact("also", "fe80::a3cd:515a:be67:a12a"),
            ],
        },
        Block {
            header: host(5, "192.168.0.238", None),
            children: Vec::new(),
        },
    ];

    assert_eq!(
        listing(&blocks),
        "  1  192.168.0.1  kabelbox.local
     hardware  c8:52:61:c7:05:94  Arris
     roles     router  dns  dhcp
     answered  arp  icmp  ndp
     also      2a02:908:8c1:b880::1
               2a02:908:8c1:b880:ca52:61ff:fec7:594

  2  192.168.0.30  EPSON928262
     hardware  dc:cd:2f:92:82:62  Seiko Epson
     answered  arp  icmp  ndp

  3  192.168.0.101  LGwebOSTV.local
     hardware  28:87:61:53:ef:8e
     answered  arp  icmp

  4  192.168.0.150  RaspberryPi
     hardware  2c:cf:67:27:15:bc  Raspberry Pi
     system    Linux  55%
     answered  arp  icmp  ndp
     also      fe80::a3cd:515a:be67:a12a

  5  192.168.0.238
"
    );
}

/// The same grammar with a port table in it. `ports` is a fact like any other,
/// so its value begins where `hardware`'s does, and its detail is a faint label
/// and a plain value one level in: the block's own shape, recursed.
#[test]
fn a_scan_puts_its_ports_in_the_value_column() {
    let block = Block {
        header: Header {
            verdict: Some(bare().good("2 open")),
            ..host(1, "192.0.2.1", Some("router.example"))
        },
        children: vec![
            fact("hardware", "00:00:5e:00:53:01  Icann, Iana"),
            facts("also", &["2001:db8::1", "fe80::1%en0"]),
            Child::rows(
                "ports",
                vec![
                    Row::plain(port("22/tcp", "open", Some(("ssh", "OpenSSH 9.6")))),
                    Row::with_detail(
                        port("443/tcp", "open", Some(("https", "nginx 1.24"))),
                        vec![
                            Detail::new("tls", "1.3  X25519  alpn h2".to_owned()),
                            Detail::new("cert", "router.example".to_owned())
                                .noted("expires in 12d".to_owned(), Urgency::Caution),
                        ],
                    ),
                    Row::plain(port("5/tcp", "filtered", None)),
                    Row::plain(bare().faint("996 closed ports not listed")),
                ],
            ),
        ],
    };

    assert_eq!(
        drawn(&block),
        "  1  192.0.2.1  router.example   2 open
     hardware  00:00:5e:00:53:01  Icann, Iana
     also      2001:db8::1
               fe80::1%en0
     ports     22/tcp   open      ssh    OpenSSH 9.6
               443/tcp  open      https  nginx 1.24
                 tls   1.3  X25519  alpn h2
                 cert  router.example  expires in 12d
               5/tcp    filtered
               996 closed ports not listed
"
    );
}

/// A tag is placed by what it occupies, not by how long the string carrying it
/// is.
///
/// The two differ by the length of an escape sequence, and that length differs
/// between roles: twenty-four bit green is one character longer than
/// twenty-four bit amber, so padding the *painted* string put a `+` and a `~`
/// one column apart and dragged every identity after them along.
///
/// Deliberately not tested by painting. Whether the escape sequences differ in
/// length depends on `COLORTERM`, which is unset under `cargo test`, so a
/// painted version of this test emits equal-length palette codes and passes
/// whether the bug is there or not. It did. A stated width and a longer string
/// is the same shape and asks the question directly.
#[test]
fn a_tag_is_placed_by_its_width_and_not_by_its_length() {
    // Two marks one column wide, carrying escape sequences of different lengths,
    // which is what a green `+` and an amber `~` are.
    let blocks: Vec<Block> = [
        "\u{1b}[38;2;1;2;3m+\u{1b}[0m",
        "\u{1b}[38;2;100;200;250m~\u{1b}[0m",
    ]
    .into_iter()
    .enumerate()
    .map(|(at, painted)| Block {
        header: Header::numbered(at + 1, "192.0.2.1".to_owned())
            .tagged(Some(painted.to_owned()), 1),
        children: Vec::new(),
    })
    .collect();

    let text = listing(&blocks);
    let columns: Vec<usize> = text
        .lines()
        .filter(|line| line.contains("192.0.2.1"))
        .map(|line| strip_escapes(line).find("192.0.2.1").expect("the identity"))
        .collect();

    assert_eq!(columns.len(), 2, "{text:?}");
    assert_eq!(
        columns[0], columns[1],
        "the length of the mark's paint moved the identity: {text:?}"
    );

    // The gutter, the handle, the gap, the mark, and one space. Not two: a mark
    // is a property of the record rather than a column beside it.
    assert_eq!(columns[0], 2 + 1 + 2 + 1 + 1, "{text:?}");
}

/// Everything a block says about a record lines up under the record, not under
/// the mark on it.
///
/// The mark classifies the whole block, so the block reads as one thing with a
/// mark on it. Labels sharing the mark's column made it read as a mark and a
/// block standing next to each other.
#[test]
fn labels_line_up_under_the_identity_and_not_under_the_mark() {
    let block = Block {
        header: Header::numbered(1, "192.0.2.1".to_owned()).tagged(Some("~".to_owned()), 1),
        children: vec![fact("addresses", "gained 2001:db8::1")],
    };

    let text = drawn(&block);
    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(
        lines[0].find("192.0.2.1"),
        lines[1].find("addresses"),
        "the label does not start under the identity: {text:?}"
    );
    assert!(
        lines[0].find('~').expect("the mark") < lines[1].find("addresses").expect("the label"),
        "the mark is not to the left of everything else: {text:?}"
    );
}

/// A block with nothing under it is one line. No placeholders, which is what
/// keeps a sweep of a mostly empty range from being a wall of near-identical
/// blocks.
#[test]
fn a_block_with_no_children_is_one_line() {
    let block = Block {
        header: Header::numbered(1, "192.0.2.1".to_owned()),
        children: Vec::new(),
    };

    assert_eq!(drawn(&block), "  1  192.0.2.1\n");
}

/// The handle is right-aligned to the width of the largest in the listing, so
/// every identity starts in one column however many records there are. This is
/// what the zero-padding in `[07]` was faking.
#[test]
fn handles_right_align_so_identities_share_a_column() {
    let blocks: Vec<Block> = [1usize, 10]
        .into_iter()
        .map(|at| Block {
            header: Header::numbered(at, "192.0.2.1".to_owned()),
            children: Vec::new(),
        })
        .collect();

    let text = listing(&blocks);
    let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();

    assert_eq!(lines[0], "   1  192.0.2.1");
    assert_eq!(lines[1], "  10  192.0.2.1");

    let column = |line: &str| line.find("192.0.2.1").expect("the identity");
    assert_eq!(column(lines[0]), column(lines[1]));
}

/// What is compared is aligned; what is looked up is not.
///
/// Two latencies are read against each other, so they share a column and their
/// decimal points line up. Two names are not, so padding them to the widest
/// would spend columns to no purpose, and would push the latency off a narrow
/// terminal the moment one host is called something long.
#[test]
fn a_latency_is_aligned_and_a_name_is_not() {
    let blocks = vec![
        Block {
            header: host(1, "192.0.2.1", Some("here")),
            children: Vec::new(),
        },
        Block {
            header: host(2, "192.0.2.200", Some("there")),
            children: Vec::new(),
        },
    ];

    let text = listing(&blocks);
    let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();

    // The decimal points share a column, so the two figures compare on sight.
    assert_eq!(
        lines[0].rfind('.'),
        lines[1].rfind('.'),
        "the decimal points do not line up: {text}"
    );

    // The identities do not, because padding them into a field is what would
    // give the names a column, and that is the first move a table makes.
    assert_ne!(
        lines[0].find("here"),
        lines[1].find("there"),
        "the identities were padded, which gave the names a column: {text}"
    );
}

/// The verdict follows the identities directly, with nothing reserved between.
#[test]
fn a_verdict_follows_the_identities_with_nothing_between() {
    let block = Block {
        header: Header {
            verdict: Some(bare().faint("no reply")),
            ..Header::numbered(1, "192.0.2.1".to_owned())
        },
        children: Vec::new(),
    };

    assert_eq!(drawn(&block), "  1  192.0.2.1   no reply\n");
}

/// Only the first line of a value carries its label. A label repeated down a
/// list is a label that has stopped meaning anything, and the continuation
/// lands in the same column the first line's value did.
#[test]
fn a_continuation_carries_no_label_and_keeps_the_column() {
    let block = Block {
        header: Header::numbered(1, "192.0.2.1".to_owned()),
        children: vec![facts("also", &["2001:db8::1", "fe80::1%en0"])],
    };

    let text = drawn(&block);
    let lines: Vec<&str> = text.lines().collect();

    assert!(lines[1].contains("also"), "{text}");
    assert!(!lines[2].contains("also"), "{text}");
    assert_eq!(
        lines[1].find("2001:db8::1"),
        lines[2].find("fe80::1%en0"),
        "the continuation did not keep the value column: {text}"
    );
}

/// Detail hangs under the row it belongs to, indented past the column that
/// carries the weight in the value above it, so a line with nothing in that
/// column reads as subordinate without a glyph having to say so.
#[test]
fn detail_hangs_inside_the_value_it_belongs_to() {
    let block = Block {
        header: Header::numbered(1, "192.0.2.1".to_owned()),
        children: vec![Child::rows(
            "ports",
            vec![Row::with_detail(
                "443/tcp  open".to_owned(),
                vec![Detail::new("cert", "router.example".to_owned())],
            )],
        )],
    };

    let text = drawn(&block);
    let lines: Vec<&str> = text.lines().collect();

    let columns = Columns::of(std::slice::from_ref(&block));
    let detail = lines[2].find("cert").expect("the detail label");

    assert_eq!(detail, columns.value_column() + DETAIL_INDENT);
    assert!(
        detail > lines[1].find("443/tcp").expect("the port"),
        "the detail is not indented past the row it hangs off: {text}"
    );
}

/// A value that is a note rather than a finding still starts in the value
/// column: it is what this child has to say, not a footnote to it.
#[test]
fn a_note_sits_in_the_value_column_like_any_other_row() {
    let block = Block {
        header: Header::numbered(1, "192.0.2.1".to_owned()),
        children: vec![Child::one(
            "ports",
            bare().faint("24 filtered ports not listed"),
        )],
    };

    assert_eq!(
        drawn(&block),
        "  1  192.0.2.1
     ports  24 filtered ports not listed
"
    );
}

/// Nothing is measured on painted text.
///
/// [`Line`] is told how wide a run is rather than measuring it, because a
/// painted string is longer than it looks, and a column measured from one is a
/// column the terminal does not have. Asserted on the type itself, since a
/// style that paints nothing cannot catch this.
#[test]
fn a_column_is_measured_on_the_text_and_not_on_its_paint() {
    let mut line = Line::new();

    line.push("\x1b[2;38;2;1;2;3mab\x1b[0m", 2);
    line.pad_to(10);
    line.push("cd", 2);

    let finished = line.finish();
    let plain = strip_escapes(&finished);

    assert_eq!(plain, "ab        cd");
    assert!(
        finished.len() > plain.len(),
        "the paint was not carried through: {finished:?}"
    );
}

/// Two values never touch, even where a column was measured from a listing the
/// line does not belong to.
#[test]
fn padding_never_closes_to_nothing() {
    let mut line = Line::new();
    line.push("aaaaaaaa", 8);
    line.pad_to(3);
    line.push("b", 1);

    assert_eq!(line.finish(), "aaaaaaaa b");
}
