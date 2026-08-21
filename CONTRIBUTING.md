# Contributing to Zond

Thanks for wanting to help. This repository is the command-line front end to
[Zond Engine](https://github.com/zond-rs/zond-engine) — the argument grammar,
target resolution, rendering, and the exit status. The scanning itself lives in
the engine.

**Which repository does your change belong in?** If it is about what goes on the
wire — probes, timing, retransmission, fingerprinting, the report — it belongs in
the engine. If it is about what a person typed or what they see, it belongs here.
When in doubt, open an issue and ask; a pull request against the wrong repository
is a lot of work to move.

## Before you start

For anything larger than a bug fix, **open an issue or a discussion first**. Output
format in particular is an interface: `--pipe` is a documented contract that
scripts depend on, and exit codes are read by shell. Agreeing on an approach is
much cheaper than reworking a finished pull request.

## License and the CLA

Zond is licensed under the **GNU Affero General Public License, version 3 or
later**. Two things follow from that, and both matter before you write code.

**Your contribution ships under the AGPL.** If you distribute Zond, or run a
modified version as a network service, your users are entitled to the corresponding
source. See [LICENSE](LICENSE).

**You will be asked to sign a Contributor License Agreement.** On your first pull
request the CLA Assistant bot will post a comment; reply to it with:

```
I have read the CLA Document and I hereby sign the CLA
```

That is the whole process, and you only do it once. The agreements are
[CLA.md](CLA.md) for individuals and [CLA-ENTITY.md](CLA-ENTITY.md) for
organisations.

**Why a CLA?** You keep the copyright in your work. The agreement gives the
maintainer permission to relicense it, which is what makes it possible to offer
Zond commercially to organisations that cannot accept the AGPL, and to fix the
license later if the AGPL turns out to be the wrong choice. In exchange, the CLA
commits the project to always keeping a version available under an OSI-approved
open source license. If you contribute code you wrote for an employer, check that
they are happy for you to do so — clause 5 of the CLA covers this.

## New license headers

Every source file carries this header. New files need it too:

```rust
// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
```

Leave the copyright line as it is — "and Contributors" covers you, and the commit
history is the authoritative record of who wrote what.

## Third-party code

Do not paste in code or data you did not write without saying so. If an algorithm
or a table comes from somewhere else, say where in the pull request and name the
license. Permissively licensed material (MIT, BSD, Apache-2.0, ISC) can generally
be included with its attribution preserved. Code under a copyleft license other
than the AGPL usually cannot be included at all.

## Working on the code

The engine is a sibling path dependency, so a checkout of this repository alone
does not build. Clone both side by side:

```bash
git clone https://github.com/zond-rs/zond-engine.git
```

Then, from this repository:

```bash
cargo test
```

```bash
cargo clippy --all-targets -- -D warnings
```

```bash
cargo fmt --check
```

The test suite scans loopback and the documentation ranges only, so it needs no
network and no privileges.

A few expectations specific to this codebase:

- **Comments explain what a value is for**, not how it came to be that way. Not
  why an alternative was rejected either — that is what the commit message is
  for — and never a restatement of the line below.
- **Tests should earn their place.** A test that restates the implementation is
  worse than no test. Test what can be wrong without being visible: parsing,
  rendering, exit codes, redaction. Do not test help text or documentation.
- **Two streams.** Records go to standard output and commentary to standard
  error, in every presentation. A change that blurs that breaks
  `zond discover lan > hosts.txt`.
- **`--pipe` is append-only.** Fields may be added at the end and never
  reordered or removed; a script reading field 3 today must read field 3 after
  the next release.

## Pull requests

Keep them focused — one concern per pull request. Fill in the template, explain
what you verified and how, and note anything you deliberately left out. If your
change affects what a scan puts on the wire or what it prints, say what you
observed on a real network.

## Reporting security issues

Please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
