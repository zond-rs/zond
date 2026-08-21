# Zond

[![Crates.io](https://img.shields.io/crates/v/zond-cli.svg)](https://crates.io/crates/zond-cli)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![Rust Version](https://img.shields.io/badge/rustc-1.93+-blue.svg)

**Zond** is the command-line interface to [Zond Engine](https://github.com/zond-rs/zond-engine),
a network mapping and discovery tool for Linux and macOS.

Two phases, and they are two commands. `zond discover` finds which hosts on a
network are alive; `zond scan` finds which of a host's ports are open.

## Installing

```bash
cargo install zond-cli
```

The crate is `zond-cli`; the command it installs is `zond`.

To build from a checkout instead, note that the engine is a sibling path
dependency while the two repositories move together, so `../zond-engine` has to
be present:

```bash
cargo install --path .
```

## Using it

```bash
sudo zond discover 192.168.0.0/24
```

`d` is the short form, and every example below works with either spelling.

| Written | Means |
|---|---|
| `sudo zond d 192.0.2.1` | one address |
| `sudo zond d 192.0.2.1-50` | a range; the end continues the start's octets |
| `sudo zond d 192.168.0.0/24` | a CIDR block |
| `sudo zond d 2001:db8::1` | one IPv6 address |
| `sudo zond d 2001:db8::/120` | an IPv6 prefix |
| `sudo zond d fe80::1%en0` | a link-local address, on a named interface |
| `sudo zond d one.one.one.one` | a hostname, resolved before the scan |
| `sudo zond d lan` | this host's own segment |

Several targets may be given at once, and each may itself be a comma-separated
list: `sudo zond d lan,10.0.0.0/24`. A hostname becomes every address it resolves
to, so `zond d one.one.one.one` sweeps all four of Cloudflare's.

`--no-dns` (`-n`) stops the scan generating any DNS traffic. Resolving a target
name *is* DNS traffic, so under `-n` a hostname target is refused rather than
quietly skipped — a scan that covers less than its input said it covers is a
wrong answer that looks like a right one.

### What gets refused before the scan starts

A single run will not sweep more than about a million IPv4 addresses — a `/12`.
That is a guard against a mistyped prefix, not a policy about how much anyone may
scan; `/8` is sixteen million probes and hours of waiting, and almost nobody who
types it meant to ask for that.

IPv6 is *not* capped by that rule. A `/64` is eighteen quintillion addresses,
but with root on the local segment it is one all-nodes echo rather than a walk —
so the engine decides per range whether a strategy exists that can cover it, and
records the gap when none does. Such a run exits `3` rather than running until
you kill it.

## Scanning ports

```
$ sudo zond scan 192.0.2.1 -p 22,80,443
scanning 3 probes across 1 host (192.0.2.1)

* 192.0.2.1 [router.example]
  mac:  00:00:5e:00:53:01 (Icann, Iana Department)
  rtt:  1.42ms
  via:  arp, tcp_syn
  port: 22/tcp open (ssh OpenSSH 9.6)
        443/tcp open (https nginx 1.24)
        [1 closed port omitted]
```

`s` is the short form. `-p` takes `22,80,443`, `1-1024`, or `u:53` for UDP, and
a target may carry its own — `zond s 10.0.0.1:8080 lan -p 80,443` gives `.1` port
8080 and everything else 80 and 443. Without `-p` it uses `default_ports` from
the settings file, and the well-known range when that says nothing either.

**A scan checks each target is there before it probes its ports.** The same
probes `zond discover` sends, against the addresses you named and no others —
ARP on the local segment, ICMP and TCP off it. An address that answers nothing
is reported and skipped, because otherwise it costs one probe per port to learn
what a handful established.

```
$ zond scan 192.0.2.1 -p 1-1024

0 hosts up of 1 address in 1.5s
note: 1 address answered no liveness probe and was not port-scanned. Pass --assume-up to probe it anyway.
```

That run takes 1.5 seconds. `--assume-up` skips the check and scans on trust,
which takes 32 and prints a thousand lines of `filtered`. Use it when the check
is what is wrong: a host behind a firewall that drops ICMP and has nothing on
the ports discovery tries is up, and says nothing to a knock.

The check costs nothing measurable on a host that *is* up — it answers
immediately, and the round-trip time and hostname it establishes are ones the
scan wanted anyway.

**It is not a sweep.** Scanning one host does not wake its neighbours: the
liveness phase probes the addresses you named and nothing else. `lan` is what
asks about a network.

Closed ports are counted rather than listed.

`--tcp-technique` chooses which segment a probe carries. Only `syn` identifies an
open port positively and only `syn` has an unprivileged fallback; the rest need
root and are refused without it rather than quietly substituted.

### Why `sudo`

Discovery uses ARP and ICMPv6 on the local segment and raw TCP elsewhere, and
raw sockets need root. Without it the scan still runs — it falls back to ordinary
TCP connect attempts against a few common ports — but it finds fewer hosts, and
the hosts it misses look exactly like hosts that are not there. Zond says which
of the two ran rather than leaving you to guess.

### `lan` is not the same as the range it expands to

`lan` names a *network*, and sweeping a network sends the ICMPv6 all-nodes echo
and takes leads from this host's neighbour table. That is how an IPv6 device with
no address in the IPv4 range gets found at all. Writing the range out by hand asks
a narrower question and gets a narrower answer — which is the right behaviour for
`zond d 192.168.0.7`, where waking the target's neighbours would answer a question
nobody asked.

## Output

```
$ sudo zond d 192.0.2.0/26
discovering 64 addresses (192.0.2.0/26)
found 192.0.2.1 +1
found 192.0.2.30

* 192.0.2.1 [router.example]
  mac:  00:00:5e:00:53:01 (Icann, Iana Department)
  rtt:  min 1.10ms  avg 1.51ms  max 2.03ms
  via:  arp, ndp
  also: 2001:db8::1
        fe80::1%eth0

* 192.0.2.30 [printer.example]
  mac:  00:00:5e:00:53:02 (Icann, Iana Department)
  os:   Linux [84%]
  rtt:  12.1ms
  via:  arp

* 2001:db8::4
  mac:  02:00:5e:00:53:04
  rtt:  8.20ms
  via:  ndp

3 hosts up of 64 addresses in 1.42s
```

**A block is a device, not an address.** The address that opens it names the
machine, with its hostname beside it; `also:` is where its other addresses are,
one per line. A dual-stack machine answering at three addresses is one block.

**`rtt` shows the spread when there is one.** A host probed several ways gets
`min / avg / max`; one that answered once gets a single figure, because a spread
nobody measured is not worth three columns of the same number. `--pipe` also
carries the median, for a consumer that wants one robust figure.

**A missing line was not learned.** There are no placeholders, because a
placeholder is a line you have to read to discover it says nothing. The one line
that means something by its absence is `status`, which appears only when a host
is *not* simply up — so an address something is filtering stands out instead of
being one row among two hundred.

Every tag is short enough that the values line up under one column, so an eye
can run down them. A block pays only for what it has — nothing is padded to the
width of the best-known host in the sweep. The cost is length: a `/24` with two
hundred live hosts is long, and that is what `--pipe` is for.

**Standard output carries the records. Standard error carries everything else** —
the header, the live progress, the warnings and the summary. So

```bash
sudo zond discover lan > hosts.txt
```

leaves a file with nothing in it but hosts, and you still watch the sweep happen.
`-q` drops the heading row too.

### Piping

`--pipe` (or `--presentation pipe`) writes every field a sweep established, one
host per line, separated by single tabs:

```bash
sudo zond --pipe d lan | awk -F'\t' '$3 > 100 {print $1, $3}'
```

```
192.0.2.1	Up	1.420	arp,ndp	00:00:5e:00:53:01	router.example	-	Icann, Iana Department	1.100	1.510	2.030	-	-
```

Thirteen fields, in this order, on every line:

| | Field | |
|---|---|---|
| 1 | `ADDRESS` | every address the host answers at, comma-joined, primary first |
| 2 | `STATUS` | `Up`, `Down`, `Filtered`, `Unknown` |
| 3 | `RTT` | median round trip **in milliseconds**, no unit |
| 4 | `EVIDENCE` | what proved it alive: `arp`, `ndp`, `icmp_echo`, `tcp_syn`, … |
| 5 | `MAC` | hardware addresses, comma-joined, most recent first |
| 6 | `HOSTNAME` | |
| 7 | `OS` | passive fingerprint, `name generation [accuracy%]` |
| 8 | `VENDOR` | |
| 9 | `RTT_MIN` | fastest round trip, milliseconds |
| 10 | `RTT_AVG` | mean round trip, milliseconds |
| 11 | `RTT_MAX` | slowest round trip, milliseconds |
| 12 | `PORTS` | `number/proto/state/service`, comma-joined; closed ones left out |
| 13 | `CLOSED` | how many came back plainly closed; `-` when none were probed |

Fields are separated by a single tab, which cannot occur inside any of these
values — so `cut -f4` and `awk -F'\t'` need no quoting rules. A field the scan
did not learn is `-`, never empty, so the count never changes. There is no
heading line, and fields are only ever *appended* to.

`EVIDENCE` is worth reading: `arp` and `ndp` are conclusive and only possible
with raw sockets, where `tcp_syn` alone is what an unprivileged sweep is limited
to.

## Scan settings

Every flag below is also a key in `engine.toml`, and layers the same way:
built-in defaults, then `/etc/zond/engine.toml`, then your file, then the flag.
**An absent flag says nothing** — it cannot cancel a setting you wrote.

| Flag | |
|---|---|
| `-n`, `--no-dns` | Send no DNS traffic. A hostname target is refused rather than dropped. |
| `--redact` | Mask hostnames, hardware addresses and IPv6 host parts in the output. |
| `--effort <LEVEL>` | `single`, `fast`, `balanced`, `thorough` — how hard the scan tries before accepting silence. |
| `--max-attempts <N>` | Replace the attempt budget outright. `1` disables retransmission. |
| `--timeout-scale <F>` | Multiply how long the scan waits. Never below what a protocol costs. |
| `--no-dampen` | Spend the full budget on hosts that answer nothing. Thorough and expensive. |
| `--max-probe-rate <PPS>` | Cap the probe rate. A coverage control before a politeness one. |
| `--send-mode <MODE>` | `auto`, `raw_socket`, `ethernet`. |
| `--os-detection <LEVEL>` | `off`, `passive`, `active`, `aggressive`. `passive` sends nothing of its own. |
| `--profile <NAME>` | Use a named profile from `engine.toml`. |
| `--tcp-technique <T>` | `syn`, `fin`, `null`, `xmas`, `maimon`, `ack`. `zond scan` only. |
| `--assume-up` | Skip the liveness check and scan every target on trust. `zond scan` only. |

Values are parsed by the engine, so a wrong one is answered with the names that
would have worked:

```
$ zond d --effort quick lan
error: invalid value 'quick' for '--effort <LEVEL>': unknown scan effort 'quick',
expected one of: single, fast, balanced, thorough
```

`--redact` covers hostnames, hardware addresses **and IPv6 host parts** — a
link-local address derives its host part from the hardware address, so masking
the MAC while printing the address in full would hand the MAC straight back.

## Settings

Two files, in one directory:

| | |
|---|---|
| `~/.config/zond/cli.toml` | how a run is shown |
| `~/.config/zond/engine.toml` | what a scan puts on the wire |

Both are created on the first run that can write them, from templates compiled
into the binary — no network, no build step, nothing to download. Every key in
both is commented out, so the files appearing changes nothing about the run that
created them. An existing file is never overwritten, never reformatted, and never
extended.

They layer: built-in defaults, then `/etc/zond/*.toml`, then the files above,
then command-line flags. A layer speaks only about the keys it mentions, so a
flag you did not pass cannot cancel a setting you did write.

`--profile <NAME>` selects a named profile from `engine.toml`.

Because discovery wants root, the first run is usually `sudo zond discover lan` —
so anything created under `sudo` is handed to the user who invoked it, rather than
left `root`-owned in a directory you are meant to edit.

### Presentation

`cli.toml` sets how a run is drawn, and `--presentation <MODE>` overrides it for
one invocation.

| Mode | |
|---|---|
| `pipe` | Tab-separated records for a program. **Built.** `--pipe` is shorthand. |
| `minimal` | A tagged block per host, for reading. **Built, and the default.** |
| `standard` | Not built yet. More of what a scan found, still without colour. Intended to become the default. |
| `fancy` | Not built yet. Colour and decoration. |

`pipe` is not a step on that ladder, it is a different audience: `minimal` is a
listing and `pipe` is a record format, and both show everything.

Naming a mode that is not built is refused rather than quietly served as
something else. Whatever the mode, records go to standard output and commentary
to standard error.

## Exit status

| Code | Meaning |
|---|---|
| 0 | The run finished and covered everything it was asked to. |
| 1 | The run could not be carried out. |
| 2 | What was asked for was not usable — a bad flag, a target that is not a target, or a settings file this program cannot act on. |
| 3 | The run finished, but something it was asked to cover was not covered. |
| 130 | Interrupted with `Ctrl-C`. |

Finding nothing is not a failure — a sweep of an empty range exits `0`, because
"nothing is there" is an answer.

Code `3` is the one worth knowing about. A scan whose raw scanner would not
start, or whose range no strategy could walk, still returns every host it did
find — the engine records the gap rather than abandoning the run. The result is
narrower than what was asked for and dangerous to read as though it were not. A
script that does not care writes `zond discover lan || true`.

`q` or `Ctrl-C` asks the scan to stop and waits for it, so the hosts already
found are still reported. Either again leaves immediately, giving up the probes
still in flight. Reading a keypress needs a terminal, so in a pipe or a script
`Ctrl-C` is the one that works.

## Building on it

The scanning, the domain model, the report and the file formats all live in
[`zond-engine`](https://github.com/zond-rs/zond-engine), which is a library
anybody can use. This repository is one front end to it, and holds only what a
front end is for: the argument grammar, target resolution, rendering, and the
exit status.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

If you distribute this, or run a modified version as a network service, your users
are entitled to the corresponding source.
