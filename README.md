# Zond

[![Crates.io](https://img.shields.io/crates/v/zond-cli.svg)](https://crates.io/crates/zond-cli)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
![Rust Version](https://img.shields.io/badge/rustc-1.93+-blue.svg)

**Zond** is the command-line interface to [Zond Engine](https://github.com/zond-rs/zond-engine),
a network mapping and discovery tool for Linux and macOS.

Two phases, and they are two commands. `zond discover` finds which hosts on a
network are alive; `zond scan` finds which of a host's ports are open.

Three more read back what those left behind. `zond journal` lists the scans this
machine has a record of, and continues one that stopped part way. `zond read`
prints one, from a record or from any file. `zond diff` says what changed
between any two of them, and `zond merge` folds several into one report.

## Installing

```bash
cargo install zond-cli
```

The crate is `zond-cli`; the command it installs is `zond`.

To build from a checkout instead:

```bash
cargo install --path .
```

The engine comes from crates.io like any other dependency, so a checkout of this
repository alone builds.

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
quietly skipped. A scan that covers less than its input said it covers is a
wrong answer that looks like a right one.

### What gets refused before the scan starts

A single run will not sweep more than about a million IPv4 addresses, which is a
`/12`. That is a guard against a mistyped prefix, not a policy about how much
anyone may scan: `/8` is sixteen million probes and hours of waiting, and almost
nobody who types it meant to ask for that.

IPv6 is *not* capped by that rule. A `/64` is eighteen quintillion addresses,
but with root on the local segment it is one all-nodes echo rather than a walk.
So the engine decides per range whether a strategy exists that can cover it, and
records the gap when none does. Such a run exits `3` rather than running until
you kill it.

## Scanning ports

```
$ sudo zond scan 192.0.2.1 -p 22,80,443
• scanning 3 probes across 1 host (192.0.2.1)

  1  192.0.2.1  router.example  1.42 ms   2 open
     hardware  00:00:5e:00:53:01  Icann, Iana Department
     answered  ARP  TCP_SYN
     ports     22/tcp   open  ssh OpenSSH 9.6
               443/tcp  open  https nginx 1.24
               [1 closed port omitted]

• 1 host up of 1 address in 0.12s
• 2 open ports of 3 probed
```

`s` is the short form. `-p` takes `22,80,443`, `1-1024`, or `u:53` for UDP, and
a target may carry its own: `zond s 10.0.0.1:8080 lan -p 80,443` gives `.1` port
8080 and everything else 80 and 443.

Without `-p` it uses `default_ports` from the settings file, and when that says
nothing either, the thousand TCP ports most likely to be listening. That is a
deliberate choice over `1-1024`. Most of what a machine listens on today is
above that range, and much of what is inside it belongs to protocols nobody has
deployed this century.

**A scan checks each target is there before it probes its ports.** The same
probes `zond discover` sends, against the addresses you named and no others: ARP
on the local segment, ICMP and TCP off it. An address that answers nothing is
reported and skipped, because otherwise it costs one probe per port to learn
what a handful established.

```
$ zond scan 192.0.2.1 -p 1-1024

• 0 hosts up of 1 address in 1.5s
! 1 address answered no liveness probe and was not port-scanned. Pass --assume-up to probe it anyway.
```

That run takes 1.5 seconds. `--assume-up` skips the check and scans on trust,
which takes 32 and prints a thousand lines of `filtered`. Use it when the check
is what is wrong: a host behind a firewall that drops ICMP and has nothing on
the ports discovery tries is up, and says nothing to a knock.

The check costs nothing measurable on a host that *is* up. It answers
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
raw sockets need root. Without it the scan still runs, falling back to ordinary
TCP connect attempts against a few common ports, but it finds fewer hosts, and
the hosts it misses look exactly like hosts that are not there. Zond says which
of the two ran rather than leaving you to guess.

## Measuring the route to a host

`--traceroute` records the routers between you and each host that answered.

```
$ sudo zond s 198.51.100.9 -p 443 --traceroute

  1  198.51.100.9  14.20 ms   1 open
     answered  TCP_SYN
     path      1  192.168.0.1   0.40ms
               2  *
               3  198.51.100.1  12.80ms
     ports     443/tcp  open  https nginx 1.24
```

**A router is made to name itself by giving it something to throw away.** One
forwarding a packet need not say so; one whose hop limit reached zero is required
to. So a probe built to expire a chosen number of hops out makes exactly that
router announce itself.

**The probe matches the scan**, which is why this belongs on `zond scan` more
than on `zond discover`. A host with an open TCP port is traced with SYNs to that
port and everything else with pings, and a SYN to :443 crosses filters that
discard every ping, so a trace run before the ports were known would stop at the
first firewall. It works under `discover` too; it just has less to work with.

A `*` is a router that would not identify itself, shown at its own distance
rather than left out, because dropping it would renumber every hop past it. A
hop marked `inferred` was taken from another host's trace through the same
router: scanning a whole network measures the shared part of the path once, and
says where it did.

Only hosts that answered are traced. A path is measured backwards from its far
end, and the far end's distance is read out of a reply it sent, so there is
nothing to measure from otherwise. Needs root, and says so rather than reporting
an empty path.

Paths reach the JSON export as `path` on each host, and the nmap-XML export as
`<trace>` and `<distance>`, so anything that already draws topology from nmap
XML draws this too. They are **not** in `--pipe` output: that format is one
fixed-width record per host and a path is a variable-length list, which is also
why nmap's own grepable output has no traces in it.

## Keeping out of somewhere

`--exclude` names addresses the run may not touch, in the same grammar targets
are written in. Repeat it, or write a comma-separated list.

```bash
sudo zond d 10.0.0.0/16 --exclude 10.0.5.0/24,10.0.9.7
```

```
discovering 65279 addresses (10.0.0.0/16)
excluding 10.0.5.0-10.0.5.255, 10.0.9.7 (257 addresses withheld)
```

The ranges are printed so you can check them against the scope document you
copied them from, and the count is what tells you they actually met the targets.
An exclusion with a typo in it withholds nothing and says so.

Nothing is addressed to an excluded host and nothing about one is reported, *including
a neighbour a segment sweep would otherwise learn about from an ARP reply or this
host's neighbour table.* That second half is why this is a guarantee rather than a
filter on the target list: a sweep does not confine itself to the addresses it was
given.

**What it cannot promise is that an excluded machine never receives a packet.** An
ARP request goes to the broadcast address and the IPv6 all-nodes echo to `ff02::1`,
and every machine on the link sees them. The reply is dropped and nothing is
recorded, but the probe was sent. If that distinction matters, do not sweep the
segment that machine is on.

Excluding every address you named is a usage error rather than a scan of nothing,
because the usual cause is a typo in the exclusion and a run that found no hosts
looks exactly like a network with nothing on it.

A standing policy belongs in the settings file instead:

```toml
[defaults]
exclude = ["10.0.5.0/24", "192.168.1.10-20"]
```

`exclude` is the one key in that file that **accumulates** across layers rather
than being overridden. A range in `/etc/zond/engine.toml` stays excluded when
your own file names another, and both stay excluded when `--exclude` adds a
third. Every other setting is replaced by the layer above it; this one cannot be,
because a layer that could cancel an exclusion is a layer that can put a
forbidden range back into a scan. The file takes addresses, ranges and CIDR
blocks only: `lan` and hostnames mean something different on every machine that
reads it, so they belong on the command line where they are resolved at the
moment they are used.

### `lan` is not the same as the range it expands to

`lan` names a *network*, and sweeping a network sends the ICMPv6 all-nodes echo
and takes leads from this host's neighbour table. That is how an IPv6 device with
no address in the IPv4 range gets found at all. Writing the range out by hand asks
a narrower question and gets a narrower answer, which is the right behaviour for
`zond d 192.168.0.7`, where waking the target's neighbours would answer a question
nobody asked.

## Output

```
$ sudo zond d 192.0.2.0/26
• recording this run as 06G3JC56RSVTRBTR
• discovering 64 addresses (192.0.2.0/26)

  1  192.0.2.1  router.example     1.42 ms
     hardware  00:00:5e:00:53:01  Icann, Iana Department
     answered  ARP  NDP
     also      2001:db8::1
               fe80::1%en0

  2  192.0.2.30  printer.example  12.10 ms
     hardware  00:00:5e:00:53:02  Icann, Iana Department
     system    Linux [84%]
     answered  ARP

  3  2001:db8::4                       8.20 ms
     hardware  02:00:5e:00:53:04
     answered  NDP

• 3 hosts up of 64 addresses in 1.42s
```

**A block is a device, not an address.** The address that opens it names the
machine, with its hostname beside it, and `also` is where its other addresses
are, one per line. A dual-stack machine answering at three addresses is one
block.

**What is compared is aligned; what is looked up is not.** Two latencies are
read against each other, so they share a column and their decimal points line
up. Two hostnames are not, so padding them to the widest would spend columns to
no purpose and push the latency off a narrow terminal the moment one host is
called something long.

**The header carries the fastest round trip.** What the round trips did *apart*
from the fastest is a different fact, and a host whose fastest reply is 8 ms and
whose slowest is 1.2 s is not 8 ms away. That waits for `-v`, because most hosts
have nothing to say about it. `--pipe` carries all four figures always.

**A missing line was not learned.** There are no placeholders, because a
placeholder is a line you have to read to discover it says nothing. A host that
is anything other than simply up says so on its header line, so an address
something is filtering stands out instead of being one block among two hundred.

A block pays only for what it has, and nothing is padded to the width of the
best-known host in the sweep. The cost is length: a `/24` with two hundred live
hosts is long, and that is what `--pipe` is for.

**Standard output carries the records. Standard error carries everything else**:
the header, the live progress, the warnings and the summary. So

```bash
sudo zond discover lan > hosts.txt
```

leaves a file with nothing in it but hosts, and you still watch the sweep happen.
`-q` drops the commentary as well, leaving the records alone.

### Piping

`--pipe` (or `--presentation pipe`) writes every field a sweep established, one
host per line, separated by single tabs:

```bash
sudo zond --pipe d lan | awk -F'\t' '$3 > 100 {print $1, $3}'
```

```
192.0.2.1	Up	1.420	arp,ndp	00:00:5e:00:53:01	router.example	-	Icann, Iana Department	1.100	1.510	2.030	-	-	router,dns
```

Fourteen fields, in this order, on every line:

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
| 14 | `ROLES` | what the host does, comma-joined: `router`, `dns`, `dhcp`, `ntp`, … |

Fields are separated by a single tab, which cannot occur inside any of these
values, so `cut -f4` and `awk -F'\t'` need no quoting rules. A field the scan
did not learn is `-`, never empty, so the count never changes. There is no
heading line, and fields are only ever *appended* to.

`EVIDENCE` is worth reading: `arp` and `ndp` are conclusive and only possible
with raw sockets, where `tcp_syn` alone is what an unprivileged sweep is limited
to.

## Keeping a record

Every scan is recorded, without being asked. The moment you want to continue one
is *after* it was cut short, and a flag you would have had to pass beforehand is
a flag you did not pass.

```
$ zond journal
 #  ID                STATE       DONE   AGE  SCOPE
 1  06G3JC56RSVTRBTR  resumable    41%    4m  192.168.0.0/24 on 1000 ports
 2  06G3HZ0PQK4M8XTF  complete    100%    2h  192.168.0.0/24
```

```bash
zond scan --resume 06G3JC          # continue it; a prefix is enough
zond read latest                   # print what it found, as the run printed it
zond read latest -o out.json
zond journal show 06G3JC           # where it is, how far it got, what holds it
zond journal prune --older-than 30d
```

An address that answered, or that was asked as many times as it was going to be,
is not asked again. The plan comes from the record, so a resume takes the id and
nothing else. Targets named anyway are checked against it and refused if they
describe a different scan, because a position counted against one plan means
nothing against another.

A record holds the addresses you scanned and what answered, under your own home
and readable only by you. `--no-journal` declines for one run and
`journal = false` in `cli.toml` for all of them. The newest hundred are kept;
`journal_entry_limit` moves that number, and `"unlimited"` lifts it.

## Comparing two scans

```bash
zond diff latest 06G3HZ0PQK4M8XTF     two records on this machine
zond diff baseline.json latest        an archived report against tonight's scan
zond diff q1.xml q2.xml               two nmap files, neither written by zond
```

A side that names a file on disk is read as one, taking this engine's JSON or
nmap's XML from its extension. Anything else is taken for a record id. That last
example is the one worth pointing at: a comparison takes reports and asks nothing
about where they came from, so a team with a year of nmap output in an engagement
repository can use this against files this engine never wrote.

```
$ zond diff latest 06G3HZ0PQK4M8XTF
• comparing latest (4m) with 06G3HZ0PQK4M8XTF (2h)

  1  + 192.168.0.77
     now    up, 1 port open
     ports  22/tcp opened

  2  ~ 192.168.0.1  kabelbox.local
     ports  443/tcp  certificate rotated, a1b2c3d4e5f6…

• 1 host appeared, 1 host changed, 1 port opened
```

**Only a change the other scan is known to have looked for counts.** A scan of
new ground turns up hosts nobody had checked before, and those are reported
without being treated as findings about the network. It is the difference
between a monitor somebody trusts and one they learn to ignore, and it is what
decides the exit status: `0` for no change, `4` for changes, so a nightly job is
`zond diff last tonight || notify`.

`--identity hardware` follows a machine across a DHCP lease, which is what a
segment with phones on it wants; the default follows one by any address it
shares. `-o changes.json` and `-o changes.html` write the comparison to a file
instead of the terminal.

## Folding several scans into one

```bash
zond merge chunk*.json           a range scanned in pieces, put back together
zond merge q1.xml q2.xml q3.xml  a quarter of nmap files, neither written by zond
zond merge baseline.json latest  an archived report and tonight's scan
```

Sources are named the way either side of a comparison is: a file on disk is read
as one, and anything else is taken for a record id. Give as many as you have.

**A merge answers what is out there, given everything you know.** Sources are
folded oldest to newest, and where a newer one states something it wins. Where it
says nothing the older answer stands, because absence is not a claim: a host
missing from tonight's scan is not evidence the host went away, and a port not
listed is not evidence it closed. For what *changed* rather than what is there,
use `zond diff`.

```
$ zond merge q1.xml baseline.json latest
• folding 3 sources into one report, oldest first
•   q1.xml         176d  nmap 7.94, 41 hosts
•   baseline.json  8d    zond-engine 0.12.1, 52 hosts
•   latest         4m    zond-engine 0.13.0, 38 hosts

  1  192.168.0.1  kabelbox.local  2 open
     ports  443/tcp  open  https
            22/tcp   open  ssh

• 61 hosts up of 65534 addresses, drawn from 176d of scanning
```

**A merged report reports the span it draws on, not a duration.** A scan says how
long it took; a fold is not one job, and adding up what its sources spent would
describe a scan that never ran. The span is the number that matters here anyway,
because it says how much drift is baked into a single answer assembled out of
several moments — a report drawing on 176 days is not a picture of one evening.

The order they are given in does not matter: a fold is ordered by each document's
own clock. What does matter is that they all go into one command. Merging in
rounds folds each new source against a report already carrying an older source's
clock, so a verdict the new one should have overturned survives it — `zond merge
a b c` is not the same as merging `a` and `b` and then folding in `c`.

What comes back is an ordinary report, so every `-o` format a scan writes works
here too, and a merged report is a legal input to the next merge and to
`zond diff`. Naming a file replaces the terminal rather than adding to it: nobody
is watching a merge happen the way they watch a scan.

`--identity hardware` folds a machine across a DHCP lease, the same way it
follows one in a comparison.

## Why a port is in the state it is

```bash
zond scan 192.168.0.0/24 --reason
```

A verdict you cannot check is a verdict you have to take on trust. `--reason`
shows the packet behind every one:

```
  1  192.168.0.1  kabelbox.local  2 open
     answered  ARP  an address resolution reply
               ICMP_unreachable  unreachable for a probed port, via 192.168.0.254
     ports     22/tcp   open      ssh OpenSSH 9.6
                 reason  SYN/ACK  2.24 ms
               443/tcp  filtered
                 reason  ICMP prohibited
               8080/tcp filtered
                 reason  no reply
```

**The two `filtered` ports are different findings.** One was dropped by a
firewall that said so; the other answered nothing at all — and an absence is
only as good as the scan that waited for it. The word is the same and the
evidence is not.

The host lines say the same thing one level up. An ICMP error the host sent for
itself proves the host is there; the same error `via` a router proves only that
something in the path speaks for that address, which is not the same claim.

It works on a scan, on a record, and on any file — including one nmap wrote,
whose own reasons are read back. `reason = true` in `cli.toml` turns it on for
good. Not on `--pipe`, whose fields are a stable interface; a program reads the
JSON, which carries all of it unconditionally.

## Detections, including your own

After a service is named, the detection corpus probes it further for what is
wrong with it. `zond detections` lists what a scan would run:

```bash
zond detections
```

The corpus is not fixed. A detection is a TOML document, and `--detections`
takes a file or a directory of them:

```bash
zond detections --detections ./checks          # compile them, and say what they are
zond scan 10.0.0.0/24 --detections ./checks    # and run them
```

`[[step]]` makes a detection a flow: a bounded sequence of probes and matches
ending in a finding, carrying no code. `[compute]` makes it a sandboxed module,
which reaches the network only through the verbs its class is granted, and whose
code may sit in a sibling file. The engine's README has the format, and
`--only-named-detections` leaves the built-in corpus out while you are getting
one right.

What a detection may do is not its own decision. Each declares a class, and
`--detection` is the ceiling an operator permits:

```bash
zond scan 10.0.0.0/24 --detection passive       # read only what the scan gathered
zond scan 10.0.0.0/24 --detection exploit       # prove it rather than infer it
```

The default stops at `active-benign`, so a detection that mutates, exploits or
degrades a target is listed by `zond detections` and does not run until somebody
raises the ceiling.

### Giving them to somebody else

Detections you wrote are yours to run. Somebody else's arrive signed, and the
only way to load one is to name the key you trust:

```bash
zond detections keygen ~/.zond/acme
zond detections sign ./checks --out ./acme-1 --key ~/.zond/acme --name acme-security
```

That writes a bundle: one self-contained document per detection, a manifest
naming each and the hash of its source, and a signature over the manifest. The
recipient points a scan at it and says whose it is:

```bash
zond scan 10.0.0.0/24 --detections-bundle ./acme-1 --trust-key acme.pub
```

The key has to reach them by some other route than the bundle. A signature names
the key that made it, and a checker that trusted that one would accept anything
anybody re-signed. Because the signature covers the manifest, it covers the
membership as well as the bytes: an attacker serving the files can neither alter
a detection nor drop the one that would have found them.

## Reading a scan back

```bash
zond read latest              # what the last scan found, as the run printed it
zond read merged.json         # a folded report, and the documents it came from
zond read theirs.xml          # an nmap file, drawn the way this tool draws one
zond read q1.xml -o q1.json   # convert, since the writers are already there
```

The same rule as everywhere else: a name that is a file on disk is read as one,
and anything else is a record id. Nothing is probed. A scan still being recorded
prints what it has committed so far, which is a little behind what it has found.

A report another scanner produced says so, so a file a colleague sent you is
never mistaken for one of your own scans:

```
$ zond read theirs.xml
• reading theirs.xml, a scan by nmap 7.94 from 2026-08-17T20:53:20Z
```

Reading a merged report back is the only way to see what went into it:

```
$ zond read merged.json
• reading merged.json, folded from 3 sources
•   q1.xml         176d  nmap 7.94
•   baseline.json  8d    zond-engine 0.12.1
•   latest         4m    zond-engine 0.13.0
```

Those names are written into the report by `zond merge` and survive being
exported and folded again. What does not survive is what each source held on its
own — a fold puts every document's hosts into one set — so the counts the merge
itself printed are not there to read back.

As everywhere, naming a file replaces the terminal rather than adding to it.

## Scan settings

Every flag below is also a key in `engine.toml`, and layers the same way:
built-in defaults, then `/etc/zond/engine.toml`, then your file, then the flag.
**An absent flag says nothing.** It cannot cancel a setting you wrote.

| Flag | |
|---|---|
| `-n`, `--no-dns` | Send no DNS traffic. A hostname target is refused rather than dropped. |
| `--redact` | Mask hostnames, hardware addresses and IPv6 host parts in the output. |
| `--effort <LEVEL>` | `single`, `fast`, `balanced`, `thorough`: how hard the scan tries before accepting silence. |
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

`--redact` covers hostnames, hardware addresses **and IPv6 host parts**. A
link-local address derives its host part from the hardware address, so masking
the MAC while printing the address in full would hand the MAC straight back.

## Settings

Two files, in one directory:

| | |
|---|---|
| `~/.config/zond/cli.toml` | how a run is shown |
| `~/.config/zond/engine.toml` | what a scan puts on the wire |

Both are created on the first run that can write them, from templates compiled
into the binary: no network, no build step, nothing to download. Every key in
both is commented out, so the files appearing changes nothing about the run that
created them. An existing file is never overwritten, never reformatted, and never
extended.

They layer: built-in defaults, then `/etc/zond/*.toml`, then the files above,
then command-line flags. A layer speaks only about the keys it mentions, so a
flag you did not pass cannot cancel a setting you did write.

`--profile <NAME>` selects a named profile from `engine.toml`.

Because discovery wants root, the first run is usually `sudo zond discover lan`,
so anything created under `sudo` is handed to the user who invoked it rather than
left `root`-owned in a directory you are meant to edit.

### Presentation

`cli.toml` sets how a run is drawn, and `--presentation <MODE>` overrides it for
one invocation.

| Mode | |
|---|---|
| `pipe` | Tab-separated records for a program. `--pipe` is shorthand. |
| `minimal` | A tagged block per host, in abbreviated tags and no colour. The terse reading mode. |
| `fancy` | A numbered block per host: colour, aligned columns, and the TLS session and certificate hanging under the port that served them. **The default.** `scan`, `discover`, `diff` and `journal` all draw in it. |

`pipe` is not a step on that ladder, it is a different audience: `minimal` is a
listing and `pipe` is a record format, and both show everything.

Whatever the mode, records go to standard output and commentary to standard
error.

`--colour <auto|always|never>` decides whether that output is painted, and the
`colour` key in `cli.toml` sets it for every run. `auto` colours a terminal and
leaves a redirected stream alone, reading `NO_COLOR`, `CLICOLOR_FORCE` and
`TERM` the way other tools do; the two streams are asked separately, so
`zond discover lan | less` sends the records out plain and keeps the commentary
coloured. Colour never carries a fact by itself: every state a colour marks is
also a word, and every mark opening a line of commentary differs in shape as
well as in hue, so a run captured to a file loses nothing but the paint.

## Exit status

| Code | Meaning |
|---|---|
| 0 | The run finished and covered everything it was asked to. |
| 1 | The run could not be carried out. |
| 2 | What was asked for was not usable: a bad flag, a target that is not a target, or a settings file this program cannot act on. |
| 3 | The run finished, but something it was asked to cover was not covered. |
| 4 | A comparison found changes. `zond diff` only. |
| 130 | Interrupted with `Ctrl-C`. |

Finding nothing is not a failure. A sweep of an empty range exits `0`, because
"nothing is there" is an answer.

Code `3` is the one worth knowing about. A scan whose raw scanner would not
start, or whose range no strategy could walk, still returns every host it did
find, because the engine records the gap rather than abandoning the run. The
result is narrower than what was asked for and dangerous to read as though it
were not. A script that does not care writes `zond discover lan || true`.

Code `4` is `diff`'s alone, and follows the convention `diff(1)` set. It is off
`1` because `1` here already means the run could not be carried out, and a
monitor that could not tell "the network changed" from "the scan failed" would
be worse than no monitor.

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
