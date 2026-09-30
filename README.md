# zond

A network scanner. It finds the hosts on a network, the ports they have open
and what is listening on them, and then tells you which of those have known
vulnerabilities, judged against the fixes the distribution actually shipped
rather than the version number alone.

```
$ zond scan scanme.nmap.org -p 22,80

  1  45.33.32.156  scanme.nmap.org                     2 open  4 risks
     system    Linux [84%] · Ubuntu 14.04 [55%]
     ports     22/tcp  open  ssh   OpenSSH 6.6.1p1 (Ubuntu 14.04 2ubuntu2.13)
               80/tcp  open  http  Apache HTTP Server 2.4.7 (Ubuntu)
     risks     1 high · 1 medium · 1 low · 1 info · 4 other unverified
               HIGH  80/tcp  Apache HTTP Server 2.4.7: 8 CVEs with no fix for Ubuntu 14.04
                             CVE-2006-20001  CVE-2019-10092  CVE-2019-10098  +5
               MED   22/tcp  OpenSSH 6.6.1p1: 2 CVEs with no fix for Ubuntu 14.04
                             CVE-2016-20012  CVE-2023-48795
               + 1 low, 1 info, 4 unverified · --risks to list them
```

It runs on Linux, macOS and Windows. The scanning itself is a library,
[zond-engine](https://github.com/zond-rs/zond-engine), which you can build on.

Only scan networks you own or have permission to scan.

## Install

**Debian, Ubuntu, Kali** (amd64, arm64), from the
[latest release](https://github.com/zond-rs/zond/releases/latest):

```bash
sudo apt install ./zond_*.deb
```

**Fedora** (x86_64, aarch64), from the same page:

```bash
sudo dnf install ./zond-*.rpm
```

**macOS**:

```bash
brew install zond-rs/tap/zond
```

**Windows**: run `zond-<version>-setup.exe` from the release page. It installs
for your user only and needs [Npcap](https://npcap.com).

**From source**, with Rust 1.93 or newer. The crate is `zond-cli`, the command
is `zond`:

```bash
cargo install zond-cli
```

### Raw sockets

SYN scans and ARP/ICMPv6 discovery need raw sockets. Without them zond falls
back to plain TCP connections, which find less, and it tells you when it does.

- The .deb and .rpm grant the binary the capabilities it needs, so you don't
  need `sudo`, and the files a scan writes stay yours.
- After `cargo install` on Linux, grant them once:
  `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v zond)"`
- On macOS, use `sudo`, or install `wireshark-chmodbpf`
  (`brew install --cask wireshark-chmodbpf`) and log in again.
- On Windows, run it from an Administrator terminal.

## Using it

```bash
zond discover lan                    # which hosts on my segment are up
zond scan 192.168.1.10               # open ports and what's behind them
zond scan 10.0.0.0/24 -d             # also run the service checks
zond scan 10.0.0.5 -p- -O --tls-enum # every port, the OS, and what TLS accepts
zond scan lan -F --pipe              # quick pass, one line per host for scripts
zond listen %eth0 --for 10m          # sends nothing, just watches the link
```

Targets can be addresses, ranges (`10.0.0.1-50`), CIDR blocks, IPv6 prefixes,
hostnames, or `lan` for your own segment. Separate several with commas, read
them from a file with `-i`, and keep addresses out of a run with `-x`.
`zond help targets` has the full grammar, and `zond help ports` the port syntax.

Every command has `-h` for a summary and `--help` for all of it.

## Vulnerabilities

Versions zond identifies are matched against known CVEs. Linux distributions
fix vulnerabilities without changing the version number, so `OpenSSH 6.6.1p1`
on Ubuntu may already carry most of the fixes a plain version match would
report. When a banner names the distribution's build, zond checks it against
that distribution's own fix data and only reports what the build still has.

- **Ubuntu's** data comes with the release packages. A `cargo install` build
  doesn't carry it, so run `zond update` once.
- **Debian's** is downloaded the first time you run a scan interactively, if
  you say yes. Say no and it won't ask again.
- `zond update` refreshes both, along with CISA's list of vulnerabilities
  known to be exploited.

What the data can't settle is listed as *unverified* and isn't counted with
the real risks. `--risks` lists everything, and `--explain` adds the evidence
and the fix for each finding. Findings that cite a CVE CISA has seen exploited
are marked *known exploited* and listed first.

## Records and reports

Every scan is saved as it runs, so an interrupted one can be continued and
old ones can be compared.

```bash
zond journal                     # what's been recorded on this machine
zond resume 06G3JC               # continue one that stopped
zond read latest -o report.html  # print or export the last scan
zond diff baseline.json latest   # what changed (exits 4 if anything did)
zond merge part*.json -o all.xml # combine several scans into one
```

`-o` picks the format from the file extension: JSON, JSONL, CSV, HTML or nmap
XML. `diff`, `merge` and `read` take nmap XML too. Results go to stdout and
everything else to stderr, so `zond scan lan --pipe > hosts.tsv` gives you
clean data.

## Settings

Two files are created on first run, with every option commented out:

- `~/.config/zond/cli.toml` for how output looks
- `~/.config/zond/engine.toml` for what gets sent over the network

Flags override them for a single run. `zond help settings` explains how they
layer with `/etc/zond/` and named profiles.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done, and everything asked for was covered |
| 1 | Couldn't run |
| 2 | Bad arguments or input |
| 3 | Done, but part of what was asked wasn't covered |
| 4 | `zond diff` found changes |
| 130 | Interrupted |

Finding nothing is not an error.

## Getting help

- Something wrong or confusing: [open an issue](https://github.com/zond-rs/zond/issues/new/choose).
  A finding you think is wrong counts too.
- A security problem in zond itself: see [SECURITY.md](SECURITY.md), and
  please don't open a public issue.
- Contributing: see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

AGPL-3.0-or-later, see [LICENSE](LICENSE). If you distribute zond or run a
modified version as a network service, your users are entitled to its source.
For uses where the AGPL doesn't fit, a commercial license is available:
licensing@zond.rs.

The Ubuntu security data bundled with release builds is Canonical's, under
CC BY-SA 4.0; see [assets/advisories/NOTICE](assets/advisories/NOTICE).

Copyright (c) 2026 Erik Lening (hollowpointer) and contributors.
