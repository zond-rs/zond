<h1 align="center">Zond</h1>

<p align="center">
  <a href="https://crates.io/crates/zond-cli"><img src="https://img.shields.io/crates/v/zond-cli.svg" alt="Crates.io"></a>
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL_v3-blue.svg" alt="License: AGPL v3"></a>
  <img src="https://img.shields.io/badge/rustc-1.93+-blue.svg" alt="Rust Version">
</p>

<p align="center">
  Zond is a network scanner for discovery and auditing. It finds the hosts on a
  network, their open ports and the services behind them, and shows the CVEs
  that still apply to each service.<br>
  It is the official command-line interface to
  <a href="https://github.com/zond-rs/zond-engine">zond-engine</a>, a scanning
  library you can build on.
</p>

<p align="center">
  Linux, macOS and Windows. Currently in beta.
</p>

<p align="center">
  <video src="https://github.com/zond-rs/zond/raw/main/public/demo.mp4" width="100%" controls muted playsinline></video>
</p>

## Install

**Debian, Ubuntu, Kali:** grab the `.deb` from the [latest release](https://github.com/zond-rs/zond/releases/latest).

```bash
sudo apt install ./zond_*.deb
```

**Fedora:** grab the `.rpm` from the same page.

```bash
sudo dnf install ./zond-*.rpm
```

**macOS:**

```bash
brew install zond-rs/tap/zond
```

**Windows:** run `zond-<version>-setup.exe` from the release page. It needs [Npcap](https://npcap.com).

**Nix or NixOS:** there is a [package in nixpkgs](https://search.nixos.org/packages?channel=unstable&from=0&size=50&sort=relevance&query=zond).
The latest release usually lands in the `unstable` channel first.

```bash
nix-env -iA nixos.zond
```

**Anything else**, with Rust 1.93 or newer:

```bash
cargo install zond-cli
```

## Quick start

You usually don't need `sudo` on Linux or macOS. The Linux packages give zond
the network access it needs, and where it can't get that access, it falls back
to ordinary connections and tells you so.

```bash
zond discover lan               # which devices on my network are up?
zond scan 192.168.1.10          # open ports and what's running on them
zond scan 192.168.1.0/24 -F     # quick pass over a whole subnet
zond scan 192.168.1.10 -p- -A   # every port, the OS and deeper checks
zond scan lan --pipe            # one line per host, for scripts
```

Targets can be addresses, ranges like `10.0.0.1-50`, CIDR blocks, hostnames
or `lan`. Every command takes `-h` for a short summary and `--help` for the
full story.

<details>
<summary>Getting the most out of it without sudo</summary>

Some scan types and local discovery need raw sockets. Zond works without
them, but finds less.

- **Linux, installed with `cargo`:** grant them once with
  `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v zond)"`
- **macOS:** `brew install --cask wireshark-chmodbpf`, then log out and back in.
- **Windows:** run zond from an Administrator terminal.

</details>

## Commands

| Command | What it does |
|---|---|
| `discover` | Finds which hosts on a network are up. |
| `scan` | Finds open ports, identifies services and checks them for vulnerabilities. |
| `listen` | Watches a network link and records what it hears. Sends nothing. |
| `resume` | Continues a scan, discovery or watch that was interrupted. |
| `journal` | Lists the scans saved on this machine. |
| `read` | Prints an old scan again, or exports it to JSON, CSV, HTML or nmap XML. |
| `diff` | Shows what changed between two scans. |
| `merge` | Combines several scans into one report. |
| `detections` | Shows which checks a scan would run, without scanning. |
| `update` | Downloads the latest vulnerability data. |
| `completions` | Prints shell completions for bash, zsh, fish, PowerShell or elvish. |
| `help` | Help for any command, plus topics like `targets`, `ports` and `settings`. |

## Feedback

Zond is new, and beta testers are what make it better. If something breaks,
confuses you or reports a vulnerability that isn't there,
[open an issue](https://github.com/zond-rs/zond/issues/new/choose).

Found a security problem in zond itself? Please follow [SECURITY.md](SECURITY.md)
instead of opening a public issue.

Only scan networks you own or have permission to scan.

## License

[AGPL-3.0-or-later](LICENSE). A commercial license is available for cases
where the AGPL doesn't fit: licensing@zond.rs.

Ubuntu security data in release builds is Canonical's, under CC BY-SA 4.0
([notice](assets/advisories/NOTICE)).
