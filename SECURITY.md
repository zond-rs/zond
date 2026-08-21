# Security Policy

## Supported versions

Zond is in early development. Security updates are provided for the latest
release only.

| Version | Supported |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| older   | :x:                |

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security report.**

Send a detailed report to **security@zond.rs**.

Include:

- What the vulnerability is.
- How to reproduce it, with the `zond` command line you ran.
- What an attacker could do with it.

## Scope

This repository is the command-line front end. Its own security surface is
narrower than the engine's, and roughly:

- **Redaction.** `--redact` masking that leaks what it claims to hide — a
  hostname, a hardware address, or the host part of an IPv6 address surviving
  into output.
- **Settings files.** Provisioning that overwrites a file, creates one with
  permissions wider than `0600`, or leaves a `root`-owned file where an
  unprivileged run needs to read it.
- **Argument and target parsing.** An expression that resolves to addresses
  outside what was named.

Anything about what goes on the wire — probe construction, raw sockets,
privilege handling, fingerprinting — belongs to
[zond-engine](https://github.com/zond-rs/zond-engine) and should be reported
against that repository. If you are not sure which, report it here and it will
be routed.

## Our commitment

Zond is a **best-effort project**. There is no full-time security team, but:

- Reports are acknowledged within **7 days**.
- A timeline follows once a vulnerability is confirmed.
- You are credited in the release notes, if you want to be.

There are no financial bounties, but the time researchers put in is genuinely
appreciated.
