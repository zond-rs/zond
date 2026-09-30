# Changelog

## 0.19

The command line is settled for the first testers, and vulnerability findings
now take the distribution's own fixes into account. The flags under *Renamed or
removed* changed outright, with no old spelling kept alongside, so a script
written against 0.18 has to change where it uses them.

### Vulnerabilities

A distribution patches the version it ships without changing the number, so
`OpenSSH 6.6.1p1 Ubuntu-2ubuntu2.13` used to be reported with every CVE of
upstream 6.6.1p1, most of them long fixed. A build that names its distribution
is now judged by that distribution's own fix data.

- What the build fixed, or never shipped, is no longer reported; `-v` counts
  it in one line. What it still carries says why: *no fix for Ubuntu 14.04*,
  *fixed in a newer build* with the version to install, or *fixed only in
  Ubuntu Pro*.
- What the data can't settle, such as an Apache whose banner hides its patch
  level, is *unverified* and counted apart from the risks.
- Client-side and local-only CVEs, such as ssh-agent's, are no longer charged
  to the server. Those that need a non-default setting are their own,
  unverified row.
- Release packages carry Ubuntu's data. Debian's is offered on the first
  interactive scan, and `zond update` fetches both, along with CISA's list of
  vulnerabilities known to be exploited.
- A row whose finding cites a CVE on CISA's list ends in `known exploited` and
  is drawn ahead of worse grades nobody is exploiting.
- The port row shows the build: `OpenSSH 6.6.1p1 (Ubuntu 14.04 2ubuntu2.13)`.

### Renamed or removed

| 0.18 | 0.19 |
|---|---|
| `zond scan --resume ID`, `zond discover --resume ID`, `zond listen --resume ID` | `zond resume ID` |
| `--detection CLASS` | `-d=CLASS`, which takes the word or the step |
| `--detections PATH` | `--load PATH`, one path per flag |
| `--detections-bundle DIR` | `--bundle DIR` |
| `--only-named-detections` | `--no-builtin` |
| `-O` (aggressive) | `-O` is active, `-OO` aggressive |
| `--os-aggressive` | `-OO` |
| `--risk GRADE`, `risk` in `cli.toml` | `--min-risk GRADE`, `min_risk` |
| `--g PORT` | `-g PORT` |
| `--send-mode raw_socket` | `raw-socket`; `raw_socket` is still read |

`--reason`, `--evidence`, `--remedy` and `--min-risk` are taken by the commands
that draw findings (`discover`, `scan`, `listen`, `read`, `merge`, `resume`)
rather than by every command, and after the command's name rather than before
it. `listen` no longer accepts the probe, pace and evasion flags it ignored, and
`discover` no longer accepts service detection.

### The risks block

The findings under a host used to set the width of the whole scan and outgrow
everything above them. A dozen rows for two open ports, each padded out to the
longest title in the block so that one verbose correlation put a hard right edge
on every row beside it.

- Nothing is right-aligned any more. A citation trails its own title after a
  middle dot, so a long title costs its own row and nobody else's.
- The identifiers a correlation cites begin in the column its title began in,
  unlabelled and drawn as quietly as a label, rather than sitting under it behind
  the word `cve` in the ink of a finding. The line is the rest of what the row
  above it said, and at full strength it read as another row and crowded the ones
  on either side.
- Findings whose detections say they cover one weakness between them draw one
  row: the four weak SSH algorithms in a KEXINIT are *4 weak SSH algorithms
  offered*. They are still four findings in every file the scan writes.
- The block opens with what the host carries by grade — `1 high · 6 medium · 1
  low · 4 other unverified` — which is the count a reader decides from. Grey,
  every count of it: it is the scope of the list rather than an entry in it, and
  the colour in the block belongs to the findings. The host's header no longer
  counts the unverified beside its `8 risks`, since this line says the same
  thing better and a reader meeting the number twice has to pick one.
- A finding the engine could not settle is counted rather than drawn, as is
  anything past the sixth row. The block's last line counts everything it is not
  showing, the grades under `--min-risk` included, and names one command for the
  lot: `+ 1 low, 4 unverified · zond read latest --risks`. The floor's own line
  is gone, folded into that one. A host with no row drawn at all gets one line
  rather than two, since the head and the foot would otherwise count the same
  findings one after the other: `4 low · 1 info · zond read latest --risks`.
- `--risks` is that command's flag: every finding, one row each, gathered rows
  come apart, whatever `--min-risk` says. The pointer names the scan it means —
  the record a run just wrote, or the one the reader themselves named — so it can
  be pasted; a run that writes no record, and a scan named by something too long
  to spell, are pointed at the flag alone.
- No row says how sure it is any more. The block answers that once, where it
  matters: everything above the caption is at least probably true, everything
  below it is not settled. Which of `probable`, `strong` or `certain` a settled
  row landed on changed nothing a reader does next, and spelling it put a word on
  every line that was the widest thing on most of them. `--pipe` still carries
  the grade per finding, as does every file the scan writes.
- Where the unverified are drawn, they say so once, in a line above the first of
  them: *unverified below: matched, but not settled for this build*. They are
  already drawn without the colour their severity would carry, so the word on
  each was the same thing said twice.

A host with three findings or fewer is drawn whole, floor and all. Below that
there is nothing to summarise: one medium drawn and a line under it saying a low
is being held back saves no space and sends the reader for a second command to
see two findings. A floor the reader set themselves still holds, however few
there are.

The certificate under a port had the same disease and takes the same cure. It
led with the common name, which is free text of any length, so one
forty-character subject set the column for every port on the host and pushed the
cipher suites off the side of the terminal. It now leads with `expires in 1d`
and follows with the name: the expiry is sixteen characters at its longest, so
the column is bounded by construction, and the colour that says *this one is
about to lapse* sits where the eye runs down instead of wherever a name happened
to end. On a seven-port host with three certificates that is 106 columns down to
86.

`--pipe` and `--minimal` are unchanged: both are one line per finding for a
reader who is grepping, and neither gathers, caps nor defers anything.

### New

- `zond resume ID` continues a scan, a sweep or a watch, whichever the record
  holds.
- `-i FILE` and `--exclude-file FILE` read targets and exclusions from a file,
  or from standard input with `-`.
- Short flags: `-x` for `--exclude`, `-e` for `--send-interface`, `-D` for
  `--decoy`, `-F` for the hundred likeliest ports.
- `--minimal` and `--fancy` beside `--pipe`, and `--explain` for the reason,
  evidence and remedy together.
- `--risks` lists every finding a scan recorded rather than the block's summary
  of them, whatever `--min-risk` is set to.
- `--max-rate` and `--min-rate` as names for the probe rates, and the American
  spellings `--color`, `--characterize` and `--cve-catalog`.
- `-s` for the scan type by letter: `-sS` for SYN, `-sU` for UDP, `-sV` for
  service detection, and the rest of `--tcp-technique` and `--sctp-technique`.
- `-Pn` for `--assume-up`, `-iL` for `--input-file`, `-sI` for `--idle-scan`,
  and `--excludefile`, `--max-retries`, `--version-all` and `--version-light`.
  `-T0` to `-T5` set the pace, and `-A` is `-O -d --traceroute`. `-f` is
  refused with what to write instead.
- `journal show latest`.

### Help

`-h` lists the flags most runs use, grouped by task, and ends with examples;
`--help` adds the rest and the reference prose. Every flag that takes a word
lists the words it takes. The top-level help says what the tool does, where the
settings live, and what each exit status means.
