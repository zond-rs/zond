# Changelog

## 0.19

The command line is settled for the first testers. The flags below were renamed
or removed outright, with no old spelling kept alongside, so a script written
against 0.18 has to change where it uses them.

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

### New

- `zond resume ID` continues a scan, a sweep or a watch, whichever the record
  holds.
- `-i FILE` and `--exclude-file FILE` read targets and exclusions from a file,
  or from standard input with `-`.
- Short flags: `-x` for `--exclude`, `-e` for `--send-interface`, `-D` for
  `--decoy`, `-F` for the hundred likeliest ports.
- `--minimal` and `--fancy` beside `--pipe`, and `--explain` for the reason,
  evidence and remedy together.
- `--max-rate` and `--min-rate` as names for the probe rates, and the American
  spellings `--color`, `--characterize` and `--cve-catalog`.
- `-s` for the scan type by letter: `-sS` for SYN, `-sU` for UDP, `-sV` for
  service detection, and the rest of `--tcp-technique` and `--sctp-technique`.
- `-Pn` for `--assume-up`, `-iL` for `--input-file`, `-sI` for `--idle-scan`,
  and `--excludefile`, `--max-retries`, `--version-all` and `--version-light`.
  `-T`, `-A`, `-f` and `-S` are refused with what to write instead.
- `journal show latest`.

### Help

`-h` lists the flags most runs use, grouped by task, and ends with examples;
`--help` adds the rest and the reference prose. Every flag that takes a word
lists the words it takes. The top-level help says what the tool does, where the
settings live, and what each exit status means.
