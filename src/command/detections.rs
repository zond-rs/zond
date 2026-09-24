// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # `zond detections`
//!
//! The corpus a scan runs against what it identifies, and the command that
//! compiles one without scanning.
//!
//! Fingerprinting names a service; a detection says what is wrong with it. The
//! engine ships a corpus and takes more, so this module is the front end's half
//! of that: it turns paths into the bytes the engine's builder takes, and it
//! gives an author somewhere to point `zond detections` while they are still
//! getting a file to compile.
//!
//! ## Reading files is this side's job
//!
//! The engine opens nothing. Its builder takes named contents, from a directory,
//! an archive, a database row, and validates and compiles each as it arrives, so
//! everything here is the walk and the read: which files count, what a bundle
//! directory is laid out as, and where a public key is read from. What a
//! detection is allowed to do once loaded is decided by its class and the
//! operator's envelope, and neither is affected by having come off disk.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use std::io::Write;

use zond_engine::config::{DetectionEnvelope, ServiceDetection};
use zond_engine::detect::Detections;
use zond_engine::detect::bundle::Bundle;
use zond_engine::detect::compute::replay_run;
use zond_engine::journal::{paths, store};
use zond_engine::model::finding::{DetectionClass, Finding, Severity};
use zond_engine::signature::{Domain, Signature, Signing, SigningKey};
use zond_engine::{PortSet, scan};

use crate::cli::{
    DetectionArgs, DetectionsAction, DetectionsArgs, KeygenArgs, ReplayArgs, SignArgs, TestArgs,
};
use crate::command::{catalogue, page};
use crate::diagnostics::Verbosity;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::style::{Palette, Style};
use crate::render::{self, Phase};
use crate::settings::{Presentation, Risk};
use crate::target;

/// The manifest a bundle directory holds.
const BUNDLE_MANIFEST: &str = "manifest.toml";

/// The detached signature beside it, named as the engine names one.
const BUNDLE_SIGNATURE: &str = "manifest.toml.sig";

/// The extension a detection document carries.
const DOCUMENT: &str = "toml";

/// The extension a compute body carries. Rhai today; a body in another language
/// arrives as another arm here.
const BODY: &str = "rhai";

/// The corpus a scan should run, given what the command line named.
///
/// The built-in detections unless `--only-named-detections` says otherwise, then
/// whatever `--detections` names, then a bundle if one was named. Each detection
/// is validated and compiled here, so a file that will not compile stops the run
/// before a packet is sent rather than at the moment a port it gates on turns up.
pub(crate) fn corpus(args: &DetectionArgs) -> Result<Detections, Error> {
    if args.paths.is_empty() && args.detections_bundle.is_none() {
        return Ok(Detections::embedded());
    }

    let mut builder = Detections::builder();
    if args.only_named_detections {
        builder = builder.without_embedded();
    }

    if !args.paths.is_empty() {
        let mut sources = BTreeMap::new();
        for path in &args.paths {
            read_into(path, &mut sources)?;
        }
        if sources.is_empty() {
            return Err(Error::NoDetections {
                named: args.paths.clone(),
            });
        }
        builder = builder.sources(&sources).map_err(Error::Detections)?;
    }

    if let Some(directory) = &args.detections_bundle {
        // Checked before the manifest is parsed and before a source is compiled,
        // which is the engine's own ordering; all this does is find the files.
        let key = trusted_key(args.trust_key.as_deref().expect("--trust-key is required"))?;
        let bundle = verified_bundle(directory, &key)?;
        builder = builder.bundle(bundle).map_err(Error::Detections)?;
    }

    Ok(builder.build())
}

/// Compiles the detections the command line names and prints what a scan would
/// run.
///
/// Not a [`Renderer`](crate::render::Renderer): a renderer draws a scan as it
/// happens, and nothing happens here. What it draws in is
/// [`render::detections`], so this module keeps the
/// half that is about files and the drawing stays where every other drawing is.
///
/// The count goes to standard error with the rest of the commentary. Records to
/// standard output, commentary to standard error, in every mode: a count on the
/// record stream is a line every reader of that stream has to know to skip.
pub(crate) fn run(
    args: &DetectionsArgs,
    presentation: Presentation,
    verbosity: Verbosity,
    palette: Palette,
) -> Result<Outcome, Error> {
    match &args.action {
        // `test` drives the network and is async, so `main` dispatches it before
        // this synchronous path is ever reached.
        Some(DetectionsAction::Test(_)) => unreachable!("test is dispatched in main"),
        Some(DetectionsAction::Replay(replay_args)) => {
            return replay(replay_args, presentation, verbosity, palette);
        }
        Some(DetectionsAction::Keygen(keygen)) => return keys(keygen),
        Some(DetectionsAction::Sign(sign)) => return publish(sign),
        None => {}
    }

    let corpus = corpus(&args.detections)?;
    let compiled = corpus.listing();
    let whole = compiled.len();

    // Narrowed and ordered before anything is measured, because the catalogue's
    // columns are measured across what it draws: a listing of one class should
    // not carry the width of a class name that was filtered out.
    let listing = catalogue::select(compiled, &args.catalogue);

    if listing.is_empty() && whole > 0 {
        // The conditions read back, not a bare absence. Somebody who asked for
        // `--class dos` against a corpus that has none is owed the reason their
        // screen is empty, and the reason is what they typed.
        tracing::info!(
            "no detection among the {whole} matches {}",
            catalogue::asked_for(&args.catalogue)
        );
        return Ok(Outcome::Complete);
    }

    let page = page::paginate(&args.page, presentation, listing.len())?;

    let mut out = std::io::stdout().lock();
    render::detections::list(
        &listing[page.shown.clone()],
        presentation,
        verbosity,
        &mut out,
        Style::records(presentation, palette),
    )?;
    out.flush()?;

    // A blank line above the summary, the way a scan's narrator opens its own
    // closing line. On the commentary stream rather than the record one, because
    // the blank exists to separate the listing *from the summary*: a run whose
    // commentary was sent to `/dev/null` should not be left with a trailing
    // newline separating its records from nothing.
    if verbosity.narrates() {
        let _ = writeln!(std::io::stderr());
    }

    // What the whole catalogue came to first, then where in it this page fell.
    // The counts describe everything the filter admitted rather than the rows on
    // screen, so a page of ten out of ninety is not read as a corpus of ten.
    tracing::info!("{}", render::detections::summary(&listing, whole));
    if let Some(footer) = page::footer(&page, listing.len(), "detections") {
        tracing::info!("{footer}");
    }

    Ok(Outcome::Complete)
}

/// Runs detections against one endpoint and draws the scan, the author's loop.
///
/// A scan scoped to the one host and port: it port-scans it, identifies the
/// service a gate names, and runs the detections at a raised ceiling, so a check
/// written to confirm a weakness fires against the box it was pointed at rather
/// than waiting for an operator to widen a real scan. The endpoint is drawn with
/// its evidence, since a test exists to show what a detection decided on.
///
/// It builds its own renderer rather than taking the shared one, so it can turn
/// evidence on whatever the command line said: on a scan that is the reader's
/// call, here it is the point.
pub(crate) async fn test(
    args: &TestArgs,
    presentation: Presentation,
    verbosity: Verbosity,
    palette: Palette,
) -> Result<Outcome, Error> {
    let (host, port) = parse_target(&args.target)?;

    // Everything it found, and the working behind it: every grade, the evidence,
    // and the advice. Certificates follow `-v`, as they do everywhere.
    let showing = render::field::Showing {
        certificates: verbosity.explains(),
        reasons: false,
        excerpts: true,
        remedies: true,
        risk: Risk::from_str("info").expect("info is a valid risk floor"),
    };
    let mut renderer = render::renderer(presentation, verbosity, palette, showing);

    let mut config = crate::command::engine_settings(None)?.config;
    // The service is identified so a gate that names one fits, and the ceiling is
    // raised to what the author is testing. A test is an explicit act against a
    // named target, which is the whole of what the envelope decides.
    config.service_detection = ServiceDetection::Thorough;
    config.detection = args
        .detection
        .unwrap_or_else(|| DetectionEnvelope::up_to(DetectionClass::Exploit));

    // A plain port number is always a valid single-port set; the parse cannot fail
    // on what `parse_target` already read as a `u16`.
    let ports = PortSet::from_str(&port.to_string()).expect("a port number is a valid port set");
    let targets = target::resolve_ports(
        std::slice::from_ref(&host),
        &[] as &[&str],
        &config.exclusions,
        ports,
        !config.no_dns,
    )
    .await?;
    targets.apply_to(&mut config);

    let redaction = crate::command::redaction(&config);
    // Recorded nowhere, so nothing it leaves undecided can be resumed.
    renderer.started(
        Phase::PortScan {
            targets: &targets,
            resumable: false,
        },
        redaction,
    )?;

    let corpus = test_corpus(&args.detections)?;
    let plan = targets.into_map();
    let (session, task) = scan(plan, &config, corpus).await?;

    // The same driver the scan command uses, so a test is drawn exactly as the
    // scan it is. Nothing is written to a file: a test goes to the terminal.
    crate::command::drive(
        session,
        task,
        &[],
        redaction,
        crate::command::Stopping::CutsShort,
        None,
        renderer.as_mut(),
    )
    .await
}

/// `host:port` into its two parts. An IPv6 address is bracketed, `[::1]:443`, so
/// the port is told from the address's own colons; a name or an IPv4 address is
/// split at its single colon. Without a port it is not an endpoint, which is what
/// a detection runs against, so that is an error rather than a whole-host scan.
fn parse_target(target: &str) -> Result<(String, u16), Error> {
    let malformed = || Error::MalformedTarget {
        target: target.to_string(),
    };

    if let Some(rest) = target.strip_prefix('[') {
        let (address, port) = rest.split_once("]:").ok_or_else(malformed)?;
        let port = port.parse().map_err(|_| malformed())?;
        return Ok((address.to_string(), port));
    }

    let (host, port) = target.rsplit_once(':').ok_or_else(malformed)?;
    let port = port.parse().map_err(|_| malformed())?;
    if host.is_empty() {
        return Err(malformed());
    }
    Ok((host.to_string(), port))
}

/// The corpus a test runs: the named detections alone when any were named, so a
/// test is about the file in hand, and the built-in corpus when none were, for a
/// quick look at what fires against the endpoint.
fn test_corpus(args: &DetectionArgs) -> Result<Detections, Error> {
    if args.paths.is_empty() && args.detections_bundle.is_none() {
        return Ok(Detections::embedded());
    }

    let mut builder = Detections::builder().without_embedded();
    if !args.paths.is_empty() {
        let mut sources = BTreeMap::new();
        for path in &args.paths {
            read_into(path, &mut sources)?;
        }
        if sources.is_empty() {
            return Err(Error::NoDetections {
                named: args.paths.clone(),
            });
        }
        builder = builder.sources(&sources).map_err(Error::Detections)?;
    }
    if let Some(directory) = &args.detections_bundle {
        let key = trusted_key(args.trust_key.as_deref().expect("--trust-key is required"))?;
        builder = builder
            .bundle(verified_bundle(directory, &key)?)
            .map_err(Error::Detections)?;
    }
    Ok(builder.build())
}

/// Re-runs the compute detections a scan journalled, offline, and draws what
/// reproduced.
///
/// A compute detection reaches the world only through its capabilities, which the
/// scan recorded, so replaying the tape reproduces the finding with no target and
/// no packet. A finding prints with its evidence; a run that drew nothing waits
/// for `-v`, the way a finding's own working does, so an all-quiet replay is one
/// summary line rather than a line per run. A run this build can no longer
/// reproduce (its detection changed, or came off `--detections`) is named as
/// unavailable rather than reproduced by a different one, since [`replay_run`]
/// matches by the content hash of the body that ran. Only the compute tier tapes
/// a run; a flow leaves nothing here, which the summary says when a scan recorded
/// none.
///
/// The findings go to standard output and the summary to standard error, the
/// stream split every command here keeps.
pub(crate) fn replay(
    args: &ReplayArgs,
    presentation: Presentation,
    verbosity: Verbosity,
    palette: Palette,
) -> Result<Outcome, Error> {
    let (directory, label) = journal_directory(&args.scan)?;
    let runs = store::read_detections(&directory)?;
    let selected: Vec<&_> = runs
        .iter()
        .filter(|run| {
            args.only
                .as_deref()
                .is_none_or(|only| run.detection.id == only)
        })
        .collect();

    let style = Style::records(presentation, palette);
    let mut out = std::io::stdout().lock();

    let mut findings_total = 0usize;
    let mut unavailable = 0usize;
    let mut wrote_records = false;

    for run in &selected {
        // The detection is the subject of a line and the endpoint the circumstance;
        // the address is bracketed when IPv6, or the port reads as another group.
        let header = || format!("{} on {}", run.detection.id, endpoint(&run.host, run.port));

        match replay_run(run) {
            Ok(findings) if findings.is_empty() => {
                // A run that drew nothing is the working behind a clean result, not
                // the result, so it waits for `-v` the way a finding's own evidence
                // does. What it read is what makes the silence legible once asked.
                if verbosity.explains() {
                    writeln!(out, "{}", style.strong(&header()))?;
                    writeln!(
                        out,
                        "    {}",
                        style.faint(&format!(
                            "no finding · read {}",
                            read_preview(&run.responses)
                        )),
                    )?;
                    wrote_records = true;
                }
            }
            Ok(findings) => {
                findings_total += findings.len();
                writeln!(out, "{}", style.strong(&header()))?;
                for finding in &findings {
                    write_finding(&mut out, style, finding)?;
                }
                wrote_records = true;
            }
            Err(error) => {
                // A recorded run this build can no longer reproduce is a hole in the
                // replay, not noise, so it is named whether or not detail was asked.
                unavailable += 1;
                writeln!(
                    out,
                    "{}  {}",
                    style.strong(&header()),
                    style.faint(&format!("unavailable, {error}")),
                )?;
                wrote_records = true;
            }
        }
    }
    out.flush()?;

    if verbosity.narrates() {
        // A blank line separates the records from the summary, and only earns its
        // place when there were records: an all-quiet replay is one summary line.
        if wrote_records {
            let _ = writeln!(std::io::stderr());
        }
        tracing::info!(
            "{}",
            replay_summary(
                &label,
                runs.len(),
                selected.len(),
                findings_total,
                unavailable
            )
        );
    }

    Ok(Outcome::Complete)
}

/// The one line that says what a replay amounted to.
///
/// It leads with the answer a reader wants, whether anything reproduced, and
/// names the scope where it would otherwise mislead: a scan that recorded no
/// runs did not run no detections, it ran flows, which are live and leave no tape
/// to replay.
fn replay_summary(
    label: &str,
    recorded: usize,
    selected: usize,
    findings: usize,
    unavailable: usize,
) -> String {
    let runs = |n: usize| if n == 1 { "run" } else { "runs" };

    if recorded == 0 {
        return format!(
            "no compute detections were recorded for {label}; flows run live and leave no tape to replay"
        );
    }
    if selected == 0 {
        return format!("no recorded run in {label} matched the id asked for");
    }

    let mut summary = if findings > 0 {
        format!(
            "replayed {selected} detection {} from {label}: {findings} {}",
            runs(selected),
            if findings == 1 { "finding" } else { "findings" },
        )
    } else {
        format!(
            "replayed {selected} detection {} from {label}: no findings reproduced",
            runs(selected),
        )
    };
    if unavailable > 0 {
        use std::fmt::Write as _;
        let _ = write!(
            summary,
            ", {unavailable} could not be replayed against this build"
        );
    }
    summary
}

/// `host:port`, bracketing an IPv6 address so the port is not read as another of
/// its colon-separated groups.
fn endpoint(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// A one-line look at what a detection was handed, for saying why a replay drew
/// nothing. The first non-empty response's first line, control bytes shown as
/// dots and the whole truncated, or a note that nothing was gathered.
fn read_preview(responses: &[String]) -> String {
    let Some(text) = responses
        .iter()
        .find(|response| !response.trim().is_empty())
    else {
        return "nothing (no response was gathered)".to_string();
    };

    let line = text.lines().next().unwrap_or_default();
    let mut preview: String = line
        .chars()
        .map(|character| {
            if character.is_control() {
                '.'
            } else {
                character
            }
        })
        .take(PREVIEW_CHARS)
        .collect();
    if line.chars().count() > PREVIEW_CHARS {
        preview.push('…');
    }
    format!("\"{preview}\"")
}

/// The most characters of a gathered response a replay previews. Enough for a
/// status line or a banner, short enough to stay one line in a terminal.
const PREVIEW_CHARS: usize = 80;

/// One finding and the evidence behind it, indented under its detection.
fn write_finding(out: &mut impl Write, style: Style, finding: &Finding) -> Result<(), Error> {
    writeln!(
        out,
        "    {}  {}",
        severity_tag(style, finding.severity()),
        style.plain(finding.title()),
    )?;
    let excerpt = finding.excerpt();
    if !excerpt.is_empty() {
        writeln!(
            out,
            "        {} {}",
            style.faint("evidence"),
            style.faint(excerpt.as_str()),
        )?;
    }
    Ok(())
}

/// A finding's severity as a coloured tag: the graver it is, the louder the ink.
fn severity_tag(style: Style, severity: Severity) -> String {
    let label = severity.label().to_uppercase();
    match severity {
        Severity::Critical | Severity::High => style.alarm(&label),
        Severity::Medium => style.caution(&label),
        Severity::Low => style.accent(&label),
        // Info, and any grade a later model adds below it.
        _ => style.faint(&label),
    }
}

/// The journal directory to replay and a label naming it for the summary: a path
/// if one was named, else the record the id resolves to. `latest` is the newest
/// record, and the label is the id it resolved to rather than the word `latest`,
/// so the summary says which scan was actually read.
fn journal_directory(scan: &str) -> Result<(PathBuf, String), Error> {
    let path = Path::new(scan);
    if path.is_dir() {
        return Ok((path.to_path_buf(), scan.to_string()));
    }

    let id = crate::command::journal::newest_if_latest(scan)?;
    let directory = paths::scan(&id).ok_or(Error::NoJournalDirectory)?;
    if !directory.is_dir() {
        return Err(Error::NoSuchJournal {
            id,
            known: paths::root()
                .and_then(|root| store::list(&root).ok())
                .map_or(0, |entries| entries.len()),
        });
    }
    Ok((directory, id))
}

/// Reads one `--detections` path into `sources`, keyed by file name.
///
/// A file is read as it stands. A directory is read one level deep, taking the
/// documents and the bodies and leaving everything else, so a README or a
/// `.gitignore` beside a detection is not offered to the engine as one.
///
/// One level rather than a walk: a directory of detections is a flat thing, and
/// recursing would make the corpus depend on what a nested directory happened to
/// hold.
fn read_into(path: &Path, sources: &mut BTreeMap<String, String>) -> Result<(), Error> {
    let metadata = std::fs::metadata(path).map_err(|cause| Error::DetectionPath {
        path: path.to_path_buf(),
        cause,
    })?;

    if metadata.is_file() {
        return insert(path, sources);
    }

    let entries = std::fs::read_dir(path).map_err(|cause| Error::DetectionPath {
        path: path.to_path_buf(),
        cause,
    })?;

    for entry in entries {
        let entry = entry.map_err(|cause| Error::DetectionPath {
            path: path.to_path_buf(),
            cause,
        })?;
        let found = entry.path();
        let extension = found.extension().and_then(|e| e.to_str());
        if found.is_file() && matches!(extension, Some(DOCUMENT | BODY)) {
            insert(&found, sources)?;
        }
    }

    Ok(())
}

/// Reads one file into `sources` under its file name, which is the name a
/// `[compute]` section references a body by.
///
/// Two files with the same name from different directories are refused. Taking
/// the second would run a detection the caller did not name and skip one they
/// did.
fn insert(path: &Path, sources: &mut BTreeMap<String, String>) -> Result<(), Error> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::DetectionName {
            path: path.to_path_buf(),
        })?
        .to_string();

    let contents = std::fs::read_to_string(path).map_err(|cause| Error::DetectionPath {
        path: path.to_path_buf(),
        cause,
    })?;

    if sources.insert(name.clone(), contents).is_some() {
        return Err(Error::DuplicateDetection { name });
    }

    Ok(())
}

/// The raw public key held in `path`, written as hex.
///
/// Hex because that is how a signature document spells the key that made it, so
/// a publisher who prints their key and a recipient who saves it are handling one
/// spelling. Whitespace around it is ignored; a file written by `echo` has a
/// newline on the end.
fn trusted_key(path: &Path) -> Result<Vec<u8>, Error> {
    let text = std::fs::read_to_string(path).map_err(|cause| Error::DetectionPath {
        path: path.to_path_buf(),
        cause,
    })?;

    decode_hex(text.trim()).ok_or_else(|| Error::MalformedKey {
        path: path.to_path_buf(),
    })
}

/// Decodes lowercase or upper-case hex, or nothing if it is not hex.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.is_empty() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// Reads a bundle directory and hands it to the engine to verify.
///
/// The layout is the manifest, its detached signature, and the sources the
/// manifest names. Every other file in the directory is read too and handed over,
/// because a source the manifest does not name is something the engine refuses
/// rather than something this should quietly drop: a file sitting in a bundle
/// that no signature covers is worth being told about.
fn verified_bundle(directory: &Path, trusted_key: &[u8]) -> Result<Bundle, Error> {
    let manifest_path = directory.join(BUNDLE_MANIFEST);
    let manifest =
        std::fs::read_to_string(&manifest_path).map_err(|cause| Error::DetectionPath {
            path: manifest_path,
            cause,
        })?;

    let signature_path = directory.join(BUNDLE_SIGNATURE);
    let file = std::fs::File::open(&signature_path).map_err(|cause| Error::DetectionPath {
        path: signature_path.clone(),
        cause,
    })?;
    let signature = Signature::read(&mut std::io::BufReader::new(file))?;

    let mut sources = BTreeMap::new();
    let entries = std::fs::read_dir(directory).map_err(|cause| Error::DetectionPath {
        path: directory.to_path_buf(),
        cause,
    })?;
    for entry in entries {
        let entry = entry.map_err(|cause| Error::DetectionPath {
            path: directory.to_path_buf(),
            cause,
        })?;
        let found = entry.path();
        let name = found.file_name().and_then(|name| name.to_str());
        let is_bundle_file = matches!(name, Some(BUNDLE_MANIFEST | BUNDLE_SIGNATURE));
        if found.is_file() && !is_bundle_file {
            insert(&found, &mut sources)?;
        }
    }

    Bundle::verified(&manifest, &signature, trusted_key, sources).map_err(Error::Bundle)
}

/// Writes a fresh signing key pair.
///
/// The private key is the PKCS#8 document the engine's signer reads, written
/// with only the owner able to read it; the public key goes beside it as hex,
/// which is the spelling a signature document uses and the spelling
/// `--trust-key` reads. Neither is consulted by a scan: a scan verifies against
/// the public key a recipient was given, and signing happens here.
///
/// Refuses to write over an existing key. Overwriting one silently would end
/// every bundle already published under it.
fn keys(args: &KeygenArgs) -> Result<Outcome, Error> {
    let public_path = args.path.with_extension("pub");
    for path in [&args.path, &public_path] {
        if path.exists() {
            return Err(Error::KeyExists { path: path.clone() });
        }
    }

    // The directory the key goes in, since `~/.zond/erik` names one that
    // usually does not exist yet and `sign --out` already creates its own.
    if let Some(parent) = args.path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|cause| Error::DetectionPath {
            path: parent.to_path_buf(),
            cause,
        })?;
    }

    let (pkcs8, key) = SigningKey::generate()?;

    write_private(&args.path, &pkcs8)?;
    std::fs::write(&public_path, hex(&key.public_key())).map_err(|cause| Error::DetectionPath {
        path: public_path.clone(),
        cause,
    })?;

    let mut out = std::io::stdout().lock();
    writeln!(out, "private key  {}", args.path.display())?;
    writeln!(out, "public key   {}", public_path.display())?;
    writeln!(
        out,
        "\nPublish the public key. A recipient names it with --trust-key, and \
         has to obtain it from you rather than from a bundle."
    )?;

    Ok(Outcome::Complete)
}

/// Writes a private key readable only by its owner.
///
/// The mode is set as the file is created rather than after, so there is no
/// moment where the key exists and anybody can read it.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|cause| Error::DetectionPath {
            path: path.to_path_buf(),
            cause,
        })?;

    file.write_all(bytes).map_err(|cause| Error::DetectionPath {
        path: path.to_path_buf(),
        cause,
    })
}

/// Writes a private key, on a platform whose permissions this does not set.
///
/// Windows inherits the directory's ACL, so a key written into a user's own
/// profile is already theirs alone and one written elsewhere is not; there is no
/// mode to set on the way past.
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    std::fs::write(path, bytes).map_err(|cause| Error::DetectionPath {
        path: path.to_path_buf(),
        cause,
    })
}

/// Signs a directory of detections as a bundle.
///
/// Every detection is compiled first. A bundle whose sources will not build is
/// one a recipient would refuse after checking a signature that was perfectly
/// good, and the moment to learn that is before publishing rather than after.
///
/// The manifest names each source, the tier that runs it and the hash of its
/// bytes; the signature covers the manifest, so it covers the membership as well
/// as the contents. Both are written into the directory that was signed.
fn publish(args: &SignArgs) -> Result<Outcome, Error> {
    let mut sources = BTreeMap::new();
    read_into(&args.directory, &mut sources)?;
    if sources.is_empty() {
        return Err(Error::NoDetections {
            named: vec![args.directory.clone()],
        });
    }

    // Compiled before it is signed, and by the same builder a scan uses. A
    // bundle whose sources will not build is one a recipient refuses after
    // checking a signature that was perfectly good.
    Detections::builder()
        .without_embedded()
        .sources(&sources)
        .map_err(Error::Detections)?;

    // What a bundle carries is detections, not the files they were kept in: a
    // module's body is resolved into the document that runs it, so every entry
    // is self-contained and a recipient can hash whole files.
    let named = Bundle::publishable(&sources).map_err(Error::Detections)?;
    let manifest = Bundle::manifest(&args.name, &args.bundle_version, &named);

    let pkcs8 = std::fs::read(&args.key).map_err(|cause| Error::DetectionPath {
        path: args.key.clone(),
        cause,
    })?;
    let key = SigningKey::from_pkcs8(&pkcs8)?;

    let mut sink = Vec::new();
    let mut writer = Signing::new(&mut sink);
    writer.write_all(manifest.as_bytes())?;
    let signature = writer.finish(&key, Domain::DETECTIONS);

    std::fs::create_dir_all(&args.out).map_err(|cause| Error::DetectionPath {
        path: args.out.clone(),
        cause,
    })?;

    // The documents first, then the manifest, then the signature. A bundle found
    // half-written is one missing its signature rather than one whose signature
    // covers documents that are not there yet.
    for (name, (_, document)) in &named {
        write_out(&args.out.join(name), document)?;
    }
    write_out(&args.out.join(BUNDLE_MANIFEST), &manifest)?;
    write_out(&args.out.join(BUNDLE_SIGNATURE), &signature.to_document())?;

    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "signed {} detections as {} {} into {}",
        named.len(),
        args.name,
        args.bundle_version,
        args.out.display()
    )?;
    for name in named.keys() {
        writeln!(out, "  {name}")?;
    }
    writeln!(
        out,
        "\nA recipient runs: zond scan TARGET --detections-bundle {} --trust-key {}",
        args.out.display(),
        args.key.with_extension("pub").display()
    )?;

    Ok(Outcome::Complete)
}

/// Writes one file of a bundle, naming it if the write fails.
fn write_out(path: &Path, contents: &str) -> Result<(), Error> {
    std::fs::write(path, contents).map_err(|cause| Error::DetectionPath {
        path: path.to_path_buf(),
        cause,
    })
}

/// Bytes as lowercase hex, which is how a key is written down.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}
