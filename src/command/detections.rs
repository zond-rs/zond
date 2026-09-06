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
use std::path::Path;

use std::io::Write;

use zond_engine::detect::Detections;
use zond_engine::detect::bundle::Bundle;
use zond_engine::signature::{Domain, Signature, Signing, SigningKey};

use crate::cli::{DetectionArgs, DetectionsAction, DetectionsArgs, KeygenArgs, SignArgs};
use crate::diagnostics::Verbosity;
use crate::error::Error;
use crate::exit::Outcome;
use crate::render;
use crate::render::style::{Palette, Style};
use crate::settings::Presentation;

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
/// [`render::detections`](crate::render::detections), so this module keeps the
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
        Some(DetectionsAction::Keygen(keygen)) => return keys(keygen),
        Some(DetectionsAction::Sign(sign)) => return publish(sign),
        None => {}
    }

    let corpus = corpus(&args.detections)?;
    let listing = corpus.listing();

    let mut out = std::io::stdout().lock();
    render::detections::list(
        &listing,
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

    tracing::info!("{}", render::detections::summary(&listing));

    Ok(Outcome::Complete)
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
