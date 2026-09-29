// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # `zond resume`
//!
//! Continues a record by its id alone. The record says whether it was a scan,
//! a sweep or a watch, so this reads that and hands the sitting to the command
//! that runs that phase, which makes every check a resume has always made: the
//! lock, the plan, and the options the job ran under.
//!
//! The record is read here without being opened for writing. The command it
//! goes to opens it, and a record that has changed hands between the two is
//! refused there as it would be anyway.

use zond_engine::report::ScanKind;

use crate::cli::ResumeArgs;
use crate::command::{self, Recording, journal};
use crate::error::Error;
use crate::exit::Outcome;
use crate::render::Renderer;

pub(crate) async fn run(
    args: ResumeArgs,
    recording: Recording,
    reasons: bool,
    renderer: &mut dyn Renderer,
) -> Result<Outcome, Error> {
    let id = journal::newest_if_latest(&args.id)?;
    let listing = journal::read()?;
    let kind = journal::find_in(&listing, &id)?.manifest.kind();

    if args.r#for.is_some() && kind != ScanKind::Listen {
        return Err(Error::SpanOnAJob {
            id,
            held: held(kind),
        });
    }

    match kind {
        ScanKind::Discovery => {
            command::discover::run(&args.into_discover(id), recording, renderer).await
        }
        ScanKind::Listen => command::listen::run(&args.into_listen(id), recording, renderer).await,
        // A port scan, and anything a newer engine records that this build has
        // no command for, which the scan path refuses by its phase.
        _ => command::scan::run(&args.into_scan(id), recording, reasons, renderer).await,
    }
}

/// What a record of `kind` holds, as a phrase that reads after "records".
fn held(kind: ScanKind) -> &'static str {
    match kind {
        ScanKind::Discovery => "a sweep",
        ScanKind::Listen => "a watch",
        _ => "a port scan",
    }
}
