// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond, licensed under the GNU Affero General Public
// License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Embeds the Ubuntu security data snapshot where the checkout carries one.
//!
//! The snapshot is committed to the repository and left out of the crates.io
//! package: it is Canonical's data under CC BY-SA 4.0 rather than this crate's
//! code, and a crate's licence field would otherwise have to carry both. So a
//! release build, made from a checkout, carries it, and a build from the
//! published package does not and relies on `zond update`. The cfg
//! `bundled_ubuntu` says which.

use std::path::Path;

fn main() {
    const SNAPSHOT: &str = "assets/advisories/ubuntu.bin";
    println!("cargo::rerun-if-changed={SNAPSHOT}");
    println!("cargo::rustc-check-cfg=cfg(bundled_ubuntu)");
    if Path::new(SNAPSHOT).is_file() {
        println!("cargo::rustc-cfg=bundled_ubuntu");
    }
}
