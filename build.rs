//! Stamps the revision of the SDK checkout beside this repo into the binary
//! (`HARNESS_SDK_REV`): `race-get` links the SDK's engine from there, so that
//! checkout IS the arm a run measures, and a record that could not say which
//! one it was would be a record of nothing.

use std::process::Command;

fn main() {
    let sdk = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../craftworks-sdk");
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(&sdk)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    // "unknown" is a value a reader must treat as a mismatch, never a pass.
    let rev = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty =
        git(&["status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| !s.is_empty());
    println!(
        "cargo:rustc-env=HARNESS_SDK_REV={rev}{}",
        if dirty { "-dirty" } else { "" }
    );
    // Re-stamp on every build: the checkout can change without any file of
    // THIS crate changing, and a stale stamp names the wrong arm.
    println!("cargo:rerun-if-changed=build.rs.always");
}
