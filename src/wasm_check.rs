//! Load a contract artefact, and refuse to run against the wrong one.
//!
//! A round-trip that silently tests a stale wasm reports a PASS for a contract
//! nobody ships. That happened: a Bag run passed every step against a build
//! four commits old, and only a size comparison caught it. Printing the hash
//! was not enough — the run has to FAIL.
//!
//! The expected hash is a parameter, never a constant, because these move on
//! every contract change: pinning one in the source would go stale exactly as
//! quietly as having no check at all.

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};

/// sha256, the digest `freenet-contracts/*/build.sh` reports.
///
/// Named for what it is. An earlier version of this computed BLAKE3 and
/// printed it labelled `sha256=`, which made every comparison against the
/// build script's output fail for a reason that looked like a stale artefact.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Read a wasm and check it against `expect`, if given.
///
/// `expect` may be a prefix — the build scripts print the first 16 hex
/// characters — so a caller can paste what the build printed.
pub fn load(path: &str, expect: Option<&str>) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow!("{path}: {e} — run ../freenet-contracts/build.sh first"))?;
    let got = sha256_hex(&bytes);
    println!("{path}: {} bytes  sha256={}", bytes.len(), &got[..16]);
    if let Some(want) = expect {
        let want = want.trim().to_lowercase();
        if want.is_empty() {
            bail!("--expect-sha was given but empty");
        }
        if !got.starts_with(&want) {
            bail!(
                "wasm mismatch: {path} is sha256 {} but --expect-sha said {want}.\n  \
                 Refusing to run: a round trip against the wrong artefact reports a PASS \
                 for a contract nobody ships. Rebuild with freenet-contracts/build.sh, or \
                 pass the hash it printed.",
                &got[..16.min(got.len())]
            );
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest must be the one the build scripts print, not merely *a*
    /// digest. This vector is sha256("") — if this file ever goes back to
    /// BLAKE3, this fails rather than silently disagreeing with every build.
    #[test]
    fn the_digest_is_really_sha256() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn a_prefix_matches_so_a_caller_can_paste_what_the_build_printed() {
        let full = sha256_hex(b"hello");
        assert!(full.starts_with(&full[..16]));
    }
}
