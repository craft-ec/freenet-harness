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

/// Read a wasm and check it against `expect`.
///
/// `expect` is not optional. A run with no check and a run whose check passed
/// print the same thing and exit the same way, so an optional gate is one
/// nobody can tell was skipped — the safe path has to be the only path.
///
/// `expect` may be a prefix — the build scripts print the first 16 hex
/// characters — so a caller can paste what the build printed.
pub fn load(path: &str, expect: &str) -> Result<Vec<u8>> {
    let want = expect.trim().to_lowercase();
    if want.is_empty() {
        bail!(
            "--expect-sha is empty. It is required: pass the sha256 that \
             freenet-contracts/build.sh printed for {path} (a prefix is enough)."
        );
    }
    if want.len() < MIN_PREFIX {
        bail!(
            "--expect-sha {want:?} is {} hex chars; at least {MIN_PREFIX} are required. \
             A short prefix matches artefacts it was never meant to.",
            want.len()
        );
    }
    if !want.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("--expect-sha {want:?} is not hex — a non-hex value can never match.");
    }
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow!("{path}: {e} — run ../freenet-contracts/build.sh first"))?;
    let got = sha256_hex(&bytes);
    println!("{path}: {} bytes  sha256={}", bytes.len(), &got[..16]);
    if !got.starts_with(&want) {
        bail!(
            "wasm mismatch: {path} is sha256 {} but --expect-sha said {want}.\n  \
             Refusing to run: a round trip against the wrong artefact reports a PASS \
             for a contract nobody ships. Rebuild with freenet-contracts/build.sh, or \
             pass the hash it printed.",
            &got[..16.min(got.len())]
        );
    }
    Ok(bytes)
}

/// Shortest prefix accepted.
///
/// A one-character `--expect-sha` matches one artefact in sixteen by luck,
/// which is a gate that passes for the wrong build often enough to be worse
/// than no gate: it prints "checked". Eight hex chars is 2^32.
const MIN_PREFIX: usize = 8;

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

    /// A file of known bytes, and the hash the build script would print for it.
    fn fixture(name: &str) -> (String, String) {
        let path = std::env::temp_dir().join(format!("wasm-check-{name}.bin"));
        std::fs::write(&path, b"not really a wasm, but the hash is real").unwrap();
        let sha = sha256_hex(&std::fs::read(&path).unwrap());
        (path.to_string_lossy().into_owned(), sha)
    }

    #[test]
    fn the_right_hash_loads() {
        let (path, sha) = fixture("right");
        let bytes = load(&path, &sha[..16]).expect("the matching hash must load");
        assert_eq!(sha256_hex(&bytes), sha);
    }

    /// The control for every refusal below: they must fail for their own
    /// reason, not because `load` refuses everything.
    #[test]
    fn a_full_length_hash_loads_too() {
        let (path, sha) = fixture("full");
        assert!(load(&path, &sha).is_ok());
        assert!(
            load(&path, &sha.to_uppercase()).is_ok(),
            "case must not matter"
        );
    }

    /// Asserted on "is empty", not on "required": the length check below also
    /// refuses an empty value and also says "required", so a test worded that
    /// way passes with this guard deleted — the bound has to be able to bite
    /// SEPARATELY or a green run says nothing about it.
    #[test]
    fn an_empty_hash_is_refused_not_treated_as_no_check() {
        let (path, _) = fixture("empty");
        let e = load(&path, "   ").unwrap_err().to_string();
        assert!(e.contains("is empty"), "{e}");
    }

    /// One hex char matches one build in sixteen by luck. A gate that passes
    /// for the wrong artefact while printing "checked" is worse than none.
    #[test]
    fn a_too_short_prefix_is_refused() {
        let (path, sha) = fixture("short");
        let e = load(&path, &sha[..1]).unwrap_err().to_string();
        assert!(e.contains("hex chars"), "{e}");
    }

    #[test]
    fn a_non_hex_value_is_refused_before_it_can_silently_never_match() {
        let (path, _) = fixture("nonhex");
        let e = load(&path, "deadbeefzz").unwrap_err().to_string();
        assert!(e.contains("not hex"), "{e}");
    }

    #[test]
    fn a_wrong_hash_refuses_to_run() {
        let (path, _) = fixture("wrong");
        let e = load(&path, "0123456789abcdef").unwrap_err().to_string();
        assert!(e.contains("wasm mismatch"), "{e}");
    }
}
