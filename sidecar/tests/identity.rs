//! RED tests for the sidecar's persistent-identity layer.
//!
//! Contract (plan §3 pattern 1): a random 32-byte endpoint key is generated
//! once per profile and stored with restrictive permissions; restarts reuse
//! the SAME identity.

use hermes_iroh_sidecar::identity;

#[test]
fn creates_and_reuses_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("endpoint.key");

    let first = identity::load_or_create(&path).unwrap();
    let second = identity::load_or_create(&path).unwrap();

    assert_eq!(
        first.to_bytes(),
        second.to_bytes(),
        "identity must be stable across loads"
    );
}

#[test]
fn identity_file_has_restrictive_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("endpoint.key");

    let _ = identity::load_or_create(&path).unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "endpoint key must be 0600");
}

#[test]
fn identity_is_a_valid_ed25519_keypair() {
    let dir = tempfile::tempdir().unwrap();
    let key = identity::load_or_create(dir.path().join("k")).unwrap();
    // The public half must be derivable and stable.
    let id1 = key.public().to_z32();
    let id2 = identity::load_or_create(dir.path().join("k")).unwrap().public().to_z32();
    assert_eq!(id1, id2);
    assert_eq!(id1.len(), 52, "z-base32 endpoint id length");
}

#[test]
fn rejects_corrupt_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("endpoint.key");
    std::fs::write(&path, vec![0u8; 10]).unwrap(); // wrong length
    assert!(identity::load_or_create(&path).is_err());
}
