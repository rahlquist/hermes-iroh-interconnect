//! Persistent endpoint identity (plan §3 pattern 1).
//!
//! A random 32-byte Ed25519 key is generated once per profile and stored at
//! `<state>/endpoint.key` with 0600 permissions. Restarts reuse the same
//! identity so paired peers can keep dialing. A corrupt file fails closed
//! (never silently regenerated — that would strand paired peers).

use std::path::Path;

use anyhow::{bail, Context, Result};
use iroh::SecretKey;

/// Loads the endpoint key from `path`, creating it on first use.
///
/// The file contains the raw 32 secret bytes. Existing files with wrong
/// permissions are tightened to 0600; files with wrong length are rejected.
pub fn load_or_create(path: impl AsRef<Path>) -> Result<SecretKey> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("creating identity directory")?;
    }

    if path.exists() {
        let bytes = std::fs::read(path).context("reading endpoint key")?;
        if bytes.len() != 32 {
            bail!(
                "endpoint key file {} is corrupt ({} bytes, expected 32); \
                 refusing to regenerate — restore it from backup or delete it \
                 to mint a new identity (paired peers will need re-pairing)",
                path.display(),
                bytes.len()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
            if mode != 0o600 {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(SecretKey::from_bytes(&arr));
    }

    let key = SecretKey::generate();
    std::fs::write(path, key.to_bytes()).context("writing endpoint key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}
