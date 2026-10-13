//! The host's network key.
//!
//! One Ed25519 key per host names its endpoint. It is generated at first
//! start and kept beside the validator keys, so a restart keeps the
//! identity its peers already hold paths and address records for. It is
//! distinct from every consensus key: the transport holds it hot, and a
//! consensus key must not be exposed by it.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use hex::{decode as hex_decode, encode as hex_encode};
use iroh::SecretKey;

use crate::error::NetworkError;

/// Read the network key stored at `path`, generating and storing a fresh
/// one when the file does not exist.
///
/// The file holds the key's 32 bytes as hex. A new file is created readable
/// by its owner alone.
///
/// # Errors
///
/// Returns [`NetworkError::Key`] when the file cannot be read or written, or
/// holds something other than a key.
pub fn load_or_generate_secret_key(path: &Path) -> Result<SecretKey, NetworkError> {
    match fs::read_to_string(path) {
        Ok(text) => parse_secret_key(text.trim())
            .ok_or_else(|| NetworkError::Key(format!("{} does not hold a key", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            store(path, &key)
                .map_err(|e| NetworkError::Key(format!("cannot write {}: {e}", path.display())))?;
            Ok(key)
        }
        Err(e) => Err(NetworkError::Key(format!(
            "cannot read {}: {e}",
            path.display()
        ))),
    }
}

fn parse_secret_key(text: &str) -> Option<SecretKey> {
    let bytes: [u8; 32] = hex_decode(text).ok()?.try_into().ok()?;
    Some(SecretKey::from_bytes(&bytes))
}

fn store(path: &Path, key: &SecretKey) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(hex_encode(key.to_bytes()).as_bytes())?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn a_generated_key_is_the_one_read_back() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("network.key");

        let first = load_or_generate_secret_key(&path).expect("generates");
        let second = load_or_generate_secret_key(&path).expect("reads back");
        assert_eq!(first.public(), second.public());
    }

    #[cfg(unix)]
    #[test]
    fn a_new_key_file_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("network.key");
        load_or_generate_secret_key(&path).expect("generates");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_file_that_holds_no_key_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("network.key");
        fs::write(&path, "not a key").unwrap();
        assert!(matches!(
            load_or_generate_secret_key(&path),
            Err(NetworkError::Key(_))
        ));
    }
}
