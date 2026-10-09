//! Directory operations that survive a power loss.
//!
//! A rename or a new directory is an entry in its parent directory, and
//! that entry reaches disk only when the parent itself is synced: syncing
//! the files inside it does not carry the name that reaches them.

use std::io;
use std::path::Path;

/// Create `dir` and any missing ancestors, with the entry of each
/// directory it creates durable.
pub fn create_dir_durably(dir: &Path) -> io::Result<()> {
    let missing = dir
        .ancestors()
        .take_while(|ancestor| !ancestor.as_os_str().is_empty() && !ancestor.exists())
        .count();
    std::fs::create_dir_all(dir)?;
    dir.ancestors().take(missing).try_for_each(sync_parent)
}

/// Rename `from` to `to`, durably: after a power loss the entry is found
/// under `to`, never `from`.
///
/// # Errors
///
/// Returns the error the rename or the sync of `to`'s parent does.
pub fn rename_durably(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::rename(from, to)?;
    sync_parent(to)
}

fn sync_parent(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => sync_dir(parent),
        _ => Ok(()),
    }
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

// Windows opens no directory as a file, and NTFS journals its metadata.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    /// Every missing ancestor is created, and a directory already there
    /// is left as it is.
    #[test]
    fn create_dir_durably_makes_every_missing_ancestor() {
        let root = TempDir::new().unwrap();
        let dir = root.path().join("a").join("b").join("c");
        create_dir_durably(&dir).unwrap();
        assert!(dir.is_dir());
        create_dir_durably(&dir).unwrap();
        assert!(dir.is_dir());
    }
}
