//! Directory operations that survive a power loss.
//!
//! A rename or a new directory is an entry in its parent directory, and
//! that entry reaches disk only when the parent itself is synced: syncing
//! the files inside it does not carry the name that reaches them.

use std::io;
use std::path::Path;

/// Create `dir` and any missing ancestors, with its own entry durable.
pub fn create_dir_durably(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    sync_parent(dir)
}

/// Rename `from` to `to`, durably: after a power loss the entry is found
/// under `to`, never `from`.
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
