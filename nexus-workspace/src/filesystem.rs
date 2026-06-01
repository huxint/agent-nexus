//! Filesystem helpers — mapping between disk files and Merkle-DAG nodes.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A lightweight file entry returned when listing a directory.
#[derive(Clone, Debug)]
pub struct FileEntry {
    /// Name of the file or directory.
    pub name: String,
    /// Full path relative to workspace root.
    pub path: PathBuf,
    /// Whether it's a file or directory.
    pub is_dir: bool,
    /// File size in bytes (0 for directories).
    pub size: u64,
}

/// Recursively list all files under `root`, returning entries relative to `root`.
pub fn list_files(root: &Path) -> Result<Vec<FileEntry>, std::io::Error> {
    let mut entries = Vec::new();
    list_files_recursive(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

fn list_files_recursive(
    base: &Path,
    current: &Path,
    entries: &mut Vec<FileEntry>,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if current == base && name == ".nexus" {
            continue;
        }

        let file_type = entry.file_type()?;
        if file_type.is_symlink() || (!file_type.is_dir() && !file_type.is_file()) {
            continue;
        }

        let path = entry.path();
        let metadata = entry.metadata()?;
        let relative = path.strip_prefix(base).unwrap_or(&path);

        entries.push(FileEntry {
            name,
            path: relative.to_path_buf(),
            is_dir: metadata.is_dir(),
            size: metadata.len(),
        });

        if metadata.is_dir() {
            list_files_recursive(base, &path, entries)?;
        }
    }
    Ok(())
}

/// Ensure a directory exists, creating it and all parents as needed.
pub fn ensure_dir(path: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(path)
}

/// Atomically replace a file in place, flushing both the file and parent
/// directory where the platform supports it.
pub fn write_file_atomic(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path =
        path.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));

    let result = (|| {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, path)?;
        sync_parent_dir(path);
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }

    result
}

fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    #[cfg(not(unix))]
    let _ = path;
}

/// Recursively remove a directory and all its contents.
#[allow(dead_code)]
pub fn remove_dir_all(path: &Path) -> Result<(), std::io::Error> {
    if path.exists() {
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}
