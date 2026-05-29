//! Filesystem helpers — mapping between disk files and Merkle-DAG nodes.

use std::path::{Path, PathBuf};

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

/// Recursively remove a directory and all its contents.
#[allow(dead_code)]
pub fn remove_dir_all(path: &Path) -> Result<(), std::io::Error> {
    if path.exists() {
        std::fs::remove_dir_all(path)?;
    }
    Ok(())
}
