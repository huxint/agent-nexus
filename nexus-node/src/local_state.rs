use std::path::{Path, PathBuf};

use nexus_crypto::NodeIdentity;

use crate::state::write_file_atomic;

pub fn identity_path(base: &Path) -> PathBuf {
    base.join(".nexus-identity.json")
}

fn workspace_registry_path(base: &Path) -> PathBuf {
    base.join(".nexus-workspaces.json")
}

pub fn normalize_workspace_path(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(std::fs::canonicalize(path)?)
}

fn load_workspace_registry(base: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let path = workspace_registry_path(base);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = std::fs::read(&path)?;
    let value: serde_json::Value = serde_json::from_slice(&data)?;
    let entries = value
        .get("workspaces")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_else(|| value.as_array().cloned().unwrap_or_default());

    let mut paths = Vec::new();
    for entry in entries {
        if let Some(path) = entry.as_str() {
            paths.push(PathBuf::from(path));
        }
    }
    Ok(paths)
}

fn save_workspace_registry(
    base: &Path,
    paths: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries = paths
        .iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect::<Vec<_>>();
    entries.sort();
    entries.dedup();

    let path = workspace_registry_path(base);
    write_file_atomic(
        &path,
        &serde_json::to_vec_pretty(&serde_json::json!({ "workspaces": entries }))?,
    )?;
    Ok(())
}

pub fn register_workspace_path(
    base: &Path,
    workspace_path: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    let normalized = normalize_workspace_path(workspace_path)?;
    let mut paths = load_workspace_registry(base)?
        .into_iter()
        .filter_map(|path| normalize_workspace_path(&path).ok())
        .collect::<Vec<_>>();

    if paths.iter().any(|path| path == &normalized) {
        return Ok(false);
    }

    paths.push(normalized);
    save_workspace_registry(base, &paths)?;
    Ok(true)
}

pub fn local_workspace_paths(base: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut paths = load_workspace_registry(base)?
        .into_iter()
        .filter_map(|path| normalize_workspace_path(&path).ok())
        .collect::<Vec<_>>();

    if let Ok(entries) = std::fs::read_dir(base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join(".nexus").is_dir() {
                if let Ok(path) = normalize_workspace_path(&path) {
                    paths.push(path);
                }
            }
        }
    }

    paths.sort();
    paths.dedup();
    Ok(paths)
}

pub fn load_or_create_identity(base: &Path) -> Result<NodeIdentity, Box<dyn std::error::Error>> {
    let id_path = identity_path(base);
    let passphrase = identity_passphrase()?;
    if id_path.exists() {
        Ok(NodeIdentity::load_from_file_with_passphrase(
            &id_path,
            &passphrase,
        )?)
    } else {
        let id = NodeIdentity::generate();
        save_identity_with_passphrase(base, &id, &passphrase)?;
        Ok(id)
    }
}

pub fn save_identity(
    base: &Path,
    identity: &NodeIdentity,
) -> Result<(), Box<dyn std::error::Error>> {
    let passphrase = identity_passphrase()?;
    save_identity_with_passphrase(base, identity, &passphrase)
}

fn save_identity_with_passphrase(
    base: &Path,
    identity: &NodeIdentity,
    passphrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let id_path = identity_path(base);
    identity.save_to_file_with_passphrase(&id_path, passphrase)?;
    Ok(())
}

fn identity_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(passphrase) = std::env::var("NEXUS_PASSPHRASE") {
        if passphrase.is_empty() {
            return Err("NEXUS_PASSPHRASE must not be empty".into());
        }
        return Ok(passphrase);
    }

    #[cfg(test)]
    {
        Ok("nexus-test-passphrase".into())
    }

    #[cfg(not(test))]
    {
        use std::io::{IsTerminal, Write};

        if !std::io::stdin().is_terminal() {
            return Err("NEXUS_PASSPHRASE is required when stdin is not interactive".into());
        }

        eprint!("Identity passphrase: ");
        std::io::stderr().flush()?;
        let mut passphrase = String::new();
        std::io::stdin().read_line(&mut passphrase)?;
        let passphrase = passphrase.trim_end_matches(['\r', '\n']).to_string();
        if passphrase.is_empty() {
            return Err("identity passphrase must not be empty".into());
        }
        Ok(passphrase)
    }
}
