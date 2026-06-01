use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::discovery::{
    load_workspace_discovery, normalized_announcement_bootstrap_addrs,
    normalized_peer_bootstrap_addrs, verify_workspace_announcement, WorkspaceAnnouncement,
};
use crate::state::write_file_atomic;

const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &[];
const PUBLIC_RENDEZVOUS_ENV: &str = "NEXUS_PUBLIC_RENDEZVOUS";
const IPFS_PUBLIC_RENDEZVOUS_DNSADDR: &str = "/dnsaddr/bootstrap.libp2p.io";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerCacheEntry {
    pub peer: String,
    pub addrs: Vec<String>,
    pub last_seen: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_connected: Option<u64>,
    #[serde(default)]
    pub failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BootstrapStatus {
    pub base: String,
    pub public_defaults_enabled: bool,
    pub env_configured: bool,
    pub env_peers: Vec<String>,
    pub invite_peers: Vec<String>,
    pub config_peers: Vec<String>,
    pub peer_cache: Vec<PeerCacheEntry>,
    pub peer_cache_peers: Vec<String>,
    pub discovery_cache_peers: Vec<String>,
    pub public_rendezvous_peers: Vec<String>,
    pub public_default_peers: Vec<String>,
    pub effective_peers: Vec<String>,
}

pub fn parse_bootstrap_list(
    value: &str,
) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    let mut addrs = Vec::new();
    for item in value
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter(|item| !item.is_empty())
    {
        push_unique_bootstrap_addr(&mut addrs, item.parse()?);
    }
    Ok(addrs)
}

pub fn extend_bootstrap_peers(
    peers: &mut Vec<libp2p::Multiaddr>,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for addr in parse_bootstrap_list(value)? {
        push_unique_bootstrap_addr(peers, addr);
    }
    Ok(())
}

pub fn default_bootstrap_peers(
    base: &Path,
    use_public_defaults: bool,
) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    match std::env::var("NEXUS_BOOTSTRAP") {
        Ok(value) => return parse_bootstrap_list(&value),
        Err(std::env::VarError::NotPresent) => {}
        Err(err) => return Err(format!("read NEXUS_BOOTSTRAP: {err}").into()),
    }

    let mut addrs = Vec::new();
    for addr in peer_cache_bootstrap_peers(base) {
        push_unique_bootstrap_addr(&mut addrs, addr);
    }
    for addr in load_bootstrap_config_peers(base)? {
        push_unique_bootstrap_addr(&mut addrs, addr);
    }
    for addr in cached_workspace_bootstrap_peers(base) {
        push_unique_bootstrap_addr(&mut addrs, addr);
    }
    if use_public_defaults {
        for addr in public_rendezvous_bootstrap_peers()? {
            push_unique_bootstrap_addr(&mut addrs, addr);
        }
        for addr in public_default_bootstrap_peers()? {
            push_unique_bootstrap_addr(&mut addrs, addr);
        }
    }

    Ok(addrs)
}

pub fn bootstrap_status(
    base: &Path,
    use_public_defaults: bool,
    invite_peers: &[libp2p::Multiaddr],
) -> Result<BootstrapStatus, Box<dyn std::error::Error>> {
    let (env_configured, env_peers) = match std::env::var("NEXUS_BOOTSTRAP") {
        Ok(value) => (true, parse_bootstrap_list(&value)?),
        Err(std::env::VarError::NotPresent) => (false, Vec::new()),
        Err(err) => return Err(format!("read NEXUS_BOOTSTRAP: {err}").into()),
    };
    let config_peers = load_bootstrap_config_peers(base)?;
    let peer_cache = load_peer_cache(base)?;
    let peer_cache_peers = peer_cache_bootstrap_peers_from_entries(&peer_cache);
    let discovery_cache_peers = cached_workspace_bootstrap_peers(base);
    let (public_rendezvous_peers, public_default_peers) = if use_public_defaults {
        (
            public_rendezvous_bootstrap_peers()?,
            public_default_bootstrap_peers()?,
        )
    } else {
        (Vec::new(), Vec::new())
    };

    let mut effective_peers = Vec::new();
    if env_configured {
        for addr in &env_peers {
            push_unique_bootstrap_addr(&mut effective_peers, addr.clone());
        }
    } else {
        for addr in invite_peers {
            push_unique_bootstrap_addr(&mut effective_peers, addr.clone());
        }
        for source in [
            peer_cache_peers.as_slice(),
            config_peers.as_slice(),
            discovery_cache_peers.as_slice(),
            public_rendezvous_peers.as_slice(),
            public_default_peers.as_slice(),
        ] {
            for addr in source {
                push_unique_bootstrap_addr(&mut effective_peers, addr.clone());
            }
        }
    }

    Ok(BootstrapStatus {
        base: base.display().to_string(),
        public_defaults_enabled: use_public_defaults,
        env_configured,
        env_peers: stringify_multiaddrs(&env_peers),
        invite_peers: stringify_multiaddrs(invite_peers),
        config_peers: stringify_multiaddrs(&config_peers),
        peer_cache,
        peer_cache_peers: stringify_multiaddrs(&peer_cache_peers),
        discovery_cache_peers: stringify_multiaddrs(&discovery_cache_peers),
        public_rendezvous_peers: stringify_multiaddrs(&public_rendezvous_peers),
        public_default_peers: stringify_multiaddrs(&public_default_peers),
        effective_peers: stringify_multiaddrs(&effective_peers),
    })
}

pub fn public_rendezvous_bootstrap_peers(
) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    match std::env::var(PUBLIC_RENDEZVOUS_ENV) {
        Ok(value) => public_rendezvous_bootstrap_peers_from_value(&value),
        Err(std::env::VarError::NotPresent) => Ok(Vec::new()),
        Err(err) => Err(format!("read {PUBLIC_RENDEZVOUS_ENV}: {err}").into()),
    }
}

pub fn public_rendezvous_bootstrap_peers_from_value(
    value: &str,
) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    let mut addrs = Vec::new();
    for item in value
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter(|item| !item.is_empty())
    {
        match item {
            "off" | "none" | "disabled" => {}
            "ipfs" | "ipfs-dht" | "ipfs-mainnet" => {
                push_unique_bootstrap_addr(&mut addrs, IPFS_PUBLIC_RENDEZVOUS_DNSADDR.parse()?);
            }
            addr => push_unique_bootstrap_addr(&mut addrs, addr.parse()?),
        }
    }
    Ok(addrs)
}

fn public_default_bootstrap_peers() -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    let mut addrs = Vec::new();
    if let Some(value) = option_env!("NEXUS_DEFAULT_BOOTSTRAP") {
        for addr in parse_bootstrap_list(value)? {
            push_unique_bootstrap_addr(&mut addrs, addr);
        }
    }
    for item in DEFAULT_BOOTSTRAP_PEERS {
        push_unique_bootstrap_addr(&mut addrs, item.parse()?);
    }
    Ok(addrs)
}

pub fn bootstrap_config_path(base: &Path) -> PathBuf {
    base.join(".nexus-bootstrap.json")
}

pub fn load_bootstrap_config_peers(
    base: &Path,
) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    let path = bootstrap_config_path(base);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = std::fs::read(&path)?;
    let value: serde_json::Value = serde_json::from_slice(&data)?;
    let entries = value
        .get("peers")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_else(|| value.as_array().cloned().unwrap_or_default());

    let mut addrs = Vec::new();
    for entry in entries {
        let addr = entry
            .as_str()
            .ok_or_else(|| format!("invalid bootstrap peer in {}", path.display()))?;
        push_unique_bootstrap_addr(&mut addrs, addr.parse()?);
    }
    Ok(addrs)
}

pub fn cached_workspace_bootstrap_peers(base: &Path) -> Vec<libp2p::Multiaddr> {
    let announcements = match load_workspace_discovery(base) {
        Ok(announcements) => announcements,
        Err(err) => {
            tracing::warn!("failed to read workspace discovery bootstrap cache: {err}");
            return Vec::new();
        }
    };

    let mut addrs = Vec::new();
    for announcement in announcements {
        if verify_workspace_announcement(&announcement).is_err() {
            continue;
        }
        match normalized_announcement_bootstrap_addrs(&announcement) {
            Ok(announcement_addrs) => {
                for addr in announcement_addrs {
                    push_unique_bootstrap_addr(&mut addrs, addr);
                }
            }
            Err(err) => {
                tracing::warn!(
                    "ignored cached bootstrap addresses for {}: {err}",
                    announcement.peer
                );
            }
        }
    }
    addrs
}

fn announcement_bootstrap_addr_strings(
    announcement: &WorkspaceAnnouncement,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(normalized_announcement_bootstrap_addrs(announcement)?
        .into_iter()
        .map(|addr| addr.to_string())
        .collect())
}

pub fn peer_cache_path(base: &Path) -> PathBuf {
    base.join(".nexus-peer-cache.json")
}

pub fn load_peer_cache(base: &Path) -> Result<Vec<PeerCacheEntry>, Box<dyn std::error::Error>> {
    let path = peer_cache_path(base);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = std::fs::read(&path)?;
    let value: serde_json::Value = serde_json::from_slice(&data)?;
    let entries = value
        .get("peers")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_else(|| value.as_array().cloned().unwrap_or_default());

    let mut peers = Vec::new();
    for entry in entries {
        let mut peer = match serde_json::from_value::<PeerCacheEntry>(entry) {
            Ok(peer) => peer,
            Err(err) => {
                tracing::warn!(
                    "ignored invalid peer cache entry in {}: {err}",
                    path.display()
                );
                continue;
            }
        };
        let peer_id = match peer.peer.parse::<libp2p::PeerId>() {
            Ok(peer_id) => peer_id,
            Err(err) => {
                tracing::warn!(
                    "ignored peer cache entry with invalid peer id {}: {err}",
                    peer.peer
                );
                continue;
            }
        };
        peer.addrs = match normalized_peer_bootstrap_addrs(peer_id, &peer.addrs) {
            Ok(addrs) => addrs.into_iter().map(|addr| addr.to_string()).collect(),
            Err(err) => {
                tracing::warn!("ignored peer cache entry for {}: {err}", peer.peer);
                continue;
            }
        };
        peers.push(peer);
    }
    peers.sort_by(|a, b| a.peer.cmp(&b.peer));
    Ok(peers)
}

fn save_peer_cache(
    base: &Path,
    peers: &[PeerCacheEntry],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut peers = peers.to_vec();
    peers.sort_by(|a, b| a.peer.cmp(&b.peer));
    let path = peer_cache_path(base);
    write_file_atomic(
        &path,
        &serde_json::to_vec_pretty(&serde_json::json!({ "peers": peers }))?,
    )?;
    Ok(())
}

pub fn cache_peer_from_announcement(
    base: &Path,
    announcement: &WorkspaceAnnouncement,
    now: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let addrs = announcement_bootstrap_addr_strings(announcement)?;
    upsert_peer_cache(base, &announcement.peer, &addrs, now, None, None)
}

pub fn mark_peer_cache_connected(
    base: &Path,
    peer: libp2p::PeerId,
    now: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    upsert_peer_cache(base, &peer.to_string(), &[], now, Some(now), Some(false))
}

pub fn mark_peer_cache_failure(
    base: &Path,
    peer: libp2p::PeerId,
    now: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    upsert_peer_cache(base, &peer.to_string(), &[], now, None, Some(true))
}

pub fn upsert_peer_cache(
    base: &Path,
    peer: &str,
    addrs: &[String],
    now: u64,
    connected_at: Option<u64>,
    failed: Option<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let peer_id = peer
        .parse::<libp2p::PeerId>()
        .map_err(|err| format!("invalid peer cache id {peer}: {err}"))?;
    let normalized_addrs = normalized_peer_bootstrap_addrs(peer_id, addrs)?
        .into_iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>();
    let mut entries = load_peer_cache(base)?;
    if let Some(existing) = entries.iter_mut().find(|entry| entry.peer == peer) {
        existing.last_seen = existing.last_seen.max(now);
        if let Some(connected_at) = connected_at {
            existing.last_connected = Some(connected_at);
            existing.failures = 0;
            existing.last_failure = None;
        }
        if failed == Some(true) {
            existing.failures = existing.failures.saturating_add(1);
            existing.last_failure = Some(now);
        }
        for addr in &normalized_addrs {
            if !existing.addrs.contains(addr) {
                existing.addrs.push(addr.clone());
            }
        }
        existing.addrs.sort();
        existing.addrs.dedup();
    } else {
        let mut addrs = normalized_addrs;
        addrs.sort();
        addrs.dedup();
        entries.push(PeerCacheEntry {
            peer: peer.to_string(),
            addrs,
            last_seen: now,
            last_connected: connected_at,
            failures: u32::from(failed == Some(true)),
            last_failure: failed.and_then(|failed| failed.then_some(now)),
        });
    }
    save_peer_cache(base, &entries)
}

pub fn peer_cache_bootstrap_peers(base: &Path) -> Vec<libp2p::Multiaddr> {
    match load_peer_cache(base) {
        Ok(entries) => peer_cache_bootstrap_peers_from_entries(&entries),
        Err(err) => {
            tracing::warn!("failed to read peer bootstrap cache: {err}");
            Vec::new()
        }
    }
}

fn peer_cache_bootstrap_peers_from_entries(entries: &[PeerCacheEntry]) -> Vec<libp2p::Multiaddr> {
    let mut entries = entries.to_vec();
    entries.sort_by(|a, b| {
        a.failures
            .cmp(&b.failures)
            .then_with(|| b.last_connected.cmp(&a.last_connected))
            .then_with(|| b.last_seen.cmp(&a.last_seen))
            .then_with(|| a.peer.cmp(&b.peer))
    });

    let mut addrs = Vec::new();
    for entry in entries {
        for addr in entry.addrs {
            match addr.parse::<libp2p::Multiaddr>() {
                Ok(addr) => push_unique_bootstrap_addr(&mut addrs, addr),
                Err(err) => tracing::warn!("ignored peer cache address {addr}: {err}"),
            }
        }
    }
    addrs
}

fn stringify_multiaddrs(addrs: &[libp2p::Multiaddr]) -> Vec<String> {
    addrs.iter().map(ToString::to_string).collect()
}

fn push_unique_bootstrap_addr(addrs: &mut Vec<libp2p::Multiaddr>, addr: libp2p::Multiaddr) {
    if !addrs.iter().any(|existing| existing == &addr) {
        addrs.push(addr);
    }
}
