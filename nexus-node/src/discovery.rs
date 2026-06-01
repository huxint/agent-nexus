use std::cmp::Reverse;
use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use nexus_core::{Did, WorkspaceId};
use nexus_crypto::{verify_did_signature, NodeIdentity};
use nexus_storage::Cid;

use crate::bootstrap::{load_peer_cache, PeerCacheEntry};
use crate::ids::{parse_cid, parse_workspace_id};
use crate::state::write_file_atomic;

pub const WORKSPACE_ANNOUNCEMENT_VERSION: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceAnnouncement {
    pub version: u32,
    pub peer: String,
    #[serde(default)]
    pub addrs: Vec<String>,
    pub author: Did,
    pub workspace: String,
    pub name: String,
    pub description: String,
    pub owner: Did,
    pub root: Option<String>,
    pub timestamp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DiscoveredWorkspaceView {
    pub workspace: String,
    pub name: String,
    pub description: String,
    pub owner: Did,
    pub root: Option<String>,
    pub concurrency_model: WorkspaceConcurrencyModel,
    pub forked: bool,
    pub fork_roots: Vec<String>,
    pub latest_timestamp: u64,
    pub verified: bool,
    pub clone_ready: bool,
    pub peers: Vec<String>,
    pub addrs: Vec<String>,
    pub announcements: Vec<WorkspaceAnnouncement>,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceConcurrencyModel {
    SnapshotForks,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DiscoverySort {
    #[default]
    Relevance,
    CloneReady,
    Name,
    Owner,
    Latest,
}

#[derive(Clone, Debug, Default)]
pub struct DiscoveryFilter {
    pub workspace: Option<String>,
    pub peer: Option<String>,
    pub owner: Option<Did>,
    pub name: Option<String>,
    pub sort: DiscoverySort,
    pub verified_only: bool,
    pub clone_ready_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredCloneSource {
    pub peer: libp2p::PeerId,
    pub addrs: Vec<libp2p::Multiaddr>,
    pub owner: Did,
    pub root: Option<Cid>,
}

fn workspace_discovery_path(base: &Path) -> std::path::PathBuf {
    base.join(".nexus-workspace-discovery.json")
}

pub fn load_workspace_discovery(
    base: &Path,
) -> Result<Vec<WorkspaceAnnouncement>, Box<dyn std::error::Error>> {
    let path = workspace_discovery_path(base);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = std::fs::read(&path)?;
    let value: serde_json::Value = serde_json::from_slice(&data)?;
    let entries = value
        .get("announcements")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_else(|| value.as_array().cloned().unwrap_or_default());

    let mut announcements = Vec::new();
    for entry in entries {
        let announcement: WorkspaceAnnouncement = serde_json::from_value(entry)?;
        parse_workspace_id(&announcement.workspace)?;
        if let Some(root) = &announcement.root {
            parse_cid(root)?;
        }
        announcements.push(announcement);
    }
    Ok(announcements)
}

fn save_workspace_discovery(
    base: &Path,
    announcements: &[WorkspaceAnnouncement],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut announcements = announcements.to_vec();
    announcements.sort_by(|a, b| {
        a.workspace
            .cmp(&b.workspace)
            .then_with(|| a.peer.cmp(&b.peer))
    });

    let path = workspace_discovery_path(base);
    write_file_atomic(
        &path,
        &serde_json::to_vec_pretty(&serde_json::json!({ "announcements": announcements }))?,
    )?;
    Ok(())
}

pub fn record_workspace_announcement(
    base: &Path,
    announcement: WorkspaceAnnouncement,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut announcements = load_workspace_discovery(base)?;
    if let Some(existing) = announcements.iter_mut().find(|existing| {
        existing.peer == announcement.peer && existing.workspace == announcement.workspace
    }) {
        if existing.timestamp >= announcement.timestamp && existing.root == announcement.root {
            return Ok(false);
        }
        *existing = announcement;
    } else {
        announcements.push(announcement);
    }
    save_workspace_discovery(base, &announcements)?;
    Ok(true)
}

fn workspace_announcement_signing_payload(
    announcement: &WorkspaceAnnouncement,
) -> Result<Vec<u8>, serde_json::Error> {
    #[derive(Serialize)]
    struct Payload<'a> {
        version: u32,
        peer: &'a str,
        addrs: &'a [String],
        author: &'a Did,
        workspace: &'a str,
        name: &'a str,
        description: &'a str,
        owner: &'a Did,
        root: &'a Option<String>,
        timestamp: u64,
    }

    serde_json::to_vec(&Payload {
        version: announcement.version,
        peer: &announcement.peer,
        addrs: &announcement.addrs,
        author: &announcement.author,
        workspace: &announcement.workspace,
        name: &announcement.name,
        description: &announcement.description,
        owner: &announcement.owner,
        root: &announcement.root,
        timestamp: announcement.timestamp,
    })
}

pub fn sign_workspace_announcement(
    mut announcement: WorkspaceAnnouncement,
    identity: &NodeIdentity,
) -> Result<WorkspaceAnnouncement, Box<dyn std::error::Error>> {
    if &announcement.author != identity.did() {
        return Err("workspace announcement author does not match signer".into());
    }
    let payload = workspace_announcement_signing_payload(&announcement)?;
    announcement.signature = Some(identity.sign(&payload).to_bytes().to_vec());
    Ok(announcement)
}

pub fn verify_workspace_announcement(
    announcement: &WorkspaceAnnouncement,
) -> Result<(), Box<dyn std::error::Error>> {
    if announcement.version != WORKSPACE_ANNOUNCEMENT_VERSION {
        return Err(format!(
            "unsupported workspace announcement version {}",
            announcement.version
        )
        .into());
    }
    parse_workspace_id(&announcement.workspace)?;
    if let Some(root) = &announcement.root {
        parse_cid(root)?;
    }
    normalized_announcement_bootstrap_addrs(announcement)?;
    let signature = announcement
        .signature
        .as_deref()
        .ok_or("workspace announcement missing signature")?;
    let payload = workspace_announcement_signing_payload(announcement)?;
    verify_did_signature(&announcement.author, &payload, signature)?;
    Ok(())
}

pub fn announcement_peer_id(
    announcement: &WorkspaceAnnouncement,
) -> Result<libp2p::PeerId, Box<dyn std::error::Error>> {
    announcement
        .peer
        .parse()
        .map_err(|err| format!("invalid announcement peer {}: {err}", announcement.peer).into())
}

pub fn multiaddr_peer_id(addr: &libp2p::Multiaddr) -> Option<libp2p::PeerId> {
    addr.iter()
        .filter_map(|protocol| match protocol {
            libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .last()
}

pub fn normalized_announcement_bootstrap_addrs(
    announcement: &WorkspaceAnnouncement,
) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    let peer = announcement_peer_id(announcement)?;
    normalized_peer_bootstrap_addrs(peer, &announcement.addrs)
}

pub fn normalized_peer_bootstrap_addrs(
    peer: libp2p::PeerId,
    raw_addrs: &[String],
) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    let mut normalized = Vec::new();
    for addr in raw_addrs {
        let addr = addr.parse::<libp2p::Multiaddr>()?;
        match multiaddr_peer_id(&addr) {
            Some(addr_peer) if addr_peer != peer => {
                return Err(format!(
                    "announcement addr peer {addr_peer} does not match peer {peer}"
                )
                .into());
            }
            Some(_) => push_unique_addr(&mut normalized, addr),
            None => push_unique_addr(
                &mut normalized,
                addr.with(libp2p::multiaddr::Protocol::P2p(peer)),
            ),
        }
    }
    Ok(normalized)
}

pub fn discovered_workspace_views(
    announcements: &[WorkspaceAnnouncement],
    filter: &DiscoveryFilter,
) -> Vec<DiscoveredWorkspaceView> {
    let name_filter = filter.name.as_ref().map(|name| name.to_ascii_lowercase());
    let mut groups = std::collections::BTreeMap::<String, Vec<WorkspaceAnnouncement>>::new();

    for announcement in announcements {
        if let Some(workspace) = &filter.workspace {
            if &announcement.workspace != workspace {
                continue;
            }
        }
        if let Some(peer) = &filter.peer {
            if &announcement.peer != peer {
                continue;
            }
        }
        if let Some(owner) = &filter.owner {
            if &announcement.owner != owner {
                continue;
            }
        }
        if let Some(name) = &name_filter {
            if !announcement.name.to_ascii_lowercase().contains(name)
                && !announcement.description.to_ascii_lowercase().contains(name)
            {
                continue;
            }
        }
        groups
            .entry(announcement.workspace.clone())
            .or_default()
            .push(announcement.clone());
    }

    let mut views = Vec::with_capacity(groups.len());
    for (workspace, mut announcements) in groups {
        announcements.sort_by(|a, b| {
            b.timestamp
                .cmp(&a.timestamp)
                .then_with(|| a.peer.cmp(&b.peer))
        });
        let verified_announcements = announcements
            .iter()
            .filter(|announcement| verify_workspace_announcement(announcement).is_ok())
            .cloned()
            .collect::<Vec<_>>();
        let authoritative_announcements = if verified_announcements.is_empty() {
            announcements.as_slice()
        } else {
            verified_announcements.as_slice()
        };
        let latest = authoritative_announcements
            .first()
            .expect("grouped discovery entries cannot be empty");
        let verified = !verified_announcements.is_empty();
        let mut peers = authoritative_announcements
            .iter()
            .map(|announcement| announcement.peer.clone())
            .collect::<Vec<_>>();
        peers.sort();
        peers.dedup();
        let mut addrs = Vec::new();
        for announcement in authoritative_announcements {
            if verified {
                if let Ok(normalized) = normalized_announcement_bootstrap_addrs(announcement) {
                    addrs.extend(normalized.into_iter().map(|addr| addr.to_string()));
                }
            } else {
                addrs.extend(announcement.addrs.iter().cloned());
            }
        }
        addrs.sort();
        addrs.dedup();
        let clone_ready = verified && !addrs.is_empty();
        let fork_roots = workspace_fork_roots(authoritative_announcements);
        let forked = fork_roots.len() > 1;
        if filter.verified_only && !verified {
            continue;
        }
        if filter.clone_ready_only && !clone_ready {
            continue;
        }
        views.push(DiscoveredWorkspaceView {
            workspace,
            name: latest.name.clone(),
            description: latest.description.clone(),
            owner: latest.owner.clone(),
            root: latest.root.clone(),
            concurrency_model: WorkspaceConcurrencyModel::SnapshotForks,
            forked,
            fork_roots,
            latest_timestamp: latest.timestamp,
            verified,
            clone_ready,
            peers,
            addrs,
            announcements,
        });
    }

    sort_discovered_workspace_views(&mut views, filter.sort);
    views
}

fn workspace_fork_roots(announcements: &[WorkspaceAnnouncement]) -> Vec<String> {
    let mut roots = announcements
        .iter()
        .filter_map(|announcement| announcement.root.clone())
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    roots
}

fn sort_discovered_workspace_views(views: &mut [DiscoveredWorkspaceView], sort: DiscoverySort) {
    match sort {
        DiscoverySort::Relevance => views.sort_by(|a, b| {
            discovery_relevance_score(b)
                .cmp(&discovery_relevance_score(a))
                .then_with(|| {
                    a.name
                        .to_ascii_lowercase()
                        .cmp(&b.name.to_ascii_lowercase())
                })
                .then_with(|| b.latest_timestamp.cmp(&a.latest_timestamp))
                .then_with(|| a.workspace.cmp(&b.workspace))
        }),
        DiscoverySort::CloneReady => views.sort_by(|a, b| {
            b.clone_ready
                .cmp(&a.clone_ready)
                .then_with(|| b.verified.cmp(&a.verified))
                .then_with(|| {
                    a.name
                        .to_ascii_lowercase()
                        .cmp(&b.name.to_ascii_lowercase())
                })
                .then_with(|| b.latest_timestamp.cmp(&a.latest_timestamp))
                .then_with(|| a.workspace.cmp(&b.workspace))
        }),
        DiscoverySort::Name => views.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then_with(|| b.clone_ready.cmp(&a.clone_ready))
                .then_with(|| a.workspace.cmp(&b.workspace))
        }),
        DiscoverySort::Owner => views.sort_by(|a, b| {
            a.owner
                .to_string()
                .cmp(&b.owner.to_string())
                .then_with(|| {
                    a.name
                        .to_ascii_lowercase()
                        .cmp(&b.name.to_ascii_lowercase())
                })
                .then_with(|| a.workspace.cmp(&b.workspace))
        }),
        DiscoverySort::Latest => views.sort_by(|a, b| {
            b.latest_timestamp
                .cmp(&a.latest_timestamp)
                .then_with(|| a.workspace.cmp(&b.workspace))
        }),
    }
}

fn discovery_relevance_score(view: &DiscoveredWorkspaceView) -> u64 {
    let mut score = 0;
    if view.clone_ready {
        score += 4_000;
    }
    if view.verified {
        score += 2_000;
    }
    if view.root.is_some() {
        score += 500;
    }
    score += (view.peers.len().min(20) as u64) * 25;
    score += (view.addrs.len().min(20) as u64) * 10;
    score
}

pub fn discover_clone_source(
    base: &Path,
    workspace_id: &WorkspaceId,
    preferred_peer: Option<&libp2p::PeerId>,
) -> Result<Option<DiscoveredCloneSource>, Box<dyn std::error::Error>> {
    let peer_cache = load_peer_cache(base)
        .unwrap_or_else(|err| {
            tracing::warn!("failed to read peer cache for clone discovery: {err}");
            Vec::new()
        })
        .into_iter()
        .map(|entry| (entry.peer.clone(), entry))
        .collect::<HashMap<_, _>>();

    let mut announcements = load_workspace_discovery(base)?
        .into_iter()
        .filter(|announcement| announcement.workspace == workspace_id.to_string())
        .filter(|announcement| {
            preferred_peer
                .map(|peer| announcement.peer == peer.to_string())
                .unwrap_or(true)
        })
        .filter(|announcement| !announcement.addrs.is_empty())
        .collect::<Vec<_>>();

    announcements.sort_by(|a, b| {
        clone_source_priority(a, peer_cache.get(&a.peer))
            .cmp(&clone_source_priority(b, peer_cache.get(&b.peer)))
            .then_with(|| a.peer.cmp(&b.peer))
    });

    for announcement in announcements {
        if verify_workspace_announcement(&announcement).is_err() {
            continue;
        }
        let peer = announcement.peer.parse::<libp2p::PeerId>()?;
        let addrs = normalized_announcement_bootstrap_addrs(&announcement)?;
        let root = announcement.root.as_deref().map(parse_cid).transpose()?;
        return Ok(Some(DiscoveredCloneSource {
            peer,
            addrs,
            owner: announcement.owner,
            root,
        }));
    }

    Ok(None)
}

fn clone_source_priority(
    announcement: &WorkspaceAnnouncement,
    cache: Option<&PeerCacheEntry>,
) -> (u8, u32, Reverse<u64>, Reverse<u64>, Reverse<u64>, String) {
    let cache_rank = match cache {
        Some(entry) if entry.last_connected.is_some() && entry.failures == 0 => 0,
        Some(entry) if entry.last_connected.is_some() => 1,
        Some(entry) if entry.failures == 0 => 2,
        Some(_) => 3,
        None => 4,
    };
    let failure_rank = cache.map(|entry| entry.failures).unwrap_or(u32::MAX);
    let last_connected_rank = Reverse(cache.and_then(|entry| entry.last_connected).unwrap_or(0));
    let last_seen_rank = Reverse(cache.map(|entry| entry.last_seen).unwrap_or(0));
    let timestamp_rank = Reverse(announcement.timestamp);
    (
        cache_rank,
        failure_rank,
        last_connected_rank,
        last_seen_rank,
        timestamp_rank,
        announcement.peer.clone(),
    )
}

fn push_unique_addr(addrs: &mut Vec<libp2p::Multiaddr>, addr: libp2p::Multiaddr) {
    if !addrs.iter().any(|existing| existing == &addr) {
        addrs.push(addr);
    }
}
