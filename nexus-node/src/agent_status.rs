use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::cli_args::required_arg;
use crate::discovery::{discovered_workspace_views, load_workspace_discovery, DiscoveryFilter};
use crate::local_state::{identity_path, local_workspace_paths};
use crate::social_sync::load_social_memory;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AgentStatusReport {
    schema: &'static str,
    base: String,
    identity: IdentityStatus,
    social_memory: SocialMemoryStatus,
    local_workspaces: Vec<LocalWorkspaceStatus>,
    discovered_workspaces: Vec<DiscoveredWorkspaceStatus>,
    control_plane: ControlPlaneStatus,
    recommended_commands: Vec<CommandHint>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct IdentityStatus {
    path: String,
    present: bool,
    did: Option<String>,
    encrypted: bool,
    legacy_plaintext: bool,
    passphrase_required: bool,
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct SocialMemoryStatus {
    path: String,
    present: bool,
    bytes: Option<u64>,
    events: Option<usize>,
    events_retained: Option<usize>,
    events_compacted: Option<usize>,
    agents: Option<usize>,
    manifests: Option<usize>,
    interactions: Option<usize>,
    workspaces: Option<usize>,
    collectives: Option<usize>,
    intents: Option<usize>,
    tasks: Option<usize>,
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct LocalWorkspaceStatus {
    path: String,
    present: bool,
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    owner: Option<String>,
    latest_root: Option<String>,
    snapshot_count: Option<usize>,
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct DiscoveredWorkspaceStatus {
    workspace: String,
    name: String,
    owner: String,
    root: Option<String>,
    verified: bool,
    clone_ready: bool,
    peers: usize,
    addrs: usize,
    latest_timestamp: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct ControlPlaneStatus {
    mode: &'static str,
    realtime_ready: bool,
    daemon_supported: bool,
    issue: &'static str,
    next_design: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct CommandHint {
    name: &'static str,
    command: String,
}

pub(crate) fn cmd_agent(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.get(2).map(String::as_str) {
        Some("status") | Some("context") => cmd_agent_status(args),
        Some(other) => Err(format!("unknown agent subcommand: {other}").into()),
        None => Err("agent subcommand required: status".into()),
    }
}

fn cmd_agent_status(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut json = false;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--json" => {
                json = true;
            }
            other => return Err(format!("unknown agent status option: {other}").into()),
        }
        i += 1;
    }

    let report = agent_status_report(&base);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_agent_status_text(&report);
    }
    Ok(())
}

pub(crate) fn agent_status_report(base: &Path) -> AgentStatusReport {
    AgentStatusReport {
        schema: "nexus.agent_status.v1",
        base: base.display().to_string(),
        identity: identity_status(base),
        social_memory: social_memory_status(base),
        local_workspaces: local_workspace_statuses(base),
        discovered_workspaces: discovered_workspace_statuses(base),
        control_plane: ControlPlaneStatus {
            mode: "foreground_serve_only",
            realtime_ready: false,
            daemon_supported: false,
            issue: "serve owns the invoking process, so agents cannot keep a conversational turn active while serving",
            next_design: "add a local daemon plus short-lived control commands over a base-scoped IPC socket",
        },
        recommended_commands: recommended_commands(base),
    }
}

fn identity_status(base: &Path) -> IdentityStatus {
    let path = identity_path(base);
    if !path.exists() {
        return IdentityStatus {
            path: path.display().to_string(),
            present: false,
            did: None,
            encrypted: false,
            legacy_plaintext: false,
            passphrase_required: false,
            error: None,
        };
    }

    match std::fs::read_to_string(&path)
        .map_err(|err| err.to_string())
        .and_then(|data| {
            serde_json::from_str::<serde_json::Value>(&data).map_err(|err| err.to_string())
        }) {
        Ok(value) => {
            let encrypted = value.get("key").is_some_and(|key| key.is_object());
            let legacy_plaintext = value.get("seed_hex").is_some_and(|seed| seed.is_string());
            IdentityStatus {
                path: path.display().to_string(),
                present: true,
                did: value
                    .get("did")
                    .and_then(|did| did.as_str())
                    .map(str::to_string),
                encrypted,
                legacy_plaintext,
                passphrase_required: encrypted || legacy_plaintext,
                error: None,
            }
        }
        Err(error) => IdentityStatus {
            path: path.display().to_string(),
            present: true,
            did: None,
            encrypted: false,
            legacy_plaintext: false,
            passphrase_required: false,
            error: Some(error),
        },
    }
}

fn social_memory_status(base: &Path) -> SocialMemoryStatus {
    let path = base.join(".nexus-social-memory.json");
    let present = path.exists();
    let bytes = std::fs::metadata(&path).map(|metadata| metadata.len()).ok();
    match load_social_memory(&path) {
        Ok(memory) => {
            let society = memory.society();
            SocialMemoryStatus {
                path: path.display().to_string(),
                present,
                bytes,
                events: Some(memory.event_count()),
                events_retained: Some(memory.retained_event_count()),
                events_compacted: Some(memory.compacted_event_count()),
                agents: Some(society.agent_count()),
                manifests: Some(society.manifest_count()),
                interactions: Some(society.interaction_count()),
                workspaces: Some(society.workspace_ids().len()),
                collectives: Some(society.collectives().len()),
                intents: Some(society.intents().len()),
                tasks: Some(society.task_count()),
                error: None,
            }
        }
        Err(error) => SocialMemoryStatus {
            path: path.display().to_string(),
            present,
            bytes,
            events: None,
            events_retained: None,
            events_compacted: None,
            agents: None,
            manifests: None,
            interactions: None,
            workspaces: None,
            collectives: None,
            intents: None,
            tasks: None,
            error: Some(error.to_string()),
        },
    }
}

fn local_workspace_statuses(base: &Path) -> Vec<LocalWorkspaceStatus> {
    match local_workspace_paths(base) {
        Ok(paths) => paths
            .into_iter()
            .map(|path| local_workspace_status(&path))
            .collect(),
        Err(error) => vec![LocalWorkspaceStatus {
            path: base.display().to_string(),
            present: base.exists(),
            id: None,
            name: None,
            description: None,
            owner: None,
            latest_root: None,
            snapshot_count: None,
            error: Some(error.to_string()),
        }],
    }
}

fn local_workspace_status(path: &Path) -> LocalWorkspaceStatus {
    let config_path = path.join(".nexus").join("config.json");
    match std::fs::read_to_string(&config_path)
        .map_err(|err| err.to_string())
        .and_then(|data| {
            serde_json::from_str::<serde_json::Value>(&data).map_err(|err| err.to_string())
        }) {
        Ok(value) => {
            let snapshots = value
                .get("snapshot_history")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default();
            LocalWorkspaceStatus {
                path: path.display().to_string(),
                present: path.exists(),
                id: value
                    .get("id")
                    .and_then(|id| id.as_str())
                    .map(str::to_string),
                name: value
                    .get("name")
                    .and_then(|name| name.as_str())
                    .map(str::to_string),
                description: value
                    .get("description")
                    .and_then(|description| description.as_str())
                    .map(str::to_string),
                owner: value
                    .get("owner")
                    .and_then(|owner| owner.as_str())
                    .map(str::to_string),
                latest_root: snapshots
                    .last()
                    .and_then(|root| root.as_str())
                    .map(str::to_string),
                snapshot_count: Some(snapshots.len()),
                error: None,
            }
        }
        Err(error) => LocalWorkspaceStatus {
            path: path.display().to_string(),
            present: path.exists(),
            id: None,
            name: None,
            description: None,
            owner: None,
            latest_root: None,
            snapshot_count: None,
            error: Some(format!("read {}: {error}", config_path.display())),
        },
    }
}

fn discovered_workspace_statuses(base: &Path) -> Vec<DiscoveredWorkspaceStatus> {
    load_workspace_discovery(base)
        .map(|announcements| {
            discovered_workspace_views(&announcements, &DiscoveryFilter::default())
                .into_iter()
                .map(|workspace| DiscoveredWorkspaceStatus {
                    workspace: workspace.workspace,
                    name: workspace.name,
                    owner: workspace.owner.to_string(),
                    root: workspace.root,
                    verified: workspace.verified,
                    clone_ready: workspace.clone_ready,
                    peers: workspace.peers.len(),
                    addrs: workspace.addrs.len(),
                    latest_timestamp: workspace.latest_timestamp,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn recommended_commands(base: &Path) -> Vec<CommandHint> {
    let base = base.display();
    vec![
        CommandHint {
            name: "status",
            command: format!("nexus-node agent status --base {base} --json"),
        },
        CommandHint {
            name: "society",
            command: format!("nexus-node society --base {base} --json --intent-limit 10"),
        },
        CommandHint {
            name: "discover_lan",
            command: format!("nexus-node discover --base {base} --lan --json --timeout-ms 3000"),
        },
        CommandHint {
            name: "serve_foreground",
            command: format!("nexus-node serve --base {base} --listen /ip4/0.0.0.0/udp/0/quic-v1"),
        },
    ]
}

fn print_agent_status_text(report: &AgentStatusReport) {
    println!("Agent status: {}", report.base);
    println!(
        "identity: {}",
        report
            .identity
            .did
            .as_deref()
            .unwrap_or(if report.identity.present {
                "unreadable"
            } else {
                "missing"
            })
    );
    println!(
        "social_memory: events={} agents={} tasks={} workspaces={}",
        display_count(report.social_memory.events),
        display_count(report.social_memory.agents),
        display_count(report.social_memory.tasks),
        display_count(report.social_memory.workspaces)
    );
    println!("local_workspaces: {}", report.local_workspaces.len());
    for workspace in &report.local_workspaces {
        println!(
            "  {}  {}  root={}",
            workspace.id.as_deref().unwrap_or("unknown-workspace"),
            workspace.name.as_deref().unwrap_or("unnamed"),
            workspace.latest_root.as_deref().unwrap_or("-")
        );
    }
    println!(
        "discovered_workspaces: {}",
        report.discovered_workspaces.len()
    );
    println!(
        "control_plane: mode={} realtime_ready={}",
        report.control_plane.mode, report.control_plane.realtime_ready
    );
    println!("recommended:");
    for hint in &report.recommended_commands {
        println!("  {}: {}", hint.name, hint.command);
    }
}

fn display_count(value: Option<usize>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_does_not_create_identity() {
        let temp = tempfile::TempDir::new().unwrap();

        let report = agent_status_report(temp.path());

        assert!(!report.identity.present);
        assert!(!identity_path(temp.path()).exists());
        assert_eq!(report.control_plane.mode, "foreground_serve_only");
    }

    #[test]
    fn status_reads_workspace_metadata_without_identity_passphrase() {
        let temp = tempfile::TempDir::new().unwrap();
        let workspace = temp.path().join("workspace-a");
        std::fs::create_dir_all(workspace.join(".nexus")).unwrap();
        std::fs::write(
            workspace.join(".nexus/config.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "name": "workspace-a",
                "description": "status test",
                "id": "1111111111111111111111111111111111111111111111111111111111111111",
                "owner": "did:key:z6Mktest",
                "snapshot_history": [
                    "2222222222222222222222222222222222222222222222222222222222222222"
                ],
                "snapshot_retention_limit": 32
            }))
            .unwrap(),
        )
        .unwrap();

        let report = agent_status_report(temp.path());

        assert_eq!(report.local_workspaces.len(), 1);
        assert_eq!(
            report.local_workspaces[0].id.as_deref(),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(
            report.local_workspaces[0].latest_root.as_deref(),
            Some("2222222222222222222222222222222222222222222222222222222222222222")
        );
        assert_eq!(report.social_memory.events, Some(0));
    }
}
