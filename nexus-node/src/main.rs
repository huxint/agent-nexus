//! Nexus Node — a complete AI workspace node.
//!
//! Usage:
//!   nexus-node create --name <name> [--base <dir>]
//!   nexus-node serve  --base <dir> [--listen <addr>] [--bootstrap <addr>] [--no-public-bootstrap]
//!   nexus-node society --base <dir> [--json] [--agent <did>] [--workspace <hex>] [--task <id>] [--intent-limit <n>]
//!   nexus-node join --base <dir> --workspace <path>
//!   nexus-node clone --base <dir> [--global|--lan] [--peer <peer-id>] [--bootstrap <addr>] [--no-public-bootstrap] --workspace <hex> --name <name>
//!   nexus-node exec --base <dir> --workspace <path> [--cwd <dir>] [--env KEY=VALUE] [--stdin <text>|--stdin-file <path>] [--timeout-ms <n>] -- <command> [args...]
//!   nexus-node discover --base <dir> [--global|--lan] [--bootstrap <addr>] [--no-public-bootstrap] [--sort <mode>] [--json] [--verified] [--clone-ready] [--workspace <hex>] [--peer <peer-id>] [--owner <did>] [--name <text>]
//!   nexus-node bootstrap status --base <dir> [--json] [--no-public-bootstrap]
//!   nexus-node event manifest|intent|intent-response|workspace-join|workspace-snapshot|workspace-run|capability|collective|collective-join|collective-workspace|collective-proposal|collective-vote|collective-decision|relation|interaction|task-publish|task-offer|task-accept|task-cancel|task-complete|task-dispute --base <dir> ...
//!   nexus-node act --base <dir> --intent <id> --kind <respond-intent|offer-task|join-workspace|propose-collective> ...
//!   nexus-node demo   (runs a self-contained two-node demo)

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use nexus_agent::{
    random_social_id, task_result_claim_id, AgentIntent, AgentManifest, CapabilityDecl,
    CapabilityGrant, Collective, CollectiveDecision, CollectiveDecisionOutcome, CollectiveProposal,
    CollectiveVote, CollectiveVoteChoice, ExecutionReceipt, GovernanceSignal, IntentActionKind,
    IntentActionPlan, IntentKind, IntentRecommendation, IntentResponse, IntentResponseKind,
    Interaction, InteractionOutcome, ProviderRecommendation, RelationKind, ReputationScore,
    SettlementRecord, SocialEdge, SocialEvent, SocialEventKind, SocialMemory, TaskClaimJudgment,
    TaskDispute, WorkspaceRun, WorkspaceRunContext, WorkspaceRunFailure, WorkspaceRunStdin,
    WorkspaceSnapshot,
};
use nexus_agent::{Task, TaskAcceptance, TaskCancellation, TaskOffer, TaskResult, TaskSpec};
use nexus_core::{Did, PermissionSet, WorkspaceId};
use nexus_crypto::capability::sign_capability;
use nexus_crypto::verify_did_signature;
use nexus_crypto::NodeIdentity;
use nexus_economy::SettlementProof;
use nexus_network::{
    global_discovery_key, workspace_discovery_key, Network, NetworkConfig, NetworkEvent,
};
use nexus_runtime::{ExecError, ExecOptions, ProcessOutput, ResourceUsage};
use nexus_storage::{BlockStore, Cid, DiskBlockStore};
use nexus_sync::codec::MAX_SYNC_MESSAGE_BYTES;
use nexus_sync::message::{SyncRequest, SyncResponse};
use nexus_sync::SyncClient;
use nexus_workspace::{
    Workspace, WorkspaceConfig, WorkspaceError, WorkspaceServer, WorkspaceState,
};

const WORKSPACE_ANNOUNCEMENT_VERSION: u32 = 2;
const WORKSPACE_OBSERVE_INTERVAL: Duration = Duration::from_secs(15);
const MAX_SOCIAL_EVENTS_PER_RESPONSE: usize = 512;
const MAX_WORKSPACE_ANNOUNCEMENTS_PER_RESPONSE: usize = 256;
const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &[];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct WorkspaceAnnouncement {
    version: u32,
    peer: String,
    #[serde(default)]
    addrs: Vec<String>,
    author: Did,
    workspace: String,
    name: String,
    description: String,
    owner: Did,
    root: Option<String>,
    timestamp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct DiscoveredWorkspaceView {
    workspace: String,
    name: String,
    description: String,
    owner: Did,
    root: Option<String>,
    latest_timestamp: u64,
    verified: bool,
    clone_ready: bool,
    peers: Vec<String>,
    addrs: Vec<String>,
    announcements: Vec<WorkspaceAnnouncement>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum DiscoverySort {
    #[default]
    Relevance,
    CloneReady,
    Name,
    Owner,
    Latest,
}

#[derive(Clone, Debug, Default)]
struct DiscoveryFilter {
    workspace: Option<String>,
    peer: Option<String>,
    owner: Option<Did>,
    name: Option<String>,
    sort: DiscoverySort,
    verified_only: bool,
    clone_ready_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DiscoveredCloneSource {
    peer: libp2p::PeerId,
    addrs: Vec<libp2p::Multiaddr>,
    owner: Did,
    root: Option<Cid>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PeerCacheEntry {
    peer: String,
    addrs: Vec<String>,
    last_seen: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_connected: Option<u64>,
    #[serde(default)]
    failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_failure: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct BootstrapStatus {
    base: String,
    public_defaults_enabled: bool,
    env_configured: bool,
    env_peers: Vec<String>,
    config_peers: Vec<String>,
    peer_cache: Vec<PeerCacheEntry>,
    peer_cache_peers: Vec<String>,
    discovery_cache_peers: Vec<String>,
    public_default_peers: Vec<String>,
    effective_peers: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "create" => cmd_create(&args).await?,
        "join" => cmd_join(&args).await?,
        "clone" => cmd_clone(&args).await?,
        "exec" => cmd_exec(&args).await?,
        "serve" => cmd_serve(&args).await?,
        "discover" => cmd_discover(&args).await?,
        "bootstrap" => cmd_bootstrap(&args)?,
        "society" => cmd_society(&args)?,
        "act" => cmd_act(&args)?,
        "event" => cmd_event(&args)?,
        "demo" => cmd_demo().await?,
        _ => print_usage(&args[0]),
    }
    Ok(())
}

fn print_usage(prog: &str) {
    eprintln!("nexus-node — AI workspace node");
    eprintln!("  {prog} create --name <NAME> [--base <DIR>]");
    eprintln!("  {prog} join --base <DIR> --workspace <PATH>");
    eprintln!("  {prog} clone --base <DIR> [--global|--lan] [--peer <PEER_ID>] [--bootstrap <ADDR>] [--no-public-bootstrap] --workspace <HEX> --name <NAME> [--listen <ADDR>] [--timeout-ms <N>] [--description <TEXT>]");
    eprintln!("  {prog} exec --base <DIR> --workspace <PATH> [--cwd <DIR>] [--env KEY=VALUE] [--stdin <TEXT>|--stdin-file <PATH>] [--timeout-ms <N>] [--note <TEXT>] -- <CMD> [ARG...]");
    eprintln!("  {prog} serve  --base <DIR> [--listen <ADDR>] [--bootstrap <ADDR>] [--no-public-bootstrap]");
    eprintln!("  {prog} discover --base <DIR> [--global|--lan] [--bootstrap <ADDR>] [--no-public-bootstrap] [--listen <ADDR>] [--timeout-ms <N>] [--sort <relevance|clone-ready|name|owner|latest>] [--json] [--verified] [--clone-ready] [--workspace <HEX>] [--peer <PEER_ID>] [--owner <DID>] [--name <TEXT>]");
    eprintln!("  {prog} bootstrap status --base <DIR> [--json] [--no-public-bootstrap]");
    eprintln!(
        "  {prog} society --base <DIR> [--json] [--agent <DID>] [--workspace <HEX>] [--task <ID>] [--activity-limit <N>] [--activity-since <TS>] [--intent-limit <N>]"
    );
    eprintln!("  {prog} act --base <DIR> --intent <ID> --kind <respond-intent|offer-task|join-workspace|propose-collective> [--body <TEXT>] [--price <N>] [--eta <SECS>] [--collective <ID>] [--proposal <ID>] [--deadline <TS>]");
    eprintln!("  {prog} event manifest --base <DIR> [--name <NAME>] [--description <TEXT>] [--provide <NAME>] [--goal <TEXT>] [--value <TEXT>] [--preference <TEXT>] [--role <TEXT>]");
    eprintln!("  {prog} event intent --base <DIR> --kind <goal|need|offer|proposal|status> --title <TEXT> [--body <TEXT>] [--workspace <HEX>] [--task <ID>] [--capability <NAME>] [--tag <TEXT>...] [--expires-at <TS>]");
    eprintln!("  {prog} event intent-response --base <DIR> --intent <ID> --kind <interested|accept|decline|counter|fulfilled> [--body <TEXT>] [--workspace <HEX>] [--task <ID>] [--capability <NAME>] [--evidence <TEXT>]");
    eprintln!("  {prog} event workspace-join --base <DIR> --workspace <HEX>");
    eprintln!("  {prog} event workspace-snapshot --base <DIR> --workspace <HEX> --root <CID_HEX> [--label <TEXT>] [--note <TEXT>]");
    eprintln!("  {prog} event workspace-run --base <DIR> --workspace <HEX> --command <CMD> [--arg <ARG>...] [--exit-code <N>] [--stdout <TEXT>|--stdout-cid <CID_HEX>] [--stderr <TEXT>|--stderr-cid <CID_HEX>] [--output-root <CID_HEX>] [--cwd <DIR>] [--env-key <KEY>] [--stdin <TEXT>|--stdin-cid <CID_HEX> --stdin-bytes <N>] [--timeout-ms <N>] [--failure-kind <KIND> --failure-message <TEXT>] [--started-at <TS>] [--finished-at <TS>] [--note <TEXT>]");
    eprintln!("  {prog} event capability --base <DIR> --subject <DID> --workspace <HEX> [--permission <PERM>...] [--expires-at <TS>] [--note <TEXT>]");
    eprintln!("  {prog} event collective --base <DIR> --id <ID> --name <NAME> --purpose <TEXT>");
    eprintln!("  {prog} event collective-join --base <DIR> --id <ID>");
    eprintln!("  {prog} event collective-workspace --base <DIR> --id <ID> --workspace <HEX>");
    eprintln!("  {prog} event collective-proposal --base <DIR> --collective <ID> --proposal <ID> --title <TEXT> --body <TEXT> [--workspace <HEX>] [--deadline <TS>]");
    eprintln!("  {prog} event collective-vote --base <DIR> --collective <ID> --proposal <ID> --choice <CHOICE> [--rationale <TEXT>]");
    eprintln!("  {prog} event collective-decision --base <DIR> --collective <ID> --proposal <ID> --outcome <OUTCOME> [--reason <TEXT>] [--task <ID>] [--claim <CLAIM_ID>] [--target <DID>]");
    eprintln!("  {prog} event relation --base <DIR> --peer <DID> --kind <KIND> [--note <TEXT>]");
    eprintln!("  {prog} event interaction --base <DIR> --peer <DID> --topic <TEXT> --outcome <OUTCOME> [--workspace <HEX>] [--evidence <TEXT>]");
    eprintln!("  {prog} event task-publish --base <DIR> --description <TEXT> --capability <NAME> --command <CMD> [--arg <ARG>...] --max-budget <N> [--deadline <TS>]");
    eprintln!("  {prog} event task-offer --base <DIR> --task <ID> --price <N> [--eta <SECS>] [--rationale <TEXT>]");
    eprintln!("  {prog} event task-accept --base <DIR> --task <ID> --bidder <DID> --price <N>");
    eprintln!("  {prog} event task-cancel --base <DIR> --task <ID> --reason <TEXT>");
    eprintln!("  {prog} event task-complete --base <DIR> --task <ID> (--success|--failure) [--exit-code <N>] [--stdout <TEXT>] [--stderr <TEXT>] [--actual-cost <N>] [--error <TEXT>] [--receipt --command <CMD> [--arg <ARG>...] [--workspace <HEX>] [--output-root <CID_HEX>] [--started-at <TS>] [--finished-at <TS>]]");
    eprintln!("  {prog} event task-dispute --base <DIR> --task <ID> --target <DID> --reason <TEXT> [--claim <CLAIM_ID>] [--evidence <TEXT>]");
    eprintln!("  {prog} event settlement --base <DIR> --payee <DID> --amount <N> [--task <ID>] [--claim <CLAIM_ID>] [--id <ID>] [--proof sovereign]");
    eprintln!("  {prog} demo");
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

async fn cmd_create(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut name = None;
    let mut base = PathBuf::from(".");
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                i += 1;
                name = Some(required_arg(args, i, "--name")?.to_string());
            }
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            o => {
                eprintln!("unknown: {o}");
                return Ok(());
            }
        }
        i += 1;
    }
    let name = name.ok_or("--name required")?;
    let id = load_or_create_identity(&base)?;
    println!("Identity: {}", id.did());
    let ws = Workspace::create(
        &id,
        &base,
        WorkspaceConfig {
            name: name.clone(),
            description: format!("Workspace '{name}'"),
        },
    )
    .await?;
    register_workspace_path(&base, ws.root_dir())?;
    println!("Created: {} ({})", ws.name(), ws.id());
    Ok(())
}

// ---------------------------------------------------------------------------
// join
// ---------------------------------------------------------------------------

async fn cmd_join(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut workspace_path = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--workspace" => {
                i += 1;
                workspace_path = Some(PathBuf::from(required_arg(args, i, "--workspace")?));
            }
            other => return Err(format!("unknown join option: {other}").into()),
        }
        i += 1;
    }

    let workspace_path = workspace_path.ok_or("--workspace required")?;
    let identity = load_or_create_identity(&base)?;
    let memory_path = base.join(".nexus-social-memory.json");
    let mut memory = load_social_memory(&memory_path)?;
    let mut workspace = Workspace::load(&identity, &workspace_path).await?;
    let now = unix_now();

    workspace.join_agent(identity.did(), now)?;
    register_workspace_path(&base, workspace.root_dir())?;
    let event = SocialEvent::new(
        identity.did().clone(),
        now,
        SocialEventKind::WorkspaceJoined {
            workspace: workspace.id(),
        },
    )
    .sign(&identity)?;
    if memory.ingest_event(event.clone())? {
        save_social_memory(&memory_path, &memory)?;
    }

    println!(
        "Joined workspace {} as {} ({})",
        workspace.id(),
        identity.did(),
        event.id
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// clone
// ---------------------------------------------------------------------------

async fn cmd_clone(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut listen = "/ip4/0.0.0.0/udp/0/quic-v1".to_string();
    let mut bootstrap = Vec::new();
    let mut peer = None;
    let mut workspace_id = None;
    let mut name = None;
    let mut description = None;
    let mut online = false;
    let mut use_public_bootstrap = true;
    let mut discovery_timeout = DEFAULT_DISCOVERY_TIMEOUT;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--listen" => {
                i += 1;
                listen = required_arg(args, i, "--listen")?.to_string();
            }
            "--bootstrap" => {
                i += 1;
                bootstrap.push(required_arg(args, i, "--bootstrap")?.parse()?);
                online = true;
            }
            "--no-public-bootstrap" => {
                use_public_bootstrap = false;
            }
            "--peer" => {
                i += 1;
                peer = Some(required_arg(args, i, "--peer")?.parse()?);
            }
            "--global" | "--online" | "--lan" => {
                online = true;
            }
            "--timeout-ms" => {
                i += 1;
                let millis = parse_u64_arg(required_arg(args, i, "--timeout-ms")?, "--timeout-ms")?;
                discovery_timeout = Duration::from_millis(millis);
            }
            "--workspace" => {
                i += 1;
                workspace_id = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--name" => {
                i += 1;
                name = Some(required_arg(args, i, "--name")?.to_string());
            }
            "--description" => {
                i += 1;
                description = Some(required_arg(args, i, "--description")?.to_string());
            }
            other => return Err(format!("unknown clone option: {other}").into()),
        }
        i += 1;
    }

    let workspace_id = workspace_id.ok_or("--workspace required")?;
    let name = name.ok_or("--name required")?;
    if bootstrap.is_empty() {
        bootstrap = default_bootstrap_peers(&base, use_public_bootstrap)?;
        if !bootstrap.is_empty() && peer.is_none() {
            online = true;
        }
    }
    let mut discovered_source = None;
    let mut peer_ready = false;
    if peer.is_none() || bootstrap.is_empty() {
        if let Some(discovered) = discover_clone_source(&base, &workspace_id, peer.as_ref())? {
            if peer.is_none() {
                peer = Some(discovered.peer);
            }
            if bootstrap.is_empty() {
                bootstrap = discovered.addrs.clone();
            }
            discovered_source = Some(discovered);
        }
    }
    let identity = load_or_create_identity(&base)?;
    let mut network = None;
    if peer.is_none() && online {
        let online_network = Network::new(
            &identity,
            NetworkConfig {
                listen_addr: listen.parse()?,
                bootstrap_peers: bootstrap.clone(),
                ..Default::default()
            },
        )
        .await?;
        refresh_online_discovery(
            &base,
            &online_network,
            Some(workspace_id),
            None,
            discovery_timeout,
        )
        .await?;
        if let Some(discovered) = discover_clone_source(&base, &workspace_id, None)? {
            let discovered_peer = discovered.peer;
            peer = Some(discovered_peer);
            if bootstrap.is_empty() {
                bootstrap = discovered.addrs.clone();
            }
            discovered_source = Some(discovered);
            peer_ready = online_network.is_connected(discovered_peer);
        }
        network = Some(online_network);
    }
    let peer = peer.ok_or("--peer required or discoverable workspace announcement required")?;
    if bootstrap.is_empty() && !peer_ready {
        return Err(
            "--bootstrap required or discoverable workspace announcement with addrs required"
                .into(),
        );
    }
    let network = match network {
        Some(network) => network,
        None => {
            Network::new(
                &identity,
                NetworkConfig {
                    listen_addr: listen.parse()?,
                    bootstrap_peers: bootstrap,
                    ..Default::default()
                },
            )
            .await?
        }
    };

    if !peer_ready {
        wait_for_peer_connected(&network, peer, Duration::from_secs(15)).await?;
    }
    let memory_path = base.join(".nexus-social-memory.json");
    let mut memory = load_social_memory(&memory_path)?;
    let synced_social_events =
        request_social_events_from_peer(&network, peer, &mut memory, &memory_path).await;
    if synced_social_events > 0 {
        tracing::info!(
            "synced {synced_social_events} social events before cloning workspace {}",
            workspace_id
        );
    }

    let client = SyncClient::new(network.sync_request_channel());
    let state = client.get_state(peer, workspace_id).await?;
    let (remote_name, remote_owner, root_cid) = match state {
        SyncResponse::StateResponse {
            workspace_id: got_workspace,
            root_cid_hex,
            name,
            owner_did,
        } if got_workspace == workspace_id => {
            (name, Did::new(owner_did), parse_cid(&root_cid_hex)?)
        }
        SyncResponse::WorkspaceNotFound { .. } => return Err("remote workspace not found".into()),
        other => return Err(format!("unexpected state response: {other:?}").into()),
    };
    if let Some(discovered) = &discovered_source {
        if remote_owner != discovered.owner {
            return Err(format!(
                "remote owner {} does not match signed discovery owner {}",
                remote_owner, discovered.owner
            )
            .into());
        }
        if let Some(expected_root) = discovered.root {
            if root_cid != expected_root {
                return Err(format!(
                    "remote root {} does not match signed discovery root {}",
                    hex::encode(root_cid.as_bytes()),
                    hex::encode(expected_root.as_bytes())
                )
                .into());
            }
        }
    }

    let clone_path = base.join(&name);
    if clone_path.exists() {
        return Err(format!("clone target already exists: {}", clone_path.display()).into());
    }

    let sync_store_path = base
        .join(".nexus")
        .join("synced-blocks")
        .join(workspace_id.to_string());
    let sync_store: Arc<dyn BlockStore> = Arc::new(DiskBlockStore::new(sync_store_path));
    let cloned_root = client
        .clone_workspace(peer, workspace_id, &sync_store)
        .await?;
    if cloned_root != root_cid {
        return Err(format!(
            "remote root changed while cloning: expected {}, got {}",
            hex::encode(root_cid.as_bytes()),
            hex::encode(cloned_root.as_bytes())
        )
        .into());
    }

    let workspace = Workspace::materialize_from_store(
        &remote_owner,
        &clone_path,
        WorkspaceConfig {
            name: name.clone(),
            description: description.unwrap_or_else(|| format!("Clone of remote {remote_name}")),
        },
        workspace_id,
        cloned_root,
        sync_store.as_ref(),
    )
    .await?;
    let mut workspace = workspace;
    workspace.join_agent(identity.did(), unix_now())?;
    register_workspace_path(&base, workspace.root_dir())?;

    let now = unix_now().max(
        memory
            .events()
            .iter()
            .map(|event| event.timestamp)
            .max()
            .unwrap_or(0)
            .saturating_add(1),
    );
    let events = [
        SocialEvent::new(
            identity.did().clone(),
            now,
            SocialEventKind::WorkspaceJoined {
                workspace: workspace.id(),
            },
        )
        .sign(&identity)?,
        SocialEvent::new(
            identity.did().clone(),
            now,
            SocialEventKind::WorkspaceSnapshotted {
                snapshot: WorkspaceSnapshot {
                    workspace: workspace.id(),
                    actor: identity.did().clone(),
                    root: cloned_root,
                    label: Some("cloned".into()),
                    note: Some(format!("cloned from peer {peer}")),
                    timestamp: now,
                },
            },
        )
        .sign(&identity)?,
    ];
    let mut inserted = false;
    for event in events {
        if memory.ingest_event(event)? {
            inserted = true;
        }
    }
    if inserted {
        save_social_memory(&memory_path, &memory)?;
    }

    println!(
        "Cloned workspace {} to {} at root {}",
        workspace.id(),
        workspace.root_dir().display(),
        hex::encode(cloned_root.as_bytes())
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// exec
// ---------------------------------------------------------------------------

async fn cmd_exec(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut workspace_path = None;
    let mut note = None;
    let mut exec_options = ExecOptions::default();
    let mut stdin_source = None::<&'static str>;
    let mut command_start = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--workspace" => {
                i += 1;
                workspace_path = Some(PathBuf::from(required_arg(args, i, "--workspace")?));
            }
            "--note" => {
                i += 1;
                note = Some(required_arg(args, i, "--note")?.to_string());
            }
            "--cwd" | "--working-dir" => {
                i += 1;
                exec_options.working_dir = Some(PathBuf::from(required_arg(args, i, "--cwd")?));
            }
            "--env" => {
                i += 1;
                exec_options
                    .env
                    .push(parse_env_assignment(required_arg(args, i, "--env")?)?);
            }
            "--stdin" => {
                i += 1;
                if stdin_source.replace("--stdin").is_some() {
                    return Err("only one stdin source may be provided".into());
                }
                exec_options.stdin = Some(required_arg(args, i, "--stdin")?.as_bytes().to_vec());
            }
            "--stdin-file" => {
                i += 1;
                if stdin_source.replace("--stdin-file").is_some() {
                    return Err("only one stdin source may be provided".into());
                }
                exec_options.stdin = Some(std::fs::read(required_arg(args, i, "--stdin-file")?)?);
            }
            "--timeout-ms" => {
                i += 1;
                let millis = parse_u64_arg(required_arg(args, i, "--timeout-ms")?, "--timeout-ms")?;
                exec_options.timeout = Some(Duration::from_millis(millis));
            }
            "--" => {
                command_start = Some(i + 1);
                break;
            }
            other if command_start.is_none() && other.starts_with("--") => {
                return Err(format!("unknown exec option: {other}").into());
            }
            _ => {
                command_start = Some(i);
                break;
            }
        }
        i += 1;
    }

    let command_start = command_start.ok_or("command required")?;
    let command = args
        .get(command_start)
        .ok_or("command required after --")?
        .clone();
    let command_args = args[command_start + 1..].to_vec();
    let workspace_path = workspace_path.ok_or("--workspace required")?;
    let identity = load_or_create_identity(&base)?;
    let memory_path = base.join(".nexus-social-memory.json");
    let mut memory = load_social_memory(&memory_path)?;
    let mut workspace = Workspace::load(&identity, &workspace_path).await?;
    register_workspace_path(&base, workspace.root_dir())?;

    let started_at = unix_now();
    let arg_refs = command_args.iter().map(String::as_str).collect::<Vec<_>>();
    let context = workspace_run_context_from_exec_options(&exec_options);
    let wall_start = Instant::now();
    let output = match workspace.exec(&command, &arg_refs, &exec_options).await {
        Ok(output) => output,
        Err(err) => {
            let wall_time = wall_start.elapsed();
            let finished_at = unix_now().max(started_at);
            let output_root = workspace.snapshot().await.ok();
            let run = WorkspaceRun {
                workspace: workspace.id(),
                actor: identity.did().clone(),
                command: command.clone(),
                args: command_args.clone(),
                exit_code: -1,
                stdout: workspace_run_failure_stdout(&err),
                stderr: workspace_run_failure_stderr(&err),
                output_root,
                resources: workspace_run_failure_resources_from_error(&err, wall_time),
                context,
                failure: Some(workspace_run_failure_from_error(&err)),
                started_at,
                finished_at,
                note: note.clone(),
            };
            match SocialEvent::new(
                identity.did().clone(),
                finished_at,
                SocialEventKind::WorkspaceRunRecorded { run: Box::new(run) },
            )
            .sign(&identity)
            {
                Ok(event) => {
                    if let Err(record_err) =
                        record_social_events(&memory_path, &mut memory, [event])
                    {
                        eprintln!("failed to record workspace run failure: {record_err}");
                    }
                }
                Err(record_err) => eprintln!("failed to sign workspace run failure: {record_err}"),
            }
            return Err(Box::new(err));
        }
    };
    let finished_at = unix_now().max(started_at);
    let output_root = workspace.snapshot().await?;

    let run = WorkspaceRun {
        workspace: workspace.id(),
        actor: identity.did().clone(),
        command: command.clone(),
        args: command_args.clone(),
        exit_code: output.exit_code,
        stdout: Cid::hash_of(&output.stdout),
        stderr: Cid::hash_of(&output.stderr),
        output_root: Some(output_root),
        resources: output.resources.clone(),
        context,
        failure: None,
        started_at,
        finished_at,
        note: note.clone(),
    };
    let snapshot = WorkspaceSnapshot {
        workspace: workspace.id(),
        actor: identity.did().clone(),
        root: output_root,
        label: Some(format!("after:{command}")),
        note,
        timestamp: finished_at,
    };

    let events = [
        SocialEvent::new(
            identity.did().clone(),
            finished_at,
            SocialEventKind::WorkspaceRunRecorded { run: Box::new(run) },
        )
        .sign(&identity)?,
        SocialEvent::new(
            identity.did().clone(),
            finished_at,
            SocialEventKind::WorkspaceSnapshotted { snapshot },
        )
        .sign(&identity)?,
    ];
    record_social_events(&memory_path, &mut memory, events)?;

    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    println!(
        "\nRecorded workspace run: workspace={} root={} exit={}",
        workspace.id(),
        hex::encode(output_root.as_bytes()),
        output.exit_code
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

async fn cmd_serve(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut listen = "/ip4/0.0.0.0/udp/0/quic-v1".to_string();
    let mut bootstrap = Vec::new();
    let mut use_public_bootstrap = true;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--listen" => {
                i += 1;
                listen = required_arg(args, i, "--listen")?.to_string();
            }
            "--bootstrap" => {
                i += 1;
                bootstrap.push(required_arg(args, i, "--bootstrap")?.parse()?);
            }
            "--no-public-bootstrap" => {
                use_public_bootstrap = false;
            }
            o => {
                eprintln!("unknown: {o}");
                return Ok(());
            }
        }
        i += 1;
    }
    if bootstrap.is_empty() {
        bootstrap = default_bootstrap_peers(&base, use_public_bootstrap)?;
    }

    let id_path = identity_path(&base);
    let id = load_or_create_identity(&base)?;
    println!("Node DID: {}", id.did());
    let memory_path = base.join(".nexus-social-memory.json");
    let mut social_memory = load_social_memory(&memory_path)?;

    let network = Network::new(
        &id,
        NetworkConfig {
            listen_addr: listen.parse()?,
            bootstrap_peers: bootstrap,
            ..Default::default()
        },
    )
    .await?;

    let network_arc = Arc::new(network.clone());
    let mut server = WorkspaceServer::new(network_arc);
    let mut net_clone = network.clone();
    let mut workspace_ids = Vec::new();

    println!("Node PeerId: {}", net_clone.local_peer_id());

    // Load workspaces
    for p in local_workspace_paths(&base)? {
        if p != id_path.parent().unwrap_or(&base) {
            match Workspace::load(&id, &p).await {
                Ok(ws) => {
                    workspace_ids.push(ws.id());
                    println!("  loaded: {} ({})", ws.name(), p.display());
                    server.register(ws);
                }
                Err(err) => eprintln!("  skip {}: {err}", p.display()),
            }
        }
    }
    announce_dht_presence(&network, &workspace_ids);

    announce_node_presence(
        &id,
        &network,
        &workspace_ids,
        &mut social_memory,
        &memory_path,
        &base,
        unix_now(),
    )
    .await;
    publish_workspace_announcements(
        &id,
        &network,
        &mut server,
        &mut social_memory,
        &memory_path,
        unix_now(),
    )
    .await;

    println!(
        "Serving {} workspaces. Press Ctrl-C to stop.",
        server.workspace_count()
    );

    // Event loop
    let mut observe_tick = tokio::time::interval(WORKSPACE_OBSERVE_INTERVAL);
    loop {
        tokio::select! {
            Some(event) = net_clone.next_event() => {
                handle_node_event(event, &network, &mut server, &mut social_memory, &memory_path, &base, &id).await;
            }
            _ = observe_tick.tick() => {
                publish_workspace_announcements(
                    &id,
                    &network,
                    &mut server,
                    &mut social_memory,
                    &memory_path,
                    unix_now(),
                )
                .await;
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Shutting down.");
                break;
            }
        }
    }

    Ok(())
}

fn identity_path(base: &Path) -> PathBuf {
    base.join(".nexus-identity.json")
}

fn workspace_registry_path(base: &Path) -> PathBuf {
    base.join(".nexus-workspaces.json")
}

fn workspace_discovery_path(base: &Path) -> PathBuf {
    base.join(".nexus-workspace-discovery.json")
}

fn normalize_workspace_path(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
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

fn register_workspace_path(
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

fn local_workspace_paths(base: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
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

fn load_workspace_discovery(
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

fn record_workspace_announcement(
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

fn sign_workspace_announcement(
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

fn verify_workspace_announcement(
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

fn announcement_peer_id(
    announcement: &WorkspaceAnnouncement,
) -> Result<libp2p::PeerId, Box<dyn std::error::Error>> {
    announcement
        .peer
        .parse()
        .map_err(|err| format!("invalid announcement peer {}: {err}", announcement.peer).into())
}

fn multiaddr_peer_id(addr: &libp2p::Multiaddr) -> Option<libp2p::PeerId> {
    addr.iter().find_map(|protocol| match protocol {
        libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

fn normalized_announcement_bootstrap_addrs(
    announcement: &WorkspaceAnnouncement,
) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    let peer = announcement_peer_id(announcement)?;
    normalized_peer_bootstrap_addrs(peer, &announcement.addrs)
}

fn normalized_peer_bootstrap_addrs(
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
            Some(_) => push_unique_bootstrap_addr(&mut normalized, addr),
            None => push_unique_bootstrap_addr(
                &mut normalized,
                addr.with(libp2p::multiaddr::Protocol::P2p(peer)),
            ),
        }
    }
    Ok(normalized)
}

fn discovered_workspace_views(
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

fn discover_clone_source(
    base: &Path,
    workspace_id: &WorkspaceId,
    preferred_peer: Option<&libp2p::PeerId>,
) -> Result<Option<DiscoveredCloneSource>, Box<dyn std::error::Error>> {
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
        b.timestamp
            .cmp(&a.timestamp)
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

#[cfg(test)]
async fn wait_for_peer(
    network: &Network,
    peer: libp2p::PeerId,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut events = network.clone();
    tokio::time::timeout(timeout, async {
        loop {
            match events.next_event().await {
                Some(NetworkEvent::PeerConnected(connected)) if connected == peer => break,
                Some(NetworkEvent::PeerDiscovered { peer_id }) if peer_id == peer => break,
                Some(NetworkEvent::RoutingUpdated { peer_id, .. }) if peer_id == peer => break,
                Some(_) => {}
                None => return Err("network event stream ended"),
            }
        }
        Ok::<(), &'static str>(())
    })
    .await
    .map_err(|_| format!("timed out waiting for peer {peer}"))??;
    Ok(())
}

async fn wait_for_peer_connected(
    network: &Network,
    peer: libp2p::PeerId,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    if network.is_connected(peer) {
        return Ok(());
    }

    let mut events = network.clone();
    network.dial_peer(peer);
    tokio::time::timeout(timeout, async {
        loop {
            if network.is_connected(peer) {
                break;
            }
            match events.next_event().await {
                Some(NetworkEvent::PeerConnected(connected)) if connected == peer => break,
                Some(_) => {}
                None => return Err("network event stream ended"),
            }
        }
        Ok::<(), &'static str>(())
    })
    .await
    .map_err(|_| format!("timed out waiting for connection to peer {peer}"))??;
    Ok(())
}

fn load_or_create_identity(base: &Path) -> Result<NodeIdentity, Box<dyn std::error::Error>> {
    let id_path = identity_path(base);
    if id_path.exists() {
        NodeIdentity::load_from_file(&id_path)
    } else {
        let id = NodeIdentity::generate();
        id.save_to_file(&id_path)?;
        Ok(id)
    }
}

fn load_social_memory(path: &PathBuf) -> Result<SocialMemory, Box<dyn std::error::Error>> {
    if path.exists() {
        let data = std::fs::read(path)?;
        let memory = serde_json::from_slice(&data)?;
        Ok(memory)
    } else {
        Ok(SocialMemory::new())
    }
}

fn save_social_memory(
    path: &Path,
    memory: &SocialMemory,
) -> Result<(), Box<dyn std::error::Error>> {
    write_file_atomic(path, &serde_json::to_vec_pretty(memory)?)?;
    Ok(())
}

fn write_file_atomic(path: &Path, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let tmp_path =
        path.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));

    let write_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, path)?;
        sync_parent_dir(path);
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }

    write_result
}

fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

fn record_social_events(
    path: &Path,
    memory: &mut SocialMemory,
    events: impl IntoIterator<Item = SocialEvent>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut inserted = false;
    for event in events {
        if memory.ingest_event(event)? {
            inserted = true;
        }
    }
    if inserted {
        save_social_memory(path, memory)?;
    }
    Ok(())
}

fn workspace_run_failure_resources_from_error(
    error: &WorkspaceError,
    wall_time: Duration,
) -> ResourceUsage {
    match error {
        WorkspaceError::Exec(error) => match error.as_ref() {
            ExecError::Timeout { resources, .. } => resources.clone(),
            _ => ResourceUsage {
                wall_time,
                process_count: 0,
                ..Default::default()
            },
        },
        _ => ResourceUsage {
            wall_time,
            process_count: 0,
            ..Default::default()
        },
    }
}

fn workspace_run_failure_stdout(error: &WorkspaceError) -> Cid {
    match error {
        WorkspaceError::Exec(error) => match error.as_ref() {
            ExecError::Timeout { stdout, .. } => Cid::hash_of(stdout),
            _ => Cid::hash_of(b""),
        },
        _ => Cid::hash_of(b""),
    }
}

fn workspace_run_failure_stderr(error: &WorkspaceError) -> Cid {
    match error {
        WorkspaceError::Exec(error) => match error.as_ref() {
            ExecError::Timeout { stderr, .. } => Cid::hash_of(stderr),
            _ => Cid::hash_of(b""),
        },
        _ => Cid::hash_of(b""),
    }
}

fn workspace_run_failure_from_error(error: &WorkspaceError) -> WorkspaceRunFailure {
    match error {
        WorkspaceError::Exec(error) => workspace_run_failure_from_exec_error(error.as_ref()),
        WorkspaceError::NotFound(message) => WorkspaceRunFailure {
            kind: "workspace_not_found".into(),
            message: message.clone(),
        },
        WorkspaceError::Io(error) => WorkspaceRunFailure {
            kind: "io".into(),
            message: error.to_string(),
        },
        WorkspaceError::Storage(error) => WorkspaceRunFailure {
            kind: "storage".into(),
            message: error.to_string(),
        },
        WorkspaceError::Json(error) => WorkspaceRunFailure {
            kind: "json".into(),
            message: error.to_string(),
        },
        WorkspaceError::AlreadyExists(message) => WorkspaceRunFailure {
            kind: "workspace_already_exists".into(),
            message: message.clone(),
        },
        WorkspaceError::PermissionDenied { reason } => WorkspaceRunFailure {
            kind: "permission_denied".into(),
            message: reason.clone(),
        },
        WorkspaceError::InvalidCapability(message) => WorkspaceRunFailure {
            kind: "invalid_capability".into(),
            message: message.clone(),
        },
        WorkspaceError::Other(message) => WorkspaceRunFailure {
            kind: "workspace_error".into(),
            message: message.clone(),
        },
    }
}

fn workspace_run_failure_from_exec_error(error: &ExecError) -> WorkspaceRunFailure {
    let kind = match error {
        ExecError::CommandNotFound(_) => "command_not_found",
        ExecError::ExitCode(_) => "exit_code",
        ExecError::Signalled => "signalled",
        ExecError::Io(_) => "io",
        ExecError::Timeout { .. } => "timeout",
        ExecError::Other(_) => "exec_error",
    };
    WorkspaceRunFailure {
        kind: kind.into(),
        message: error.to_string(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocialIngestOutcome {
    Inserted,
    Duplicate,
}

fn ingest_social_event_bytes(
    data: &[u8],
    social_memory: &mut SocialMemory,
    memory_path: &Path,
) -> Result<SocialIngestOutcome, Box<dyn std::error::Error>> {
    if social_memory.ingest_json(data)? {
        save_social_memory(memory_path, social_memory)?;
        Ok(SocialIngestOutcome::Inserted)
    } else {
        Ok(SocialIngestOutcome::Duplicate)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ---------------------------------------------------------------------------
// discover
// ---------------------------------------------------------------------------

async fn refresh_online_discovery(
    base: &Path,
    network: &Network,
    workspace_filter: Option<WorkspaceId>,
    peer_filter: Option<libp2p::PeerId>,
    timeout: Duration,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut events = network.clone();
    let mut contacted = std::collections::HashSet::new();
    let mut inserted = 0;
    let stop_after_first_match = workspace_filter.is_some() || peer_filter.is_some();
    let discovery_key = workspace_filter
        .as_ref()
        .map(workspace_discovery_key)
        .unwrap_or_else(global_discovery_key);
    let mut query_tick = tokio::time::interval(Duration::from_secs(1));
    network.find_providers(discovery_key.clone())?;

    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => break,
            _ = query_tick.tick() => {
                network.find_providers(discovery_key.clone())?;
            }
            event = events.next_event() => {
                match event {
                    Some(NetworkEvent::ProvidersFound { providers, .. }) => {
                        for peer in providers {
                            if Some(peer) == peer_filter || peer_filter.is_none() {
                                network.dial_peer(peer);
                            }
                        }
                    }
                    Some(NetworkEvent::PeerDiscovered { peer_id })
                    | Some(NetworkEvent::RoutingUpdated { peer_id, .. }) => {
                        if Some(peer_id) == peer_filter || peer_filter.is_none() {
                            network.dial_peer(peer_id);
                        }
                    }
                    Some(NetworkEvent::PeerConnected(peer)) => {
                        if peer == network.local_peer_id() {
                            continue;
                        }
                        if peer_filter.map(|filter| filter != peer).unwrap_or(false) {
                            continue;
                        }
                        if let Err(err) = mark_peer_cache_connected(base, peer, unix_now()) {
                            tracing::warn!("failed to update peer cache for {peer}: {err}");
                        }
                        if contacted.insert(peer) {
                            inserted += request_workspace_announcements_from_peer(
                                network,
                                peer,
                                workspace_filter,
                                base,
                            )
                            .await;
                            if inserted > 0 && stop_after_first_match {
                                break;
                            }
                        }
                    }
                    Some(NetworkEvent::WorkspaceAnnounce { source, data }) => {
                        match record_workspace_announcement_bytes(base, source, &data) {
                            Ok(true) => {
                                inserted += 1;
                                if stop_after_first_match {
                                    break;
                                }
                            }
                            Ok(false) => {}
                            Err(err) => tracing::warn!(
                                "rejected online workspace announcement from {:?}: {err}",
                                source
                            ),
                        }
                    }
                    Some(_) => {}
                    None => break,
                }
            }
        }
    }

    Ok(inserted)
}

async fn cmd_discover(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut listen = "/ip4/0.0.0.0/udp/0/quic-v1".to_string();
    let mut bootstrap = Vec::new();
    let mut online = false;
    let mut use_public_bootstrap = true;
    let mut timeout = DEFAULT_DISCOVERY_TIMEOUT;
    let mut json = false;
    let mut filter = DiscoveryFilter::default();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--json" => {
                json = true;
            }
            "--global" | "--online" | "--lan" => {
                online = true;
            }
            "--listen" => {
                i += 1;
                listen = required_arg(args, i, "--listen")?.to_string();
            }
            "--bootstrap" => {
                i += 1;
                bootstrap.push(required_arg(args, i, "--bootstrap")?.parse()?);
                online = true;
            }
            "--no-public-bootstrap" => {
                use_public_bootstrap = false;
            }
            "--timeout-ms" => {
                i += 1;
                let millis = parse_u64_arg(required_arg(args, i, "--timeout-ms")?, "--timeout-ms")?;
                timeout = Duration::from_millis(millis);
            }
            "--sort" => {
                i += 1;
                filter.sort = parse_discovery_sort(required_arg(args, i, "--sort")?)?;
            }
            "--verified" => {
                filter.verified_only = true;
            }
            "--clone-ready" => {
                filter.clone_ready_only = true;
            }
            "--workspace" => {
                i += 1;
                let workspace = parse_workspace_id(required_arg(args, i, "--workspace")?)?;
                filter.workspace = Some(workspace.to_string());
            }
            "--peer" => {
                i += 1;
                filter.peer = Some(required_arg(args, i, "--peer")?.to_string());
            }
            "--owner" => {
                i += 1;
                filter.owner = Some(Did::new(required_arg(args, i, "--owner")?.to_string()));
            }
            "--name" => {
                i += 1;
                filter.name = Some(required_arg(args, i, "--name")?.to_string());
            }
            other => return Err(format!("unknown discover option: {other}").into()),
        }
        i += 1;
    }

    if online && bootstrap.is_empty() {
        bootstrap = default_bootstrap_peers(&base, use_public_bootstrap)?;
    }
    if online {
        let identity = load_or_create_identity(&base)?;
        let network = Network::new(
            &identity,
            NetworkConfig {
                listen_addr: listen.parse()?,
                bootstrap_peers: bootstrap,
                ..Default::default()
            },
        )
        .await?;
        let workspace_filter = filter
            .workspace
            .as_deref()
            .map(parse_workspace_id)
            .transpose()?;
        let peer_filter = filter
            .peer
            .as_deref()
            .map(str::parse::<libp2p::PeerId>)
            .transpose()?;
        refresh_online_discovery(&base, &network, workspace_filter, peer_filter, timeout).await?;
    }

    let announcements = load_workspace_discovery(&base)?;
    let workspaces = discovered_workspace_views(&announcements, &filter);
    if json {
        println!("{}", serde_json::to_string_pretty(&workspaces)?);
    } else {
        print_discovered_workspaces_text(&base, &workspaces);
    }
    Ok(())
}

fn print_discovered_workspaces_text(base: &Path, workspaces: &[DiscoveredWorkspaceView]) {
    println!("Discovered AI workspaces: {}", base.display());
    println!("workspaces: {}", workspaces.len());
    for workspace in workspaces {
        println!(
            "\n{}  {}  peers={} latest={} verified={} clone_ready={}",
            workspace.workspace,
            workspace.name,
            workspace.peers.len(),
            workspace.latest_timestamp,
            workspace.verified,
            workspace.clone_ready
        );
        if !workspace.description.is_empty() {
            println!("  description: {}", workspace.description);
        }
        println!("  owner: {}", workspace.owner);
        println!("  root: {}", workspace.root.as_deref().unwrap_or("-"));
        for peer in &workspace.peers {
            println!("  peer: {peer}");
        }
        for addr in &workspace.addrs {
            println!("  addr: {addr}");
        }
    }
}

// ---------------------------------------------------------------------------
// bootstrap
// ---------------------------------------------------------------------------

fn cmd_bootstrap(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.get(2).map(String::as_str) != Some("status") {
        return Err("bootstrap subcommand required: status".into());
    }

    let mut base = PathBuf::from(".");
    let mut json = false;
    let mut use_public_bootstrap = true;
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
            "--no-public-bootstrap" => {
                use_public_bootstrap = false;
            }
            other => return Err(format!("unknown bootstrap status option: {other}").into()),
        }
        i += 1;
    }

    let status = bootstrap_status(&base, use_public_bootstrap)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        print_bootstrap_status_text(&status);
    }
    Ok(())
}

fn print_bootstrap_status_text(status: &BootstrapStatus) {
    println!("Bootstrap status: {}", status.base);
    println!(
        "public_default_peers: {}",
        if status.public_defaults_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "NEXUS_BOOTSTRAP: {} peers{}",
        status.env_peers.len(),
        if status.env_configured {
            " configured"
        } else {
            ""
        }
    );
    println!("config_peers: {}", status.config_peers.len());
    println!("peer_cache_entries: {}", status.peer_cache.len());
    println!("peer_cache_peers: {}", status.peer_cache_peers.len());
    println!(
        "discovery_cache_peers: {}",
        status.discovery_cache_peers.len()
    );
    println!(
        "public_default_peers: {}",
        status.public_default_peers.len()
    );
    println!("effective_peers: {}", status.effective_peers.len());
    for peer in &status.effective_peers {
        println!("  {peer}");
    }
}

// ---------------------------------------------------------------------------
// society
// ---------------------------------------------------------------------------

fn cmd_society(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut json = false;
    let mut options = SocietyJsonOptions::default();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--json" => {
                json = true;
            }
            "--activity-limit" => {
                i += 1;
                options.activity_limit = Some(parse_usize_arg(
                    required_arg(args, i, "--activity-limit")?,
                    "--activity-limit",
                )?);
            }
            "--activity-since" => {
                i += 1;
                options.activity_since = Some(parse_u64_arg(
                    required_arg(args, i, "--activity-since")?,
                    "--activity-since",
                )?);
            }
            "--intent-limit" | "--recommendation-limit" => {
                i += 1;
                options.intent_recommendation_limit = Some(parse_usize_arg(
                    required_arg(args, i, "--intent-limit")?,
                    "--intent-limit",
                )?);
            }
            "--agent" | "--did" => {
                i += 1;
                options.agent_filter =
                    Some(Did::new(required_arg(args, i, "--agent")?.to_string()));
            }
            "--workspace" => {
                i += 1;
                options.workspace_filter =
                    Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--task" | "--task-id" => {
                i += 1;
                options.task_filter = Some(required_arg(args, i, "--task")?.to_string());
            }
            o => {
                eprintln!("unknown: {o}");
                return Ok(());
            }
        }
        i += 1;
    }

    let memory = load_social_memory(&base.join(".nexus-social-memory.json"))?;
    if json {
        print_society_json(&base, &memory, options)?;
    } else {
        print_society_text(&base, &memory);
    }
    Ok(())
}

fn print_society_text(base: &Path, memory: &SocialMemory) {
    let society = memory.society();
    println!("AI Society: {}", base.display());
    println!("events: {}", memory.event_count());
    println!("agents: {}", society.agent_count());
    println!("manifests: {}", society.manifest_count());
    println!("interactions: {}", society.interaction_count());
    println!("tasks: {}", society.task_count());

    println!("\nAgents:");
    for did in society.agents() {
        if let Some(manifest) = society.agent_manifest(did) {
            let capabilities = manifest
                .provides
                .iter()
                .map(|cap| cap.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            println!("  {}  {}  [{}]", did, manifest.name, capabilities);
        } else {
            println!("  {did}");
        }
    }

    println!("\nWorkspaces:");
    for workspace in society.workspace_ids() {
        let members = society
            .workspace_members(&workspace)
            .into_iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        println!("  {workspace}  members={}", members.len());
        for member in members {
            println!("    {member}");
        }
    }

    println!("\nCollectives:");
    for collective in society.collectives() {
        println!(
            "  {}  {}  members={} workspaces={}",
            collective.id,
            collective.name,
            collective.members.len(),
            collective.workspaces.len()
        );
    }

    println!("\nTasks:");
    for task in society.tasks() {
        println!(
            "  {}  {:?}  {}  publisher={} assigned={}",
            task.id,
            task.state,
            task.required_capability,
            task.publisher,
            task.assigned_to
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "-".into())
        );
    }
}

// ---------------------------------------------------------------------------
// act
// ---------------------------------------------------------------------------

fn cmd_act(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut intent_id = None;
    let mut kind = None;
    let mut body = None;
    let mut price = None;
    let mut eta = None;
    let mut collective_id = None;
    let mut proposal_id = None;
    let mut title = None;
    let mut deadline = None;
    let mut evidence = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--intent" | "--intent-id" => {
                i += 1;
                intent_id = Some(required_arg(args, i, "--intent")?.to_string());
            }
            "--kind" | "--action" => {
                i += 1;
                kind = Some(parse_intent_action_kind(required_arg(args, i, "--kind")?)?);
            }
            "--body" | "--note" | "--rationale" => {
                i += 1;
                body = Some(required_arg(args, i, "--body")?.to_string());
            }
            "--title" => {
                i += 1;
                title = Some(required_arg(args, i, "--title")?.to_string());
            }
            "--price" => {
                i += 1;
                price = Some(parse_u64_arg(required_arg(args, i, "--price")?, "--price")?);
            }
            "--eta" | "--estimated-time" => {
                i += 1;
                eta = Some(parse_u64_arg(required_arg(args, i, "--eta")?, "--eta")?);
            }
            "--collective" => {
                i += 1;
                collective_id = Some(required_arg(args, i, "--collective")?.to_string());
            }
            "--proposal" => {
                i += 1;
                proposal_id = Some(required_arg(args, i, "--proposal")?.to_string());
            }
            "--deadline" => {
                i += 1;
                deadline = Some(parse_u64_arg(
                    required_arg(args, i, "--deadline")?,
                    "--deadline",
                )?);
            }
            "--evidence" => {
                i += 1;
                evidence = Some(required_arg(args, i, "--evidence")?.to_string());
            }
            other => return Err(format!("unknown act option: {other}").into()),
        }
        i += 1;
    }

    let intent_id = intent_id.ok_or("--intent required")?;
    let kind = kind.ok_or("--kind required")?;
    let now = unix_now();
    let action = select_intent_action(&base, &intent_id, kind, now)?;
    let event = signed_local_event(
        &base,
        |identity| {
            if action.actor != *identity.did() {
                return Err("selected action actor does not match local identity".into());
            }
            social_event_from_action(
                action,
                body,
                price,
                eta,
                collective_id,
                proposal_id,
                title,
                deadline,
                evidence,
                now,
            )
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn social_event_from_action(
    action: IntentActionPlan,
    body: Option<String>,
    price: Option<u64>,
    eta: Option<u64>,
    collective_id: Option<String>,
    proposal_id: Option<String>,
    title: Option<String>,
    deadline: Option<u64>,
    evidence: Option<String>,
    now: u64,
) -> Result<SocialEventKind, Box<dyn std::error::Error>> {
    match action.kind {
        IntentActionKind::RespondIntent => {
            let mut response = IntentResponse::new(
                action.intent_id.clone(),
                action.actor.clone(),
                action
                    .response_kind
                    .unwrap_or(IntentResponseKind::Interested),
                body.unwrap_or(action.body),
                action.workspace,
                action.task_id,
                action.capability,
                evidence.or(Some(action.event_hint)),
                now,
            );
            response.id = random_social_id();
            Ok(SocialEventKind::IntentResponded { response })
        }
        IntentActionKind::OfferTask => Ok(SocialEventKind::TaskOffered {
            offer: TaskOffer {
                task_id: action.task_id.ok_or("selected action has no task id")?,
                bidder: action.actor,
                price: price.or(action.suggested_price).unwrap_or(0),
                estimated_time_secs: eta.or(action.estimated_time_secs).unwrap_or(0),
                rationale: body.unwrap_or(action.body),
            },
        }),
        IntentActionKind::JoinWorkspace => Ok(SocialEventKind::WorkspaceJoined {
            workspace: action.workspace.ok_or("selected action has no workspace")?,
        }),
        IntentActionKind::ProposeCollective => {
            let collective_id =
                collective_id.ok_or("--collective required for propose-collective")?;
            let proposal = CollectiveProposal {
                id: proposal_id.unwrap_or_else(|| format!("intent-{}", action.intent_id)),
                collective_id,
                proposer: action.actor,
                title: title.unwrap_or(action.title),
                body: body.unwrap_or(action.body),
                workspace: action.workspace,
                created_at: now,
                deadline: deadline.unwrap_or(0),
            };
            Ok(SocialEventKind::CollectiveProposalPublished { proposal })
        }
    }
}

fn select_intent_action(
    base: &Path,
    intent_id: &str,
    kind: IntentActionKind,
    now: u64,
) -> Result<IntentActionPlan, Box<dyn std::error::Error>> {
    let identity = load_or_create_identity(base)?;
    let memory = load_social_memory(&base.join(".nexus-social-memory.json"))?;
    memory
        .society()
        .recommend_intents(identity.did(), Some(now), usize::MAX)
        .into_iter()
        .find(|recommendation| recommendation.intent.id == intent_id)
        .and_then(|recommendation| {
            recommendation
                .actions
                .into_iter()
                .find(|action| action.kind == kind)
        })
        .ok_or_else(|| format!("no recommended action {kind:?} for intent {intent_id}").into())
}

#[derive(Clone, Debug, Default)]
struct SocietyJsonOptions {
    activity_limit: Option<usize>,
    activity_since: Option<u64>,
    intent_recommendation_limit: Option<usize>,
    agent_filter: Option<Did>,
    workspace_filter: Option<WorkspaceId>,
    task_filter: Option<String>,
}

fn print_society_json(
    base: &Path,
    memory: &SocialMemory,
    options: SocietyJsonOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{}",
        serde_json::to_string_pretty(&society_json_for_base(base, memory, options))?
    );
    Ok(())
}

#[cfg(test)]
fn society_json(memory: &SocialMemory) -> serde_json::Value {
    society_json_for_base(Path::new("."), memory, SocietyJsonOptions::default())
}

fn society_json_for_base(
    base: &Path,
    memory: &SocialMemory,
    options: SocietyJsonOptions,
) -> serde_json::Value {
    let society = memory.society();
    let agents = society
        .agents()
        .into_iter()
        .filter(|did| agent_matches_filters(society, did, &options))
        .map(|did| {
            let manifest = society.agent_manifest(did);
            let provider_recommendations = manifest
                .map(|manifest| {
                    manifest
                        .provides
                        .iter()
                        .flat_map(|capability| {
                            society
                                .recommend_providers(did, &capability.name, 10)
                                .into_iter()
                        })
                        .filter(|provider| provider.did == *did)
                        .map(provider_recommendation_json)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            serde_json::json!({
                "did": did.to_string(),
                "manifest": manifest,
                "provider_recommendations": provider_recommendations,
                "activity": agent_activity_json(society, did, &options),
                "intents": society
                    .agent_intents(did)
                    .into_iter()
                    .filter(|intent| intent_matches_filters(intent, &options))
                    .map(intent_json)
                    .collect::<Vec<_>>(),
                "intent_responses": society
                    .agent_intent_responses(did)
                    .into_iter()
                    .filter(|response| intent_response_matches_filters(response, &options))
                    .map(intent_response_json)
                    .collect::<Vec<_>>(),
                "intent_recommendations": society
                    .recommend_intents(
                        did,
                        Some(unix_now()),
                        options.intent_recommendation_limit.unwrap_or(10),
                    )
                    .into_iter()
                    .filter(|recommendation| {
                        intent_recommendation_matches_filters(recommendation, &options)
                    })
                    .map(intent_recommendation_json)
                    .collect::<Vec<_>>(),
                "workspaces": society
                    .agent_workspaces(did)
                    .into_iter()
                    .filter(|workspace| workspace_matches_filters(society, workspace, &options))
                    .map(|workspace| workspace.to_string())
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let workspaces = society
        .workspace_ids()
        .into_iter()
        .filter(|workspace| workspace_matches_filters(society, workspace, &options))
        .map(|workspace| {
            serde_json::json!({
                "id": workspace.to_string(),
                "members": society
                    .workspace_members(&workspace)
                    .into_iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                "capability_grants": society
                    .workspace_capability_grants(&workspace)
                    .into_iter()
                    .map(capability_grant_json)
                    .collect::<Vec<_>>(),
                "snapshots": society
                    .workspace_snapshots(&workspace)
                    .into_iter()
                    .map(workspace_snapshot_json)
                    .collect::<Vec<_>>(),
                "latest_snapshot": society
                    .latest_workspace_snapshot(&workspace)
                    .map(workspace_snapshot_json),
                "runs": society
                    .workspace_runs(&workspace)
                    .into_iter()
                    .map(workspace_run_json)
                    .collect::<Vec<_>>(),
                "intents": society
                    .workspace_intents(&workspace)
                    .into_iter()
                    .filter(|intent| intent_matches_filters(intent, &options))
                    .map(intent_json)
                    .collect::<Vec<_>>(),
                "intent_responses": society
                    .workspace_intent_responses(&workspace)
                    .into_iter()
                    .filter(|response| intent_response_matches_filters(response, &options))
                    .map(intent_response_json)
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let capability_grants = society
        .capability_grants()
        .into_iter()
        .filter(|grant| capability_grant_matches_filters(society, grant, &options))
        .map(capability_grant_json)
        .collect::<Vec<_>>();
    let collectives = society
        .collectives()
        .into_iter()
        .filter(|collective| collective_matches_filters(society, collective, &options))
        .map(|collective| {
            let mut members = collective
                .members
                .iter()
                .filter(|member| member_matches_filters(society, member, &options))
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            members.sort();
            let mut workspaces = collective
                .workspaces
                .iter()
                .filter(|workspace| workspace_matches_filters(society, workspace, &options))
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            workspaces.sort();
            let proposals = society
                .collective_proposals(&collective.id)
                .into_iter()
                .filter(|proposal| proposal_matches_filters(society, proposal, &options))
                .map(|proposal| {
                    serde_json::json!({
                        "id": proposal.id,
                        "collective_id": proposal.collective_id,
                        "proposer": proposal.proposer.to_string(),
                        "title": proposal.title,
                        "body": proposal.body,
                        "workspace": proposal.workspace.map(|workspace| workspace.to_string()),
                        "created_at": proposal.created_at,
                        "deadline": proposal.deadline,
                        "votes": society
                            .collective_votes(&proposal.collective_id, &proposal.id)
                            .into_iter()
                            .filter(|vote| vote_matches_filters(vote, &options))
                            .map(|vote| {
                                serde_json::json!({
                                    "proposal_id": vote.proposal_id,
                                    "collective_id": vote.collective_id,
                                    "voter": vote.voter.to_string(),
                                    "choice": vote.choice,
                                    "rationale": vote.rationale,
                                    "timestamp": vote.timestamp,
                                })
                            })
                            .collect::<Vec<_>>(),
                        "decision": society
                            .collective_decision(&proposal.collective_id, &proposal.id)
                            .map(|decision| {
                            serde_json::json!({
                                "proposal_id": decision.proposal_id,
                                "collective_id": decision.collective_id,
                                "decider": decision.decider.to_string(),
                                "outcome": decision.outcome,
                                "task_id": decision.task_id,
                                "claim_id": decision.claim_id,
                                "target": decision.target.as_ref().map(ToString::to_string),
                                "reason": decision.reason,
                                "timestamp": decision.timestamp,
                            })
                        }),
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "id": collective.id,
                "name": collective.name,
                "purpose": collective.purpose,
                "members": members,
                "workspaces": workspaces,
                "proposals": proposals,
                "created_at": collective.created_at,
            })
        })
        .collect::<Vec<_>>();
    let tasks = society
        .tasks()
        .into_iter()
        .filter(|task| task_matches_filters(society, task, &options))
        .map(|task| {
            serde_json::json!({
                "id": task.id,
                "publisher": task.publisher.to_string(),
                "description": task.description,
                "required_capability": task.required_capability,
                "command": task.command,
                "args": task.args,
                "max_budget": task.max_budget,
                "deadline": task.deadline,
                "state": task.state,
                "assigned_to": task.assigned_to.as_ref().map(ToString::to_string),
                "created_at": task.created_at,
                "offers": society.task_offers(&task.id),
                "acceptance": society.task_acceptance(&task.id).map(|acceptance| {
                    serde_json::json!({
                        "task_id": acceptance.task_id,
                        "publisher": acceptance.publisher.to_string(),
                        "bidder": acceptance.bidder.to_string(),
                        "price": acceptance.price,
                        "accepted_at": acceptance.accepted_at,
                    })
                }),
                "cancellation": society.task_cancellation(&task.id).map(|cancellation| {
                    serde_json::json!({
                        "task_id": cancellation.task_id,
                        "publisher": cancellation.publisher.to_string(),
                        "reason": cancellation.reason,
                        "cancelled_at": cancellation.cancelled_at,
                    })
                }),
                "result": society.task_result(&task.id).map(task_result_json),
                "result_claims": society
                    .task_result_claims(&task.id)
                    .into_iter()
                    .map(|result| task_result_claim_json(society, result))
                    .collect::<Vec<_>>(),
                "claim_judgments": society
                    .task_claim_judgments(&task.id)
                    .into_iter()
                    .map(task_claim_judgment_json)
                    .collect::<Vec<_>>(),
                "disputes": society
                    .task_disputes(&task.id)
                    .into_iter()
                    .map(|dispute| {
                        serde_json::json!({
                            "task_id": dispute.task_id,
                            "disputer": dispute.disputer.to_string(),
                            "target": dispute.target.to_string(),
                            "claim_id": dispute.claim_id,
                            "reason": dispute.reason,
                            "evidence": dispute.evidence,
                            "timestamp": dispute.timestamp,
                        })
                    })
                    .collect::<Vec<_>>(),
                "settlements": society
                    .task_settlements(&task.id)
                    .into_iter()
                    .map(settlement_json)
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let relations = society
        .edges()
        .into_iter()
        .filter(|edge| relation_matches_filters(society, edge, &options))
        .map(|edge| {
            serde_json::json!({
                "from": edge.from.to_string(),
                "to": edge.to.to_string(),
                "kind": edge.kind,
                "trust": edge.trust,
                "affinity": edge.affinity,
                "successes": edge.successes,
                "failures": edge.failures,
                "score": edge.score(),
                "notes": edge.notes,
                "created_at": edge.created_at,
                "updated_at": edge.updated_at,
            })
        })
        .collect::<Vec<_>>();
    let interactions = society
        .interactions()
        .iter()
        .filter(|interaction| interaction_matches_filters(interaction, &options))
        .map(interaction_json)
        .collect::<Vec<_>>();
    let intents = society
        .intents()
        .into_iter()
        .filter(|intent| intent_matches_filters(intent, &options))
        .map(intent_json)
        .collect::<Vec<_>>();
    let intent_responses = society
        .intent_responses()
        .into_iter()
        .filter(|response| intent_response_matches_filters(response, &options))
        .map(intent_response_json)
        .collect::<Vec<_>>();
    let reputations = society
        .reputations()
        .into_iter()
        .filter(|reputation| reputation_matches_filters(society, *reputation, &options))
        .map(reputation_json)
        .collect::<Vec<_>>();
    let settlements = society
        .settlements()
        .into_iter()
        .filter(|settlement| settlement_matches_filters(settlement, &options))
        .map(settlement_json)
        .collect::<Vec<_>>();
    let discovered_workspaces =
        if options.task_filter.is_some() && options.workspace_filter.is_none() {
            Vec::new()
        } else {
            load_workspace_discovery(base)
                .map(|announcements| {
                    let discovery_filter = DiscoveryFilter {
                        workspace: options
                            .workspace_filter
                            .map(|workspace| workspace.to_string()),
                        owner: options.agent_filter.clone(),
                        ..Default::default()
                    };
                    discovered_workspace_views(&announcements, &discovery_filter)
                })
                .unwrap_or_default()
        };

    serde_json::json!({
        "events": memory.event_count(),
        "agents": agents,
        "workspaces": workspaces,
        "discovered_workspaces": discovered_workspaces,
        "collectives": collectives,
        "relations": relations,
        "interactions": interactions,
        "intents": intents,
        "intent_responses": intent_responses,
        "reputations": reputations,
        "capability_grants": capability_grants,
        "settlements": settlements,
        "tasks": tasks,
    })
}

fn agent_matches_filters(
    society: &nexus_agent::Society,
    did: &Did,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| did == agent)
        && options
            .workspace_filter
            .is_none_or(|workspace| agent_uses_workspace(society, did, &workspace))
        && options.task_filter.as_ref().is_none_or(|task_id| {
            society.task(task_id).is_some_and(|task| {
                task.publisher == *did
                    || task.assigned_to.as_ref() == Some(did)
                    || society
                        .task_offers(task_id)
                        .iter()
                        .any(|offer| offer.bidder == *did)
                    || society.task_acceptance(task_id).is_some_and(|acceptance| {
                        acceptance.publisher == *did || acceptance.bidder == *did
                    })
                    || society
                        .task_result(task_id)
                        .is_some_and(|result| result.executor == *did)
                    || society
                        .task_result_claims(task_id)
                        .into_iter()
                        .any(|result| result.executor == *did)
                    || society
                        .task_disputes(task_id)
                        .into_iter()
                        .any(|dispute| dispute.disputer == *did || dispute.target == *did)
                    || society
                        .task_claim_judgments(task_id)
                        .into_iter()
                        .any(|judgment| {
                            judgment.decider == *did || judgment.target.as_ref() == Some(did)
                        })
            })
        })
}

fn member_matches_filters(
    society: &nexus_agent::Society,
    did: &Did,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| did == agent)
        && options.task_filter.as_ref().is_none_or(|task_id| {
            society.task(task_id).is_some_and(|task| {
                task.publisher == *did || task.assigned_to.as_ref() == Some(did)
            })
        })
}

fn workspace_matches_filters(
    society: &nexus_agent::Society,
    workspace: &WorkspaceId,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .workspace_filter
        .is_none_or(|filter| workspace == &filter)
        && options.agent_filter.as_ref().is_none_or(|agent| {
            society
                .workspace_members(workspace)
                .into_iter()
                .any(|member| member == agent)
                || society
                    .workspace_runs(workspace)
                    .into_iter()
                    .any(|run| run.actor == *agent)
                || society
                    .workspace_snapshots(workspace)
                    .into_iter()
                    .any(|snapshot| snapshot.actor == *agent)
                || society
                    .workspace_capability_grants(workspace)
                    .into_iter()
                    .any(|grant| {
                        grant.capability.issuer == *agent || grant.capability.subject == *agent
                    })
                || society
                    .workspace_intents(workspace)
                    .into_iter()
                    .any(|intent| intent.author == *agent)
                || society
                    .workspace_intent_responses(workspace)
                    .into_iter()
                    .any(|response| response.responder == *agent)
                || agent_task_uses_workspace(society, agent, workspace)
        })
        && options
            .task_filter
            .as_ref()
            .is_none_or(|task_id| task_uses_workspace(society, task_id, workspace))
}

fn capability_grant_matches_filters(
    society: &nexus_agent::Society,
    grant: &CapabilityGrant,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .workspace_filter
        .is_none_or(|workspace| grant.capability.workspace == workspace)
        && options.agent_filter.as_ref().is_none_or(|agent| {
            grant.capability.issuer == *agent || grant.capability.subject == *agent
        })
        && options.task_filter.as_ref().is_none_or(|task_id| {
            task_uses_workspace(society, task_id, &grant.capability.workspace)
        })
}

fn collective_matches_filters(
    society: &nexus_agent::Society,
    collective: &Collective,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| collective_involves_agent(society, collective, agent))
        && options.workspace_filter.is_none_or(|workspace| {
            collective.workspaces.contains(&workspace)
                || society
                    .collective_proposals(&collective.id)
                    .into_iter()
                    .any(|proposal| proposal.workspace == Some(workspace))
        })
        && options.task_filter.as_ref().is_none_or(|task_id| {
            society
                .collective_proposals(&collective.id)
                .into_iter()
                .any(|proposal| proposal_matches_task_filter(society, proposal, task_id))
        })
}

fn proposal_matches_filters(
    society: &nexus_agent::Society,
    proposal: &CollectiveProposal,
    options: &SocietyJsonOptions,
) -> bool {
    options.agent_filter.as_ref().is_none_or(|agent| {
        proposal.proposer == *agent
            || society
                .collective_votes(&proposal.collective_id, &proposal.id)
                .into_iter()
                .any(|vote| vote.voter == *agent)
            || society
                .collective_decision(&proposal.collective_id, &proposal.id)
                .is_some_and(|decision| {
                    decision.decider == *agent || decision.target.as_ref() == Some(agent)
                })
    }) && options
        .workspace_filter
        .is_none_or(|workspace| proposal.workspace == Some(workspace))
        && options
            .task_filter
            .as_ref()
            .is_none_or(|task_id| proposal_matches_task_filter(society, proposal, task_id))
}

fn vote_matches_filters(vote: &CollectiveVote, options: &SocietyJsonOptions) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| vote.voter == *agent)
}

fn task_matches_filters(
    society: &nexus_agent::Society,
    task: &Task,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .task_filter
        .as_ref()
        .is_none_or(|task_id| task.id == *task_id)
        && options
            .agent_filter
            .as_ref()
            .is_none_or(|agent| task_involves_agent(society, task, agent))
        && options
            .workspace_filter
            .is_none_or(|workspace| task_uses_workspace(society, &task.id, &workspace))
}

fn relation_matches_filters(
    society: &nexus_agent::Society,
    edge: &SocialEdge,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| edge.from == *agent || edge.to == *agent)
        && options.task_filter.as_ref().is_none_or(|task_id| {
            society.task(task_id).is_some_and(|task| {
                edge.from == task.publisher
                    || edge.to == task.publisher
                    || task.assigned_to.as_ref() == Some(&edge.from)
                    || task.assigned_to.as_ref() == Some(&edge.to)
            })
        })
}

fn interaction_matches_filters(interaction: &&Interaction, options: &SocietyJsonOptions) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| interaction.from == *agent || interaction.to == *agent)
        && options
            .workspace_filter
            .is_none_or(|workspace| interaction.workspace == Some(workspace))
        && options.task_filter.as_ref().is_none_or(|task_id| {
            interaction.evidence.as_deref() == Some(task_id) || interaction.topic.contains(task_id)
        })
}

fn settlement_matches_filters(
    settlement: &&SettlementRecord,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| settlement.payer == *agent || settlement.payee == *agent)
        && options
            .task_filter
            .as_ref()
            .is_none_or(|task_id| settlement.task_id.as_deref() == Some(task_id.as_str()))
}

fn intent_matches_filters(intent: &&AgentIntent, options: &SocietyJsonOptions) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| intent.author == *agent)
        && options
            .workspace_filter
            .is_none_or(|workspace| intent.workspace == Some(workspace))
        && options.task_filter.as_ref().is_none_or(|task_id| {
            intent.task_id.as_deref() == Some(task_id)
                || intent.title.contains(task_id)
                || intent.body.contains(task_id)
        })
}

fn intent_response_matches_filters(
    response: &&IntentResponse,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| response.responder == *agent)
        && options
            .workspace_filter
            .is_none_or(|workspace| response.workspace == Some(workspace))
        && options.task_filter.as_ref().is_none_or(|task_id| {
            response.task_id.as_deref() == Some(task_id)
                || response.intent_id == *task_id
                || response.body.contains(task_id)
        })
}

fn intent_recommendation_matches_filters(
    recommendation: &IntentRecommendation,
    options: &SocietyJsonOptions,
) -> bool {
    options
        .workspace_filter
        .is_none_or(|workspace| recommendation.intent.workspace == Some(workspace))
        && options.task_filter.as_ref().is_none_or(|task_id| {
            recommendation.intent.task_id.as_deref() == Some(task_id)
                || recommendation.intent.title.contains(task_id)
                || recommendation.intent.body.contains(task_id)
        })
}

fn reputation_matches_filters(
    society: &nexus_agent::Society,
    (from, to, _score): (&Did, &Did, &ReputationScore),
    options: &SocietyJsonOptions,
) -> bool {
    options
        .agent_filter
        .as_ref()
        .is_none_or(|agent| from == agent || to == agent)
        && options.task_filter.as_ref().is_none_or(|task_id| {
            society.task(task_id).is_some_and(|task| {
                from == &task.publisher
                    || to == &task.publisher
                    || task.assigned_to.as_ref() == Some(from)
                    || task.assigned_to.as_ref() == Some(to)
            })
        })
}

fn collective_involves_agent(
    society: &nexus_agent::Society,
    collective: &Collective,
    agent: &Did,
) -> bool {
    collective.members.contains(agent)
        || society
            .collective_proposals(&collective.id)
            .into_iter()
            .any(|proposal| {
                proposal.proposer == *agent
                    || society
                        .collective_votes(&proposal.collective_id, &proposal.id)
                        .into_iter()
                        .any(|vote| vote.voter == *agent)
                    || society
                        .collective_decision(&proposal.collective_id, &proposal.id)
                        .is_some_and(|decision| {
                            decision.decider == *agent || decision.target.as_ref() == Some(agent)
                        })
            })
}

fn proposal_matches_task_filter(
    society: &nexus_agent::Society,
    proposal: &CollectiveProposal,
    task_id: &str,
) -> bool {
    society
        .collective_decision(&proposal.collective_id, &proposal.id)
        .is_some_and(|decision| decision.task_id.as_deref() == Some(task_id))
}

fn task_involves_agent(society: &nexus_agent::Society, task: &Task, agent: &Did) -> bool {
    task.publisher == *agent
        || task.assigned_to.as_ref() == Some(agent)
        || society
            .task_offers(&task.id)
            .iter()
            .any(|offer| offer.bidder == *agent)
        || society
            .task_acceptance(&task.id)
            .is_some_and(|acceptance| acceptance.publisher == *agent || acceptance.bidder == *agent)
        || society
            .task_result(&task.id)
            .is_some_and(|result| result.executor == *agent)
        || society
            .task_result_claims(&task.id)
            .into_iter()
            .any(|result| result.executor == *agent)
        || society
            .task_disputes(&task.id)
            .into_iter()
            .any(|dispute| dispute.disputer == *agent || dispute.target == *agent)
        || society
            .task_claim_judgments(&task.id)
            .into_iter()
            .any(|judgment| judgment.decider == *agent || judgment.target.as_ref() == Some(agent))
}

fn agent_uses_workspace(
    society: &nexus_agent::Society,
    agent: &Did,
    workspace: &WorkspaceId,
) -> bool {
    society.agent_workspaces(agent).contains(workspace)
        || society
            .workspace_runs(workspace)
            .into_iter()
            .any(|run| run.actor == *agent)
        || society
            .workspace_snapshots(workspace)
            .into_iter()
            .any(|snapshot| snapshot.actor == *agent)
        || society
            .workspace_capability_grants(workspace)
            .into_iter()
            .any(|grant| grant.capability.issuer == *agent || grant.capability.subject == *agent)
        || society
            .workspace_intents(workspace)
            .into_iter()
            .any(|intent| intent.author == *agent)
        || society
            .workspace_intent_responses(workspace)
            .into_iter()
            .any(|response| response.responder == *agent)
        || agent_task_uses_workspace(society, agent, workspace)
}

fn agent_task_uses_workspace(
    society: &nexus_agent::Society,
    agent: &Did,
    workspace: &WorkspaceId,
) -> bool {
    society
        .tasks()
        .into_iter()
        .filter(|task| task_involves_agent(society, task, agent))
        .any(|task| task_uses_workspace(society, &task.id, workspace))
}

fn task_uses_workspace(
    society: &nexus_agent::Society,
    task_id: &str,
    workspace: &WorkspaceId,
) -> bool {
    society
        .task_result(task_id)
        .and_then(|result| result.receipt.as_deref())
        .is_some_and(|receipt| receipt.workspace.as_ref() == Some(workspace))
        || society
            .task_result_claims(task_id)
            .into_iter()
            .filter_map(|result| result.receipt.as_deref())
            .any(|receipt| receipt.workspace.as_ref() == Some(workspace))
}

fn capability_grant_json(grant: &CapabilityGrant) -> serde_json::Value {
    serde_json::json!({
        "issuer": grant.capability.issuer.to_string(),
        "subject": grant.capability.subject.to_string(),
        "workspace": grant.capability.workspace.to_string(),
        "permissions": {
            "read": grant.capability.permissions.read,
            "write": grant.capability.permissions.write,
            "exec": grant.capability.permissions.exec,
            "admin": grant.capability.permissions.admin,
        },
        "expires_at": grant.capability.expires_at,
        "issued_at": grant.issued_at,
        "note": grant.note,
    })
}

fn provider_recommendation_json(recommendation: ProviderRecommendation) -> serde_json::Value {
    serde_json::json!({
        "did": recommendation.did.to_string(),
        "name": recommendation.name,
        "capability": recommendation.capability,
        "social_score": recommendation.social_score,
        "reputation_score": recommendation.reputation_score,
        "governance_score": recommendation.governance_score,
        "governance_signals": recommendation
            .governance_signals
            .into_iter()
            .map(governance_signal_json)
            .collect::<Vec<_>>(),
        "price_per_unit": recommendation.price_per_unit,
        "ranking_score": recommendation.ranking_score,
    })
}

fn governance_signal_json(signal: GovernanceSignal) -> serde_json::Value {
    serde_json::json!({
        "collective_id": signal.collective_id,
        "proposal_id": signal.proposal_id,
        "decider": signal.decider.to_string(),
        "outcome": signal.outcome,
        "task_id": signal.task_id,
        "claim_id": signal.claim_id,
        "reason": signal.reason,
        "timestamp": signal.timestamp,
    })
}

fn intent_json(intent: &AgentIntent) -> serde_json::Value {
    serde_json::json!({
        "id": intent.id,
        "author": intent.author.to_string(),
        "kind": intent.kind,
        "title": intent.title,
        "body": intent.body,
        "workspace": intent.workspace.map(|workspace| workspace.to_string()),
        "task_id": intent.task_id,
        "capability": intent.capability,
        "tags": intent.tags,
        "created_at": intent.created_at,
        "expires_at": intent.expires_at,
    })
}

fn intent_response_json(response: &IntentResponse) -> serde_json::Value {
    serde_json::json!({
        "id": response.id,
        "intent_id": response.intent_id,
        "responder": response.responder.to_string(),
        "kind": response.kind,
        "body": response.body,
        "workspace": response.workspace.map(|workspace| workspace.to_string()),
        "task_id": response.task_id,
        "capability": response.capability,
        "evidence": response.evidence,
        "created_at": response.created_at,
    })
}

fn intent_recommendation_json(recommendation: IntentRecommendation) -> serde_json::Value {
    serde_json::json!({
        "intent": intent_json(&recommendation.intent),
        "author_name": recommendation.author_name,
        "capability_score": recommendation.capability_score,
        "workspace_score": recommendation.workspace_score,
        "social_score": recommendation.social_score,
        "reputation_score": recommendation.reputation_score,
        "response_score": recommendation.response_score,
        "preference_score": recommendation.preference_score,
        "response_count": recommendation.response_count,
        "fulfilled": recommendation.fulfilled,
        "ranking_score": recommendation.ranking_score,
        "reasons": recommendation.reasons,
        "actions": recommendation
            .actions
            .into_iter()
            .map(intent_action_plan_json)
            .collect::<Vec<_>>(),
    })
}

fn intent_action_plan_json(action: nexus_agent::IntentActionPlan) -> serde_json::Value {
    serde_json::json!({
        "kind": action.kind,
        "event_hint": action.event_hint,
        "intent_id": action.intent_id,
        "actor": action.actor.to_string(),
        "peer": action.peer.to_string(),
        "title": action.title,
        "body": action.body,
        "confidence": action.confidence,
        "workspace": action.workspace.map(|workspace| workspace.to_string()),
        "task_id": action.task_id,
        "capability": action.capability,
        "response_kind": action.response_kind,
        "suggested_price": action.suggested_price,
        "estimated_time_secs": action.estimated_time_secs,
    })
}

fn agent_activity_json(
    society: &nexus_agent::Society,
    agent: &Did,
    options: &SocietyJsonOptions,
) -> serde_json::Value {
    serde_json::json!({
        "workspace_runs": activity_window(
            society.agent_workspace_runs(agent),
            options,
            |run| run.finished_at,
        )
            .into_iter()
            .map(workspace_run_json)
            .collect::<Vec<_>>(),
        "task_results": activity_window(
            society.agent_task_results(agent),
            options,
            |result| task_result_activity_timestamp(result),
        )
            .into_iter()
            .map(task_result_json)
            .collect::<Vec<_>>(),
        "task_result_claims": activity_window(
            society.agent_task_result_claims(agent),
            options,
            |result| task_result_activity_timestamp(result),
        )
            .into_iter()
            .map(|result| task_result_claim_json(society, result))
            .collect::<Vec<_>>(),
        "interactions": activity_window(
            society.agent_interactions(agent),
            options,
            |interaction| interaction.timestamp,
        )
            .into_iter()
            .map(interaction_json)
            .collect::<Vec<_>>(),
        "reputations": activity_window(
            society.agent_reputations(agent),
            options,
            |(_, _, score)| score.last_seen,
        )
            .into_iter()
            .map(reputation_json)
            .collect::<Vec<_>>(),
    })
}

fn activity_window<T, F>(items: Vec<T>, options: &SocietyJsonOptions, timestamp: F) -> Vec<T>
where
    F: Fn(&T) -> u64,
{
    let mut filtered = items
        .into_iter()
        .filter(|item| {
            options
                .activity_since
                .is_none_or(|since| timestamp(item) >= since)
        })
        .collect::<Vec<_>>();

    if let Some(limit) = options.activity_limit {
        let drop_count = filtered.len().saturating_sub(limit);
        if drop_count > 0 {
            filtered.drain(0..drop_count);
        }
    }

    filtered
}

fn task_result_activity_timestamp(result: &TaskResult) -> u64 {
    result
        .receipt
        .as_deref()
        .map(|receipt| receipt.finished_at)
        .unwrap_or_default()
}

fn workspace_snapshot_json(snapshot: &WorkspaceSnapshot) -> serde_json::Value {
    serde_json::json!({
        "workspace": snapshot.workspace.to_string(),
        "actor": snapshot.actor.to_string(),
        "root": hex::encode(snapshot.root.as_bytes()),
        "label": snapshot.label,
        "note": snapshot.note,
        "timestamp": snapshot.timestamp,
    })
}

fn workspace_run_json(run: &WorkspaceRun) -> serde_json::Value {
    serde_json::json!({
        "workspace": run.workspace.to_string(),
        "actor": run.actor.to_string(),
        "command": run.command,
        "args": run.args,
        "exit_code": run.exit_code,
        "stdout": hex::encode(run.stdout.as_bytes()),
        "stderr": hex::encode(run.stderr.as_bytes()),
        "output_root": run.output_root.map(|root| hex::encode(root.as_bytes())),
        "resources": run.resources,
        "context": run.context.as_ref().map(workspace_run_context_json),
        "failure": run.failure.as_ref().map(workspace_run_failure_json),
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "note": run.note,
    })
}

fn workspace_run_failure_json(failure: &WorkspaceRunFailure) -> serde_json::Value {
    serde_json::json!({
        "kind": failure.kind,
        "message": failure.message,
    })
}

fn workspace_run_context_json(context: &WorkspaceRunContext) -> serde_json::Value {
    serde_json::json!({
        "working_dir": context.working_dir.as_ref(),
        "env_keys": &context.env_keys,
        "stdin": context.stdin.as_ref().map(|stdin| serde_json::json!({
            "bytes": stdin.bytes,
            "cid": hex::encode(stdin.cid.as_bytes()),
        })),
        "timeout_ms": context.timeout_ms,
    })
}

fn workspace_run_context_from_exec_options(options: &ExecOptions) -> Option<WorkspaceRunContext> {
    let mut env_keys = options
        .env
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    env_keys.sort();
    env_keys.dedup();

    let context = WorkspaceRunContext {
        working_dir: options
            .working_dir
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        env_keys,
        stdin: options.stdin.as_ref().map(|stdin| WorkspaceRunStdin {
            bytes: stdin.len() as u64,
            cid: Cid::hash_of(stdin),
        }),
        timeout_ms: options
            .timeout
            .map(|timeout| u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
    };

    (!context.is_empty()).then_some(context)
}

fn interaction_json(interaction: &Interaction) -> serde_json::Value {
    serde_json::json!({
        "id": interaction.id,
        "from": interaction.from.to_string(),
        "to": interaction.to.to_string(),
        "workspace": interaction.workspace.map(|workspace| workspace.to_string()),
        "topic": interaction.topic,
        "outcome": interaction.outcome,
        "timestamp": interaction.timestamp,
        "evidence": interaction.evidence,
    })
}

fn reputation_json((from, to, score): (&Did, &Did, &ReputationScore)) -> serde_json::Value {
    serde_json::json!({
        "from": from.to_string(),
        "to": to.to_string(),
        "subject": score.subject.to_string(),
        "availability": score.availability,
        "correctness": score.correctness,
        "timeliness": score.timeliness,
        "fairness": score.fairness,
        "successes": score.successes,
        "failures": score.failures,
        "composite": score.composite(),
        "first_seen": score.first_seen,
        "last_seen": score.last_seen,
    })
}

fn task_result_json(result: &TaskResult) -> serde_json::Value {
    serde_json::json!({
        "task_id": result.task_id,
        "executor": result.executor.to_string(),
        "success": result.success,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "actual_cost": result.actual_cost,
        "error": result.error,
        "receipt": result.receipt.as_deref().map(execution_receipt_json),
    })
}

fn settlement_json(settlement: &SettlementRecord) -> serde_json::Value {
    serde_json::json!({
        "id": settlement.id,
        "task_id": settlement.task_id,
        "claim_id": settlement.claim_id,
        "payer": settlement.payer.to_string(),
        "payee": settlement.payee.to_string(),
        "amount": settlement.amount,
        "proof": settlement.proof,
        "settled_at": settlement.settled_at,
    })
}

fn task_result_claim_json(
    society: &nexus_agent::Society,
    result: &TaskResult,
) -> serde_json::Value {
    let claim_id = task_result_claim_id(result);
    let mut value = task_result_json(result);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "claim_id".into(),
            serde_json::Value::String(claim_id.clone()),
        );
        object.insert(
            "judgments".into(),
            serde_json::Value::Array(
                society
                    .result_claim_judgments(&result.task_id, &claim_id)
                    .into_iter()
                    .map(task_claim_judgment_json)
                    .collect(),
            ),
        );
    }
    value
}

fn task_claim_judgment_json(judgment: TaskClaimJudgment) -> serde_json::Value {
    serde_json::json!({
        "collective_id": judgment.collective_id,
        "proposal_id": judgment.proposal_id,
        "decider": judgment.decider.to_string(),
        "outcome": judgment.outcome,
        "task_id": judgment.task_id,
        "claim_id": judgment.claim_id,
        "target": judgment.target.as_ref().map(ToString::to_string),
        "reason": judgment.reason,
        "timestamp": judgment.timestamp,
    })
}

fn execution_receipt_json(receipt: &ExecutionReceipt) -> serde_json::Value {
    serde_json::json!({
        "task_id": receipt.task_id,
        "executor": receipt.executor.to_string(),
        "workspace": receipt.workspace.map(|workspace| workspace.to_string()),
        "command": receipt.command,
        "args": receipt.args,
        "exit_code": receipt.exit_code,
        "stdout_cid": hex::encode(receipt.stdout_cid.as_bytes()),
        "stderr_cid": hex::encode(receipt.stderr_cid.as_bytes()),
        "output_root": receipt.output_root.map(|root| hex::encode(root.as_bytes())),
        "resources": receipt.resources,
        "started_at": receipt.started_at,
        "finished_at": receipt.finished_at,
        "signature": receipt.signature.as_ref().map(hex::encode),
    })
}

// ---------------------------------------------------------------------------
// event
// ---------------------------------------------------------------------------

fn cmd_event(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() < 3 {
        return Err(
            "event subcommand required: manifest, intent, workspace-join, workspace-snapshot, workspace-run, capability, collective, collective-join, collective-workspace, collective-proposal, collective-vote, collective-decision, relation, interaction, task-publish, task-offer, task-accept, task-cancel, task-complete, task-dispute, or settlement"
                .into(),
        );
    }

    match args[2].as_str() {
        "manifest" => cmd_event_manifest(args),
        "intent" | "goal" | "need" | "offer-intent" | "proposal-intent" | "status" => {
            cmd_event_intent(args)
        }
        "intent-response" | "respond" | "response" => cmd_event_intent_response(args),
        "workspace-join" | "workspace" | "join" => cmd_event_workspace_join(args),
        "workspace-snapshot" | "snapshot" => cmd_event_workspace_snapshot(args),
        "workspace-run" | "run" => cmd_event_workspace_run(args),
        "capability" | "capability-issue" | "invite" => cmd_event_capability(args),
        "collective" | "collective-declare" | "collective-create" => cmd_event_collective(args),
        "collective-join" => cmd_event_collective_join(args),
        "collective-workspace" | "collective-attach-workspace" => {
            cmd_event_collective_workspace(args)
        }
        "collective-proposal" | "proposal" => cmd_event_collective_proposal(args),
        "collective-vote" | "vote" => cmd_event_collective_vote(args),
        "collective-decision" | "decision" => cmd_event_collective_decision(args),
        "relation" => cmd_event_relation(args),
        "interaction" => cmd_event_interaction(args),
        "task-publish" => cmd_event_task_publish(args),
        "task-offer" => cmd_event_task_offer(args),
        "task-accept" | "task-accepted" | "accept" => cmd_event_task_accept(args),
        "task-cancel" | "task-cancelled" | "cancel" => cmd_event_task_cancel(args),
        "task-complete" => cmd_event_task_complete(args),
        "task-dispute" | "dispute" => cmd_event_task_dispute(args),
        "settlement" | "settle" => cmd_event_settlement(args),
        other => Err(format!("unknown event subcommand: {other}").into()),
    }
}

fn cmd_event_manifest(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut name = None;
    let mut description = None;
    let mut provides = Vec::new();
    let mut requires = Vec::new();
    let mut goals = Vec::new();
    let mut values = Vec::new();
    let mut preferences = Vec::new();
    let mut roles = Vec::new();
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--name" => {
                i += 1;
                name = Some(required_arg(args, i, "--name")?.to_string());
            }
            "--description" => {
                i += 1;
                description = Some(required_arg(args, i, "--description")?.to_string());
            }
            "--provide" => {
                i += 1;
                provides.push(capability_from_name(required_arg(args, i, "--provide")?));
            }
            "--require" => {
                i += 1;
                requires.push(capability_from_name(required_arg(args, i, "--require")?));
            }
            "--goal" => {
                i += 1;
                goals.push(required_arg(args, i, "--goal")?.to_string());
            }
            "--value" => {
                i += 1;
                values.push(required_arg(args, i, "--value")?.to_string());
            }
            "--preference" => {
                i += 1;
                preferences.push(required_arg(args, i, "--preference")?.to_string());
            }
            "--role" => {
                i += 1;
                roles.push(required_arg(args, i, "--role")?.to_string());
            }
            other => return Err(format!("unknown manifest option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            let manifest_name = name.unwrap_or_else(|| {
                base.file_name()
                    .and_then(|value| value.to_str())
                    .filter(|value| !value.is_empty())
                    .unwrap_or("nexus-node")
                    .to_string()
            });
            let mut manifest = AgentManifest::new(identity.did().clone(), &manifest_name, now);
            manifest.description = description.unwrap_or_default();
            manifest.provides = provides;
            manifest.requires = requires;
            manifest.goals = goals;
            manifest.values = values;
            manifest.preferences = preferences;
            manifest.workspace_roles = roles;
            Ok(SocialEventKind::ManifestPublished { manifest })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_intent(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut id = None;
    let mut kind = match args.get(2).map(String::as_str) {
        Some("goal") => Some(IntentKind::Goal),
        Some("need") => Some(IntentKind::Need),
        Some("offer-intent") => Some(IntentKind::Offer),
        Some("proposal-intent") => Some(IntentKind::Proposal),
        Some("status") => Some(IntentKind::Status),
        _ => None,
    };
    let mut title = None;
    let mut body = String::new();
    let mut workspace = None;
    let mut task_id = None;
    let mut capability = None;
    let mut tags = Vec::new();
    let mut expires_at = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--id" | "--intent" => {
                i += 1;
                id = Some(required_arg(args, i, "--id")?.to_string());
            }
            "--kind" | "--type" => {
                i += 1;
                kind = Some(parse_intent_kind(required_arg(args, i, "--kind")?)?);
            }
            "--title" => {
                i += 1;
                title = Some(required_arg(args, i, "--title")?.to_string());
            }
            "--body" | "--note" => {
                i += 1;
                body = required_arg(args, i, "--body")?.to_string();
            }
            "--workspace" => {
                i += 1;
                workspace = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--task" | "--task-id" => {
                i += 1;
                task_id = Some(required_arg(args, i, "--task")?.to_string());
            }
            "--capability" | "--cap" => {
                i += 1;
                capability = Some(required_arg(args, i, "--capability")?.to_string());
            }
            "--tag" => {
                i += 1;
                tags.push(required_arg(args, i, "--tag")?.to_string());
            }
            "--expires-at" | "--expires" => {
                i += 1;
                expires_at = Some(parse_u64_arg(
                    required_arg(args, i, "--expires-at")?,
                    "--expires-at",
                )?);
            }
            other => return Err(format!("unknown intent option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            let mut intent = AgentIntent::new(
                identity.did().clone(),
                kind.ok_or("--kind required")?,
                title.ok_or("--title required")?,
                body,
                workspace,
                task_id,
                capability,
                tags,
                now,
                expires_at,
            );
            if let Some(id) = id {
                intent.id = id;
            } else {
                intent.id = random_social_id();
            }
            Ok(SocialEventKind::IntentPublished { intent })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_intent_response(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut id = None;
    let mut intent_id = None;
    let mut kind = None;
    let mut body = String::new();
    let mut workspace = None;
    let mut task_id = None;
    let mut capability = None;
    let mut evidence = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--id" | "--response" => {
                i += 1;
                id = Some(required_arg(args, i, "--id")?.to_string());
            }
            "--intent" | "--intent-id" => {
                i += 1;
                intent_id = Some(required_arg(args, i, "--intent")?.to_string());
            }
            "--kind" | "--type" => {
                i += 1;
                kind = Some(parse_intent_response_kind(required_arg(
                    args, i, "--kind",
                )?)?);
            }
            "--body" | "--note" => {
                i += 1;
                body = required_arg(args, i, "--body")?.to_string();
            }
            "--workspace" => {
                i += 1;
                workspace = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--task" | "--task-id" => {
                i += 1;
                task_id = Some(required_arg(args, i, "--task")?.to_string());
            }
            "--capability" | "--cap" => {
                i += 1;
                capability = Some(required_arg(args, i, "--capability")?.to_string());
            }
            "--evidence" => {
                i += 1;
                evidence = Some(required_arg(args, i, "--evidence")?.to_string());
            }
            other => return Err(format!("unknown intent-response option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            let mut response = IntentResponse::new(
                intent_id.ok_or("--intent required")?,
                identity.did().clone(),
                kind.ok_or("--kind required")?,
                body,
                workspace,
                task_id,
                capability,
                evidence,
                now,
            );
            if let Some(id) = id {
                response.id = id;
            } else {
                response.id = random_social_id();
            }
            Ok(SocialEventKind::IntentResponded { response })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_workspace_join(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut workspace = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--workspace" => {
                i += 1;
                workspace = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            other => return Err(format!("unknown workspace-join option: {other}").into()),
        }
        i += 1;
    }

    let event = signed_local_event(
        &base,
        |_identity| {
            Ok(SocialEventKind::WorkspaceJoined {
                workspace: workspace.ok_or("--workspace required")?,
            })
        },
        unix_now(),
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_workspace_snapshot(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut workspace = None;
    let mut root = None;
    let mut label = None;
    let mut note = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--workspace" => {
                i += 1;
                workspace = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--root" | "--cid" => {
                i += 1;
                root = Some(parse_cid(required_arg(args, i, "--root")?)?);
            }
            "--label" => {
                i += 1;
                label = Some(required_arg(args, i, "--label")?.to_string());
            }
            "--note" => {
                i += 1;
                note = Some(required_arg(args, i, "--note")?.to_string());
            }
            other => return Err(format!("unknown workspace-snapshot option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::WorkspaceSnapshotted {
                snapshot: WorkspaceSnapshot {
                    workspace: workspace.ok_or("--workspace required")?,
                    actor: identity.did().clone(),
                    root: root.ok_or("--root required")?,
                    label,
                    note,
                    timestamp: now,
                },
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_workspace_run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut workspace = None;
    let mut command = None;
    let mut run_args = Vec::new();
    let mut exit_code = None;
    let mut stdout = Cid::hash_of(b"");
    let mut stderr = Cid::hash_of(b"");
    let mut output_root = None;
    let mut started_at = None;
    let mut finished_at = None;
    let mut note = None;
    let mut context = WorkspaceRunContext::default();
    let mut stdin_cid = None;
    let mut stdin_bytes = None;
    let mut failure_kind = None;
    let mut failure_message = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--workspace" => {
                i += 1;
                workspace = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--command" => {
                i += 1;
                command = Some(required_arg(args, i, "--command")?.to_string());
            }
            "--arg" => {
                i += 1;
                run_args.push(required_arg(args, i, "--arg")?.to_string());
            }
            "--exit-code" => {
                i += 1;
                exit_code = Some(parse_i32_arg(
                    required_arg(args, i, "--exit-code")?,
                    "--exit-code",
                )?);
            }
            "--stdout" => {
                i += 1;
                stdout = Cid::hash_of(required_arg(args, i, "--stdout")?.as_bytes());
            }
            "--stdout-cid" => {
                i += 1;
                stdout = parse_cid(required_arg(args, i, "--stdout-cid")?)?;
            }
            "--stderr" => {
                i += 1;
                stderr = Cid::hash_of(required_arg(args, i, "--stderr")?.as_bytes());
            }
            "--stderr-cid" => {
                i += 1;
                stderr = parse_cid(required_arg(args, i, "--stderr-cid")?)?;
            }
            "--output-root" | "--root" => {
                i += 1;
                output_root = Some(parse_cid(required_arg(args, i, "--output-root")?)?);
            }
            "--cwd" | "--working-dir" => {
                i += 1;
                context.working_dir = Some(required_arg(args, i, "--cwd")?.to_string());
            }
            "--env-key" => {
                i += 1;
                let key = required_arg(args, i, "--env-key")?;
                if key.is_empty() {
                    return Err("--env-key cannot be empty".into());
                }
                context.env_keys.push(key.to_string());
            }
            "--stdin" => {
                i += 1;
                if context.stdin.is_some() || stdin_cid.is_some() || stdin_bytes.is_some() {
                    return Err("only one stdin source may be provided".into());
                }
                let stdin = required_arg(args, i, "--stdin")?.as_bytes().to_vec();
                context.stdin = Some(WorkspaceRunStdin {
                    bytes: stdin.len() as u64,
                    cid: Cid::hash_of(&stdin),
                });
            }
            "--stdin-cid" => {
                i += 1;
                if context.stdin.is_some() {
                    return Err("only one stdin source may be provided".into());
                }
                if stdin_cid.is_some() {
                    return Err("--stdin-cid may only be provided once".into());
                }
                stdin_cid = Some(parse_cid(required_arg(args, i, "--stdin-cid")?)?);
            }
            "--stdin-bytes" => {
                i += 1;
                if context.stdin.is_some() {
                    return Err("only one stdin source may be provided".into());
                }
                if stdin_bytes.is_some() {
                    return Err("--stdin-bytes may only be provided once".into());
                }
                stdin_bytes = Some(parse_u64_arg(
                    required_arg(args, i, "--stdin-bytes")?,
                    "--stdin-bytes",
                )?);
            }
            "--timeout-ms" => {
                i += 1;
                context.timeout_ms = Some(parse_u64_arg(
                    required_arg(args, i, "--timeout-ms")?,
                    "--timeout-ms",
                )?);
            }
            "--started-at" => {
                i += 1;
                started_at = Some(parse_u64_arg(
                    required_arg(args, i, "--started-at")?,
                    "--started-at",
                )?);
            }
            "--finished-at" => {
                i += 1;
                finished_at = Some(parse_u64_arg(
                    required_arg(args, i, "--finished-at")?,
                    "--finished-at",
                )?);
            }
            "--note" => {
                i += 1;
                note = Some(required_arg(args, i, "--note")?.to_string());
            }
            "--failure-kind" => {
                i += 1;
                let kind = required_arg(args, i, "--failure-kind")?;
                if kind.is_empty() {
                    return Err("--failure-kind cannot be empty".into());
                }
                failure_kind = Some(kind.to_string());
            }
            "--failure-message" => {
                i += 1;
                failure_message = Some(required_arg(args, i, "--failure-message")?.to_string());
            }
            other => return Err(format!("unknown workspace-run option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let started_at = started_at.unwrap_or(now);
    let finished_at = finished_at.unwrap_or(started_at);
    match (stdin_cid, stdin_bytes) {
        (Some(cid), Some(bytes)) => {
            context.stdin = Some(WorkspaceRunStdin { bytes, cid });
        }
        (Some(_), None) => return Err("--stdin-cid requires --stdin-bytes".into()),
        (None, Some(_)) => return Err("--stdin-bytes requires --stdin-cid".into()),
        (None, None) => {}
    }
    context.env_keys.sort();
    context.env_keys.dedup();
    let context = (!context.is_empty()).then_some(context);
    let failure = match (failure_kind, failure_message) {
        (Some(kind), Some(message)) => Some(WorkspaceRunFailure { kind, message }),
        (Some(_), None) => return Err("--failure-kind requires --failure-message".into()),
        (None, Some(_)) => return Err("--failure-message requires --failure-kind".into()),
        (None, None) => None,
    };
    let exit_code = exit_code.unwrap_or(if failure.is_some() { -1 } else { 0 });
    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::WorkspaceRunRecorded {
                run: Box::new(WorkspaceRun {
                    workspace: workspace.ok_or("--workspace required")?,
                    actor: identity.did().clone(),
                    command: command.ok_or("--command required")?,
                    args: run_args,
                    exit_code,
                    stdout,
                    stderr,
                    output_root,
                    resources: ResourceUsage {
                        process_count: 1,
                        ..Default::default()
                    },
                    context,
                    failure,
                    started_at,
                    finished_at,
                    note,
                }),
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_capability(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut subject = None;
    let mut workspace = None;
    let mut permissions = PermissionSet::FULL;
    let mut saw_permission = false;
    let mut expires_at = None;
    let mut note = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--subject" | "--guest" | "--peer" => {
                i += 1;
                subject = Some(Did::new(required_arg(args, i, "--subject")?.to_string()));
            }
            "--workspace" => {
                i += 1;
                workspace = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--permission" | "--perm" => {
                i += 1;
                if !saw_permission {
                    permissions = PermissionSet {
                        read: false,
                        write: false,
                        exec: false,
                        admin: false,
                    };
                    saw_permission = true;
                }
                apply_permission(&mut permissions, required_arg(args, i, "--permission")?)?;
            }
            "--expires-at" | "--expires" => {
                i += 1;
                expires_at = Some(parse_u64_arg(
                    required_arg(args, i, "--expires-at")?,
                    "--expires-at",
                )?);
            }
            "--note" => {
                i += 1;
                note = Some(required_arg(args, i, "--note")?.to_string());
            }
            other => return Err(format!("unknown capability option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            let capability = sign_capability(
                identity,
                &subject.ok_or("--subject required")?,
                workspace.ok_or("--workspace required")?,
                permissions.clone(),
                expires_at.unwrap_or(u64::MAX),
            )?;
            Ok(SocialEventKind::CapabilityIssued {
                grant: CapabilityGrant {
                    capability,
                    issued_at: now,
                    note,
                },
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_collective(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut collective_id = None;
    let mut name = None;
    let mut purpose = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--id" | "--collective" => {
                i += 1;
                collective_id = Some(required_arg(args, i, "--id")?.to_string());
            }
            "--name" => {
                i += 1;
                name = Some(required_arg(args, i, "--name")?.to_string());
            }
            "--purpose" => {
                i += 1;
                purpose = Some(required_arg(args, i, "--purpose")?.to_string());
            }
            other => return Err(format!("unknown collective option: {other}").into()),
        }
        i += 1;
    }

    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::CollectiveDeclared {
                collective_id: collective_id.ok_or("--id required")?,
                name: name.ok_or("--name required")?,
                purpose: purpose.ok_or("--purpose required")?,
                members: vec![identity.did().clone()],
            })
        },
        unix_now(),
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_collective_join(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut collective_id = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--id" | "--collective" => {
                i += 1;
                collective_id = Some(required_arg(args, i, "--id")?.to_string());
            }
            other => return Err(format!("unknown collective-join option: {other}").into()),
        }
        i += 1;
    }

    let event = signed_local_event(
        &base,
        |_identity| {
            Ok(SocialEventKind::CollectiveJoined {
                collective_id: collective_id.ok_or("--id required")?,
            })
        },
        unix_now(),
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_collective_workspace(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut collective_id = None;
    let mut workspace = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--id" | "--collective" => {
                i += 1;
                collective_id = Some(required_arg(args, i, "--id")?.to_string());
            }
            "--workspace" => {
                i += 1;
                workspace = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            other => return Err(format!("unknown collective-workspace option: {other}").into()),
        }
        i += 1;
    }

    let event = signed_local_event(
        &base,
        |_identity| {
            Ok(SocialEventKind::CollectiveWorkspaceAttached {
                collective_id: collective_id.ok_or("--id required")?,
                workspace: workspace.ok_or("--workspace required")?,
            })
        },
        unix_now(),
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_collective_proposal(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut collective_id = None;
    let mut proposal_id = None;
    let mut title = None;
    let mut body = None;
    let mut workspace = None;
    let mut deadline = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--collective" | "--collective-id" => {
                i += 1;
                collective_id = Some(required_arg(args, i, "--collective")?.to_string());
            }
            "--proposal" | "--proposal-id" => {
                i += 1;
                proposal_id = Some(required_arg(args, i, "--proposal")?.to_string());
            }
            "--title" => {
                i += 1;
                title = Some(required_arg(args, i, "--title")?.to_string());
            }
            "--body" => {
                i += 1;
                body = Some(required_arg(args, i, "--body")?.to_string());
            }
            "--workspace" => {
                i += 1;
                workspace = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--deadline" => {
                i += 1;
                deadline = Some(parse_u64_arg(
                    required_arg(args, i, "--deadline")?,
                    "--deadline",
                )?);
            }
            other => return Err(format!("unknown collective-proposal option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::CollectiveProposalPublished {
                proposal: CollectiveProposal {
                    id: proposal_id.ok_or("--proposal required")?,
                    collective_id: collective_id.ok_or("--collective required")?,
                    proposer: identity.did().clone(),
                    title: title.ok_or("--title required")?,
                    body: body.ok_or("--body required")?,
                    workspace,
                    created_at: now,
                    deadline: deadline.unwrap_or(0),
                },
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_collective_vote(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut collective_id = None;
    let mut proposal_id = None;
    let mut choice = None;
    let mut rationale = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--collective" | "--collective-id" => {
                i += 1;
                collective_id = Some(required_arg(args, i, "--collective")?.to_string());
            }
            "--proposal" | "--proposal-id" => {
                i += 1;
                proposal_id = Some(required_arg(args, i, "--proposal")?.to_string());
            }
            "--choice" => {
                i += 1;
                choice = Some(parse_collective_vote_choice(required_arg(
                    args, i, "--choice",
                )?)?);
            }
            "--rationale" => {
                i += 1;
                rationale = Some(required_arg(args, i, "--rationale")?.to_string());
            }
            other => return Err(format!("unknown collective-vote option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::CollectiveVoteCast {
                vote: CollectiveVote {
                    proposal_id: proposal_id.ok_or("--proposal required")?,
                    collective_id: collective_id.ok_or("--collective required")?,
                    voter: identity.did().clone(),
                    choice: choice.ok_or("--choice required")?,
                    rationale: rationale.unwrap_or_default(),
                    timestamp: now,
                },
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_collective_decision(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut collective_id = None;
    let mut proposal_id = None;
    let mut outcome = None;
    let mut task_id = None;
    let mut claim_id = None;
    let mut target = None;
    let mut reason = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--collective" | "--collective-id" => {
                i += 1;
                collective_id = Some(required_arg(args, i, "--collective")?.to_string());
            }
            "--proposal" | "--proposal-id" => {
                i += 1;
                proposal_id = Some(required_arg(args, i, "--proposal")?.to_string());
            }
            "--outcome" => {
                i += 1;
                outcome = Some(parse_collective_decision_outcome(required_arg(
                    args,
                    i,
                    "--outcome",
                )?)?);
            }
            "--task" | "--task-id" => {
                i += 1;
                task_id = Some(required_arg(args, i, "--task")?.to_string());
            }
            "--claim" | "--claim-id" => {
                i += 1;
                claim_id = Some(required_arg(args, i, "--claim")?.to_string());
            }
            "--target" | "--peer" => {
                i += 1;
                target = Some(Did::new(required_arg(args, i, "--target")?.to_string()));
            }
            "--reason" => {
                i += 1;
                reason = Some(required_arg(args, i, "--reason")?.to_string());
            }
            other => return Err(format!("unknown collective-decision option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::CollectiveDecisionRecorded {
                decision: CollectiveDecision {
                    proposal_id: proposal_id.ok_or("--proposal required")?,
                    collective_id: collective_id.ok_or("--collective required")?,
                    decider: identity.did().clone(),
                    outcome: outcome.ok_or("--outcome required")?,
                    task_id,
                    claim_id,
                    target,
                    reason: reason.unwrap_or_default(),
                    timestamp: now,
                },
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_relation(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut peer = None;
    let mut relation = None;
    let mut note = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--peer" => {
                i += 1;
                peer = Some(Did::new(required_arg(args, i, "--peer")?.to_string()));
            }
            "--kind" => {
                i += 1;
                relation = Some(parse_relation_kind(required_arg(args, i, "--kind")?)?);
            }
            "--note" => {
                i += 1;
                note = Some(required_arg(args, i, "--note")?.to_string());
            }
            other => return Err(format!("unknown relation option: {other}").into()),
        }
        i += 1;
    }

    let event = signed_local_event(
        &base,
        |_identity| {
            Ok(SocialEventKind::RelationDeclared {
                peer: peer.ok_or("--peer required")?,
                relation: relation.ok_or("--kind required")?,
                note,
            })
        },
        unix_now(),
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_interaction(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut peer = None;
    let mut topic = None;
    let mut outcome = None;
    let mut workspace = None;
    let mut evidence = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--peer" => {
                i += 1;
                peer = Some(Did::new(required_arg(args, i, "--peer")?.to_string()));
            }
            "--topic" => {
                i += 1;
                topic = Some(required_arg(args, i, "--topic")?.to_string());
            }
            "--outcome" => {
                i += 1;
                outcome = Some(parse_interaction_outcome(required_arg(
                    args,
                    i,
                    "--outcome",
                )?)?);
            }
            "--workspace" => {
                i += 1;
                workspace = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--evidence" => {
                i += 1;
                evidence = Some(required_arg(args, i, "--evidence")?.to_string());
            }
            other => return Err(format!("unknown interaction option: {other}").into()),
        }
        i += 1;
    }

    let event = signed_local_event(
        &base,
        |identity| {
            let mut interaction = Interaction::new(
                identity.did().clone(),
                peer.ok_or("--peer required")?,
                workspace,
                topic.ok_or("--topic required")?,
                outcome.ok_or("--outcome required")?,
                unix_now(),
            );
            interaction.evidence = evidence;
            Ok(SocialEventKind::InteractionRecorded { interaction })
        },
        unix_now(),
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_task_publish(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut description = None;
    let mut capability = None;
    let mut command = None;
    let mut task_args = Vec::new();
    let mut max_budget = None;
    let mut deadline = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--description" => {
                i += 1;
                description = Some(required_arg(args, i, "--description")?.to_string());
            }
            "--capability" => {
                i += 1;
                capability = Some(required_arg(args, i, "--capability")?.to_string());
            }
            "--command" => {
                i += 1;
                command = Some(required_arg(args, i, "--command")?.to_string());
            }
            "--arg" => {
                i += 1;
                task_args.push(required_arg(args, i, "--arg")?.to_string());
            }
            "--max-budget" => {
                i += 1;
                max_budget = Some(parse_u64_arg(
                    required_arg(args, i, "--max-budget")?,
                    "--max-budget",
                )?);
            }
            "--deadline" => {
                i += 1;
                deadline = Some(parse_u64_arg(
                    required_arg(args, i, "--deadline")?,
                    "--deadline",
                )?);
            }
            other => return Err(format!("unknown task-publish option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::TaskPublished {
                task: TaskSpec::new(
                    identity.did().clone(),
                    description.ok_or("--description required")?,
                    capability.ok_or("--capability required")?,
                    command.ok_or("--command required")?,
                    task_args,
                    max_budget.ok_or("--max-budget required")?,
                    deadline.unwrap_or(0),
                    now,
                ),
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_task_offer(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut task_id = None;
    let mut price = None;
    let mut estimated_time_secs = None;
    let mut rationale = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--task" | "--task-id" => {
                i += 1;
                task_id = Some(required_arg(args, i, "--task")?.to_string());
            }
            "--price" => {
                i += 1;
                price = Some(parse_u64_arg(required_arg(args, i, "--price")?, "--price")?);
            }
            "--eta" | "--estimated-time" => {
                i += 1;
                estimated_time_secs =
                    Some(parse_u64_arg(required_arg(args, i, "--eta")?, "--eta")?);
            }
            "--rationale" => {
                i += 1;
                rationale = Some(required_arg(args, i, "--rationale")?.to_string());
            }
            other => return Err(format!("unknown task-offer option: {other}").into()),
        }
        i += 1;
    }

    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.ok_or("--task required")?,
                    bidder: identity.did().clone(),
                    price: price.ok_or("--price required")?,
                    estimated_time_secs: estimated_time_secs.unwrap_or(0),
                    rationale: rationale.unwrap_or_default(),
                },
            })
        },
        unix_now(),
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_task_accept(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut task_id = None;
    let mut bidder = None;
    let mut price = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--task" | "--task-id" => {
                i += 1;
                task_id = Some(required_arg(args, i, "--task")?.to_string());
            }
            "--bidder" => {
                i += 1;
                bidder = Some(Did::new(required_arg(args, i, "--bidder")?.to_string()));
            }
            "--price" => {
                i += 1;
                price = Some(parse_u64_arg(required_arg(args, i, "--price")?, "--price")?);
            }
            other => return Err(format!("unknown task-accept option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::TaskAccepted {
                acceptance: TaskAcceptance {
                    task_id: task_id.ok_or("--task required")?,
                    publisher: identity.did().clone(),
                    bidder: bidder.ok_or("--bidder required")?,
                    price: price.ok_or("--price required")?,
                    accepted_at: now,
                },
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_task_cancel(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut task_id = None;
    let mut reason = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--task" | "--task-id" => {
                i += 1;
                task_id = Some(required_arg(args, i, "--task")?.to_string());
            }
            "--reason" => {
                i += 1;
                reason = Some(required_arg(args, i, "--reason")?.to_string());
            }
            other => return Err(format!("unknown task-cancel option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::TaskCancelled {
                cancellation: TaskCancellation {
                    task_id: task_id.ok_or("--task required")?,
                    publisher: identity.did().clone(),
                    reason: reason.ok_or("--reason required")?,
                    cancelled_at: now,
                },
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_task_complete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut task_id = None;
    let mut success = None;
    let mut exit_code = None;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut actual_cost = None;
    let mut error = None;
    let mut with_receipt = false;
    let mut command = None;
    let mut receipt_args = Vec::new();
    let mut workspace = None;
    let mut output_root = None;
    let mut started_at = None;
    let mut finished_at = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--task" | "--task-id" => {
                i += 1;
                task_id = Some(required_arg(args, i, "--task")?.to_string());
            }
            "--success" => {
                success = Some(true);
            }
            "--failure" => {
                success = Some(false);
            }
            "--exit-code" => {
                i += 1;
                exit_code = Some(parse_i32_arg(
                    required_arg(args, i, "--exit-code")?,
                    "--exit-code",
                )?);
            }
            "--stdout" => {
                i += 1;
                stdout = required_arg(args, i, "--stdout")?.to_string();
            }
            "--stderr" => {
                i += 1;
                stderr = required_arg(args, i, "--stderr")?.to_string();
            }
            "--actual-cost" => {
                i += 1;
                actual_cost = Some(parse_u64_arg(
                    required_arg(args, i, "--actual-cost")?,
                    "--actual-cost",
                )?);
            }
            "--error" => {
                i += 1;
                error = Some(required_arg(args, i, "--error")?.to_string());
            }
            "--receipt" => {
                with_receipt = true;
            }
            "--command" => {
                i += 1;
                command = Some(required_arg(args, i, "--command")?.to_string());
            }
            "--arg" => {
                i += 1;
                receipt_args.push(required_arg(args, i, "--arg")?.to_string());
            }
            "--workspace" => {
                i += 1;
                workspace = Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--output-root" => {
                i += 1;
                output_root = Some(parse_cid(required_arg(args, i, "--output-root")?)?);
            }
            "--started-at" => {
                i += 1;
                started_at = Some(parse_u64_arg(
                    required_arg(args, i, "--started-at")?,
                    "--started-at",
                )?);
            }
            "--finished-at" => {
                i += 1;
                finished_at = Some(parse_u64_arg(
                    required_arg(args, i, "--finished-at")?,
                    "--finished-at",
                )?);
            }
            other => return Err(format!("unknown task-complete option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            let success = success.ok_or("--success or --failure required")?;
            let task_id = task_id.ok_or("--task required")?;
            let exit_code = exit_code.unwrap_or(if success { 0 } else { 1 });
            let receipt = if with_receipt {
                let output = ProcessOutput {
                    exit_code,
                    stdout: stdout.as_bytes().to_vec(),
                    stderr: stderr.as_bytes().to_vec(),
                    resources: ResourceUsage::default(),
                };
                Some(Box::new(
                    ExecutionReceipt::from_process_output(
                        task_id.clone(),
                        identity.did().clone(),
                        workspace,
                        command.ok_or("--command required when --receipt is set")?,
                        receipt_args,
                        &output,
                        output_root,
                        started_at.unwrap_or(now),
                        finished_at.unwrap_or(now),
                    )
                    .sign(identity)?,
                ))
            } else {
                None
            };
            Ok(SocialEventKind::TaskCompleted {
                result: TaskResult {
                    task_id,
                    executor: identity.did().clone(),
                    success,
                    exit_code,
                    stdout,
                    stderr,
                    actual_cost: actual_cost.unwrap_or(0),
                    error,
                    receipt,
                },
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_task_dispute(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut task_id = None;
    let mut target = None;
    let mut claim_id = None;
    let mut reason = None;
    let mut evidence = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--task" | "--task-id" => {
                i += 1;
                task_id = Some(required_arg(args, i, "--task")?.to_string());
            }
            "--target" | "--peer" => {
                i += 1;
                target = Some(Did::new(required_arg(args, i, "--target")?.to_string()));
            }
            "--reason" => {
                i += 1;
                reason = Some(required_arg(args, i, "--reason")?.to_string());
            }
            "--claim" | "--claim-id" => {
                i += 1;
                claim_id = Some(required_arg(args, i, "--claim")?.to_string());
            }
            "--evidence" => {
                i += 1;
                evidence = Some(required_arg(args, i, "--evidence")?.to_string());
            }
            other => return Err(format!("unknown task-dispute option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::TaskDisputed {
                dispute: TaskDispute {
                    task_id: task_id.ok_or("--task required")?,
                    disputer: identity.did().clone(),
                    target: target.ok_or("--target required")?,
                    claim_id,
                    reason: reason.ok_or("--reason required")?,
                    evidence,
                    timestamp: now,
                },
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn cmd_event_settlement(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut id = None;
    let mut task_id = None;
    let mut claim_id = None;
    let mut payee = None;
    let mut amount = None;
    let mut proof = SettlementProof::Sovereign;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--id" => {
                i += 1;
                id = Some(required_arg(args, i, "--id")?.to_string());
            }
            "--task" | "--task-id" => {
                i += 1;
                task_id = Some(required_arg(args, i, "--task")?.to_string());
            }
            "--claim" | "--claim-id" => {
                i += 1;
                claim_id = Some(required_arg(args, i, "--claim")?.to_string());
            }
            "--payee" => {
                i += 1;
                payee = Some(Did::new(required_arg(args, i, "--payee")?.to_string()));
            }
            "--amount" => {
                i += 1;
                amount = Some(parse_u64_arg(
                    required_arg(args, i, "--amount")?,
                    "--amount",
                )?);
            }
            "--proof" => {
                i += 1;
                let value = required_arg(args, i, "--proof")?;
                proof = match value {
                    "sovereign" | "society" | "signed-event" => SettlementProof::Sovereign,
                    other => {
                        return Err(format!(
                            "unsupported settlement proof for CLI: {other}; use sovereign"
                        )
                        .into())
                    }
                };
            }
            other => return Err(format!("unknown settlement option: {other}").into()),
        }
        i += 1;
    }

    let now = unix_now();
    let event = signed_local_event(
        &base,
        |identity| {
            Ok(SocialEventKind::SettlementRecorded {
                settlement: SettlementRecord {
                    id: id.unwrap_or_else(random_social_id),
                    task_id,
                    claim_id,
                    payer: identity.did().clone(),
                    payee: payee.ok_or("--payee required")?,
                    amount: amount.ok_or("--amount required")?,
                    proof,
                    settled_at: now,
                },
            })
        },
        now,
    )?;
    println!("{}", event_summary(&event));
    Ok(())
}

fn signed_local_event<F>(
    base: &Path,
    build_kind: F,
    now: u64,
) -> Result<SocialEvent, Box<dyn std::error::Error>>
where
    F: FnOnce(&NodeIdentity) -> Result<SocialEventKind, Box<dyn std::error::Error>>,
{
    let identity = load_or_create_identity(base)?;
    let memory_path = base.join(".nexus-social-memory.json");
    let mut memory = load_social_memory(&memory_path)?;
    let event =
        SocialEvent::new(identity.did().clone(), now, build_kind(&identity)?).sign(&identity)?;
    if memory.ingest_event(event.clone())? {
        save_social_memory(&memory_path, &memory)?;
    }
    Ok(event)
}

fn required_arg<'a>(
    args: &'a [String],
    index: usize,
    flag: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_u64_arg(value: &str, flag: &str) -> Result<u64, Box<dyn std::error::Error>> {
    value
        .parse::<u64>()
        .map_err(|err| format!("invalid {flag}: {err}").into())
}

fn parse_usize_arg(value: &str, flag: &str) -> Result<usize, Box<dyn std::error::Error>> {
    value
        .parse::<usize>()
        .map_err(|err| format!("invalid {flag}: {err}").into())
}

fn parse_discovery_sort(value: &str) -> Result<DiscoverySort, Box<dyn std::error::Error>> {
    match value {
        "relevance" | "relevant" => Ok(DiscoverySort::Relevance),
        "clone-ready" | "clone_ready" | "ready" => Ok(DiscoverySort::CloneReady),
        "name" => Ok(DiscoverySort::Name),
        "owner" => Ok(DiscoverySort::Owner),
        "latest" | "time" | "recent" => Ok(DiscoverySort::Latest),
        other => Err(format!(
            "invalid --sort: {other}; use relevance, clone-ready, name, owner, or latest"
        )
        .into()),
    }
}

fn parse_bootstrap_list(value: &str) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    let mut addrs = Vec::new();
    for item in value
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter(|item| !item.is_empty())
    {
        push_unique_bootstrap_addr(&mut addrs, item.parse()?);
    }
    Ok(addrs)
}

fn default_bootstrap_peers(
    base: &Path,
    use_public_defaults: bool,
) -> Result<Vec<libp2p::Multiaddr>, Box<dyn std::error::Error>> {
    match std::env::var("NEXUS_BOOTSTRAP") {
        Ok(value) => return parse_bootstrap_list(&value),
        Err(std::env::VarError::NotPresent) => {}
        Err(err) => return Err(format!("read NEXUS_BOOTSTRAP: {err}").into()),
    }

    let mut addrs = load_bootstrap_config_peers(base)?;
    for addr in peer_cache_bootstrap_peers(base) {
        push_unique_bootstrap_addr(&mut addrs, addr);
    }
    for addr in cached_workspace_bootstrap_peers(base) {
        push_unique_bootstrap_addr(&mut addrs, addr);
    }
    if use_public_defaults {
        for addr in public_default_bootstrap_peers()? {
            push_unique_bootstrap_addr(&mut addrs, addr);
        }
    }

    Ok(addrs)
}

fn bootstrap_status(
    base: &Path,
    use_public_defaults: bool,
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
    let public_default_peers = if use_public_defaults {
        public_default_bootstrap_peers()?
    } else {
        Vec::new()
    };

    let mut effective_peers = Vec::new();
    if env_configured {
        for addr in &env_peers {
            push_unique_bootstrap_addr(&mut effective_peers, addr.clone());
        }
    } else {
        for source in [
            config_peers.as_slice(),
            peer_cache_peers.as_slice(),
            discovery_cache_peers.as_slice(),
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
        config_peers: stringify_multiaddrs(&config_peers),
        peer_cache,
        peer_cache_peers: stringify_multiaddrs(&peer_cache_peers),
        discovery_cache_peers: stringify_multiaddrs(&discovery_cache_peers),
        public_default_peers: stringify_multiaddrs(&public_default_peers),
        effective_peers: stringify_multiaddrs(&effective_peers),
    })
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

fn bootstrap_config_path(base: &Path) -> PathBuf {
    base.join(".nexus-bootstrap.json")
}

fn load_bootstrap_config_peers(
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

fn cached_workspace_bootstrap_peers(base: &Path) -> Vec<libp2p::Multiaddr> {
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

fn peer_cache_path(base: &Path) -> PathBuf {
    base.join(".nexus-peer-cache.json")
}

fn load_peer_cache(base: &Path) -> Result<Vec<PeerCacheEntry>, Box<dyn std::error::Error>> {
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

fn cache_peer_from_announcement(
    base: &Path,
    announcement: &WorkspaceAnnouncement,
    now: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let addrs = announcement_bootstrap_addr_strings(announcement)?;
    upsert_peer_cache(base, &announcement.peer, &addrs, now, None, None)
}

fn mark_peer_cache_connected(
    base: &Path,
    peer: libp2p::PeerId,
    now: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    upsert_peer_cache(base, &peer.to_string(), &[], now, Some(now), Some(false))
}

fn mark_peer_cache_failure(
    base: &Path,
    peer: libp2p::PeerId,
    now: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    upsert_peer_cache(base, &peer.to_string(), &[], now, None, Some(true))
}

fn upsert_peer_cache(
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

fn peer_cache_bootstrap_peers(base: &Path) -> Vec<libp2p::Multiaddr> {
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

fn parse_i32_arg(value: &str, flag: &str) -> Result<i32, Box<dyn std::error::Error>> {
    value
        .parse::<i32>()
        .map_err(|err| format!("invalid {flag}: {err}").into())
}

fn parse_env_assignment(value: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| "invalid --env, expected KEY=VALUE".to_string())?;
    if key.is_empty() {
        return Err("invalid --env, key cannot be empty".into());
    }
    Ok((key.to_string(), value.to_string()))
}

fn capability_from_name(name: &str) -> CapabilityDecl {
    CapabilityDecl {
        name: name.to_string(),
        description: format!("Declared capability {name}"),
        version: "1.0".into(),
        price_per_unit: 0,
        price_unit: "local-policy".into(),
    }
}

fn parse_relation_kind(value: &str) -> Result<RelationKind, Box<dyn std::error::Error>> {
    match normalize_symbol(value).as_str() {
        "acquaintance" => Ok(RelationKind::Acquaintance),
        "collaborator" => Ok(RelationKind::Collaborator),
        "serviceprovider" | "service-provider" | "service_provider" => {
            Ok(RelationKind::ServiceProvider)
        }
        "mentor" => Ok(RelationKind::Mentor),
        "coowner" | "co-owner" | "co_owner" => Ok(RelationKind::CoOwner),
        "rival" => Ok(RelationKind::Rival),
        "blocked" => Ok(RelationKind::Blocked),
        _ => Err(format!("unknown relation kind: {value}").into()),
    }
}

fn parse_interaction_outcome(
    value: &str,
) -> Result<InteractionOutcome, Box<dyn std::error::Error>> {
    match normalize_symbol(value).as_str() {
        "success" => Ok(InteractionOutcome::Success),
        "neutral" => Ok(InteractionOutcome::Neutral),
        "failure" | "failed" => Ok(InteractionOutcome::Failure),
        "dispute" => Ok(InteractionOutcome::Dispute),
        _ => Err(format!("unknown interaction outcome: {value}").into()),
    }
}

fn parse_intent_kind(value: &str) -> Result<IntentKind, Box<dyn std::error::Error>> {
    match normalize_symbol(value).as_str() {
        "goal" => Ok(IntentKind::Goal),
        "need" | "request" => Ok(IntentKind::Need),
        "offer" | "provide" => Ok(IntentKind::Offer),
        "proposal" | "propose" => Ok(IntentKind::Proposal),
        "status" | "state" => Ok(IntentKind::Status),
        _ => Err(format!("unknown intent kind: {value}").into()),
    }
}

fn parse_intent_response_kind(
    value: &str,
) -> Result<IntentResponseKind, Box<dyn std::error::Error>> {
    match normalize_symbol(value).as_str() {
        "interested" | "interest" => Ok(IntentResponseKind::Interested),
        "accept" | "accepted" => Ok(IntentResponseKind::Accept),
        "decline" | "declined" | "reject" | "rejected" => Ok(IntentResponseKind::Decline),
        "counter" | "counteroffer" | "counter-offer" | "counter_offer" => {
            Ok(IntentResponseKind::Counter)
        }
        "fulfilled" | "fulfill" | "done" => Ok(IntentResponseKind::Fulfilled),
        _ => Err(format!("unknown intent response kind: {value}").into()),
    }
}

fn parse_intent_action_kind(value: &str) -> Result<IntentActionKind, Box<dyn std::error::Error>> {
    match normalize_symbol(value).as_str() {
        "respondintent" | "respond-intent" | "respond_intent" | "respond" => {
            Ok(IntentActionKind::RespondIntent)
        }
        "offertask" | "offer-task" | "offer_task" | "task-offer" | "bid" => {
            Ok(IntentActionKind::OfferTask)
        }
        "joinworkspace" | "join-workspace" | "join_workspace" | "join" => {
            Ok(IntentActionKind::JoinWorkspace)
        }
        "proposecollective"
        | "propose-collective"
        | "propose_collective"
        | "collective-proposal"
        | "proposal" => Ok(IntentActionKind::ProposeCollective),
        _ => Err(format!("unknown intent action kind: {value}").into()),
    }
}

fn parse_collective_vote_choice(
    value: &str,
) -> Result<CollectiveVoteChoice, Box<dyn std::error::Error>> {
    match normalize_symbol(value).as_str() {
        "approve" | "yes" | "y" => Ok(CollectiveVoteChoice::Approve),
        "reject" | "no" | "n" => Ok(CollectiveVoteChoice::Reject),
        "abstain" => Ok(CollectiveVoteChoice::Abstain),
        "block" | "veto" => Ok(CollectiveVoteChoice::Block),
        _ => Err(format!("unknown collective vote choice: {value}").into()),
    }
}

fn parse_collective_decision_outcome(
    value: &str,
) -> Result<CollectiveDecisionOutcome, Box<dyn std::error::Error>> {
    match normalize_symbol(value).as_str() {
        "accepted" | "accept" | "approved" | "approve" => Ok(CollectiveDecisionOutcome::Accepted),
        "rejected" | "reject" => Ok(CollectiveDecisionOutcome::Rejected),
        "deferred" | "defer" => Ok(CollectiveDecisionOutcome::Deferred),
        "disputed" | "dispute" => Ok(CollectiveDecisionOutcome::Disputed),
        _ => Err(format!("unknown collective decision outcome: {value}").into()),
    }
}

fn apply_permission(
    permissions: &mut PermissionSet,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match normalize_symbol(value).as_str() {
        "read" | "r" => permissions.read = true,
        "write" | "w" => permissions.write = true,
        "exec" | "execute" | "x" => permissions.exec = true,
        "admin" | "full" | "all" => {
            permissions.read = true;
            permissions.write = true;
            permissions.exec = true;
            permissions.admin = true;
        }
        _ => return Err(format!("unknown permission: {value}").into()),
    }
    Ok(())
}

fn normalize_symbol(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn parse_workspace_id(value: &str) -> Result<WorkspaceId, Box<dyn std::error::Error>> {
    let bytes = hex::decode(value)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "workspace id must be 32 bytes hex")?;
    Ok(WorkspaceId::from_bytes(bytes))
}

fn parse_cid(value: &str) -> Result<Cid, Box<dyn std::error::Error>> {
    let value = value
        .strip_prefix("cid:")
        .or_else(|| {
            value
                .strip_prefix("cid(")
                .and_then(|inner| inner.strip_suffix(')'))
        })
        .unwrap_or(value);
    let bytes = hex::decode(value)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "cid root must be 32 bytes hex")?;
    Ok(Cid::from_bytes(bytes))
}

fn event_summary(event: &SocialEvent) -> String {
    format!("Recorded social event {} by {}", event.id, event.author)
}

fn build_node_manifest(identity: &NodeIdentity, base: &Path, now: u64) -> AgentManifest {
    let label = base
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("nexus-node");

    AgentManifest::new(identity.did().clone(), label, now)
        .goal("maintain a free native AI workspace")
        .goal("participate in decentralized AI society")
        .value("autonomy")
        .value("verifiable social provenance")
        .preference("peer-to-peer collaboration")
        .preference("append-only social memory")
        .workspace_role("owner")
        .workspace_role("collaborator")
        .provide(CapabilityDecl {
            name: "native-workspace".into(),
            description: "Runs commands and stores files in an unrestricted native workspace"
                .into(),
            version: env!("CARGO_PKG_VERSION").into(),
            price_per_unit: 0,
            price_unit: "local-policy".into(),
        })
        .provide(CapabilityDecl {
            name: "social-event-gossip".into(),
            description: "Publishes and ingests signed AI society events over gossipsub".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            price_per_unit: 0,
            price_unit: "per-event".into(),
        })
}

fn signed_presence_events(
    identity: &NodeIdentity,
    manifest: AgentManifest,
    workspaces: &[WorkspaceId],
    now: u64,
) -> Result<Vec<SocialEvent>, Box<dyn std::error::Error>> {
    let mut events = Vec::with_capacity(1 + workspaces.len());
    events.push(
        SocialEvent::new(
            identity.did().clone(),
            now,
            SocialEventKind::ManifestPublished { manifest },
        )
        .sign(identity)?,
    );

    for workspace in workspaces {
        events.push(
            SocialEvent::new(
                identity.did().clone(),
                now,
                SocialEventKind::WorkspaceJoined {
                    workspace: *workspace,
                },
            )
            .sign(identity)?,
        );
    }

    Ok(events)
}

async fn publish_social_event_with_retry(network: &Network, event: &SocialEvent) {
    let data = match event.to_json() {
        Ok(data) => data,
        Err(err) => {
            tracing::warn!("failed to serialize social event {}: {err}", event.id);
            return;
        }
    };

    let mut last_error = None;
    for _ in 0..8 {
        match network.publish_social_event(data.clone()).await {
            Ok(()) => return,
            Err(err) => {
                last_error = Some(err);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }

    if let Some(err) = last_error {
        tracing::debug!("social event {} not broadcast yet: {err}", event.id);
    }
}

fn announce_dht_presence(network: &Network, workspace_ids: &[WorkspaceId]) {
    if let Err(err) = network.start_providing(global_discovery_key()) {
        tracing::warn!("failed to announce global DHT presence: {err}");
    }
    for workspace_id in workspace_ids {
        if let Err(err) = network.start_providing(workspace_discovery_key(workspace_id)) {
            tracing::warn!("failed to announce workspace {workspace_id} in DHT: {err}");
        }
    }
}

async fn announce_node_presence(
    identity: &NodeIdentity,
    network: &Network,
    workspace_ids: &[WorkspaceId],
    social_memory: &mut SocialMemory,
    memory_path: &Path,
    base: &Path,
    now: u64,
) {
    let manifest = build_node_manifest(identity, base, now);
    let events = match signed_presence_events(identity, manifest, workspace_ids, now) {
        Ok(events) => events,
        Err(err) => {
            tracing::warn!("failed to sign node presence events: {err}");
            return;
        }
    };

    for event in events {
        match social_memory.ingest_event(event.clone()) {
            Ok(true) => {
                if let Err(err) = save_social_memory(memory_path, social_memory) {
                    tracing::warn!("failed to save local presence event {}: {err}", event.id);
                }
                tracing::info!("recorded local presence event {}", event.id);
            }
            Ok(false) => {}
            Err(err) => {
                tracing::warn!("failed to record local presence event {}: {err}", event.id);
                continue;
            }
        }

        publish_social_event_with_retry(network, &event).await;
    }
}

fn workspace_announcement(
    identity: &NodeIdentity,
    peer: libp2p::PeerId,
    addrs: Vec<libp2p::Multiaddr>,
    workspace: &Workspace,
    now: u64,
) -> Result<WorkspaceAnnouncement, Box<dyn std::error::Error>> {
    let mut addrs = addrs
        .into_iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>();
    addrs.sort();
    addrs.dedup();
    let announcement = WorkspaceAnnouncement {
        version: WORKSPACE_ANNOUNCEMENT_VERSION,
        peer: peer.to_string(),
        addrs,
        author: identity.did().clone(),
        workspace: workspace.id().to_string(),
        name: workspace.name().to_string(),
        description: workspace.description().to_string(),
        owner: workspace.owner().clone(),
        root: workspace.root_cid().map(|cid| hex::encode(cid.as_bytes())),
        timestamp: now,
        signature: None,
    };
    sign_workspace_announcement(announcement, identity)
}

async fn publish_workspace_announcements(
    identity: &NodeIdentity,
    network: &Network,
    server: &mut WorkspaceServer,
    social_memory: &mut SocialMemory,
    memory_path: &Path,
    now: u64,
) {
    let peer = network.local_peer_id();
    let addrs = network.listen_addrs();
    let workspace_ids = server
        .workspaces()
        .map(|workspace| workspace.id())
        .collect::<Vec<_>>();
    for workspace_id in workspace_ids {
        let state = match server.refresh_workspace(&workspace_id).await {
            Ok(Some(state)) => state,
            Ok(None) => continue,
            Err(err) => {
                tracing::warn!(
                    "failed to refresh workspace {workspace_id} before announcement: {err}"
                );
                continue;
            }
        };
        record_served_workspace_snapshot(
            identity,
            network,
            social_memory,
            memory_path,
            &state,
            now,
        )
        .await;
        let Some(workspace) = server.get(&workspace_id) else {
            continue;
        };
        let announcement =
            match workspace_announcement(identity, peer, addrs.clone(), workspace, now) {
                Ok(announcement) => announcement,
                Err(err) => {
                    tracing::warn!("failed to sign workspace announcement: {err}");
                    continue;
                }
            };
        let data = match serde_json::to_vec(&announcement) {
            Ok(data) => data,
            Err(err) => {
                tracing::warn!("failed to serialize workspace announcement: {err}");
                continue;
            }
        };
        if let Err(err) = network.publish_announce(data).await {
            tracing::debug!(
                "workspace announcement for {} not broadcast yet: {err}",
                workspace.id()
            );
        }
    }
}

async fn record_served_workspace_snapshot(
    identity: &NodeIdentity,
    network: &Network,
    social_memory: &mut SocialMemory,
    memory_path: &Path,
    state: &WorkspaceState,
    now: u64,
) {
    if social_memory
        .society()
        .workspace_snapshots(&state.workspace_id)
        .iter()
        .any(|snapshot| snapshot.actor == *identity.did() && snapshot.root == state.root)
    {
        return;
    }

    let event = match SocialEvent::new(
        identity.did().clone(),
        now,
        SocialEventKind::WorkspaceSnapshotted {
            snapshot: WorkspaceSnapshot {
                workspace: state.workspace_id,
                actor: identity.did().clone(),
                root: state.root,
                label: Some("served".into()),
                note: Some("observed by nexus-node serve".into()),
                timestamp: now,
            },
        },
    )
    .sign(identity)
    {
        Ok(event) => event,
        Err(err) => {
            tracing::warn!("failed to sign served workspace snapshot: {err}");
            return;
        }
    };

    match social_memory.ingest_event(event.clone()) {
        Ok(true) => {
            if let Err(err) = save_social_memory(memory_path, social_memory) {
                tracing::warn!(
                    "failed to save served workspace snapshot {}: {err}",
                    event.id
                );
            }
            publish_social_event_with_retry(network, &event).await;
        }
        Ok(false) => {}
        Err(err) => {
            tracing::warn!(
                "failed to record served workspace snapshot for {}: {err}",
                state.workspace_id
            );
        }
    }
}

async fn replay_social_memory(network: &Network, social_memory: &SocialMemory) {
    for event in social_memory.events() {
        publish_social_event_with_retry(network, event).await;
    }
}

fn social_events_response(
    social_memory: &SocialMemory,
    known_event_ids: &[String],
    limit: usize,
) -> SyncResponse {
    social_events_response_with_caps(
        social_memory,
        known_event_ids,
        limit,
        MAX_SOCIAL_EVENTS_PER_RESPONSE,
        MAX_SYNC_MESSAGE_BYTES,
    )
}

fn social_events_response_with_caps(
    social_memory: &SocialMemory,
    known_event_ids: &[String],
    limit: usize,
    max_events: usize,
    max_frame_bytes: usize,
) -> SyncResponse {
    let known: std::collections::HashSet<&str> =
        known_event_ids.iter().map(String::as_str).collect();
    let effective_limit = limit.min(max_events);
    let mut events_json = Vec::new();

    for event in social_memory.events() {
        if events_json.len() >= effective_limit {
            break;
        }
        if known.contains(event.id.as_str()) {
            continue;
        }
        match event.to_json() {
            Ok(json) => events_json.push(json),
            Err(err) => {
                return SyncResponse::Error {
                    message: format!("serialize social event {}: {err}", event.id),
                };
            }
        }
        match social_events_response_frame_len(&events_json) {
            Ok(frame_len) if frame_len <= max_frame_bytes => {}
            Ok(_) => {
                let oversized_event_id = event.id.clone();
                events_json.pop();
                if events_json.is_empty() {
                    return SyncResponse::Error {
                        message: format!(
                            "social event {oversized_event_id} exceeds sync frame limit"
                        ),
                    };
                }
                break;
            }
            Err(err) => {
                return SyncResponse::Error {
                    message: format!("serialize social events response: {err}"),
                };
            }
        }
    }

    SyncResponse::SocialEventsResponse { events_json }
}

fn social_events_response_frame_len(events_json: &[Vec<u8>]) -> Result<usize, serde_json::Error> {
    serde_json::to_vec(&SyncResponse::SocialEventsResponse {
        events_json: events_json.to_vec(),
    })
    .map(|bytes| bytes.len())
}

async fn workspace_announcements_response(
    identity: &NodeIdentity,
    network: &Network,
    server: &mut WorkspaceServer,
    workspace_filter: Option<WorkspaceId>,
    limit: usize,
    now: u64,
) -> SyncResponse {
    let effective_limit = limit.min(MAX_WORKSPACE_ANNOUNCEMENTS_PER_RESPONSE);
    let peer = network.local_peer_id();
    let addrs = network.listen_addrs();
    let workspace_ids = server
        .workspaces()
        .map(|workspace| workspace.id())
        .filter(|workspace_id| {
            workspace_filter
                .map(|filter| filter == *workspace_id)
                .unwrap_or(true)
        })
        .take(effective_limit)
        .collect::<Vec<_>>();

    let mut announcements_json = Vec::new();
    for workspace_id in workspace_ids {
        match server.refresh_workspace(&workspace_id).await {
            Ok(Some(_)) => {}
            Ok(None) => continue,
            Err(err) => {
                return SyncResponse::Error {
                    message: format!("refresh workspace {workspace_id}: {err}"),
                }
            }
        }
        let Some(workspace) = server.get(&workspace_id) else {
            continue;
        };
        let announcement =
            match workspace_announcement(identity, peer, addrs.clone(), workspace, now) {
                Ok(announcement) => announcement,
                Err(err) => {
                    return SyncResponse::Error {
                        message: format!("sign workspace announcement {workspace_id}: {err}"),
                    }
                }
            };
        match serde_json::to_vec(&announcement) {
            Ok(data) => announcements_json.push(data),
            Err(err) => {
                return SyncResponse::Error {
                    message: format!("serialize workspace announcement {workspace_id}: {err}"),
                }
            }
        }
    }

    SyncResponse::WorkspaceAnnouncementsResponse { announcements_json }
}

async fn request_social_events_from_peer(
    network: &Network,
    peer: libp2p::PeerId,
    social_memory: &mut SocialMemory,
    memory_path: &Path,
) -> usize {
    let client = SyncClient::new(network.sync_request_channel());
    let known_event_ids = social_memory
        .events()
        .iter()
        .map(|event| event.id.clone())
        .collect();
    let mut inserted = 0;

    match client.get_social_events(peer, known_event_ids, 512).await {
        Ok(events_json) => {
            for data in events_json {
                match ingest_social_event_bytes(&data, social_memory, memory_path) {
                    Ok(SocialIngestOutcome::Inserted) => {
                        inserted += 1;
                        tracing::info!(
                            "synced social event from {}; events={}, agents={}",
                            peer,
                            social_memory.event_count(),
                            social_memory.agent_count()
                        );
                    }
                    Ok(SocialIngestOutcome::Duplicate) => {}
                    Err(err) => {
                        tracing::warn!("rejected synced social event from {}: {err}", peer);
                    }
                }
            }
        }
        Err(err) => {
            tracing::debug!("social event sync request to {} failed: {err}", peer);
        }
    }
    inserted
}

fn record_workspace_announcement_bytes(
    base: &Path,
    source: Option<libp2p::PeerId>,
    data: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let announcement = serde_json::from_slice::<WorkspaceAnnouncement>(data)?;
    if announcement.version != WORKSPACE_ANNOUNCEMENT_VERSION {
        return Err(format!(
            "unsupported workspace announcement version {}",
            announcement.version
        )
        .into());
    }
    if let Some(source) = source {
        if announcement.peer != source.to_string() {
            return Err(format!(
                "announcement peer {} does not match source {}",
                announcement.peer, source
            )
            .into());
        }
    }
    verify_workspace_announcement(&announcement)?;
    if let Err(err) = cache_peer_from_announcement(base, &announcement, unix_now()) {
        tracing::warn!(
            "failed to cache bootstrap hint from workspace announcement {}: {err}",
            announcement.peer
        );
    }
    record_workspace_announcement(base, announcement)
}

async fn request_workspace_announcements_from_peer(
    network: &Network,
    peer: libp2p::PeerId,
    workspace_filter: Option<WorkspaceId>,
    base: &Path,
) -> usize {
    let client = SyncClient::with_timeout(network.sync_request_channel(), Duration::from_secs(5));
    let mut inserted = 0;

    match client
        .get_workspace_announcements(
            peer,
            workspace_filter,
            MAX_WORKSPACE_ANNOUNCEMENTS_PER_RESPONSE,
        )
        .await
    {
        Ok(announcements_json) => {
            for data in announcements_json {
                match record_workspace_announcement_bytes(base, Some(peer), &data) {
                    Ok(true) => inserted += 1,
                    Ok(false) => {}
                    Err(err) => {
                        tracing::warn!("rejected workspace announcement from {}: {err}", peer);
                    }
                }
            }
        }
        Err(err) => {
            tracing::debug!("workspace announcement request to {} failed: {err}", peer);
            if let Err(cache_err) = mark_peer_cache_failure(base, peer, unix_now()) {
                tracing::warn!("failed to update peer cache failure for {peer}: {cache_err}");
            }
        }
    }

    inserted
}

async fn handle_node_event(
    event: NetworkEvent,
    network: &Network,
    server: &mut WorkspaceServer,
    social_memory: &mut SocialMemory,
    memory_path: &Path,
    base: &Path,
    identity: &NodeIdentity,
) {
    match &event {
        NetworkEvent::WorkspaceAnnounce {
            source: Some(source),
            data,
        } => match record_workspace_announcement_bytes(base, Some(*source), data) {
            Ok(true) => tracing::info!("recorded workspace announcement from {}", source),
            Ok(false) => {}
            Err(err) => tracing::warn!("rejected workspace announcement from {:?}: {err}", source),
        },
        NetworkEvent::SocialEvent { source, data } => {
            match ingest_social_event_bytes(data, social_memory, memory_path) {
                Ok(SocialIngestOutcome::Inserted) => {
                    tracing::info!(
                        "accepted social event from {:?}; events={}, agents={}",
                        source,
                        social_memory.event_count(),
                        social_memory.agent_count()
                    );
                }
                Ok(SocialIngestOutcome::Duplicate) => {
                    tracing::debug!("ignored duplicate social event from {:?}", source);
                }
                Err(err) => {
                    tracing::warn!("rejected social event from {:?}: {err}", source);
                }
            }
        }
        NetworkEvent::PeerConnected(peer) => {
            tracing::debug!(
                "replaying {} social events to newly connected peer {}",
                social_memory.event_count(),
                peer
            );
            replay_social_memory(network, social_memory).await;
            publish_workspace_announcements(
                identity,
                network,
                server,
                social_memory,
                memory_path,
                unix_now(),
            )
            .await;
            let _ =
                request_social_events_from_peer(network, *peer, social_memory, memory_path).await;
        }
        NetworkEvent::SyncRequest {
            request_id,
            request:
                SyncRequest::SocialEventsRequest {
                    known_event_ids,
                    limit,
                },
            ..
        } => {
            let response = social_events_response(social_memory, known_event_ids, *limit);
            network.respond_to_sync(*request_id, response);
            return;
        }
        NetworkEvent::SyncRequest {
            request_id,
            request:
                SyncRequest::WorkspaceAnnouncementsRequest {
                    workspace_id,
                    limit,
                },
            ..
        } => {
            let response = workspace_announcements_response(
                identity,
                network,
                server,
                *workspace_id,
                *limit,
                unix_now(),
            )
            .await;
            network.respond_to_sync(*request_id, response);
            return;
        }
        NetworkEvent::SyncRequest {
            request: SyncRequest::StateRequest { workspace_id },
            ..
        } => match server.refresh_workspace(workspace_id).await {
            Ok(Some(state)) => {
                record_served_workspace_snapshot(
                    identity,
                    network,
                    social_memory,
                    memory_path,
                    &state,
                    unix_now(),
                )
                .await;
            }
            Ok(None) => {}
            Err(err) => tracing::warn!("failed to refresh workspace {workspace_id}: {err}"),
        },
        _ => {}
    }

    server.handle_event(event).await;
}

// ---------------------------------------------------------------------------
// demo — two-node self-contained demo
// ---------------------------------------------------------------------------

async fn cmd_demo() -> Result<(), Box<dyn std::error::Error>> {
    use nexus_network::NetworkEvent;
    use nexus_runtime::ExecOptions;

    println!("=== Nexus Two-Node Demo ===\n");

    // Node A: creates workspace, writes files, executes, publishes
    let id_a = NodeIdentity::generate();
    let mut net_a = Network::new(&id_a, NetworkConfig::default()).await?;

    // Wait for listen
    let mut addr_a = None;
    while let Some(ev) = net_a.next_event().await {
        if let NetworkEvent::Listening(a) = ev {
            addr_a = Some(a);
            break;
        }
    }
    let addr_a = addr_a.unwrap();
    println!("[A] listening on {addr_a}");

    // A creates a workspace (use a persistent tempdir)
    let base_a = tempfile::TempDir::new()?;
    let base_path = base_a.path().to_path_buf();
    let mut ws_a = Workspace::create(
        &id_a,
        &base_path,
        WorkspaceConfig {
            name: "demo-ws".into(),
            description: "Demo workspace".into(),
        },
    )
    .await?;
    println!("[A] workspace created: {}", ws_a.id());

    // A writes files
    ws_a.write_file("hello.txt", b"Hello from Node A!")?;
    ws_a.write_file("compute.sh", b"#!/bin/sh\necho 'result: 42' > output.txt")?;
    let _root = ws_a.snapshot().await?;
    println!("[A] files written + snapshot");

    // A executes the script
    let out = ws_a
        .exec("sh", &["compute.sh"], &ExecOptions::default())
        .await?;
    println!("[A] exec: exit={}", out.exit_code);
    let output = ws_a.read_file("output.txt")?;
    println!(
        "[A] output.txt: {}",
        String::from_utf8_lossy(&output).trim()
    );

    // A starts serving
    // Node B: bootstraps from A
    let id_b = NodeIdentity::generate();
    let mut net_b = Network::new(
        &id_b,
        NetworkConfig {
            bootstrap_peers: vec![addr_a],
            ..Default::default()
        },
    )
    .await?;

    println!("\n[B] connecting to A...");
    let mut b_connected = false;
    while let Some(ev) = net_b.next_event().await {
        if matches!(ev, NetworkEvent::PeerConnected(_)) {
            b_connected = true;
            break;
        }
    }
    assert!(b_connected);

    // B requests workspace state from A
    // (Requires A to have the server running — which we haven't set up in this demo yet)
    // For demo purposes, just show that both nodes are connected.

    println!("\n=== Demo Complete ===");
    println!("Node A and B are connected via QUIC.");
    println!("Node A has workspace '{}' with files:", ws_a.name());
    for f in ws_a.list_files()? {
        println!("  {} ({} bytes)", f.path.display(), f.size);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::multiaddr::Protocol;
    use nexus_agent::{RelationKind, SocialEvent, SocialEventKind};
    use nexus_core::WorkspaceId;
    use tempfile::TempDir;
    use tokio::sync::Mutex;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_string()).collect()
    }

    fn signed_workspace_event(identity: &NodeIdentity, byte: u8, timestamp: u64) -> SocialEvent {
        SocialEvent::new(
            identity.did().clone(),
            timestamp,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([byte; 32]),
            },
        )
        .sign(identity)
        .unwrap()
    }

    fn test_bootstrap_addr(port: u16) -> (String, libp2p::Multiaddr) {
        let peer = nexus_network::to_peer_id(&NodeIdentity::generate());
        let addr = format!("/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{peer}");
        let parsed = addr.parse().unwrap();
        (addr, parsed)
    }

    #[tokio::test]
    async fn node_identity_persists_across_create_and_serve_paths() {
        let temp = TempDir::new().unwrap();
        let first = load_or_create_identity(temp.path()).unwrap();
        let did = first.did().clone();
        assert!(identity_path(temp.path()).exists());

        let ws = Workspace::create(
            &first,
            temp.path(),
            WorkspaceConfig {
                name: "persistent-owner".into(),
                description: "created by stable node identity".into(),
            },
        )
        .await
        .unwrap();

        let second = load_or_create_identity(temp.path()).unwrap();
        assert_eq!(second.did(), &did);
        let loaded = Workspace::load(&second, ws.root_dir()).await.unwrap();
        assert_eq!(loaded.owner(), &did);
    }

    #[tokio::test]
    async fn create_command_registers_workspace_path() {
        let temp = TempDir::new().unwrap();
        cmd_create(&[
            "nexus-node".into(),
            "create".into(),
            "--base".into(),
            temp.path().to_string_lossy().to_string(),
            "--name".into(),
            "local-computer".into(),
        ])
        .await
        .unwrap();

        let expected = normalize_workspace_path(&temp.path().join("local-computer")).unwrap();
        let paths = local_workspace_paths(temp.path()).unwrap();
        assert_eq!(paths, vec![expected]);
    }

    #[tokio::test]
    async fn cli_commands_reject_missing_option_values_without_panic() {
        let create_err = cmd_create(&args(&["nexus-node", "create", "--name"]))
            .await
            .expect_err("missing create value should be an error");
        assert!(create_err.to_string().contains("--name requires a value"));

        let serve_err = cmd_serve(&args(&["nexus-node", "serve", "--listen"]))
            .await
            .expect_err("missing serve value should be an error");
        assert!(serve_err.to_string().contains("--listen requires a value"));

        let society_err = cmd_society(&args(&["nexus-node", "society", "--base"]))
            .expect_err("missing society value should be an error");
        assert!(society_err.to_string().contains("--base requires a value"));
    }

    #[test]
    fn workspace_discovery_registry_upserts_announcements() {
        let temp = TempDir::new().unwrap();
        let identity = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([91; 32]);
        let first = WorkspaceAnnouncement {
            version: WORKSPACE_ANNOUNCEMENT_VERSION,
            peer: "12D3KooWTestPeer".into(),
            addrs: Vec::new(),
            author: identity.did().clone(),
            workspace: workspace.to_string(),
            name: "shared-lab".into(),
            description: "shared workspace".into(),
            owner: identity.did().clone(),
            root: None,
            timestamp: 10,
            signature: None,
        };
        assert!(record_workspace_announcement(temp.path(), first.clone()).unwrap());
        assert!(!record_workspace_announcement(temp.path(), first).unwrap());

        let latest = WorkspaceAnnouncement {
            root: Some(hex::encode(Cid::hash_of(b"latest root").as_bytes())),
            timestamp: 11,
            ..load_workspace_discovery(temp.path()).unwrap()[0].clone()
        };
        assert!(record_workspace_announcement(temp.path(), latest.clone()).unwrap());

        let announcements = load_workspace_discovery(temp.path()).unwrap();
        assert_eq!(announcements, vec![latest]);
    }

    #[test]
    fn bootstrap_config_and_discovery_cache_provide_peer_hints() {
        let temp = TempDir::new().unwrap();
        let (config_addr, config_peer) = test_bootstrap_addr(4011);
        let (cache_addr, cache_peer) = test_bootstrap_addr(4012);
        let (_peer_cache_addr, peer_cache_peer) = test_bootstrap_addr(4013);

        std::fs::write(
            bootstrap_config_path(temp.path()),
            serde_json::to_vec_pretty(&serde_json::json!({ "peers": [config_addr] })).unwrap(),
        )
        .unwrap();
        assert_eq!(
            load_bootstrap_config_peers(temp.path()).unwrap(),
            vec![config_peer.clone()]
        );

        let identity = NodeIdentity::generate();
        let announcement = WorkspaceAnnouncement {
            version: WORKSPACE_ANNOUNCEMENT_VERSION,
            peer: multiaddr_peer_id(&cache_peer).unwrap().to_string(),
            addrs: vec![cache_addr],
            author: identity.did().clone(),
            workspace: WorkspaceId::from_bytes([90; 32]).to_string(),
            name: "cached-bootstrap-source".into(),
            description: "cached workspace bootstrap hint".into(),
            owner: identity.did().clone(),
            root: None,
            timestamp: 1,
            signature: None,
        };
        let announcement = sign_workspace_announcement(announcement, &identity).unwrap();
        record_workspace_announcement(temp.path(), announcement).unwrap();
        assert_eq!(
            cached_workspace_bootstrap_peers(temp.path()),
            vec![cache_peer]
        );

        upsert_peer_cache(
            temp.path(),
            &multiaddr_peer_id(&peer_cache_peer).unwrap().to_string(),
            &["/ip4/127.0.0.1/udp/4013/quic-v1".into()],
            2,
            Some(3),
            None,
        )
        .unwrap();
        assert_eq!(
            peer_cache_bootstrap_peers(temp.path()),
            vec![peer_cache_peer.clone()]
        );

        let entries = load_peer_cache(temp.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].addrs, vec![peer_cache_peer.to_string()]);
        assert_eq!(entries[0].last_connected, Some(3));
        assert_eq!(entries[0].failures, 0);

        if std::env::var("NEXUS_BOOTSTRAP").is_err() {
            let status = bootstrap_status(temp.path(), false).unwrap();
            assert!(status.effective_peers.contains(&config_peer.to_string()));
            assert!(status
                .effective_peers
                .contains(&peer_cache_peer.to_string()));
        }
    }

    #[test]
    fn peer_cache_load_normalizes_addresses_and_ignores_invalid_rows() {
        let temp = TempDir::new().unwrap();
        let peer = nexus_network::to_peer_id(&NodeIdentity::generate());
        let other_peer = nexus_network::to_peer_id(&NodeIdentity::generate());
        let raw_addr = "/ip4/127.0.0.1/udp/4021/quic-v1";
        let normalized_addr = format!("{raw_addr}/p2p/{peer}");

        std::fs::write(
            peer_cache_path(temp.path()),
            serde_json::to_vec_pretty(&serde_json::json!({
                "peers": [
                    {
                        "peer": "not-a-peer",
                        "addrs": [raw_addr],
                        "last_seen": 1
                    },
                    {
                        "peer": peer.to_string(),
                        "addrs": [raw_addr],
                        "last_seen": 2,
                        "failures": 1
                    },
                    {
                        "peer": other_peer.to_string(),
                        "addrs": [normalized_addr],
                        "last_seen": 3
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let entries = load_peer_cache(temp.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].peer, peer.to_string());
        assert_eq!(entries[0].addrs, vec![normalized_addr.clone()]);
        assert_eq!(
            peer_cache_bootstrap_peers(temp.path()),
            vec![normalized_addr.parse::<libp2p::Multiaddr>().unwrap()]
        );
    }

    #[test]
    fn discovered_workspace_views_group_and_filter_announcements() {
        let owner = NodeIdentity::generate();
        let other = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([92; 32]).to_string();
        let other_workspace = WorkspaceId::from_bytes([93; 32]).to_string();
        let announcements = vec![
            WorkspaceAnnouncement {
                version: WORKSPACE_ANNOUNCEMENT_VERSION,
                peer: "peer-a".into(),
                addrs: vec!["/ip4/127.0.0.1/udp/1111/quic-v1".into()],
                author: owner.did().clone(),
                workspace: workspace.clone(),
                name: "shared-lab".into(),
                description: "shared research workspace".into(),
                owner: owner.did().clone(),
                root: None,
                timestamp: 10,
                signature: None,
            },
            WorkspaceAnnouncement {
                version: WORKSPACE_ANNOUNCEMENT_VERSION,
                peer: "peer-b".into(),
                addrs: vec!["/ip4/127.0.0.1/udp/2222/quic-v1".into()],
                author: owner.did().clone(),
                workspace: workspace.clone(),
                name: "shared-lab-new".into(),
                description: "new shared research workspace".into(),
                owner: owner.did().clone(),
                root: Some(hex::encode(Cid::hash_of(b"new root").as_bytes())),
                timestamp: 12,
                signature: None,
            },
            WorkspaceAnnouncement {
                version: WORKSPACE_ANNOUNCEMENT_VERSION,
                peer: "peer-c".into(),
                addrs: Vec::new(),
                author: other.did().clone(),
                workspace: other_workspace,
                name: "other-lab".into(),
                description: "other workspace".into(),
                owner: other.did().clone(),
                root: None,
                timestamp: 11,
                signature: None,
            },
        ];

        let views = discovered_workspace_views(
            &announcements,
            &DiscoveryFilter {
                owner: Some(owner.did().clone()),
                name: Some("SHARED".into()),
                ..Default::default()
            },
        );

        assert_eq!(views.len(), 1);
        assert_eq!(views[0].workspace, workspace);
        assert_eq!(views[0].name, "shared-lab-new");
        assert_eq!(views[0].latest_timestamp, 12);
        assert!(!views[0].verified);
        assert!(!views[0].clone_ready);
        assert_eq!(views[0].peers, vec!["peer-a", "peer-b"]);
        assert_eq!(
            views[0].addrs,
            vec![
                "/ip4/127.0.0.1/udp/1111/quic-v1",
                "/ip4/127.0.0.1/udp/2222/quic-v1"
            ]
        );
        assert_eq!(views[0].announcements.len(), 2);
        assert_eq!(views[0].announcements[0].peer, "peer-b");
    }

    #[tokio::test]
    async fn discover_command_outputs_grouped_workspace_json() {
        let temp = TempDir::new().unwrap();
        let identity = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([94; 32]);
        let announcement = WorkspaceAnnouncement {
            version: WORKSPACE_ANNOUNCEMENT_VERSION,
            peer: "12D3KooWDiscoverPeer".into(),
            addrs: vec!["/ip4/127.0.0.1/udp/3333/quic-v1".into()],
            author: identity.did().clone(),
            workspace: workspace.to_string(),
            name: "discoverable-lab".into(),
            description: "discoverable workspace".into(),
            owner: identity.did().clone(),
            root: Some(hex::encode(Cid::hash_of(b"discover root").as_bytes())),
            timestamp: 20,
            signature: None,
        };
        assert!(record_workspace_announcement(temp.path(), announcement).unwrap());

        cmd_discover(&[
            "nexus-node".into(),
            "discover".into(),
            "--base".into(),
            temp.path().to_string_lossy().to_string(),
            "--json".into(),
            "--workspace".into(),
            workspace.to_string(),
        ])
        .await
        .unwrap();

        let views = discovered_workspace_views(
            &load_workspace_discovery(temp.path()).unwrap(),
            &DiscoveryFilter {
                workspace: Some(workspace.to_string()),
                ..Default::default()
            },
        );
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].workspace, workspace.to_string());
        assert_eq!(views[0].name, "discoverable-lab");
        assert!(!views[0].verified);
        assert!(!views[0].clone_ready);
        assert_eq!(views[0].peers, vec!["12D3KooWDiscoverPeer"]);
        assert_eq!(views[0].addrs, vec!["/ip4/127.0.0.1/udp/3333/quic-v1"]);

        let verified = discovered_workspace_views(
            &load_workspace_discovery(temp.path()).unwrap(),
            &DiscoveryFilter {
                verified_only: true,
                ..Default::default()
            },
        );
        assert!(verified.is_empty());
    }

    #[tokio::test]
    async fn discover_lan_scan_does_not_require_bootstrap() {
        let temp = TempDir::new().unwrap();
        cmd_discover(&[
            "nexus-node".into(),
            "discover".into(),
            "--base".into(),
            temp.path().to_string_lossy().to_string(),
            "--lan".into(),
            "--no-public-bootstrap".into(),
            "--listen".into(),
            "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            "--timeout-ms".into(),
            "20".into(),
            "--json".into(),
        ])
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn workspace_announcement_signature_covers_claims() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let mut workspace = Workspace::create(
            &identity,
            temp.path(),
            WorkspaceConfig {
                name: "signed-lab".into(),
                description: "signed discovery claim".into(),
            },
        )
        .await
        .unwrap();
        workspace.write_file("claim.txt", b"verified").unwrap();
        workspace.snapshot().await.unwrap();

        let announcement = workspace_announcement(
            &identity,
            nexus_network::to_peer_id(&identity),
            vec!["/ip4/127.0.0.1/udp/4444/quic-v1".parse().unwrap()],
            &workspace,
            30,
        )
        .unwrap();
        assert!(announcement.signature.is_some());
        verify_workspace_announcement(&announcement).unwrap();
        let normalized_addrs = normalized_announcement_bootstrap_addrs(&announcement).unwrap();
        assert_eq!(normalized_addrs.len(), 1);
        assert!(normalized_addrs[0].to_string().contains("/p2p/"));

        let mut tampered = announcement.clone();
        tampered.root = Some(hex::encode(Cid::hash_of(b"forged root").as_bytes()));
        assert!(verify_workspace_announcement(&tampered).is_err());

        let mut wrong_peer = announcement.clone();
        wrong_peer.peer = "not-a-peer".into();
        assert!(verify_workspace_announcement(&wrong_peer).is_err());

        let other_peer = nexus_network::to_peer_id(&NodeIdentity::generate());
        let mut wrong_addr_peer = announcement.clone();
        wrong_addr_peer.addrs = vec![format!("/ip4/127.0.0.1/udp/5555/quic-v1/p2p/{other_peer}")];
        wrong_addr_peer.signature = None;
        let wrong_addr_peer = sign_workspace_announcement(wrong_addr_peer, &identity).unwrap();
        assert!(verify_workspace_announcement(&wrong_addr_peer).is_err());

        let mut unsigned = announcement;
        unsigned.signature = None;
        assert!(verify_workspace_announcement(&unsigned).is_err());
    }

    #[tokio::test]
    async fn discovered_workspace_views_mark_verified_clone_ready_sources() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let mut workspace = Workspace::create(
            &identity,
            temp.path(),
            WorkspaceConfig {
                name: "verified-lab".into(),
                description: "verified discovery view".into(),
            },
        )
        .await
        .unwrap();
        workspace.snapshot().await.unwrap();
        let peer = nexus_network::to_peer_id(&identity);
        let announcement = workspace_announcement(
            &identity,
            peer,
            vec!["/ip4/127.0.0.1/udp/5555/quic-v1".parse().unwrap()],
            &workspace,
            35,
        )
        .unwrap();
        let newer_unverified = WorkspaceAnnouncement {
            version: WORKSPACE_ANNOUNCEMENT_VERSION,
            peer: "12D3KooWUnverifiedPeer".into(),
            addrs: Vec::new(),
            author: identity.did().clone(),
            workspace: WorkspaceId::from_bytes([95; 32]).to_string(),
            name: "zzz-newer-unverified".into(),
            description: "newer but not clone ready".into(),
            owner: identity.did().clone(),
            root: None,
            timestamp: 99,
            signature: None,
        };
        let announcements = vec![announcement, newer_unverified];

        let views = discovered_workspace_views(
            &announcements,
            &DiscoveryFilter {
                clone_ready_only: true,
                ..Default::default()
            },
        );
        assert_eq!(views.len(), 1);
        assert!(views[0].verified);
        assert!(views[0].clone_ready);
        assert_eq!(views[0].name, "verified-lab");
        assert_eq!(
            views[0].addrs,
            vec![format!("/ip4/127.0.0.1/udp/5555/quic-v1/p2p/{peer}")]
        );

        let relevance_sorted =
            discovered_workspace_views(&announcements, &DiscoveryFilter::default());
        assert_eq!(relevance_sorted[0].name, "verified-lab");

        let latest_sorted = discovered_workspace_views(
            &announcements,
            &DiscoveryFilter {
                sort: DiscoverySort::Latest,
                ..Default::default()
            },
        );
        assert_eq!(latest_sorted[0].name, "zzz-newer-unverified");
    }

    #[tokio::test]
    async fn discover_clone_source_selects_signed_addressed_announcement() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let mut workspace = Workspace::create(
            &identity,
            temp.path(),
            WorkspaceConfig {
                name: "addressed-lab".into(),
                description: "clone source discovery".into(),
            },
        )
        .await
        .unwrap();
        workspace.snapshot().await.unwrap();
        let workspace_id = workspace.id();
        let peer = nexus_network::to_peer_id(&identity);
        let addr: libp2p::Multiaddr = "/ip4/127.0.0.1/udp/4555/quic-v1".parse().unwrap();
        let announcement =
            workspace_announcement(&identity, peer, vec![addr.clone()], &workspace, 40).unwrap();
        assert!(record_workspace_announcement(temp.path(), announcement).unwrap());

        let source = discover_clone_source(temp.path(), &workspace_id, None)
            .unwrap()
            .expect("signed addressed announcement should be selectable");
        assert_eq!(source.peer, peer);
        assert_eq!(
            source.addrs,
            vec![addr.with(libp2p::multiaddr::Protocol::P2p(peer))]
        );
        assert_eq!(source.owner, *identity.did());
        assert_eq!(source.root, workspace.root_cid());
    }

    async fn wait_for_test_listen(network: &mut Network) -> libp2p::Multiaddr {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(NetworkEvent::Listening(addr)) = network.next_event().await {
                    return addr;
                }
            }
        })
        .await
        .expect("test network should listen")
    }

    fn test_addr_with_peer(addr: libp2p::Multiaddr, peer: libp2p::PeerId) -> libp2p::Multiaddr {
        addr.with(Protocol::P2p(peer))
    }

    async fn publish_test_announce(network: &Network, data: Vec<u8>) {
        let mut last_error = None;
        for _ in 0..40 {
            match network.publish_announce(data.clone()).await {
                Ok(()) => return,
                Err(err) => {
                    last_error = Some(err);
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }
        panic!("workspace announcement publish failed after retries: {last_error:?}");
    }

    fn spawn_test_workspace_social_server(
        identity: Arc<NodeIdentity>,
        network: &Network,
        server: WorkspaceServer,
        social_memory: SocialMemory,
    ) -> tokio::task::JoinHandle<()> {
        let social_memory = Arc::new(Mutex::new(social_memory));
        spawn_test_workspace_social_server_with_memory(identity, network, server, social_memory)
    }

    fn spawn_test_workspace_social_server_with_memory(
        identity: Arc<NodeIdentity>,
        network: &Network,
        server: WorkspaceServer,
        social_memory: Arc<Mutex<SocialMemory>>,
    ) -> tokio::task::JoinHandle<()> {
        let mut server_events = network.clone();
        let network = network.clone();
        tokio::spawn(async move {
            let mut server = server;
            while let Some(event) = server_events.next_event().await {
                if let NetworkEvent::SyncRequest {
                    request_id,
                    request:
                        SyncRequest::SocialEventsRequest {
                            known_event_ids,
                            limit,
                        },
                    ..
                } = &event
                {
                    let response = {
                        let social_memory = social_memory.lock().await;
                        social_events_response(&social_memory, known_event_ids, *limit)
                    };
                    server_events.respond_to_sync(*request_id, response);
                    continue;
                }
                if let NetworkEvent::SyncRequest {
                    request_id,
                    request:
                        SyncRequest::WorkspaceAnnouncementsRequest {
                            workspace_id,
                            limit,
                        },
                    ..
                } = &event
                {
                    let response = workspace_announcements_response(
                        &identity,
                        &network,
                        &mut server,
                        *workspace_id,
                        *limit,
                        unix_now(),
                    )
                    .await;
                    server_events.respond_to_sync(*request_id, response);
                    continue;
                }
                let memory_path = std::env::temp_dir().join(format!(
                    "nexus-test-social-memory-{}.json",
                    network.local_peer_id()
                ));
                if matches!(
                    event,
                    NetworkEvent::PeerConnected(_)
                        | NetworkEvent::SyncRequest {
                            request: SyncRequest::StateRequest { .. },
                            ..
                        }
                ) {
                    let mut social_memory = social_memory.lock().await;
                    publish_workspace_announcements(
                        &identity,
                        &network,
                        &mut server,
                        &mut social_memory,
                        &memory_path,
                        unix_now(),
                    )
                    .await;
                }
                server.handle_event(event).await;
            }
        })
    }

    #[tokio::test]
    async fn workspace_announcement_is_recorded_as_discovery_hint() {
        let owner_base = TempDir::new().unwrap();
        let owner = load_or_create_identity(owner_base.path()).unwrap();
        let mut workspace = Workspace::create(
            &owner,
            owner_base.path(),
            WorkspaceConfig {
                name: "announced-computer".into(),
                description: "discoverable AI computer".into(),
            },
        )
        .await
        .unwrap();
        workspace.write_file("note.txt", b"discover me").unwrap();
        let root = workspace.snapshot().await.unwrap();
        let workspace_id = workspace.id();

        let mut net_a = Network::new(
            &owner,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let addr_a = wait_for_test_listen(&mut net_a).await;
        let mut server_a = WorkspaceServer::new(Arc::new(net_a.clone()));
        server_a.register(workspace);

        let clone_base = TempDir::new().unwrap();
        let clone_identity = load_or_create_identity(clone_base.path()).unwrap();
        let mut net_b = Network::new(
            &clone_identity,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                bootstrap_peers: vec![addr_a.clone()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        wait_for_peer(&net_b, net_a.local_peer_id(), Duration::from_secs(10))
            .await
            .unwrap();

        let announcement = workspace_announcement(
            &owner,
            net_a.local_peer_id(),
            vec![addr_a.clone()],
            server_a.workspaces().next().unwrap(),
            123,
        )
        .unwrap();
        let data = serde_json::to_vec(&announcement).unwrap();
        publish_test_announce(&net_a, data).await;

        let mut memory = SocialMemory::new();
        let memory_path = clone_base.path().join(".nexus-social-memory.json");
        let mut server_b = WorkspaceServer::new(Arc::new(net_b.clone()));

        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(event @ NetworkEvent::WorkspaceAnnounce { .. }) =
                    net_b.next_event().await
                {
                    handle_node_event(
                        event,
                        &net_b,
                        &mut server_b,
                        &mut memory,
                        &memory_path,
                        clone_base.path(),
                        &clone_identity,
                    )
                    .await;
                    if !load_workspace_discovery(clone_base.path())
                        .unwrap()
                        .is_empty()
                    {
                        break;
                    }
                }
            }
        })
        .await
        .expect("workspace announcement should be recorded");

        let announcements = load_workspace_discovery(clone_base.path()).unwrap();
        assert_eq!(announcements.len(), 1);
        assert_eq!(announcements[0].peer, net_a.local_peer_id().to_string());
        assert_eq!(announcements[0].workspace, workspace_id.to_string());
        assert_eq!(announcements[0].owner, *owner.did());
        assert_eq!(announcements[0].root, Some(hex::encode(root.as_bytes())));

        let view = society_json_for_base(clone_base.path(), &memory, SocietyJsonOptions::default());
        assert_eq!(
            view["discovered_workspaces"][0]["workspace"],
            workspace_id.to_string()
        );
        assert_eq!(
            view["discovered_workspaces"][0]["root"],
            hex::encode(root.as_bytes())
        );
        assert_eq!(
            view["discovered_workspaces"][0]["peers"][0],
            net_a.local_peer_id().to_string()
        );
        assert_eq!(
            view["discovered_workspaces"][0]["announcements"][0]["workspace"],
            workspace_id.to_string()
        );
    }

    #[tokio::test]
    async fn global_discovery_fetches_workspace_announcements_via_dht_provider() {
        let seed_id = NodeIdentity::generate();
        let mut seed = Network::new(
            &seed_id,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let seed_addr =
            test_addr_with_peer(wait_for_test_listen(&mut seed).await, seed.local_peer_id());

        let owner_base = TempDir::new().unwrap();
        let owner = Arc::new(load_or_create_identity(owner_base.path()).unwrap());
        let mut workspace = Workspace::create(
            &owner,
            owner_base.path(),
            WorkspaceConfig {
                name: "global-discovery-source".into(),
                description: "discoverable through DHT provider records".into(),
            },
        )
        .await
        .unwrap();
        workspace.write_file("hello.txt", b"hello global").unwrap();
        workspace.snapshot().await.unwrap();
        let workspace_id = workspace.id();

        let mut owner_net = Network::new(
            &owner,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                bootstrap_peers: vec![seed_addr.clone()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        wait_for_test_listen(&mut owner_net).await;
        wait_for_peer(&owner_net, seed.local_peer_id(), Duration::from_secs(10))
            .await
            .unwrap();
        announce_dht_presence(&owner_net, &[workspace_id]);

        let mut owner_server = WorkspaceServer::new(Arc::new(owner_net.clone()));
        owner_server.register(workspace);
        let owner_task = spawn_test_workspace_social_server(
            owner.clone(),
            &owner_net,
            owner_server,
            SocialMemory::new(),
        );

        let discover_base = TempDir::new().unwrap();
        let discover_id = load_or_create_identity(discover_base.path()).unwrap();
        let mut discover_net = Network::new(
            &discover_id,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                bootstrap_peers: vec![seed_addr],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        wait_for_test_listen(&mut discover_net).await;
        wait_for_peer(&discover_net, seed.local_peer_id(), Duration::from_secs(10))
            .await
            .unwrap();

        let inserted = refresh_online_discovery(
            discover_base.path(),
            &discover_net,
            Some(workspace_id),
            None,
            Duration::from_secs(12),
        )
        .await
        .unwrap();

        owner_task.abort();

        assert!(
            inserted > 0,
            "online discovery should record an announcement"
        );
        let views = discovered_workspace_views(
            &load_workspace_discovery(discover_base.path()).unwrap(),
            &DiscoveryFilter {
                workspace: Some(workspace_id.to_string()),
                clone_ready_only: true,
                ..Default::default()
            },
        );
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].name, "global-discovery-source");
        assert_eq!(views[0].peers, vec![owner_net.local_peer_id().to_string()]);
    }

    #[tokio::test]
    async fn clone_command_can_discover_workspace_peer_through_dht() {
        let seed_id = NodeIdentity::generate();
        let mut seed = Network::new(
            &seed_id,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let seed_addr =
            test_addr_with_peer(wait_for_test_listen(&mut seed).await, seed.local_peer_id());

        let owner_base = TempDir::new().unwrap();
        let owner = Arc::new(load_or_create_identity(owner_base.path()).unwrap());
        let mut source = Workspace::create(
            &owner,
            owner_base.path(),
            WorkspaceConfig {
                name: "dht-clone-source".into(),
                description: "clone source discovered through DHT".into(),
            },
        )
        .await
        .unwrap();
        source
            .write_file("global.txt", b"cloned without peer id")
            .unwrap();
        source.snapshot().await.unwrap();
        let workspace_id = source.id();

        let mut owner_net = Network::new(
            &owner,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                bootstrap_peers: vec![seed_addr.clone()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
        wait_for_test_listen(&mut owner_net).await;
        wait_for_peer(&owner_net, seed.local_peer_id(), Duration::from_secs(10))
            .await
            .unwrap();
        announce_dht_presence(&owner_net, &[workspace_id]);

        let mut owner_server = WorkspaceServer::new(Arc::new(owner_net.clone()));
        owner_server.register(source);
        let owner_task = spawn_test_workspace_social_server(
            owner.clone(),
            &owner_net,
            owner_server,
            SocialMemory::new(),
        );

        let clone_base = TempDir::new().unwrap();
        cmd_clone(&[
            "nexus-node".into(),
            "clone".into(),
            "--base".into(),
            clone_base.path().to_string_lossy().to_string(),
            "--listen".into(),
            "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            "--global".into(),
            "--bootstrap".into(),
            seed_addr.to_string(),
            "--timeout-ms".into(),
            "6000".into(),
            "--workspace".into(),
            workspace_id.to_string(),
            "--name".into(),
            "dht-cloned".into(),
        ])
        .await
        .unwrap();

        owner_task.abort();

        let clone_identity = load_or_create_identity(clone_base.path()).unwrap();
        let cloned = Workspace::load(&clone_identity, &clone_base.path().join("dht-cloned"))
            .await
            .unwrap();
        assert_eq!(cloned.id(), workspace_id);
        assert_eq!(
            cloned.read_file("global.txt").unwrap(),
            b"cloned without peer id"
        );
    }

    #[tokio::test]
    async fn clone_command_fetches_remote_workspace_and_records_social_facts() {
        let owner_base = TempDir::new().unwrap();
        let owner = load_or_create_identity(owner_base.path()).unwrap();
        let mut source = Workspace::create(
            &owner,
            owner_base.path(),
            WorkspaceConfig {
                name: "source-computer".into(),
                description: "remote AI computer".into(),
            },
        )
        .await
        .unwrap();
        source
            .write_file("hello.txt", b"hello from remote")
            .unwrap();
        source
            .write_file("nested/data.txt", b"portable memory")
            .unwrap();
        let root = source.snapshot().await.unwrap();
        let workspace_id = source.id();

        let mut owner_network = Network::new(
            &owner,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let owner_addr = wait_for_test_listen(&mut owner_network).await;
        let owner_peer = owner_network.local_peer_id();
        let server = WorkspaceServer::new(Arc::new(owner_network.clone()));
        let mut server = server;
        server.register(source);
        let mut remote_memory = SocialMemory::new();
        for event in signed_presence_events(
            &owner,
            build_node_manifest(&owner, owner_base.path(), 100),
            &[workspace_id],
            100,
        )
        .unwrap()
        {
            assert!(remote_memory.ingest_event(event).unwrap());
        }
        let serve_task = spawn_test_workspace_social_server(
            Arc::new(load_or_create_identity(owner_base.path()).unwrap()),
            &owner_network,
            server,
            remote_memory.clone(),
        );

        let clone_base = TempDir::new().unwrap();
        cmd_clone(&[
            "nexus-node".into(),
            "clone".into(),
            "--base".into(),
            clone_base.path().to_string_lossy().to_string(),
            "--listen".into(),
            "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            "--bootstrap".into(),
            owner_addr.to_string(),
            "--peer".into(),
            owner_peer.to_string(),
            "--workspace".into(),
            workspace_id.to_string(),
            "--name".into(),
            "cloned-computer".into(),
        ])
        .await
        .unwrap();

        serve_task.abort();

        let clone_identity = load_or_create_identity(clone_base.path()).unwrap();
        let cloned_path = clone_base.path().join("cloned-computer");
        let cloned = Workspace::load(&clone_identity, &cloned_path)
            .await
            .unwrap();
        assert_eq!(cloned.id(), workspace_id);
        assert_eq!(cloned.owner(), owner.did());
        assert_eq!(cloned.guests().len(), 1);
        assert_eq!(&cloned.guests()[0].did, clone_identity.did());
        assert_eq!(cloned.root_cid(), Some(root));
        assert_eq!(cloned.read_file("hello.txt").unwrap(), b"hello from remote");
        assert_eq!(
            cloned.read_file("nested/data.txt").unwrap(),
            b"portable memory"
        );
        assert_eq!(
            local_workspace_paths(clone_base.path()).unwrap(),
            vec![normalize_workspace_path(&cloned_path).unwrap()]
        );

        let memory =
            load_social_memory(&clone_base.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), remote_memory.event_count() + 3);
        assert!(memory
            .society()
            .workspace_snapshots(&workspace_id)
            .into_iter()
            .any(|snapshot| snapshot.actor == *owner.did()
                && snapshot.root == root
                && snapshot.label.as_deref() == Some("served")));
        let view = society_json(&memory);
        assert!(view["agents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|agent| agent["did"] == owner.did().to_string()));
        let workspace = view["workspaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|workspace| workspace["id"] == workspace_id.to_string())
            .unwrap();
        let members = workspace["members"].as_array().unwrap();
        assert!(members
            .iter()
            .any(|member| *member == owner.did().to_string()));
        assert!(members
            .iter()
            .any(|member| *member == clone_identity.did().to_string()));
        assert_eq!(
            workspace["latest_snapshot"]["root"],
            hex::encode(root.as_bytes())
        );
        assert_eq!(workspace["latest_snapshot"]["label"], "cloned");
    }

    #[tokio::test]
    async fn clone_fetches_workspace_state_refreshed_after_external_exec() {
        let owner_base = TempDir::new().unwrap();
        let owner = load_or_create_identity(owner_base.path()).unwrap();
        let mut source = Workspace::create(
            &owner,
            owner_base.path(),
            WorkspaceConfig {
                name: "live-state-source".into(),
                description: "serve should sync current workspace state".into(),
            },
        )
        .await
        .unwrap();
        source.write_file("state.txt", b"initial").unwrap();
        let initial_root = source.snapshot().await.unwrap();
        let workspace_id = source.id();
        let workspace_path = source.root_dir().to_path_buf();

        let mut owner_network = Network::new(
            &owner,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let owner_addr = wait_for_test_listen(&mut owner_network).await;
        let owner_peer = owner_network.local_peer_id();
        let mut server = WorkspaceServer::new(Arc::new(owner_network.clone()));
        server.register(source);
        let served_memory = Arc::new(Mutex::new(SocialMemory::new()));
        let serve_task = spawn_test_workspace_social_server_with_memory(
            Arc::new(load_or_create_identity(owner_base.path()).unwrap()),
            &owner_network,
            server,
            Arc::clone(&served_memory),
        );

        let mut external = Workspace::load(&owner, &workspace_path).await.unwrap();
        external
            .write_file("state.txt", b"updated by another AI")
            .unwrap();
        external
            .write_file("new.txt", b"fresh state is visible")
            .unwrap();
        let updated_root = external.snapshot().await.unwrap();
        assert_ne!(initial_root, updated_root);

        let clone_base = TempDir::new().unwrap();
        cmd_clone(&[
            "nexus-node".into(),
            "clone".into(),
            "--base".into(),
            clone_base.path().to_string_lossy().to_string(),
            "--listen".into(),
            "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            "--bootstrap".into(),
            owner_addr.to_string(),
            "--peer".into(),
            owner_peer.to_string(),
            "--workspace".into(),
            workspace_id.to_string(),
            "--name".into(),
            "cloned-live-state".into(),
        ])
        .await
        .unwrap();

        serve_task.abort();

        let clone_identity = load_or_create_identity(clone_base.path()).unwrap();
        let cloned_path = clone_base.path().join("cloned-live-state");
        let cloned = Workspace::load(&clone_identity, &cloned_path)
            .await
            .unwrap();
        assert_eq!(cloned.id(), workspace_id);
        assert_eq!(cloned.root_cid(), Some(updated_root));
        assert_eq!(
            cloned.read_file("state.txt").unwrap(),
            b"updated by another AI"
        );
        assert_eq!(
            cloned.read_file("new.txt").unwrap(),
            b"fresh state is visible"
        );
        let served_memory = served_memory.lock().await;
        let served_snapshot = served_memory
            .society()
            .workspace_snapshots(&workspace_id)
            .into_iter()
            .find(|snapshot| snapshot.root == updated_root)
            .expect("serve should record the refreshed root as social memory");
        assert_eq!(served_snapshot.actor, *owner.did());
        assert_eq!(served_snapshot.label.as_deref(), Some("served"));

        let clone_memory =
            load_social_memory(&clone_base.path().join(".nexus-social-memory.json")).unwrap();
        assert!(clone_memory
            .society()
            .workspace_snapshots(&workspace_id)
            .into_iter()
            .any(|snapshot| snapshot.actor == *owner.did()
                && snapshot.root == updated_root
                && snapshot.label.as_deref() == Some("served")));
    }

    #[tokio::test]
    async fn workspace_observation_records_new_root_without_peer_request() {
        let owner_base = TempDir::new().unwrap();
        let owner = load_or_create_identity(owner_base.path()).unwrap();
        let mut workspace = Workspace::create(
            &owner,
            owner_base.path(),
            WorkspaceConfig {
                name: "observed-local-state".into(),
                description: "periodic observe records local workspace roots".into(),
            },
        )
        .await
        .unwrap();
        workspace.write_file("state.txt", b"initial").unwrap();
        let initial_root = workspace.snapshot().await.unwrap();
        let workspace_id = workspace.id();
        let workspace_path = workspace.root_dir().to_path_buf();

        let mut network = Network::new(
            &owner,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let _addr = wait_for_test_listen(&mut network).await;
        let mut server = WorkspaceServer::new(Arc::new(network.clone()));
        server.register(workspace);
        let mut memory = SocialMemory::new();
        let memory_path = owner_base.path().join(".nexus-social-memory.json");

        let mut external = Workspace::load(&owner, &workspace_path).await.unwrap();
        external
            .write_file("state.txt", b"changed offline")
            .unwrap();
        let updated_root = external.snapshot().await.unwrap();
        assert_ne!(initial_root, updated_root);

        publish_workspace_announcements(
            &owner,
            &network,
            &mut server,
            &mut memory,
            &memory_path,
            77,
        )
        .await;

        let snapshots = memory.society().workspace_snapshots(&workspace_id);
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].actor, *owner.did());
        assert_eq!(snapshots[0].root, updated_root);
        assert_eq!(snapshots[0].label.as_deref(), Some("served"));
        assert!(memory_path.exists());
    }

    #[tokio::test]
    async fn clone_command_can_use_discovered_workspace_address() {
        let owner_base = TempDir::new().unwrap();
        let owner = load_or_create_identity(owner_base.path()).unwrap();
        let mut source = Workspace::create(
            &owner,
            owner_base.path(),
            WorkspaceConfig {
                name: "discover-source".into(),
                description: "remote AI computer discovered before clone".into(),
            },
        )
        .await
        .unwrap();
        source
            .write_file("hello.txt", b"hello through discovery")
            .unwrap();
        let root = source.snapshot().await.unwrap();
        let workspace_id = source.id();

        let mut owner_network = Network::new(
            &owner,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let owner_addr = wait_for_test_listen(&mut owner_network).await;
        let owner_peer = owner_network.local_peer_id();
        let mut server = WorkspaceServer::new(Arc::new(owner_network.clone()));
        server.register(source);
        let announcement = workspace_announcement(
            &owner,
            owner_peer,
            vec![owner_addr],
            server.workspaces().next().unwrap(),
            50,
        )
        .unwrap();
        let mut remote_memory = SocialMemory::new();
        for event in signed_presence_events(
            &owner,
            build_node_manifest(&owner, owner_base.path(), 200),
            &[workspace_id],
            200,
        )
        .unwrap()
        {
            assert!(remote_memory.ingest_event(event).unwrap());
        }
        let serve_task = spawn_test_workspace_social_server(
            Arc::new(load_or_create_identity(owner_base.path()).unwrap()),
            &owner_network,
            server,
            remote_memory.clone(),
        );

        let clone_base = TempDir::new().unwrap();
        assert!(record_workspace_announcement(clone_base.path(), announcement).unwrap());
        cmd_clone(&[
            "nexus-node".into(),
            "clone".into(),
            "--base".into(),
            clone_base.path().to_string_lossy().to_string(),
            "--listen".into(),
            "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            "--workspace".into(),
            workspace_id.to_string(),
            "--name".into(),
            "cloned-via-discovery".into(),
        ])
        .await
        .unwrap();

        serve_task.abort();

        let clone_identity = load_or_create_identity(clone_base.path()).unwrap();
        let cloned_path = clone_base.path().join("cloned-via-discovery");
        let cloned = Workspace::load(&clone_identity, &cloned_path)
            .await
            .unwrap();
        assert_eq!(cloned.id(), workspace_id);
        assert_eq!(cloned.root_cid(), Some(root));
        assert_eq!(
            cloned.read_file("hello.txt").unwrap(),
            b"hello through discovery"
        );
        let memory =
            load_social_memory(&clone_base.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), remote_memory.event_count() + 3);
        assert!(memory.society().has_agent(owner.did()));
        assert!(memory
            .society()
            .workspace_snapshots(&workspace_id)
            .into_iter()
            .any(|snapshot| snapshot.actor == *owner.did()
                && snapshot.root == root
                && snapshot.label.as_deref() == Some("served")));
    }

    #[tokio::test]
    async fn clone_from_discovery_rejects_remote_root_mismatch() {
        let owner_base = TempDir::new().unwrap();
        let owner = load_or_create_identity(owner_base.path()).unwrap();
        let mut source = Workspace::create(
            &owner,
            owner_base.path(),
            WorkspaceConfig {
                name: "mutable-discovery-source".into(),
                description: "signed discovery state must match clone state".into(),
            },
        )
        .await
        .unwrap();
        source.write_file("state.txt", b"announced").unwrap();
        let announced_root = source.snapshot().await.unwrap();
        let workspace_id = source.id();

        let mut owner_network = Network::new(
            &owner,
            NetworkConfig {
                listen_addr: "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let owner_addr = wait_for_test_listen(&mut owner_network).await;
        let owner_peer = owner_network.local_peer_id();
        let mut server = WorkspaceServer::new(Arc::new(owner_network.clone()));
        let announcement =
            workspace_announcement(&owner, owner_peer, vec![owner_addr], &source, 55).unwrap();

        source
            .write_file("state.txt", b"mutated after announcement")
            .unwrap();
        let mutated_root = source.snapshot().await.unwrap();
        assert_ne!(announced_root, mutated_root);
        server.register(source);
        let serve_task = spawn_test_workspace_social_server(
            Arc::new(load_or_create_identity(owner_base.path()).unwrap()),
            &owner_network,
            server,
            SocialMemory::new(),
        );

        let clone_base = TempDir::new().unwrap();
        assert!(record_workspace_announcement(clone_base.path(), announcement).unwrap());
        let err = cmd_clone(&[
            "nexus-node".into(),
            "clone".into(),
            "--base".into(),
            clone_base.path().to_string_lossy().to_string(),
            "--listen".into(),
            "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            "--workspace".into(),
            workspace_id.to_string(),
            "--name".into(),
            "should-not-clone".into(),
        ])
        .await
        .expect_err("clone must reject state that diverged from signed discovery root");

        serve_task.abort();

        assert!(
            err.to_string()
                .contains("does not match signed discovery root"),
            "unexpected clone error: {err}"
        );
        assert!(!clone_base.path().join("should-not-clone").exists());
    }

    #[tokio::test]
    async fn join_command_persists_workspace_membership_and_social_event() {
        let owner_base = TempDir::new().unwrap();
        let owner = load_or_create_identity(owner_base.path()).unwrap();
        let ws = Workspace::create(
            &owner,
            owner_base.path(),
            WorkspaceConfig {
                name: "shared-computer".into(),
                description: "joinable AI computer".into(),
            },
        )
        .await
        .unwrap();
        let workspace_path = ws.root_dir().to_path_buf();

        let guest_base = TempDir::new().unwrap();
        let guest = load_or_create_identity(guest_base.path()).unwrap();
        cmd_join(&[
            "nexus-node".into(),
            "join".into(),
            "--base".into(),
            guest_base.path().to_string_lossy().to_string(),
            "--workspace".into(),
            workspace_path.to_string_lossy().to_string(),
        ])
        .await
        .unwrap();

        let loaded = Workspace::load(&owner, &workspace_path).await.unwrap();
        assert_eq!(loaded.owner(), owner.did());
        assert_eq!(loaded.guests().len(), 1);
        assert_eq!(&loaded.guests()[0].did, guest.did());

        let memory =
            load_social_memory(&guest_base.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 1);
        let view = society_json(&memory);
        assert_eq!(view["agents"][0]["did"], guest.did().to_string());
        assert_eq!(view["workspaces"][0]["id"], ws.id().to_string());
        assert_eq!(view["workspaces"][0]["members"][0], guest.did().to_string());

        let expected = normalize_workspace_path(&workspace_path).unwrap();
        let paths = local_workspace_paths(guest_base.path()).unwrap();
        assert_eq!(paths, vec![expected]);
    }

    #[tokio::test]
    async fn exec_command_runs_workspace_and_records_social_events() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let mut ws = Workspace::create(
            &identity,
            temp.path(),
            WorkspaceConfig {
                name: "exec-ws".into(),
                description: "workspace exec smoke".into(),
            },
        )
        .await
        .unwrap();
        ws.write_file("input.txt", b"hello").unwrap();
        ws.snapshot().await.unwrap();
        let workspace_path = ws.root_dir().to_path_buf();
        let base = temp.path().to_string_lossy().to_string();

        cmd_exec(&[
            "nexus-node".into(),
            "exec".into(),
            "--base".into(),
            base,
            "--workspace".into(),
            workspace_path.to_string_lossy().to_string(),
            "--note".into(),
            "real workspace execution".into(),
            "--".into(),
            "sh".into(),
            "-c".into(),
            "cat input.txt > output.txt && printf done".into(),
        ])
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(workspace_path.join("output.txt")).unwrap(),
            b"hello"
        );
        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 2);
        let view = society_json(&memory);
        let workspace = &view["workspaces"][0];
        assert_eq!(workspace["runs"].as_array().unwrap().len(), 1);
        assert_eq!(workspace["snapshots"].as_array().unwrap().len(), 1);
        assert_eq!(workspace["runs"][0]["command"], "sh");
        assert_eq!(workspace["runs"][0]["exit_code"], 0);
        assert_eq!(workspace["runs"][0]["note"], "real workspace execution");
        assert_eq!(
            workspace["runs"][0]["output_root"],
            workspace["latest_snapshot"]["root"]
        );
        assert!(workspace["runs"][0]["context"].is_null());
        assert_eq!(workspace["latest_snapshot"]["label"], "after:sh");
    }

    #[tokio::test]
    async fn exec_command_accepts_native_execution_options() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let mut ws = Workspace::create(
            &identity,
            temp.path(),
            WorkspaceConfig {
                name: "exec-options-ws".into(),
                description: "workspace exec options".into(),
            },
        )
        .await
        .unwrap();
        ws.write_file("sub/.keep", b"").unwrap();
        ws.snapshot().await.unwrap();
        let workspace_path = ws.root_dir().to_path_buf();

        cmd_exec(&[
            "nexus-node".into(),
            "exec".into(),
            "--base".into(),
            temp.path().to_string_lossy().to_string(),
            "--workspace".into(),
            workspace_path.to_string_lossy().to_string(),
            "--cwd".into(),
            "sub".into(),
            "--env".into(),
            "NEXUS_MODE=free".into(),
            "--stdin".into(),
            "input-".into(),
            "--timeout-ms".into(),
            "5000".into(),
            "--".into(),
            "sh".into(),
            "-c".into(),
            "cat > output.txt && printf \"$NEXUS_MODE\" >> output.txt".into(),
        ])
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(workspace_path.join("sub/output.txt")).unwrap(),
            b"input-free"
        );
        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json(&memory);
        let run = &view["workspaces"][0]["runs"][0];
        assert_eq!(run["command"], "sh");
        assert_eq!(
            run["args"][1],
            "cat > output.txt && printf \"$NEXUS_MODE\" >> output.txt"
        );
        assert_eq!(run["exit_code"], 0);
        assert_eq!(run["context"]["working_dir"], "sub");
        assert_eq!(
            run["context"]["env_keys"],
            serde_json::json!(["NEXUS_MODE"])
        );
        assert_eq!(run["context"]["stdin"]["bytes"], 6);
        assert_eq!(
            run["context"]["stdin"]["cid"],
            hex::encode(Cid::hash_of(b"input-").as_bytes())
        );
        assert_eq!(run["context"]["timeout_ms"], 5000);
        assert!(!run.to_string().contains("free"));
    }

    #[tokio::test]
    async fn exec_command_hashes_stdin_file_without_recording_contents() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let mut ws = Workspace::create(
            &identity,
            temp.path(),
            WorkspaceConfig {
                name: "exec-stdin-file-ws".into(),
                description: "workspace exec stdin file".into(),
            },
        )
        .await
        .unwrap();
        ws.snapshot().await.unwrap();
        let workspace_path = ws.root_dir().to_path_buf();
        let stdin_path = temp.path().join("stdin.txt");
        std::fs::write(&stdin_path, b"private-input").unwrap();

        cmd_exec(&[
            "nexus-node".into(),
            "exec".into(),
            "--base".into(),
            temp.path().to_string_lossy().to_string(),
            "--workspace".into(),
            workspace_path.to_string_lossy().to_string(),
            "--stdin-file".into(),
            stdin_path.to_string_lossy().to_string(),
            "--".into(),
            "sh".into(),
            "-c".into(),
            "cat > copied.txt".into(),
        ])
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(workspace_path.join("copied.txt")).unwrap(),
            b"private-input"
        );
        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json(&memory);
        let run = &view["workspaces"][0]["runs"][0];
        assert_eq!(run["context"]["stdin"]["bytes"], 13);
        assert_eq!(
            run["context"]["stdin"]["cid"],
            hex::encode(Cid::hash_of(b"private-input").as_bytes())
        );
        assert!(!run.to_string().contains("private-input"));
    }

    #[tokio::test]
    async fn exec_command_records_startup_failures_as_social_events() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let mut ws = Workspace::create(
            &identity,
            temp.path(),
            WorkspaceConfig {
                name: "exec-failure-ws".into(),
                description: "workspace exec failure recording".into(),
            },
        )
        .await
        .unwrap();
        ws.write_file("sub/.keep", b"").unwrap();
        let initial_root = ws.snapshot().await.unwrap();
        let workspace_path = ws.root_dir().to_path_buf();

        let err = cmd_exec(&[
            "nexus-node".into(),
            "exec".into(),
            "--base".into(),
            temp.path().to_string_lossy().to_string(),
            "--workspace".into(),
            workspace_path.to_string_lossy().to_string(),
            "--cwd".into(),
            "sub".into(),
            "--env".into(),
            "NEXUS_SECRET=free".into(),
            "--stdin".into(),
            "private-input".into(),
            "--timeout-ms".into(),
            "5000".into(),
            "--note".into(),
            "startup failure".into(),
            "--".into(),
            "__nexus_missing_command_for_failure_record__".into(),
        ])
        .await
        .expect_err("startup failure should be returned to the caller");

        assert!(err.to_string().contains("command not found"));
        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 1);
        let view = society_json(&memory);
        let workspace = &view["workspaces"][0];
        assert_eq!(workspace["snapshots"].as_array().unwrap().len(), 1);
        assert_eq!(
            workspace["latest_snapshot"]["root"],
            hex::encode(initial_root.as_bytes())
        );
        assert_eq!(workspace["latest_snapshot"]["label"], "workspace-run");
        let run = &workspace["runs"][0];
        assert_eq!(
            run["command"],
            "__nexus_missing_command_for_failure_record__"
        );
        assert_eq!(run["exit_code"], -1);
        assert_eq!(run["stdout"], hex::encode(Cid::hash_of(b"").as_bytes()));
        assert_eq!(run["stderr"], hex::encode(Cid::hash_of(b"").as_bytes()));
        assert_eq!(run["output_root"], hex::encode(initial_root.as_bytes()));
        assert_eq!(run["context"]["working_dir"], "sub");
        assert_eq!(
            run["context"]["env_keys"],
            serde_json::json!(["NEXUS_SECRET"])
        );
        assert_eq!(run["context"]["stdin"]["bytes"], 13);
        assert_eq!(
            run["context"]["stdin"]["cid"],
            hex::encode(Cid::hash_of(b"private-input").as_bytes())
        );
        assert_eq!(run["context"]["timeout_ms"], 5000);
        assert_eq!(run["resources"]["process_count"], 0);
        assert_eq!(run["failure"]["kind"], "command_not_found");
        assert!(run["failure"]["message"]
            .as_str()
            .unwrap()
            .contains("__nexus_missing_command_for_failure_record__"));
        assert_eq!(run["note"], "startup failure");
        assert!(!run.to_string().contains("free"));
        assert!(!run.to_string().contains("private-input"));
    }

    #[tokio::test]
    async fn exec_command_records_timeout_failure_resources() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let mut ws = Workspace::create(
            &identity,
            temp.path(),
            WorkspaceConfig {
                name: "exec-timeout-ws".into(),
                description: "workspace exec timeout recording".into(),
            },
        )
        .await
        .unwrap();
        let initial_root = ws.snapshot().await.unwrap();
        let workspace_path = ws.root_dir().to_path_buf();

        let err = cmd_exec(&[
            "nexus-node".into(),
            "exec".into(),
            "--base".into(),
            temp.path().to_string_lossy().to_string(),
            "--workspace".into(),
            workspace_path.to_string_lossy().to_string(),
            "--timeout-ms".into(),
            "20".into(),
            "--env".into(),
            "NEXUS_TIMEOUT_STDOUT=partial-out".into(),
            "--env".into(),
            "NEXUS_TIMEOUT_STDERR=partial-err".into(),
            "--".into(),
            "sh".into(),
            "-c".into(),
            "printf \"$NEXUS_TIMEOUT_STDOUT\"; printf \"$NEXUS_TIMEOUT_STDERR\" >&2; sleep 1"
                .into(),
        ])
        .await
        .expect_err("timeout should be returned to the caller");

        assert!(err.to_string().contains("timeout"));
        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 1);
        let view = society_json(&memory);
        let run = &view["workspaces"][0]["runs"][0];
        assert_eq!(run["command"], "sh");
        assert_eq!(run["exit_code"], -1);
        assert_eq!(
            run["stdout"],
            hex::encode(Cid::hash_of(b"partial-out").as_bytes())
        );
        assert_eq!(
            run["stderr"],
            hex::encode(Cid::hash_of(b"partial-err").as_bytes())
        );
        assert_eq!(run["output_root"], hex::encode(initial_root.as_bytes()));
        assert_eq!(run["context"]["timeout_ms"], 20);
        assert_eq!(run["failure"]["kind"], "timeout");
        assert_eq!(run["resources"]["process_count"], 1);
        let wall_time = &run["resources"]["wall_time"];
        let wall_time_nanos = wall_time["secs"].as_u64().unwrap() * 1_000_000_000
            + u64::from(wall_time["nanos"].as_u64().unwrap() as u32);
        assert!(wall_time_nanos > 0);
        assert!(!run.to_string().contains("partial-out"));
        assert!(!run.to_string().contains("partial-err"));
    }

    #[test]
    fn node_ingests_social_event_bytes_into_persistent_memory() {
        let alice = NodeIdentity::generate();
        let bob = NodeIdentity::generate();
        let event = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::RelationDeclared {
                peer: bob.did().clone(),
                relation: RelationKind::Collaborator,
                note: Some("node memory".into()),
            },
        )
        .sign(&alice)
        .unwrap();
        let bytes = event.to_json().unwrap();

        let temp = TempDir::new().unwrap();
        let memory_path = temp.path().join("social-memory.json");
        let mut memory = SocialMemory::new();

        let outcome = ingest_social_event_bytes(&bytes, &mut memory, &memory_path).unwrap();
        assert_eq!(outcome, SocialIngestOutcome::Inserted);
        assert_eq!(memory.event_count(), 1);
        assert_eq!(
            memory.society().edge(alice.did(), bob.did()).unwrap().kind,
            RelationKind::Collaborator
        );

        let loaded = load_social_memory(&memory_path).unwrap();
        assert_eq!(loaded.event_count(), 1);
        assert!(loaded.society().has_agent(alice.did()));
        assert!(loaded.society().has_agent(bob.did()));
    }

    #[test]
    fn node_deduplicates_or_rejects_social_event_bytes() {
        let alice = NodeIdentity::generate();
        let signed = SocialEvent::new(
            alice.did().clone(),
            1,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([21; 32]),
            },
        )
        .sign(&alice)
        .unwrap()
        .to_json()
        .unwrap();
        let unsigned = SocialEvent::new(
            alice.did().clone(),
            2,
            SocialEventKind::WorkspaceJoined {
                workspace: WorkspaceId::from_bytes([22; 32]),
            },
        )
        .to_json()
        .unwrap();

        let temp = TempDir::new().unwrap();
        let memory_path = temp.path().join("social-memory.json");
        let mut memory = SocialMemory::new();

        assert_eq!(
            ingest_social_event_bytes(&signed, &mut memory, &memory_path).unwrap(),
            SocialIngestOutcome::Inserted
        );
        assert_eq!(
            ingest_social_event_bytes(&signed, &mut memory, &memory_path).unwrap(),
            SocialIngestOutcome::Duplicate
        );
        assert!(ingest_social_event_bytes(&unsigned, &mut memory, &memory_path).is_err());
        assert_eq!(memory.event_count(), 1);
    }

    #[test]
    fn atomic_write_replaces_existing_file_and_cleans_temp() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("nested").join("state.json");

        write_file_atomic(&path, br#"{"version":1}"#).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"version":1}"#);

        write_file_atomic(&path, br#"{"version":2}"#).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"version":2}"#);

        let parent = path.parent().unwrap();
        let leftovers = std::fs::read_dir(parent)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn node_presence_events_publish_manifest_and_workspace_membership() {
        let identity = NodeIdentity::generate();
        let workspaces = [
            WorkspaceId::from_bytes([31; 32]),
            WorkspaceId::from_bytes([32; 32]),
        ];
        let manifest = build_node_manifest(&identity, Path::new("/tmp/alice-node"), 100);
        assert_eq!(manifest.did, *identity.did());
        assert_eq!(manifest.name, "alice-node");
        assert!(manifest.provides_named("native-workspace"));
        assert!(manifest.provides_named("social-event-gossip"));

        let events = signed_presence_events(&identity, manifest, &workspaces, 100).unwrap();
        assert_eq!(events.len(), 3);
        for event in &events {
            event.verify_signature().unwrap();
        }

        assert!(matches!(
            &events[0].kind,
            SocialEventKind::ManifestPublished { manifest } if manifest.did == *identity.did()
        ));
        assert!(matches!(
            &events[1].kind,
            SocialEventKind::WorkspaceJoined { workspace } if *workspace == workspaces[0]
        ));
        assert!(matches!(
            &events[2].kind,
            SocialEventKind::WorkspaceJoined { workspace } if *workspace == workspaces[1]
        ));

        let mut memory = SocialMemory::new();
        for event in events {
            assert!(memory.ingest_event(event).unwrap());
        }
        assert_eq!(memory.event_count(), 3);
        assert!(memory.society().has_agent(identity.did()));
    }

    #[test]
    fn social_events_response_filters_known_events_and_respects_limit() {
        let identity = NodeIdentity::generate();
        let event_a = signed_workspace_event(&identity, 41, 1);
        let event_b = signed_workspace_event(&identity, 42, 2);
        let event_c = signed_workspace_event(&identity, 43, 3);
        let mut memory = SocialMemory::new();
        for event in [event_a.clone(), event_b.clone(), event_c.clone()] {
            assert!(memory.ingest_event(event).unwrap());
        }

        let response = social_events_response(&memory, std::slice::from_ref(&event_a.id), 1);
        let events_json = match response {
            SyncResponse::SocialEventsResponse { events_json } => events_json,
            other => panic!("unexpected response: {other:?}"),
        };

        assert_eq!(events_json.len(), 1);
        let decoded = SocialEvent::from_json(&events_json[0]).unwrap();
        decoded.verify_signature().unwrap();
        assert_eq!(decoded.id, event_b.id);
    }

    #[test]
    fn social_events_response_clamps_remote_limit() {
        let identity = NodeIdentity::generate();
        let mut memory = SocialMemory::new();
        for i in 0..3 {
            let event = signed_workspace_event(&identity, (i % 251) as u8, i as u64 + 1);
            assert!(memory.ingest_event(event).unwrap());
        }

        let response =
            social_events_response_with_caps(&memory, &[], usize::MAX, 2, MAX_SYNC_MESSAGE_BYTES);
        let events_json = match response {
            SyncResponse::SocialEventsResponse { events_json } => events_json,
            other => panic!("unexpected response: {other:?}"),
        };

        assert_eq!(events_json.len(), 2);
    }

    #[test]
    fn social_events_response_stops_before_frame_limit() {
        let identity = NodeIdentity::generate();
        let event_a = signed_workspace_event(&identity, 45, 1);
        let event_b = signed_workspace_event(&identity, 46, 2);
        let first_event_json = event_a.to_json().unwrap();
        let max_frame_bytes =
            social_events_response_frame_len(std::slice::from_ref(&first_event_json)).unwrap();
        let mut memory = SocialMemory::new();
        for event in [event_a, event_b] {
            assert!(memory.ingest_event(event).unwrap());
        }

        let response = social_events_response_with_caps(&memory, &[], 10, 10, max_frame_bytes);
        let events_json = match response {
            SyncResponse::SocialEventsResponse { events_json } => events_json,
            other => panic!("unexpected response: {other:?}"),
        };

        assert_eq!(events_json.len(), 1);
    }

    #[test]
    fn social_events_response_errors_when_single_event_exceeds_frame_limit() {
        let identity = NodeIdentity::generate();
        let event = signed_workspace_event(&identity, 47, 1);
        let event_id = event.id.clone();
        let mut memory = SocialMemory::new();
        assert!(memory.ingest_event(event).unwrap());

        let response = social_events_response_with_caps(&memory, &[], 10, 10, 0);

        assert!(matches!(
            response,
            SyncResponse::Error { message }
                if message.contains(&event_id) && message.contains("exceeds sync frame limit")
        ));
    }

    #[test]
    fn synced_social_events_are_ingested_and_persisted() {
        let identity = NodeIdentity::generate();
        let event = signed_workspace_event(&identity, 44, 1);
        let response = SyncResponse::SocialEventsResponse {
            events_json: vec![event.to_json().unwrap()],
        };
        let events_json = match response {
            SyncResponse::SocialEventsResponse { events_json } => events_json,
            _ => unreachable!(),
        };

        let temp = TempDir::new().unwrap();
        let memory_path = temp.path().join("social-memory.json");
        let mut memory = SocialMemory::new();

        for data in events_json {
            assert_eq!(
                ingest_social_event_bytes(&data, &mut memory, &memory_path).unwrap(),
                SocialIngestOutcome::Inserted
            );
        }

        let loaded = load_social_memory(&memory_path).unwrap();
        assert_eq!(loaded.event_count(), 1);
        assert!(loaded.society().has_agent(identity.did()));
    }

    #[test]
    fn society_json_exposes_agents_workspaces_and_tasks() {
        let identity = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([55; 32]);
        let manifest = build_node_manifest(&identity, Path::new("/tmp/social-node"), 100);
        let events = signed_presence_events(&identity, manifest, &[workspace], 100).unwrap();
        let mut memory = SocialMemory::new();
        for event in events {
            assert!(memory.ingest_event(event).unwrap());
        }

        let view = society_json(&memory);
        assert_eq!(view["events"], 2);
        assert_eq!(view["agents"][0]["did"], identity.did().to_string());
        assert_eq!(view["agents"][0]["manifest"]["name"], "social-node");
        assert_eq!(view["agents"][0]["workspaces"][0], workspace.to_string());
        assert_eq!(view["workspaces"][0]["id"], workspace.to_string());
        assert_eq!(
            view["workspaces"][0]["members"][0],
            identity.did().to_string()
        );
        assert_eq!(
            view["workspaces"][0]["snapshots"].as_array().unwrap().len(),
            0
        );
        assert_eq!(view["workspaces"][0]["runs"].as_array().unwrap().len(), 0);
        assert!(view["workspaces"][0]["latest_snapshot"].is_null());
        assert_eq!(view["relations"].as_array().unwrap().len(), 0);
        assert_eq!(view["interactions"].as_array().unwrap().len(), 0);
        assert_eq!(view["reputations"].as_array().unwrap().len(), 0);
        assert_eq!(view["collectives"].as_array().unwrap().len(), 0);
        assert_eq!(view["capability_grants"].as_array().unwrap().len(), 0);
        assert_eq!(view["intents"].as_array().unwrap().len(), 0);
        assert_eq!(view["tasks"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn event_commands_record_agent_intents() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let workspace = WorkspaceId::from_bytes([56; 32]);
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "intent".into(),
            "--base".into(),
            base,
            "--id".into(),
            "intent-review-1".into(),
            "--kind".into(),
            "need".into(),
            "--title".into(),
            "Need reviewer".into(),
            "--body".into(),
            "another AI should inspect this workspace".into(),
            "--workspace".into(),
            workspace.to_string(),
            "--task".into(),
            "task-review-1".into(),
            "--capability".into(),
            "code-review".into(),
            "--tag".into(),
            "audit".into(),
            "--tag".into(),
            "high-autonomy".into(),
            "--expires-at".into(),
            "9999999999".into(),
        ])
        .unwrap();
        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "intent-response".into(),
            "--base".into(),
            temp.path().to_string_lossy().to_string(),
            "--id".into(),
            "response-review-1".into(),
            "--intent".into(),
            "intent-review-1".into(),
            "--kind".into(),
            "interested".into(),
            "--body".into(),
            "I can review this workspace".into(),
            "--workspace".into(),
            workspace.to_string(),
            "--task".into(),
            "task-review-1".into(),
            "--capability".into(),
            "code-review".into(),
            "--evidence".into(),
            "manifest:reviewer".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json(&memory);
        assert_eq!(view["events"], 2);
        assert_eq!(view["intents"][0]["id"], "intent-review-1");
        assert_eq!(view["intents"][0]["author"], identity.did().to_string());
        assert_eq!(view["intents"][0]["kind"], "Need");
        assert_eq!(view["intents"][0]["workspace"], workspace.to_string());
        assert_eq!(view["intents"][0]["task_id"], "task-review-1");
        assert_eq!(view["intents"][0]["capability"], "code-review");
        assert_eq!(view["intents"][0]["tags"][0], "audit");
        assert_eq!(view["agents"][0]["intents"][0]["id"], "intent-review-1");
        assert_eq!(view["workspaces"][0]["intents"][0]["id"], "intent-review-1");
        assert_eq!(view["intent_responses"][0]["id"], "response-review-1");
        assert_eq!(
            view["intent_responses"][0]["responder"],
            identity.did().to_string()
        );
        assert_eq!(view["intent_responses"][0]["intent_id"], "intent-review-1");
        assert_eq!(view["intent_responses"][0]["kind"], "Interested");
        assert_eq!(
            view["agents"][0]["intent_responses"][0]["id"],
            "response-review-1"
        );
        assert_eq!(
            view["workspaces"][0]["intent_responses"][0]["id"],
            "response-review-1"
        );

        let workspace_slice = society_json_for_base(
            temp.path(),
            &memory,
            SocietyJsonOptions {
                workspace_filter: Some(workspace),
                ..Default::default()
            },
        );
        assert_eq!(workspace_slice["intents"].as_array().unwrap().len(), 1);
        assert_eq!(
            workspace_slice["intent_responses"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let task_slice = society_json_for_base(
            temp.path(),
            &memory,
            SocietyJsonOptions {
                task_filter: Some("task-review-1".into()),
                ..Default::default()
            },
        );
        assert_eq!(task_slice["intents"].as_array().unwrap().len(), 1);
        assert_eq!(task_slice["intent_responses"].as_array().unwrap().len(), 1);
        for event in memory.events() {
            event.verify_signature().unwrap();
        }
    }

    #[test]
    fn society_json_recommends_open_intents_for_agent() {
        let temp = TempDir::new().unwrap();
        let requester = NodeIdentity::generate();
        let author = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([57; 32]);
        let mut memory = SocialMemory::new();

        let events = [
            SocialEvent::new(
                requester.did().clone(),
                1,
                SocialEventKind::ManifestPublished {
                    manifest: AgentManifest::new(requester.did().clone(), "reviewer", 1)
                        .provide(CapabilityDecl {
                            name: "code-review".into(),
                            description: "review workspaces".into(),
                            version: "1.0".into(),
                            price_per_unit: 1,
                            price_unit: "per-request".into(),
                        })
                        .preference("high-autonomy"),
                },
            )
            .sign(&requester)
            .unwrap(),
            SocialEvent::new(
                requester.did().clone(),
                2,
                SocialEventKind::WorkspaceJoined { workspace },
            )
            .sign(&requester)
            .unwrap(),
            SocialEvent::new(
                author.did().clone(),
                3,
                SocialEventKind::IntentPublished {
                    intent: AgentIntent {
                        id: "intent-review-open".into(),
                        author: author.did().clone(),
                        kind: IntentKind::Need,
                        title: "Need reviewer".into(),
                        body: "inspect this AI workspace".into(),
                        workspace: Some(workspace),
                        task_id: Some("task-open-review".into()),
                        capability: Some("code-review".into()),
                        tags: vec!["high-autonomy".into()],
                        created_at: 3,
                        expires_at: Some(4_102_444_800),
                    },
                },
            )
            .sign(&author)
            .unwrap(),
        ];
        for event in events {
            assert!(memory.ingest_event(event).unwrap());
        }

        let view = society_json_for_base(
            temp.path(),
            &memory,
            SocietyJsonOptions {
                agent_filter: Some(requester.did().clone()),
                intent_recommendation_limit: Some(1),
                ..Default::default()
            },
        );
        let recommendations = view["agents"][0]["intent_recommendations"]
            .as_array()
            .unwrap();
        assert_eq!(recommendations.len(), 1);
        assert_eq!(recommendations[0]["intent"]["id"], "intent-review-open");
        assert_eq!(
            recommendations[0]["intent"]["workspace"],
            workspace.to_string()
        );
        assert_eq!(recommendations[0]["capability_score"], 1.0);
        assert_eq!(recommendations[0]["workspace_score"], 1.0);
        assert!(recommendations[0]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason == "capability:code-review"));
        assert!(recommendations[0]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason == "shared-workspace"));
        let actions = recommendations[0]["actions"].as_array().unwrap();
        assert!(actions.iter().any(|action| {
            action["kind"] == "RespondIntent"
                && action["event_hint"] == "event intent-response"
                && action["response_kind"] == "Interested"
        }));
        assert!(actions.iter().any(|action| {
            action["kind"] == "OfferTask"
                && action["event_hint"] == "event task-offer"
                && action["task_id"] == "task-open-review"
        }));
    }

    #[test]
    fn act_command_records_selected_intent_action() {
        let temp = TempDir::new().unwrap();
        let requester = load_or_create_identity(temp.path()).unwrap();
        let author = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([58; 32]);
        let memory_path = temp.path().join(".nexus-social-memory.json");
        let mut memory = SocialMemory::new();

        let events = [
            SocialEvent::new(
                requester.did().clone(),
                1,
                SocialEventKind::ManifestPublished {
                    manifest: AgentManifest::new(requester.did().clone(), "reviewer", 1)
                        .provide(CapabilityDecl {
                            name: "code-review".into(),
                            description: "review workspaces".into(),
                            version: "1.0".into(),
                            price_per_unit: 7,
                            price_unit: "per-request".into(),
                        })
                        .preference("high-autonomy"),
                },
            )
            .sign(&requester)
            .unwrap(),
            SocialEvent::new(
                requester.did().clone(),
                2,
                SocialEventKind::WorkspaceJoined { workspace },
            )
            .sign(&requester)
            .unwrap(),
            SocialEvent::new(
                author.did().clone(),
                3,
                SocialEventKind::IntentPublished {
                    intent: AgentIntent {
                        id: "intent-act-review".into(),
                        author: author.did().clone(),
                        kind: IntentKind::Need,
                        title: "Need review action".into(),
                        body: "inspect this AI workspace".into(),
                        workspace: Some(workspace),
                        task_id: Some("task-act-review".into()),
                        capability: Some("code-review".into()),
                        tags: vec!["high-autonomy".into()],
                        created_at: 3,
                        expires_at: Some(4_102_444_800),
                    },
                },
            )
            .sign(&author)
            .unwrap(),
        ];
        for event in events {
            assert!(memory.ingest_event(event).unwrap());
        }
        save_social_memory(&memory_path, &memory).unwrap();

        cmd_act(&[
            "nexus-node".into(),
            "act".into(),
            "--base".into(),
            temp.path().to_string_lossy().to_string(),
            "--intent".into(),
            "intent-act-review".into(),
            "--kind".into(),
            "respond-intent".into(),
            "--body".into(),
            "I will inspect this workspace".into(),
            "--evidence".into(),
            "selected-action:intent-act-review".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&memory_path).unwrap();
        assert_eq!(memory.event_count(), 4);
        let view = society_json(&memory);
        assert_eq!(
            view["intent_responses"][0]["intent_id"],
            "intent-act-review"
        );
        assert_eq!(
            view["intent_responses"][0]["responder"],
            requester.did().to_string()
        );
        assert_eq!(view["intent_responses"][0]["kind"], "Interested");
        assert_eq!(
            view["intent_responses"][0]["body"],
            "I will inspect this workspace"
        );
        assert_eq!(
            view["intent_responses"][0]["evidence"],
            "selected-action:intent-act-review"
        );
        for event in memory.events() {
            event.verify_signature().unwrap();
        }
    }

    #[test]
    fn event_commands_record_capability_grants() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let subject = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([56; 32]);
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "capability".into(),
            "--base".into(),
            base,
            "--subject".into(),
            subject.did().to_string(),
            "--workspace".into(),
            workspace.to_string(),
            "--permission".into(),
            "read".into(),
            "--permission".into(),
            "exec".into(),
            "--expires-at".into(),
            "9999999999".into(),
            "--note".into(),
            "join shared workspace".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json(&memory);
        assert_eq!(view["events"], 1);
        assert_eq!(
            view["capability_grants"][0]["issuer"],
            identity.did().to_string()
        );
        assert_eq!(
            view["capability_grants"][0]["subject"],
            subject.did().to_string()
        );
        assert_eq!(
            view["capability_grants"][0]["workspace"],
            workspace.to_string()
        );
        assert_eq!(view["capability_grants"][0]["permissions"]["read"], true);
        assert_eq!(view["capability_grants"][0]["permissions"]["write"], false);
        assert_eq!(view["capability_grants"][0]["permissions"]["exec"], true);
        assert_eq!(view["capability_grants"][0]["permissions"]["admin"], false);
        assert_eq!(
            view["capability_grants"][0]["note"],
            "join shared workspace"
        );
        assert_eq!(
            view["workspaces"][0]["capability_grants"][0]["subject"],
            subject.did().to_string()
        );
    }

    #[test]
    fn event_commands_record_workspace_snapshots() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let workspace = WorkspaceId::from_bytes([57; 32]);
        let root = Cid::hash_of(b"workspace root");
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "workspace-snapshot".into(),
            "--base".into(),
            base,
            "--workspace".into(),
            workspace.to_string(),
            "--root".into(),
            hex::encode(root.as_bytes()),
            "--label".into(),
            "after-analysis".into(),
            "--note".into(),
            "finished local run".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json(&memory);
        assert_eq!(view["events"], 1);
        assert_eq!(view["workspaces"][0]["id"], workspace.to_string());
        assert_eq!(
            view["workspaces"][0]["snapshots"][0]["actor"],
            identity.did().to_string()
        );
        assert_eq!(
            view["workspaces"][0]["snapshots"][0]["root"],
            hex::encode(root.as_bytes())
        );
        assert_eq!(
            view["workspaces"][0]["latest_snapshot"]["label"],
            "after-analysis"
        );
        assert_eq!(
            view["workspaces"][0]["latest_snapshot"]["note"],
            "finished local run"
        );
    }

    #[test]
    fn event_commands_record_workspace_runs() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let workspace = WorkspaceId::from_bytes([58; 32]);
        let output_root = Cid::hash_of(b"run root");
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "workspace-run".into(),
            "--base".into(),
            base,
            "--workspace".into(),
            workspace.to_string(),
            "--command".into(),
            "python".into(),
            "--arg".into(),
            "analysis.py".into(),
            "--exit-code".into(),
            "0".into(),
            "--stdout".into(),
            "ok".into(),
            "--stderr".into(),
            "".into(),
            "--output-root".into(),
            hex::encode(output_root.as_bytes()),
            "--cwd".into(),
            "analysis".into(),
            "--env-key".into(),
            "PYTHONPATH".into(),
            "--env-key".into(),
            "NEXUS_MODE".into(),
            "--stdin".into(),
            "{}".into(),
            "--timeout-ms".into(),
            "30000".into(),
            "--started-at".into(),
            "10".into(),
            "--finished-at".into(),
            "12".into(),
            "--note".into(),
            "autonomous analysis".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json(&memory);
        assert_eq!(view["events"], 1);
        let run = &view["workspaces"][0]["runs"][0];
        assert_eq!(run["workspace"], workspace.to_string());
        assert_eq!(run["actor"], identity.did().to_string());
        assert_eq!(run["command"], "python");
        assert_eq!(run["args"][0], "analysis.py");
        assert_eq!(run["exit_code"], 0);
        assert_eq!(run["stdout"], hex::encode(Cid::hash_of(b"ok").as_bytes()));
        assert_eq!(run["stderr"], hex::encode(Cid::hash_of(b"").as_bytes()));
        assert_eq!(run["output_root"], hex::encode(output_root.as_bytes()));
        assert_eq!(run["resources"]["process_count"], 1);
        assert_eq!(run["context"]["working_dir"], "analysis");
        assert_eq!(
            run["context"]["env_keys"],
            serde_json::json!(["NEXUS_MODE", "PYTHONPATH"])
        );
        assert_eq!(run["context"]["stdin"]["bytes"], 2);
        assert_eq!(
            run["context"]["stdin"]["cid"],
            hex::encode(Cid::hash_of(b"{}").as_bytes())
        );
        assert_eq!(run["context"]["timeout_ms"], 30000);
        assert_eq!(run["started_at"], 10);
        assert_eq!(run["finished_at"], 12);
        assert_eq!(run["note"], "autonomous analysis");
        let agent = view["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["did"] == identity.did().to_string())
            .unwrap();
        assert_eq!(agent["activity"]["workspace_runs"][0]["command"], "python");
        assert_eq!(
            agent["activity"]["workspace_runs"][0]["output_root"],
            hex::encode(output_root.as_bytes())
        );
        assert_eq!(
            view["workspaces"][0]["latest_snapshot"]["root"],
            hex::encode(output_root.as_bytes())
        );
        assert_eq!(
            view["workspaces"][0]["latest_snapshot"]["label"],
            "workspace-run"
        );
    }

    #[test]
    fn event_workspace_run_failure_defaults_to_failure_exit_code() {
        let temp = TempDir::new().unwrap();
        load_or_create_identity(temp.path()).unwrap();
        let workspace = WorkspaceId::from_bytes([78; 32]);
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "workspace-run".into(),
            "--base".into(),
            base,
            "--workspace".into(),
            workspace.to_string(),
            "--command".into(),
            "python".into(),
            "--arg".into(),
            "analysis.py".into(),
            "--failure-kind".into(),
            "timeout".into(),
            "--failure-message".into(),
            "external runner timed out".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json(&memory);
        let run = &view["workspaces"][0]["runs"][0];
        assert_eq!(run["exit_code"], -1);
        assert_eq!(run["failure"]["kind"], "timeout");
        assert_eq!(run["failure"]["message"], "external runner timed out");
    }

    #[test]
    fn society_json_can_window_agent_activity() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let workspace = WorkspaceId::from_bytes([59; 32]);
        let base = temp.path().to_string_lossy().to_string();

        for (label, finished_at) in [("old", "10"), ("middle", "20"), ("new", "30")] {
            cmd_event(&[
                "nexus-node".into(),
                "event".into(),
                "workspace-run".into(),
                "--base".into(),
                base.clone(),
                "--workspace".into(),
                workspace.to_string(),
                "--command".into(),
                "python".into(),
                "--arg".into(),
                format!("{label}.py"),
                "--exit-code".into(),
                "0".into(),
                "--stdout".into(),
                label.into(),
                "--stderr".into(),
                "".into(),
                "--started-at".into(),
                finished_at.into(),
                "--finished-at".into(),
                finished_at.into(),
                "--note".into(),
                label.into(),
            ])
            .unwrap();
        }

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json_for_base(
            Path::new("."),
            &memory,
            SocietyJsonOptions {
                activity_limit: Some(1),
                activity_since: Some(20),
                ..Default::default()
            },
        );
        let agent = view["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["did"] == identity.did().to_string())
            .unwrap();
        assert_eq!(view["workspaces"][0]["runs"].as_array().unwrap().len(), 3);
        assert_eq!(
            agent["activity"]["workspace_runs"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(agent["activity"]["workspace_runs"][0]["note"], "new");
        assert_eq!(agent["activity"]["workspace_runs"][0]["finished_at"], 30);
    }

    #[test]
    fn society_json_can_filter_fact_slices() {
        let temp = TempDir::new().unwrap();
        let publisher = load_or_create_identity(temp.path()).unwrap();
        let executor = NodeIdentity::generate();
        let observer = NodeIdentity::generate();
        let workspace_a = WorkspaceId::from_bytes([60; 32]);
        let workspace_b = WorkspaceId::from_bytes([61; 32]);
        let root_a = Cid::hash_of(b"task one output root");
        let root_b = Cid::hash_of(b"task two output root");
        let mut memory = SocialMemory::new();

        let events = [
            SocialEvent::new(
                publisher.did().clone(),
                1,
                SocialEventKind::ManifestPublished {
                    manifest: AgentManifest::new(publisher.did().clone(), "publisher", 1),
                },
            )
            .sign(&publisher)
            .unwrap(),
            SocialEvent::new(
                executor.did().clone(),
                2,
                SocialEventKind::ManifestPublished {
                    manifest: AgentManifest::new(executor.did().clone(), "executor", 2),
                },
            )
            .sign(&executor)
            .unwrap(),
            SocialEvent::new(
                observer.did().clone(),
                3,
                SocialEventKind::ManifestPublished {
                    manifest: AgentManifest::new(observer.did().clone(), "observer", 3),
                },
            )
            .sign(&observer)
            .unwrap(),
            SocialEvent::new(
                executor.did().clone(),
                4,
                SocialEventKind::WorkspaceJoined {
                    workspace: workspace_a,
                },
            )
            .sign(&executor)
            .unwrap(),
            SocialEvent::new(
                observer.did().clone(),
                5,
                SocialEventKind::WorkspaceJoined {
                    workspace: workspace_b,
                },
            )
            .sign(&observer)
            .unwrap(),
        ];
        for event in events {
            assert!(memory.ingest_event(event).unwrap());
        }

        let task_one = TaskSpec::new(
            publisher.did().clone(),
            "task one",
            "python-exec",
            "python",
            vec!["one.py".into()],
            100,
            999,
            10,
        );
        let task_one_id = task_one.id.clone();
        let task_two = TaskSpec::new(
            publisher.did().clone(),
            "task two",
            "python-exec",
            "python",
            vec!["two.py".into()],
            100,
            999,
            20,
        );
        let task_two_id = task_two.id.clone();
        for (task, timestamp) in [(task_one, 10), (task_two, 20)] {
            assert!(memory
                .ingest_event(
                    SocialEvent::new(
                        publisher.did().clone(),
                        timestamp,
                        SocialEventKind::TaskPublished { task },
                    )
                    .sign(&publisher)
                    .unwrap()
                )
                .unwrap());
        }

        for (task_id, workspace, output_root, timestamp) in [
            (task_one_id.clone(), workspace_a, root_a, 30),
            (task_two_id.clone(), workspace_b, root_b, 40),
        ] {
            assert!(memory
                .ingest_event(
                    SocialEvent::new(
                        publisher.did().clone(),
                        timestamp,
                        SocialEventKind::TaskAccepted {
                            acceptance: TaskAcceptance {
                                task_id: task_id.clone(),
                                publisher: publisher.did().clone(),
                                bidder: executor.did().clone(),
                                price: 10,
                                accepted_at: timestamp,
                            },
                        },
                    )
                    .sign(&publisher)
                    .unwrap()
                )
                .unwrap());

            let stdout = format!("ok:{task_id}");
            let output = ProcessOutput {
                exit_code: 0,
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
                resources: ResourceUsage {
                    process_count: 1,
                    ..Default::default()
                },
            };
            let receipt = ExecutionReceipt::from_process_output(
                task_id.clone(),
                executor.did().clone(),
                Some(workspace),
                "python",
                vec![if workspace == workspace_a {
                    "one.py".into()
                } else {
                    "two.py".into()
                }],
                &output,
                Some(output_root),
                timestamp,
                timestamp + 1,
            )
            .sign(&executor)
            .unwrap();
            assert!(memory
                .ingest_event(
                    SocialEvent::new(
                        executor.did().clone(),
                        timestamp + 1,
                        SocialEventKind::TaskCompleted {
                            result: TaskResult {
                                task_id,
                                executor: executor.did().clone(),
                                success: true,
                                exit_code: 0,
                                stdout,
                                stderr: String::new(),
                                actual_cost: 10,
                                error: None,
                                receipt: Some(Box::new(receipt)),
                            },
                        },
                    )
                    .sign(&executor)
                    .unwrap()
                )
                .unwrap());
        }

        let task_slice = society_json_for_base(
            temp.path(),
            &memory,
            SocietyJsonOptions {
                task_filter: Some(task_one_id.clone()),
                ..Default::default()
            },
        );
        assert_eq!(task_slice["tasks"].as_array().unwrap().len(), 1);
        assert_eq!(task_slice["tasks"][0]["id"], task_one_id);
        assert_eq!(task_slice["workspaces"].as_array().unwrap().len(), 1);
        assert_eq!(task_slice["workspaces"][0]["id"], workspace_a.to_string());
        assert!(task_slice["interactions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|interaction| interaction["evidence"] == task_slice["tasks"][0]["id"]));

        let workspace_slice = society_json_for_base(
            temp.path(),
            &memory,
            SocietyJsonOptions {
                workspace_filter: Some(workspace_b),
                ..Default::default()
            },
        );
        assert_eq!(workspace_slice["workspaces"].as_array().unwrap().len(), 1);
        assert_eq!(
            workspace_slice["workspaces"][0]["id"],
            workspace_b.to_string()
        );
        assert_eq!(workspace_slice["tasks"].as_array().unwrap().len(), 1);
        assert_eq!(workspace_slice["tasks"][0]["id"], task_two_id);
        assert!(workspace_slice["agents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|agent| agent["did"] == executor.did().to_string()));

        let agent_slice = society_json_for_base(
            temp.path(),
            &memory,
            SocietyJsonOptions {
                agent_filter: Some(executor.did().clone()),
                ..Default::default()
            },
        );
        assert_eq!(agent_slice["agents"].as_array().unwrap().len(), 1);
        assert_eq!(agent_slice["agents"][0]["did"], executor.did().to_string());
        assert_eq!(agent_slice["tasks"].as_array().unwrap().len(), 2);
        assert!(agent_slice["relations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|relation| relation["from"] == executor.did().to_string()
                || relation["to"] == executor.did().to_string()));
        assert!(agent_slice["interactions"].as_array().unwrap().iter().all(
            |interaction| interaction["from"] == executor.did().to_string()
                || interaction["to"] == executor.did().to_string()
        ));
    }

    #[test]
    fn event_commands_record_manifest_and_workspace_presence() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let workspace = WorkspaceId::from_bytes([66; 32]);
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "manifest".into(),
            "--base".into(),
            base.clone(),
            "--name".into(),
            "agent-one".into(),
            "--description".into(),
            "scriptable autonomous agent".into(),
            "--provide".into(),
            "python-exec".into(),
            "--goal".into(),
            "build AI society".into(),
            "--value".into(),
            "autonomy".into(),
            "--preference".into(),
            "append-only memory".into(),
            "--role".into(),
            "collaborator".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "workspace-join".into(),
            "--base".into(),
            base,
            "--workspace".into(),
            workspace.to_string(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 2);
        let view = society_json(&memory);
        assert_eq!(view["agents"][0]["did"], identity.did().to_string());
        assert_eq!(view["agents"][0]["manifest"]["name"], "agent-one");
        assert_eq!(
            view["agents"][0]["manifest"]["provides"][0]["name"],
            "python-exec"
        );
        assert_eq!(view["agents"][0]["workspaces"][0], workspace.to_string());
        assert_eq!(
            view["workspaces"][0]["members"][0],
            identity.did().to_string()
        );
        for event in memory.events() {
            event.verify_signature().unwrap();
        }
    }

    #[test]
    fn event_commands_record_collective_membership_and_workspace_context() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let workspace = WorkspaceId::from_bytes([67; 32]);
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective".into(),
            "--base".into(),
            base.clone(),
            "--id".into(),
            "open-lab".into(),
            "--name".into(),
            "Open Lab".into(),
            "--purpose".into(),
            "build a decentralized AI society".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective-join".into(),
            "--base".into(),
            base.clone(),
            "--id".into(),
            "open-lab".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective-workspace".into(),
            "--base".into(),
            base,
            "--id".into(),
            "open-lab".into(),
            "--workspace".into(),
            workspace.to_string(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 3);
        let view = society_json(&memory);
        assert_eq!(view["collectives"][0]["id"], "open-lab");
        assert_eq!(view["collectives"][0]["name"], "Open Lab");
        assert_eq!(
            view["collectives"][0]["purpose"],
            "build a decentralized AI society"
        );
        assert_eq!(
            view["collectives"][0]["members"][0],
            identity.did().to_string()
        );
        assert_eq!(
            view["collectives"][0]["workspaces"][0],
            workspace.to_string()
        );
        for event in memory.events() {
            event.verify_signature().unwrap();
        }
    }

    #[test]
    fn event_commands_record_collective_governance_facts() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let workspace = WorkspaceId::from_bytes([68; 32]);
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective".into(),
            "--base".into(),
            base.clone(),
            "--id".into(),
            "open-lab".into(),
            "--name".into(),
            "Open Lab".into(),
            "--purpose".into(),
            "coordinate AI society governance".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective-proposal".into(),
            "--base".into(),
            base.clone(),
            "--collective".into(),
            "open-lab".into(),
            "--proposal".into(),
            "proposal-1".into(),
            "--title".into(),
            "Open shared workspace".into(),
            "--body".into(),
            "coordinate a shared run".into(),
            "--workspace".into(),
            workspace.to_string(),
            "--deadline".into(),
            "999999".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective-vote".into(),
            "--base".into(),
            base.clone(),
            "--collective".into(),
            "open-lab".into(),
            "--proposal".into(),
            "proposal-1".into(),
            "--choice".into(),
            "approve".into(),
            "--rationale".into(),
            "aligned with autonomous coordination".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective-decision".into(),
            "--base".into(),
            base,
            "--collective".into(),
            "open-lab".into(),
            "--proposal".into(),
            "proposal-1".into(),
            "--outcome".into(),
            "accepted".into(),
            "--reason".into(),
            "local quorum accepted".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 4);
        let view = society_json(&memory);
        let proposal = &view["collectives"][0]["proposals"][0];
        assert_eq!(proposal["id"], "proposal-1");
        assert_eq!(proposal["title"], "Open shared workspace");
        assert_eq!(proposal["workspace"], workspace.to_string());
        assert_eq!(proposal["proposer"], identity.did().to_string());
        assert_eq!(proposal["votes"][0]["voter"], identity.did().to_string());
        assert_eq!(proposal["votes"][0]["choice"], "Approve");
        assert_eq!(proposal["decision"]["decider"], identity.did().to_string());
        assert_eq!(proposal["decision"]["outcome"], "Accepted");
        assert!(proposal["decision"]["task_id"].is_null());
        assert!(proposal["decision"]["claim_id"].is_null());
        assert!(proposal["decision"]["target"].is_null());
        for event in memory.events() {
            event.verify_signature().unwrap();
        }
    }

    #[test]
    fn collective_decision_can_judge_a_specific_task_result_claim() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let target = identity.did().clone();
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "manifest".into(),
            "--base".into(),
            base.clone(),
            "--name".into(),
            "claim-runner".into(),
            "--provide".into(),
            "python-exec".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-publish".into(),
            "--base".into(),
            base.clone(),
            "--description".into(),
            "audit a result claim".into(),
            "--capability".into(),
            "python-exec".into(),
            "--command".into(),
            "python".into(),
            "--arg".into(),
            "analysis.py".into(),
            "--max-budget".into(),
            "100".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let task_id = memory.society().tasks()[0].id.clone();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-complete".into(),
            "--base".into(),
            base.clone(),
            "--task".into(),
            task_id.clone(),
            "--success".into(),
            "--stdout".into(),
            "unverified".into(),
            "--actual-cost".into(),
            "20".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let claim_id = society_json(&memory)["tasks"][0]["result_claims"][0]["claim_id"]
            .as_str()
            .unwrap()
            .to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective".into(),
            "--base".into(),
            base.clone(),
            "--id".into(),
            "audit-lab".into(),
            "--name".into(),
            "Audit Lab".into(),
            "--purpose".into(),
            "judge task result claims".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective-proposal".into(),
            "--base".into(),
            base.clone(),
            "--collective".into(),
            "audit-lab".into(),
            "--proposal".into(),
            "claim-review-1".into(),
            "--title".into(),
            "Review unverified claim".into(),
            "--body".into(),
            "Decide whether the claim should be trusted".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective-decision".into(),
            "--base".into(),
            base,
            "--collective".into(),
            "audit-lab".into(),
            "--proposal".into(),
            "claim-review-1".into(),
            "--outcome".into(),
            "disputed".into(),
            "--task".into(),
            task_id.clone(),
            "--claim".into(),
            claim_id.clone(),
            "--target".into(),
            target.to_string(),
            "--reason".into(),
            "claim lacks signed execution receipt".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json(&memory);
        assert_eq!(memory.event_count(), 6);
        assert_eq!(view["tasks"][0]["claim_judgments"][0]["task_id"], task_id);
        assert_eq!(view["tasks"][0]["claim_judgments"][0]["claim_id"], claim_id);
        assert_eq!(
            view["tasks"][0]["claim_judgments"][0]["target"],
            target.to_string()
        );
        assert_eq!(
            view["tasks"][0]["claim_judgments"][0]["outcome"],
            "Disputed"
        );
        assert_eq!(
            view["tasks"][0]["result_claims"][0]["judgments"][0]["proposal_id"],
            "claim-review-1"
        );
        assert_eq!(
            view["collectives"][0]["proposals"][0]["decision"]["claim_id"],
            claim_id
        );
        let target_agent = view["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["did"] == target.to_string())
            .unwrap();
        assert_eq!(
            target_agent["provider_recommendations"][0]["governance_signals"][0]["claim_id"],
            claim_id
        );
        assert_eq!(
            target_agent["provider_recommendations"][0]["governance_signals"][0]["outcome"],
            "Disputed"
        );
        assert!(
            target_agent["provider_recommendations"][0]["governance_score"]
                .as_f64()
                .unwrap()
                < 0.5
        );
        for event in memory.events() {
            event.verify_signature().unwrap();
        }
    }

    #[test]
    fn society_json_scopes_collective_governance_by_collective() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().to_string_lossy().to_string();

        for collective in ["open-lab", "audit-lab"] {
            cmd_event(&[
                "nexus-node".into(),
                "event".into(),
                "collective".into(),
                "--base".into(),
                base.clone(),
                "--id".into(),
                collective.into(),
                "--name".into(),
                collective.into(),
                "--purpose".into(),
                "govern shared AI work".into(),
            ])
            .unwrap();

            cmd_event(&[
                "nexus-node".into(),
                "event".into(),
                "collective-proposal".into(),
                "--base".into(),
                base.clone(),
                "--collective".into(),
                collective.into(),
                "--proposal".into(),
                "proposal-1".into(),
                "--title".into(),
                format!("proposal for {collective}"),
                "--body".into(),
                "same proposal id, different collective".into(),
            ])
            .unwrap();
        }

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective-vote".into(),
            "--base".into(),
            base.clone(),
            "--collective".into(),
            "audit-lab".into(),
            "--proposal".into(),
            "proposal-1".into(),
            "--choice".into(),
            "reject".into(),
            "--rationale".into(),
            "audit lab rejects only its own proposal".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "collective-decision".into(),
            "--base".into(),
            base,
            "--collective".into(),
            "audit-lab".into(),
            "--proposal".into(),
            "proposal-1".into(),
            "--outcome".into(),
            "rejected".into(),
            "--reason".into(),
            "scoped to audit lab".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json(&memory);
        let collectives = view["collectives"].as_array().unwrap();
        let audit = collectives
            .iter()
            .find(|collective| collective["id"] == "audit-lab")
            .unwrap();
        let open = collectives
            .iter()
            .find(|collective| collective["id"] == "open-lab")
            .unwrap();

        assert_eq!(audit["proposals"][0]["id"], "proposal-1");
        assert_eq!(audit["proposals"][0]["votes"].as_array().unwrap().len(), 1);
        assert_eq!(audit["proposals"][0]["decision"]["outcome"], "Rejected");
        assert_eq!(open["proposals"][0]["id"], "proposal-1");
        assert_eq!(open["proposals"][0]["votes"].as_array().unwrap().len(), 0);
        assert!(open["proposals"][0]["decision"].is_null());
    }

    #[test]
    fn event_commands_record_signed_relation_and_interaction() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let peer = NodeIdentity::generate();
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "relation".into(),
            "--base".into(),
            base.clone(),
            "--peer".into(),
            peer.did().to_string(),
            "--kind".into(),
            "collaborator".into(),
            "--note".into(),
            "shared task history".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "interaction".into(),
            "--base".into(),
            base,
            "--peer".into(),
            peer.did().to_string(),
            "--topic".into(),
            "local collaboration".into(),
            "--outcome".into(),
            "success".into(),
            "--evidence".into(),
            "manual:test".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 2);
        let view = society_json(&memory);
        assert_eq!(view["relations"][0]["kind"], "Collaborator");
        assert_eq!(view["relations"][0]["successes"], 1);
        assert_eq!(view["interactions"][0]["topic"], "local collaboration");
        assert_eq!(view["interactions"][0]["outcome"], "Success");
        assert_eq!(view["reputations"][0]["successes"], 1);
        assert!(view["reputations"][0]["composite"].as_f64().unwrap() > 0.5);

        let edge = memory.society().edge(identity.did(), peer.did()).unwrap();
        assert_eq!(edge.kind, RelationKind::Collaborator);
        assert_eq!(edge.successes, 1);
        assert!(
            memory
                .society()
                .reputation(identity.did(), peer.did())
                .unwrap()
                .composite()
                > 0.5
        );
        for event in memory.events() {
            event.verify_signature().unwrap();
        }
    }

    #[test]
    fn event_commands_record_task_market_facts() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let base = temp.path().to_string_lossy().to_string();
        let workspace = WorkspaceId::from_bytes([75; 32]);
        let output_root = Cid::hash_of(b"task output root");

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-publish".into(),
            "--base".into(),
            base.clone(),
            "--description".into(),
            "analyze workspace".into(),
            "--capability".into(),
            "python-exec".into(),
            "--command".into(),
            "python".into(),
            "--arg".into(),
            "analysis.py".into(),
            "--max-budget".into(),
            "100".into(),
            "--deadline".into(),
            "999999".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let task_id = memory.society().tasks()[0].id.clone();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-offer".into(),
            "--base".into(),
            base.clone(),
            "--task".into(),
            task_id.clone(),
            "--price".into(),
            "25".into(),
            "--eta".into(),
            "30".into(),
            "--rationale".into(),
            "local runtime ready".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-accept".into(),
            "--base".into(),
            base.clone(),
            "--task".into(),
            task_id.clone(),
            "--bidder".into(),
            identity.did().to_string(),
            "--price".into(),
            "25".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-complete".into(),
            "--base".into(),
            base,
            "--task".into(),
            task_id.clone(),
            "--success".into(),
            "--stdout".into(),
            "ok".into(),
            "--actual-cost".into(),
            "20".into(),
            "--receipt".into(),
            "--command".into(),
            "python".into(),
            "--arg".into(),
            "analysis.py".into(),
            "--workspace".into(),
            workspace.to_string(),
            "--output-root".into(),
            hex::encode(output_root.as_bytes()),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 4);
        let view = society_json(&memory);
        assert_eq!(view["tasks"][0]["id"], task_id);
        assert_eq!(view["tasks"][0]["state"], "Completed");
        assert_eq!(view["tasks"][0]["offers"][0]["price"], 25);
        assert_eq!(view["tasks"][0]["result"]["success"], true);
        assert_eq!(
            view["tasks"][0]["result_claims"][0]["task_id"],
            view["tasks"][0]["result"]["task_id"]
        );
        assert_eq!(view["tasks"][0]["result"]["receipt"]["command"], "python");
        assert_eq!(
            view["tasks"][0]["result"]["receipt"]["args"][0],
            "analysis.py"
        );
        assert_eq!(
            view["tasks"][0]["result"]["receipt"]["workspace"],
            workspace.to_string()
        );
        assert_eq!(
            view["tasks"][0]["result"]["receipt"]["output_root"],
            hex::encode(output_root.as_bytes())
        );
        assert_eq!(
            view["tasks"][0]["result"]["receipt"]["stdout_cid"],
            hex::encode(Cid::hash_of(b"ok").as_bytes())
        );
        assert_eq!(
            view["tasks"][0]["result"]["receipt"]["stderr_cid"],
            hex::encode(Cid::hash_of(b"").as_bytes())
        );
        let task_workspace = view["workspaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|workspace_view| workspace_view["id"] == workspace.to_string())
            .unwrap();
        assert_eq!(
            task_workspace["latest_snapshot"]["root"],
            hex::encode(output_root.as_bytes())
        );
        assert_eq!(task_workspace["latest_snapshot"]["label"], "task-result");
        assert_eq!(view["relations"][0]["successes"], 1);
        assert!(view["reputations"][0]["composite"].as_f64().unwrap() > 0.5);
        let agent = view["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|agent| agent["did"] == identity.did().to_string())
            .unwrap();
        assert_eq!(agent["activity"]["task_results"][0]["task_id"], task_id);
        assert_eq!(
            agent["activity"]["task_result_claims"][0]["task_id"],
            task_id
        );
        assert_eq!(agent["activity"]["interactions"][0]["outcome"], "Success");
        assert_eq!(agent["activity"]["reputations"][0]["successes"], 1);
        for event in memory.events() {
            event.verify_signature().unwrap();
        }
        assert_eq!(
            memory.society().task(&task_id).unwrap().publisher,
            *identity.did()
        );
    }

    #[test]
    fn event_commands_record_task_acceptance_and_cancellation() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let bidder = NodeIdentity::generate();
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-publish".into(),
            "--base".into(),
            base.clone(),
            "--description".into(),
            "assign task".into(),
            "--capability".into(),
            "python-exec".into(),
            "--command".into(),
            "python".into(),
            "--arg".into(),
            "analysis.py".into(),
            "--max-budget".into(),
            "100".into(),
        ])
        .unwrap();
        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let task_id = memory.society().tasks()[0].id.clone();

        let offer = SocialEvent::new(
            bidder.did().clone(),
            unix_now(),
            SocialEventKind::TaskOffered {
                offer: TaskOffer {
                    task_id: task_id.clone(),
                    bidder: bidder.did().clone(),
                    price: 25,
                    estimated_time_secs: 10,
                    rationale: "remote worker ready".into(),
                },
            },
        )
        .sign(&bidder)
        .unwrap();
        let memory_path = temp.path().join(".nexus-social-memory.json");
        let mut memory = load_social_memory(&memory_path).unwrap();
        assert!(memory.ingest_event(offer).unwrap());
        save_social_memory(&memory_path, &memory).unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-accept".into(),
            "--base".into(),
            base.clone(),
            "--task".into(),
            task_id.clone(),
            "--bidder".into(),
            bidder.did().to_string(),
            "--price".into(),
            "25".into(),
        ])
        .unwrap();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-publish".into(),
            "--base".into(),
            base.clone(),
            "--description".into(),
            "cancel task".into(),
            "--capability".into(),
            "python-exec".into(),
            "--command".into(),
            "python".into(),
            "--arg".into(),
            "cancel.py".into(),
            "--max-budget".into(),
            "50".into(),
        ])
        .unwrap();
        let memory = load_social_memory(&memory_path).unwrap();
        let cancel_id = memory
            .society()
            .tasks()
            .into_iter()
            .find(|task| task.description == "cancel task")
            .unwrap()
            .id
            .clone();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-cancel".into(),
            "--base".into(),
            base,
            "--task".into(),
            cancel_id.clone(),
            "--reason".into(),
            "superseded".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&memory_path).unwrap();
        let view = society_json(&memory);
        let accepted = view["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|task| task["id"] == task_id)
            .unwrap();
        assert_eq!(accepted["state"], "InProgress");
        assert_eq!(accepted["assigned_to"], bidder.did().to_string());
        assert_eq!(
            accepted["acceptance"]["publisher"],
            identity.did().to_string()
        );
        assert_eq!(accepted["acceptance"]["bidder"], bidder.did().to_string());
        assert_eq!(accepted["acceptance"]["price"], 25);

        let cancelled = view["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|task| task["id"] == cancel_id)
            .unwrap();
        assert_eq!(cancelled["state"], "Cancelled");
        assert_eq!(
            cancelled["cancellation"]["publisher"],
            identity.did().to_string()
        );
        assert_eq!(cancelled["cancellation"]["reason"], "superseded");
    }

    #[test]
    fn event_commands_record_sovereign_settlement_facts() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let payee = NodeIdentity::generate();
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "settlement".into(),
            "--base".into(),
            base,
            "--id".into(),
            "settlement-1".into(),
            "--task".into(),
            "task-1".into(),
            "--claim".into(),
            "claim-1".into(),
            "--payee".into(),
            payee.did().to_string(),
            "--amount".into(),
            "42".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let settlement = memory
            .society()
            .settlement("settlement-1")
            .expect("settlement should be recorded");
        assert_eq!(settlement.payer, *identity.did());
        assert_eq!(settlement.payee, *payee.did());
        assert_eq!(settlement.amount, 42);
        assert!(matches!(settlement.proof, SettlementProof::Sovereign));

        let view = society_json(&memory);
        assert_eq!(view["settlements"][0]["id"], "settlement-1");
        assert_eq!(view["settlements"][0]["proof"]["kind"], "Sovereign");
    }

    #[test]
    fn event_task_success_without_receipt_does_not_grant_reputation() {
        let temp = TempDir::new().unwrap();
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-publish".into(),
            "--base".into(),
            base.clone(),
            "--description".into(),
            "unverified task".into(),
            "--capability".into(),
            "python-exec".into(),
            "--command".into(),
            "python".into(),
            "--arg".into(),
            "analysis.py".into(),
            "--max-budget".into(),
            "100".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let task_id = memory.society().tasks()[0].id.clone();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-complete".into(),
            "--base".into(),
            base,
            "--task".into(),
            task_id.clone(),
            "--success".into(),
            "--stdout".into(),
            "ok".into(),
            "--actual-cost".into(),
            "20".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let view = society_json(&memory);
        assert_eq!(view["tasks"][0]["id"], task_id);
        assert_eq!(view["tasks"][0]["state"], "Published");
        assert!(view["tasks"][0]["result"].is_null());
        let claim_id = view["tasks"][0]["result_claims"][0]["claim_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(claim_id.len(), 64);
        assert_eq!(view["tasks"][0]["result_claims"][0]["success"], true);
        assert!(view["tasks"][0]["result_claims"][0]["receipt"].is_null());
        assert_eq!(view["relations"].as_array().unwrap().len(), 0);
        assert_eq!(view["reputations"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn event_commands_record_task_dispute_facts() {
        let temp = TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let target = NodeIdentity::generate();
        let base = temp.path().to_string_lossy().to_string();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-publish".into(),
            "--base".into(),
            base.clone(),
            "--description".into(),
            "auditable task".into(),
            "--capability".into(),
            "python-exec".into(),
            "--command".into(),
            "python".into(),
            "--arg".into(),
            "analysis.py".into(),
            "--max-budget".into(),
            "100".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        let task_id = memory.society().tasks()[0].id.clone();

        cmd_event(&[
            "nexus-node".into(),
            "event".into(),
            "task-dispute".into(),
            "--base".into(),
            base,
            "--task".into(),
            task_id.clone(),
            "--target".into(),
            target.did().to_string(),
            "--claim".into(),
            "claim-abc123".into(),
            "--reason".into(),
            "receipt output mismatch".into(),
            "--evidence".into(),
            "audit:receipt".into(),
        ])
        .unwrap();

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 2);
        let view = society_json(&memory);
        assert_eq!(view["tasks"][0]["disputes"][0]["task_id"], task_id);
        assert_eq!(
            view["tasks"][0]["disputes"][0]["disputer"],
            identity.did().to_string()
        );
        assert_eq!(
            view["tasks"][0]["disputes"][0]["target"],
            target.did().to_string()
        );
        assert_eq!(view["tasks"][0]["disputes"][0]["claim_id"], "claim-abc123");
        assert_eq!(
            view["tasks"][0]["disputes"][0]["reason"],
            "receipt output mismatch"
        );
        assert_eq!(view["relations"][0]["kind"], "Acquaintance");
        assert_eq!(view["relations"][0]["failures"], 1);
        assert_eq!(view["interactions"][0]["outcome"], "Dispute");
        assert_eq!(view["reputations"][0]["failures"], 1);
        for event in memory.events() {
            event.verify_signature().unwrap();
        }
    }
}
