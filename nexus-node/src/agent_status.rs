use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use nexus_agent::{
    AgentIntent, IntentActionKind, IntentActionPlan, IntentKind, IntentRecommendation,
    SocialEventKind, SocialMemory, Task, TaskState, WorkspaceRunContext,
};
use nexus_core::Did;
use nexus_runtime::ResourceUsage;
use nexus_storage::Cid;

use crate::bootstrap::extend_bootstrap_peers;
use crate::cli_args::{normalize_symbol, parse_u64_arg, parse_usize_arg, required_arg};
use crate::daemon::{daemon_status_report, start_daemon, DaemonStartOptions, DaemonStatusReport};
use crate::discovery::{
    discovered_workspace_views, load_workspace_discovery, DiscoveredWorkspaceView, DiscoveryFilter,
    DiscoverySort,
};
use crate::ids::parse_workspace_id;
use crate::local_state::{identity_path, load_or_create_identity, local_workspace_paths};
use crate::social_sync::{load_social_memory, save_social_memory};
use crate::{
    parse_workspace_exec_options, run_workspace_exec, unix_now, WorkspaceExecOptions,
    WorkspaceExecReport,
};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AgentStatusReport {
    schema: &'static str,
    base: String,
    identity: IdentityStatus,
    social_memory: SocialMemoryStatus,
    local_workspaces: Vec<LocalWorkspaceStatus>,
    discovered_workspaces: Vec<DiscoveredWorkspaceStatus>,
    daemon: DaemonStatusReport,
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

#[derive(Clone, Debug, Serialize, PartialEq)]
pub(crate) struct AgentInboxReport {
    schema: &'static str,
    base: String,
    agent: Option<String>,
    generated_at: u64,
    daemon: DaemonStatusReport,
    summary: AgentInboxSummary,
    items: Vec<AgentInboxItem>,
    recommended_commands: Vec<CommandHint>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
struct AgentInboxSummary {
    items: usize,
    daemon_alerts: usize,
    intent_recommendations: usize,
    open_tasks: usize,
    assigned_tasks: usize,
    discovered_workspaces: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
struct AgentInboxItem {
    kind: &'static str,
    priority: u32,
    title: String,
    body: Option<String>,
    author: Option<String>,
    workspace: Option<String>,
    task_id: Option<String>,
    capability: Option<String>,
    timestamp: Option<u64>,
    score: Option<f64>,
    reasons: Vec<String>,
    actions: Vec<AgentInboxAction>,
    command_hint: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub(crate) struct AgentDiscoverReport {
    schema: &'static str,
    base: String,
    mode: &'static str,
    daemon: DaemonStatusReport,
    summary: AgentDiscoverSummary,
    workspaces: Vec<DiscoveredWorkspaceView>,
    error: Option<String>,
    recommended_commands: Vec<CommandHint>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AgentUpReport {
    schema: &'static str,
    started: bool,
    status: DaemonStatusReport,
    recommended_commands: Vec<CommandHint>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub(crate) struct AgentSendReport {
    schema: &'static str,
    base: String,
    event: AgentSendEvent,
    intent: AgentSendIntent,
    delivery: AgentSendDelivery,
    daemon: DaemonStatusReport,
    recommended_commands: Vec<CommandHint>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub(crate) struct AgentExecReport {
    schema: &'static str,
    base: String,
    daemon: DaemonStatusReport,
    execution: AgentExecExecution,
    delivery: AgentExecDelivery,
    recommended_commands: Vec<CommandHint>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
struct AgentExecExecution {
    workspace: String,
    workspace_path: String,
    actor: String,
    command: String,
    args: Vec<String>,
    exit_code: i32,
    stdout: AgentExecStream,
    stderr: AgentExecStream,
    output_root: String,
    resources: AgentExecResources,
    context: Option<WorkspaceRunContext>,
    started_at: u64,
    finished_at: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentExecStream {
    bytes: usize,
    cid: String,
    text: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentExecResources {
    wall_time_ms: u64,
    cpu_user_ms: u64,
    cpu_kernel_ms: u64,
    peak_memory: Option<u64>,
    fs_read_bytes: u64,
    fs_write_bytes: u64,
    process_count: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentExecDelivery {
    mode: &'static str,
    local_memory: bool,
    live_broadcast: bool,
    issue: &'static str,
    suggested_command: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentSendEvent {
    id: String,
    author: String,
    seq: u64,
    timestamp: u64,
    inserted: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentSendIntent {
    id: String,
    kind: &'static str,
    title: String,
    body: String,
    workspace: Option<String>,
    task_id: Option<String>,
    capability: Option<String>,
    tags: Vec<String>,
    expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentSendDelivery {
    mode: &'static str,
    local_memory: bool,
    live_broadcast: bool,
    issue: &'static str,
    suggested_command: Option<String>,
}

#[derive(Clone, Debug)]
struct AgentSendOptions {
    base: PathBuf,
    id: Option<String>,
    kind: IntentKind,
    title: Option<String>,
    body: String,
    workspace: Option<nexus_core::WorkspaceId>,
    task_id: Option<String>,
    capability: Option<String>,
    tags: Vec<String>,
    expires_at: Option<u64>,
    json: bool,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
struct AgentDiscoverSummary {
    cached_announcements: usize,
    workspaces: usize,
    verified: usize,
    clone_ready: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
struct AgentInboxAction {
    kind: String,
    event_hint: String,
    confidence: Option<f64>,
    command_hint: Option<String>,
}

pub(crate) async fn cmd_agent(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.get(2).map(String::as_str) {
        Some("status") | Some("context") => cmd_agent_status(args),
        Some("up") | Some("start") => cmd_agent_up(args),
        Some("inbox") => cmd_agent_inbox(args),
        Some("discover") => cmd_agent_discover(args),
        Some("send") => cmd_agent_send(args),
        Some("exec") | Some("run") => cmd_agent_exec(args).await,
        Some(other) => Err(format!("unknown agent subcommand: {other}").into()),
        None => Err("agent subcommand required: status, up, inbox, discover, send, or exec".into()),
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

fn cmd_agent_up(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = DaemonStartOptions {
        base: PathBuf::from("."),
        listen: "/ip4/0.0.0.0/udp/0/quic-v1".into(),
        bootstrap_peers: Vec::new(),
        use_public_bootstrap: true,
        json: false,
    };
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                options.base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--listen" => {
                i += 1;
                options.listen = required_arg(args, i, "--listen")?.to_string();
            }
            "--bootstrap" => {
                i += 1;
                options
                    .bootstrap_peers
                    .push(required_arg(args, i, "--bootstrap")?.parse()?);
            }
            "--invite" => {
                i += 1;
                extend_bootstrap_peers(
                    &mut options.bootstrap_peers,
                    required_arg(args, i, "--invite")?,
                )?;
            }
            "--no-public-bootstrap" => {
                options.use_public_bootstrap = false;
            }
            "--json" => {
                options.json = true;
            }
            other => return Err(format!("unknown agent up option: {other}").into()),
        }
        i += 1;
    }

    let json = options.json;
    let report = agent_up_report(&options)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_agent_up_text(&report);
    }
    Ok(())
}

fn cmd_agent_inbox(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut agent = None;
    let mut json = false;
    let mut limit = 20usize;
    let mut since = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--agent" | "--did" => {
                i += 1;
                agent = Some(Did::new(required_arg(args, i, "--agent")?.to_string()));
            }
            "--json" => {
                json = true;
            }
            "--limit" => {
                i += 1;
                limit = parse_usize_arg(required_arg(args, i, "--limit")?, "--limit")?;
            }
            "--since" => {
                i += 1;
                since = Some(parse_u64_arg(required_arg(args, i, "--since")?, "--since")?);
            }
            other => return Err(format!("unknown agent inbox option: {other}").into()),
        }
        i += 1;
    }

    let report = agent_inbox_report(&base, agent, limit, since);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_agent_inbox_text(&report);
    }
    Ok(())
}

fn cmd_agent_discover(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut json = false;
    let mut filter = DiscoveryFilter::default();
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
            "--sort" => {
                i += 1;
                filter.sort = parse_agent_discovery_sort(required_arg(args, i, "--sort")?)?;
            }
            "--verified" => {
                filter.verified_only = true;
            }
            "--clone-ready" => {
                filter.clone_ready_only = true;
            }
            "--workspace" => {
                i += 1;
                filter.workspace =
                    Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?.to_string());
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
            "--global"
            | "--online"
            | "--lan"
            | "--bootstrap"
            | "--invite"
            | "--listen"
            | "--timeout-ms"
            | "--no-public-bootstrap" => {
                return Err(format!(
                    "agent discover is cache-only; use `nexus-node discover {}` for network refresh",
                    args[i]
                )
                .into());
            }
            other => return Err(format!("unknown agent discover option: {other}").into()),
        }
        i += 1;
    }

    let report = agent_discover_report(&base, filter);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_agent_discover_text(&report);
    }
    Ok(())
}

fn cmd_agent_send(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = AgentSendOptions {
        base: PathBuf::from("."),
        id: None,
        kind: IntentKind::Status,
        title: None,
        body: String::new(),
        workspace: None,
        task_id: None,
        capability: None,
        tags: Vec::new(),
        expires_at: None,
        json: false,
    };
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                options.base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--id" | "--intent" => {
                i += 1;
                options.id = Some(required_arg(args, i, "--id")?.to_string());
            }
            "--kind" | "--type" => {
                i += 1;
                options.kind = parse_agent_intent_kind(required_arg(args, i, "--kind")?)?;
            }
            "--title" => {
                i += 1;
                options.title = Some(required_arg(args, i, "--title")?.to_string());
            }
            "--body" | "--message" | "--note" => {
                i += 1;
                options.body = required_arg(args, i, "--body")?.to_string();
            }
            "--workspace" => {
                i += 1;
                options.workspace =
                    Some(parse_workspace_id(required_arg(args, i, "--workspace")?)?);
            }
            "--task" | "--task-id" => {
                i += 1;
                options.task_id = Some(required_arg(args, i, "--task")?.to_string());
            }
            "--capability" | "--cap" => {
                i += 1;
                options.capability = Some(required_arg(args, i, "--capability")?.to_string());
            }
            "--tag" => {
                i += 1;
                options
                    .tags
                    .push(required_arg(args, i, "--tag")?.to_string());
            }
            "--expires-at" | "--expires" => {
                i += 1;
                options.expires_at = Some(parse_u64_arg(
                    required_arg(args, i, "--expires-at")?,
                    "--expires-at",
                )?);
            }
            "--json" => {
                options.json = true;
            }
            other => return Err(format!("unknown agent send option: {other}").into()),
        }
        i += 1;
    }

    let json = options.json;
    let report = agent_send_report(options)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_agent_send_text(&report);
    }
    Ok(())
}

async fn cmd_agent_exec(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (options, json) = parse_workspace_exec_options(args, 3, true)?;
    let report = agent_exec_report(options).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_agent_exec_text(&report);
    }
    Ok(())
}

pub(crate) fn agent_up_report(
    options: &DaemonStartOptions,
) -> Result<AgentUpReport, Box<dyn std::error::Error>> {
    let report = start_daemon(options)?;
    Ok(AgentUpReport {
        schema: "nexus.agent_up.v1",
        started: report.started,
        recommended_commands: up_recommended_commands(&options.base),
        status: report.status,
    })
}

pub(crate) async fn agent_exec_report(
    options: WorkspaceExecOptions,
) -> Result<AgentExecReport, Box<dyn std::error::Error>> {
    let base = options.base.clone();
    let report = run_workspace_exec(options).await?;
    Ok(agent_exec_report_from_workspace_report(&base, report))
}

fn agent_exec_report_from_workspace_report(
    base: &Path,
    report: WorkspaceExecReport,
) -> AgentExecReport {
    let daemon = daemon_status_report(base);
    let delivery = exec_delivery(base, &daemon);
    AgentExecReport {
        schema: "nexus.agent_exec.v1",
        base: base.display().to_string(),
        daemon,
        execution: AgentExecExecution {
            workspace: report.workspace.to_string(),
            workspace_path: report.workspace_path.display().to_string(),
            actor: report.actor.to_string(),
            command: report.command,
            args: report.args,
            exit_code: report.exit_code,
            stdout: agent_exec_stream(&report.stdout, &report.stdout_cid),
            stderr: agent_exec_stream(&report.stderr, &report.stderr_cid),
            output_root: hex::encode(report.output_root.as_bytes()),
            resources: agent_exec_resources(&report.resources),
            context: report.context,
            started_at: report.started_at,
            finished_at: report.finished_at,
        },
        delivery,
        recommended_commands: exec_recommended_commands(base),
    }
}

fn agent_send_report(
    options: AgentSendOptions,
) -> Result<AgentSendReport, Box<dyn std::error::Error>> {
    let now = unix_now();
    let title = options
        .title
        .or_else(|| title_from_body(&options.body))
        .ok_or("--title required")?;
    let identity = load_or_create_identity(&options.base)?;
    let memory_path = options.base.join(".nexus-social-memory.json");
    let mut memory = load_social_memory(&memory_path)?;
    let mut intent = AgentIntent::new(
        identity.did().clone(),
        options.kind,
        title.clone(),
        options.body.clone(),
        options.workspace,
        options.task_id.clone(),
        options.capability.clone(),
        options.tags.clone(),
        now,
        options.expires_at,
    );
    if let Some(id) = options.id {
        intent.id = id;
    }
    let event = memory.sign_event(
        &identity,
        now,
        SocialEventKind::IntentPublished {
            intent: intent.clone(),
        },
    )?;
    let inserted = memory.ingest_event(event.clone())?;
    if inserted {
        save_social_memory(&memory_path, &memory)?;
    }
    let daemon = daemon_status_report(&options.base);
    let delivery = send_delivery(&options.base, &daemon);

    Ok(AgentSendReport {
        schema: "nexus.agent_send.v1",
        base: options.base.display().to_string(),
        event: AgentSendEvent {
            id: event.id,
            author: event.author.to_string(),
            seq: event.seq,
            timestamp: event.timestamp,
            inserted,
        },
        intent: AgentSendIntent {
            id: intent.id,
            kind: intent_kind_name(intent.kind),
            title: intent.title,
            body: intent.body,
            workspace: intent.workspace.map(|workspace| workspace.to_string()),
            task_id: intent.task_id,
            capability: intent.capability,
            tags: intent.tags,
            expires_at: intent.expires_at,
        },
        delivery,
        daemon,
        recommended_commands: send_recommended_commands(&options.base),
    })
}

pub(crate) fn agent_status_report(base: &Path) -> AgentStatusReport {
    let daemon = daemon_status_report(base);
    let control_plane = control_plane_status(&daemon);
    AgentStatusReport {
        schema: "nexus.agent_status.v1",
        base: base.display().to_string(),
        identity: identity_status(base),
        social_memory: social_memory_status(base),
        local_workspaces: local_workspace_statuses(base),
        discovered_workspaces: discovered_workspace_statuses(base),
        daemon,
        control_plane,
        recommended_commands: recommended_commands(base),
    }
}

pub(crate) fn agent_discover_report(base: &Path, filter: DiscoveryFilter) -> AgentDiscoverReport {
    let daemon = daemon_status_report(base);
    let mode = if daemon.running {
        if daemon.ipc_available {
            "daemon_running_cache"
        } else {
            "daemon_running_no_ipc_cache"
        }
    } else {
        "local_cache"
    };

    let (cached_announcements, workspaces, error) = match load_workspace_discovery(base) {
        Ok(announcements) => {
            let cached_announcements = announcements.len();
            let workspaces = discovered_workspace_views(&announcements, &filter);
            (cached_announcements, workspaces, None)
        }
        Err(error) => (0, Vec::new(), Some(error.to_string())),
    };
    let summary = AgentDiscoverSummary {
        cached_announcements,
        workspaces: workspaces.len(),
        verified: workspaces
            .iter()
            .filter(|workspace| workspace.verified)
            .count(),
        clone_ready: workspaces
            .iter()
            .filter(|workspace| workspace.clone_ready)
            .count(),
    };

    AgentDiscoverReport {
        schema: "nexus.agent_discover.v1",
        base: base.display().to_string(),
        mode,
        daemon,
        summary,
        workspaces,
        error,
        recommended_commands: discover_recommended_commands(base),
    }
}

pub(crate) fn agent_inbox_report(
    base: &Path,
    requested_agent: Option<Did>,
    limit: usize,
    since: Option<u64>,
) -> AgentInboxReport {
    let generated_at = unix_now();
    let daemon = daemon_status_report(base);
    let resolved_agent = requested_agent.or_else(|| identity_status(base).did.map(Did::new));
    let mut items = Vec::new();

    push_daemon_inbox_items(base, &daemon, generated_at, &mut items);

    let memory_path = base.join(".nexus-social-memory.json");
    match load_social_memory(&memory_path) {
        Ok(memory) => {
            if let Some(agent) = resolved_agent.as_ref() {
                push_intent_recommendation_items(
                    base,
                    &memory,
                    agent,
                    limit,
                    generated_at,
                    &mut items,
                );
            }
            push_task_items(base, &memory, resolved_agent.as_ref(), &mut items);
        }
        Err(error) => items.push(AgentInboxItem {
            kind: "social_memory_error",
            priority: 85,
            title: "Social memory is unreadable".into(),
            body: Some(format!("{}: {error}", memory_path.display())),
            author: None,
            workspace: None,
            task_id: None,
            capability: None,
            timestamp: Some(generated_at),
            score: None,
            reasons: vec!["social-memory-read-error".into()],
            actions: Vec::new(),
            command_hint: Some(format!(
                "nexus-node agent status --base {} --json",
                base.display()
            )),
        }),
    }

    push_discovered_workspace_items(base, &mut items);

    if let Some(cursor) = since {
        items.retain(|item| item.timestamp.is_none_or(|timestamp| timestamp > cursor));
    }
    sort_inbox_items(&mut items);
    items.truncate(limit);

    let summary = summarize_inbox_items(&items);
    AgentInboxReport {
        schema: "nexus.agent_inbox.v1",
        base: base.display().to_string(),
        agent: resolved_agent.as_ref().map(ToString::to_string),
        generated_at,
        daemon,
        summary,
        items,
        recommended_commands: inbox_recommended_commands(base),
    }
}

fn parse_agent_intent_kind(value: &str) -> Result<IntentKind, Box<dyn std::error::Error>> {
    match normalize_symbol(value).as_str() {
        "goal" => Ok(IntentKind::Goal),
        "need" | "request" => Ok(IntentKind::Need),
        "offer" | "provide" => Ok(IntentKind::Offer),
        "proposal" | "propose" => Ok(IntentKind::Proposal),
        "status" | "state" => Ok(IntentKind::Status),
        other => Err(format!("unknown intent kind: {other}").into()),
    }
}

fn intent_kind_name(kind: IntentKind) -> &'static str {
    match kind {
        IntentKind::Goal => "goal",
        IntentKind::Need => "need",
        IntentKind::Offer => "offer",
        IntentKind::Proposal => "proposal",
        IntentKind::Status => "status",
    }
}

fn title_from_body(body: &str) -> Option<String> {
    let title = body
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::trim)
        .unwrap_or_default();
    if title.is_empty() {
        return None;
    }
    const MAX_TITLE_CHARS: usize = 80;
    let mut chars = title.chars();
    let truncated = chars.by_ref().take(MAX_TITLE_CHARS).collect::<String>();
    if chars.next().is_some() {
        Some(format!("{truncated}..."))
    } else {
        Some(truncated)
    }
}

fn send_delivery(base: &Path, daemon: &DaemonStatusReport) -> AgentSendDelivery {
    if daemon.running {
        AgentSendDelivery {
            mode: "local_memory_daemon_running",
            local_memory: true,
            live_broadcast: false,
            issue: "daemon send IPC is pending; the event is saved locally but not injected into the running daemon",
            suggested_command: Some(format!("nexus-node daemon status --base {} --json", base.display())),
        }
    } else {
        AgentSendDelivery {
            mode: "local_memory",
            local_memory: true,
            live_broadcast: false,
            issue: "daemon is not running; the event will be available for replay after the daemon or serve starts",
            suggested_command: Some(format!("nexus-node agent up --base {} --json", base.display())),
        }
    }
}

fn exec_delivery(base: &Path, daemon: &DaemonStatusReport) -> AgentExecDelivery {
    if daemon.running {
        AgentExecDelivery {
            mode: "local_exec_daemon_running",
            local_memory: true,
            live_broadcast: false,
            issue: "daemon exec IPC is pending; the command ran locally and recorded social memory outside the running daemon",
            suggested_command: Some(format!("nexus-node daemon status --base {} --json", base.display())),
        }
    } else {
        AgentExecDelivery {
            mode: "local_exec",
            local_memory: true,
            live_broadcast: false,
            issue: "daemon is not running; the command ran locally and will be available for replay after the daemon or serve starts",
            suggested_command: Some(format!(
                "nexus-node daemon start --base {} --listen /ip4/0.0.0.0/udp/0/quic-v1",
                base.display()
            )),
        }
    }
}

fn agent_exec_stream(bytes: &[u8], cid: &Cid) -> AgentExecStream {
    AgentExecStream {
        bytes: bytes.len(),
        cid: hex::encode(cid.as_bytes()),
        text: String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn agent_exec_resources(resources: &ResourceUsage) -> AgentExecResources {
    AgentExecResources {
        wall_time_ms: duration_millis(resources.wall_time),
        cpu_user_ms: duration_millis(resources.cpu_user),
        cpu_kernel_ms: duration_millis(resources.cpu_kernel),
        peak_memory: resources.peak_memory,
        fs_read_bytes: resources.fs_read_bytes,
        fs_write_bytes: resources.fs_write_bytes,
        process_count: resources.process_count,
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn control_plane_status(daemon: &DaemonStatusReport) -> ControlPlaneStatus {
    if daemon.running {
        ControlPlaneStatus {
            mode: "daemon_running",
            realtime_ready: true,
            daemon_supported: true,
            issue: "daemon is running; request-response IPC routing is still pending",
            next_design: "route agent inbox, sync, discover, send, and exec through the base-scoped daemon control socket",
        }
    } else {
        ControlPlaneStatus {
            mode: "daemon_supported_not_running",
            realtime_ready: false,
            daemon_supported: true,
            issue: "daemon is not running, so network serving still requires an explicit foreground or daemon start command",
            next_design: "start daemon for background network availability, then add request-response IPC routing",
        }
    }
}

fn parse_agent_discovery_sort(value: &str) -> Result<DiscoverySort, Box<dyn std::error::Error>> {
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

fn push_daemon_inbox_items(
    base: &Path,
    daemon: &DaemonStatusReport,
    generated_at: u64,
    items: &mut Vec<AgentInboxItem>,
) {
    if let Some(error) = &daemon.error {
        items.push(AgentInboxItem {
            kind: "daemon_alert",
            priority: 95,
            title: "Daemon state is unreadable".into(),
            body: Some(error.clone()),
            author: None,
            workspace: None,
            task_id: None,
            capability: None,
            timestamp: Some(generated_at),
            score: None,
            reasons: vec!["daemon-state-error".into()],
            actions: Vec::new(),
            command_hint: Some(format!(
                "nexus-node daemon status --base {} --json",
                base.display()
            )),
        });
        return;
    }

    if daemon.stale {
        items.push(AgentInboxItem {
            kind: "daemon_alert",
            priority: 90,
            title: "Daemon record is stale".into(),
            body: Some("The recorded daemon pid is no longer running.".into()),
            author: None,
            workspace: None,
            task_id: None,
            capability: None,
            timestamp: daemon.started_at.or(Some(generated_at)),
            score: None,
            reasons: vec!["stale-daemon-record".into()],
            actions: Vec::new(),
            command_hint: Some(format!("nexus-node daemon stop --base {}", base.display())),
        });
    } else if !daemon.running {
        items.push(AgentInboxItem {
            kind: "daemon_alert",
            priority: 70,
            title: "Daemon is not running".into(),
            body: Some(
                "Inbox is based on local caches; start the daemon for live P2P availability."
                    .into(),
            ),
            author: None,
            workspace: None,
            task_id: None,
            capability: None,
            timestamp: Some(generated_at),
            score: None,
            reasons: vec!["daemon-not-running".into()],
            actions: Vec::new(),
            command_hint: Some(format!(
                "nexus-node daemon start --base {} --listen /ip4/0.0.0.0/udp/0/quic-v1",
                base.display()
            )),
        });
    } else if !daemon.ipc_available {
        items.push(AgentInboxItem {
            kind: "daemon_alert",
            priority: 65,
            title: "Daemon IPC is not available".into(),
            body: Some(
                "The daemon appears to be running, but live control-socket status is unavailable."
                    .into(),
            ),
            author: None,
            workspace: None,
            task_id: None,
            capability: None,
            timestamp: daemon.started_at.or(Some(generated_at)),
            score: None,
            reasons: vec!["daemon-ipc-unavailable".into()],
            actions: Vec::new(),
            command_hint: Some(format!(
                "nexus-node daemon status --base {} --json",
                base.display()
            )),
        });
    }
}

fn push_intent_recommendation_items(
    base: &Path,
    memory: &SocialMemory,
    agent: &Did,
    limit: usize,
    now: u64,
    items: &mut Vec<AgentInboxItem>,
) {
    for recommendation in memory.society().recommend_intents(agent, Some(now), limit) {
        items.push(intent_recommendation_item(base, recommendation));
    }
}

fn intent_recommendation_item(base: &Path, recommendation: IntentRecommendation) -> AgentInboxItem {
    let IntentRecommendation {
        intent,
        ranking_score,
        reasons,
        actions,
        ..
    } = recommendation;
    let command_hint = actions
        .first()
        .map(|action| intent_action_command_hint(base, action))
        .or_else(|| {
            Some(format!(
                "nexus-node society --base {} --json --intent-limit 10",
                base.display()
            ))
        });
    let actions = actions
        .into_iter()
        .map(|action| AgentInboxAction {
            kind: intent_action_kind_name(action.kind).into(),
            event_hint: action.event_hint.clone(),
            confidence: Some(action.confidence),
            command_hint: Some(intent_action_command_hint(base, &action)),
        })
        .collect::<Vec<_>>();

    AgentInboxItem {
        kind: "intent_recommendation",
        priority: priority_from_score(55, 40, ranking_score),
        title: intent.title.clone(),
        body: non_empty_string(intent.body.clone()),
        author: Some(intent.author.to_string()),
        workspace: intent.workspace.map(|workspace| workspace.to_string()),
        task_id: intent.task_id,
        capability: intent.capability,
        timestamp: Some(intent.created_at),
        score: Some(ranking_score),
        reasons,
        actions,
        command_hint,
    }
}

fn push_task_items(
    base: &Path,
    memory: &SocialMemory,
    agent: Option<&Did>,
    items: &mut Vec<AgentInboxItem>,
) {
    let society = memory.society();
    for task in society.tasks() {
        if task.state == TaskState::InProgress
            && agent.is_some_and(|agent| task.assigned_to.as_ref() == Some(agent))
        {
            items.push(assigned_task_item(base, task));
            continue;
        }
        if task.is_open() {
            items.push(open_task_item(
                base,
                task,
                task_matches_agent_capability(memory, task, agent),
                agent,
            ));
        }
    }
}

fn open_task_item(
    base: &Path,
    task: &Task,
    capability_match: bool,
    agent: Option<&Did>,
) -> AgentInboxItem {
    let mut reasons = vec![
        "task-open".into(),
        format!("capability:{}", task.required_capability),
    ];
    if capability_match {
        reasons.push("matches-agent-capability".into());
    }
    if agent.is_some_and(|agent| task.publisher == *agent) {
        reasons.push("published-by-agent".into());
    }

    AgentInboxItem {
        kind: "open_task",
        priority: if capability_match { 76 } else { 58 },
        title: format!("Open task: {}", task.description),
        body: Some(
            format!("{} {}", task.command, task.args.join(" "))
                .trim()
                .to_string(),
        ),
        author: Some(task.publisher.to_string()),
        workspace: None,
        task_id: Some(task.id.clone()),
        capability: Some(task.required_capability.clone()),
        timestamp: Some(task.created_at),
        score: None,
        reasons,
        actions: Vec::new(),
        command_hint: Some(format!(
            "nexus-node society --base {} --json --task {}",
            base.display(),
            task.id
        )),
    }
}

fn assigned_task_item(base: &Path, task: &Task) -> AgentInboxItem {
    AgentInboxItem {
        kind: "assigned_task",
        priority: 88,
        title: format!("Assigned task in progress: {}", task.description),
        body: Some(
            format!("{} {}", task.command, task.args.join(" "))
                .trim()
                .to_string(),
        ),
        author: Some(task.publisher.to_string()),
        workspace: None,
        task_id: Some(task.id.clone()),
        capability: Some(task.required_capability.clone()),
        timestamp: Some(task.created_at),
        score: None,
        reasons: vec![
            "task-assigned-to-agent".into(),
            format!("capability:{}", task.required_capability),
        ],
        actions: Vec::new(),
        command_hint: Some(format!(
            "nexus-node society --base {} --json --task {}",
            base.display(),
            task.id
        )),
    }
}

fn task_matches_agent_capability(memory: &SocialMemory, task: &Task, agent: Option<&Did>) -> bool {
    let Some(agent) = agent else {
        return false;
    };
    memory
        .society()
        .agent_manifest(agent)
        .is_some_and(|manifest| {
            manifest
                .provides
                .iter()
                .any(|capability| capability.name == task.required_capability)
        })
}

fn push_discovered_workspace_items(base: &Path, items: &mut Vec<AgentInboxItem>) {
    let Ok(announcements) = load_workspace_discovery(base) else {
        return;
    };
    for workspace in discovered_workspace_views(&announcements, &DiscoveryFilter::default()) {
        if !workspace.clone_ready {
            continue;
        }
        items.push(AgentInboxItem {
            kind: "discovered_workspace",
            priority: 52,
            title: format!("Clone-ready workspace: {}", workspace.name),
            body: non_empty_string(workspace.description),
            author: Some(workspace.owner.to_string()),
            workspace: Some(workspace.workspace.clone()),
            task_id: None,
            capability: None,
            timestamp: Some(workspace.latest_timestamp),
            score: None,
            reasons: vec![
                "clone-ready".into(),
                "verified".into(),
                format!("peers:{}", workspace.peers.len()),
                format!("addrs:{}", workspace.addrs.len()),
            ],
            actions: Vec::new(),
            command_hint: Some(format!(
                "nexus-node discover --base {} --clone-ready --json --workspace {}",
                base.display(),
                workspace.workspace
            )),
        });
    }
}

fn send_recommended_commands(base: &Path) -> Vec<CommandHint> {
    let base = base.display();
    vec![
        CommandHint {
            name: "status",
            command: format!("nexus-node agent status --base {base} --json"),
        },
        CommandHint {
            name: "inbox",
            command: format!("nexus-node agent inbox --base {base} --json"),
        },
        CommandHint {
            name: "society",
            command: format!("nexus-node society --base {base} --json --intent-limit 10"),
        },
        CommandHint {
            name: "up",
            command: format!("nexus-node agent up --base {base} --json"),
        },
    ]
}

fn exec_recommended_commands(base: &Path) -> Vec<CommandHint> {
    let base = base.display();
    vec![
        CommandHint {
            name: "status",
            command: format!("nexus-node agent status --base {base} --json"),
        },
        CommandHint {
            name: "inbox",
            command: format!("nexus-node agent inbox --base {base} --json"),
        },
        CommandHint {
            name: "society",
            command: format!("nexus-node society --base {base} --json --intent-limit 10"),
        },
        CommandHint {
            name: "send_status",
            command: format!(
                "nexus-node agent send --base {base} --kind status --title <TEXT> --json"
            ),
        },
        CommandHint {
            name: "daemon_start",
            command: format!(
                "nexus-node daemon start --base {base} --listen /ip4/0.0.0.0/udp/0/quic-v1"
            ),
        },
    ]
}

fn up_recommended_commands(base: &Path) -> Vec<CommandHint> {
    let base = base.display();
    vec![
        CommandHint {
            name: "status",
            command: format!("nexus-node agent status --base {base} --json"),
        },
        CommandHint {
            name: "inbox",
            command: format!("nexus-node agent inbox --base {base} --json"),
        },
        CommandHint {
            name: "discover",
            command: format!("nexus-node agent discover --base {base} --json"),
        },
        CommandHint {
            name: "send_status",
            command: format!(
                "nexus-node agent send --base {base} --kind status --title <TEXT> --json"
            ),
        },
        CommandHint {
            name: "daemon_status",
            command: format!("nexus-node daemon status --base {base} --json"),
        },
        CommandHint {
            name: "daemon_stop",
            command: format!("nexus-node daemon stop --base {base} --json"),
        },
    ]
}

fn discover_recommended_commands(base: &Path) -> Vec<CommandHint> {
    let base = base.display();
    vec![
        CommandHint {
            name: "status",
            command: format!("nexus-node agent status --base {base} --json"),
        },
        CommandHint {
            name: "inbox",
            command: format!("nexus-node agent inbox --base {base} --json"),
        },
        CommandHint {
            name: "send_status",
            command: format!(
                "nexus-node agent send --base {base} --kind status --title <TEXT> --json"
            ),
        },
        CommandHint {
            name: "discover_cache",
            command: format!("nexus-node agent discover --base {base} --json"),
        },
        CommandHint {
            name: "discover_lan_refresh",
            command: format!("nexus-node discover --base {base} --lan --json --timeout-ms 3000"),
        },
        CommandHint {
            name: "daemon_start",
            command: format!(
                "nexus-node daemon start --base {base} --listen /ip4/0.0.0.0/udp/0/quic-v1"
            ),
        },
    ]
}

fn inbox_recommended_commands(base: &Path) -> Vec<CommandHint> {
    let base = base.display();
    vec![
        CommandHint {
            name: "status",
            command: format!("nexus-node agent status --base {base} --json"),
        },
        CommandHint {
            name: "inbox",
            command: format!("nexus-node agent inbox --base {base} --json"),
        },
        CommandHint {
            name: "send_status",
            command: format!(
                "nexus-node agent send --base {base} --kind status --title <TEXT> --json"
            ),
        },
        CommandHint {
            name: "society",
            command: format!("nexus-node society --base {base} --json --intent-limit 10"),
        },
        CommandHint {
            name: "discover_ready",
            command: format!("nexus-node discover --base {base} --clone-ready --json"),
        },
        CommandHint {
            name: "daemon_start",
            command: format!(
                "nexus-node daemon start --base {base} --listen /ip4/0.0.0.0/udp/0/quic-v1"
            ),
        },
    ]
}

fn sort_inbox_items(items: &mut [AgentInboxItem]) {
    items.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| b.timestamp.unwrap_or(0).cmp(&a.timestamp.unwrap_or(0)))
            .then_with(|| a.kind.cmp(b.kind))
            .then_with(|| a.title.cmp(&b.title))
    });
}

fn summarize_inbox_items(items: &[AgentInboxItem]) -> AgentInboxSummary {
    let mut summary = AgentInboxSummary {
        items: items.len(),
        ..Default::default()
    };
    for item in items {
        match item.kind {
            "daemon_alert" => summary.daemon_alerts += 1,
            "intent_recommendation" => summary.intent_recommendations += 1,
            "open_task" => summary.open_tasks += 1,
            "assigned_task" => summary.assigned_tasks += 1,
            "discovered_workspace" => summary.discovered_workspaces += 1,
            _ => {}
        }
    }
    summary
}

fn priority_from_score(base: u32, weight: u32, score: f64) -> u32 {
    let normalized = if score.is_finite() {
        score.clamp(0.0, 1.0)
    } else {
        0.0
    };
    base + (weight as f64 * normalized).round() as u32
}

fn non_empty_string(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn intent_action_kind_name(kind: IntentActionKind) -> &'static str {
    match kind {
        IntentActionKind::RespondIntent => "RespondIntent",
        IntentActionKind::OfferTask => "OfferTask",
        IntentActionKind::JoinWorkspace => "JoinWorkspace",
        IntentActionKind::ProposeCollective => "ProposeCollective",
    }
}

fn intent_action_kind_arg(kind: IntentActionKind) -> &'static str {
    match kind {
        IntentActionKind::RespondIntent => "respond-intent",
        IntentActionKind::OfferTask => "offer-task",
        IntentActionKind::JoinWorkspace => "join-workspace",
        IntentActionKind::ProposeCollective => "propose-collective",
    }
}

fn intent_action_command_hint(base: &Path, action: &IntentActionPlan) -> String {
    let mut command = format!(
        "nexus-node act --base {} --intent {} --kind {}",
        base.display(),
        action.intent_id,
        intent_action_kind_arg(action.kind)
    );
    if let Some(price) = action.suggested_price {
        command.push_str(&format!(" --price {price}"));
    }
    if let Some(eta) = action.estimated_time_secs {
        command.push_str(&format!(" --eta {eta}"));
    }
    command
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
            name: "daemon_start",
            command: format!(
                "nexus-node daemon start --base {base} --listen /ip4/0.0.0.0/udp/0/quic-v1"
            ),
        },
        CommandHint {
            name: "daemon_status",
            command: format!("nexus-node daemon status --base {base} --json"),
        },
        CommandHint {
            name: "send_status",
            command: format!(
                "nexus-node agent send --base {base} --kind status --title <TEXT> --json"
            ),
        },
        CommandHint {
            name: "exec",
            command: format!(
                "nexus-node agent exec --base {base} --workspace <PATH> --json -- <CMD> [ARG...]"
            ),
        },
        CommandHint {
            name: "serve_foreground",
            command: format!("nexus-node serve --base {base} --listen /ip4/0.0.0.0/udp/0/quic-v1"),
        },
    ]
}

fn print_agent_exec_text(report: &AgentExecReport) {
    print!("{}", report.execution.stdout.text);
    eprint!("{}", report.execution.stderr.text);
    println!(
        "\nAgent exec: workspace={} root={} exit={}",
        report.execution.workspace, report.execution.output_root, report.execution.exit_code
    );
    println!("workspace_path: {}", report.execution.workspace_path);
    println!(
        "daemon: running={} ipc_available={}",
        report.daemon.running, report.daemon.ipc_available
    );
    println!(
        "delivery: mode={} local_memory={} live_broadcast={}",
        report.delivery.mode, report.delivery.local_memory, report.delivery.live_broadcast
    );
    println!("issue: {}", report.delivery.issue);
    if let Some(command) = &report.delivery.suggested_command {
        println!("suggested: {command}");
    }
    println!("recommended:");
    for hint in &report.recommended_commands {
        println!("  {}: {}", hint.name, hint.command);
    }
}

fn print_agent_send_text(report: &AgentSendReport) {
    println!("Agent send: {}", report.base);
    println!(
        "event: {} author={} seq={} inserted={}",
        report.event.id, report.event.author, report.event.seq, report.event.inserted
    );
    println!(
        "intent: {} kind={} title={}",
        report.intent.id, report.intent.kind, report.intent.title
    );
    println!(
        "delivery: mode={} local_memory={} live_broadcast={}",
        report.delivery.mode, report.delivery.local_memory, report.delivery.live_broadcast
    );
    println!("issue: {}", report.delivery.issue);
    if let Some(command) = &report.delivery.suggested_command {
        println!("suggested: {command}");
    }
    println!("recommended:");
    for hint in &report.recommended_commands {
        println!("  {}: {}", hint.name, hint.command);
    }
}

fn print_agent_up_text(report: &AgentUpReport) {
    println!("Agent up: {}", report.status.base);
    println!("started: {}", report.started);
    println!(
        "daemon: running={} ipc_available={} pid={}",
        report.status.running,
        report.status.ipc_available,
        report
            .status
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".into())
    );
    println!("listen: {}", report.status.listen.as_deref().unwrap_or("-"));
    if let Some(error) = &report.status.error {
        println!("error: {error}");
    }
    println!("recommended:");
    for hint in &report.recommended_commands {
        println!("  {}: {}", hint.name, hint.command);
    }
}

fn print_agent_discover_text(report: &AgentDiscoverReport) {
    println!("Agent discover: {}", report.base);
    println!("mode: {}", report.mode);
    println!(
        "daemon: running={} ipc_available={}",
        report.daemon.running, report.daemon.ipc_available
    );
    println!(
        "workspaces: {} verified={} clone_ready={} cached_announcements={}",
        report.summary.workspaces,
        report.summary.verified,
        report.summary.clone_ready,
        report.summary.cached_announcements
    );
    if let Some(error) = &report.error {
        println!("error: {error}");
    }
    for workspace in &report.workspaces {
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
    println!("recommended:");
    for hint in &report.recommended_commands {
        println!("  {}: {}", hint.name, hint.command);
    }
}

fn print_agent_inbox_text(report: &AgentInboxReport) {
    println!("Agent inbox: {}", report.base);
    println!("agent: {}", report.agent.as_deref().unwrap_or("-"));
    println!("generated_at: {}", report.generated_at);
    println!(
        "daemon: running={} ipc_available={}",
        report.daemon.running, report.daemon.ipc_available
    );
    println!(
        "items: {} daemon_alerts={} intents={} open_tasks={} assigned_tasks={} discovered_workspaces={}",
        report.summary.items,
        report.summary.daemon_alerts,
        report.summary.intent_recommendations,
        report.summary.open_tasks,
        report.summary.assigned_tasks,
        report.summary.discovered_workspaces
    );
    for item in &report.items {
        println!("  [{} p{}] {}", item.kind, item.priority, item.title);
        if let Some(body) = &item.body {
            println!("    {body}");
        }
        if !item.reasons.is_empty() {
            println!("    reasons: {}", item.reasons.join(", "));
        }
        if let Some(command) = &item.command_hint {
            println!("    command: {command}");
        }
    }
    println!("recommended:");
    for hint in &report.recommended_commands {
        println!("  {}: {}", hint.name, hint.command);
    }
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
    println!(
        "daemon: running={} pid={}",
        report.daemon.running,
        report
            .daemon
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".into())
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
    use crate::discovery::{
        record_workspace_announcement, sign_workspace_announcement, WorkspaceAnnouncement,
        WORKSPACE_ANNOUNCEMENT_VERSION,
    };
    use crate::social_sync::save_social_memory;
    use nexus_agent::{
        AgentIntent, AgentManifest, CapabilityDecl, IntentKind, SocialEventKind, TaskAcceptance,
        TaskOffer, TaskSpec,
    };
    use nexus_core::WorkspaceId;
    use nexus_crypto::NodeIdentity;
    use nexus_workspace::{Workspace, WorkspaceConfig};

    #[test]
    fn status_does_not_create_identity() {
        let temp = tempfile::TempDir::new().unwrap();

        let report = agent_status_report(temp.path());

        assert!(!report.identity.present);
        assert!(!identity_path(temp.path()).exists());
        assert_eq!(report.control_plane.mode, "daemon_supported_not_running");
        assert!(!report.daemon.running);
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

    #[test]
    fn inbox_does_not_create_identity() {
        let temp = tempfile::TempDir::new().unwrap();

        let report = agent_inbox_report(temp.path(), None, 10, None);

        assert!(report.agent.is_none());
        assert!(!identity_path(temp.path()).exists());
        assert_eq!(report.summary.daemon_alerts, 1);
        assert!(report.items.iter().any(|item| {
            item.kind == "daemon_alert"
                && item
                    .command_hint
                    .as_deref()
                    .is_some_and(|command| command.contains("nexus-node daemon start"))
        }));
    }

    #[test]
    fn inbox_recommends_intents_and_open_tasks_for_agent() {
        let temp = tempfile::TempDir::new().unwrap();
        let requester = NodeIdentity::generate();
        let author = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([71; 32]);
        let memory_path = temp.path().join(".nexus-social-memory.json");
        let mut memory = SocialMemory::new();

        let requester_events = memory
            .sign_event_sequence(
                &requester,
                [
                    (
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
                    ),
                    (2, SocialEventKind::WorkspaceJoined { workspace }),
                ],
            )
            .unwrap();
        assert_eq!(memory.ingest_events(requester_events).unwrap(), 2);

        let task = TaskSpec::new(
            author.did().clone(),
            "inspect a shared workspace",
            "code-review",
            "nexus-node",
            vec!["society".into(), "--json".into()],
            100,
            4_102_444_800,
            4,
        );
        let task_id = task.id.clone();
        let author_events = memory
            .sign_event_sequence(
                &author,
                [
                    (
                        3,
                        SocialEventKind::IntentPublished {
                            intent: AgentIntent {
                                id: "intent-review-open".into(),
                                author: author.did().clone(),
                                kind: IntentKind::Need,
                                title: "Need reviewer".into(),
                                body: "inspect this AI workspace".into(),
                                workspace: Some(workspace),
                                task_id: Some(task_id.clone()),
                                capability: Some("code-review".into()),
                                tags: vec!["high-autonomy".into()],
                                created_at: 3,
                                expires_at: Some(4_102_444_800),
                            },
                        },
                    ),
                    (4, SocialEventKind::TaskPublished { task }),
                ],
            )
            .unwrap();
        assert_eq!(memory.ingest_events(author_events).unwrap(), 2);
        save_social_memory(&memory_path, &memory).unwrap();

        let report = agent_inbox_report(temp.path(), Some(requester.did().clone()), 10, None);

        assert_eq!(report.agent.as_deref(), Some(requester.did().as_str()));
        assert_eq!(report.summary.intent_recommendations, 1);
        assert_eq!(report.summary.open_tasks, 1);
        let intent_item = report
            .items
            .iter()
            .find(|item| item.kind == "intent_recommendation")
            .unwrap();
        assert_eq!(intent_item.task_id.as_deref(), Some(task_id.as_str()));
        assert!(intent_item
            .reasons
            .contains(&"capability:code-review".into()));
        assert!(intent_item.actions.iter().any(|action| {
            action.kind == "RespondIntent"
                && action.command_hint.as_deref().is_some_and(|command| {
                    command.contains("nexus-node act") && command.contains("--kind respond-intent")
                })
        }));
        let task_item = report
            .items
            .iter()
            .find(|item| item.kind == "open_task")
            .unwrap();
        assert_eq!(task_item.task_id.as_deref(), Some(task_id.as_str()));
        assert!(task_item
            .reasons
            .contains(&"matches-agent-capability".into()));
    }

    #[test]
    fn inbox_reports_assigned_tasks_for_agent() {
        let temp = tempfile::TempDir::new().unwrap();
        let publisher = NodeIdentity::generate();
        let worker = NodeIdentity::generate();
        let memory_path = temp.path().join(".nexus-social-memory.json");
        let mut memory = SocialMemory::new();

        let task = TaskSpec::new(
            publisher.did().clone(),
            "finish accepted task",
            "native-workspace",
            "true",
            Vec::new(),
            10,
            4_102_444_800,
            1,
        );
        let task_id = task.id.clone();
        let published = memory
            .sign_event(&publisher, 1, SocialEventKind::TaskPublished { task })
            .unwrap();
        assert!(memory.ingest_event(published).unwrap());
        let offered = memory
            .sign_event(
                &worker,
                2,
                SocialEventKind::TaskOffered {
                    offer: TaskOffer {
                        task_id: task_id.clone(),
                        bidder: worker.did().clone(),
                        price: 7,
                        estimated_time_secs: 60,
                        rationale: "ready".into(),
                    },
                },
            )
            .unwrap();
        assert!(memory.ingest_event(offered).unwrap());
        let accepted = memory
            .sign_event(
                &publisher,
                3,
                SocialEventKind::TaskAccepted {
                    acceptance: TaskAcceptance {
                        task_id: task_id.clone(),
                        publisher: publisher.did().clone(),
                        bidder: worker.did().clone(),
                        price: 7,
                        accepted_at: 3,
                    },
                },
            )
            .unwrap();
        assert!(memory.ingest_event(accepted).unwrap());
        save_social_memory(&memory_path, &memory).unwrap();

        let report = agent_inbox_report(temp.path(), Some(worker.did().clone()), 10, None);

        assert_eq!(report.summary.assigned_tasks, 1);
        let item = report
            .items
            .iter()
            .find(|item| item.kind == "assigned_task")
            .unwrap();
        assert_eq!(item.task_id.as_deref(), Some(task_id.as_str()));
    }

    #[test]
    fn discover_reads_cached_clone_ready_workspaces() {
        let temp = tempfile::TempDir::new().unwrap();
        let owner = NodeIdentity::generate();
        let peer = nexus_network::to_peer_id(&owner);
        let workspace = WorkspaceId::from_bytes([72; 32]);
        let announcement = WorkspaceAnnouncement {
            version: WORKSPACE_ANNOUNCEMENT_VERSION,
            peer: peer.to_string(),
            addrs: vec!["/ip4/127.0.0.1/udp/1234/quic-v1".into()],
            author: owner.did().clone(),
            workspace: workspace.to_string(),
            name: "cached workspace".into(),
            description: "ready for clone".into(),
            owner: owner.did().clone(),
            root: None,
            timestamp: 10,
            signature: None,
        };
        let signed = sign_workspace_announcement(announcement, &owner).unwrap();
        assert!(record_workspace_announcement(temp.path(), signed).unwrap());

        let report = agent_discover_report(
            temp.path(),
            DiscoveryFilter {
                clone_ready_only: true,
                ..Default::default()
            },
        );

        assert_eq!(report.schema, "nexus.agent_discover.v1");
        assert_eq!(report.mode, "local_cache");
        assert_eq!(report.summary.cached_announcements, 1);
        assert_eq!(report.summary.workspaces, 1);
        assert_eq!(report.summary.verified, 1);
        assert_eq!(report.summary.clone_ready, 1);
        assert_eq!(report.workspaces[0].workspace, workspace.to_string());
        assert!(report.workspaces[0].clone_ready);
        assert!(!identity_path(temp.path()).exists());
    }

    #[test]
    fn up_reports_existing_daemon_without_creating_identity() {
        let temp = tempfile::TempDir::new().unwrap();
        let daemon_dir = temp.path().join(".nexus");
        std::fs::create_dir_all(&daemon_dir).unwrap();
        std::fs::write(
            daemon_dir.join("daemon.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 2,
                "base": temp.path().display().to_string(),
                "pid": std::process::id(),
                "started_at": 123,
                "listen": "/ip4/127.0.0.1/udp/0/quic-v1",
                "public_defaults_enabled": false,
                "bootstrap_peers": [],
                "stdout_log": "stdout.log",
                "stderr_log": "stderr.log",
                "control_socket": null,
                "command": ["nexus-node", "serve"]
            }))
            .unwrap(),
        )
        .unwrap();
        let options = DaemonStartOptions {
            base: temp.path().to_path_buf(),
            listen: "/ip4/0.0.0.0/udp/0/quic-v1".into(),
            bootstrap_peers: Vec::new(),
            use_public_bootstrap: true,
            json: true,
        };

        let report = agent_up_report(&options).unwrap();

        assert_eq!(report.schema, "nexus.agent_up.v1");
        assert!(!report.started);
        assert!(report.status.running);
        assert_eq!(report.status.pid, Some(std::process::id()));
        assert!(!identity_path(temp.path()).exists());
    }

    #[test]
    fn send_records_signed_status_intent() {
        let temp = tempfile::TempDir::new().unwrap();

        let report = agent_send_report(AgentSendOptions {
            base: temp.path().to_path_buf(),
            id: Some("intent-agent-send-status".into()),
            kind: IntentKind::Status,
            title: Some("Agent status update".into()),
            body: "ready for collaboration".into(),
            workspace: None,
            task_id: None,
            capability: Some("native-workspace".into()),
            tags: vec!["agent-send".into()],
            expires_at: None,
            json: true,
        })
        .unwrap();

        assert_eq!(report.schema, "nexus.agent_send.v1");
        assert_eq!(report.intent.id, "intent-agent-send-status");
        assert_eq!(report.intent.kind, "status");
        assert!(report.event.inserted);
        assert_eq!(report.delivery.mode, "local_memory");
        assert!(!report.delivery.live_broadcast);

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 1);
        memory.events()[0].verify_signature().unwrap();
        let author = Did::new(report.event.author.clone());
        let intents = memory.society().agent_intents(&author);
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].id, "intent-agent-send-status");
        assert_eq!(intents[0].title, "Agent status update");
        assert_eq!(intents[0].capability.as_deref(), Some("native-workspace"));
    }

    #[test]
    fn send_can_derive_title_from_body() {
        let temp = tempfile::TempDir::new().unwrap();

        let report = agent_send_report(AgentSendOptions {
            base: temp.path().to_path_buf(),
            id: None,
            kind: IntentKind::Need,
            title: None,
            body: "Need a reviewer\nwith workspace context".into(),
            workspace: None,
            task_id: Some("task-send-title".into()),
            capability: Some("code-review".into()),
            tags: Vec::new(),
            expires_at: Some(4_102_444_800),
            json: true,
        })
        .unwrap();

        assert_eq!(report.intent.kind, "need");
        assert_eq!(report.intent.title, "Need a reviewer");
        assert_eq!(report.intent.task_id.as_deref(), Some("task-send-title"));
        assert_eq!(report.intent.capability.as_deref(), Some("code-review"));
        assert_eq!(report.intent.expires_at, Some(4_102_444_800));
    }

    #[tokio::test]
    async fn exec_runs_workspace_and_reports_output() {
        let temp = tempfile::TempDir::new().unwrap();
        let identity = load_or_create_identity(temp.path()).unwrap();
        let mut workspace = Workspace::create(
            &identity,
            temp.path(),
            WorkspaceConfig {
                name: "agent-exec-ws".into(),
                description: "agent exec smoke".into(),
            },
        )
        .await
        .unwrap();
        workspace.write_file("input.txt", b"hello").unwrap();
        workspace.snapshot().await.unwrap();
        let workspace_path = workspace.root_dir().to_path_buf();

        let args = vec![
            "nexus-node".into(),
            "agent".into(),
            "exec".into(),
            "--base".into(),
            temp.path().to_string_lossy().to_string(),
            "--workspace".into(),
            workspace_path.to_string_lossy().to_string(),
            "--note".into(),
            "agent exec test".into(),
            "--json".into(),
            "--".into(),
            "sh".into(),
            "-c".into(),
            "cat input.txt > output.txt && printf agent-output".into(),
        ];
        let (options, json) = parse_workspace_exec_options(&args, 3, true).unwrap();
        assert!(json);

        let report = agent_exec_report(options).await.unwrap();

        assert_eq!(report.schema, "nexus.agent_exec.v1");
        assert_eq!(report.execution.actor, identity.did().to_string());
        assert_eq!(report.execution.command, "sh");
        assert_eq!(report.execution.exit_code, 0);
        assert_eq!(report.execution.stdout.text, "agent-output");
        assert_eq!(report.delivery.mode, "local_exec");
        assert!(!report.delivery.live_broadcast);
        assert_eq!(
            std::fs::read(workspace_path.join("output.txt")).unwrap(),
            b"hello"
        );

        let memory = load_social_memory(&temp.path().join(".nexus-social-memory.json")).unwrap();
        assert_eq!(memory.event_count(), 2);
        memory.events()[0].verify_signature().unwrap();
        memory.events()[1].verify_signature().unwrap();
    }
}
