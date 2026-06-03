use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
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
use crate::daemon::{
    daemon_agent_discover, daemon_agent_send, daemon_agent_sync, daemon_events_report,
    daemon_status_report, start_daemon, DaemonAgentSendRequest, DaemonAgentSendResponse,
    DaemonEvent, DaemonEventJournal, DaemonEventsReport, DaemonStartOptions, DaemonStatusReport,
};
#[cfg(test)]
use crate::daemon::{spawn_serve_control_socket, DaemonEventJournalHandle};
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

const DEFAULT_AGENT_WATCH_INTERVAL: Duration = Duration::from_millis(1000);

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
    error: Option<AgentIssue>,
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
    error: Option<AgentIssue>,
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
    error: Option<AgentIssue>,
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
    issue: AgentIssue,
    next_design: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct CommandHint {
    name: &'static str,
    command: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentIssue {
    kind: &'static str,
    message: String,
    suggested_command: Option<String>,
}

fn agent_issue(
    kind: &'static str,
    message: impl Into<String>,
    suggested_command: Option<String>,
) -> AgentIssue {
    AgentIssue {
        kind,
        message: message.into(),
        suggested_command,
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub(crate) struct AgentInboxReport {
    schema: &'static str,
    base: String,
    agent: Option<String>,
    generated_at: u64,
    daemon: DaemonStatusReport,
    daemon_events: DaemonEventsReport,
    discovery_source: &'static str,
    summary: AgentInboxSummary,
    items: Vec<AgentInboxItem>,
    recommended_commands: Vec<CommandHint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AgentWatchOptions {
    base: PathBuf,
    since: Option<u64>,
    limit: usize,
    interval: Duration,
    json: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentWatchEvent {
    schema: &'static str,
    base: String,
    generated_at: u64,
    cursor: u64,
    kind: &'static str,
    daemon_event: Option<DaemonEvent>,
    error: Option<AgentIssue>,
    command_hint: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
struct AgentInboxSummary {
    items: usize,
    daemon_alerts: usize,
    daemon_events: usize,
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
    error: Option<AgentIssue>,
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
pub(crate) struct AgentSyncReport {
    schema: &'static str,
    base: String,
    mode: &'static str,
    daemon: DaemonStatusReport,
    filter: AgentSyncFilter,
    summary: AgentSyncSummary,
    targets: Vec<AgentSyncTarget>,
    error: Option<AgentIssue>,
    issue: AgentIssue,
    recommended_commands: Vec<CommandHint>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentSyncFilter {
    workspace: Option<String>,
    name: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
struct AgentSyncSummary {
    targets: usize,
    local_workspaces: usize,
    discovered_workspaces: usize,
    clone_ready: usize,
    clone_suggestions: usize,
    refresh_suggestions: usize,
    local_only: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentSyncTarget {
    workspace: String,
    name: Option<String>,
    status: &'static str,
    action: &'static str,
    local: Option<AgentSyncLocal>,
    discovered: Option<AgentSyncDiscovered>,
    reasons: Vec<String>,
    command_hint: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentSyncLocal {
    path: String,
    present: bool,
    latest_root: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct AgentSyncDiscovered {
    owner: String,
    root: Option<String>,
    verified: bool,
    clone_ready: bool,
    peers: usize,
    addrs: usize,
    latest_timestamp: u64,
    forked: bool,
    fork_roots: Vec<String>,
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
    issue: AgentIssue,
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
    kind: String,
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
    issue: AgentIssue,
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
        Some("watch") => cmd_agent_watch(args),
        Some("discover") => cmd_agent_discover(args),
        Some("send") => cmd_agent_send(args),
        Some("exec") | Some("run") => cmd_agent_exec(args).await,
        Some("sync") => cmd_agent_sync(args),
        Some(other) => Err(format!("unknown agent subcommand: {other}").into()),
        None => Err(
            "agent subcommand required: status, up, inbox, watch, discover, send, exec, or sync"
                .into(),
        ),
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

fn cmd_agent_watch(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_agent_watch_options(args)?;
    run_agent_watch(&options)
}

fn parse_agent_watch_options(
    args: &[String],
) -> Result<AgentWatchOptions, Box<dyn std::error::Error>> {
    let mut options = AgentWatchOptions {
        base: PathBuf::from("."),
        since: None,
        limit: 50,
        interval: DEFAULT_AGENT_WATCH_INTERVAL,
        json: false,
    };
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                options.base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--json" => {
                options.json = true;
            }
            "--since" => {
                i += 1;
                options.since = Some(parse_u64_arg(required_arg(args, i, "--since")?, "--since")?);
            }
            "--limit" => {
                i += 1;
                options.limit = parse_positive_usize_arg(required_arg(args, i, "--limit")?)?;
            }
            "--interval-ms" => {
                i += 1;
                options.interval = Duration::from_millis(parse_positive_u64_arg(
                    required_arg(args, i, "--interval-ms")?,
                    "--interval-ms",
                )?);
            }
            other => return Err(format!("unknown agent watch option: {other}").into()),
        }
        i += 1;
    }
    Ok(options)
}

fn parse_positive_usize_arg(value: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let value = parse_usize_arg(value, "--limit")?;
    if value == 0 {
        return Err("--limit must be greater than 0".into());
    }
    Ok(value)
}

fn parse_positive_u64_arg(value: &str, flag: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let value = parse_u64_arg(value, flag)?;
    if value == 0 {
        return Err(format!("{flag} must be greater than 0").into());
    }
    Ok(value)
}

fn run_agent_watch(options: &AgentWatchOptions) -> Result<(), Box<dyn std::error::Error>> {
    let mut cursor = options.since;
    let mut last_error = None;
    let mut stdout = io::stdout();
    loop {
        let report = daemon_events_report(&options.base, cursor, Some(options.limit));
        for event in &report.journal.events {
            let watch_event = agent_watch_daemon_event(&options.base, event);
            write_agent_watch_event(&mut stdout, &watch_event, options.json)?;
            cursor = Some(event.sequence);
        }

        if let Some(error) = report.error.clone() {
            if last_error.as_deref() != Some(error.as_str()) {
                let watch_event = agent_watch_error_event(
                    &options.base,
                    cursor.unwrap_or(report.journal.cursor),
                    error,
                );
                write_agent_watch_event(&mut stdout, &watch_event, options.json)?;
                last_error = watch_event
                    .error
                    .as_ref()
                    .map(|issue| issue.message.clone());
            }
        } else {
            last_error = None;
            cursor = Some(report.journal.cursor);
        }
        stdout.flush()?;
        thread::sleep(options.interval);
    }
}

fn agent_watch_daemon_event(base: &Path, event: &DaemonEvent) -> AgentWatchEvent {
    AgentWatchEvent {
        schema: "nexus.agent_watch_event.v1",
        base: base.display().to_string(),
        generated_at: unix_now(),
        cursor: event.sequence,
        kind: "daemon_event",
        daemon_event: Some(event.clone()),
        error: None,
        command_hint: Some(format!(
            "nexus-node agent inbox --base {} --since {} --json",
            base.display(),
            event.sequence
        )),
    }
}

fn agent_watch_error_event(base: &Path, cursor: u64, error: String) -> AgentWatchEvent {
    AgentWatchEvent {
        schema: "nexus.agent_watch_event.v1",
        base: base.display().to_string(),
        generated_at: unix_now(),
        cursor,
        kind: "watch_error",
        daemon_event: None,
        error: Some(agent_issue(
            "daemon_events_unavailable",
            error,
            Some(format!(
                "nexus-node agent up --base {} --listen /ip4/0.0.0.0/udp/0/quic-v1 --json",
                base.display()
            )),
        )),
        command_hint: Some(format!(
            "nexus-node agent up --base {} --listen /ip4/0.0.0.0/udp/0/quic-v1 --json",
            base.display()
        )),
    }
}

fn write_agent_watch_event(
    writer: &mut impl Write,
    event: &AgentWatchEvent,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if json {
        writeln!(writer, "{}", serde_json::to_string(event)?)?;
        return Ok(());
    }

    if let Some(daemon_event) = &event.daemon_event {
        writeln!(
            writer,
            "#{} {} {} {}",
            daemon_event.sequence, daemon_event.timestamp, daemon_event.kind, daemon_event.summary
        )?;
    } else if let Some(error) = &event.error {
        writeln!(
            writer,
            "watch_error cursor={} {}",
            event.cursor, error.message
        )?;
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

fn cmd_agent_sync(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut json = false;
    let mut workspace = None;
    let mut name = None;
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
            "--name" | "--local-name" => {
                i += 1;
                name = Some(required_arg(args, i, "--name")?.to_string());
            }
            "--json" => {
                json = true;
            }
            "--global" | "--online" | "--lan" | "--bootstrap" | "--invite" | "--listen"
            | "--timeout-ms" | "--peer" | "--apply" => {
                return Err(format!(
                    "agent sync is cache-backed for now; use `nexus-node clone {}` or `nexus-node discover {}` for explicit network work",
                    args[i], args[i]
                )
                .into());
            }
            other => return Err(format!("unknown agent sync option: {other}").into()),
        }
        i += 1;
    }

    let report = agent_sync_report(&base, workspace.map(|id| id.to_string()), name);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_agent_sync_text(&report);
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

pub(crate) fn agent_sync_report(
    base: &Path,
    workspace_filter: Option<String>,
    name: Option<String>,
) -> AgentSyncReport {
    let mut daemon = daemon_status_report(base);
    let mut mode = sync_mode(&daemon);
    let locals = local_workspace_statuses(base);
    let discovery_filter = DiscoveryFilter {
        workspace: workspace_filter.clone(),
        ..Default::default()
    };
    let (discovered, error) = if daemon.running && daemon.ipc_available {
        match daemon_agent_sync(base, discovery_filter.clone()) {
            Ok(response) => {
                daemon = response.status;
                mode = "daemon_ipc_local_plan";
                (
                    response.workspaces,
                    response.error.map(|error| {
                        agent_issue(
                            "daemon_sync_error",
                            error,
                            Some(format!(
                                "nexus-node daemon status --base {} --json",
                                base.display()
                            )),
                        )
                    }),
                )
            }
            Err(error) => {
                mode = "daemon_ipc_error_local_plan";
                let (discovered, cache_error) =
                    local_sync_discovered_workspaces(base, &discovery_filter);
                (
                    discovered,
                    cache_error.or_else(|| {
                        Some(agent_issue(
                            "daemon_sync_ipc_error",
                            error.to_string(),
                            Some(format!(
                                "nexus-node daemon status --base {} --json",
                                base.display()
                            )),
                        ))
                    }),
                )
            }
        }
    } else {
        local_sync_discovered_workspaces(base, &discovery_filter)
    };

    let mut targets = Vec::new();
    for workspace in discovered {
        if let Some(filter) = &workspace_filter {
            if &workspace.workspace != filter {
                continue;
            }
        }
        let local = find_local_workspace(&locals, &workspace.workspace);
        targets.push(sync_target_from_discovered(
            base,
            local,
            workspace,
            name.as_deref(),
        ));
    }
    for local in &locals {
        let Some(id) = local.id.as_deref() else {
            continue;
        };
        if workspace_filter
            .as_deref()
            .is_some_and(|filter| id != filter)
        {
            continue;
        }
        if targets.iter().any(|target| target.workspace == id) {
            continue;
        }
        targets.push(sync_target_from_local(base, local));
    }

    let summary = summarize_sync_targets(&targets);
    let issue = sync_issue(base, &daemon, mode);
    AgentSyncReport {
        schema: "nexus.agent_sync.v1",
        base: base.display().to_string(),
        mode,
        daemon,
        filter: AgentSyncFilter {
            workspace: workspace_filter,
            name,
        },
        summary,
        targets,
        error,
        issue,
        recommended_commands: sync_recommended_commands(base),
    }
}

fn agent_send_report(
    options: AgentSendOptions,
) -> Result<AgentSendReport, Box<dyn std::error::Error>> {
    let title = options
        .title
        .clone()
        .or_else(|| title_from_body(&options.body))
        .ok_or("--title required")?;
    let daemon = daemon_status_report(&options.base);
    if daemon.running && daemon.ipc_available {
        let request = daemon_agent_send_request_from_options(&options, title.clone());
        match daemon_agent_send(&options.base, request) {
            Ok(response) => {
                return Ok(agent_send_report_from_daemon(
                    options.base,
                    response.status,
                    response.send,
                ));
            }
            Err(error) => {
                return local_agent_send_report(options, title, daemon, Some(error.to_string()));
            }
        }
    }

    local_agent_send_report(options, title, daemon, None)
}

fn local_agent_send_report(
    options: AgentSendOptions,
    title: String,
    daemon: DaemonStatusReport,
    fallback_error: Option<String>,
) -> Result<AgentSendReport, Box<dyn std::error::Error>> {
    let now = unix_now();
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
    let delivery = send_delivery(&options.base, &daemon, fallback_error);

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
            kind: intent_kind_name(intent.kind).into(),
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

fn daemon_agent_send_request_from_options(
    options: &AgentSendOptions,
    title: String,
) -> DaemonAgentSendRequest {
    DaemonAgentSendRequest {
        id: options.id.clone(),
        kind: intent_kind_name(options.kind).into(),
        title,
        body: options.body.clone(),
        workspace: options.workspace.as_ref().map(ToString::to_string),
        task_id: options.task_id.clone(),
        capability: options.capability.clone(),
        tags: options.tags.clone(),
        expires_at: options.expires_at,
    }
}

fn agent_send_report_from_daemon(
    base: PathBuf,
    daemon: DaemonStatusReport,
    response: DaemonAgentSendResponse,
) -> AgentSendReport {
    let DaemonAgentSendResponse {
        event_id,
        author,
        seq,
        timestamp,
        inserted,
        intent_id,
        kind,
        title,
        body,
        workspace,
        task_id,
        capability,
        tags,
        expires_at,
        live_broadcast,
    } = response;

    AgentSendReport {
        schema: "nexus.agent_send.v1",
        base: base.display().to_string(),
        event: AgentSendEvent {
            id: event_id,
            author,
            seq,
            timestamp,
            inserted,
        },
        intent: AgentSendIntent {
            id: intent_id,
            kind,
            title,
            body,
            workspace,
            task_id,
            capability,
            tags,
            expires_at,
        },
        delivery: daemon_send_delivery(live_broadcast),
        daemon,
        recommended_commands: send_recommended_commands(&base),
    }
}

fn daemon_send_delivery(live_broadcast: bool) -> AgentSendDelivery {
    let message = if live_broadcast {
        "daemon signed, persisted, and broadcast the event through the live network"
    } else {
        "daemon signed and persisted the event; live broadcast was not accepted by the network yet"
    };
    AgentSendDelivery {
        mode: "daemon_ipc",
        local_memory: true,
        live_broadcast,
        issue: agent_issue("daemon_ipc_delivery", message, None),
    }
}

pub(crate) fn agent_status_report(base: &Path) -> AgentStatusReport {
    let daemon = daemon_status_report(base);
    let control_plane = control_plane_status(base, &daemon);
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
    if daemon.running && daemon.ipc_available {
        match daemon_agent_discover(base, filter.clone()) {
            Ok(response) => {
                return agent_discover_report_from_parts(
                    base,
                    "daemon_ipc_cache",
                    response.status,
                    response.cached_announcements,
                    response.workspaces,
                    response.error.map(|error| {
                        agent_issue(
                            "daemon_discover_error",
                            error,
                            Some(format!(
                                "nexus-node daemon status --base {} --json",
                                base.display()
                            )),
                        )
                    }),
                );
            }
            Err(error) => {
                return local_agent_discover_report(
                    base,
                    filter,
                    daemon,
                    "daemon_ipc_error_local_cache",
                    Some(agent_issue(
                        "daemon_discover_ipc_error",
                        error.to_string(),
                        Some(format!(
                            "nexus-node daemon status --base {} --json",
                            base.display()
                        )),
                    )),
                );
            }
        }
    }

    let mode = if daemon.running {
        "daemon_running_no_ipc_cache"
    } else {
        "local_cache"
    };
    local_agent_discover_report(base, filter, daemon, mode, None)
}

fn local_agent_discover_report(
    base: &Path,
    filter: DiscoveryFilter,
    daemon: DaemonStatusReport,
    mode: &'static str,
    fallback_error: Option<AgentIssue>,
) -> AgentDiscoverReport {
    let (cached_announcements, workspaces, error) = match load_workspace_discovery(base) {
        Ok(announcements) => {
            let cached_announcements = announcements.len();
            let workspaces = discovered_workspace_views(&announcements, &filter);
            (cached_announcements, workspaces, fallback_error)
        }
        Err(error) => (
            0,
            Vec::new(),
            Some(discovery_cache_read_issue(base, error.to_string())),
        ),
    };
    agent_discover_report_from_parts(base, mode, daemon, cached_announcements, workspaces, error)
}

fn agent_discover_report_from_parts(
    base: &Path,
    mode: &'static str,
    daemon: DaemonStatusReport,
    cached_announcements: usize,
    workspaces: Vec<DiscoveredWorkspaceView>,
    error: Option<AgentIssue>,
) -> AgentDiscoverReport {
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

fn discovery_cache_read_issue(base: &Path, error: String) -> AgentIssue {
    agent_issue(
        "discovery_cache_read_error",
        error,
        Some(format!(
            "nexus-node discover --base {} --lan --json --timeout-ms 3000",
            base.display()
        )),
    )
}

pub(crate) fn agent_inbox_report(
    base: &Path,
    requested_agent: Option<Did>,
    limit: usize,
    since: Option<u64>,
) -> AgentInboxReport {
    let generated_at = unix_now();
    let daemon_events = daemon_events_report(base, since, Some(limit));
    let daemon = daemon_events.status.clone();
    let resolved_agent = requested_agent.or_else(|| identity_status(base).did.map(Did::new));
    let mut items = Vec::new();
    let daemon_delta_mode = since.is_some() && daemon_events_are_live(&daemon_events);
    let mut discovery_source = "skipped_delta_mode";

    push_daemon_inbox_items(base, &daemon, generated_at, &mut items);
    push_daemon_event_items(base, &daemon_events.journal, &mut items);

    if !daemon_delta_mode {
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

        discovery_source = push_discovered_workspace_items(base, &daemon, &mut items);
    }

    if !daemon_delta_mode {
        if let Some(cursor) = since {
            items.retain(|item| item.timestamp.is_none_or(|timestamp| timestamp > cursor));
        }
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
        daemon_events,
        discovery_source,
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

fn send_delivery(
    base: &Path,
    daemon: &DaemonStatusReport,
    fallback_error: Option<String>,
) -> AgentSendDelivery {
    if let Some(error) = fallback_error {
        AgentSendDelivery {
            mode: "local_memory_daemon_ipc_fallback",
            local_memory: true,
            live_broadcast: false,
            issue: agent_issue(
                "daemon_send_ipc_failed",
                format!("daemon send IPC failed; the event is saved locally instead: {error}"),
                Some(format!(
                    "nexus-node daemon status --base {} --json",
                    base.display()
                )),
            ),
        }
    } else if daemon.running && daemon.ipc_available {
        AgentSendDelivery {
            mode: "local_memory_daemon_ipc_unavailable",
            local_memory: true,
            live_broadcast: false,
            issue: agent_issue(
                "daemon_send_ipc_unavailable",
                "daemon send IPC was not available; the event is saved locally but not injected into the running daemon",
                Some(format!("nexus-node daemon status --base {} --json", base.display())),
            ),
        }
    } else if daemon.running {
        AgentSendDelivery {
            mode: "local_memory_daemon_running",
            local_memory: true,
            live_broadcast: false,
            issue: agent_issue(
                "daemon_send_ipc_unavailable",
                "daemon is running without an available control socket; the event is saved locally but not injected into the running daemon",
                Some(format!("nexus-node daemon status --base {} --json", base.display())),
            ),
        }
    } else {
        AgentSendDelivery {
            mode: "local_memory",
            local_memory: true,
            live_broadcast: false,
            issue: agent_issue(
                "daemon_not_running",
                "daemon is not running; the event will be available for replay after the daemon or serve starts",
                Some(format!("nexus-node agent up --base {} --json", base.display())),
            ),
        }
    }
}

fn exec_delivery(base: &Path, daemon: &DaemonStatusReport) -> AgentExecDelivery {
    if daemon.running {
        AgentExecDelivery {
            mode: "local_exec_daemon_running",
            local_memory: true,
            live_broadcast: false,
            issue: agent_issue(
                "daemon_exec_ipc_pending",
                "daemon exec IPC is pending; the command ran locally and recorded social memory outside the running daemon",
                Some(format!("nexus-node daemon status --base {} --json", base.display())),
            ),
        }
    } else {
        AgentExecDelivery {
            mode: "local_exec",
            local_memory: true,
            live_broadcast: false,
            issue: agent_issue(
                "daemon_not_running",
                "daemon is not running; the command ran locally and will be available for replay after the daemon or serve starts",
                Some(format!(
                    "nexus-node daemon start --base {} --listen /ip4/0.0.0.0/udp/0/quic-v1",
                    base.display()
                )),
            ),
        }
    }
}

fn sync_mode(daemon: &DaemonStatusReport) -> &'static str {
    if daemon.running {
        if daemon.ipc_available {
            "daemon_running_local_plan"
        } else {
            "daemon_running_no_ipc_local_plan"
        }
    } else {
        "local_cache_plan"
    }
}

fn local_sync_discovered_workspaces(
    base: &Path,
    filter: &DiscoveryFilter,
) -> (Vec<DiscoveredWorkspaceView>, Option<AgentIssue>) {
    match load_workspace_discovery(base) {
        Ok(announcements) => (discovered_workspace_views(&announcements, filter), None),
        Err(error) => (
            Vec::new(),
            Some(discovery_cache_read_issue(
                base,
                format!("read discovery cache: {error}"),
            )),
        ),
    }
}

fn sync_issue(base: &Path, daemon: &DaemonStatusReport, mode: &'static str) -> AgentIssue {
    if mode == "daemon_ipc_local_plan" {
        agent_issue(
            "daemon_sync_apply_pending",
            "daemon discovery IPC is active; this report still returns a local clone/sync plan and does not apply network changes",
            Some(format!("nexus-node daemon status --base {} --json", base.display())),
        )
    } else if daemon.running {
        agent_issue(
            "daemon_sync_ipc_pending",
            "daemon sync IPC is pending; this report is based on local workspace and discovery caches",
            Some(format!("nexus-node daemon status --base {} --json", base.display())),
        )
    } else {
        agent_issue(
            "daemon_not_running",
            "daemon is not running; this report is based on local caches and suggests explicit clone/discover commands",
            Some(format!(
                "nexus-node agent up --base {} --json",
                base.display()
            )),
        )
    }
}

fn find_local_workspace<'a>(
    locals: &'a [LocalWorkspaceStatus],
    workspace: &str,
) -> Option<&'a LocalWorkspaceStatus> {
    locals
        .iter()
        .find(|local| local.id.as_deref() == Some(workspace))
}

fn sync_target_from_discovered(
    base: &Path,
    local: Option<&LocalWorkspaceStatus>,
    workspace: DiscoveredWorkspaceView,
    clone_name: Option<&str>,
) -> AgentSyncTarget {
    let discovered = sync_discovered(&workspace);
    let local = local.map(sync_local);
    let mut reasons = vec!["discovery-cache".into()];
    if discovered.verified {
        reasons.push("verified-announcement".into());
    }
    if discovered.clone_ready {
        reasons.push("clone-ready".into());
    }
    if local.is_some() {
        reasons.push("local-workspace-present".into());
    }
    if workspace.forked {
        reasons.push("snapshot-forks".into());
    }

    let (status, action, command_hint) = match (&local, discovered.clone_ready) {
        (Some(local), _) => {
            if local
                .latest_root
                .as_deref()
                .zip(discovered.root.as_deref())
                .is_some_and(|(local_root, discovered_root)| local_root != discovered_root)
            {
                (
                    "local_and_discovered_roots_differ",
                    "inspect_snapshot_fork",
                    Some(format!(
                        "nexus-node society --base {} --json --workspace {}",
                        base.display(),
                        workspace.workspace
                    )),
                )
            } else {
                (
                    "local_and_discovered",
                    "no_network_action",
                    Some(format!(
                        "nexus-node agent status --base {} --json",
                        base.display()
                    )),
                )
            }
        }
        (None, true) => {
            let name = sync_clone_name(clone_name, &workspace.name, &workspace.workspace);
            (
                "clone_ready",
                "clone_with_expert_command",
                Some(format!(
                    "nexus-node clone --base {} --workspace {} --name {}",
                    base.display(),
                    workspace.workspace,
                    name
                )),
            )
        }
        (None, false) => (
            "discovered_not_clone_ready",
            "refresh_discovery",
            Some(format!(
                "nexus-node discover --base {} --lan --json --workspace {}",
                base.display(),
                workspace.workspace
            )),
        ),
    };

    AgentSyncTarget {
        workspace: workspace.workspace,
        name: Some(workspace.name),
        status,
        action,
        local,
        discovered: Some(discovered),
        reasons,
        command_hint,
    }
}

fn sync_target_from_local(base: &Path, local: &LocalWorkspaceStatus) -> AgentSyncTarget {
    let workspace = local.id.clone().unwrap_or_else(|| "unknown".into());
    AgentSyncTarget {
        workspace,
        name: local.name.clone(),
        status: "local_only",
        action: "serve_or_refresh_discovery",
        local: Some(sync_local(local)),
        discovered: None,
        reasons: vec!["local-workspace".into(), "no-discovery-cache-match".into()],
        command_hint: Some(format!(
            "nexus-node agent up --base {} --json",
            base.display()
        )),
    }
}

fn sync_local(local: &LocalWorkspaceStatus) -> AgentSyncLocal {
    AgentSyncLocal {
        path: local.path.clone(),
        present: local.present,
        latest_root: local.latest_root.clone(),
    }
}

fn sync_discovered(workspace: &DiscoveredWorkspaceView) -> AgentSyncDiscovered {
    AgentSyncDiscovered {
        owner: workspace.owner.to_string(),
        root: workspace.root.clone(),
        verified: workspace.verified,
        clone_ready: workspace.clone_ready,
        peers: workspace.peers.len(),
        addrs: workspace.addrs.len(),
        latest_timestamp: workspace.latest_timestamp,
        forked: workspace.forked,
        fork_roots: workspace.fork_roots.clone(),
    }
}

fn summarize_sync_targets(targets: &[AgentSyncTarget]) -> AgentSyncSummary {
    let mut summary = AgentSyncSummary {
        targets: targets.len(),
        ..Default::default()
    };
    for target in targets {
        if target.local.is_some() {
            summary.local_workspaces += 1;
        }
        if let Some(discovered) = &target.discovered {
            summary.discovered_workspaces += 1;
            if discovered.clone_ready {
                summary.clone_ready += 1;
            }
        }
        match target.action {
            "clone_with_expert_command" => summary.clone_suggestions += 1,
            "refresh_discovery" | "serve_or_refresh_discovery" => summary.refresh_suggestions += 1,
            _ => {}
        }
        if target.status == "local_only" {
            summary.local_only += 1;
        }
    }
    summary
}

fn sync_clone_name(explicit: Option<&str>, discovered_name: &str, workspace: &str) -> String {
    let raw = explicit.unwrap_or(discovered_name);
    let mut slug = String::new();
    let mut last_dash = false;
    for ch in raw.chars() {
        let normalized = if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.') {
            Some(ch.to_ascii_lowercase())
        } else if ch.is_ascii_whitespace() || matches!(ch, '-' | '/') {
            Some('-')
        } else {
            None
        };
        let Some(ch) = normalized else {
            continue;
        };
        if ch == '-' {
            if last_dash {
                continue;
            }
            last_dash = true;
        } else {
            last_dash = false;
        }
        slug.push(ch);
    }
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        format!("workspace-{}", &workspace[..workspace.len().min(12)])
    } else {
        slug
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

fn control_plane_status(base: &Path, daemon: &DaemonStatusReport) -> ControlPlaneStatus {
    if daemon.running {
        ControlPlaneStatus {
            mode: "daemon_running",
            realtime_ready: true,
            daemon_supported: true,
            issue: agent_issue(
                "daemon_ipc_routing_pending",
                "daemon is running; exec and remaining live sync IPC routes are still pending",
                Some(format!(
                    "nexus-node daemon status --base {} --json",
                    base.display()
                )),
            ),
            next_design:
                "route agent exec and live sync through the base-scoped daemon control socket",
        }
    } else {
        ControlPlaneStatus {
            mode: "daemon_supported_not_running",
            realtime_ready: false,
            daemon_supported: true,
            issue: agent_issue(
                "daemon_not_running",
                "daemon is not running, so network serving still requires an explicit foreground or daemon start command",
                Some(format!("nexus-node agent up --base {} --json", base.display())),
            ),
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

fn daemon_events_are_live(report: &DaemonEventsReport) -> bool {
    report.error.is_none()
        && report.status.running
        && report.status.ipc_available
        && report.status.control_socket.is_some()
}

fn push_daemon_event_items(
    base: &Path,
    journal: &DaemonEventJournal,
    items: &mut Vec<AgentInboxItem>,
) {
    for event in &journal.events {
        items.push(daemon_event_item(base, event));
    }
}

fn daemon_event_item(base: &Path, event: &DaemonEvent) -> AgentInboxItem {
    AgentInboxItem {
        kind: "daemon_event",
        priority: daemon_event_priority(&event.kind),
        title: format!("Daemon event: {}", event.kind),
        body: Some(event.summary.clone()),
        author: None,
        workspace: None,
        task_id: None,
        capability: None,
        timestamp: Some(event.timestamp),
        score: None,
        reasons: vec![format!("daemon-event-sequence:{}", event.sequence)],
        actions: Vec::new(),
        command_hint: Some(format!(
            "nexus-node agent inbox --base {} --since {} --json",
            base.display(),
            event.sequence
        )),
    }
}

fn daemon_event_priority(kind: &str) -> u32 {
    match kind {
        "social_event" => 84,
        "workspace_snapshot_changed" => 82,
        "workspace_announcement" => 78,
        "sync_request" => 68,
        "peer_connected" | "peer_disconnected" => 62,
        "listening" => 58,
        _ => 54,
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

fn push_discovered_workspace_items(
    base: &Path,
    daemon: &DaemonStatusReport,
    items: &mut Vec<AgentInboxItem>,
) -> &'static str {
    if daemon.running && daemon.ipc_available {
        match daemon_agent_discover(base, DiscoveryFilter::default()) {
            Ok(response) => {
                push_discovered_workspace_view_items(base, response.workspaces, items);
                return "daemon_ipc_cache";
            }
            Err(error) => {
                items.push(AgentInboxItem {
                    kind: "daemon_alert",
                    priority: 63,
                    title: "Daemon discovery IPC failed".into(),
                    body: Some(error.to_string()),
                    author: None,
                    workspace: None,
                    task_id: None,
                    capability: None,
                    timestamp: Some(unix_now()),
                    score: None,
                    reasons: vec!["daemon-discovery-ipc-error".into()],
                    actions: Vec::new(),
                    command_hint: Some(format!(
                        "nexus-node daemon status --base {} --json",
                        base.display()
                    )),
                });
                push_local_discovered_workspace_items(base, items);
                return "daemon_ipc_error_local_cache";
            }
        }
    }

    push_local_discovered_workspace_items(base, items);
    if daemon.running {
        "daemon_running_no_ipc_cache"
    } else {
        "local_cache"
    }
}

fn push_local_discovered_workspace_items(base: &Path, items: &mut Vec<AgentInboxItem>) {
    let Ok(announcements) = load_workspace_discovery(base) else {
        return;
    };
    push_discovered_workspace_view_items(
        base,
        discovered_workspace_views(&announcements, &DiscoveryFilter::default()),
        items,
    );
}

fn push_discovered_workspace_view_items(
    base: &Path,
    workspaces: Vec<DiscoveredWorkspaceView>,
    items: &mut Vec<AgentInboxItem>,
) {
    for workspace in workspaces {
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

fn sync_recommended_commands(base: &Path) -> Vec<CommandHint> {
    let base = base.display();
    vec![
        CommandHint {
            name: "status",
            command: format!("nexus-node agent status --base {base} --json"),
        },
        CommandHint {
            name: "discover_cache",
            command: format!("nexus-node agent discover --base {base} --json"),
        },
        CommandHint {
            name: "inbox",
            command: format!("nexus-node agent inbox --base {base} --json"),
        },
        CommandHint {
            name: "discover_lan_refresh",
            command: format!("nexus-node discover --base {base} --lan --json --timeout-ms 3000"),
        },
        CommandHint {
            name: "daemon_start",
            command: format!(
                "nexus-node agent up --base {base} --listen /ip4/0.0.0.0/udp/0/quic-v1 --json"
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
            "daemon_event" => summary.daemon_events += 1,
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
            error: Some(agent_issue("identity_read_error", error, None)),
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
            error: Some(agent_issue(
                "social_memory_read_error",
                error.to_string(),
                Some(format!(
                    "nexus-node agent status --base {} --json",
                    base.display()
                )),
            )),
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
            error: Some(agent_issue(
                "local_workspace_list_error",
                error.to_string(),
                None,
            )),
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
            error: Some(agent_issue(
                "local_workspace_config_read_error",
                format!("read {}: {error}", config_path.display()),
                None,
            )),
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
            name: "sync",
            command: format!("nexus-node agent sync --base {base} --json"),
        },
        CommandHint {
            name: "serve_foreground",
            command: format!("nexus-node serve --base {base} --listen /ip4/0.0.0.0/udp/0/quic-v1"),
        },
    ]
}

fn print_agent_sync_text(report: &AgentSyncReport) {
    println!("Agent sync: {}", report.base);
    println!("mode: {}", report.mode);
    println!(
        "daemon: running={} ipc_available={}",
        report.daemon.running, report.daemon.ipc_available
    );
    println!(
        "targets: {} local={} discovered={} clone_ready={} clone_suggestions={} refresh_suggestions={}",
        report.summary.targets,
        report.summary.local_workspaces,
        report.summary.discovered_workspaces,
        report.summary.clone_ready,
        report.summary.clone_suggestions,
        report.summary.refresh_suggestions
    );
    println!("issue: {}", report.issue.message);
    if let Some(error) = &report.error {
        println!("error[{}]: {}", error.kind, error.message);
    }
    if let Some(command) = &report.issue.suggested_command {
        println!("suggested: {command}");
    }
    for target in &report.targets {
        println!(
            "\n{}  status={} action={}",
            target.workspace, target.status, target.action
        );
        if let Some(name) = &target.name {
            println!("  name: {name}");
        }
        if let Some(local) = &target.local {
            println!(
                "  local: {} root={}",
                local.path,
                local.latest_root.as_deref().unwrap_or("-")
            );
        }
        if let Some(discovered) = &target.discovered {
            println!(
                "  discovered: owner={} root={} peers={} addrs={} verified={} clone_ready={}",
                discovered.owner,
                discovered.root.as_deref().unwrap_or("-"),
                discovered.peers,
                discovered.addrs,
                discovered.verified,
                discovered.clone_ready
            );
        }
        if !target.reasons.is_empty() {
            println!("  reasons: {}", target.reasons.join(", "));
        }
        if let Some(command) = &target.command_hint {
            println!("  command: {command}");
        }
    }
    println!("recommended:");
    for hint in &report.recommended_commands {
        println!("  {}: {}", hint.name, hint.command);
    }
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
    println!("issue: {}", report.delivery.issue.message);
    if let Some(command) = &report.delivery.issue.suggested_command {
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
    println!("issue: {}", report.delivery.issue.message);
    if let Some(command) = &report.delivery.issue.suggested_command {
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
        println!("error[{}]: {}", error.kind, error.message);
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
        "items: {} daemon_alerts={} daemon_events={} intents={} open_tasks={} assigned_tasks={} discovered_workspaces={}",
        report.summary.items,
        report.summary.daemon_alerts,
        report.summary.daemon_events,
        report.summary.intent_recommendations,
        report.summary.open_tasks,
        report.summary.assigned_tasks,
        report.summary.discovered_workspaces
    );
    println!(
        "daemon_events: cursor={} events={} limit={} error={}",
        report.daemon_events.journal.cursor,
        report.daemon_events.journal.events.len(),
        report.daemon_events.journal.limit,
        report.daemon_events.error.as_deref().unwrap_or("-")
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
        "control_plane_issue: {}",
        report.control_plane.issue.message
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
        assert_eq!(report.summary.daemon_events, 0);
        assert_eq!(report.discovery_source, "local_cache");
        assert_eq!(report.daemon_events.journal.cursor, 0);
        assert!(report.daemon_events.journal.events.is_empty());
        assert_eq!(
            report.daemon_events.error.as_deref(),
            Some("daemon control socket is not available")
        );
        assert!(report.items.iter().any(|item| {
            item.kind == "daemon_alert"
                && item
                    .command_hint
                    .as_deref()
                    .is_some_and(|command| command.contains("nexus-node daemon start"))
        }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn inbox_prefers_daemon_ipc_discovery_when_available() {
        let temp = tempfile::TempDir::new().unwrap();
        let owner = NodeIdentity::generate();
        let peer = nexus_network::to_peer_id(&owner);
        let workspace = WorkspaceId::from_bytes([87; 32]);
        let announcement = WorkspaceAnnouncement {
            version: WORKSPACE_ANNOUNCEMENT_VERSION,
            peer: peer.to_string(),
            addrs: vec!["/ip4/127.0.0.1/udp/5678/quic-v1".into()],
            author: owner.did().clone(),
            workspace: workspace.to_string(),
            name: "daemon inbox workspace".into(),
            description: "served by agent inbox discovery IPC".into(),
            owner: owner.did().clone(),
            root: None,
            timestamp: 14,
            signature: None,
        };
        let signed = sign_workspace_announcement(announcement, &owner).unwrap();
        assert!(record_workspace_announcement(temp.path(), signed).unwrap());

        let daemon_dir = temp.path().join(".nexus");
        std::fs::create_dir_all(&daemon_dir).unwrap();
        let socket = daemon_dir.join("daemon.sock");
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
                "control_socket": socket.display().to_string(),
                "command": ["nexus-node", "serve"]
            }))
            .unwrap(),
        )
        .unwrap();
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = spawn_serve_control_socket(
            temp.path().to_path_buf(),
            socket,
            shutdown_tx,
            DaemonEventJournalHandle::new(),
            None,
        )
        .unwrap();

        let base = temp.path().to_path_buf();
        let report = tokio::task::spawn_blocking(move || agent_inbox_report(&base, None, 10, None))
            .await
            .unwrap();

        assert_eq!(report.discovery_source, "daemon_ipc_cache");
        assert_eq!(report.summary.discovered_workspaces, 1);
        let workspace_id = workspace.to_string();
        assert!(report.items.iter().any(|item| {
            item.kind == "discovered_workspace"
                && item.workspace.as_deref() == Some(workspace_id.as_str())
        }));

        handle.abort();
    }

    #[test]
    fn daemon_event_items_are_cursor_friendly() {
        let temp = tempfile::TempDir::new().unwrap();
        let journal = DaemonEventJournal {
            schema: "nexus.daemon_events.v1".into(),
            base: temp.path().display().to_string(),
            cursor: 42,
            limit: 10,
            events: vec![DaemonEvent {
                sequence: 42,
                timestamp: 1234,
                kind: "workspace_snapshot_changed".into(),
                summary: "workspace_snapshot_changed workspace=abc root=def".into(),
            }],
        };
        let mut items = Vec::new();

        push_daemon_event_items(temp.path(), &journal, &mut items);
        let summary = summarize_inbox_items(&items);

        assert_eq!(summary.items, 1);
        assert_eq!(summary.daemon_events, 1);
        assert_eq!(items[0].kind, "daemon_event");
        assert_eq!(items[0].priority, 82);
        assert_eq!(items[0].timestamp, Some(1234));
        assert!(items[0]
            .reasons
            .contains(&"daemon-event-sequence:42".into()));
        assert!(items[0]
            .command_hint
            .as_deref()
            .is_some_and(|command| command.contains("--since 42")));
    }

    #[test]
    fn watch_options_parse_cursor_limit_and_interval() {
        let options = parse_agent_watch_options(&[
            "nexus-node".into(),
            "agent".into(),
            "watch".into(),
            "--base".into(),
            "/tmp/watch-base".into(),
            "--since".into(),
            "41".into(),
            "--limit".into(),
            "7".into(),
            "--interval-ms".into(),
            "250".into(),
            "--json".into(),
        ])
        .unwrap();

        assert_eq!(options.base, PathBuf::from("/tmp/watch-base"));
        assert_eq!(options.since, Some(41));
        assert_eq!(options.limit, 7);
        assert_eq!(options.interval, Duration::from_millis(250));
        assert!(options.json);

        assert!(parse_agent_watch_options(&[
            "nexus-node".into(),
            "agent".into(),
            "watch".into(),
            "--interval-ms".into(),
            "0".into(),
        ])
        .unwrap_err()
        .to_string()
        .contains("greater than 0"));
        assert!(parse_agent_watch_options(&[
            "nexus-node".into(),
            "agent".into(),
            "watch".into(),
            "--limit".into(),
            "0".into(),
        ])
        .unwrap_err()
        .to_string()
        .contains("greater than 0"));
    }

    #[test]
    fn watch_events_render_as_ndjson_and_text() {
        let temp = tempfile::TempDir::new().unwrap();
        let daemon_event = DaemonEvent {
            sequence: 9,
            timestamp: 1234,
            kind: "social_event".into(),
            summary: "social_event source=peer events=3 agents=2".into(),
        };
        let watch_event = agent_watch_daemon_event(temp.path(), &daemon_event);
        let mut json = Vec::new();

        write_agent_watch_event(&mut json, &watch_event, true).unwrap();

        assert_eq!(json.last(), Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["schema"], "nexus.agent_watch_event.v1");
        assert_eq!(value["kind"], "daemon_event");
        assert_eq!(value["cursor"], 9);
        assert_eq!(value["daemon_event"]["kind"], "social_event");
        assert!(value["command_hint"]
            .as_str()
            .is_some_and(|command| command.contains("--since 9")));

        let error_event = agent_watch_error_event(temp.path(), 9, "daemon is not running".into());
        let mut error_json = Vec::new();
        write_agent_watch_event(&mut error_json, &error_event, true).unwrap();
        let error_value: serde_json::Value = serde_json::from_slice(&error_json).unwrap();
        assert_eq!(error_value["error"]["kind"], "daemon_events_unavailable");
        assert_eq!(error_value["error"]["message"], "daemon is not running");
        assert!(error_value["error"]["suggested_command"]
            .as_str()
            .is_some_and(|command| command.contains("nexus-node agent up")));

        let mut text = Vec::new();
        write_agent_watch_event(&mut text, &error_event, false).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("watch_error cursor=9"));
        assert!(text.contains("daemon is not running"));
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

    #[cfg(unix)]
    #[tokio::test]
    async fn discover_prefers_daemon_ipc_when_available() {
        let temp = tempfile::TempDir::new().unwrap();
        let owner = NodeIdentity::generate();
        let peer = nexus_network::to_peer_id(&owner);
        let workspace = WorkspaceId::from_bytes([85; 32]);
        let announcement = WorkspaceAnnouncement {
            version: WORKSPACE_ANNOUNCEMENT_VERSION,
            peer: peer.to_string(),
            addrs: vec!["/ip4/127.0.0.1/udp/3456/quic-v1".into()],
            author: owner.did().clone(),
            workspace: workspace.to_string(),
            name: "daemon routed workspace".into(),
            description: "served by agent discover IPC".into(),
            owner: owner.did().clone(),
            root: None,
            timestamp: 12,
            signature: None,
        };
        let signed = sign_workspace_announcement(announcement, &owner).unwrap();
        assert!(record_workspace_announcement(temp.path(), signed).unwrap());

        let daemon_dir = temp.path().join(".nexus");
        std::fs::create_dir_all(&daemon_dir).unwrap();
        let socket = daemon_dir.join("daemon.sock");
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
                "control_socket": socket.display().to_string(),
                "command": ["nexus-node", "serve"]
            }))
            .unwrap(),
        )
        .unwrap();
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = spawn_serve_control_socket(
            temp.path().to_path_buf(),
            socket,
            shutdown_tx,
            DaemonEventJournalHandle::new(),
            None,
        )
        .unwrap();

        let base = temp.path().to_path_buf();
        let report = tokio::task::spawn_blocking(move || {
            agent_discover_report(
                &base,
                DiscoveryFilter {
                    clone_ready_only: true,
                    ..Default::default()
                },
            )
        })
        .await
        .unwrap();

        assert_eq!(report.mode, "daemon_ipc_cache");
        assert_eq!(report.summary.cached_announcements, 1);
        assert_eq!(report.summary.workspaces, 1);
        assert_eq!(report.workspaces[0].workspace, workspace.to_string());
        assert!(report.workspaces[0].clone_ready);
        assert!(report.error.is_none());

        handle.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sync_prefers_daemon_ipc_discovery_when_available() {
        let temp = tempfile::TempDir::new().unwrap();
        let owner = NodeIdentity::generate();
        let peer = nexus_network::to_peer_id(&owner);
        let workspace = WorkspaceId::from_bytes([86; 32]);
        let announcement = WorkspaceAnnouncement {
            version: WORKSPACE_ANNOUNCEMENT_VERSION,
            peer: peer.to_string(),
            addrs: vec!["/ip4/127.0.0.1/udp/4567/quic-v1".into()],
            author: owner.did().clone(),
            workspace: workspace.to_string(),
            name: "daemon sync workspace".into(),
            description: "served by agent sync IPC".into(),
            owner: owner.did().clone(),
            root: None,
            timestamp: 13,
            signature: None,
        };
        let signed = sign_workspace_announcement(announcement, &owner).unwrap();
        assert!(record_workspace_announcement(temp.path(), signed).unwrap());

        let daemon_dir = temp.path().join(".nexus");
        std::fs::create_dir_all(&daemon_dir).unwrap();
        let socket = daemon_dir.join("daemon.sock");
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
                "control_socket": socket.display().to_string(),
                "command": ["nexus-node", "serve"]
            }))
            .unwrap(),
        )
        .unwrap();
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = spawn_serve_control_socket(
            temp.path().to_path_buf(),
            socket,
            shutdown_tx,
            DaemonEventJournalHandle::new(),
            None,
        )
        .unwrap();

        let base = temp.path().to_path_buf();
        let workspace_filter = workspace.to_string();
        let report = tokio::task::spawn_blocking(move || {
            agent_sync_report(
                &base,
                Some(workspace_filter),
                Some("daemon-sync-copy".into()),
            )
        })
        .await
        .unwrap();

        assert_eq!(report.mode, "daemon_ipc_local_plan");
        assert_eq!(report.issue.kind, "daemon_sync_apply_pending");
        assert_eq!(report.summary.targets, 1);
        assert_eq!(report.summary.clone_ready, 1);
        assert_eq!(report.targets[0].workspace, workspace.to_string());
        assert_eq!(report.targets[0].action, "clone_with_expert_command");
        assert!(report.error.is_none());

        handle.abort();
    }

    #[test]
    fn discover_cache_errors_are_structured() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            temp.path().join(".nexus-workspace-discovery.json"),
            b"not json",
        )
        .unwrap();

        let report = agent_discover_report(temp.path(), DiscoveryFilter::default());

        let error = report.error.as_ref().unwrap();
        assert_eq!(error.kind, "discovery_cache_read_error");
        assert!(error
            .suggested_command
            .as_deref()
            .is_some_and(|command| command.contains("nexus-node discover")));
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["error"]["kind"], "discovery_cache_read_error");
        assert!(value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("expected ident")));
        assert!(value["error"].get("suggested_command").is_some());
    }

    #[test]
    fn sync_reports_clone_ready_discovery_without_identity() {
        let temp = tempfile::TempDir::new().unwrap();
        let owner = NodeIdentity::generate();
        let peer = nexus_network::to_peer_id(&owner);
        let workspace = WorkspaceId::from_bytes([73; 32]);
        let announcement = WorkspaceAnnouncement {
            version: WORKSPACE_ANNOUNCEMENT_VERSION,
            peer: peer.to_string(),
            addrs: vec!["/ip4/127.0.0.1/udp/2345/quic-v1".into()],
            author: owner.did().clone(),
            workspace: workspace.to_string(),
            name: "Remote Workspace".into(),
            description: "ready for sync planning".into(),
            owner: owner.did().clone(),
            root: None,
            timestamp: 11,
            signature: None,
        };
        let signed = sign_workspace_announcement(announcement, &owner).unwrap();
        assert!(record_workspace_announcement(temp.path(), signed).unwrap());

        let report = agent_sync_report(
            temp.path(),
            Some(workspace.to_string()),
            Some("Remote Copy".into()),
        );

        assert_eq!(report.schema, "nexus.agent_sync.v1");
        assert_eq!(report.mode, "local_cache_plan");
        assert_eq!(report.issue.kind, "daemon_not_running");
        assert!(report
            .issue
            .suggested_command
            .as_deref()
            .is_some_and(|command| command.contains("nexus-node agent up")));
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["issue"]["kind"], "daemon_not_running");
        assert!(value["issue"].get("message").is_some());
        assert!(value["issue"].get("suggested_command").is_some());
        assert_eq!(report.summary.targets, 1);
        assert_eq!(report.summary.clone_ready, 1);
        assert_eq!(report.summary.clone_suggestions, 1);
        assert_eq!(report.targets[0].status, "clone_ready");
        assert_eq!(report.targets[0].action, "clone_with_expert_command");
        assert!(report.targets[0]
            .command_hint
            .as_deref()
            .is_some_and(|command| {
                command.contains("nexus-node clone")
                    && command.contains("--name remote-copy")
                    && command.contains(&workspace.to_string())
            }));
        assert!(!identity_path(temp.path()).exists());
    }

    #[test]
    fn sync_reports_local_workspace_without_identity() {
        let temp = tempfile::TempDir::new().unwrap();
        let workspace = temp.path().join("workspace-local");
        std::fs::create_dir_all(workspace.join(".nexus")).unwrap();
        std::fs::write(
            workspace.join(".nexus/config.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "name": "workspace-local",
                "description": "local sync test",
                "id": "3333333333333333333333333333333333333333333333333333333333333333",
                "owner": "did:key:z6Mklocal",
                "snapshot_history": [
                    "4444444444444444444444444444444444444444444444444444444444444444"
                ],
                "snapshot_retention_limit": 32
            }))
            .unwrap(),
        )
        .unwrap();

        let report = agent_sync_report(temp.path(), None, None);

        assert_eq!(report.summary.targets, 1);
        assert_eq!(report.summary.local_workspaces, 1);
        assert_eq!(report.summary.local_only, 1);
        assert_eq!(report.targets[0].status, "local_only");
        assert_eq!(report.targets[0].action, "serve_or_refresh_discovery");
        assert_eq!(
            report.targets[0]
                .local
                .as_ref()
                .and_then(|local| local.latest_root.as_deref()),
            Some("4444444444444444444444444444444444444444444444444444444444444444")
        );
        assert!(report.targets[0]
            .command_hint
            .as_deref()
            .is_some_and(|command| command.contains("nexus-node agent up")));
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
        assert_eq!(report.delivery.issue.kind, "daemon_not_running");
        assert!(report
            .delivery
            .issue
            .suggested_command
            .as_deref()
            .is_some_and(|command| command.contains("nexus-node agent up")));
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

    #[cfg(unix)]
    #[tokio::test]
    async fn send_prefers_daemon_ipc_when_available() {
        let temp = tempfile::TempDir::new().unwrap();
        let daemon_dir = temp.path().join(".nexus");
        std::fs::create_dir_all(&daemon_dir).unwrap();
        let socket = daemon_dir.join("daemon.sock");
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
                "control_socket": socket.display().to_string(),
                "command": ["nexus-node", "serve"]
            }))
            .unwrap(),
        )
        .unwrap();
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(1);
        let command_task = tokio::spawn(async move {
            let Some(crate::daemon::DaemonControlCommand::AgentSend { request, reply }) =
                control_rx.recv().await
            else {
                panic!("agent_send command should be forwarded to the serve loop");
            };
            assert_eq!(request.id.as_deref(), Some("intent-daemon-send"));
            assert_eq!(request.kind, "status");
            assert_eq!(request.title, "Daemon status update");
            assert_eq!(request.body, "ready through daemon");
            assert_eq!(request.capability.as_deref(), Some("daemon-ipc"));
            assert_eq!(request.tags, vec!["daemon-send".to_string()]);
            reply
                .send(Ok(DaemonAgentSendResponse {
                    event_id: "event-daemon-send".into(),
                    author: "did:key:daemon".into(),
                    seq: 7,
                    timestamp: 456,
                    inserted: true,
                    intent_id: request.id.unwrap(),
                    kind: request.kind,
                    title: request.title,
                    body: request.body,
                    workspace: request.workspace,
                    task_id: request.task_id,
                    capability: request.capability,
                    tags: request.tags,
                    expires_at: request.expires_at,
                    live_broadcast: true,
                }))
                .unwrap();
        });
        let handle = spawn_serve_control_socket(
            temp.path().to_path_buf(),
            socket,
            shutdown_tx,
            DaemonEventJournalHandle::new(),
            Some(control_tx),
        )
        .unwrap();

        let base = temp.path().to_path_buf();
        let report = tokio::task::spawn_blocking(move || {
            agent_send_report(AgentSendOptions {
                base,
                id: Some("intent-daemon-send".into()),
                kind: IntentKind::Status,
                title: Some("Daemon status update".into()),
                body: "ready through daemon".into(),
                workspace: None,
                task_id: None,
                capability: Some("daemon-ipc".into()),
                tags: vec!["daemon-send".into()],
                expires_at: None,
                json: true,
            })
            .map_err(|error| error.to_string())
        })
        .await
        .unwrap()
        .unwrap();

        assert_eq!(report.event.id, "event-daemon-send");
        assert_eq!(report.event.seq, 7);
        assert_eq!(report.intent.id, "intent-daemon-send");
        assert_eq!(report.delivery.mode, "daemon_ipc");
        assert_eq!(report.delivery.issue.kind, "daemon_ipc_delivery");
        assert!(report.delivery.live_broadcast);

        command_task.await.unwrap();
        handle.abort();
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
        assert_eq!(report.delivery.issue.kind, "daemon_not_running");
        assert!(report
            .delivery
            .issue
            .suggested_command
            .as_deref()
            .is_some_and(|command| command.contains("nexus-node daemon start")));
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
