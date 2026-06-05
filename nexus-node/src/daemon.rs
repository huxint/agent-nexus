use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nexus_agent::WorkspaceRunContext;
use nexus_network::NetworkDiagnostics;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(any(unix, windows))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, ServerOptions};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot, watch};

use crate::bootstrap::extend_bootstrap_peers;
use crate::cli_args::{parse_u64_arg, required_arg};
use crate::discovery::{
    discovered_workspace_views, load_workspace_discovery, DiscoveredWorkspaceView, DiscoveryFilter,
};
use crate::state::write_file_atomic;
use crate::unix_now;

const DAEMON_RECORD_VERSION: u32 = 2;
const DEFAULT_DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_CONTROL_REQUEST_MAX_BYTES: usize = 4 * 1024 * 1024;
const DAEMON_CONTROL_RESPONSE_MAX_BYTES: u64 = 40 * 1024 * 1024;
const DAEMON_CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
const DAEMON_START_READY_TIMEOUT: Duration = Duration::from_secs(2);
const DAEMON_EVENT_JOURNAL_LIMIT: usize = 256;
const DEFAULT_DAEMON_EVENTS_LIMIT: usize = 50;
#[cfg(windows)]
const WINDOWS_ERROR_PIPE_BUSY: i32 = 231;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonStatusReport {
    pub(crate) schema: String,
    pub(crate) base: String,
    pub(crate) supported: bool,
    pub(crate) running: bool,
    pub(crate) stale: bool,
    pub(crate) pid: Option<u32>,
    pub(crate) started_at: Option<u64>,
    pub(crate) listen: Option<String>,
    pub(crate) public_defaults_enabled: Option<bool>,
    pub(crate) bootstrap_peers: Vec<String>,
    pub(crate) state_path: String,
    pub(crate) stdout_log: Option<String>,
    pub(crate) stderr_log: Option<String>,
    pub(crate) control_socket: Option<String>,
    pub(crate) ipc_available: bool,
    pub(crate) command: Vec<String>,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct DaemonStartReport {
    pub(crate) started: bool,
    pub(crate) status: DaemonStatusReport,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct DaemonStopReport {
    stopped: bool,
    stale_removed: bool,
    status: DaemonStatusReport,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DaemonRecord {
    version: u32,
    base: String,
    pid: u32,
    started_at: u64,
    listen: String,
    public_defaults_enabled: bool,
    bootstrap_peers: Vec<String>,
    stdout_log: String,
    stderr_log: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control_socket: Option<String>,
    command: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DaemonControlRequest {
    command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discovery_filter: Option<DiscoveryFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_send: Option<DaemonAgentSendRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_exec: Option<DaemonAgentExecRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_sync_apply: Option<DaemonAgentSyncApplyRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DaemonControlResponse {
    ok: bool,
    shutdown: bool,
    status: DaemonStatusReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    events: Option<DaemonEventJournal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discovered_workspaces: Option<Vec<DiscoveredWorkspaceView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cached_announcements: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_send: Option<DaemonAgentSendResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_exec: Option<DaemonAgentExecResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_sync_apply: Option<DaemonAgentSyncApplyResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network_status: Option<DaemonNetworkStatusResponse>,
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonAgentSendRequest {
    pub(crate) id: Option<String>,
    pub(crate) kind: String,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) workspace: Option<String>,
    pub(crate) task_id: Option<String>,
    pub(crate) capability: Option<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) expires_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonAgentSendResponse {
    pub(crate) event_id: String,
    pub(crate) author: String,
    pub(crate) seq: u64,
    pub(crate) timestamp: u64,
    pub(crate) inserted: bool,
    pub(crate) intent_id: String,
    pub(crate) kind: String,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) workspace: Option<String>,
    pub(crate) task_id: Option<String>,
    pub(crate) capability: Option<String>,
    pub(crate) tags: Vec<String>,
    pub(crate) expires_at: Option<u64>,
    pub(crate) live_broadcast: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonAgentExecRequest {
    pub(crate) workspace_path: String,
    pub(crate) note: Option<String>,
    pub(crate) working_dir: Option<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) stdin_hex: Option<String>,
    pub(crate) timeout_ms: Option<u64>,
    pub(crate) capture_stdout: bool,
    pub(crate) capture_stderr: bool,
    pub(crate) max_stdout_bytes: Option<usize>,
    pub(crate) max_stderr_bytes: Option<usize>,
    pub(crate) isolation: String,
    pub(crate) isolation_explicit: bool,
    pub(crate) command: String,
    pub(crate) command_args: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonAgentSyncApplyRequest {
    pub(crate) workspace: Option<String>,
    pub(crate) name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonAgentExecResponse {
    pub(crate) workspace_path: String,
    pub(crate) workspace: String,
    pub(crate) actor: String,
    pub(crate) command: String,
    pub(crate) args: Vec<String>,
    pub(crate) exit_code: i32,
    pub(crate) stdout: DaemonAgentExecStream,
    pub(crate) stderr: DaemonAgentExecStream,
    pub(crate) output_root: String,
    pub(crate) resources: DaemonAgentExecResources,
    pub(crate) context: Option<WorkspaceRunContext>,
    pub(crate) started_at: u64,
    pub(crate) finished_at: u64,
    pub(crate) live_broadcast: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonAgentSyncApplyResponse {
    pub(crate) workspace: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) applied: bool,
    pub(crate) mode: String,
    pub(crate) message: String,
    pub(crate) suggested_command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) clone: Option<DaemonAgentSyncCloneResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonAgentSyncCloneResult {
    pub(crate) path: String,
    pub(crate) root: String,
    pub(crate) peer: String,
    pub(crate) owner: String,
    pub(crate) synced_social_events: usize,
    pub(crate) recorded_social_events: usize,
    pub(crate) live_broadcast: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonAgentExecStream {
    pub(crate) bytes: usize,
    pub(crate) cid: String,
    pub(crate) text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonAgentExecResources {
    pub(crate) wall_time_ms: u64,
    pub(crate) cpu_user_ms: u64,
    pub(crate) cpu_kernel_ms: u64,
    pub(crate) peak_memory: Option<u64>,
    pub(crate) fs_read_bytes: u64,
    pub(crate) fs_write_bytes: u64,
    pub(crate) process_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonNetworkStatusResponse {
    pub(crate) diagnostics: NetworkDiagnostics,
}

#[derive(Debug)]
pub(crate) enum DaemonControlCommand {
    AgentSend {
        request: DaemonAgentSendRequest,
        reply: oneshot::Sender<Result<DaemonAgentSendResponse, String>>,
    },
    AgentExec {
        request: DaemonAgentExecRequest,
        reply: oneshot::Sender<Result<DaemonAgentExecResponse, String>>,
    },
    AgentSyncApply {
        request: DaemonAgentSyncApplyRequest,
        reply: oneshot::Sender<Result<DaemonAgentSyncApplyResponse, String>>,
    },
    NetworkStatus {
        reply: oneshot::Sender<Result<DaemonNetworkStatusResponse, String>>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DaemonAgentDiscoveryResponse {
    pub(crate) status: DaemonStatusReport,
    pub(crate) workspaces: Vec<DiscoveredWorkspaceView>,
    pub(crate) cached_announcements: usize,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaemonAgentSendControlResponse {
    pub(crate) status: DaemonStatusReport,
    pub(crate) send: DaemonAgentSendResponse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaemonAgentExecControlResponse {
    pub(crate) status: DaemonStatusReport,
    pub(crate) exec: DaemonAgentExecResponse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaemonAgentSyncApplyControlResponse {
    pub(crate) status: DaemonStatusReport,
    pub(crate) apply: DaemonAgentSyncApplyResponse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DaemonNetworkStatusControlResponse {
    pub(crate) status: DaemonStatusReport,
    pub(crate) events: DaemonEventJournal,
    pub(crate) network_status: DaemonNetworkStatusResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonEventsReport {
    pub(crate) schema: String,
    pub(crate) base: String,
    pub(crate) status: DaemonStatusReport,
    pub(crate) journal: DaemonEventJournal,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonEventJournal {
    pub(crate) schema: String,
    pub(crate) base: String,
    pub(crate) cursor: u64,
    pub(crate) limit: usize,
    pub(crate) events: Vec<DaemonEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DaemonEvent {
    pub(crate) sequence: u64,
    pub(crate) timestamp: u64,
    pub(crate) kind: String,
    pub(crate) summary: String,
}

#[derive(Clone, Debug)]
pub(crate) struct DaemonEventJournalHandle {
    inner: Arc<Mutex<DaemonEventJournalState>>,
}

#[derive(Debug)]
struct DaemonEventJournalState {
    next_sequence: u64,
    events: VecDeque<DaemonEvent>,
}

#[derive(Clone, Debug)]
pub(crate) struct DaemonStartOptions {
    pub(crate) base: PathBuf,
    pub(crate) listen: String,
    pub(crate) bootstrap_peers: Vec<libp2p::Multiaddr>,
    pub(crate) use_public_bootstrap: bool,
    pub(crate) json: bool,
}

impl DaemonEventJournalHandle {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(DaemonEventJournalState {
                next_sequence: 1,
                events: VecDeque::new(),
            })),
        }
    }

    pub(crate) fn push(&self, kind: impl Into<String>, summary: impl Into<String>) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let sequence = guard.next_sequence;
        guard.next_sequence = guard.next_sequence.saturating_add(1);
        guard.events.push_back(DaemonEvent {
            sequence,
            timestamp: unix_now(),
            kind: kind.into(),
            summary: summary.into(),
        });
        while guard.events.len() > DAEMON_EVENT_JOURNAL_LIMIT {
            guard.events.pop_front();
        }
    }

    pub(crate) fn snapshot(
        &self,
        base: &Path,
        since: Option<u64>,
        limit: Option<usize>,
    ) -> DaemonEventJournal {
        let limit = limit
            .unwrap_or(DEFAULT_DAEMON_EVENTS_LIMIT)
            .min(DAEMON_EVENT_JOURNAL_LIMIT);
        let Ok(guard) = self.inner.lock() else {
            return empty_event_journal(base, since.unwrap_or(0), limit);
        };
        let mut events = guard
            .events
            .iter()
            .filter(|event| since.is_none_or(|since| event.sequence > since))
            .cloned()
            .collect::<Vec<_>>();
        if events.len() > limit {
            let start = events.len() - limit;
            events = events.split_off(start);
        }
        let cursor = events
            .last()
            .map(|event| event.sequence)
            .or(since)
            .unwrap_or(0);
        DaemonEventJournal {
            schema: "nexus.daemon_events.v1".into(),
            base: base.display().to_string(),
            cursor,
            limit,
            events,
        }
    }
}

pub(crate) fn cmd_daemon(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.get(2).map(String::as_str) {
        Some("start") => cmd_daemon_start(args),
        Some("status") => cmd_daemon_status(args),
        Some("stop") => cmd_daemon_stop(args),
        Some("events") => cmd_daemon_events(args),
        Some(other) => Err(format!("unknown daemon subcommand: {other}").into()),
        None => Err("daemon subcommand required: start, status, stop, or events".into()),
    }
}

fn cmd_daemon_start(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_daemon_start_options(args)?;
    let report = start_daemon(&options)?;
    if options.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.started {
        print_daemon_started_text(&report.status);
    } else {
        print_daemon_status_text(&report.status);
    }
    Ok(())
}

fn cmd_daemon_status(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (base, json) = parse_daemon_status_options(args, 3)?;
    let report = daemon_status_report(&base);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_daemon_status_text(&report);
    }
    Ok(())
}

fn cmd_daemon_events(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut json = false;
    let mut since = None;
    let mut limit = None;
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
            "--since" => {
                i += 1;
                since = Some(parse_u64_arg(required_arg(args, i, "--since")?, "--since")?);
            }
            "--limit" => {
                i += 1;
                limit = Some(parse_events_limit(required_arg(args, i, "--limit")?)?);
            }
            other => return Err(format!("unknown daemon events option: {other}").into()),
        }
        i += 1;
    }

    let report = daemon_events_report(&base, since, limit);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_daemon_events_text(&report);
    }
    Ok(())
}

fn cmd_daemon_stop(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (base, json, timeout) = parse_daemon_stop_options(args)?;
    let report = stop_daemon(&base, timeout)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.stopped {
        println!("Daemon stopped: {}", report.status.base);
    } else if report.stale_removed {
        println!("Removed stale daemon state: {}", report.status.state_path);
    } else {
        print_daemon_status_text(&report.status);
    }
    Ok(())
}

pub(crate) fn daemon_events_report(
    base: &Path,
    since: Option<u64>,
    limit: Option<usize>,
) -> DaemonEventsReport {
    let status = daemon_status_report(base);
    let effective_limit = limit
        .unwrap_or(DEFAULT_DAEMON_EVENTS_LIMIT)
        .min(DAEMON_EVENT_JOURNAL_LIMIT);
    let empty = empty_event_journal(base, since.unwrap_or(0), effective_limit);
    let Some(socket) = status.control_socket.as_deref() else {
        return DaemonEventsReport {
            schema: "nexus.daemon_events_report.v1".into(),
            base: base.display().to_string(),
            status,
            journal: empty,
            error: Some("daemon control socket is not available".into()),
        };
    };
    if !status.running {
        return DaemonEventsReport {
            schema: "nexus.daemon_events_report.v1".into(),
            base: base.display().to_string(),
            status,
            journal: empty,
            error: Some("daemon is not running".into()),
        };
    }

    match query_control_socket_request(
        Path::new(socket),
        &DaemonControlRequest {
            command: "events".into(),
            since,
            limit: Some(effective_limit),
            discovery_filter: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
        },
    ) {
        Ok(response) if response.ok => DaemonEventsReport {
            schema: "nexus.daemon_events_report.v1".into(),
            base: base.display().to_string(),
            status: response.status,
            journal: response.events.unwrap_or(empty),
            error: response.error,
        },
        Ok(response) => DaemonEventsReport {
            schema: "nexus.daemon_events_report.v1".into(),
            base: base.display().to_string(),
            status: response.status,
            journal: response.events.unwrap_or(empty),
            error: response
                .error
                .or_else(|| Some("daemon events request failed".into())),
        },
        Err(error) => DaemonEventsReport {
            schema: "nexus.daemon_events_report.v1".into(),
            base: base.display().to_string(),
            status,
            journal: empty,
            error: Some(error.to_string()),
        },
    }
}

pub(crate) fn daemon_status_report(base: &Path) -> DaemonStatusReport {
    let status = daemon_status_report_from_record(base);
    if status.running {
        if let Some(socket) = status.control_socket.as_deref() {
            if let Ok(response) = query_control_socket(Path::new(socket), "status") {
                if response.ok {
                    return response.status;
                }
            }
        }
    }
    status
}

fn daemon_status_report_from_record(base: &Path) -> DaemonStatusReport {
    let state_path = daemon_record_path(base);
    let Ok(record) = load_daemon_record(base) else {
        return DaemonStatusReport {
            schema: "nexus.daemon_status.v1".into(),
            base: base.display().to_string(),
            supported: true,
            running: false,
            stale: false,
            pid: None,
            started_at: None,
            listen: None,
            public_defaults_enabled: None,
            bootstrap_peers: Vec::new(),
            state_path: state_path.display().to_string(),
            stdout_log: None,
            stderr_log: None,
            control_socket: None,
            ipc_available: false,
            command: Vec::new(),
            error: read_daemon_record_error(base),
        };
    };

    let running = is_process_running(record.pid);
    DaemonStatusReport {
        schema: "nexus.daemon_status.v1".into(),
        base: base.display().to_string(),
        supported: true,
        running,
        stale: !running,
        pid: Some(record.pid),
        started_at: Some(record.started_at),
        listen: Some(record.listen),
        public_defaults_enabled: Some(record.public_defaults_enabled),
        bootstrap_peers: record.bootstrap_peers,
        state_path: state_path.display().to_string(),
        stdout_log: Some(record.stdout_log),
        stderr_log: Some(record.stderr_log),
        control_socket: record.control_socket,
        ipc_available: false,
        command: record.command,
        error: None,
    }
}

pub(crate) fn start_daemon(
    options: &DaemonStartOptions,
) -> Result<DaemonStartReport, Box<dyn std::error::Error>> {
    let current = daemon_status_report(&options.base);
    if current.running {
        return Ok(DaemonStartReport {
            started: false,
            status: current,
        });
    }
    if std::env::var("NEXUS_PASSPHRASE").is_err() {
        return Err("NEXUS_PASSPHRASE is required for daemon start because background serve cannot prompt for identity passphrase".into());
    }

    std::fs::create_dir_all(daemon_dir(&options.base))?;
    let stdout_log = daemon_stdout_log_path(&options.base);
    let stderr_log = daemon_stderr_log_path(&options.base);
    let control_socket = daemon_control_socket_path(&options.base);
    let stdout = open_append_log(&stdout_log)?;
    let stderr = open_append_log(&stderr_log)?;

    let exe = std::env::current_exe()?;
    let mut command_args = vec![
        "serve".to_string(),
        "--base".to_string(),
        options.base.display().to_string(),
        "--listen".to_string(),
        options.listen.clone(),
    ];
    #[cfg(any(unix, windows))]
    {
        command_args.push("--control-socket".to_string());
        command_args.push(control_socket.display().to_string());
    }
    for peer in &options.bootstrap_peers {
        command_args.push("--bootstrap".to_string());
        command_args.push(peer.to_string());
    }
    if !options.use_public_bootstrap {
        command_args.push("--no-public-bootstrap".to_string());
    }

    let mut command = Command::new(&exe);
    command
        .args(&command_args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    configure_daemon_process(&mut command);
    let child = command.spawn()?;

    let record = DaemonRecord {
        version: DAEMON_RECORD_VERSION,
        base: options.base.display().to_string(),
        pid: child.id(),
        started_at: unix_now(),
        listen: options.listen.clone(),
        public_defaults_enabled: options.use_public_bootstrap,
        bootstrap_peers: options
            .bootstrap_peers
            .iter()
            .map(ToString::to_string)
            .collect(),
        stdout_log: stdout_log.display().to_string(),
        stderr_log: stderr_log.display().to_string(),
        control_socket: control_socket_for_record(&control_socket),
        command: std::iter::once(exe.display().to_string())
            .chain(command_args)
            .collect(),
    };
    save_daemon_record(&options.base, &record)?;

    Ok(DaemonStartReport {
        started: true,
        status: wait_for_daemon_ready(&options.base, DAEMON_START_READY_TIMEOUT),
    })
}

fn stop_daemon(
    base: &Path,
    timeout: Duration,
) -> Result<DaemonStopReport, Box<dyn std::error::Error>> {
    let before = daemon_status_report(base);
    let Some(pid) = before.pid else {
        return Ok(DaemonStopReport {
            stopped: false,
            stale_removed: false,
            status: before,
        });
    };
    if !before.running {
        remove_daemon_record(base)?;
        return Ok(DaemonStopReport {
            stopped: false,
            stale_removed: true,
            status: daemon_status_report(base),
        });
    }

    if let Some(socket) = before.control_socket.as_deref() {
        if query_control_socket(Path::new(socket), "shutdown").is_ok() {
            return wait_for_daemon_stopped(base, pid, timeout, false);
        }
    }

    terminate_process(pid)?;
    wait_for_daemon_stopped(base, pid, timeout, false)
}

fn parse_daemon_start_options(
    args: &[String],
) -> Result<DaemonStartOptions, Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut listen = "/ip4/0.0.0.0/udp/0/quic-v1".to_string();
    let mut bootstrap_peers = Vec::new();
    let mut use_public_bootstrap = true;
    let mut json = false;
    let mut i = 3;
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
                bootstrap_peers.push(required_arg(args, i, "--bootstrap")?.parse()?);
            }
            "--invite" => {
                i += 1;
                extend_bootstrap_peers(&mut bootstrap_peers, required_arg(args, i, "--invite")?)?;
            }
            "--no-public-bootstrap" => {
                use_public_bootstrap = false;
            }
            "--json" => {
                json = true;
            }
            other => return Err(format!("unknown daemon start option: {other}").into()),
        }
        i += 1;
    }

    Ok(DaemonStartOptions {
        base,
        listen,
        bootstrap_peers,
        use_public_bootstrap,
        json,
    })
}

fn parse_daemon_status_options(
    args: &[String],
    start: usize,
) -> Result<(PathBuf, bool), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut json = false;
    let mut i = start;
    while i < args.len() {
        match args[i].as_str() {
            "--base" => {
                i += 1;
                base = PathBuf::from(required_arg(args, i, "--base")?);
            }
            "--json" => {
                json = true;
            }
            other => return Err(format!("unknown daemon status option: {other}").into()),
        }
        i += 1;
    }
    Ok((base, json))
}

fn parse_daemon_stop_options(
    args: &[String],
) -> Result<(PathBuf, bool, Duration), Box<dyn std::error::Error>> {
    let mut base = PathBuf::from(".");
    let mut json = false;
    let mut timeout = DEFAULT_DAEMON_STOP_TIMEOUT;
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
            "--timeout-ms" => {
                i += 1;
                timeout = Duration::from_millis(parse_u64_arg(
                    required_arg(args, i, "--timeout-ms")?,
                    "--timeout-ms",
                )?);
            }
            other => return Err(format!("unknown daemon stop option: {other}").into()),
        }
        i += 1;
    }
    Ok((base, json, timeout))
}

fn parse_events_limit(value: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let limit = parse_u64_arg(value, "--limit")?;
    if limit == 0 {
        return Err("--limit must be greater than 0".into());
    }
    Ok(usize::try_from(limit)
        .unwrap_or(usize::MAX)
        .min(DAEMON_EVENT_JOURNAL_LIMIT))
}

fn print_daemon_started_text(status: &DaemonStatusReport) {
    println!(
        "Daemon started: base={} pid={} listen={}",
        status.base,
        status
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".into()),
        status.listen.as_deref().unwrap_or("-")
    );
    if let Some(stdout) = &status.stdout_log {
        println!("stdout_log: {stdout}");
    }
    if let Some(stderr) = &status.stderr_log {
        println!("stderr_log: {stderr}");
    }
}

fn print_daemon_events_text(report: &DaemonEventsReport) {
    println!("Daemon events: {}", report.base);
    println!(
        "daemon: running={} ipc_available={}",
        report.status.running, report.status.ipc_available
    );
    println!(
        "cursor: {} events={} limit={}",
        report.journal.cursor,
        report.journal.events.len(),
        report.journal.limit
    );
    if let Some(error) = &report.error {
        println!("error: {error}");
    }
    for event in &report.journal.events {
        println!(
            "  #{} {} {} {}",
            event.sequence, event.timestamp, event.kind, event.summary
        );
    }
}

fn print_daemon_status_text(status: &DaemonStatusReport) {
    println!("Daemon status: {}", status.base);
    println!("running: {}", status.running);
    println!("stale: {}", status.stale);
    println!(
        "pid: {}",
        status
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".into())
    );
    println!("listen: {}", status.listen.as_deref().unwrap_or("-"));
    println!("state: {}", status.state_path);
    if let Some(error) = &status.error {
        println!("error: {error}");
    }
}

fn empty_event_journal(base: &Path, cursor: u64, limit: usize) -> DaemonEventJournal {
    DaemonEventJournal {
        schema: "nexus.daemon_events.v1".into(),
        base: base.display().to_string(),
        cursor,
        limit,
        events: Vec::new(),
    }
}

fn daemon_dir(base: &Path) -> PathBuf {
    base.join(".nexus")
}

fn daemon_record_path(base: &Path) -> PathBuf {
    daemon_dir(base).join("daemon.json")
}

fn daemon_stdout_log_path(base: &Path) -> PathBuf {
    daemon_dir(base).join("daemon.stdout.log")
}

fn daemon_stderr_log_path(base: &Path) -> PathBuf {
    daemon_dir(base).join("daemon.stderr.log")
}

#[cfg(not(windows))]
fn daemon_control_socket_path(base: &Path) -> PathBuf {
    daemon_dir(base).join("daemon.sock")
}

#[cfg(windows)]
fn daemon_control_socket_path(base: &Path) -> PathBuf {
    let normalized = std::fs::canonicalize(base).unwrap_or_else(|_| base.to_path_buf());
    let digest = Sha256::digest(normalized.display().to_string().as_bytes());
    let digest = hex::encode(&digest[..16]);
    PathBuf::from(format!(r"\\.\pipe\nexus-node-daemon-{digest}"))
}

#[cfg(unix)]
fn control_socket_for_record(path: &Path) -> Option<String> {
    Some(path.display().to_string())
}

#[cfg(windows)]
fn control_socket_for_record(path: &Path) -> Option<String> {
    Some(path.display().to_string())
}

#[cfg(not(any(unix, windows)))]
fn control_socket_for_record(_path: &Path) -> Option<String> {
    None
}

fn wait_for_daemon_ready(base: &Path, timeout: Duration) -> DaemonStatusReport {
    let deadline = Instant::now() + timeout;
    loop {
        let mut status = daemon_status_report(base);
        if status.ipc_available || !status.running || Instant::now() >= deadline {
            if status.running && !status.ipc_available && status.error.is_none() {
                status.error = Some(format!(
                    "daemon control socket did not become ready within {} ms",
                    timeout.as_millis()
                ));
            }
            return status;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_daemon_stopped(
    base: &Path,
    pid: u32,
    timeout: Duration,
    stale_removed: bool,
) -> Result<DaemonStopReport, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !is_process_running(pid) {
            remove_daemon_record(base)?;
            return Ok(DaemonStopReport {
                stopped: !stale_removed,
                stale_removed,
                status: daemon_status_report(base),
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    Ok(DaemonStopReport {
        stopped: false,
        stale_removed: false,
        status: daemon_status_report(base),
    })
}

fn open_append_log(path: &Path) -> Result<File, std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(unix)]
fn configure_daemon_process(command: &mut Command) {
    unsafe {
        // Detach the background serve process from the caller's terminal/session.
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

#[cfg(not(unix))]
fn configure_daemon_process(_command: &mut Command) {}

fn load_daemon_record(base: &Path) -> Result<DaemonRecord, Box<dyn std::error::Error>> {
    let path = daemon_record_path(base);
    let data = std::fs::read(&path)?;
    let record = serde_json::from_slice::<DaemonRecord>(&data)?;
    if record.version == 0 || record.version > DAEMON_RECORD_VERSION {
        return Err(format!("unsupported daemon record version {}", record.version).into());
    }
    Ok(record)
}

fn read_daemon_record_error(base: &Path) -> Option<String> {
    let path = daemon_record_path(base);
    if !path.exists() {
        return None;
    }
    load_daemon_record(base).err().map(|err| err.to_string())
}

fn save_daemon_record(
    base: &Path,
    record: &DaemonRecord,
) -> Result<(), Box<dyn std::error::Error>> {
    write_file_atomic(
        &daemon_record_path(base),
        &serde_json::to_vec_pretty(record)?,
    )?;
    Ok(())
}

fn remove_daemon_record(base: &Path) -> Result<(), std::io::Error> {
    let path = daemon_record_path(base);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    let result = unsafe { libc::kill(pid as i32, 0) };
    result == 0
        || std::io::Error::last_os_error()
            .raw_os_error()
            .is_some_and(|code| code == libc::EPERM)
}

#[cfg(windows)]
fn is_process_running(pid: u32) -> bool {
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

#[cfg(not(any(unix, windows)))]
fn is_process_running(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
fn terminate_process(pid: u32) -> Result<(), std::io::Error> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid daemon pid",
        ));
    }
    let result = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn terminate_process(pid: u32) -> Result<(), std::io::Error> {
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T"])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "taskkill failed",
        ))
    }
}

#[cfg(not(any(unix, windows)))]
fn terminate_process(_pid: u32) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "daemon stop is unsupported on this platform",
    ))
}

#[cfg(unix)]
pub(crate) fn spawn_serve_control_socket(
    base: PathBuf,
    socket_path: PathBuf,
    shutdown_tx: watch::Sender<bool>,
    event_journal: DaemonEventJournalHandle,
    control_tx: Option<mpsc::Sender<DaemonControlCommand>>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let base = base.clone();
            let shutdown_tx = shutdown_tx.clone();
            let event_journal = event_journal.clone();
            let control_tx = control_tx.clone();
            tokio::spawn(async move {
                handle_control_stream(stream, base, shutdown_tx, event_journal, control_tx).await;
            });
        }
    });
    Ok(handle)
}

#[cfg(windows)]
pub(crate) fn spawn_serve_control_socket(
    base: PathBuf,
    pipe_path: PathBuf,
    shutdown_tx: watch::Sender<bool>,
    event_journal: DaemonEventJournalHandle,
    control_tx: Option<mpsc::Sender<DaemonControlCommand>>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let handle = tokio::spawn(async move {
        let mut first_pipe_instance = true;
        loop {
            let server = match ServerOptions::new()
                .first_pipe_instance(first_pipe_instance)
                .create(&pipe_path)
            {
                Ok(server) => server,
                Err(_) => break,
            };
            first_pipe_instance = false;
            if server.connect().await.is_err() {
                break;
            }
            let base = base.clone();
            let shutdown_tx = shutdown_tx.clone();
            let event_journal = event_journal.clone();
            let control_tx = control_tx.clone();
            tokio::spawn(async move {
                handle_control_stream(server, base, shutdown_tx, event_journal, control_tx).await;
            });
        }
    });
    Ok(handle)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn spawn_serve_control_socket(
    _base: PathBuf,
    _socket_path: PathBuf,
    _shutdown_tx: watch::Sender<bool>,
    _event_journal: DaemonEventJournalHandle,
    _control_tx: Option<mpsc::Sender<DaemonControlCommand>>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    Err("daemon control socket is unsupported on this platform".into())
}

#[cfg(any(unix, windows))]
async fn handle_control_stream<S>(
    mut stream: S,
    base: PathBuf,
    shutdown_tx: watch::Sender<bool>,
    event_journal: DaemonEventJournalHandle,
    control_tx: Option<mpsc::Sender<DaemonControlCommand>>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let response = match read_control_request(&mut stream).await {
        Ok(request) => match request.command.as_str() {
            "status" => DaemonControlResponse {
                ok: true,
                shutdown: false,
                status: daemon_control_status(&base),
                events: None,
                discovered_workspaces: None,
                cached_announcements: None,
                agent_send: None,
                agent_exec: None,
                agent_sync_apply: None,
                network_status: None,
                error: None,
            },
            "shutdown" => DaemonControlResponse {
                ok: true,
                shutdown: true,
                status: daemon_control_status(&base),
                events: None,
                discovered_workspaces: None,
                cached_announcements: None,
                agent_send: None,
                agent_exec: None,
                agent_sync_apply: None,
                network_status: None,
                error: None,
            },
            "events" => DaemonControlResponse {
                ok: true,
                shutdown: false,
                status: daemon_control_status(&base),
                events: Some(event_journal.snapshot(&base, request.since, request.limit)),
                discovered_workspaces: None,
                cached_announcements: None,
                agent_send: None,
                agent_exec: None,
                agent_sync_apply: None,
                network_status: None,
                error: None,
            },
            "agent_discover" | "agent_sync" => {
                daemon_control_agent_discovery_response(&base, request)
            }
            "agent_send" => daemon_control_agent_send_response(&base, request, control_tx).await,
            "agent_exec" => daemon_control_agent_exec_response(&base, request, control_tx).await,
            "agent_sync_apply" => {
                daemon_control_agent_sync_apply_response(&base, request, control_tx).await
            }
            "network_status" => {
                daemon_control_network_status_response(&base, request, event_journal, control_tx)
                    .await
            }
            other => DaemonControlResponse {
                ok: false,
                shutdown: false,
                status: daemon_control_status(&base),
                events: None,
                discovered_workspaces: None,
                cached_announcements: None,
                agent_send: None,
                agent_exec: None,
                agent_sync_apply: None,
                network_status: None,
                error: Some(format!("unknown daemon control command: {other}")),
            },
        },
        Err(error) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status: daemon_control_status(&base),
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some(error.to_string()),
        },
    };
    let shutdown = response.shutdown && response.ok;
    if let Ok(mut data) = serde_json::to_vec(&response) {
        data.push(b'\n');
        let _ = stream.write_all(&data).await;
        let _ = stream.shutdown().await;
    }
    if shutdown {
        let _ = shutdown_tx.send(true);
    }
}

async fn daemon_control_network_status_response(
    base: &Path,
    request: DaemonControlRequest,
    event_journal: DaemonEventJournalHandle,
    control_tx: Option<mpsc::Sender<DaemonControlCommand>>,
) -> DaemonControlResponse {
    let status = daemon_control_status(base);
    let events = event_journal.snapshot(base, request.since, request.limit);
    let Some(control_tx) = control_tx else {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: Some(events),
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop command channel is unavailable".into()),
        };
    };

    let (reply, reply_rx) = oneshot::channel();
    if control_tx
        .send(DaemonControlCommand::NetworkStatus { reply })
        .await
        .is_err()
    {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: Some(events),
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop command channel is closed".into()),
        };
    }

    match tokio::time::timeout(DAEMON_CONTROL_TIMEOUT, reply_rx).await {
        Ok(Ok(Ok(network_status))) => DaemonControlResponse {
            ok: true,
            shutdown: false,
            status,
            events: Some(events),
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: Some(network_status),
            error: None,
        },
        Ok(Ok(Err(error))) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: Some(events),
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some(error),
        },
        Ok(Err(_)) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: Some(events),
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop dropped network_status response".into()),
        },
        Err(_) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: Some(events),
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon network_status request timed out".into()),
        },
    }
}

fn daemon_control_agent_discovery_response(
    base: &Path,
    request: DaemonControlRequest,
) -> DaemonControlResponse {
    let status = daemon_control_status(base);
    let filter = request.discovery_filter.unwrap_or_default();
    match load_workspace_discovery(base) {
        Ok(announcements) => {
            let cached_announcements = announcements.len();
            DaemonControlResponse {
                ok: true,
                shutdown: false,
                status,
                events: None,
                discovered_workspaces: Some(discovered_workspace_views(&announcements, &filter)),
                cached_announcements: Some(cached_announcements),
                agent_send: None,
                agent_exec: None,
                agent_sync_apply: None,
                network_status: None,
                error: None,
            }
        }
        Err(error) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some(format!("read discovery cache: {error}")),
        },
    }
}

async fn daemon_control_agent_send_response(
    base: &Path,
    request: DaemonControlRequest,
    control_tx: Option<mpsc::Sender<DaemonControlCommand>>,
) -> DaemonControlResponse {
    let status = daemon_control_status(base);
    let Some(agent_send) = request.agent_send else {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("agent_send request payload is required".into()),
        };
    };
    let Some(control_tx) = control_tx else {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop command channel is unavailable".into()),
        };
    };

    let (reply, reply_rx) = oneshot::channel();
    if control_tx
        .send(DaemonControlCommand::AgentSend {
            request: agent_send,
            reply,
        })
        .await
        .is_err()
    {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop command channel is closed".into()),
        };
    }

    match tokio::time::timeout(DAEMON_CONTROL_TIMEOUT, reply_rx).await {
        Ok(Ok(Ok(agent_send))) => DaemonControlResponse {
            ok: true,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: Some(agent_send),
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: None,
        },
        Ok(Ok(Err(error))) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some(error),
        },
        Ok(Err(_)) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop dropped agent_send response".into()),
        },
        Err(_) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon agent_send request timed out".into()),
        },
    }
}

async fn daemon_control_agent_exec_response(
    base: &Path,
    request: DaemonControlRequest,
    control_tx: Option<mpsc::Sender<DaemonControlCommand>>,
) -> DaemonControlResponse {
    let status = daemon_control_status(base);
    let Some(agent_exec) = request.agent_exec else {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("agent_exec request payload is required".into()),
        };
    };
    let Some(control_tx) = control_tx else {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop command channel is unavailable".into()),
        };
    };

    let (reply, reply_rx) = oneshot::channel();
    if control_tx
        .send(DaemonControlCommand::AgentExec {
            request: agent_exec,
            reply,
        })
        .await
        .is_err()
    {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop command channel is closed".into()),
        };
    }

    match tokio::time::timeout(DAEMON_CONTROL_TIMEOUT, reply_rx).await {
        Ok(Ok(Ok(agent_exec))) => DaemonControlResponse {
            ok: true,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: Some(agent_exec),
            agent_sync_apply: None,
            network_status: None,
            error: None,
        },
        Ok(Ok(Err(error))) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some(error),
        },
        Ok(Err(_)) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop dropped agent_exec response".into()),
        },
        Err(_) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon agent_exec request timed out".into()),
        },
    }
}

async fn daemon_control_agent_sync_apply_response(
    base: &Path,
    request: DaemonControlRequest,
    control_tx: Option<mpsc::Sender<DaemonControlCommand>>,
) -> DaemonControlResponse {
    let status = daemon_control_status(base);
    let Some(agent_sync_apply) = request.agent_sync_apply else {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("agent_sync_apply request payload is required".into()),
        };
    };
    let Some(control_tx) = control_tx else {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop command channel is unavailable".into()),
        };
    };

    let (reply, reply_rx) = oneshot::channel();
    if control_tx
        .send(DaemonControlCommand::AgentSyncApply {
            request: agent_sync_apply,
            reply,
        })
        .await
        .is_err()
    {
        return DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop command channel is closed".into()),
        };
    }

    match tokio::time::timeout(DAEMON_CONTROL_TIMEOUT, reply_rx).await {
        Ok(Ok(Ok(agent_sync_apply))) => DaemonControlResponse {
            ok: true,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: Some(agent_sync_apply),
            network_status: None,
            error: None,
        },
        Ok(Ok(Err(error))) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some(error),
        },
        Ok(Err(_)) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon serve-loop dropped agent_sync_apply response".into()),
        },
        Err(_) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status,
            events: None,
            discovered_workspaces: None,
            cached_announcements: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
            network_status: None,
            error: Some("daemon agent_sync_apply request timed out".into()),
        },
    }
}

#[cfg(any(unix, windows))]
async fn read_control_request<S>(
    stream: &mut S,
) -> Result<DaemonControlRequest, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; DAEMON_CONTROL_REQUEST_MAX_BYTES + 1];
    let bytes_read = stream.read(&mut buffer).await?;
    if bytes_read == 0 {
        return Err("empty daemon control request".into());
    }
    if bytes_read > DAEMON_CONTROL_REQUEST_MAX_BYTES {
        return Err("daemon control request is too large".into());
    }
    buffer.truncate(bytes_read);
    Ok(serde_json::from_slice(&buffer)?)
}

fn daemon_control_status(base: &Path) -> DaemonStatusReport {
    let mut status = daemon_status_report_from_record(base);
    status.ipc_available = true;
    status
}

#[cfg(any(unix, windows))]
fn query_control_socket(
    socket_path: &Path,
    command: &str,
) -> Result<DaemonControlResponse, Box<dyn std::error::Error>> {
    query_control_socket_request(
        socket_path,
        &DaemonControlRequest {
            command: command.to_string(),
            since: None,
            limit: None,
            discovery_filter: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
        },
    )
}

pub(crate) fn daemon_agent_discover(
    base: &Path,
    filter: DiscoveryFilter,
) -> Result<DaemonAgentDiscoveryResponse, Box<dyn std::error::Error>> {
    daemon_agent_discovery(base, "agent_discover", filter)
}

pub(crate) fn daemon_agent_sync(
    base: &Path,
    filter: DiscoveryFilter,
) -> Result<DaemonAgentDiscoveryResponse, Box<dyn std::error::Error>> {
    daemon_agent_discovery(base, "agent_sync", filter)
}

fn daemon_agent_discovery(
    base: &Path,
    command: &str,
    filter: DiscoveryFilter,
) -> Result<DaemonAgentDiscoveryResponse, Box<dyn std::error::Error>> {
    let status = daemon_status_report(base);
    let Some(socket) = status.control_socket.as_deref() else {
        return Err("daemon control socket is not available".into());
    };
    if !status.running {
        return Err("daemon is not running".into());
    }

    let response = query_control_socket_request(
        Path::new(socket),
        &DaemonControlRequest {
            command: command.into(),
            since: None,
            limit: None,
            discovery_filter: Some(filter),
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
        },
    )?;
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| format!("daemon {command} request failed"))
            .into());
    }
    Ok(DaemonAgentDiscoveryResponse {
        status: response.status,
        workspaces: response.discovered_workspaces.unwrap_or_default(),
        cached_announcements: response.cached_announcements.unwrap_or(0),
        error: response.error,
    })
}

pub(crate) fn daemon_agent_send(
    base: &Path,
    request: DaemonAgentSendRequest,
) -> Result<DaemonAgentSendControlResponse, Box<dyn std::error::Error>> {
    let status = daemon_status_report(base);
    let Some(socket) = status.control_socket.as_deref() else {
        return Err("daemon control socket is not available".into());
    };
    if !status.running {
        return Err("daemon is not running".into());
    }

    let response = query_control_socket_request(
        Path::new(socket),
        &DaemonControlRequest {
            command: "agent_send".into(),
            since: None,
            limit: None,
            discovery_filter: None,
            agent_send: Some(request),
            agent_exec: None,
            agent_sync_apply: None,
        },
    )?;
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| "daemon agent_send request failed".into())
            .into());
    }
    let send = response
        .agent_send
        .ok_or("daemon agent_send response did not include send result")?;
    Ok(DaemonAgentSendControlResponse {
        status: response.status,
        send,
    })
}

pub(crate) fn daemon_agent_exec(
    base: &Path,
    request: DaemonAgentExecRequest,
) -> Result<DaemonAgentExecControlResponse, Box<dyn std::error::Error>> {
    let status = daemon_status_report(base);
    let Some(socket) = status.control_socket.as_deref() else {
        return Err("daemon control socket is not available".into());
    };
    if !status.running {
        return Err("daemon is not running".into());
    }

    let response = query_control_socket_request(
        Path::new(socket),
        &DaemonControlRequest {
            command: "agent_exec".into(),
            since: None,
            limit: None,
            discovery_filter: None,
            agent_send: None,
            agent_exec: Some(request),
            agent_sync_apply: None,
        },
    )?;
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| "daemon agent_exec request failed".into())
            .into());
    }
    let exec = response
        .agent_exec
        .ok_or("daemon agent_exec response did not include exec result")?;
    Ok(DaemonAgentExecControlResponse {
        status: response.status,
        exec,
    })
}

pub(crate) fn daemon_agent_sync_apply(
    base: &Path,
    request: DaemonAgentSyncApplyRequest,
) -> Result<DaemonAgentSyncApplyControlResponse, Box<dyn std::error::Error>> {
    let status = daemon_status_report(base);
    let Some(socket) = status.control_socket.as_deref() else {
        return Err("daemon control socket is not available".into());
    };
    if !status.running {
        return Err("daemon is not running".into());
    }

    let response = query_control_socket_request(
        Path::new(socket),
        &DaemonControlRequest {
            command: "agent_sync_apply".into(),
            since: None,
            limit: None,
            discovery_filter: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: Some(request),
        },
    )?;
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| "daemon agent_sync_apply request failed".into())
            .into());
    }
    let apply = response
        .agent_sync_apply
        .ok_or("daemon agent_sync_apply response did not include apply result")?;
    Ok(DaemonAgentSyncApplyControlResponse {
        status: response.status,
        apply,
    })
}

pub(crate) fn daemon_network_status(
    base: &Path,
    since: Option<u64>,
    limit: Option<usize>,
) -> Result<DaemonNetworkStatusControlResponse, Box<dyn std::error::Error>> {
    let status = daemon_status_report(base);
    let Some(socket) = status.control_socket.as_deref() else {
        return Err("daemon control socket is not available".into());
    };
    if !status.running {
        return Err("daemon is not running".into());
    }

    let response = query_control_socket_request(
        Path::new(socket),
        &DaemonControlRequest {
            command: "network_status".into(),
            since,
            limit,
            discovery_filter: None,
            agent_send: None,
            agent_exec: None,
            agent_sync_apply: None,
        },
    )?;
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| "daemon network_status request failed".into())
            .into());
    }
    let network_status = response
        .network_status
        .ok_or("daemon network_status response did not include diagnostics")?;
    let events = response
        .events
        .ok_or("daemon network_status response did not include events")?;
    Ok(DaemonNetworkStatusControlResponse {
        status: response.status,
        events,
        network_status,
    })
}

#[cfg(unix)]
fn query_control_socket_request(
    socket_path: &Path,
    request: &DaemonControlRequest,
) -> Result<DaemonControlResponse, Box<dyn std::error::Error>> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(DAEMON_CONTROL_TIMEOUT))?;
    stream.set_write_timeout(Some(DAEMON_CONTROL_TIMEOUT))?;
    let data = serde_json::to_vec(request)?;
    if data.len() > DAEMON_CONTROL_REQUEST_MAX_BYTES {
        return Err("daemon control request is too large".into());
    }
    stream.write_all(&data)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reader = stream.take(DAEMON_CONTROL_RESPONSE_MAX_BYTES + 1);
    let mut response = Vec::new();
    reader.read_to_end(&mut response)?;
    if response.len() as u64 > DAEMON_CONTROL_RESPONSE_MAX_BYTES {
        return Err("daemon control response is too large".into());
    }
    Ok(serde_json::from_slice(&response)?)
}

#[cfg(windows)]
fn query_control_socket_request(
    socket_path: &Path,
    request: &DaemonControlRequest,
) -> Result<DaemonControlResponse, Box<dyn std::error::Error>> {
    let socket_path = socket_path.to_path_buf();
    let request = request.clone();
    let run_query = move || -> Result<DaemonControlResponse, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|error| error.to_string())?;
        runtime
            .block_on(query_control_socket_request_windows(socket_path, request))
            .map_err(|error| error.to_string())
    };

    let result = match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(run_query)
        }
        Ok(_) => std::thread::spawn(run_query)
            .join()
            .map_err(|_| "daemon control socket query thread panicked".to_string())?,
        Err(_) => run_query(),
    };
    result.map_err(Into::into)
}

#[cfg(windows)]
async fn query_control_socket_request_windows(
    socket_path: PathBuf,
    request: DaemonControlRequest,
) -> Result<DaemonControlResponse, Box<dyn std::error::Error + Send + Sync>> {
    let data = serde_json::to_vec(&request)?;
    if data.len() > DAEMON_CONTROL_REQUEST_MAX_BYTES {
        return Err("daemon control request is too large".into());
    }

    let mut stream = open_named_pipe_client(&socket_path).await?;
    tokio::time::timeout(DAEMON_CONTROL_TIMEOUT, stream.write_all(&data)).await??;

    let mut response = Vec::new();
    let mut reader = (&mut stream).take(DAEMON_CONTROL_RESPONSE_MAX_BYTES + 1);
    tokio::time::timeout(DAEMON_CONTROL_TIMEOUT, reader.read_to_end(&mut response)).await??;
    if response.len() as u64 > DAEMON_CONTROL_RESPONSE_MAX_BYTES {
        return Err("daemon control response is too large".into());
    }
    Ok(serde_json::from_slice(&response)?)
}

#[cfg(windows)]
async fn open_named_pipe_client(
    socket_path: &Path,
) -> Result<NamedPipeClient, Box<dyn std::error::Error + Send + Sync>> {
    let started = Instant::now();
    loop {
        match ClientOptions::new().open(socket_path) {
            Ok(client) => return Ok(client),
            Err(error)
                if error.raw_os_error() == Some(WINDOWS_ERROR_PIPE_BUSY)
                    && started.elapsed() < DAEMON_CONTROL_TIMEOUT =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn query_control_socket(
    _socket_path: &Path,
    _command: &str,
) -> Result<DaemonControlResponse, Box<dyn std::error::Error>> {
    Err("daemon control socket is unsupported on this platform".into())
}

#[cfg(not(any(unix, windows)))]
fn query_control_socket_request(
    _socket_path: &Path,
    _request: &DaemonControlRequest,
) -> Result<DaemonControlResponse, Box<dyn std::error::Error>> {
    Err("daemon control socket is unsupported on this platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{
        record_workspace_announcement, sign_workspace_announcement, WorkspaceAnnouncement,
        WORKSPACE_ANNOUNCEMENT_VERSION,
    };
    use nexus_core::WorkspaceId;
    use nexus_crypto::NodeIdentity;

    #[test]
    fn daemon_status_reports_absent_state() {
        let temp = tempfile::TempDir::new().unwrap();

        let status = daemon_status_report(temp.path());

        assert!(!status.running);
        assert!(!status.stale);
        assert_eq!(status.pid, None);
        assert!(status.error.is_none());
    }

    #[test]
    fn daemon_status_marks_stale_record() {
        let temp = tempfile::TempDir::new().unwrap();
        let record = DaemonRecord {
            version: DAEMON_RECORD_VERSION,
            base: temp.path().display().to_string(),
            pid: 999_999_999,
            started_at: 123,
            listen: "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            public_defaults_enabled: false,
            bootstrap_peers: Vec::new(),
            stdout_log: "stdout.log".into(),
            stderr_log: "stderr.log".into(),
            control_socket: None,
            command: vec!["nexus-node".into(), "serve".into()],
        };
        save_daemon_record(temp.path(), &record).unwrap();

        let status = daemon_status_report(temp.path());

        assert!(!status.running);
        assert!(status.stale);
        assert_eq!(status.pid, Some(999_999_999));
        assert_eq!(status.started_at, Some(123));
    }

    #[test]
    fn daemon_status_reports_malformed_record() {
        let temp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(daemon_dir(temp.path())).unwrap();
        std::fs::write(daemon_record_path(temp.path()), b"{").unwrap();

        let status = daemon_status_report(temp.path());

        assert!(!status.running);
        assert!(status.error.is_some());
    }

    #[test]
    fn daemon_events_limit_is_positive_and_clamped() {
        assert_eq!(parse_events_limit("1").unwrap(), 1);
        assert_eq!(
            parse_events_limit(&(DAEMON_EVENT_JOURNAL_LIMIT + 1).to_string()).unwrap(),
            DAEMON_EVENT_JOURNAL_LIMIT
        );
        assert!(parse_events_limit("0")
            .unwrap_err()
            .to_string()
            .contains("greater than 0"));
    }

    #[test]
    fn event_journal_is_bounded_and_cursor_filtered() {
        let temp = tempfile::TempDir::new().unwrap();
        let journal = DaemonEventJournalHandle::new();

        for index in 1..=300 {
            journal.push("test_event", format!("event {index}"));
        }

        let latest = journal.snapshot(temp.path(), None, Some(3));
        assert_eq!(latest.schema, "nexus.daemon_events.v1");
        assert_eq!(latest.cursor, 300);
        assert_eq!(latest.limit, 3);
        assert_eq!(
            latest
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![298, 299, 300]
        );

        let since = journal.snapshot(temp.path(), Some(299), Some(10));
        assert_eq!(since.cursor, 300);
        assert_eq!(since.events.len(), 1);
        assert_eq!(since.events[0].summary, "event 300");

        let empty = journal.snapshot(temp.path(), Some(300), Some(10));
        assert_eq!(empty.cursor, 300);
        assert!(empty.events.is_empty());

        let clamped = journal.snapshot(temp.path(), None, Some(usize::MAX));
        assert_eq!(clamped.limit, DAEMON_EVENT_JOURNAL_LIMIT);
        assert_eq!(clamped.events.len(), DAEMON_EVENT_JOURNAL_LIMIT);
        assert_eq!(clamped.events[0].sequence, 45);
        assert_eq!(clamped.events.last().unwrap().sequence, 300);
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn control_socket_reports_status_and_shutdown() {
        let temp = tempfile::TempDir::new().unwrap();
        let socket = daemon_control_socket_path(temp.path());
        let record = DaemonRecord {
            version: DAEMON_RECORD_VERSION,
            base: temp.path().display().to_string(),
            pid: std::process::id(),
            started_at: 456,
            listen: "/ip4/127.0.0.1/udp/0/quic-v1".into(),
            public_defaults_enabled: false,
            bootstrap_peers: Vec::new(),
            stdout_log: "stdout.log".into(),
            stderr_log: "stderr.log".into(),
            control_socket: Some(socket.display().to_string()),
            command: vec!["nexus-node".into(), "serve".into()],
        };
        save_daemon_record(temp.path(), &record).unwrap();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let event_journal = DaemonEventJournalHandle::new();
        event_journal.push("peer_connected", "peer_connected peer=first");
        event_journal.push("social_event", "social_event source=peer events=1 agents=1");
        let handle = spawn_serve_control_socket(
            temp.path().to_path_buf(),
            socket.clone(),
            shutdown_tx,
            event_journal,
            None,
        )
        .unwrap();

        let status_socket = socket.clone();
        let status = tokio::task::spawn_blocking(move || {
            query_control_socket(&status_socket, "status").map_err(|err| err.to_string())
        })
        .await
        .unwrap()
        .unwrap();
        assert!(status.ok);
        assert!(!status.shutdown);
        assert!(status.status.running);
        assert!(status.status.ipc_available);
        assert!(status.events.is_none());

        let owner = NodeIdentity::generate();
        let workspace = WorkspaceId::from_bytes([84; 32]);
        let announcement = WorkspaceAnnouncement {
            version: WORKSPACE_ANNOUNCEMENT_VERSION,
            peer: nexus_network::to_peer_id(&owner).to_string(),
            addrs: vec!["/ip4/127.0.0.1/udp/3100/quic-v1".into()],
            author: owner.did().clone(),
            workspace: workspace.to_string(),
            name: "daemon cache workspace".into(),
            description: "served through agent discover IPC".into(),
            owner: owner.did().clone(),
            root: None,
            timestamp: 77,
            signature: None,
        };
        let signed = sign_workspace_announcement(announcement, &owner).unwrap();
        assert!(record_workspace_announcement(temp.path(), signed).unwrap());
        let discover_socket = socket.clone();
        let discover = tokio::task::spawn_blocking(move || {
            query_control_socket_request(
                &discover_socket,
                &DaemonControlRequest {
                    command: "agent_discover".into(),
                    since: None,
                    limit: None,
                    discovery_filter: Some(DiscoveryFilter {
                        clone_ready_only: true,
                        ..Default::default()
                    }),
                    agent_send: None,
                    agent_exec: None,
                    agent_sync_apply: None,
                },
            )
            .map_err(|err| err.to_string())
        })
        .await
        .unwrap()
        .unwrap();
        assert!(discover.ok);
        assert!(!discover.shutdown);
        assert_eq!(discover.cached_announcements, Some(1));
        let workspaces = discover
            .discovered_workspaces
            .expect("agent discover response should include workspaces");
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].workspace, workspace.to_string());
        assert!(workspaces[0].clone_ready);

        let sync_socket = socket.clone();
        let workspace_filter = workspace.to_string();
        let sync = tokio::task::spawn_blocking(move || {
            query_control_socket_request(
                &sync_socket,
                &DaemonControlRequest {
                    command: "agent_sync".into(),
                    since: None,
                    limit: None,
                    discovery_filter: Some(DiscoveryFilter {
                        workspace: Some(workspace_filter),
                        ..Default::default()
                    }),
                    agent_send: None,
                    agent_exec: None,
                    agent_sync_apply: None,
                },
            )
            .map_err(|err| err.to_string())
        })
        .await
        .unwrap()
        .unwrap();
        assert!(sync.ok);
        assert!(!sync.shutdown);
        assert_eq!(sync.cached_announcements, Some(1));
        let workspaces = sync
            .discovered_workspaces
            .expect("agent sync response should include workspaces");
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].workspace, workspace.to_string());

        let events_socket = socket.clone();
        let events = tokio::task::spawn_blocking(move || {
            query_control_socket_request(
                &events_socket,
                &DaemonControlRequest {
                    command: "events".into(),
                    since: Some(1),
                    limit: Some(10),
                    discovery_filter: None,
                    agent_send: None,
                    agent_exec: None,
                    agent_sync_apply: None,
                },
            )
            .map_err(|err| err.to_string())
        })
        .await
        .unwrap()
        .unwrap();
        assert!(events.ok);
        assert!(!events.shutdown);
        let events = events
            .events
            .expect("events response should include journal");
        assert_eq!(events.cursor, 2);
        assert_eq!(events.events.len(), 1);
        assert_eq!(events.events[0].sequence, 2);
        assert_eq!(events.events[0].kind, "social_event");

        let shutdown_socket = socket.clone();
        let shutdown = tokio::task::spawn_blocking(move || {
            query_control_socket(&shutdown_socket, "shutdown").map_err(|err| err.to_string())
        })
        .await
        .unwrap()
        .unwrap();
        assert!(shutdown.ok);
        assert!(shutdown.shutdown);
        shutdown_rx.changed().await.unwrap();
        assert!(*shutdown_rx.borrow());

        handle.abort();
    }
}
