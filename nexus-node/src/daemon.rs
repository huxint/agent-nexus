use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

use crate::bootstrap::extend_bootstrap_peers;
use crate::cli_args::{parse_u64_arg, required_arg};
use crate::state::write_file_atomic;
use crate::unix_now;

const DAEMON_RECORD_VERSION: u32 = 2;
const DEFAULT_DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_CONTROL_REQUEST_MAX_BYTES: usize = 16 * 1024;
const DAEMON_CONTROL_RESPONSE_MAX_BYTES: u64 = 64 * 1024;
const DAEMON_CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
const DAEMON_START_READY_TIMEOUT: Duration = Duration::from_secs(2);

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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DaemonControlResponse {
    ok: bool,
    shutdown: bool,
    status: DaemonStatusReport,
    error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct DaemonStartOptions {
    pub(crate) base: PathBuf,
    pub(crate) listen: String,
    pub(crate) bootstrap_peers: Vec<libp2p::Multiaddr>,
    pub(crate) use_public_bootstrap: bool,
    pub(crate) json: bool,
}

pub(crate) fn cmd_daemon(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.get(2).map(String::as_str) {
        Some("start") => cmd_daemon_start(args),
        Some("status") => cmd_daemon_status(args),
        Some("stop") => cmd_daemon_stop(args),
        Some(other) => Err(format!("unknown daemon subcommand: {other}").into()),
        None => Err("daemon subcommand required: start, status, or stop".into()),
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
    #[cfg(unix)]
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

fn daemon_control_socket_path(base: &Path) -> PathBuf {
    daemon_dir(base).join("daemon.sock")
}

#[cfg(unix)]
fn control_socket_for_record(path: &Path) -> Option<String> {
    Some(path.display().to_string())
}

#[cfg(not(unix))]
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
            tokio::spawn(async move {
                handle_control_stream(stream, base, shutdown_tx).await;
            });
        }
    });
    Ok(handle)
}

#[cfg(not(unix))]
pub(crate) fn spawn_serve_control_socket(
    _base: PathBuf,
    _socket_path: PathBuf,
    _shutdown_tx: watch::Sender<bool>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    Err("daemon control socket is unsupported on this platform".into())
}

#[cfg(unix)]
async fn handle_control_stream(
    mut stream: UnixStream,
    base: PathBuf,
    shutdown_tx: watch::Sender<bool>,
) {
    let response = match read_control_request(&mut stream).await {
        Ok(request) => match request.command.as_str() {
            "status" => DaemonControlResponse {
                ok: true,
                shutdown: false,
                status: daemon_control_status(&base),
                error: None,
            },
            "shutdown" => DaemonControlResponse {
                ok: true,
                shutdown: true,
                status: daemon_control_status(&base),
                error: None,
            },
            other => DaemonControlResponse {
                ok: false,
                shutdown: false,
                status: daemon_control_status(&base),
                error: Some(format!("unknown daemon control command: {other}")),
            },
        },
        Err(error) => DaemonControlResponse {
            ok: false,
            shutdown: false,
            status: daemon_control_status(&base),
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

#[cfg(unix)]
async fn read_control_request(
    stream: &mut UnixStream,
) -> Result<DaemonControlRequest, Box<dyn std::error::Error>> {
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

#[cfg(unix)]
fn query_control_socket(
    socket_path: &Path,
    command: &str,
) -> Result<DaemonControlResponse, Box<dyn std::error::Error>> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(DAEMON_CONTROL_TIMEOUT))?;
    stream.set_write_timeout(Some(DAEMON_CONTROL_TIMEOUT))?;
    let request = serde_json::to_vec(&DaemonControlRequest {
        command: command.to_string(),
    })?;
    if request.len() > DAEMON_CONTROL_REQUEST_MAX_BYTES {
        return Err("daemon control request is too large".into());
    }
    stream.write_all(&request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reader = stream.take(DAEMON_CONTROL_RESPONSE_MAX_BYTES + 1);
    let mut response = Vec::new();
    reader.read_to_end(&mut response)?;
    if response.len() as u64 > DAEMON_CONTROL_RESPONSE_MAX_BYTES {
        return Err("daemon control response is too large".into());
    }
    Ok(serde_json::from_slice(&response)?)
}

#[cfg(not(unix))]
fn query_control_socket(
    _socket_path: &Path,
    _command: &str,
) -> Result<DaemonControlResponse, Box<dyn std::error::Error>> {
    Err("daemon control socket is unsupported on this platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(unix)]
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
        let handle =
            spawn_serve_control_socket(temp.path().to_path_buf(), socket.clone(), shutdown_tx)
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
