use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::bootstrap::extend_bootstrap_peers;
use crate::cli_args::{parse_u64_arg, required_arg};
use crate::state::write_file_atomic;
use crate::unix_now;

const DAEMON_RECORD_VERSION: u32 = 1;
const DEFAULT_DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct DaemonStatusReport {
    pub(crate) schema: &'static str,
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
    pub(crate) command: Vec<String>,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct DaemonStartReport {
    started: bool,
    status: DaemonStatusReport,
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
    command: Vec<String>,
}

#[derive(Clone, Debug)]
struct DaemonStartOptions {
    base: PathBuf,
    listen: String,
    bootstrap_peers: Vec<libp2p::Multiaddr>,
    use_public_bootstrap: bool,
    json: bool,
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
    let state_path = daemon_record_path(base);
    let Ok(record) = load_daemon_record(base) else {
        return DaemonStatusReport {
            schema: "nexus.daemon_status.v1",
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
            command: Vec::new(),
            error: read_daemon_record_error(base),
        };
    };

    let running = is_process_running(record.pid);
    DaemonStatusReport {
        schema: "nexus.daemon_status.v1",
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
        command: record.command,
        error: None,
    }
}

fn start_daemon(
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
        command: std::iter::once(exe.display().to_string())
            .chain(command_args)
            .collect(),
    };
    save_daemon_record(&options.base, &record)?;

    Ok(DaemonStartReport {
        started: true,
        status: daemon_status_report(&options.base),
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

    terminate_process(pid)?;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !is_process_running(pid) {
            remove_daemon_record(base)?;
            return Ok(DaemonStopReport {
                stopped: true,
                stale_removed: false,
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
    if record.version != DAEMON_RECORD_VERSION {
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
}
