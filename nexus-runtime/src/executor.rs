//! Process executor — spawns native processes in a workspace directory.
//!
//! Native execution remains the default for an owner's own workspace. Callers
//! can request an isolation profile for foreign or task-derived workspaces; the
//! executor records OS-observed resource usage for billing and auditability.

#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::ExitStatus;
use std::process::Stdio;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(unix))]
use tokio::process::Command;
#[cfg(unix)]
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

use crate::resources::ResourceUsage;

/// Errors that can occur during process execution.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("command not found: {0}")]
    CommandNotFound(String),

    #[error("process exited with code {0}")]
    ExitCode(i32),

    #[error("process terminated by signal")]
    Signalled,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("timeout after {duration:?}")]
    Timeout {
        duration: std::time::Duration,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        resources: ResourceUsage,
    },

    #[error("working directory {requested} escapes workspace root {workspace}")]
    WorkingDirectoryOutsideWorkspace {
        requested: String,
        workspace: String,
    },

    #[error("execution isolation profile {profile} is unavailable: {reason}")]
    IsolationUnavailable { profile: String, reason: String },

    #[error("{0}")]
    Other(String),
}

/// The result of running a process.
#[derive(Clone, Debug)]
pub struct ProcessOutput {
    /// Exit code (0 = success).
    pub exit_code: i32,

    /// Captured stdout.
    pub stdout: Vec<u8>,

    /// Captured stderr.
    pub stderr: Vec<u8>,

    /// Resource consumption during execution.
    pub resources: ResourceUsage,
}

/// Requested process isolation profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecIsolation {
    /// Run as a native process with the executor's cwd/env boundary only.
    #[default]
    Native,
    /// Use the strongest supported local profile. Currently resolves to
    /// bubblewrap on Linux and fails closed when no backend is available.
    Auto,
    /// Run through Linux bubblewrap with only the workspace bound read-write.
    Bubblewrap,
}

impl ExecIsolation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Auto => "auto",
            Self::Bubblewrap => "bubblewrap",
        }
    }
}

/// Options for running a process.
#[derive(Clone, Debug)]
pub struct ExecOptions {
    /// Working directory (defaults to the workspace root).
    pub working_dir: Option<PathBuf>,

    /// Environment variables to set or override.
    pub env: Vec<(String, String)>,

    /// Optional stdin to pipe to the process.
    pub stdin: Option<Vec<u8>>,

    /// Maximum wall-clock time (None = no limit).
    pub timeout: Option<std::time::Duration>,

    /// Capture stdout (true by default).
    pub capture_stdout: bool,

    /// Capture stderr (true by default).
    pub capture_stderr: bool,

    /// Maximum captured stdout bytes. The process still runs freely; excess
    /// bytes are drained and discarded so pipes cannot grow memory without bound.
    pub max_stdout_bytes: Option<usize>,

    /// Maximum captured stderr bytes.
    pub max_stderr_bytes: Option<usize>,

    /// Optional execution isolation profile.
    pub isolation: ExecIsolation,
}

pub const DEFAULT_CAPTURE_LIMIT_BYTES: usize = 16 * 1024 * 1024;

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            working_dir: None,
            env: Vec::new(),
            stdin: None,
            timeout: None,
            capture_stdout: true,
            capture_stderr: true,
            max_stdout_bytes: Some(DEFAULT_CAPTURE_LIMIT_BYTES),
            max_stderr_bytes: Some(DEFAULT_CAPTURE_LIMIT_BYTES),
            isolation: ExecIsolation::Native,
        }
    }
}

#[derive(Debug)]
struct LaunchPlan {
    program: PathBuf,
    args: Vec<String>,
    current_dir: PathBuf,
    environment: LaunchEnvironment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaunchEnvironment {
    Direct,
    #[cfg(target_os = "linux")]
    Wrapper,
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// A native process executor bound to a workspace directory.
///
/// All commands run with `workspace_dir` as the default working directory.
pub struct Executor {
    workspace_dir: PathBuf,
}

impl Executor {
    /// Create a new executor rooted at `workspace_dir`.
    pub fn new(workspace_dir: impl Into<PathBuf>) -> Self {
        Self {
            workspace_dir: workspace_dir.into(),
        }
    }

    /// The workspace directory this executor is bound to.
    pub fn workspace_dir(&self) -> &Path {
        &self.workspace_dir
    }

    /// Run a command and capture all output.
    ///
    /// Spawns a native command and drains output pipes concurrently.
    /// For complex commands (pipes, redirects), pass `["sh", "-c", "<cmd>"]`.
    pub async fn exec(
        &self,
        program: &str,
        args: &[&str],
        options: &ExecOptions,
    ) -> Result<ProcessOutput, ExecError> {
        #[cfg(unix)]
        {
            return self.exec_unix(program, args, options).await;
        }

        #[cfg(not(unix))]
        {
            return self.exec_fallback(program, args, options).await;
        }
    }

    #[cfg(unix)]
    async fn exec_unix(
        &self,
        program: &str,
        args: &[&str],
        options: &ExecOptions,
    ) -> Result<ProcessOutput, ExecError> {
        let working_dir = self
            .resolve_working_dir(options.working_dir.as_deref())
            .map_err(|error| *error)?;
        let workspace_dir = self.workspace_dir.canonicalize().map_err(ExecError::Io)?;
        let launch = launch_plan(&workspace_dir, &working_dir, program, args, options)
            .map_err(|error| *error)?;

        let mut cmd = std::process::Command::new(&launch.program);
        cmd.args(&launch.args);
        cmd.current_dir(&launch.current_dir);
        configure_child_process_group(&mut cmd);

        configure_launch_environment(
            &mut cmd,
            &workspace_dir,
            &working_dir,
            options,
            launch.environment,
        );

        if options.stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        cmd.stdout(if options.capture_stdout {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });
        cmd.stderr(if options.capture_stderr {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });

        let wall_start = Instant::now();

        let mut child = cmd.spawn().map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => ExecError::CommandNotFound(program.to_string()),
            _ => ExecError::Io(err),
        })?;

        let mut process = UnixProcess::new(child.id(), wall_start);
        let mut child_stdin = match child.stdin.take().map(ChildStdin::from_std).transpose() {
            Ok(stdin) => stdin,
            Err(err) => {
                process.terminate_and_finish().await;
                return Err(ExecError::Io(err));
            }
        };
        let stdout_reader = if options.capture_stdout {
            match child.stdout.take().map(ChildStdout::from_std).transpose() {
                Ok(stdout) => {
                    stdout.map(|reader| spawn_output_reader(reader, options.max_stdout_bytes))
                }
                Err(err) => {
                    process.terminate_and_finish().await;
                    return Err(ExecError::Io(err));
                }
            }
        } else {
            None
        };
        let stderr_reader = if options.capture_stderr {
            match child.stderr.take().map(ChildStderr::from_std).transpose() {
                Ok(stderr) => {
                    stderr.map(|reader| spawn_output_reader(reader, options.max_stderr_bytes))
                }
                Err(err) => {
                    process.terminate_and_finish().await;
                    return Err(ExecError::Io(err));
                }
            }
        } else {
            None
        };
        drop(child);

        if let Some(ref stdin_data) = options.stdin {
            if let Some(mut stdin) = child_stdin.take() {
                if let Err(err) = stdin.write_all(stdin_data).await {
                    process.terminate_and_finish().await;
                    return Err(ExecError::Io(err));
                }
                if let Err(err) = stdin.shutdown().await {
                    process.terminate_and_finish().await;
                    return Err(ExecError::Io(err));
                }
            }
        }

        let exit = if let Some(timeout) = options.timeout {
            match tokio::time::timeout(timeout, process.wait_exit()).await {
                Ok(exit) => exit?,
                Err(_) => {
                    let exit = process.terminate().await?;
                    let resources = process.finish_metering(exit).await.resources;
                    return Err(ExecError::Timeout {
                        duration: timeout,
                        stdout: collect_partial_output(stdout_reader).await?,
                        stderr: collect_partial_output(stderr_reader).await?,
                        resources,
                    });
                }
            }
        } else {
            process.wait_exit().await?
        };

        let exit = process.finish_metering(exit).await;
        let exit_code = exit.status.code().unwrap_or(-1);

        Ok(ProcessOutput {
            exit_code,
            stdout: collect_output(stdout_reader).await?,
            stderr: collect_output(stderr_reader).await?,
            resources: exit.resources,
        })
    }

    #[cfg(not(unix))]
    async fn exec_fallback(
        &self,
        program: &str,
        args: &[&str],
        options: &ExecOptions,
    ) -> Result<ProcessOutput, ExecError> {
        let working_dir = self
            .resolve_working_dir(options.working_dir.as_deref())
            .map_err(|error| *error)?;
        let workspace_dir = self.workspace_dir.canonicalize().map_err(ExecError::Io)?;
        let launch = launch_plan(&workspace_dir, &working_dir, program, args, options)
            .map_err(|error| *error)?;

        let mut cmd = Command::new(&launch.program);
        cmd.args(&launch.args);
        cmd.current_dir(&launch.current_dir);
        cmd.kill_on_drop(true);
        configure_child_process_group(&mut cmd);

        configure_launch_environment(
            &mut cmd,
            &workspace_dir,
            &working_dir,
            options,
            launch.environment,
        );

        if options.stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        cmd.stdout(if options.capture_stdout {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });
        cmd.stderr(if options.capture_stderr {
            Stdio::piped()
        } else {
            Stdio::inherit()
        });

        let wall_start = Instant::now();

        let mut child = cmd.spawn().map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => ExecError::CommandNotFound(program.to_string()),
            _ => ExecError::Io(err),
        })?;

        let stdout_reader = if options.capture_stdout {
            child
                .stdout
                .take()
                .map(|reader| spawn_output_reader(reader, options.max_stdout_bytes))
        } else {
            None
        };
        let stderr_reader = if options.capture_stderr {
            child
                .stderr
                .take()
                .map(|reader| spawn_output_reader(reader, options.max_stderr_bytes))
        } else {
            None
        };

        // Feed stdin
        if let Some(ref stdin_data) = options.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(stdin_data).await?;
            }
        }

        let status = if let Some(timeout) = options.timeout {
            match tokio::time::timeout(timeout, child.wait()).await {
                Ok(status) => status.map_err(ExecError::Io)?,
                Err(_) => {
                    terminate_child_tree(&mut child).await;
                    let wall_time = wall_start.elapsed();
                    let resources = ResourceUsage {
                        wall_time,
                        process_count: 1,
                        ..Default::default()
                    };
                    return Err(ExecError::Timeout {
                        duration: timeout,
                        stdout: collect_partial_output(stdout_reader).await?,
                        stderr: collect_partial_output(stderr_reader).await?,
                        resources,
                    });
                }
            }
        } else {
            child.wait().await?
        };

        let wall_time = wall_start.elapsed();

        let exit_code = status.code().unwrap_or(-1);

        let resources = ResourceUsage {
            wall_time,
            process_count: 1,
            ..Default::default()
        };

        Ok(ProcessOutput {
            exit_code,
            stdout: collect_output(stdout_reader).await?,
            stderr: collect_output(stderr_reader).await?,
            resources,
        })
    }

    fn resolve_working_dir(&self, working_dir: Option<&Path>) -> Result<PathBuf, Box<ExecError>> {
        let workspace = self
            .workspace_dir
            .canonicalize()
            .map_err(|error| Box::new(ExecError::Io(error)))?;
        let requested = match working_dir {
            Some(path) if path.is_absolute() => path.to_path_buf(),
            Some(path) => workspace.join(path),
            None => workspace.clone(),
        };
        let resolved = requested
            .canonicalize()
            .map_err(|error| Box::new(ExecError::Io(error)))?;
        if !resolved.starts_with(&workspace) {
            return Err(Box::new(ExecError::WorkingDirectoryOutsideWorkspace {
                requested: requested.display().to_string(),
                workspace: workspace.display().to_string(),
            }));
        }
        Ok(resolved)
    }
}

fn launch_plan(
    workspace_dir: &Path,
    working_dir: &Path,
    program: &str,
    args: &[&str],
    options: &ExecOptions,
) -> Result<LaunchPlan, Box<ExecError>> {
    #[cfg(not(target_os = "linux"))]
    let _ = workspace_dir;

    match options.isolation {
        ExecIsolation::Native => Ok(LaunchPlan {
            program: PathBuf::from(program),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            current_dir: working_dir.to_path_buf(),
            environment: LaunchEnvironment::Direct,
        }),
        ExecIsolation::Auto | ExecIsolation::Bubblewrap => {
            #[cfg(target_os = "linux")]
            {
                bubblewrap_launch_plan(workspace_dir, working_dir, program, args, options)
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(Box::new(ExecError::IsolationUnavailable {
                    profile: options.isolation.as_str().into(),
                    reason: "supported only on Linux in this build".into(),
                }))
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn bubblewrap_launch_plan(
    workspace_dir: &Path,
    working_dir: &Path,
    program: &str,
    args: &[&str],
    options: &ExecOptions,
) -> Result<LaunchPlan, Box<ExecError>> {
    let bwrap = std::env::var_os("NEXUS_BWRAP_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/sbin/bwrap"));

    if !bwrap.exists() {
        return Err(Box::new(ExecError::IsolationUnavailable {
            profile: options.isolation.as_str().into(),
            reason: format!("bubblewrap binary not found at {}", bwrap.display()),
        }));
    }

    const SANDBOX_WORKSPACE: &str = "/workspace";
    let sandbox_working_dir =
        sandbox_path_for_workspace_child(workspace_dir, working_dir, SANDBOX_WORKSPACE)?;
    let mut wrapper_args = vec![
        "--die-with-parent".to_string(),
        "--unshare-all".to_string(),
        "--share-net".to_string(),
        "--chdir".to_string(),
        sandbox_working_dir.clone(),
        "--ro-bind".to_string(),
        "/usr".to_string(),
        "/usr".to_string(),
        "--ro-bind-try".to_string(),
        "/bin".to_string(),
        "/bin".to_string(),
        "--ro-bind-try".to_string(),
        "/sbin".to_string(),
        "/sbin".to_string(),
        "--ro-bind-try".to_string(),
        "/lib".to_string(),
        "/lib".to_string(),
        "--ro-bind-try".to_string(),
        "/lib64".to_string(),
        "/lib64".to_string(),
        "--bind".to_string(),
        workspace_dir.display().to_string(),
        SANDBOX_WORKSPACE.to_string(),
        "--proc".to_string(),
        "/proc".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
        "--tmpfs".to_string(),
        "/tmp".to_string(),
    ];
    append_bubblewrap_env(
        &mut wrapper_args,
        SANDBOX_WORKSPACE,
        &sandbox_working_dir,
        options,
    );
    wrapper_args.extend(["--".to_string(), program.to_string()]);
    wrapper_args.extend(args.iter().map(|arg| (*arg).to_string()));

    Ok(LaunchPlan {
        program: bwrap,
        args: wrapper_args,
        current_dir: PathBuf::from("/"),
        environment: LaunchEnvironment::Wrapper,
    })
}

#[cfg(target_os = "linux")]
fn sandbox_path_for_workspace_child(
    workspace_dir: &Path,
    child: &Path,
    sandbox_workspace: &str,
) -> Result<String, Box<ExecError>> {
    let relative = child.strip_prefix(workspace_dir).map_err(|_| {
        Box::new(ExecError::WorkingDirectoryOutsideWorkspace {
            requested: child.display().to_string(),
            workspace: workspace_dir.display().to_string(),
        })
    })?;
    if relative.as_os_str().is_empty() {
        return Ok(sandbox_workspace.to_string());
    }
    Ok(Path::new(sandbox_workspace)
        .join(relative)
        .display()
        .to_string())
}

fn configure_launch_environment<C: ChildEnvironment>(
    cmd: &mut C,
    workspace_dir: &Path,
    working_dir: &Path,
    options: &ExecOptions,
    environment: LaunchEnvironment,
) {
    match environment {
        LaunchEnvironment::Direct => {
            configure_child_environment(cmd, workspace_dir, working_dir, options)
        }
        #[cfg(target_os = "linux")]
        LaunchEnvironment::Wrapper => {
            cmd.clear_env();
            cmd.set_env("PATH", DEFAULT_EXEC_PATH);
            cmd.set_env("NEXUS_WORKSPACE_ROOT", &workspace_dir.display().to_string());
            cmd.set_env("NEXUS_WORKING_DIR", &working_dir.display().to_string());
            for key in SAFE_INHERITED_ENV_KEYS {
                if let Ok(value) = std::env::var(key) {
                    cmd.set_env(key, &value);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn append_bubblewrap_env(
    wrapper_args: &mut Vec<String>,
    sandbox_workspace: &str,
    sandbox_working_dir: &str,
    options: &ExecOptions,
) {
    wrapper_args.extend([
        "--clearenv".to_string(),
        "--setenv".to_string(),
        "PATH".to_string(),
        DEFAULT_EXEC_PATH.to_string(),
        "--setenv".to_string(),
        "HOME".to_string(),
        sandbox_workspace.to_string(),
        "--setenv".to_string(),
        "PWD".to_string(),
        sandbox_working_dir.to_string(),
        "--setenv".to_string(),
        "NEXUS_WORKSPACE_ROOT".to_string(),
        sandbox_workspace.to_string(),
    ]);

    for key in SAFE_INHERITED_ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            wrapper_args.extend(["--setenv".to_string(), (*key).to_string(), value]);
        }
    }
    for (key, value) in &options.env {
        wrapper_args.extend(["--setenv".to_string(), key.clone(), value.clone()]);
    }
}

const DEFAULT_EXEC_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const SAFE_INHERITED_ENV_KEYS: &[&str] = &["LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ"];

trait ChildEnvironment {
    fn clear_env(&mut self);
    fn set_env(&mut self, key: &str, value: &str);
}

impl ChildEnvironment for std::process::Command {
    fn clear_env(&mut self) {
        self.env_clear();
    }

    fn set_env(&mut self, key: &str, value: &str) {
        self.env(key, value);
    }
}

#[cfg(not(unix))]
impl ChildEnvironment for Command {
    fn clear_env(&mut self) {
        self.env_clear();
    }

    fn set_env(&mut self, key: &str, value: &str) {
        self.env(key, value);
    }
}

fn configure_child_environment<C: ChildEnvironment>(
    cmd: &mut C,
    workspace_dir: &Path,
    working_dir: &Path,
    options: &ExecOptions,
) {
    cmd.clear_env();
    cmd.set_env("PATH", DEFAULT_EXEC_PATH);
    cmd.set_env("HOME", &workspace_dir.display().to_string());
    cmd.set_env("PWD", &working_dir.display().to_string());
    cmd.set_env("NEXUS_WORKSPACE_ROOT", &workspace_dir.display().to_string());

    for key in SAFE_INHERITED_ENV_KEYS {
        if let Ok(value) = std::env::var(key) {
            cmd.set_env(key, &value);
        }
    }

    for (key, value) in &options.env {
        cmd.set_env(key, value);
    }
}

const OUTPUT_READ_CHUNK_SIZE: usize = 8 * 1024;
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_millis(25);

struct OutputReader {
    buffer: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

fn spawn_output_reader<R>(mut reader: R, limit: Option<usize>) -> OutputReader
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let task_buffer = Arc::clone(&buffer);
    let task = tokio::spawn(async move {
        let mut chunk = [0u8; OUTPUT_READ_CHUNK_SIZE];
        loop {
            let bytes_read = reader.read(&mut chunk).await?;
            if bytes_read == 0 {
                break;
            }
            let mut buffer = task_buffer.lock().await;
            let keep = limit
                .map(|limit| limit.saturating_sub(buffer.len()).min(bytes_read))
                .unwrap_or(bytes_read);
            if keep > 0 {
                buffer.extend_from_slice(&chunk[..keep]);
            }
        }
        Ok(())
    });
    OutputReader { buffer, task }
}

#[cfg(unix)]
struct MeteredExit {
    status: ExitStatus,
    resources: ResourceUsage,
}

#[cfg(unix)]
struct UnixProcess {
    pid: u32,
    wait_task: tokio::task::JoinHandle<std::io::Result<MeteredExit>>,
    sampler: ProcessGroupSampler,
}

#[cfg(unix)]
impl UnixProcess {
    fn new(pid: u32, wall_start: Instant) -> Self {
        let wait_task = tokio::task::spawn_blocking(move || wait4_child(pid, wall_start));
        Self {
            pid,
            wait_task,
            sampler: ProcessGroupSampler::start(pid),
        }
    }

    async fn wait_exit(&mut self) -> Result<MeteredExit, ExecError> {
        (&mut self.wait_task)
            .await
            .map_err(|err| ExecError::Other(format!("process wait task failed: {err}")))?
            .map_err(ExecError::Io)
    }

    async fn terminate(&mut self) -> Result<MeteredExit, ExecError> {
        if !self.wait_task.is_finished() {
            unsafe {
                libc::kill(-(self.pid as libc::pid_t), libc::SIGKILL);
            }
        }
        self.wait_exit().await
    }

    async fn terminate_and_finish(&mut self) {
        match self.terminate().await {
            Ok(exit) => {
                let _ = self.finish_metering(exit).await;
            }
            Err(_) => {
                self.sampler.finish().await;
            }
        }
    }

    async fn finish_metering(&mut self, mut exit: MeteredExit) -> MeteredExit {
        let observed = self.sampler.finish().await;
        exit.resources.process_count = observed.process_count;
        exit.resources.fs_read_bytes = observed.fs_read_bytes;
        exit.resources.fs_write_bytes = observed.fs_write_bytes;
        exit
    }
}

#[cfg(unix)]
impl Drop for UnixProcess {
    fn drop(&mut self) {
        if !self.wait_task.is_finished() {
            unsafe {
                libc::kill(-(self.pid as libc::pid_t), libc::SIGKILL);
            }
        }
    }
}

#[cfg(unix)]
fn wait4_child(pid: u32, wall_start: Instant) -> std::io::Result<MeteredExit> {
    loop {
        let mut status = 0;
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        let waited = unsafe { libc::wait4(pid as libc::pid_t, &mut status, 0, usage.as_mut_ptr()) };
        if waited == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        let usage = unsafe { usage.assume_init() };
        return Ok(MeteredExit {
            status: ExitStatus::from_raw(status),
            resources: resource_usage_from_rusage(wall_start.elapsed(), &usage),
        });
    }
}

#[cfg(unix)]
fn resource_usage_from_rusage(wall_time: Duration, usage: &libc::rusage) -> ResourceUsage {
    ResourceUsage {
        wall_time,
        cpu_user: timeval_to_duration(usage.ru_utime),
        cpu_kernel: timeval_to_duration(usage.ru_stime),
        peak_memory: peak_memory_bytes(usage.ru_maxrss),
        fs_read_bytes: 0,
        fs_write_bytes: 0,
        process_count: 1,
    }
}

#[cfg(unix)]
fn timeval_to_duration(value: libc::timeval) -> Duration {
    let secs = value.tv_sec.max(0) as u64;
    let micros = value.tv_usec.max(0) as u32;
    Duration::new(secs, micros.saturating_mul(1_000))
}

#[cfg(unix)]
#[cfg(all(unix, target_os = "linux"))]
fn peak_memory_bytes(kib: libc::c_long) -> Option<u64> {
    (kib > 0).then_some((kib as u64).saturating_mul(1024))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peak_memory_bytes(bytes: libc::c_long) -> Option<u64> {
    (bytes > 0).then_some(bytes as u64)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct ProcessGroupObservation {
    process_count: u64,
    fs_read_bytes: u64,
    fs_write_bytes: u64,
}

#[cfg(unix)]
impl Default for ProcessGroupObservation {
    fn default() -> Self {
        Self {
            process_count: 1,
            fs_read_bytes: 0,
            fs_write_bytes: 0,
        }
    }
}

#[cfg(unix)]
impl ProcessGroupObservation {
    fn add_io(&mut self, io: ProcessIoSample) {
        self.fs_read_bytes = self.fs_read_bytes.saturating_add(io.read_bytes);
        self.fs_write_bytes = self.fs_write_bytes.saturating_add(io.write_bytes);
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default)]
struct ProcessIoSample {
    read_bytes: u64,
    write_bytes: u64,
}

#[cfg(target_os = "linux")]
struct ProcessGroupSampler {
    stop: Arc<AtomicBool>,
    seen: Arc<StdMutex<std::collections::HashMap<u32, ProcessIoSample>>>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(target_os = "linux")]
impl ProcessGroupSampler {
    fn start(pgid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(StdMutex::new(std::collections::HashMap::from([(
            pgid,
            ProcessIoSample::default(),
        )])));
        let task_stop = Arc::clone(&stop);
        let task_seen = Arc::clone(&seen);
        let task = tokio::task::spawn_blocking(move || {
            while !task_stop.load(Ordering::Relaxed) {
                record_process_group_members(pgid, &task_seen);
                std::thread::sleep(Duration::from_millis(10));
            }
            record_process_group_members(pgid, &task_seen);
        });
        Self { stop, seen, task }
    }

    async fn finish(&mut self) -> ProcessGroupObservation {
        self.stop.store(true, Ordering::Relaxed);
        let task = std::mem::replace(&mut self.task, tokio::task::spawn_blocking(|| {}));
        let _ = task.await;
        match self.seen.lock() {
            Ok(seen) => {
                let mut observation = ProcessGroupObservation {
                    process_count: seen.len().max(1) as u64,
                    ..Default::default()
                };
                for io in seen.values().copied() {
                    observation.add_io(io);
                }
                observation
            }
            Err(_) => ProcessGroupObservation::default(),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ProcessGroupSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(target_os = "linux")]
fn record_process_group_members(
    pgid: u32,
    seen: &StdMutex<std::collections::HashMap<u32, ProcessIoSample>>,
) {
    let Ok(proc_entries) = std::fs::read_dir("/proc") else {
        return;
    };
    for entry in proc_entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if process_stat_group(&stat) == Some(pgid) {
            if let Ok(mut seen) = seen.lock() {
                let io = process_io_sample(&entry.path().join("io")).unwrap_or_default();
                seen.entry(pid)
                    .and_modify(|sample| sample.merge(io))
                    .or_insert(io);
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl ProcessIoSample {
    fn merge(&mut self, other: Self) {
        self.read_bytes = self.read_bytes.max(other.read_bytes);
        self.write_bytes = self.write_bytes.max(other.write_bytes);
    }
}

#[cfg(target_os = "linux")]
fn process_io_sample(path: &Path) -> Option<ProcessIoSample> {
    process_io_sample_from_str(&std::fs::read_to_string(path).ok()?)
}

#[cfg(target_os = "linux")]
fn process_io_sample_from_str(io: &str) -> Option<ProcessIoSample> {
    let mut sample = ProcessIoSample::default();
    let mut saw_field = false;
    for line in io.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().parse::<u64>().ok()?;
        match key {
            "read_bytes" => {
                sample.read_bytes = value;
                saw_field = true;
            }
            "write_bytes" => {
                sample.write_bytes = value;
                saw_field = true;
            }
            _ => {}
        }
    }
    saw_field.then_some(sample)
}

#[cfg(target_os = "linux")]
fn process_stat_group(stat: &str) -> Option<u32> {
    let after_comm = stat.rsplit_once(") ")?.1;
    let mut fields = after_comm.split_whitespace();
    fields.next()?;
    fields.next()?;
    fields.next()?.parse().ok()
}

#[cfg(all(unix, not(target_os = "linux")))]
struct ProcessGroupSampler;

#[cfg(all(unix, not(target_os = "linux")))]
impl ProcessGroupSampler {
    fn start(_pgid: u32) -> Self {
        Self
    }

    async fn finish(&mut self) -> ProcessGroupObservation {
        ProcessGroupObservation::default()
    }
}

#[cfg(unix)]
fn configure_child_process_group(cmd: &mut std::process::Command) {
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_child_process_group(cmd: &mut Command) {
    let _ = cmd;
}

#[cfg(not(unix))]
async fn terminate_child_tree(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
}

async fn collect_output(reader: Option<OutputReader>) -> Result<Vec<u8>, ExecError> {
    let Some(reader) = reader else {
        return Ok(Vec::new());
    };

    let OutputReader { buffer, task } = reader;
    task.await
        .map_err(|err| ExecError::Other(format!("output reader failed: {err}")))?
        .map_err(ExecError::Io)?;
    let output = buffer.lock().await.clone();
    Ok(output)
}

async fn collect_partial_output(reader: Option<OutputReader>) -> Result<Vec<u8>, ExecError> {
    let Some(reader) = reader else {
        return Ok(Vec::new());
    };

    let OutputReader { buffer, mut task } = reader;

    tokio::select! {
        result = &mut task => {
            result
                .map_err(|err| ExecError::Other(format!("output reader failed: {err}")))?
                .map_err(ExecError::Io)?;
        }
        _ = tokio::time::sleep(OUTPUT_DRAIN_GRACE) => {
            task.abort();
            match task.await {
                Ok(result) => result.map_err(ExecError::Io)?,
                Err(err) if err.is_cancelled() => {}
                Err(err) => {
                    return Err(ExecError::Other(format!("output reader failed: {err}")));
                }
            }
        }
    }

    let output = buffer.lock().await.clone();
    Ok(output)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exec_echo() {
        let executor = Executor::new("/tmp");
        let opts = ExecOptions::default();

        let result = executor
            .exec("echo", &["-n", "hello nexus"], &opts)
            .await
            .expect("echo must succeed");

        assert_eq!(result.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&result.stdout), "hello nexus");
    }

    #[tokio::test]
    async fn exec_with_env() {
        let executor = Executor::new("/tmp");
        let opts = ExecOptions {
            env: vec![("NEXUS_TEST".into(), "42".into())],
            ..Default::default()
        };

        let result = executor
            .exec("sh", &["-c", "echo $NEXUS_TEST"], &opts)
            .await
            .expect("sh must succeed");

        assert_eq!(result.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), "42");
    }

    #[tokio::test]
    async fn exec_failing_command() {
        let executor = Executor::new("/tmp");
        let opts = ExecOptions::default();

        let result = executor
            .exec("sh", &["-c", "exit 7"], &opts)
            .await
            .expect("process must run (even if it exits non-zero)");

        assert_eq!(result.exit_code, 7);
    }

    #[tokio::test]
    async fn exec_command_not_found() {
        let executor = Executor::new("/tmp");
        let opts = ExecOptions::default();

        let err = executor
            .exec("__nonexistent_command_xyzzy__", &[], &opts)
            .await
            .expect_err("missing commands should be classified");

        assert!(
            matches!(err, ExecError::CommandNotFound(command) if command == "__nonexistent_command_xyzzy__")
        );
    }

    #[tokio::test]
    async fn timeout_preserves_partial_output_and_resources() {
        let executor = Executor::new("/tmp");
        let opts = ExecOptions {
            timeout: Some(std::time::Duration::from_millis(100)),
            ..Default::default()
        };

        let err = executor
            .exec(
                "sh",
                &["-c", "printf partial-out; printf partial-err >&2; sleep 1"],
                &opts,
            )
            .await
            .expect_err("timeout should return captured evidence");

        match err {
            ExecError::Timeout {
                stdout,
                stderr,
                resources,
                ..
            } => {
                assert_eq!(stdout, b"partial-out");
                assert_eq!(stderr, b"partial-err");
                assert_eq!(resources.process_count, 1);
                assert!(resources.wall_time.as_millis() >= 50);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test]
    async fn timeout_is_not_delayed_by_descendant_inherited_stdout() {
        let executor = Executor::new("/tmp");
        let opts = ExecOptions {
            timeout: Some(std::time::Duration::from_millis(100)),
            ..Default::default()
        };
        let start = Instant::now();

        let err = executor
            .exec(
                "sh",
                &[
                    "-c",
                    "printf ready; (sleep 1) & while true; do sleep 1; done",
                ],
                &opts,
            )
            .await
            .expect_err("timeout should not wait for descendant pipe EOF");

        assert!(
            start.elapsed() < Duration::from_millis(750),
            "timeout returned too slowly"
        );
        assert!(matches!(
            err,
            ExecError::Timeout { stdout, .. } if stdout == b"ready"
        ));
    }

    #[tokio::test]
    async fn exec_with_stdin() {
        let executor = Executor::new("/tmp");
        let opts = ExecOptions {
            stdin: Some(b"hello from stdin".to_vec()),
            ..Default::default()
        };

        let result = executor
            .exec("cat", &[], &opts)
            .await
            .expect("cat must succeed");

        assert_eq!(result.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&result.stdout), "hello from stdin");
    }

    #[tokio::test]
    async fn captured_output_is_bounded_while_pipe_is_drained() {
        let executor = Executor::new("/tmp");
        let opts = ExecOptions {
            max_stdout_bytes: Some(8),
            ..Default::default()
        };

        let result = executor
            .exec("sh", &["-c", "printf 1234567890"], &opts)
            .await
            .expect("command should complete");

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, b"12345678");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_descendant_process_group() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let marker = temp.path().join("leaked.txt");
        let executor = Executor::new(temp.path());
        let opts = ExecOptions {
            timeout: Some(std::time::Duration::from_millis(50)),
            ..Default::default()
        };
        let command = format!("(sleep 0.4; echo leaked > '{}') & wait", marker.display());

        let err = executor
            .exec("sh", &["-c", &command], &opts)
            .await
            .expect_err("command should time out");
        assert!(matches!(err, ExecError::Timeout { .. }));

        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(!marker.exists(), "descendant process survived timeout");
    }

    #[tokio::test]
    async fn relative_working_dir_resolves_inside_workspace() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        std::fs::create_dir(temp.path().join("sub")).expect("subdir");
        std::fs::write(temp.path().join("sub/input.txt"), b"relative cwd").expect("input");
        let executor = Executor::new(temp.path());
        let opts = ExecOptions {
            working_dir: Some(PathBuf::from("sub")),
            ..Default::default()
        };

        let result = executor
            .exec("cat", &["input.txt"], &opts)
            .await
            .expect("cat must succeed from relative cwd");

        assert_eq!(result.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&result.stdout), "relative cwd");
    }

    #[tokio::test]
    async fn working_dir_cannot_escape_workspace_with_parent_component() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let executor = Executor::new(temp.path());
        let opts = ExecOptions {
            working_dir: Some(PathBuf::from("..")),
            ..Default::default()
        };

        let err = executor
            .exec("true", &[], &opts)
            .await
            .expect_err("parent cwd should be rejected");

        assert!(matches!(
            err,
            ExecError::WorkingDirectoryOutsideWorkspace { .. }
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn working_dir_cannot_escape_workspace_through_symlink() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let outside = tempfile::TempDir::new().expect("outside dir");
        std::os::unix::fs::symlink(outside.path(), temp.path().join("outside-link"))
            .expect("symlink");
        let executor = Executor::new(temp.path());
        let opts = ExecOptions {
            working_dir: Some(PathBuf::from("outside-link")),
            ..Default::default()
        };

        let err = executor
            .exec("true", &[], &opts)
            .await
            .expect_err("symlinked cwd should be rejected");

        assert!(matches!(
            err,
            ExecError::WorkingDirectoryOutsideWorkspace { .. }
        ));
    }

    #[tokio::test]
    async fn child_environment_is_whitelisted_and_explicit() {
        std::env::set_var("NEXUS_SECRET_TEST", "should-not-leak");
        let temp = tempfile::TempDir::new().expect("temp dir");
        let executor = Executor::new(temp.path());
        let opts = ExecOptions {
            env: vec![("NEXUS_ALLOWED".into(), "visible".into())],
            ..Default::default()
        };

        let result = executor
            .exec(
                "sh",
                &[
                    "-c",
                    "printf '%s|%s|%s' \"$NEXUS_ALLOWED\" \"${NEXUS_SECRET_TEST-unset}\" \"$HOME\"",
                ],
                &opts,
            )
            .await
            .expect("env command should succeed");

        std::env::remove_var("NEXUS_SECRET_TEST");
        let output = String::from_utf8_lossy(&result.stdout);
        let parts = output.split('|').collect::<Vec<_>>();
        assert_eq!(
            parts,
            vec!["visible", "unset", temp.path().to_str().unwrap()]
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bubblewrap_isolation_runs_with_only_workspace_writable() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let executor = Executor::new(temp.path());
        let opts = ExecOptions {
            isolation: ExecIsolation::Bubblewrap,
            env: vec![("NEXUS_ALLOWED".into(), "visible".into())],
            ..Default::default()
        };

        let result = executor
            .exec(
                "sh",
                &[
                    "-c",
                    "echo workspace > output.txt && printf '%s|%s|%s' \"$NEXUS_ALLOWED\" \"${HOME}\" \"${NEXUS_WORKSPACE_ROOT}\"",
                ],
                &opts,
            )
            .await
            .expect("bubblewrap command should run");

        assert_eq!(result.exit_code, 0);
        assert_eq!(
            std::fs::read(temp.path().join("output.txt")).expect("workspace output"),
            b"workspace\n"
        );
        let output = String::from_utf8_lossy(&result.stdout);
        let parts = output.split('|').collect::<Vec<_>>();
        assert_eq!(parts, vec!["visible", "/workspace", "/workspace"]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bubblewrap_isolation_hides_host_home_paths() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let outside = tempfile::TempDir::new().expect("outside dir");
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, b"host-secret").expect("secret");
        let executor = Executor::new(temp.path());
        let opts = ExecOptions {
            isolation: ExecIsolation::Bubblewrap,
            ..Default::default()
        };
        let command = format!(
            "if cat '{}' >/dev/null 2>&1; then printf leaked; else printf blocked; fi",
            secret.display()
        );

        let result = executor
            .exec("sh", &["-c", &command], &opts)
            .await
            .expect("sandboxed command should complete");

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, b"blocked");
    }

    #[tokio::test]
    async fn resources_are_tracked() {
        let executor = Executor::new("/tmp");
        let opts = ExecOptions::default();

        let result = executor
            .exec("sleep", &["0.1"], &opts)
            .await
            .expect("sleep must succeed");

        assert!(result.resources.wall_time.as_millis() >= 50);
        assert_eq!(result.resources.process_count, 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resources_include_os_observed_usage() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let executor = Executor::new(temp.path());
        let opts = ExecOptions::default();

        let result = executor
            .exec(
                "sh",
                &[
                    "-c",
                    "dd if=/dev/zero of=usage.bin bs=1024 count=32 >/dev/null 2>&1",
                ],
                &opts,
            )
            .await
            .expect("dd must succeed");

        assert_eq!(result.exit_code, 0);
        assert!(
            result.resources.cpu_user + result.resources.cpu_kernel > Duration::ZERO,
            "expected wait4 to report non-zero cpu time"
        );
        assert!(
            result.resources.peak_memory.is_some(),
            "expected wait4 to report peak resident set size"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn process_count_includes_observed_descendants() {
        let executor = Executor::new("/tmp");
        let opts = ExecOptions::default();

        let result = executor
            .exec("sh", &["-c", "(sleep 0.05) & wait"], &opts)
            .await
            .expect("shell command must succeed");

        assert!(
            result.resources.process_count >= 2,
            "expected process group sampler to observe the shell and its child"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_process_io_sample() {
        let sample = process_io_sample_from_str(
            "rchar: 123\nwchar: 456\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 0\n",
        )
        .expect("io sample");

        assert_eq!(sample.read_bytes, 4096);
        assert_eq!(sample.write_bytes, 8192);
    }
}
