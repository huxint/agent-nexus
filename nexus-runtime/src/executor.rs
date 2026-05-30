//! Process executor — spawns native processes in a workspace directory.
//!
//! No sandboxing, no restrictions.  The executor tracks resource usage
//! for billing but does not enforce limits.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
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
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            working_dir: None,
            env: Vec::new(),
            stdin: None,
            timeout: None,
            capture_stdout: true,
            capture_stderr: true,
        }
    }
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
    /// Uses `tokio::process::Command` and drains output pipes concurrently.
    /// For complex commands (pipes, redirects), pass `["sh", "-c", "<cmd>"]`.
    pub async fn exec(
        &self,
        program: &str,
        args: &[&str],
        options: &ExecOptions,
    ) -> Result<ProcessOutput, ExecError> {
        let working_dir = self.resolve_working_dir(options.working_dir.as_deref());

        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.current_dir(&working_dir);
        cmd.kill_on_drop(true);

        for (key, value) in &options.env {
            cmd.env(key, value);
        }

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
            child.stdout.take().map(spawn_output_reader)
        } else {
            None
        };
        let stderr_reader = if options.capture_stderr {
            child.stderr.take().map(spawn_output_reader)
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
                    let _ = child.kill().await;
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

        // Approximate resource usage from /proc if available (Linux-only)
        // For now, we just track wall time.
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

    fn resolve_working_dir(&self, working_dir: Option<&Path>) -> PathBuf {
        match working_dir {
            Some(path) if path.is_absolute() => path.to_path_buf(),
            Some(path) => self.workspace_dir.join(path),
            None => self.workspace_dir.clone(),
        }
    }
}

const OUTPUT_READ_CHUNK_SIZE: usize = 8 * 1024;
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_millis(25);

struct OutputReader {
    buffer: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

fn spawn_output_reader<R>(mut reader: R) -> OutputReader
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
            task_buffer
                .lock()
                .await
                .extend_from_slice(&chunk[..bytes_read]);
        }
        Ok(())
    });
    OutputReader { buffer, task }
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
}
