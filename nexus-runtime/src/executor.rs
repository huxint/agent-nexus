//! Process executor — spawns native processes in a workspace directory.
//!
//! No sandboxing, no restrictions.  The executor tracks resource usage
//! for billing but does not enforce limits.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

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

    #[error("timeout after {0:?}")]
    Timeout(std::time::Duration),

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
    /// Uses `tokio::process::Command` with `wait_with_output()` internally.
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

        let mut child = cmd.spawn()?;

        // Feed stdin
        if let Some(ref stdin_data) = options.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(stdin_data).await?;
            }
        }

        let output = if let Some(timeout) = options.timeout {
            tokio::time::timeout(timeout, child.wait_with_output())
                .await
                .map_err(|_| ExecError::Timeout(timeout))?
                .map_err(ExecError::Io)?
        } else {
            child.wait_with_output().await?
        };

        let wall_time = wall_start.elapsed();

        let exit_code = output.status.code().unwrap_or(-1);

        // Approximate resource usage from /proc if available (Linux-only)
        // For now, we just track wall time.
        let resources = ResourceUsage {
            wall_time,
            process_count: 1,
            ..Default::default()
        };

        Ok(ProcessOutput {
            exit_code,
            stdout: output.stdout,
            stderr: output.stderr,
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
            .await;

        assert!(err.is_err());
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
