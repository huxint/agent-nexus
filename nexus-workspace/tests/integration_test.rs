//! End-to-end integration test: create → write → exec → snapshot → read.
//!
//! This test exercises the full lifecycle of a workspace as an AI would
//! experience it — treating it as "a computer" where you can write files,
//! run commands, and version your state.

use nexus_core::PermissionSet;
use nexus_crypto::NodeIdentity;
use nexus_runtime::ExecOptions;
use nexus_workspace::{Workspace, WorkspaceConfig};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helper: create a workspace owned by a fresh identity
// ---------------------------------------------------------------------------

async fn create_test_workspace(name: &str) -> (Workspace, NodeIdentity, TempDir) {
    let owner = NodeIdentity::generate();
    let base = TempDir::new().unwrap();
    let config = WorkspaceConfig {
        name: name.into(),
        description: "Integration test workspace".into(),
    };
    let ws = Workspace::create(&owner, base.path(), config)
        .await
        .expect("create workspace");
    (ws, owner, base)
}

// ---------------------------------------------------------------------------
// Scenario 1: AI writes a Python script and runs it
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_python_script_execution() {
    let (mut ws, _owner, _base) = create_test_workspace("python-test").await;

    // Step 1: Write a Python script
    let script = r#"
import json
result = {"message": "hello from python", "sum": sum(range(10))}
print(json.dumps(result))
"#;
    ws.write_file("compute.py", script.as_bytes())
        .expect("write script");

    // Step 2: Execute it
    let opts = ExecOptions::default();
    let output = ws.exec("python3", &["compute.py"], &opts).await;

    // Python3 may not be installed; fall back to python
    let output = match output {
        Ok(o) => o,
        Err(_) => ws
            .exec("python", &["compute.py"], &opts)
            .await
            .expect("exec python"),
    };

    // Step 3: Verify output
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello from python"), "got: {stdout}");
    assert!(stdout.contains("\"sum\": 45"), "got: {stdout}");
    assert_eq!(output.exit_code, 0);
}

// ---------------------------------------------------------------------------
// Scenario 2: Shell scripting and file I/O
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_shell_script_io() {
    let (mut ws, _owner, _base) = create_test_workspace("shell-test").await;

    // Write a shell script that creates output
    ws.write_file(
        "generate.sh",
        b"#!/bin/sh\nfor i in 1 2 3 4 5; do echo \"line $i\"; done > output.txt",
    )
    .expect("write script");

    let opts = ExecOptions::default();
    ws.exec("sh", &["generate.sh"], &opts)
        .await
        .expect("exec script");

    // Read the generated output
    let data = ws.read_file("output.txt").expect("read output");
    let text = String::from_utf8_lossy(&data);
    assert!(text.contains("line 1"));
    assert!(text.contains("line 5"));
}

// ---------------------------------------------------------------------------
// Scenario 3: Versioning with snapshots
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_versioning() {
    let (mut ws, _owner, _base) = create_test_workspace("versioning-test").await;

    // Version 1: single file
    ws.write_file("v1.txt", b"version one").unwrap();
    let cid_v1 = ws.snapshot().await.expect("snapshot v1");

    // Version 2: two files
    ws.write_file("v2.txt", b"version two").unwrap();
    let cid_v2 = ws.snapshot().await.expect("snapshot v2");

    // Version 3: modify existing file
    ws.write_file("v1.txt", b"version one - modified").unwrap();
    let cid_v3 = ws.snapshot().await.expect("snapshot v3");

    // All snapshots must be different
    assert_ne!(cid_v1, cid_v2);
    assert_ne!(cid_v2, cid_v3);
    assert_ne!(cid_v1, cid_v3);

    // Root CID always points to latest
    assert_eq!(ws.root_cid().unwrap(), cid_v3);
}

// ---------------------------------------------------------------------------
// Scenario 4: Multi-agent collaboration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_multi_agent_collaboration() {
    let owner = NodeIdentity::generate();
    let alice = NodeIdentity::generate();
    let bob = NodeIdentity::generate();
    let base = TempDir::new().unwrap();

    let config = WorkspaceConfig {
        name: "collab-test".into(),
        description: "Multi-agent test".into(),
    };

    let mut ws = Workspace::create(&owner, base.path(), config)
        .await
        .expect("create");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Owner grants Alice READ_WRITE, Bob READ_ONLY
    let cap_alice = nexus_crypto::capability::sign_capability(
        &owner,
        alice.did(),
        ws.id(),
        PermissionSet::READ_WRITE,
        now + 3600,
    )
    .expect("sign alice cap");

    let cap_bob = nexus_crypto::capability::sign_capability(
        &owner,
        bob.did(),
        ws.id(),
        PermissionSet::READ_ONLY,
        now + 3600,
    )
    .expect("sign bob cap");

    // Both present their capabilities
    ws.admit_guest(alice.did(), &cap_alice, now)
        .expect("admit alice");
    ws.admit_guest(bob.did(), &cap_bob, now).expect("admit bob");

    assert_eq!(ws.guests().len(), 2);

    // Capabilities are social credentials; local workspace operations are not
    // permission gated.
    assert!(ws.check_permission(alice.did(), &PermissionSet::READ_WRITE));
    assert!(ws.check_permission(alice.did(), &PermissionSet::READ_ONLY));
    assert!(ws.check_permission(bob.did(), &PermissionSet::READ_ONLY));
    assert!(ws.check_permission(bob.did(), &PermissionSet::READ_WRITE));
    assert!(ws.check_permission(bob.did(), &PermissionSet::FULL));

    // Owner always has full access
    assert!(ws.check_permission(owner.did(), &PermissionSet::FULL));

    // Revoke Bob
    ws.revoke_guest(bob.did()).expect("revoke bob");
    assert_eq!(ws.guests().len(), 1);
    assert!(!ws.check_permission(bob.did(), &PermissionSet::READ_ONLY));
}

// ---------------------------------------------------------------------------
// Scenario 5: Workspace persistence (create → load → verify)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_persistence() {
    let owner = NodeIdentity::generate();
    let base = TempDir::new().unwrap();

    let config = WorkspaceConfig {
        name: "persist-test".into(),
        description: "Persistence test".into(),
    };

    let mut ws = Workspace::create(&owner, base.path(), config)
        .await
        .expect("create");

    // Write some content
    ws.write_file("data.txt", b"persistent data").unwrap();
    ws.write_file("sub/nested.txt", b"nested").unwrap();

    // Execute something that creates output
    let opts = ExecOptions::default();
    ws.exec("sh", &["-c", "echo 'runtime output' > runtime.txt"], &opts)
        .await
        .expect("exec");

    // Snapshot
    ws.snapshot().await.expect("snapshot");

    // Remember the root dir
    let root_dir = ws.root_dir().to_path_buf();
    let ws_id = ws.id();

    // "Restart" — load from disk
    drop(ws);
    let ws2 = Workspace::load(&owner, &root_dir).await.expect("load");

    // Verify identity
    assert_eq!(ws2.id(), ws_id);

    // Verify files survived
    let data = ws2.read_file("data.txt").expect("read data.txt");
    assert_eq!(data, b"persistent data");

    let nested = ws2.read_file("sub/nested.txt").expect("read nested");
    assert_eq!(nested, b"nested");

    // Runtime output survives (it's just a file)
    let runtime = ws2.read_file("runtime.txt").expect("read runtime.txt");
    assert_eq!(String::from_utf8_lossy(&runtime).trim(), "runtime output");
}

// ---------------------------------------------------------------------------
// Scenario 6: Resource tracking across multiple executions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scenario_resource_tracking() {
    let (mut ws, _owner, _base) = create_test_workspace("resource-test").await;

    let opts = ExecOptions::default();

    // Run several commands
    for _ in 0..5 {
        ws.exec("true", &[], &opts).await.expect("exec true");
    }

    assert_eq!(ws.total_resources().process_count, 5);
    assert!(ws.total_resources().wall_time.as_nanos() > 0);
}
