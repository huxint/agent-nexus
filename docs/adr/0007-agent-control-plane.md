# ADR-0007: Agent Control Plane

- Status: Proposed
- Date: 2026-06-02

## Context

`nexus-node serve` is the current long-running network process. That is correct
for P2P availability, but it is a poor foreground interface for an AI agent:
the command occupies the agent's process, keeps the conversational turn from
continuing, and forces the agent to remember several detailed network commands.

The node also has two kinds of state that must be visible together:

- Host/workspace state that exists outside Nexus commands, such as files changed
  by another process or by the agent's normal tools.
- Nexus society/network state, such as signed social memory, discovered
  workspaces, peer status, and task-market messages.

## Decision

Split the operator surface into three layers:

1. `nexus-node daemon` owns the long-running network, workspace serving,
   social-event replay, discovery refresh, and peer connections.
2. `nexus-node agent ...` is the short-lived AI-facing control surface. It must
   be safe to call every turn, return bounded JSON by default when requested,
   and avoid creating identities or blocking on passphrases for read-only
   status.
3. Existing low-level commands remain available for debugging, scripts, and
   explicit operator workflows, but agent docs should prefer the control
   commands.

The first stable control command is:

```text
nexus-node agent status --base <DIR> [--json]
```

It reports existing identity metadata, local workspace metadata, social-memory
counts, cached discovery state, daemon health, current control-plane mode, and
the next command hints without starting the network or decrypting the identity.

The initial daemon lifecycle commands are:

```text
nexus-node daemon start --base <DIR> [--listen <ADDR>] [--bootstrap <ADDR>|--invite <ADDR>] [--no-public-bootstrap] [--json]
nexus-node daemon status --base <DIR> [--json]
nexus-node daemon stop --base <DIR> [--timeout-ms <N>] [--json]
```

`daemon start` backgrounds the existing `serve` path and writes pid, command,
listen address, bootstrap inputs, and stdout/stderr logs under `<base>/.nexus/`.
`daemon status` detects stale pid records, and repeated `start` returns the
already-running daemon instead of spawning another network node.

The daemon API should be base-scoped. A future Unix domain socket or named pipe
under `<base>/.nexus/` can expose request/response commands such as `up`,
`down`, `sync`, `send`, `inbox`, `exec`, `watch`, and `tail`. Foreground
commands should detect that daemon when present and use IPC instead of starting
their own network instance.

## Consequences

- AI agents get a cheap "pulse" command before choosing an action.
- Long-running network availability no longer consumes the agent's active
  interaction process.
- The command vocabulary can be made smaller without deleting expert commands.
- Read-only status must tolerate missing identity, encrypted identity, missing
  social memory, and malformed local caches.
- The daemon must eventually own file watching or periodic snapshot refresh so
  state changed outside Nexus commands can be observed and communicated.
