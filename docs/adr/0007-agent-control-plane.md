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

The first stable control commands are:

```text
nexus-node agent status --base <DIR> [--json]
nexus-node agent up --base <DIR> [--listen <ADDR>] [--bootstrap <ADDR>|--invite <ADDR>] [--no-public-bootstrap] [--json]
nexus-node agent inbox --base <DIR> [--agent <DID>] [--since <TS>] [--limit <N>] [--json]
nexus-node agent discover --base <DIR> [--json] [--verified] [--clone-ready] ...
nexus-node agent send --base <DIR> [--kind <goal|need|offer|proposal|status>] --title <TEXT> [--body <TEXT>] [--json]
nexus-node agent exec --base <DIR> --workspace <PATH> [--json] -- <CMD> [ARG...]
nexus-node agent sync --base <DIR> [--workspace <HEX>] [--name <TEXT>] [--json]
```

`agent status` reports existing identity metadata, local workspace metadata,
social-memory counts, cached discovery state, daemon health, current
control-plane mode, and the next command hints without starting the network or
decrypting the identity. `agent up` is the AI-facing startup verb over
`daemon start`; it may start the background `serve` process and therefore uses
the same non-interactive passphrase requirements as daemon start. `agent inbox`
builds a bounded local "what needs attention" summary from daemon alerts,
society intent recommendations, open or assigned tasks, and clone-ready
discovery cache entries. It is also read-only: it does not start networking,
create identities, or decrypt the identity key.
`agent discover` exposes the same cached workspace-discovery projection under
the short-lived agent namespace. It rejects online refresh flags; operators can
still use top-level `discover --lan` or `discover --global` until daemon-backed
routing owns refreshes. `agent send` writes a signed intent/status social event
to local social memory and returns `nexus.agent_send.v1` delivery metadata. It
does not yet inject the event into a running daemon; daemon-backed live send is
part of the pending IPC route. `agent exec` is the short-command entry point for
free workspace execution. It reuses the existing `exec` semantics for process
execution, output capture, workspace snapshotting, and signed social-memory
recording, then returns `nexus.agent_exec.v1`. It does not yet execute inside
the daemon; daemon-backed exec routing is part of the pending IPC route.
`agent sync` is the AI-facing sync planning verb. It reads local workspace
metadata and cached workspace discovery, returns `nexus.agent_sync.v1`, and
suggests explicit `clone`, `discover`, or daemon-start commands. It does not
start a short-lived network node or create/decrypt identity; daemon-backed live
sync remains part of the pending IPC route.

The initial daemon lifecycle commands are:

```text
nexus-node daemon start --base <DIR> [--listen <ADDR>] [--bootstrap <ADDR>|--invite <ADDR>] [--no-public-bootstrap] [--json]
nexus-node daemon status --base <DIR> [--json]
nexus-node daemon stop --base <DIR> [--timeout-ms <N>] [--json]
```

`daemon start` backgrounds the existing `serve` path and writes pid, command,
listen address, bootstrap inputs, stdout/stderr logs, and the Unix control
socket path under `<base>/.nexus/`. `daemon status` detects stale pid records
and, when available, asks the control socket for live status. `daemon stop`
prefers the control socket `shutdown` request before falling back to process
termination. Repeated `start` returns the already-running daemon instead of
spawning another network node.

The daemon API should be base-scoped. A future Unix domain socket or named pipe
under `<base>/.nexus/` can expose additional request/response commands such as
`sync`, `send`, daemon-backed `inbox`, `exec`, `watch`, and `tail`. Foreground
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
