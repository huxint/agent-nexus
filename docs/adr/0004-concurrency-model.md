# ADR-0004: Concurrency Model

- Status: Proposed
- Date: 2026-06-01

## Context

The design document describes CRDT-style collaboration, while the current
implementation primarily snapshots normal filesystem state into a Merkle DAG.
That is enough for migration, clone, audit, and sync, but it is not yet a full
operation CRDT for concurrent editing.

## Decision

Until an operation CRDT is implemented, the current model is snapshot plus
explicit fork awareness. Concurrent state is represented by different Merkle
roots and social/workspace history rather than by automatic merge semantics.

## Consequences

- Documentation and UX must not imply automatic conflict-free file merges are
  already implemented.
- Future D1 work must choose between implementing operation CRDTs or making
  branch/fork/merge explicit in the user workflow.
- Snapshot history remains valid as audit evidence even before CRDT merge
  semantics exist.
