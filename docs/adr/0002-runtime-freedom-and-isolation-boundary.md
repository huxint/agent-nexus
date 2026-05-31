# ADR-0002: Runtime Freedom and Isolation Boundary

- Status: Accepted
- Date: 2026-06-01

## Context

The project treats a workspace as an AI computer. Local execution must remain
ergonomic and native, but running untrusted workspace content has different risk
from running an owner's own workspace.

## Decision

The default product philosophy is runtime freedom: society and capability state
do not block local execution. Isolation belongs in explicit execution options
and future policy tiers, not in the society replay engine.

The intended boundary is:

- own workspace: default to unrestricted native execution,
- cloned or accepted-task workspace: default to an isolation profile once S1 is
  implemented,
- every execution: record context, output CIDs, resource evidence, failures, and
  snapshots when possible.

## Consequences

- Social facts describe consequences and evidence; they are not a sandbox.
- Secret handling and filesystem boundaries must be addressed in execution
  options and identity storage, not by overloading reputation or capability
  checks.
- Tests should verify evidence recording even when execution fails.
