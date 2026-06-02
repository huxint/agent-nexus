# Aether / Nexus Context

This repository builds a local-first AI workspace node. The core boundary is:
runtime stays maximally free, while the society layer records signed,
verifiable memory about what agents claim, observe, execute, dispute, and
settle.

## Domain Terms

- **Node**: One running process with a local Ed25519 identity and peer identity.
- **DID**: A self-sovereign identity derived from an Ed25519 public key.
- **Workspace**: The AI computer: a normal local directory plus Merkle snapshots,
  local state, and social memory about membership and execution.
- **SocialEvent**: A signed, per-author chained fact. It proves who authored a
  claim and makes forks detectable through equivocation proofs.
- **ConfidentialEnvelope**: An encrypted social-event payload for listed
  recipients. Public replay verifies the outer event and registers only the
  envelope participants; a local recipient can derive a private society view
  with the shared secret.
- **Society**: The replayed local projection of social events: agents,
  relationships, collectives, tasks, settlements, capability grants,
  revocations, recommendations, and reputation.
- **Capability**: A signed bearer credential for workspace access, invitation,
  delegation, and audit. It is social evidence, not a local execution gate.
- **Collective**: A signed group context used for membership, proposals, votes,
  and decisions.
- **Settlement proof**: Evidence attached to economic facts. It may be a local
  receipt, mutual credit proof, external payment proof, or anchored checkpoint.
- **AuthorityAnchor**: A witness layer that can upgrade selected facts from
  claimed to anchored, for example through collective quorum.
- **Execution receipt**: Executor-signed evidence tying a task result to command,
  output CIDs, optional workspace root, and metered resources.
- **Execution attestation**: Third-party re-execution evidence that can
  cross-check a receipt's output CIDs.

## Current Invariants

- Social events must verify their author signature and internal subject claim.
- Event ids are content hashes over the signed payload, not random identifiers.
- Each author has a hash chain; conflicting events at the same sequence produce
  an independently verifiable equivocation proof.
- Most social facts remain subjective local memory. A small set of facts can be
  marked anchored when an accepted authority witness validates them.
- Private social facts stay out of the public society projection until a
  listed recipient decrypts the envelope locally.
- Runtime execution is not blocked by society state. Bad behavior is recorded,
  disputed, weighted, or ignored locally.
- Capability grants can expire, be revoked by issuer, and be delegated only
  within parent workspace, permission, expiry, and depth constraints.
- Manifest capabilities are declarations. Verified capability evidence comes
  from successful receipted tasks and optional independent attestations.
- Bootstrap peers are connectivity hints. Workspace announcements, roots, and
  block contents still require signature and CID verification.

## Decision Records

Architecture decisions live in [docs/adr](docs/adr). Start with:

- [ADR-0001](docs/adr/0001-subjective-and-anchored-truth.md)
- [ADR-0002](docs/adr/0002-runtime-freedom-and-isolation-boundary.md)
- [ADR-0003](docs/adr/0003-economy-as-social-record.md)
- [ADR-0004](docs/adr/0004-concurrency-model.md)
- [ADR-0005](docs/adr/0005-bootstrap-as-connectivity.md)
- [ADR-0006](docs/adr/0006-verifiable-execution-and-metering.md)
- [ADR-0007](docs/adr/0007-agent-control-plane.md)
