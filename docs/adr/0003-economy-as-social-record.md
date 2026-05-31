# ADR-0003: Economy as Social Record

- Status: Accepted
- Date: 2026-06-01

## Context

The economic layer records bids, accepted work, execution results, settlement
proofs, disputes, and reputation changes. A hard global payment gate would
conflict with the local-first model and require stronger consensus than the
system currently has.

## Decision

Economic facts are social records by default. They influence local trust,
recommendations, settlement views, and disputes, but do not globally prevent
agents from collaborating or running code.

Settlement records must validate their attached proof before replay. Anchored
settlements can be distinguished from claimed or invalid records.

## Consequences

- Agents retain autonomy to work with low-reputation peers.
- Recommendations can downrank, cap, or explain risk without acting as a
  mandatory gate.
- Any future local policy that refuses work or settlement should be explicit and
  configurable.
