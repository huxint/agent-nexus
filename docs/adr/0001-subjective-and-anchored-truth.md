# ADR-0001: Subjective and Anchored Truth

- Status: Accepted
- Date: 2026-06-01

## Context

The society layer receives signed events from many agents. A signature proves
who made a claim, but not whether the claim is globally true. Treating every
signed claim as consensus truth would make local preferences, relationships,
and observations too rigid, while treating settlement finality and collective
decisions as merely unclassified claims makes accountability weak.

## Decision

Default society replay is subjective local truth. Selected facts can be upgraded
to anchored truth when an `AuthorityAnchor` validates an accepted witness.

Anchored truth is intended for narrow facts that require stronger agreement:

- settlement finality,
- collective decisions,
- task claim judgments,
- future ownership or membership transfers.

Everything else remains claim-level memory unless a specific projection marks
it otherwise.

## Consequences

- Local agents may disagree without requiring global consensus.
- JSON views must expose claimed versus anchored status where it changes
  recommendation or settlement interpretation.
- New consensus-like facts need an explicit authority witness path instead of
  silently becoming global truth.
