# ADR-0005: Bootstrap as Connectivity

- Status: Accepted
- Date: 2026-06-01

## Context

A node with no prior network information needs some entry point. Removing every
entry point is not possible, but allowing one seed to become authoritative
would compromise self-sovereign discovery.

## Decision

Bootstrap peers are connectivity hints only. They help a node enter the network,
discover peers, and populate caches. They do not sign identities, decide
workspace truth, or replace verification.

Preferred discovery order is local and user-controlled first, then cached and
seeded paths:

- explicit CLI bootstrap,
- environment/config bootstrap,
- peer cache and discovery cache,
- public seed list as fallback,
- social introduction links or invites as first-class future inputs.

## Consequences

- Users can disable public seeds.
- Workspace announcements, owner signatures, roots, and block CIDs must still be
  verified after discovery.
- N4 work should add more independent seed options and social invitation flows
  without making any seed authoritative.
