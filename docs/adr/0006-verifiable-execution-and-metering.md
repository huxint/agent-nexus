# ADR-0006: Verifiable Execution and Metering

- Status: Accepted
- Date: 2026-06-01

## Context

Task results and workspace runs can include command output, receipts, resource
usage, and third-party attestations. Resource usage can be honestly measured by
the local runtime, but that does not make it independently trusted by default.

## Decision

Execution evidence has levels:

- self-reported result,
- executor-signed receipt with output CIDs and metered resources,
- independent re-execution attestation that cross-checks output CIDs,
- future stronger measurement witness such as TEE, container attestation, or
  external verifier.

Current code treats independent output checks as stronger output evidence, while
resource measurement remains signed executor evidence unless a stronger witness
is added.

## Consequences

- JSON views must keep `verified_output` separate from `verified_measurement`.
- Recommendations can use verified capability evidence without pretending
  resource metering is independently proven.
- Future E3 work should add stronger measurement witnesses before calling
  resource usage fully verifiable.
