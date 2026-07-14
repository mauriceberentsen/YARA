# ADR-0006: Make the planner offline and logically pure

- Status: Accepted
- Date: 2026-07-14
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

Live queries could provide fresh model, benchmark or release data during planning, but they make output dependent on mutable services and complicate privacy, testing and air-gapped use.

## Decision

The planner has no network access, target credentials, clock-dependent semantic behavior or mutation. It consumes explicit immutable inputs and catalog snapshots. Discovery, catalog acquisition and artifact acquisition are separate steps with recorded outputs.

## Consequences

### Positive

- Plans work in air-gapped environments and CI.
- Inputs can be archived and reproduced.
- Planning exposes no inventory to third parties.
- Failures and tests are less environment-dependent.

### Negative

- Users must acquire catalog snapshots separately.
- The planner can use stale data if policy permits it.
- Discovery requires an additional command/process.

### Neutral / follow-up

- Interfaces may offer a convenience workflow that updates catalogs before planning, but the resulting snapshot digest is explicit.
- Presentation timestamps do not participate in semantic plan identity.

## Alternatives considered

### Fetch current metadata during every plan

Improves apparent freshness but breaks reproducibility, privacy and offline operation and makes upstream availability part of planner reliability.

### Cache live queries transparently

Reduces network calls but creates hidden input state and inconsistent output between machines.

## Validation

End-to-end planner tests run with network denied and empty caches. The same archived inputs must yield the same semantic plan on supported platforms.
