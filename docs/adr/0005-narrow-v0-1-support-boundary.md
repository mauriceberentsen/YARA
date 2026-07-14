# ADR-0005: Use a narrow v0.1 support boundary

- Status: Accepted
- Date: 2026-07-14
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

The long-term vision spans many use cases, components, models, accelerators and targets. Each dimension multiplies compatibility and evidence work. With one maintainer at roughly ten hours per week, broad initial support would be untestable and stale quickly.

## Decision

v0.1 plans only a local single Linux host, homogeneous NVIDIA accelerators, chat and coding use cases, a curated component/model slice and local or air-gapped connectivity. It generates and validates plans but does not deploy.

## Consequences

### Positive

- A meaningful end-to-end reasoning path can be tested deeply.
- Evidence and maintenance obligations are bounded.
- Architecture mistakes are discovered before privileged deployment code.

### Negative

- Many interested users and existing environments are initially unsupported.
- Vendor-neutral goals are not proven by the first implementation.
- The early release may look less ambitious than the vision.

### Neutral / follow-up

- Domain schemas must remain vendor-neutral.
- The next expansion dimension is selected from validated demand, not convenience.

## Alternatives considered

### Support many components as experimental

Creates apparent breadth, but users may mistake catalog presence for reliable recommendations and maintenance still accumulates.

### Begin with Kubernetes enterprise deployment

Aligns with part of the target market but mixes planner validation with a large operational surface and delays first evidence.

## Validation

The boundary is revisited after external users approve and use v0.1 plans. Expansion requires golden scenarios, owners and evidence for the new dimension.
