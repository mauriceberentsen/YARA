# ADR-0009: Prototype Docker Compose as the first reference renderer

- Status: Proposed
- Date: 2026-07-19
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

YARA needs a concrete plan-to-artifact prototype before choosing its first execution target. Docker Compose has a smaller operational surface than Kubernetes and can exercise immutable artifacts, dependency order, health, isolation and idempotency on one host. It has weaker policy, reconciliation and multi-node primitives.

## Proposed decision

Use a pure, versioned Docker Compose renderer as the first prototype. Keep it separate from any executor and restrict its initial adapter matrix to the exact LiteLLM/vLLM topology already represented by v0.2 plans.

This ADR does not yet select Docker Compose as YARA's first supported executor. Acceptance requires a bounded comparison with at least one alternative and review of idempotency, secrets, air-gap operation, policy enforcement, upgrades and safe removal.

## Consequences

### Positive

- Produces reviewable artifacts without target credentials or mutation.
- Makes unsupported plan intent fail early.
- Exercises content identity, license inventory and audit binding.
- Provides a compact fixture for later preflight and executor contracts.

### Negative

- Compose cannot express every policy or lifecycle guarantee.
- GPU placement and host access boundaries require executor-side target facts and approval.
- Typed component adapters remain version-specific maintenance work.

## Alternatives to compare

- Kubernetes manifests or Helm values with a GitOps handoff.
- Podman Quadlet/systemd for a single-host rootless deployment.

## Validation required for acceptance

- deterministic output for identical plan and catalog digests;
- failure on unknown topology, component version or intent;
- no network or target mutation during render;
- complete immutable artifact and license inventory;
- independent review of one alternative prototype;
- executor design proving approval, idempotency and owned-resource removal.
