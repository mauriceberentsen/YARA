# ADR-0011: Use a fail-closed direct Kubernetes executor for the first apply slice

- Status: Accepted
- Date: 2026-07-19
- Owners: YARA maintainers

## Context

ADR-0009 selected Kubernetes/GitOps as the first reference target but left direct apply as a separately authorized capability. YARA now has immutable bundles, passive target preflight, exact observed change sets, review records, short-lived signed authorization and a deployment-receipt contract. The smallest useful next slice must exercise those contracts without pretending to solve bootstrap, artifact import or full lifecycle management.

## Decision

Implement one direct `kubectl` executor behind `yara deployment apply kubernetes`. It requires an existing exact YARA-owned namespace and bound model PVC. It accepts only create, update and no-op operations from the exact authorized change set; the Namespace must be no-op. Delete, prune and adoption have no code path.

Before bundle mutation it durably records a started audit event, acquires a namespaced Lease and revalidates target identity plus every current object digest. It actively verifies model files and executable temporary storage when authorized. It uses server-side apply with a dedicated field manager, performs rollout and bounded inference/network-policy checks, emits a content-addressed receipt for every started mutation and then completes the audit chain.

Temporary verifier Pods and the Lease are the only resources the executor deletes, and only after checking their YARA-scoped identity or Lease holder. Connection details remain ephemeral and are excluded from receipts and audit events.

## Consequences

- The first apply path is operationally useful for a pre-provisioned reference environment, but is not a clean-cluster installer.
- Audit availability is a hard precondition rather than best-effort logging.
- A receipt explicitly binds the signed authorization, closing the authority-to-result chain.
- Idempotency is defined against the normalized approved resource projection; a second independently reviewed apply should produce no-op bundle operations.
- Artifact acquisition/import, rollback, resource retirement and credential issuance remain separate future slices.
- Direct apply and GitOps handoff can coexist behind the same immutable plan/bundle boundary.

## Rejected alternatives

- Applying directly from a plan would let the executor repeat architecture decisions.
- Treating a local approval record as execution authority would not provide cryptographic assurance.
- Applying without a lock and stale-state recheck would make the reviewed change set unreliable.
- Deleting unknown or obsolete resources during apply would exceed the reviewed operation set.
- Writing audit evidence only after execution would leave successful mutation without durable start evidence.
