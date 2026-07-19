# ADR-0010: Bind mutation to an observed change set and strong approval

- Status: Accepted
- Date: 2026-07-19
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

A rendered bundle does not describe current target state. Approving only a plan or bundle permits target drift, namespace collisions or an unexpectedly different operation set between review and execution. A local operating-system username also does not provide enough identity assurance to authorize infrastructure mutation.

## Decision

Any apply-capable executor must consume four exact, content-addressed prerequisites: deployment bundle, fresh target preflight, observed change set and deployment approval. They must bind the same plan and pseudonymous target identities. ADR-0011 additionally requires a short-lived signed authorization over that complete chain.

The initial Kubernetes change-set observer is strictly read-only. It compares only the supported renderer's twelve declared resources, proposes no deletion and uses a versioned normalization profile instead of admission or server-side dry-run. Unreadable and foreign-owned objects block the change set.

Approval records separate `decision` from `effect`. A local self-asserted actor may record `approved` or `rejected`, but v1alpha1 permits only `review-only`. A typed assurance string is not authentication evidence. A future execution-authorized contract therefore requires a real signed/authenticated envelope and verifier rather than a stronger-looking string. Approval records expire within 24 hours.

A public `DeploymentReceipt` contract was defined before executor implementation. The executor selected by ADR-0011 now creates receipts that also bind the signed `ExecutionAuthorization`.

## Consequences

### Positive

- Review is bound to the operations and target actually observed.
- A status edit or local username cannot silently authorize mutation.
- Conflicts and missing RBAC visibility fail before an executor boundary.
- Receipt semantics can be reviewed and tested before privileged code exists.

### Negative

- Preflight and change-set observations must be refreshed near execution.
- Kubernetes defaulting requires a maintained, versioned normalization profile.
- Authenticated approval and signing infrastructure remain future work.

### Neutral / follow-up

- The initial comparison does not discover prune/delete operations.
- Admission behavior still requires a later separately authorized verifier.
- An executor must re-identify the target and reject stale bindings immediately before locking and mutation.

## Alternatives considered

### Approve the rendered bundle only

Rejected because it ignores current state and makes the reviewed operation set ambiguous.

### Treat the local OS identity as deployment authorization

Rejected because it is self-asserted, unsigned and does not prove authentication or separation of duties.

### Use server-side dry-run as the change set

Deferred because it invokes admission and may trigger side effects in webhooks; the first observer promises passive reads only.

## Validation

Tests must prove content identities, cross-resource binding, freshness, fail-closed auditing, target-switch rejection, conflict blocking, absence of deletion and forbidden kubectl verbs, and that local approval never has `execution-authorized` effect.
