# Auditing

## Decision

Auditing is a first-class YARA domain capability. It is designed into planning, policy, approval, execution and lifecycle workflows from the first version. It is not reconstructed later from application logs.

## Audit, explanation and observability

These records serve different questions:

| Record | Primary question | Lifetime |
|---|---|---|
| Decision trace | Why did the planner choose or reject this option? | Bound to immutable plan |
| Audit event | Who or what performed an action, on which resources, why and with what result? | Retention/policy controlled, append-only |
| Log/trace | What happened internally while processing the operation? | Operational and often shorter-lived |
| Receipt | What immutable operation inputs and results were completed? | Bound to planning/deployment/lifecycle operation |

An audit event references a plan decision or receipt rather than copying its potentially sensitive payload.

## Implemented local v0.1 coverage

The local CLI currently emits two-event started/terminal chains for:

- request, inventory, catalog and plan validation when `--audit-output` is supplied;
- planning started/completed/failed/infeasible, with audit output mandatory;
- request, inventory and catalog load/decode rejection during planning.

The remaining taxonomy below is architectural scope, not a claim of current implementation. Inventory discovery, policy resolution, semantic plan diff, approval, deployment and lifecycle events arrive with their corresponding use cases.

For a successful planning run, the event records the request, inventory, catalog and semantic-plan digests. For an unsuccessful run it records available canonical input digests, a bounded raw-input digest or an opaque input-reference digest, plus stable diagnostic codes. The distinct subject kinds prevent an attempted-input reference from being mistaken for a validated resource identity. Effective-policy and planner/rule-engine version subjects are planned but not yet emitted because those versioned resources do not yet exist.

The current local actor comes from the operating-system identity and is labelled `self-asserted-local` (or `unknown-local` when unavailable). A future authenticated service or explicit actor input may provide stronger provenance, but the current value must not be presented as cryptographically verified identity.

## Event envelope

Illustrative structure:

```yaml
apiVersion: yara.dev/v1alpha1
kind: AuditEvent
metadata:
  id: 01J...
  occurredAt: 2026-07-14T10:00:00Z
spec:
  sequence: 42
  correlationId: 01J...
  causationId: 01J...
  actor:
    id: local:operator
    type: user
    assurance: self-asserted-local
  action: plan.create.completed
  subjects:
    - kind: PlatformRequest
      digest: sha256:...
    - kind: PlatformPlan
      digest: sha256:...
  reason:
    type: user-request
    reference: cli
  policyDigest: sha256:...
  target: local
  outcome: success
  diagnosticCodes: []
  integrity:
    previousEventDigest: sha256:...
    eventDigest: sha256:...
```

The final schema will define required fields, canonicalization and permitted action names. Timestamps and event IDs do not affect semantic plan identity.

## Action taxonomy

Actions use stable namespaced verbs:

```text
request.validate.*
inventory.validate.*
inventory.inspect.*
catalog.load.*
catalog.validate.*
policy.resolve.*
plan.create.*
plan.validate.*
plan.diff.*
approval.record.*
artifact.render.*
deployment.apply.*
lifecycle.upgrade.*
lifecycle.backup.*
lifecycle.restore.*
security.trust-root.*
```

Each operation emits a start event only when useful and exactly one terminal outcome event. Retries use a new operation/event ID but retain correlation and causation links.

## Integrity and ordering

Local v0.1 audit output uses canonical events in append-only JSON Lines with a previous-event digest chain. A chain detects removal, modification and reordering but does not prove publisher identity. Optional signatures can authenticate checkpoints.

A future service uses durable append semantics, monotonically ordered sequences per organization/environment and periodic signed checkpoints. Events are never updated or deleted in place; corrections append a new event referring to the incorrect record.

## Failure behavior

- The current local `plan create` command requires an audit destination and fails closed if its start/terminal chain cannot be written.
- Read-only validation does not require persistent audit by default; once `--audit-output` is supplied, failure to persist it fails the command.
- A future explicit no-persistence planning mode, if accepted by policy, must report `auditPersistence: unavailable` prominently rather than silently omitting evidence.
- Production mutation MUST NOT start if the required audit sink is unavailable.
- A mutation is not reported successful until its terminal audit event and receipt are durably recorded.
- Audit backpressure fails safely and cannot be bypassed by a renderer/plugin.
- Emergency policy may allow a separately authenticated break-glass path, which itself must produce recoverable local audit evidence for later import.

## Privacy and minimization

Audit records are metadata, not a copy of input documents. They MUST NOT contain:

- secret values, tokens or private keys;
- prompts, completions, code or retrieved documents;
- full requests, inventories or generated configurations;
- raw environment variables or command lines containing values;
- unnecessary personal data.

Use immutable digests, typed resource references, stable diagnostic codes and redacted summaries. Access to audit data is separately authorized because infrastructure topology and actor activity remain sensitive.

## Retention and export

Retention is policy-based by event class and environment. Legal hold and organization requirements may override ordinary deletion. Export includes schema versions, checkpoint signatures, verification instructions and time-source metadata. Deleting subject data must not leave misleading audit claims; where privacy law requires erasure, use documented pseudonymization or cryptographic-erasure strategies under organization review.

## Time and identity assurance

Every event states actor assurance. Current local events use the process clock for `occurredAt`; the v1alpha1 envelope does not yet carry an explicit time-source field, so their timestamp is low assurance. A future schema revision must make time-source assurance explicit before a team service claims trusted time. Such a service can use authenticated identity and trusted time; an executor can add workload/host attestation. Consumers must not compare events as equally authoritative when their assurance differs.

## Audit coverage tests

Every command/use case defines expected audit actions and fields. Tests verify:

- success, failure, infeasible and cancellation outcomes;
- exact subject digests and causation links;
- chain verification and tamper detection;
- deterministic redaction and secret canaries;
- retry/idempotency semantics;
- unavailable/corrupt audit sink behavior;
- policy exception and override visibility;
- schema migration and historical readability.

## Non-goals

- Storing all debug output forever.
- Claiming a hash chain alone is non-repudiation.
- Logging model prompts/content by default.
- Using an audit event as authorization.
- Allowing auditing to silently send local data to a hosted service.
