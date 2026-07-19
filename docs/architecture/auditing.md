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
- complete or targeted plan explanation when `--audit-output` is supplied, bound to the plan ID and exact explanation-content digest;
- semantic plan comparison when `--audit-output` is supplied, including both plan IDs and the resulting diff ID;
- redacted debug-bundle generation, with mandatory audit evidence binding the source plan ID and resulting bundle ID;
- golden-scenario validation when `--audit-output` is supplied, binding the scenario ID and generated plan ID without claiming review approval;
- golden-scenario suite validation when `--audit-output` is supplied, binding every scenario ID and every generated plan ID without claiming or counting human approval;
- read-only SSH contract preflight, isolated runtime smoke, bounded model inference, advertised-context capacity, serving-policy and same-version lifecycle testing with mandatory fail-closed evidence, binding the catalog, exact runner executable and content-addressed test-result digests while pseudonymizing the remote reference;
- catalog coverage generation and validation, binding the exact snapshot, accepted contract-result/audit set and content-addressed coverage report while keeping missing evidence explicit;
- planning started/completed/failed/infeasible, with audit output mandatory;
- request, inventory and catalog load/decode rejection during planning.

The remaining taxonomy below is architectural scope, not a claim of current implementation. Inventory discovery, policy resolution, approval, deployment and lifecycle events arrive with their corresponding use cases.

For a successful planning run, the event records the request, inventory, catalog and semantic-plan digests. For an unsuccessful run it records available canonical input digests, a bounded raw-input digest or an opaque input-reference digest, plus stable diagnostic codes. The distinct subject kinds prevent an attempted-input reference from being mistaken for a validated resource identity. Effective-policy and planner/rule-engine version subjects are planned but not yet emitted because those versioned resources do not yet exist.

The v0.2 catalog path preserves the same boundary: `catalog validate` binds its terminal event to the exact `CatalogSnapshot` digest, and `plan create` binds both the catalog and resulting plan digests while retaining material maturity diagnostics such as `YARA-CAT-055`. Immutable artifact digests and evidence URLs live in the catalog referenced by that digest; they are not copied into every event.

Catalog promotion is not yet a CLI operation. Until it is, the Git commit and review record are the approval evidence. Preflight remains eligibility evidence only. Runtime smoke adds upstream OCI/model identity verification and bounded isolated CUDA execution. Model inference adds exact local shard verification, load, health and one bounded request. Capacity-boundary adds one exact advertised-context request at concurrency 1 under `contract.capacity-boundary.*`; it is not sustained-capacity or performance evidence. Sustained-capacity records 32 consecutive bounded requests under `contract.sustained-capacity.*`; it is not a duration soak, SLO or performance claim. Policy records observable serving-container controls under `contract.policy.*`. Lifecycle records one same-version restart with pre/post health and inference plus identity comparisons under `contract.lifecycle.*`; it is not upgrade, rollback, HA or stateful-recovery evidence. Every new result records the runner version and executable digest, while the audit chain binds catalog and result identities. Promotion and independent review remain required; a status edit or individual passing contract alone is insufficient.

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

The v1alpha1 schema defines the required event envelope and action-name shape. Timestamps and event IDs do not affect semantic plan identity.

## Action taxonomy

Actions use stable namespaced verbs:

```text
request.validate.*
inventory.validate.*
inventory.inspect.*
catalog.load.*
catalog.validate.*
catalog.artifact-verify.*
catalog.contract-test.*
catalog.promote.*
contract.preflight.*
contract.runtime-smoke.*
contract.model-inference.*
contract.capacity-boundary.*
contract.sustained-capacity.*
contract.policy.*
contract.lifecycle.*
catalog.coverage.*
policy.resolve.*
plan.create.*
plan.validate.*
plan.explain.*
plan.diff.*
debug.bundle.*
scenario.validate.*
scenario.validate-all.*
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
- The current local `debug bundle` command also requires an audit destination and removes its output if terminal evidence cannot be persisted.
- Every current contract execution command requires an audit destination and removes its result if terminal evidence cannot be persisted. Blocked and failed evaluations remain persisted as negative evidence when a trustworthy environment observation exists.
- Read-only validation, plan explanation and plan comparison do not require persistent audit by default; once `--audit-output` is supplied, failure to persist it fails the command.
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
- debug-bundle contents or secret-scan matches;
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
