# API design

## API-first, local-first

The domain and application services are interface-neutral, but v0.1 exposes a CLI and file resources before a network service. "API-first" means stable schemas and use-case boundaries, not that a server is required.

## Resource APIs

Primary versioned resources:

- `PlatformRequest`
- `Inventory`
- `Policy` and `PolicyException`
- `CatalogSnapshot`
- `PlatformPlan`
- `Approval`
- `ArtifactBundle`
- `DeploymentReceipt`
- `Observation`
- `Operation`
- `AuditEvent`
- `DebugBundle`
- `GoldenScenario`
- `ContractTestResult`

v0.1 implements the request, inventory, policy/catalog inputs, plan, diagnostics, redacted debug-bundle and golden-scenario contracts, plus local audit records. Post-v0.1 adds preflight, runtime-smoke, bounded model-inference, advertised-context capacity-boundary and serving-policy `ContractTestResult` modes. Approval, deployment, sustained-capacity/lifecycle contract modes and service-side audit storage arrive later.

## CLI surface

Proposed initial commands:

```text
yara request validate <file> [--audit-output <file>]
yara inventory inspect [--output <file>]
yara inventory validate <file> [--audit-output <file>]
yara catalog validate <path> [--audit-output <file>]
yara plan create --request <file> --inventory <file> --catalog <path> --output <file> --audit-output <file>
yara plan validate <file> [--audit-output <file>]
yara plan explain <file> [--decision <id>] [--audit-output <file>]
yara plan diff <old> <new> [--audit-output <file>]
yara debug bundle --plan <file> --output <file> --audit-output <file>
yara scenario validate <file> [--audit-output <file>]
yara scenario validate-all <directory> [--audit-output <file>]
yara contract preflight --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>
yara contract runtime-smoke --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>
yara contract model-inference --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>
yara contract capacity-boundary --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>
yara contract policy --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>
yara contract validate <file> [--audit-output <file>]
yara audit verify <file>
```

Commands write machine data to standard output or the requested file and human diagnostics to standard error. Exit codes are stable by class: success, invalid input, infeasible request, internal error and unsupported version.

The read-only validation, plan-explanation and plan-diff commands preserve positional inputs and optionally persist a local audit chain. Without `--decision`, explanation returns the complete ordered decision list for compatibility; with it, the command returns exactly one `PlanDecision` or `YARA-PLAN-040`. Planning, debug-bundle generation and every contract execution mode require an audit destination. An audit write failure prevents any generated artifact from being reported as successful; a read-only command with an explicitly requested audit destination follows the same fail-closed rule.

Contract preflight uses a fixed non-interactive SSH probe and does not mutate the target. Exit code `3` represents both blocked eligibility and a failed compatibility check; the persisted `ContractTestResult.spec.outcome` distinguishes them. The remote reference is represented by a digest in the result and audit event.

Runtime smoke first resolves public upstream OCI/model metadata, applies the same SSH preflight, and then starts an exact digest-pinned image already present on the target. The container has a unique name, blocked network, no ports or volumes, a read-only filesystem and bounded resources; ownership-scoped cleanup runs on exit. The result explicitly states that no model weights were loaded.

Model inference adds fixed capacity gates, exact revision acquisition into a temporary volume, local shard hashing, model load, health and one constrained chat request. Its serving container has no network or published ports. Prompt, completion and raw logs are not persisted. New contract results bind both runner version and executable digest; the result remains valid only for the exact recorded catalog, runner, environment and test bounds.

Scenario validation proves pinned technical conformance and counts approved `ScenarioReview` and `AcceptanceGateReview` resources discovered with the suite. `scenario validate-all` discovers a bounded, sorted suite, rejects duplicate scenario identities, requires at least ten cases and fails when any case is nonconformant. Its summary separates planned and infeasible results and reports independent review completion, acceptance-gate review completion and `releaseEligible` when all counted reviews are present and approved.

## Future service endpoints

Illustrative, not committed HTTP design:

```text
POST /v1/requests
POST /v1/planning-runs
GET  /v1/planning-runs/{id}
GET  /v1/plans/{id}
POST /v1/plans/{id}:validate
POST /v1/plans/{id}:approve
POST /v1/deployments
GET  /v1/operations/{id}
```

Planning and deployment may be long-running operations. `POST /plan` that holds a connection indefinitely is not the target service contract.

## Idempotency and concurrency

- Create operations accept an idempotency key.
- Mutable intent resources use revision/ETag preconditions.
- Plans and receipts are immutable and content-addressed.
- Approval references exact plan and, for apply, exact change-set digest.
- Retrying an operation does not create duplicate target resources.

## Errors

Errors are structured:

```json
{
  "code": "YARA-HW-004",
  "severity": "error",
  "message": "The selected model configuration exceeds allocatable accelerator memory.",
  "paths": ["spec.workload.maximumContextTokens"],
  "related": ["inventory.hosts[0].accelerators[0]"],
  "remediation": ["Reduce concurrency", "Choose a smaller artifact"]
}
```

HTTP status communicates transport/application class; the YARA code communicates the stable domain condition.

## Authentication and authorization

A future service uses standards-based identity and maps principals to organization/environment roles. Authorization checks resource scope and action, with separate permissions for policy, catalog trust, planning, approval, execution and secret-provider use. The user who proposes a destructive production change may be forbidden from approving it.

## Events

Operations may emit events such as plan created, approval recorded, apply started and verification failed. Events are versioned facts, at-least-once delivered and carry unique IDs. Consumers must be idempotent. Events never contain secret values or full sensitive inventories by default.

Audit events use the same versioned envelope but are not interchangeable with transient notifications. A notification can be retried or dropped according to delivery policy; the authoritative audit record must be durably appended before a production mutation is reported as successful.

## Compatibility

- Resource API versions change only for semantic breaks.
- Additive fields are optional until all supported clients understand them.
- Clients must not silently discard unknown required semantics.
- Deprecation and migration periods are published.
- OpenAPI/JSON Schema artifacts and conformance fixtures become release artifacts when a server exists.
