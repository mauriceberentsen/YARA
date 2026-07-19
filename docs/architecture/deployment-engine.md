# Deployment engine

## Status

Deployment is a post-v0.1 capability. This document defines its boundary early so planning does not become coupled to Helm, Compose or another target.

## Separation of responsibilities

```text
PlatformPlan --validate--> Renderer --artifact bundle--> Executor
                                                       |
                                                       v
                                             DeploymentReceipt
```

- The **planner** selects architecture and versions.
- The **renderer** performs a pure version-specific translation.
- The **executor** mutates a target after explicit approval.
- The **verifier** checks declared postconditions.

No later stage is allowed to silently replace a selected component or relax policy.

## Renderer contract

A renderer declares supported:

- plan schema versions;
- target type and version range;
- component adapter versions;
- configuration intent fields;
- lifecycle operations;
- artifact and secret providers.

Input is an immutable plan and rendering options that do not change architecture. Output is a deterministic bundle containing artifacts, manifest, checksums, required secret references, preflight contract and human-readable preview.

If a plan contains unsupported intent, rendering fails with exact paths. Best-effort rendering is unsafe and forbidden for apply-capable bundles.

## Artifact bundle

The bundle includes:

- plan ID and renderer identity;
- generated deployment files;
- immutable third-party artifact manifest;
- required secrets and permissions;
- preflight and postflight checks;
- ordered operations and rollback capabilities;
- bundle digest and optional signature;
- license/attribution inventory.

Sensitive values are injected at execution and excluded from the bundle.

## Executor workflow

1. Authenticate operator and identify target.
2. Verify plan and bundle digests/signatures.
3. Check executor/renderer support and target prerequisites.
4. Resolve secret references without exposing values.
5. Inspect current state and produce a bounded change set.
6. Classify destructive and security-sensitive operations.
7. Obtain approval bound to plan, bundle, target and change-set digests.
8. Acquire an environment operation lock.
9. Execute stages with checkpoints and timeouts.
10. Verify health and policy postconditions.
11. Emit a signed/attested receipt and release the lock.

## Idempotency and ownership

Executors label or record resources owned by one plan instance. Re-applying the same plan must be a no-op except for explicit reconciliation. YARA does not delete resources it cannot prove it owns. Adoption of existing resources is a separate reviewed operation.

## Failure and rollback

Rollback capability is operation-specific:

- stateless create/update may be automatically reversible;
- stateful schema or model-format changes may require restore;
- secret rotation may be only roll-forward;
- destructive storage changes require a verified backup and explicit approval.

The plan and bundle state rollback guarantees honestly. "Rollback supported" cannot mean only that manifests can be reapplied.

On failure the executor stops at a safe checkpoint, preserves diagnostics and reports completed, failed and unattempted operations. Automatic rollback runs only when its preconditions were verified before mutation.

## Initial backend choice

The architecture does not commit to Kubernetes first. A pure local Docker Compose renderer is now the current v0.2 prototype because it can validate plan-to-artifact boundaries with less infrastructure. [ADR-0009](../adr/0009-docker-compose-reference-renderer-prototype.md) remains Proposed: executor selection still requires an alternative prototype and comparison of:

- target audience value;
- idempotency and lifecycle support;
- secret and artifact handling;
- testability in CI;
- upgrade/rollback complexity;
- path to an air-gapped reference deployment.

## Kubernetes and GitOps

A future Kubernetes renderer should prefer established charts/operators and generate values or custom resources rather than fork large templates. A GitOps mode writes a reviewed bundle to a repository and records the commit; YARA itself need not hold cluster-admin credentials. Direct apply remains a distinct executor mode.

## Dry-run guarantees

`render` is pure and offline. `plan apply --dry-run` may perform read-only target inspection but no mutation and must identify every external call attempted. A dry-run is not proof an apply will succeed because target state can change; its timestamp and inventory digest are recorded.
