# Deployment engine

## Status

The first bounded apply-capable Kubernetes executor is implemented. Planning and rendering remain pure and independent of this privileged boundary.

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

The current `DeploymentBundle` realizes the third-party inventory as two embedded documents: an SPDX 2.3 SBOM and a YARA `OfflineAcquisitionManifest`. Both are deterministically generated, content-addressed and included in the enclosing bundle digest. The offline manifest binds the exact plan, catalog, renderer, OCI index digests, model revision, shard digests and declared license sources. It separates connected acquisition from network-denied execution but grants neither acquisition nor apply authority. Import locations, scans, signatures and receipts remain observed lifecycle data rather than renderer assumptions.

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

After bounded Docker Compose and Kubernetes/GitOps prototypes over the same plan and catalog, [ADR-0009](../adr/0009-docker-compose-reference-renderer-prototype.md) selects Kubernetes/GitOps as the first reference deployment target. Docker Compose remains the lower-friction single-host renderer and CI fixture.

The renderer selection is not apply authority. The Kubernetes renderer remains pure and offline. Direct apply separately requires the exact preflight, change set, review approval and verified short-lived signed authorization. ADR-0011 implements a deliberately narrow executor for an existing namespace and model PVC; it does not add mutation to the renderer.

## Read-only target preflight

`yara target preflight kubernetes` observes an explicitly selected kubectl target with a bounded timeout. It reads API discovery, server version, unique node platforms, aggregated allocatable NVIDIA GPU count, matching DNS-pod count, target namespace ownership and the phase of the expected model PVC. It verifies that every observed node platform is supported by every pinned bundle OCI artifact. It never creates, applies, patches, deletes, executes in, or server-side dry-runs an object.

The resulting `TargetPreflightResult` binds the exact bundle and plan IDs, observer version, observation time and a pseudonymous target digest. Every check has a stable status, diagnostic code where non-passing, allowlisted facts and an evidence digest. The overall outcome is derived from the checks and cannot overstate them. Raw API addresses, kubeconfig paths, context names, node names and pod names are not durable evidence.

A read-only observation cannot prove model-file digests inside a PVC, CNI enforcement, executable temporary storage or admission/RBAC governance of verifier labels. Those checks remain `blocked` even when all observable prerequisites pass. A later signed authorization may accept only the explicitly enumerated active-verification blockers; the executor must then test them or retain an honest limitation. Preflight audit output is mandatory and binds bundle, target and result identities.

See the [implementation contract](../implementation/target-preflight.md).

## Observed change set and approval

The current change-set observer re-identifies the preflight target, requires a preflight no older than fifteen minutes and compares the exact supported bundle resources through a versioned normalization profile. It emits create, update, no-op, conflict or unresolved operations. It neither discovers nor proposes deletes. Foreign ownership, missing read permission and target switches block the result.

Local approval is intentionally review-only: the operating-system identity is `self-asserted-local`. It becomes one bound input to a separate Ed25519-signed `ExecutionAuthorization`; the approval alone is never authority. Review records have a maximum 24-hour validity window. See [ADR-0010](../adr/0010-bind-mutation-to-observed-change-set-and-strong-approval.md) and the [implementation guide](../implementation/change-sets-and-approvals.md).

`DeploymentReceipt` was defined and validateable before privileged implementation. `deployment apply kubernetes` is now the only command that creates one. The receipt binds the full plan-to-authorization chain, exact running binary, target, per-object outcomes and postflight evidence.

## Initial direct executor

The initial executor:

- writes and syncs a mandatory start audit event before its first mutation;
- acquires a YARA-owned namespaced Lease;
- re-identifies the target and rechecks all approved current object digests under that Lease;
- requires the Namespace operation to be no-op;
- actively verifies pinned model-file sizes/digests and executable `/tmp` when authorized;
- server-side applies only approved create/update objects with field manager `yara-executor`;
- verifies the observed normalized result of each write;
- waits for Deployments and probes LiteLLM inference plus NetworkPolicy isolation;
- records failed and skipped operations instead of continuing after a write failure;
- emits a durable receipt before the terminal audit event.

Delete, prune, adoption, namespace/PVC creation, model import and rollback are absent. Only the owned Lease and temporary verifier Pods have cleanup delete paths. See the [operator contract](../implementation/kubernetes-apply.md) and [ADR-0011](../adr/0011-use-a-fail-closed-direct-kubernetes-executor.md).

Execution authorization is now represented separately as a maximum-15-minute Ed25519-signed capability. It binds the exact plan, bundle, preflight, change set, review record, target and permitted non-delete operation set. Verification requires an explicitly trusted public key; schema validity or a self-declared assurance string is insufficient. The executor must re-observe target state after verification because signature validity does not make an earlier change set current.

## Kubernetes and GitOps

The first Kubernetes adapter emits a deliberately narrow set of native resources for the exact LiteLLM/vLLM reference topology. Broader adapters should prefer established upstream charts/operators and generate values or custom resources rather than fork large templates. A GitOps mode writes a reviewed bundle to a repository and records the commit; YARA itself need not hold cluster-admin credentials. Direct apply remains a distinct executor mode.

The renderer cannot prove its target assumptions. [NetworkPolicy requires an enforcing network plugin](https://kubernetes.io/docs/concepts/services-networking/network-policies/), and GPU resources require installed vendor drivers and a device plugin before `nvidia.com/gpu` becomes allocatable. Immutable ConfigMaps are content-named so configuration changes create a new object and Pod-template revision instead of attempting forbidden in-place data mutation.

## Dry-run guarantees

`render` is pure and offline. `plan apply --dry-run` may perform read-only target inspection but no mutation and must identify every external call attempted. A dry-run is not proof an apply will succeed because target state can change; its timestamp and inventory digest are recorded.
