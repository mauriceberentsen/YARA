# ADR-0009: Select Kubernetes/GitOps as the first reference deployment target

- Status: Accepted
- Date: 2026-07-19
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

YARA needs a concrete plan-to-artifact boundary before choosing its first reference deployment target. The first Docker Compose prototype proved deterministic rendering, immutable artifact identity, supply-chain inventory, dependency order, health intent, isolation and fail-closed audit binding on one host. It also exposed weaker policy, reconciliation and multi-node primitives.

A second prototype renders the exact same LiteLLM 1.93.0 to vLLM 0.25.1 plan and immutable Qwen snapshot as native Kubernetes/GitOps resources. It adds no architecture selection and reuses the same bundle, SPDX, offline-acquisition and audit contracts, making the target comparison bounded rather than hypothetical.

## Decision

Select Kubernetes with a GitOps handoff as YARA's first reference deployment target. Keep Docker Compose as the single-host development/reference renderer and compact CI fixture. Both renderers remain pure, versioned and separate from acquisition and execution.

The Kubernetes prototype emits a namespace, immutable content-named ConfigMap, Deployments, ClusterIP Services and explicit default-deny/allow NetworkPolicies. It requests one `nvidia.com/gpu`, mounts only a pre-provisioned verified model PVC, publishes no external access boundary, and carries exact preflight assumptions. Renderer 0.1.0 bounds its tested Kubernetes minor range to 1.34 through 1.36. It does not run `kubectl`, inspect a cluster, provision storage, acquire artifacts or grant apply authority.

GitOps is the default handoff: a future workflow writes the reviewed bundle to a repository and records the commit. Direct Kubernetes API apply remains a separate executor mode requiring target identity, observed change set, explicit approval, locking, least privilege, verification and receipts.

## Bounded comparison

| Criterion | Docker Compose prototype | Kubernetes/GitOps prototype |
|---|---|---|
| Primary value | Lowest-friction single-host preview | Enterprise suite, policy and multi-node trajectory |
| Reconciliation | Command-driven project convergence | Native controllers continuously reconcile declared workloads |
| Ownership | Compose project labels and executor bookkeeping | Namespace, selectors, YARA labels and Git revision |
| Network policy | Internal network, but weak portable allow-listing | Default-deny plus explicit L3/L4 flows when the CNI enforces NetworkPolicy |
| GPU | Host/runtime-specific reservation | Stable extended-resource request, requiring vendor device plugin |
| Configuration | Bind-mounted generated file | Immutable, content-named ConfigMap drives a Pod-template revision |
| Model storage | Read-only host path | Pre-provisioned, read-only verified PVC |
| Upgrade/rollback | Executor-managed recreation | Deployment revisions and reconciliation; still not proof of application-safe rollback |
| CI cost | Low with Docker | Higher; schema tests plus a later disposable-cluster contract |
| Air gap | Simple local image/model import | Strong registry/policy ecosystem but more control-plane, DNS, CNI, CSI and mirror prerequisites |

Kubernetes wins the first reference target because YARA's product goal is an integrated, governed suite rather than only the easiest single-host installer. Compose remains valuable and is not deprecated.

## Consequences

### Positive

- Establishes a reviewed target direction before executor code is written.
- Represents ownership, reconciliation, health, GPU intent and network policy in native resources.
- Fits GitOps review, air-gapped registries and future multi-node operation.
- Preserves Compose as a lower-cost local path.

### Negative

- Kubernetes adds material CNI, CSI, DNS, device-plugin, admission and control-plane prerequisites.
- NetworkPolicy resources have no effect when the selected CNI does not enforce them.
- A PVC and digest manifest do not prove imported model contents; acquisition/import receipts remain required.
- Git reconciliation does not prove health, rollback safety or policy enforcement.
- Typed component adapters remain version-specific maintenance work.

## Alternatives rejected for the first reference target

- Docker Compose as the only target: simpler, but too weak for YARA's governed-suite and lifecycle direction.
- Podman Quadlet/systemd first: attractive for rootless single-host operation, but less aligned with the initial enterprise and multi-node scope.
- Helm-only output: useful later for upstream integrations, but values are not a universal intermediate representation and do not remove the need for typed version adapters.

## Validation completed for this decision

- deterministic output for identical plan and catalog digests;
- failure on unknown topology, component version or intent;
- no network or target mutation during render;
- complete immutable artifact and license inventory;
- bounded comparison of two prototypes using the same plan/catalog;
- explicit preflight and limitation inventory for target-dependent claims;
- fail-closed audit output binding plan, catalog and bundle.

Executor acceptance is deliberately not part of this renderer decision. No executor may be implemented without the approval, idempotency, ownership and receipt contracts defined in the deployment architecture.
