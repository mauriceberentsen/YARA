# Authorized Kubernetes apply

## Status and boundary

YARA has an initial direct Kubernetes executor for the exact LiteLLM/vLLM bundle produced by `yara.kubernetes-gitops@0.1.0`. It is intentionally not a clean-cluster installer. Before execution, the exact YARA-owned namespace and a bound `yara-model` PVC containing the bundle-declared model files must already exist.

The executor can create or server-side-apply only the ConfigMap, Deployments, ClusterIP Services and NetworkPolicies present in the approved bundle. The Namespace must be an exact `no-op`. It cannot delete or prune managed resources, create storage, import models, adopt foreign resources, change architecture or bypass an observed change set.

## Safety chain

Apply consumes eight explicit inputs:

1. content-addressed `DeploymentBundle`;
2. fresh `TargetPreflightResult`;
3. exact conflict-free `KubernetesChangeSet`;
4. unexpired `DeploymentApproval` with `decision: approved` and `effect: review-only`;
5. content-addressed `ArtifactImportReceipt` binding exact imported model identities and non-secret internal file locations;
6. short-lived Ed25519-signed `ExecutionAuthorization` binding the reviewed deployment inputs;
7. explicitly trusted Ed25519 public key;
8. an operator confirmation equal to the full authorization ID.

Structural validation is not authority. The command verifies the signature, trusted public-key digest, validity window, target and every content binding. Allowed actions, operation count, delete prohibition, active-verification flag and accepted preflight blockers must exactly match the reviewed inputs.

Immediately before mutation the executor re-identifies the cluster. It then creates an exclusive namespaced Lease and re-observes every approved object while holding that Lease. Target drift, changed ownership, a changed plan annotation or a different current digest stops execution before any bundle object is applied.

## Command

Run this only after producing and reviewing all prerequisite resources:

```bash
go run ./cmd/yara deployment apply kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --import-receipt reference-stack.import-receipt.yaml \
  --authorization reference-stack.authorization.yaml \
  --public-key execution-public.pem \
  --confirm-authorization 'sha256:<full-authorization-id>' \
  --name reference-stack-deployment \
  --receipt-output reference-stack.receipt.yaml \
  --audit-output reference-stack.apply.audit.jsonl \
  --kubeconfig /path/to/ephemeral-kubeconfig \
  --context approved-context \
  --timeout 30m
```

The authorization is valid for at most 15 minutes, while the change set must have been observed no more than five minutes before authorization issuance. Generate these inputs immediately before apply. Existing receipt and audit files are never overwritten.

## CPU-only development clusters

Rancher Desktop, kind and similar CPU-only clusters are useful for validating the negative safety path, but they cannot establish a successful apply claim for the current reference bundle. That bundle requires a tested Kubernetes minor, a compatible image platform, allocatable `nvidia.com/gpu` capacity and the exact model PVC.

Run plan, render, preflight and change-set normally. Expected environment failures such as an unsupported Kubernetes minor or zero GPU capacity must remain `failed`, not be rewritten as acceptable active-verification blockers. `authorization issue` must then reject the deployment and produce a failed audit chain. Verify that no authorization artifact and no target namespace were created.

Do not hand-author a passing preflight, patch node capacity, remove the rendered GPU request or directly construct a signed authorization to force a CPU-only test through the production executor. Those actions invalidate the evidence chain rather than test it. A future lightweight executor-conformance fixture must use a separate explicit test contract and must never produce a production `DeploymentReceipt`.

## Active prerequisite and postflight checks

When the authorization explicitly accepts the passive preflight blockers, the executor creates a temporary hardened verifier Pod using the pinned vLLM image. It mounts `yara-model` read-only, verifies every declared model-file size and SHA-256 digest and proves executable `/tmp`. The Pod has no service-account token, a read-only root filesystem, no Linux capabilities, no privilege escalation and RuntimeDefault seccomp.

The verifier invokes the image's stable `/usr/bin/python3` entrypoint explicitly; it does not depend on an optional `python` alias or image-default entrypoint. YARA observes Pod status directly and treats terminal startup states such as `ContainerCannotRun`, `CreateContainerConfigError` and `InvalidImageName` as immediate prerequisite failures. It still permits transient scheduling and image-pull states until the bounded verifier timeout.

The inference workload retains a read-only root filesystem. Its writable runtime and compilation caches are redirected through `HOME`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME` and `FLASHINFER_WORKSPACE_BASE` into the existing `/tmp` `emptyDir`; model storage remains mounted separately and read-only.

After apply, the executor:

- waits for every bundle Deployment rollout;
- creates a second temporary verifier Pod;
- checks the LiteLLM liveness endpoint;
- sends one bounded OpenAI-compatible inference request through LiteLLM;
- verifies that direct access from the verifier to the vLLM Service is denied by NetworkPolicy;
- deletes the owned verifier Pod;
- verifies Lease ownership and releases the Lease.

Verifier-label admission governance cannot be proved by this executor and remains an explicit receipt limitation. A passing network probe proves only the observed request path at that time, not universal CNI correctness.

## Durable evidence and failure behavior

Before the Lease create, YARA exclusively creates the receipt destination and writes plus `fsync`s `deployment.apply.started` to the audit file. If audit initialization fails, no mutation is attempted.

After the Lease has been acquired, every exit produces a content-addressed `DeploymentReceipt` with:

- the plan, bundle, preflight, change-set, approval, import-receipt and authorization IDs;
- pseudonymous target identity;
- exact executor version and running binary digest;
- each approved operation as applied, unchanged, failed or skipped;
- active/postflight evidence and stable diagnostics;
- explicit limitations and a derived succeeded, failed or partial outcome.

The terminal audit event is written only after the receipt is durable and binds its receipt ID. A terminal audit failure does not delete an already written receipt. This preserves the strongest available evidence after a mutation.

## Minimum Kubernetes permissions

Use a short-lived credential. The executor does not read Secrets and does not need delete permission for bundle resources. Its current command surface requires:

- cluster scope: `get` on the exact `kube-system` and target Namespace resource names, plus non-resource URL `get` on `/version`;
- target namespace: `get`, `create`, `patch` and `update` on ConfigMaps, Services, Deployments and NetworkPolicies as required by server-side apply;
- target namespace: `get`, `list` and `watch` for rollout observation of Deployments, ReplicaSets and Pods;
- target namespace: `create`, `get`, `watch` and `delete` for owned temporary verifier Pods;
- target namespace: `create`, `get` and `delete` for the exact YARA Lease;
- target namespace: `get` on the exact `yara-model` PVC.

Kubernetes RBAC cannot restrict `create` by resource name and does not prove admission policy. Bind the Role only for the duration of one authorization, apply admission controls for YARA labels and image digests, and revoke the credential after receipt production.

## Explicitly unsupported

- namespace or PVC provisioning;
- connected/offline artifact acquisition or import execution workflows;
- Secret creation or secret-value handling;
- deletion, pruning, adoption and rollback;
- changing a renderer decision during apply;
- automatic retry after partial failure;
- multi-cluster, high-availability or stateful upgrade workflows.

Re-run preflight, change-set review, approval and authorization before retrying. Never reuse a stale change set after a partial result.
