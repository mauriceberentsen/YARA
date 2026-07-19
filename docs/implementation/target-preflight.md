# Kubernetes target preflight

## Purpose and boundary

The Kubernetes target preflight is YARA's first target-aware implementation. It answers a narrow question:

> Which renderer assumptions can be observed safely on this target now, and which remain failed or unproven?

It does not apply manifests, validate admission behavior, approve a deployment or predict that a later apply will succeed. It consumes an already valid Kubernetes/GitOps `DeploymentBundle`; it cannot select or replace architecture.

## Command

```bash
go run ./cmd/yara target preflight kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --name reference-stack-preflight \
  --output reference-stack.preflight.yaml \
  --audit-output reference-stack.preflight.audit.jsonl \
  --timeout 30s
```

Use `--kubeconfig` and `--context` when the current kubectl selection is not the intended target. These values are forwarded only to kubectl and are never copied into the result or audit chain.

Validate the resource and its execution audit independently:

```bash
go run ./cmd/yara target-preflight validate reference-stack.preflight.yaml
go run ./cmd/yara audit verify reference-stack.preflight.audit.jsonl
```

Exit code `0` means the resource outcome is `passed`; `3` means trustworthy observation completed but at least one check is `blocked` or `failed`. The initial observer always leaves active-verification checks blocked, so a normal successful observation returns `3`. Exit code `2` indicates invalid input or output handling, `4` an internal failure and `5` an unsupported command or observer prerequisite.

## Read set

The observer invokes only these classes of command:

- `kubectl config view --minify --raw=false -o json` to resolve the selected API endpoint in memory;
- `kubectl get --raw=...` for version and API discovery;
- `kubectl get namespace`, `nodes`, selected kube-system DNS pods and the expected PVC.

Output is capped at 4 MiB per invocation and the complete operation is bounded to between one second and five minutes. kubectl stderr is discarded because it can contain endpoint or credential-provider detail. Execution errors are replaced with stable generic diagnostics.

The observer has no create, apply, patch, delete, exec or server-side dry-run code path. Tests inspect every generated command for that property. Operators should still provide the smallest read-only Kubernetes identity that can read the listed objects.

## Result contract

`TargetPreflightResult` is a strict `yara.dev/v1alpha1` resource. `metadata.resultId` is the canonical SHA-256 digest of the full resource with the ID field cleared. It binds:

- exact deployment bundle and platform plan identities;
- UTC observation timestamp and versioned read-only observer;
- target type, Kubernetes server version and pseudonymous reference digest;
- sorted checks with derived overall outcome;
- explicit limitations.

Each evidence digest covers only the check ID, status and sorted allowlisted facts. Resource validation recomputes both check evidence digests and the result ID. A non-passing check requires a stable `YARA-TPR-*` diagnostic code; a passing check may not carry one.

## Target identity and data minimization

The target reference is derived from the selected API-server address and the kube-system namespace UID, then stored only as a SHA-256 digest. This distinguishes observed clusters without publishing their raw identity. It is pseudonymization, not third-party authentication or attestation.

Durable result and audit evidence intentionally exclude:

- API endpoint and kubectl context;
- kubeconfig path or contents;
- namespace UID;
- node, pod and endpoint names;
- resource bodies, logs, secrets and environment variables.

Only aggregate GPU and DNS counts, namespace ownership booleans, PVC state and version/API availability are retained.

## Checks and interpretation

The current evaluator covers:

- Kubernetes minor in the renderer-tested 1.34–1.36 range;
- core/v1, apps/v1 and networking.k8s.io/v1 discovery;
- at least one DNS pod matching the renderer's selector;
- allocatable `nvidia.com/gpu` capacity;
- absence of a target namespace collision, or exact YARA plan ownership;
- expected `yara-model` PVC presence and `Bound` phase.

It deliberately reports these as blocked because passive API reads cannot prove them:

- exact model files and digests inside the PVC;
- actual NetworkPolicy enforcement by the installed CNI;
- executable `/tmp` behavior required by the workload;
- RBAC/admission governance of verifier labels.

`failed` means an observed fact conflicts with the renderer contract, such as an unsupported Kubernetes minor, no observed GPU, no matching DNS pod or a foreign namespace collision. `blocked` means evidence was unavailable or the property requires a later active/administrative verifier. Neither status authorizes mutation.

## Audit contract

Audit output is mandatory. A terminal event binds three subjects: `DeploymentBundle`, pseudonymous `DeploymentTarget` and `TargetPreflightResult`. It contains the stable diagnostic codes of every non-passing check. The audit target is the pseudonymous digest, never the raw endpoint or context.

If the terminal chain cannot be written, YARA removes the generated result and fails closed. If observation itself fails, the audit uses `kubernetes:unresolved`, binds the bundle and records only a generic diagnostic.

## Next boundary

The next implementation must define an exact observed change-set resource before any mutation. Approval must bind the plan, bundle, target identity, fresh preflight, exact change set and approver assurance. The apply-capable executor must be a separate least-privilege boundary with locking, ownership, postflight verification and a content-addressed deployment receipt.
