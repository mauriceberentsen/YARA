# Change sets, approvals and deployment receipts

## Implemented boundary

This document defines the review and authorization contracts consumed by the initial Kubernetes executor. Apply remains a distinct privileged command.

```text
DeploymentBundle
      + fresh TargetPreflightResult
      + read-only target observation
                    |
                    v
          KubernetesChangeSet
                    |
                    v
          DeploymentApproval
                    |
       signed ExecutionAuthorization
                    +
         ArtifactImportReceipt
                    |
                    v
       Kubernetes executor -> DeploymentReceipt
```

All resources are strict `yara.dev/v1alpha1` contracts with canonical SHA-256 identities. Bundle, plan, preflight, target and change-set bindings must match exactly.

## Read-only Kubernetes change set

Generate it within fifteen minutes of its bound preflight:

```bash
go run ./cmd/yara target changeset kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --name reference-stack-change-set \
  --output reference-stack.change-set.yaml \
  --audit-output reference-stack.change-set.audit.jsonl
```

Optional `--kubeconfig`, `--context` and `--timeout` settings are ephemeral and excluded from durable evidence. The observer re-identifies the target and rejects a context switch since preflight. It performs only `config view` and `get` operations.

The observer compares the twelve Namespace, ConfigMap, Deployment, Service and NetworkPolicy objects emitted by the current renderer. Each operation is one of:

- `create`: object was observably absent;
- `update`: exact YARA-owned object has a different normalized digest;
- `no-op`: exact YARA-owned object has the same normalized digest;
- `conflict`: an object exists without exact YARA/plan ownership;
- `unresolved`: read permission or trustworthy decoding was unavailable.

Conflict and unresolved operations derive an overall `blocked` outcome. No deletion is discovered or proposed. The comparison removes a small versioned allowlist of Kubernetes server-assigned metadata and known defaults; all other observed fields remain in the current digest. It does not invoke admission or server-side dry-run and cannot predict controller reconciliation.

Validate result and audit independently:

```bash
go run ./cmd/yara change-set validate reference-stack.change-set.yaml
go run ./cmd/yara audit verify reference-stack.change-set.audit.jsonl
```

## Local review record

Record an explicit review decision:

```bash
go run ./cmd/yara approval record \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --name reference-stack-review \
  --decision approve \
  --reason-reference ticket-123 \
  --valid-for 1h \
  --output reference-stack.approval.yaml \
  --audit-output reference-stack.approval.audit.jsonl
```

`approve` records `decision: approved`, but the current local command always records `effect: review-only`. Its actor is the local OS user with `self-asserted-local` assurance. It therefore cannot satisfy a future executor's execution-authorization gate. Rejection is also review-only.

The v1alpha1 contract permits only `review-only`; manually writing `assurance: signed` cannot create authority. A future execution-authorized schema needs a real authenticated/signature envelope, trust policy and verifier. Review records have a validity interval no longer than 24 hours.

## Signed execution authorization

Execution authority is a separate short-lived `ExecutionAuthorization`, not an upgraded approval field. Generate an Ed25519 key under organization-controlled policy:

```bash
openssl genpkey -algorithm ED25519 -out execution-private.pem
chmod 600 execution-private.pem
openssl pkey -in execution-private.pem -pubout -out execution-public.pem
```

Issue a capability over the exact reviewed inputs:

```bash
go run ./cmd/yara authorization issue \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --private-key execution-private.pem \
  --key-id operations-key-1 \
  --name reference-stack-execution \
  --valid-for 10m \
  --output reference-stack.authorization.yaml \
  --audit-output reference-stack.authorization.audit.jsonl
```

The issuer requires a preflight no older than 15 minutes, a change set no older than 5 minutes, a currently valid approved review record, a conflict-free operation set and private-key permissions no broader than `0600`. Authorization expires after at most 15 minutes and always forbids deletion. Its signed constraints contain the exact allowed actions, maximum operation count and explicitly accepted preflight blockers that the executor must verify or retain as limitations.

Verify against an explicitly trusted public key:

```bash
go run ./cmd/yara authorization verify \
  --authorization reference-stack.authorization.yaml \
  --public-key execution-public.pem \
  --audit-output reference-stack.authorization-verification.audit.jsonl
```

Structural schema validation alone never establishes authority. Consumers must verify the Ed25519 signature, public-key digest, trust-policy key selection and current validity. Private-key paths and bytes are excluded from result and audit evidence.

## Deployment receipt

`DeploymentReceipt` is public and independently validateable through:

```bash
go run ./cmd/yara receipt validate receipt.yaml
```

It binds plan, bundle, preflight, change set, approval, signed authorization, target, exact executor binary, execution correlation, per-object before/after evidence and postflight checks. Its overall outcome is derived from operation and postflight results.

`ArtifactImportReceipt` is a separate public contract for pre-apply model import evidence and internal non-secret file locations. Validate it through:

```bash
go run ./cmd/yara import-receipt validate reference-stack.import-receipt.yaml
```

`deployment apply kubernetes` now requires this receipt and rejects mutation when its plan/bundle/target or file bindings drift from the reviewed bundle.

## Separate authorized retirement

Retirement is a separate delete-only path and never extends ordinary apply with prune behavior:

```bash
go run ./cmd/yara authorization issue-retirement \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --private-key execution-private.pem \
  --key-id operations-key-1 \
  --name reference-stack-retirement-authorization \
  --output reference-stack.retirement.authorization.yaml \
  --audit-output reference-stack.retirement.authorization.audit.jsonl

go run ./cmd/yara deployment retire kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --authorization reference-stack.retirement.authorization.yaml \
  --public-key execution-public.pem \
  --confirm-authorization 'sha256:<full-authorization-id>' \
  --name reference-stack-retirement \
  --receipt-output reference-stack.retirement.receipt.yaml \
  --audit-output reference-stack.retirement.audit.jsonl
```

Retirement authorization requires an exact fresh no-op owned baseline and issues delete-only constraints. The executor then rechecks ownership/digests under lock before each delete and emits a content-addressed `RetirementReceipt`.

The initial apply-capable executor now produces this receipt after rechecking target identity, signed authorization, audit availability and operation state under a Lease. See [Authorized Kubernetes apply](kubernetes-apply.md).

## Audit and privacy

Change-set generation and approval recording require audit output and remove generated resources if terminal audit persistence fails. Events bind immutable resource and pseudonymous target digests. They exclude kubeconfig paths, contexts, API endpoints and full Kubernetes objects. Approval reasons are non-secret references, not free-form justifications or credentials.

## Remaining lifecycle work after initial apply

- short-lived Kubernetes credential issuance remains operator-managed;
- acquisition/import execution remains out of scope; apply only consumes a separate import receipt and re-verifies model-PVC file digests;
- verifier-label admission governance remains an explicit limitation;
- owned rollback remains unimplemented; safe owned-resource retirement is implemented as a separate authorization and executor path;
- clean-cluster namespace, storage and model provisioning remain outside the first executor.
