# Change sets, approvals and deployment receipts

## Implemented boundary

This slice implements the review contracts immediately before an executor. It does not implement apply.

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
       future strong authorization
                    |
                    v
       future executor -> DeploymentReceipt
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

It binds plan, bundle, preflight, change set, approval, target, exact executor binary, execution correlation, per-object before/after evidence and postflight checks. Its overall outcome is derived from operation and postflight results.

There is deliberately no receipt-generation command. Only a future apply-capable executor, after rechecking target identity, freshness, strong approval, audit availability and operation lock, may produce one.

## Audit and privacy

Change-set generation and approval recording require audit output and remove generated resources if terminal audit persistence fails. Events bind immutable resource and pseudonymous target digests. They exclude kubeconfig paths, contexts, API endpoints and full Kubernetes objects. Approval reasons are non-secret references, not free-form justifications or credentials.

## Remaining blockers before apply

- authenticated/signed approval issuance and verification;
- exact executor permission manifest and short-lived credential acquisition;
- target lock and stale-change-set revalidation;
- acquisition/import receipts and model-PVC digest verification;
- active checks for CNI enforcement, executable temporary storage and verifier-label governance;
- postflight verifier, owned rollback/removal and durable receipt/audit transaction design.
