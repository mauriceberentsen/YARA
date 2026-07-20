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
                    +
       ArtifactTransferReceipt...
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

`ArtifactImportReceipt` is a separate public contract for pre-apply model import evidence and internal non-secret file locations. For bounded bootstrap PVC ingestion, record it through:

```bash
go run ./cmd/yara deployment import kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --confirm-bundle sha256:<bundle-id> \
  --preflight reference-stack.preflight.yaml \
  --target sha256:<target-reference-digest> \
  --artifact-ref Qwen/Qwen2.5-Coder-7B-Instruct-AWQ \
  --source-dir ./offline-model \
  --internal-root model \
  --namespace reference-stack \
  --model-pvc yara-model \
  --name reference-stack-import \
  --output reference-stack.import-receipt.yaml \
  --audit-output reference-stack.import-receipt.audit.jsonl
```

Validate it through:

```bash
go run ./cmd/yara import-receipt validate reference-stack.import-receipt.yaml
```

The import command verifies local file digests/sizes against exact bundle model identities before mutation, stages only the selected artifact into the existing YARA-owned PVC, and fails closed on target/ownership/path drift. `deployment apply kubernetes` requires this receipt and rejects mutation when its plan/bundle/target or file bindings drift from the reviewed bundle.

`BootstrapReceipt` is a separate immutable contract for first-use namespace and model PVC provisioning. Record it through:

```bash
go run ./cmd/yara deployment bootstrap kubernetes \
  --name reference-stack-bootstrap \
  --namespace reference-stack \
  --model-pvc yara-model \
  --storage-class local-path \
  --size 200Gi \
  --target sha256:<target-reference-digest> \
  --receipt-output reference-stack.bootstrap-receipt.yaml \
  --audit-output reference-stack.bootstrap.audit.jsonl
```

Validate it through:

```bash
go run ./cmd/yara bootstrap-receipt validate reference-stack.bootstrap-receipt.yaml
```

Bootstrap remains bounded: it creates only the declared YARA-owned namespace and one model PVC, and fails closed on foreign ownership or storage-configuration drift. It does not run import, apply, retirement or rollback flows.

`ArtifactTransferReceipt` is a separate immutable chain-of-custody contract for offline transfer stages between import and deployment contexts. Record it through:

```bash
go run ./cmd/yara artifact transfer record \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --import-receipt reference-stack.import-receipt.yaml \
  --stage vault-to-registry \
  --source-attestation-ref ticket-src \
  --destination-attestation-ref ticket-dst \
  --name reference-stack-transfer \
  --output reference-stack.transfer-receipt.yaml \
  --audit-output reference-stack.transfer-receipt.audit.jsonl
```

Validate it through:

```bash
go run ./cmd/yara artifact-transfer-receipt validate reference-stack.transfer-receipt.yaml
```

For bundles whose embedded offline-acquisition policy marks air-gapped execution (`networkRequiredDuringAcquisition: true` and `networkAllowedDuringExecution: false`), `deployment apply kubernetes` now requires at least one transfer receipt that binds the same plan/bundle/catalog/target, exactly matches required model artifacts and forms a prior-receipt chain back to the `ArtifactImportReceipt`.

`ArtifactScanReceipt` is a separate immutable scanner-verdict contract for exact transferred artifacts. Record it through:

```bash
go run ./cmd/yara artifact scan record \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --transfer-receipt reference-stack.transfer-receipt.yaml \
  --scanner-name trivy \
  --scanner-version 0.53.0 \
  --scanner-profile offline-policy-default \
  --policy-digest sha256:<policy-id> \
  --verdict passed \
  --reason-reference ticket-scan-123 \
  --name reference-stack-scan \
  --output reference-stack.scan-receipt.yaml \
  --audit-output reference-stack.scan-receipt.audit.jsonl
```

Validate it through:

```bash
go run ./cmd/yara artifact-scan-receipt validate reference-stack.scan-receipt.yaml
```

For air-gapped policy bundles, apply now additionally requires at least one passed scan receipt bound to the same plan/bundle/catalog/target, exact model artifact identities, and a prior-receipt chain that references accepted transfer receipts.

`AirgapProvenanceGateResult` is a separate deterministic policy-evaluation resource that summarizes import+transfer+scan gate outcomes without mutating deployment state:

```bash
go run ./cmd/yara airgap provenance-gate evaluate \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --import-receipt reference-stack.import-receipt.yaml \
  --transfer-receipt reference-stack.transfer-receipt.yaml \
  --scan-receipt reference-stack.scan-receipt.yaml \
  --private-key gate-private.pem \
  --key-id operations-key-1 \
  --reason-reference ticket-gate-123 \
  --name reference-stack-airgap-gate \
  --output reference-stack.airgap-gate.yaml \
  --audit-output reference-stack.airgap-gate.audit.jsonl

go run ./cmd/yara airgap provenance-gate verify \
  --gate-result reference-stack.airgap-gate.yaml \
  --trust-policy reference-stack.airgap-gate-trust-policy.yaml \
  --confirm-policy 'sha256:<full-policy-id>' \
  --policy-diff reference-stack.airgap-gate-trust-policy-diff.yaml \
  --confirm-policy-diff 'sha256:<full-policy-diff-id>' \
  --transition-review reference-stack.airgap-gate-transition-review.yaml \
  --confirm-transition-review 'sha256:<full-transition-review-id>'

go run ./cmd/yara airgap gate-trust-policy record \
  --target-reference-digest sha256:<target-reference-digest> \
  --signer key-id=operations-key-1,public-key=gate-public.pem,status=active \
  --name reference-stack-airgap-gate-trust-policy \
  --output reference-stack.airgap-gate-trust-policy.yaml \
  --audit-output reference-stack.airgap-gate-trust-policy.audit.jsonl

go run ./cmd/yara airgap gate-trust-policy diff \
  --from-policy previous.airgap-gate-trust-policy.yaml \
  --to-policy reference-stack.airgap-gate-trust-policy.yaml \
  --name reference-stack-airgap-gate-trust-policy-diff \
  --output reference-stack.airgap-gate-trust-policy-diff.yaml \
  --audit-output reference-stack.airgap-gate-trust-policy-diff.audit.jsonl

go run ./cmd/yara airgap gate-trust-policy review-transition \
  --policy-diff reference-stack.airgap-gate-trust-policy-diff.yaml \
  --decision approved \
  --reviewer-role platform-security \
  --reason-reference ticket-airgap-transition-review-123 \
  --name reference-stack-airgap-gate-transition-review \
  --output reference-stack.airgap-gate-transition-review.yaml \
  --audit-output reference-stack.airgap-gate-transition-review.audit.jsonl
```

Validate it through:

```bash
go run ./cmd/yara airgap-provenance-gate-result validate reference-stack.airgap-gate.yaml
```

When provided via `deployment apply kubernetes --airgap-gate-result --airgap-gate-trust-policy --confirm-airgap-gate-trust-policy`, apply can fail closed on this gate binding instead of recomputing provenance checks ad hoc. The gate result must be passed, signature-valid under an active trust-policy signer identity, explicitly policy-confirmed by operator-supplied `policyId`, unexpired at apply time, and bind the exact plan/bundle/catalog/target/import identities plus referenced receipt sets. For automated policy transitions, apply can also consume `--airgap-gate-policy-diff --confirm-airgap-gate-policy-diff`; destructive policy diffs additionally require `--airgap-gate-transition-review --confirm-airgap-gate-transition-review` with an approved transition review bound to the same diff/policy/target.

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

## Separate authorized rollback

Rollback is a separate bounded restore path and is never inferred from drift:

```bash
go run ./cmd/yara authorization issue-rollback \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --private-key execution-private.pem \
  --key-id operations-key-1 \
  --name reference-stack-rollback-authorization \
  --output reference-stack.rollback.authorization.yaml \
  --audit-output reference-stack.rollback.authorization.audit.jsonl

go run ./cmd/yara deployment rollback kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --authorization reference-stack.rollback.authorization.yaml \
  --public-key execution-public.pem \
  --confirm-authorization 'sha256:<full-authorization-id>' \
  --name reference-stack-rollback \
  --receipt-output reference-stack.rollback.receipt.yaml \
  --audit-output reference-stack.rollback.audit.jsonl
```

Rollback authorization requires fresh exact reviewed inputs and non-delete constraints bound to the reviewed action set and operation count. The executor rechecks ownership/state under lock, applies only reviewed `create`/`update` operations, and emits a content-addressed `RollbackReceipt`.

## Lifecycle proof ledger

Phase-3 rehearsal evidence can now be linked without granting mutation authority:

```bash
go run ./cmd/yara lifecycle proof record \
  --apply-receipt reference-stack.receipt.yaml \
  --retirement-receipt reference-stack.retirement.receipt.yaml \
  --rollback-receipt reference-stack.rollback.receipt.yaml \
  --reviewer-role platform-security \
  --decision approved \
  --reason-reference ticket-lifecycle-proof-123 \
  --name reference-stack-lifecycle-proof \
  --output reference-stack.lifecycle-proof-ledger.yaml \
  --audit-output reference-stack.lifecycle-proof-ledger.audit.jsonl

go run ./cmd/yara lifecycle-proof-ledger validate reference-stack.lifecycle-proof-ledger.yaml
```

`lifecycle proof record` fails closed unless all receipts are valid, belong to the same plan/bundle/target, are ordered apply->retire->rollback, succeeded, and remain within the configured freshness window.

## Audit and privacy

Change-set generation and approval recording require audit output and remove generated resources if terminal audit persistence fails. Events bind immutable resource and pseudonymous target digests. They exclude kubeconfig paths, contexts, API endpoints and full Kubernetes objects. Approval reasons are non-secret references, not free-form justifications or credentials.

## Remaining lifecycle work after initial apply

- short-lived Kubernetes credential issuance remains operator-managed;
- acquisition/import/scanning execution remains out of scope; apply consumes separate import, transfer and scan receipts (or a passed equivalent gate result binding) and re-verifies model-PVC file digests;
- verifier-label admission governance remains an explicit limitation;
- safe owned rollback and retirement are implemented as separate authorization and executor paths;
- clean-cluster namespace, storage and model provisioning remain outside the first executor.
