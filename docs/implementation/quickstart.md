# First-use quickstart (M3)

## Scope and honesty boundary

This walkthrough documents the currently implemented first-use path for YARA on Kubernetes:

1. plan;
2. render;
3. bootstrap namespace/PVC;
4. import model artifact into PVC;
5. preflight (fresh read-only observation before review/apply);
6. change-set;
7. approval;
8. authorization;
9. apply;
10. receipt and audit verification.

It is intentionally bounded:

- no automatic clean-cluster installation;
- no automatic acquisition pipeline;
- no team API, web UI, multi-node planning, RAG topology, runtime manager, backup/restore or version-upgrade orchestration.

Use this as an implementation reference, not a claim of full production automation.

Note on current command contracts: `deployment import kubernetes` requires an exact preflight input for target/bundle binding. This guide therefore runs one preflight before import for identity binding, then refreshes preflight again before change-set and apply review.

## Prerequisites

- Go toolchain able to run `go run ./cmd/yara`.
- `kubectl` configured for the target cluster.
- Existing `catalog/v0.2/snapshot.yaml`.
- A local directory containing the model files declared by the selected bundle artifact.
- An ephemeral execution keypair for authorization signing:

```bash
openssl genpkey -algorithm ED25519 -out execution-private.pem
chmod 600 execution-private.pem
openssl pkey -in execution-private.pem -pubout -out execution-public.pem
```

## Evidence conventions

Each mutating step writes:

- one immutable resource output (`*.yaml`);
- one append-only audit chain (`*.audit.jsonl`).

Fail closed expectation: if a command cannot persist mandatory audit output, it must stop and not continue silently.

## Step 1: Create plan

```bash
go run ./cmd/yara plan create \
  --request docs/examples/v0.2-platform-request.yaml \
  --inventory docs/examples/v0.2-inventory.yaml \
  --catalog catalog/v0.2/snapshot.yaml \
  --output reference-stack.plan.yaml \
  --audit-output reference-stack.plan.audit.jsonl
```

Expected durable outputs:

- `reference-stack.plan.yaml`;
- `reference-stack.plan.audit.jsonl`.

Fail closed checkpoint:

- stop if plan creation exits non-zero or audit file is absent.

## Step 2: Render Kubernetes bundle

```bash
go run ./cmd/yara render kubernetes-gitops \
  --plan reference-stack.plan.yaml \
  --catalog catalog/v0.2/snapshot.yaml \
  --name reference-stack \
  --output reference-stack.kubernetes.bundle.yaml \
  --audit-output reference-stack.render.audit.jsonl
```

Expected durable outputs:

- `reference-stack.kubernetes.bundle.yaml`;
- `reference-stack.render.audit.jsonl`.

Optional verification:

```bash
go run ./cmd/yara bundle validate reference-stack.kubernetes.bundle.yaml
```

## Step 3: Bootstrap namespace and model PVC

Before running bootstrap, obtain the target digest from a fresh preflight (or a known validated target identity in your release process). Bootstrap requires explicit confirmation.

```bash
go run ./cmd/yara deployment bootstrap kubernetes \
  --name reference-stack-bootstrap \
  --namespace reference-stack \
  --model-pvc yara-model \
  --storage-class local-path \
  --size 200Gi \
  --target sha256:<target-reference-digest> \
  --receipt-output reference-stack.bootstrap.receipt.yaml \
  --audit-output reference-stack.bootstrap.audit.jsonl
```

Expected durable outputs:

- `reference-stack.bootstrap.receipt.yaml`;
- `reference-stack.bootstrap.audit.jsonl`.

Validation:

```bash
go run ./cmd/yara bootstrap-receipt validate reference-stack.bootstrap.receipt.yaml
```

Fail closed checkpoint:

- bootstrap must fail on target confirmation drift, foreign ownership, or storage mismatch.

## Step 4: Import model artifact into PVC

Stage one explicit model artifact into the bootstrap PVC. Use the exact bundle and target confirmations.

Generate a preflight input for import binding:

```bash
go run ./cmd/yara target preflight kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --name reference-stack-preflight-import \
  --output reference-stack.preflight.import.yaml \
  --audit-output reference-stack.preflight.import.audit.jsonl
```

Then run import:

```bash
go run ./cmd/yara deployment import kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --confirm-bundle sha256:<bundle-id> \
  --preflight reference-stack.preflight.import.yaml \
  --target sha256:<target-reference-digest> \
  --artifact-ref Qwen/Qwen2.5-Coder-7B-Instruct-AWQ \
  --source-dir ./offline-model \
  --internal-root model \
  --namespace reference-stack \
  --model-pvc yara-model \
  --name reference-stack-import \
  --output reference-stack.import.receipt.yaml \
  --audit-output reference-stack.import.audit.jsonl
```

Expected durable outputs:

- `reference-stack.import.receipt.yaml`;
- `reference-stack.import.audit.jsonl`.

Validation:

```bash
go run ./cmd/yara import-receipt validate reference-stack.import.receipt.yaml
```

Fail closed checkpoints:

- bundle confirmation mismatch;
- target confirmation mismatch;
- unsafe path derivation;
- source digest/size mismatch;
- foreign or missing namespace/PVC ownership.

## Step 5: Preflight

```bash
go run ./cmd/yara target preflight kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --name reference-stack-preflight-apply \
  --output reference-stack.preflight.apply.yaml \
  --audit-output reference-stack.preflight.apply.audit.jsonl
```

Validation:

```bash
go run ./cmd/yara target-preflight validate reference-stack.preflight.apply.yaml
```

## Step 6: Change-set

```bash
go run ./cmd/yara target changeset kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.apply.yaml \
  --name reference-stack-change-set \
  --output reference-stack.change-set.yaml \
  --audit-output reference-stack.change-set.audit.jsonl
```

Validation:

```bash
go run ./cmd/yara change-set validate reference-stack.change-set.yaml
```

Fail closed checkpoint:

- stop if the change-set is `blocked` or not exactly bound to the selected preflight/bundle.

## Step 7: Record review approval

```bash
go run ./cmd/yara approval record \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.apply.yaml \
  --change-set reference-stack.change-set.yaml \
  --name reference-stack-approval \
  --decision approve \
  --reason-reference ticket-123 \
  --output reference-stack.approval.yaml \
  --audit-output reference-stack.approval.audit.jsonl
```

Validation:

```bash
go run ./cmd/yara approval validate reference-stack.approval.yaml
```

## Step 8: Issue and verify execution authorization

```bash
go run ./cmd/yara authorization issue \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.apply.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --private-key execution-private.pem \
  --key-id operations-key-1 \
  --name reference-stack-authorization \
  --valid-for 10m \
  --output reference-stack.authorization.yaml \
  --audit-output reference-stack.authorization.audit.jsonl
```

Then verify:

```bash
go run ./cmd/yara authorization verify \
  --authorization reference-stack.authorization.yaml \
  --public-key execution-public.pem \
  --audit-output reference-stack.authorization.verify.audit.jsonl
```

Fail closed checkpoint:

- stop if authorization does not verify under the explicit trusted public key.

## Step 9: Apply

Use exact confirmed authorization ID and the import receipt produced in step 4.

```bash
go run ./cmd/yara deployment apply kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.apply.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --import-receipt reference-stack.import.receipt.yaml \
  --authorization reference-stack.authorization.yaml \
  --public-key execution-public.pem \
  --confirm-authorization sha256:<authorization-id> \
  --name reference-stack-deployment \
  --receipt-output reference-stack.receipt.yaml \
  --audit-output reference-stack.apply.audit.jsonl
```

Expected durable outputs:

- `reference-stack.receipt.yaml`;
- `reference-stack.apply.audit.jsonl`.

Validation:

```bash
go run ./cmd/yara receipt validate reference-stack.receipt.yaml
go run ./cmd/yara audit verify reference-stack.apply.audit.jsonl
```

## Step 10: Optional contract checks and lifecycle evidence

If you have a real runtime target, continue with bounded contract commands (preflight/runtime/model/capacity/lifecycle) and their audit outputs. Treat these as additional evidence layers, not prerequisites for the apply receipt format itself.

## Simulated/local vs live classification

- **Simulated/local**: unit tests, fake-runner executor tests, local schema validation, local command dry runs without real cluster mutation.
- **Live**: this walkthrough is live only when commands execute against a real cluster and produce real receipt/audit artifacts in this session.

Do not classify simulated/local results as live.

## Deferred and unsupported paths (post-MVP)

Not part of this quickstart:

- runtime manager / drift detection;
- backup and restore workflows;
- version upgrade orchestration;
- team API and multi-user approval workflow;
- web UI review cockpit;
- multi-node and RAG/embedding topology support;
- additional hardware vendors beyond current scope.
