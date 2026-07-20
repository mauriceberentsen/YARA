# YARA quickstart (pre-alpha)

## Who this is for

Use this guide if you are evaluating what YARA can do today and want the shortest honest path to run the currently supported workflow.

For the full command-by-command implementation flow, use:

- `docs/implementation/quickstart.md`

## Expected time

- 20-30 minutes for local validation and plan/render commands.
- 45-90 minutes if you also run the bounded Kubernetes bootstrap/import/apply path on a real cluster.

## Minimum prerequisites

- Go toolchain compatible with this repository (`go.mod` is the source of truth).
- `make`, `git`, and `kubectl` available on your machine.
- Access to this repository with `catalog/v0.2/snapshot.yaml`.
- For Kubernetes execution path: a reachable cluster and an ephemeral Ed25519 authorization keypair.

## Supported pre-alpha path

1. Run repository checks:
   - `make check`
2. Create a deterministic plan:
   - `go run ./cmd/yara plan create --request docs/examples/v0.2-platform-request.yaml --inventory docs/examples/v0.2-inventory.yaml --catalog catalog/v0.2/snapshot.yaml --output reference-stack.plan.yaml --audit-output reference-stack.plan.audit.jsonl`
3. Render a Kubernetes bundle:
   - `go run ./cmd/yara render kubernetes-gitops --plan reference-stack.plan.yaml --catalog catalog/v0.2/snapshot.yaml --name reference-stack --output reference-stack.kubernetes.bundle.yaml --audit-output reference-stack.render.audit.jsonl`
4. Follow the bounded first-use chain:
   - bootstrap namespace/PVC -> import artifact -> preflight -> change-set -> approval -> authorization -> apply
5. Verify evidence outputs:
   - `go run ./cmd/yara receipt validate reference-stack.receipt.yaml`
   - `go run ./cmd/yara audit verify reference-stack.apply.audit.jsonl`

The exact command sequence, flags, and fail-closed checkpoints are documented in `docs/implementation/quickstart.md`.

## Known limitations for this quickstart

- This is not a general installer or production deployment manager.
- Full clean-cluster installation is out of scope.
- Air-gap acquisition, transfer-medium attestation chain, and scanning attestations remain external to this quickstart.
- Integration execution evidence is bounded contract evidence, not throughput/latency/SLA certification.

## Deferred features (not part of this path)

- runtime manager / drift detection;
- backup and restore workflows;
- version upgrade orchestration;
- team API and multi-user approval workflow;
- web UI / review cockpit;
- multi-node planning and RAG/embedding topology;
- additional hardware vendors beyond current NVIDIA-focused scope.
