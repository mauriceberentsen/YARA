# YARA

> **Pre-alpha AI runtime planning and bounded deployment evidence.**

YARA is an open-source CLI for deterministic AI platform planning plus bounded, auditable deployment workflows. It is in **pre-alpha** and should be evaluated as an evidence-first engineering toolchain, not a production platform product.

## What YARA does today

Implemented and usable today:

- validate versioned resources and schemas (`v1alpha1`) with strict decode/validation rules;
- generate deterministic, explainable platform plans from request + inventory + catalog;
- render bounded reference bundles (Docker Compose and Kubernetes/GitOps) from exact plan identities;
- execute read-only Kubernetes preflight and change-set observation before any mutation;
- require review + signed short-lived authorization for mutation commands (`apply`, `retire`, `rollback`);
- produce content-addressed receipts and append-only audit chains for planning, review, execution, and publication gates;
- run deterministic CI and release checks with reproducible binary and schema artifacts.

## Hard support boundary (pre-alpha)

Current supported evaluation boundary:

- single-node Linux profile with NVIDIA-focused catalog coverage (including GB10 and Ada-class reference assertions);
- chat and coding oriented planning/evidence paths in the curated catalog snapshots;
- explicit, fail-closed Kubernetes executor paths only (no implicit installers, adopters, or global environment management);
- operator-reviewed workflows where immutable evidence IDs are the source of truth.

Out of scope for this pre-alpha support boundary:

- production SLA/uptime claims;
- implicit prune/adopt/delete behavior;
- undisclosed mutable automation beyond explicitly reviewed commands;
- claims of universal hardware, orchestration, or workload compatibility.

## Deferred features (not in pre-alpha)

The following are intentionally deferred and must not be interpreted as currently shipped:

- runtime manager / drift detection;
- backup and restore contracts;
- version upgrade path;
- team API and multi-user approval workflow;
- web UI / review cockpit;
- multi-node planning and RAG/embedding topology;
- additional hardware vendors beyond current NVIDIA-focused coverage.

## Suggested starting path

For first use on the currently implemented path:

1. Read the [implementation quickstart](docs/implementation/quickstart.md).
2. Run `make check`.
3. Generate/validate plan and render artifacts.
4. If using Kubernetes, follow preflight -> changeset -> approval -> authorization -> bounded apply exactly as documented.
5. Verify receipts and audit chains after each major step.

## Architecture at a glance

```text
PlatformRequest + Inventory + Policies
                    |
                    v
          Normalize and validate
                    |
                    v
          Derive required capabilities
                    |
                    v
     Generate -> filter -> score candidates
                    |
                    v
       Resolve dependencies and versions
                    |
                    v
       Validate topology and capacity
                    |
                    v
         Emit explainable PlatformPlan
                    |
          +---------+---------+
          |                   |
        review          authorized executor
```

The detailed design is in the [architecture documentation](docs/architecture/README.md).

## Scope

The complete product boundary, acceptance posture, and deferred roadmap are documented in:

- [Product scope](docs/product/scope.md)
- [Roadmap](docs/roadmap.md)
- [Implementation status](docs/implementation/README.md)

## Documentation

Start at the [documentation index](docs/README.md). Important documents include:

- [Vision and principles](docs/vision.md)
- [Product scope](docs/product/scope.md)
- [System architecture](docs/architecture/system-overview.md)
- [Domain model](docs/architecture/domain-model.md)
- [Planning pipeline](docs/architecture/planning-pipeline.md)
- [Catalog design](docs/catalogs/README.md)
- [Security model](docs/architecture/security.md)
- [Auditing model](docs/architecture/auditing.md)
- [Roadmap](docs/roadmap.md)
- [Architectural decisions](docs/adr/README.md)

## Development

The v0 implementation is written in Go and pins its toolchain through `go.mod`.

```bash
make check
go run ./cmd/yara version
go run ./cmd/yara request validate docs/examples/platform-request.yaml \
  --audit-output request-validation.audit.jsonl
go run ./cmd/yara inventory validate docs/examples/inventory.yaml
go run ./cmd/yara catalog validate catalog/v0.2/snapshot.yaml \
  --audit-output catalog-validation.audit.jsonl
go run ./cmd/yara catalog coverage create \
  --catalog catalog/v0.2/snapshot.yaml \
  --evidence-dir catalog/v0.2/evidence \
  --name catalog-v0.2-coverage \
  --output .yara/catalog-v0.2-coverage.yaml \
  --audit-output .yara/audit/catalog-v0.2-coverage.jsonl
go run ./cmd/yara plan create \
  --request docs/examples/v0.2-platform-request.yaml \
  --inventory docs/examples/v0.2-inventory.yaml \
  --catalog catalog/v0.2/snapshot.yaml \
  --output plan.yaml \
  --audit-output audit.jsonl
go run ./cmd/yara render docker-compose \
  --plan plan.yaml \
  --catalog catalog/v0.2/snapshot.yaml \
  --name reference-stack \
  --output reference-stack.bundle.yaml \
  --audit-output reference-stack.render.audit.jsonl
go run ./cmd/yara render kubernetes-gitops \
  --plan plan.yaml \
  --catalog catalog/v0.2/snapshot.yaml \
  --name reference-stack \
  --output reference-stack.kubernetes.bundle.yaml \
  --audit-output reference-stack.kubernetes.render.audit.jsonl
go run ./cmd/yara bundle validate reference-stack.bundle.yaml
go run ./cmd/yara bundle validate reference-stack.kubernetes.bundle.yaml
go run ./cmd/yara target preflight kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --name reference-stack-preflight \
  --output reference-stack.preflight.yaml \
  --audit-output reference-stack.preflight.audit.jsonl
go run ./cmd/yara target-preflight validate reference-stack.preflight.yaml
go run ./cmd/yara audit verify reference-stack.preflight.audit.jsonl
go run ./cmd/yara target changeset kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --name reference-stack-change-set \
  --output reference-stack.change-set.yaml \
  --audit-output reference-stack.change-set.audit.jsonl
go run ./cmd/yara approval record \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --name reference-stack-review \
  --decision approve \
  --reason-reference ticket-123 \
  --output reference-stack.approval.yaml \
  --audit-output reference-stack.approval.audit.jsonl
go run ./cmd/yara authorization issue \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --private-key execution-private.pem \
  --key-id operations-key-1 \
  --name reference-stack-execution \
  --output reference-stack.authorization.yaml \
  --audit-output reference-stack.authorization.audit.jsonl
go run ./cmd/yara authorization issue-retirement \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --private-key execution-private.pem \
  --key-id operations-key-1 \
  --name reference-stack-retirement-execution \
  --output reference-stack.retirement.authorization.yaml \
  --audit-output reference-stack.retirement.authorization.audit.jsonl
go run ./cmd/yara authorization issue-rollback \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --preflight reference-stack.preflight.yaml \
  --change-set reference-stack.change-set.yaml \
  --approval reference-stack.approval.yaml \
  --private-key execution-private.pem \
  --key-id operations-key-1 \
  --name reference-stack-rollback-execution \
  --output reference-stack.rollback.authorization.yaml \
  --audit-output reference-stack.rollback.authorization.audit.jsonl
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
  --audit-output reference-stack.apply.audit.jsonl
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
go run ./cmd/yara rollback-receipt validate reference-stack.rollback.receipt.yaml
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
go run ./cmd/yara lifecycle proof approve-publication \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --lifecycle-proof-ledger reference-stack.lifecycle-proof-ledger.yaml \
  --confirm-lifecycle-proof-ledger 'sha256:<full-ledger-id>' \
  --evidence sha256:<lifecycle-contract-result-id> \
  --reviewer-role release-manager \
  --decision approved \
  --reason-reference ticket-lifecycle-publication-123 \
  --max-ledger-age 720h \
  --name reference-stack-lifecycle-proof-approval \
  --output reference-stack.lifecycle-proof-approval.yaml \
  --audit-output reference-stack.lifecycle-proof-approval.audit.jsonl
go run ./cmd/yara lifecycle-proof-approval validate reference-stack.lifecycle-proof-approval.yaml
go run ./cmd/yara plan diff docs/examples/platform-plan.yaml plan.yaml \
  --audit-output plan-diff.audit.jsonl
go run ./cmd/yara debug bundle \
  --plan docs/examples/platform-plan.yaml \
  --output debug-bundle.json \
  --audit-output debug-bundle.audit.jsonl
go run ./cmd/yara scenario validate \
  scenarios/v0.1/private-chat-coding/scenario.yaml \
  --audit-output scenario-validation.audit.jsonl
go run ./cmd/yara scenario validate-all scenarios/v0.1 \
  --audit-output v0.1-scenario-suite.audit.jsonl
go run ./cmd/yara contract preflight \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-rtx4090 \
  --target user@host \
  --name rtx4090-preflight \
  --output contract-result.yaml \
  --audit-output contract-preflight.audit.jsonl
go run ./cmd/yara contract runtime-smoke \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-runtime-smoke \
  --output gb10-runtime-smoke.yaml \
  --audit-output gb10-runtime-smoke.audit.jsonl
go run ./cmd/yara contract model-inference \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-model-inference \
  --output gb10-qwen-coder-model-inference.yaml \
  --audit-output gb10-qwen-coder-model-inference.audit.jsonl
go run ./cmd/yara contract capacity-boundary \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-capacity-boundary \
  --output gb10-qwen-coder-capacity-boundary.yaml \
  --audit-output gb10-qwen-coder-capacity-boundary.audit.jsonl
go run ./cmd/yara contract policy \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-policy \
  --output gb10-qwen-coder-policy.yaml \
  --audit-output gb10-qwen-coder-policy.audit.jsonl
go run ./cmd/yara contract lifecycle \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --lifecycle-proof-ledger reference-stack.lifecycle-proof-ledger.yaml \
  --confirm-lifecycle-proof-ledger 'sha256:<full-ledger-id>' \
  --lifecycle-apply-receipt reference-stack.receipt.yaml \
  --lifecycle-retirement-receipt reference-stack.retirement.receipt.yaml \
  --lifecycle-rollback-receipt reference-stack.rollback.receipt.yaml \
  --confirm-lifecycle-reason-reference ticket-lifecycle-proof-123 \
  --lifecycle-proof-max-age 720h \
  --name gb10-qwen-coder-lifecycle \
  --output gb10-qwen-coder-lifecycle.yaml \
  --audit-output gb10-qwen-coder-lifecycle.audit.jsonl
go run ./cmd/yara promotion review record \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --evidence sha256:<accepted-result-id> \
  --reviewer-role release-manager \
  --decision approved \
  --reason-reference ticket-123 \
  --name gb10-qwen-coder-promotion-review \
  --output gb10-qwen-coder-promotion-review.yaml \
  --audit-output gb10-qwen-coder-promotion-review.audit.jsonl
go run ./cmd/yara artifact transfer record \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --import-receipt reference-stack.import-receipt.yaml \
  --stage vault-to-registry \
  --source-attestation-ref ticket-src \
  --destination-attestation-ref ticket-dst \
  --name reference-stack-transfer \
  --output reference-stack.transfer-receipt.yaml \
  --audit-output reference-stack.transfer-receipt.audit.jsonl
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

Currently implemented:

- strict YAML and JSON decoding with unknown-field and input-size protection;
- semantic validation for the first `PlatformRequest` and `Inventory` boundary;
- stable machine-readable diagnostics and CLI exit classes;
- public draft-2020-12 schemas for request, inventory, catalog manifests, plan and audit events;
- deterministic SHA-256 content digests;
- append-only audit-event chaining, tamper verification and `audit verify` CLI support;
- a frozen placeholder catalog for v0.1 acceptance plus a curated v0.2 snapshot with ten real components, two immutable model snapshots, three NVIDIA Ada profiles, one GB10 coherent-unified-memory profile, six selectable serving candidates and two knowledge-only GB10 hypotheses;
- open-world compatibility governance where explicit negative evidence overrides positive claims and conflicts are quarantined;
- a deterministic, content-addressed catalog coverage report that accepts only exact-catalog contract results with verified adjacent audit chains and exposes every missing promotion gate;
- a strict component/topology integration result contract whose validation audit cannot be mistaken for execution evidence;
- bounded integration execution commands for `component-smoke` and `topology-end-to-end` that emit content-addressed evidence with dedicated execution audit actions;
- independent promotion review records bound to exact catalog and selected evidence identities, with deterministic coverage-gate evaluation;
- artifact transfer chain-of-custody receipts bound to exact bundle artifacts and prior immutable receipt identities, required by apply when embedded offline policy marks air-gapped execution;
- artifact scan attestation receipts bound to exact transferred artifact identities and scanner policy/tool identities, required by apply for air-gapped policy bundles;
- deterministic air-gap provenance gate results that bind exact import/transfer/scan receipt sets and can be consumed by apply for fail-closed policy enforcement;
- a pure versioned Docker Compose renderer for the exact LiteLLM/vLLM topology, producing pinned files, artifact/license inventory, checks, limitations and a fail-closed render audit;
- a pure Kubernetes/GitOps renderer for the same exact topology plus content-addressed read-only target preflight and object-level change-set observation;
- review-only deployment approvals, short-lived signed execution authorization and a fail-closed direct Kubernetes executor producing deployment receipts;
- strict artifact-import receipts bound to plan/bundle/target and required before Kubernetes apply;
- safe owned-resource retirement as a separate signed delete-only command and receipt path;
- safe owned-state rollback as a separate signed non-delete command and receipt path;
- short-lived Ed25519-signed execution authorization bound to exact reviewed inputs and an explicitly trusted public key;
- a catalog-authored abstract topology template resolved into gateway and inference component instances;
- mandatory manifest ownership and provenance with deterministic snapshot-time freshness gates;
- a deterministic planner that applies asserted hardware compatibility and memory/policy constraints before scoring;
- independently validated multi-component `PlatformPlan` output with interface connections, dependency-safe deployment stages, explanations, rejected alternatives, explicit search bounds, ordinal confidence factors, governance diagnostics and content integrity;
- deterministic, content-addressed `PlatformPlanDiff` output with provenance causes, decision references and conservative review/redeploy/destructive impact classification;
- targeted `plan explain --decision` output with stable missing-decision diagnostics and optional fail-closed audit evidence bound to the exact explanation digest;
- deterministic, content-addressed `DebugBundle` output containing only an inspectable redacted plan summary, section inventory and successful secret-scan assertion;
- a content-addressed `GoldenScenario` contract and offline validator for exact inputs, plan identity, required decisions, forbidden outcomes, diagnostics and review requirements;
- a bounded, deterministic ten-case acceptance-suite validator with duplicate-identity rejection, planned/infeasible coverage and fail-closed audit evidence;
- a content-addressed `ContractTestResult` across read-only SSH preflight, isolated runtime smoke, bounded model inference, exact advertised-context boundary, serving-container policy and same-version restart lifecycle testing;
- tamper-evident audit chains for validation plus successful, infeasible and input-rejected planning outcomes, containing available input identities and stable diagnostic codes, including material warnings;
- optional fail-closed validation, plan-explanation and plan-diff audit receipts, plus mandatory fail-closed persistence for `plan create` and `debug bundle`, with path- and payload-minimized evidence for resources that cannot be decoded.

Selectable software, model, hardware and compatibility manifests in v0.2 remain explicitly `experimental`; their warning caps recommendation confidence and is preserved in generated plans and audit evidence. Researched suite components that lack YARA contract tests remain `known` and cannot be selected. Ten technically conformant v0.1 golden scenarios exist—seven planned and three infeasible—with approved `ScenarioReview` and `AcceptanceGateReview` resources counted by the CLI. Run `yara scenario validate-all scenarios/v0.1` to confirm `releaseEligible: true`. See the [v0.1 acceptance ledger](docs/implementation/v0.1-acceptance-status.md) and the [v0.2 catalog notes](catalog/v0.2/README.md).

## Project status

YARA is pre-alpha. Validation and audit commands are working foundations, not a platform recommendation or deployment product. Proposed integrations and catalog examples remain illustrative until backed by manifests, tests and maintained compatibility evidence.

## Contributing

Contribution policy for this pre-alpha phase:

- prefer small, reviewable changes that improve determinism, evidence quality, and fail-closed behavior;
- prioritize schema/resource validation, diagnostics stability, audit integrity, and reproducible docs/automation;
- avoid broad speculative feature expansion that weakens current support-boundary honesty.

Early contributions should improve falsifiability: clearer requirements, counterexamples, schemas, compatibility evidence, and test scenarios. Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes.

## License

YARA is licensed under the [Apache License 2.0](LICENSE). Third-party software selected or managed by YARA retains its own license; catalog inclusion never changes or supersedes that license.
