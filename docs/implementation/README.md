# v0.1 implementation guide

## Start condition

The foundational architecture is sufficiently defined to begin a thin v0.1 implementation. Open product questions remain, but they do not block the first vertical slice. The first code should test the architecture, not attempt the full catalog or planner.

## Current implementation status

The bootstrap now includes strict resource decoding, public schemas, stable diagnostics, canonical digests and audit-event chaining. The catalog compiler resolves capability, component, model, hardware, compatibility and topology manifests. Every manifest declares lifecycle status, owners, evidence sources, confidence and a verification/review window. Freshness is evaluated deterministically against the immutable snapshot `publishedAt`; missing ownership, malformed provenance and expired evidence invalidate the snapshot. The bundled fixtures remain experimental and emit `YARA-CAT-055` into catalog output, plans, explanations, diffs, debug bundles, scenarios and audit evidence. Compatibility quarantine, multi-component topology resolution and independent plan validation remain active. Generated plans state bounded search and ordinal confidence; explanation, diff and debug-bundle paths are auditable. `scenario validate-all` proves exact offline technical conformance for ten content-addressed cases and counts approved review resources for release eligibility. See the [v0.1 acceptance ledger](v0.1-acceptance-status.md).

After v0.1 acceptance, `catalog/v0.2/` introduces the first curated real stack. It contains ten versioned suite components, two immutable Qwen AWQ model snapshots, three NVIDIA Ada hardware profiles, one GB10 coherent-unified-memory profile, six compatibility-bounded selectable serving candidates and two knowledge-only GB10 test hypotheses. LiteLLM and vLLM are selectable only as experimental components; Open WebUI, Qdrant, PostgreSQL, Redis, ClickHouse, Prometheus, Grafana and Langfuse remain knowledge-only until their YARA integration contracts are tested. The planner rejects requests outside a candidate's asserted context window or minimum driver branch. [Contract testing](contract-testing.md) includes read-only SSH preflight, isolated runtime smoke, bounded model inference, exact advertised-context capacity, repeated-request capacity, serving-container policy and same-version lifecycle recovery. [Integration testing](integration-testing.md) now includes bounded `integration component-smoke` and `integration topology-end-to-end` execution commands that emit separately audited evidence bound to exact manifest versions. The audited `CatalogCoverageReport` compiles exact-catalog evidence into explicit passed, failed, blocked, missing and not-implemented gates. Both GB10 tuples passed every implemented technical compatibility gate, but remain knowledge-only because component/topology integration coverage and independent promotion are incomplete.

The [offline renderers](rendering.md) translate the exact LiteLLM/vLLM plan into content-addressed Docker Compose or Kubernetes/GitOps `DeploymentBundle` resources. Both remain pure and never acquire or deploy anything. The [Kubernetes target preflight](target-preflight.md), [change-set and approval flow](change-sets-and-approvals.md), and short-lived signed authorization lead to the [initial direct executor](kubernetes-apply.md). It can apply the exact authorized bundle to an existing YARA-owned namespace and model PVC, with a Lease, active verification, mandatory durable auditing and a content-addressed receipt.

## Fixed decisions

- Go CLI and planning core ([ADR-0008](../adr/0008-use-go-for-the-v0-cli-and-core.md)).
- Versioned YAML/JSON resources validated by JSON Schema.
- Declarative request compiled into immutable platform plan.
- Offline deterministic planner with no target mutation.
- Git-authored, compiled catalog snapshots.
- Hard constraints before soft scoring.
- Structured decisions, diagnostics and append-only audit evidence.
- Single Linux host, homogeneous NVIDIA hardware, chat/coding scope.

## Decisions intentionally deferred

- Clean-cluster bootstrap and acquisition/import execution workflows remain deferred beyond the bounded Kubernetes executor. Safe owned-resource retirement and rollback are separate authorized paths.
- Persistent service/API database.
- Web UI framework.
- General plugin transport implementation.
- Graph database or external solver.
- Commercial feature boundary.

None should appear in the first vertical slice.

## Bootstrap deliverables

1. Go module, formatter/linter/test commands and CI.
2. Minimal `yara` CLI with stable exit codes.
3. v1alpha1 schemas for `PlatformRequest`, `Inventory`, `DiagnosticReport`, `PlatformPlan` and `AuditEvent`.
4. Strict YAML-to-typed-resource loading with unknown-field rejection.
5. Canonical JSON and digest test vectors.
6. One capability, topology, component, model and hardware catalog fixture.
7. One end-to-end planning scenario and unsafe counterexample.
8. `plan create`, `plan validate` and `plan explain` for that scenario.
9. Local append-only audit output with chain verification.

## Engineering rules

- Keep raw resource types separate from validated domain types.
- Use explicit units and typed unknown/absent states.
- Inject clock, ID generator and file interfaces; planner semantics never read wall clock.
- Sort every externally visible unordered collection.
- Return stable domain diagnostic codes rather than matching error strings.
- Never log complete input resources or environment variables.
- No network client or deployment dependency in planner packages.
- Do not generalize until a second concrete scenario needs it.

## Definition of done for a slice

- User scenario and acceptance behavior documented.
- Public schema and migration impact reviewed.
- Success, negative, boundary and unknown tests included.
- Material decision and audit coverage included.
- Offline/determinism checks pass.
- Documentation and example updated.
- No unsupported catalog claim introduced.
- `go test ./...`, formatting, static analysis, schema and link checks pass.

## First package boundaries

```text
cmd/yara                 command wiring and presentation only
internal/application     use-case orchestration
internal/domain          validated immutable domain values
internal/resources       v1alpha1 wire resources and conversion
internal/catalog         snapshot loading and typed queries
internal/planner         pure stages and decision construction
internal/plandiff        pure semantic plan comparison and impact classification
internal/debugbundle     allowlisted support summaries and secret-pattern gate
internal/scenario        offline golden-scenario conformance evaluation
internal/contracttest    read-only environment observation and pure contract evaluation
internal/renderer        pure versioned plan-to-bundle prototype; no target access
internal/targetpreflight bounded read-only target observation and pure evaluation
internal/changeset       bounded Kubernetes object projection, observation and comparison
internal/diagnostics     stable codes and structured reports
internal/audit           event construction, redaction and local sink
internal/canonical       canonical JSON and content digests
```

Package names can adjust during bootstrap, but dependency direction from the [repository layout](../architecture/repository-layout.md) remains mandatory.

## Initial command behavior

```text
yara request validate request.yaml --audit-output request-validation.audit.jsonl
yara inventory validate inventory.yaml
yara catalog validate catalog/v0.1/snapshot.yaml --audit-output catalog-validation.audit.jsonl
yara catalog coverage create --catalog catalog/v0.2/snapshot.yaml \
  --evidence-dir catalog/v0.2/evidence --name catalog-v0.2-coverage \
  --output catalog-v0.2-coverage.yaml --audit-output catalog-v0.2-coverage.audit.jsonl
yara catalog coverage validate catalog-v0.2-coverage.yaml
yara catalog coverage lifecycle-publication-policy \
  --report catalog-v0.2-coverage.yaml \
  --audit-output catalog-v0.2-coverage.lifecycle-publication-policy.audit.jsonl
yara integration execute component-smoke --catalog catalog/v0.2/snapshot.yaml \
  --target local --component core.litellm@1.93.0 \
  --confirm-catalog-digest sha256:<catalog-digest> --name litellm-smoke \
  --output litellm-smoke.integration.yaml --audit-output litellm-smoke.integration.audit.jsonl
yara plan create --request request.yaml --inventory inventory.yaml \
  --catalog catalog/ --output plan.yaml --audit-output audit.jsonl
yara plan validate plan.yaml --audit-output plan-validation.audit.jsonl
yara plan explain plan.yaml --decision decision.inference \
  --audit-output plan-explanation.audit.jsonl
yara plan diff old-plan.yaml new-plan.yaml --audit-output plan-diff.audit.jsonl
yara debug bundle --plan plan.yaml --output debug-bundle.json \
  --audit-output debug-bundle.audit.jsonl
yara scenario validate scenarios/v0.1/private-chat-coding/scenario.yaml \
  --audit-output scenario-validation.audit.jsonl
yara scenario validate-all scenarios/v0.1 \
  --audit-output v0.1-scenario-suite.audit.jsonl
yara contract preflight --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-rtx4090 \
  --target user@host --name rtx4090-preflight \
  --output contract-result.yaml --audit-output contract-preflight.audit.jsonl
yara contract runtime-smoke --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example --name gb10-runtime-smoke \
  --output gb10-runtime-smoke.yaml --audit-output gb10-runtime-smoke.audit.jsonl
yara contract model-inference --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example --name gb10-qwen-coder-model-inference \
  --output gb10-model-inference.yaml --audit-output gb10-model-inference.audit.jsonl
yara contract capacity-boundary --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example --name gb10-capacity-boundary \
  --output gb10-capacity-boundary.yaml --audit-output gb10-capacity-boundary.audit.jsonl
yara contract sustained-capacity --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example --name gb10-sustained-capacity \
  --output gb10-sustained-capacity.yaml --audit-output gb10-sustained-capacity.audit.jsonl
yara contract lifecycle --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --lifecycle-proof-ledger reference-stack.lifecycle-proof-ledger.yaml \
  --confirm-lifecycle-proof-ledger 'sha256:<full-ledger-id>' \
  --lifecycle-apply-receipt reference-stack.receipt.yaml \
  --lifecycle-retirement-receipt reference-stack.retirement.receipt.yaml \
  --lifecycle-rollback-receipt reference-stack.rollback.receipt.yaml \
  --confirm-lifecycle-reason-reference ticket-lifecycle-proof-123 \
  --lifecycle-proof-max-age 720h \
  --target user@gb10-runner.example --name gb10-lifecycle \
  --output gb10-lifecycle.yaml --audit-output gb10-lifecycle.audit.jsonl
yara lifecycle proof approve-publication --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --lifecycle-proof-ledger reference-stack.lifecycle-proof-ledger.yaml \
  --confirm-lifecycle-proof-ledger 'sha256:<full-ledger-id>' \
  --evidence sha256:<lifecycle-contract-result-id> \
  --reviewer-role release-manager --decision approved \
  --reason-reference ticket-lifecycle-publication-123 --max-ledger-age 720h \
  --name gb10-lifecycle-proof-approval \
  --output gb10-lifecycle-proof-approval.yaml --audit-output gb10-lifecycle-proof-approval.audit.jsonl
yara contract validate contract-result.yaml
yara target preflight kubernetes --bundle kubernetes-bundle.yaml \
  --name reference-preflight --output preflight.yaml \
  --audit-output preflight.audit.jsonl
yara target-preflight validate preflight.yaml
yara target changeset kubernetes --bundle kubernetes-bundle.yaml \
  --preflight preflight.yaml --name reference-change-set \
  --output change-set.yaml --audit-output change-set.audit.jsonl
yara change-set validate change-set.yaml
yara approval record --bundle kubernetes-bundle.yaml --preflight preflight.yaml \
  --change-set change-set.yaml --name reference-review --decision approve \
  --reason-reference ticket-123 --output approval.yaml \
  --audit-output approval.audit.jsonl
yara approval validate approval.yaml
yara deployment apply kubernetes --bundle kubernetes-bundle.yaml \
  --preflight preflight.yaml --change-set change-set.yaml \
  --approval approval.yaml --authorization authorization.yaml \
  --public-key execution-public.pem --confirm-authorization sha256:<id> \
  --name deployment --receipt-output receipt.yaml \
  --audit-output deployment.audit.jsonl
yara receipt validate receipt.yaml
yara audit verify audit.jsonl
```

Planning and local validation commands must work with networking disabled. Contract workload modes are explicit exceptions: they resolve upstream artifact metadata and connect to the declared SSH target. Runtime smoke requires a pre-staged image; model inference additionally acquires a public pinned model revision before starting its no-network server. Human output goes to stderr when structured output is written to stdout. Existing output files are not overwritten without an explicit flag.

`--audit-output` remains optional for read-only validation, explanation and diff commands to preserve simple local inspection. When supplied, the command writes a two-event started/terminal chain and fails if that evidence cannot be persisted. Explanation events bind the plan ID and exact selected-decision or decision-list digest without copying the explanation. `plan create`, `debug bundle` and every contract execution mode always require audit output. Debug-bundle and contract-result generation roll their artifact back when audit persistence fails. Contract results bind the exact runner executable digest; audit events use a digest of the remote SSH reference rather than storing it. Load failures record stable diagnostic codes and only content or opaque input-reference digests; resource bodies and local paths are never copied into audit evidence.

Continue with the [first vertical slice](first-vertical-slice.md).
