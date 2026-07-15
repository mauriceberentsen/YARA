# v0.1 implementation guide

## Start condition

The foundational architecture is sufficiently defined to begin a thin v0.1 implementation. Open product questions remain, but they do not block the first vertical slice. The first code should test the architecture, not attempt the full catalog or planner.

## Current implementation status

The bootstrap now includes strict resource decoding, public schemas, stable diagnostics, canonical digests and audit-event chaining. The catalog compiler resolves capability, component, model, hardware, compatibility and topology manifests. Every manifest declares lifecycle status, owners, evidence sources, confidence and a verification/review window. Freshness is evaluated deterministically against the immutable snapshot `publishedAt`; missing ownership, malformed provenance and expired evidence invalidate the snapshot. The bundled fixtures remain experimental and emit `YARA-CAT-055` into catalog output, plans, explanations, diffs, debug bundles, scenarios and audit evidence. Compatibility quarantine, multi-component topology resolution and independent plan validation remain active. Generated plans state bounded search and ordinal confidence; explanation, diff and debug-bundle paths are auditable. `scenario validate` now proves exact offline conformance for one content-addressed golden scenario while explicitly withholding review approval. Nine additional representative scenarios and independent domain-expert evidence remain required.

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

- First deployment renderer/executor target.
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
yara audit verify audit.jsonl
```

Commands must work with networking disabled. Human output goes to stderr when structured output is written to stdout. Existing output files are not overwritten without an explicit flag.

`--audit-output` remains optional for read-only validation, explanation and diff commands to preserve simple local inspection. When supplied, the command writes a two-event started/terminal chain and fails if that evidence cannot be persisted. Explanation events bind the plan ID and exact selected-decision or decision-list digest without copying the explanation. `plan create` and `debug bundle` always require audit output. Debug-bundle generation binds the plan and bundle IDs, refuses secret-like output and rolls the artifact back when audit persistence fails. Load failures record stable diagnostic codes and only content or opaque input-reference digests; resource bodies and local paths are never copied into audit evidence.

Continue with the [first vertical slice](first-vertical-slice.md).
