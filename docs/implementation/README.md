# v0.1 implementation guide

## Start condition

The foundational architecture is sufficiently defined to begin a thin v0.1 implementation. Open product questions remain, but they do not block the first vertical slice. The first code should test the architecture, not attempt the full catalog or planner.

## Current implementation status

The bootstrap now includes the Go module and CLI, strict request/inventory decoding and semantic validation, public schemas, stable diagnostics, canonical SHA-256 digests, audit-event chaining and `audit verify`. The catalog slice, planner, plan schema/validation and automatic planning-event emission remain the next work.

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
internal/diagnostics     stable codes and structured reports
internal/audit           event construction, redaction and local sink
internal/canonical       canonical JSON and content digests
```

Package names can adjust during bootstrap, but dependency direction from the [repository layout](../architecture/repository-layout.md) remains mandatory.

## Initial command behavior

```text
yara request validate request.yaml
yara inventory validate inventory.yaml
yara catalog validate catalog/
yara plan create --request request.yaml --inventory inventory.yaml \
  --catalog catalog/ --output plan.yaml --audit-output audit.jsonl
yara plan validate plan.yaml
yara plan explain plan.yaml
yara audit verify audit.jsonl
```

Commands must work with networking disabled. Human output goes to stderr when structured output is written to stdout. Existing output files are not overwritten without an explicit flag.

Continue with the [first vertical slice](first-vertical-slice.md).
