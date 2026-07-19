# YARA catalog v0.2

This snapshot is YARA's first evidence-backed catalog of real upstream software, model artifacts and hardware. It replaces the placeholder records from `v0.1` for development of the next planner slice.

## Coverage

| Kind | Count | Selectable | Purpose |
|---|---:|---:|---|
| Capabilities | 13 | 13 | Stable YARA taxonomy and interface contracts |
| Components | 10 | 2 | vLLM and LiteLLM form the selectable serving path; eight suite components are researched but not yet contract-tested |
| Models | 2 | 2 | Immutable Qwen AWQ snapshots for chat and coding |
| Hardware profiles | 4 | 4 | Three NVIDIA Ada devices with dedicated VRAM plus GB10 coherent unified memory |
| Compatibility assertions | 8 | 6 | Six selectable Ada tuples and two knowledge-only GB10 test hypotheses |
| Topology templates | 1 | 1 | Local LiteLLM-to-vLLM chat/coding path |

Selectable means the manifest status is `experimental` or `supported`. Every generated v0.2 plan therefore carries `YARA-CAT-055` and requires expert review. `known` records are catalog knowledge only and cannot enter a plan.

## Evidence standard

Each real component records its exact upstream version, license facts, health contract, source links and an immutable OCI index digest. Each model records an immutable Git revision plus the size and SHA-256 digest of every weight shard. Compatibility assertions bind a runtime version and model revision to a hardware profile and execution envelope.

Artifact verification proves identity; it does not prove operational compatibility. Six positive Ada assertions remain experimental and selectable. Both GB10 assertions remain knowledge-only and have passed artifact verification, runtime/CUDA smoke, exact local shard verification, bounded inference, one exact 32768-token context-envelope request, 32 consecutive context-1024 requests, serving policy and same-version restart recovery at concurrency 1. Qwen3's boundary pass uses an explicit 10% GPU-memory-utilization allocation; its earlier 8% failure remains archived. Component-integration coverage and independent promotion remain open.

Read-only contract preflight, isolated runtime smoke, bounded model inference and an exact advertised-context boundary contract are implemented. All write content-addressed evidence plus mandatory audit chains. No individual pass satisfies the promotion gate by itself; see the [contract-testing guide](../../docs/implementation/contract-testing.md).

The first two GB10 smoke results and their verified audit chains are archived under [`evidence/gb10/`](evidence/gb10/README.md). They remain bounded evidence, not a support declaration.

## Completion status

[`coverage.yaml`](coverage.yaml) is the deterministic completion ledger for this exact snapshot. It currently binds all 14 archived contract results and their 14 verified audit chains. The report enumerates all 13 capabilities, ten components, two models, four hardware profiles, eight compatibility assertions and the topology template. It remains `complete: false`: no assertion is promotion-eligible, the six Ada tuples have no observed target evidence, every component lacks accepted component-smoke and topology integration evidence, and the topology lacks end-to-end integration evidence. Both GB10 compatibility assertions have passed every implemented technical contract mode and now only lack independent promotion review; that does not complete component integration.

Regenerate the report after evidence changes, using a new output filename because YARA never overwrites evidence:

```bash
go run ./cmd/yara catalog coverage create \
  --catalog catalog/v0.2/snapshot.yaml \
  --evidence-dir catalog/v0.2/evidence \
  --name catalog-v0.2-coverage \
  --output .yara/catalog-v0.2-coverage.yaml \
  --audit-output .yara/audit/catalog-v0.2-coverage.jsonl

go run ./cmd/yara catalog coverage validate catalog/v0.2/coverage.yaml
go run ./cmd/yara audit verify catalog/v0.2/coverage.audit.jsonl
```

A result without its exact adjacent `.audit.jsonl`, a mismatched catalog/tuple, or an audit terminal event that does not bind the result is rejected rather than counted as missing.

## License and telemetry caveats

- Open WebUI is recorded as source-available, not OSI open source, because its current license includes a branding restriction.
- Langfuse is recorded as open core because its published image contains directories governed by its Enterprise License.
- Redis is cataloged under the AGPLv3 option from its Redis 8 tri-license.
- Qdrant, Grafana and Langfuse retain conservative telemetry or external-egress flags until a YARA-owned hardened configuration is tested.
- Langfuse records its web and worker images plus PostgreSQL, Redis, ClickHouse and S3/blob-storage dependencies. No S3 provider is selected yet; that gap prevents a Langfuse topology from becoming eligible.

These facts intentionally keep policy-incompatible components out of future plans instead of silently treating every publicly visible repository as unrestricted open source.

## Auditing

Catalog validation and plan creation support append-only JSONL audit output. The catalog digest, diagnostics, evidence references and selected manifest versions are part of the planning evidence. A release process must archive:

1. the exact snapshot and its digest;
2. validation audit events;
3. artifact verification output;
4. contract-test evidence for every promoted compatibility tuple;
5. reviewer identity and promotion decision.

No manifest may be promoted to `supported` merely because its documentation or artifact digest is present.

## Validate

From a source checkout, run the CLI through Go:

```bash
go run ./cmd/yara catalog validate catalog/v0.2/snapshot.yaml \
  --audit-output .yara/audit/catalog-v0.2.jsonl
```

YARA creates missing output directories, writes the audit file exclusively and refuses to overwrite an existing audit file. Use a new filename for every validation run.

To build a reusable local executable instead:

```bash
make build
./bin/yara catalog validate catalog/v0.2/snapshot.yaml \
  --audit-output .yara/audit/catalog-v0.2.jsonl
```

`go yara` is not a valid Go command. A bare `yara` command works only after a YARA executable has been installed somewhere on your `PATH`.

## Preflight a compatibility assertion

The following command only reads OS, Docker and NVIDIA accelerator facts from the target:

```bash
go run ./cmd/yara contract preflight \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-rtx4090 \
  --target user@gpu-runner.example \
  --name rtx4090-preflight \
  --output .yara/contracts/rtx4090-preflight.yaml \
  --audit-output .yara/audit/rtx4090-preflight.jsonl
```

Exit code `3` with outcome `blocked` is expected when the reachable host does not contain an RTX 4090. The result remains valid evidence and can be inspected with `contract validate`; it must not be described as a successful test of the RTX 4090 assertion.

## Smoke-test GB10 runtime compatibility

After deliberately staging the exact digest-pinned vLLM image on the target, run:

```bash
go run ./cmd/yara contract runtime-smoke \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-runtime-smoke \
  --output .yara/contracts/gb10-runtime-smoke.yaml \
  --audit-output .yara/audit/gb10-runtime-smoke.jsonl
```

The command verifies the cataloged OCI index, model revision and every weight-shard identity, performs preflight, and starts a uniquely named no-network container to exercise vLLM/PyTorch/CUDA on GB10. It does not download or load the model. Review the safety contract and image-staging command before use in the [contract-testing guide](../../docs/implementation/contract-testing.md).

## Load and query the GB10 Qwen Coder tuple

This explicit mutating test performs networked acquisition into a temporary volume and then serves the verified local snapshot without network or published ports:

```bash
go run ./cmd/yara contract model-inference \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-model-inference \
  --output .yara/contracts/gb10-qwen-coder-model-inference.yaml \
  --audit-output .yara/audit/gb10-qwen-coder-model-inference.jsonl
```

The fixed run is intentionally limited to 16 GiB container memory, context 1024, concurrency 1 and eight output tokens. A pass is bounded evidence—not a capacity or production-support claim.

## Test the advertised GB10 context boundary

```bash
go run ./cmd/yara contract capacity-boundary \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-capacity-boundary \
  --output .yara/contracts/gb10-qwen-coder-capacity-boundary.yaml \
  --audit-output .yara/audit/gb10-qwen-coder-capacity-boundary.jsonl
```

This single-sequence contract reserves eight output tokens and requires the API to report exactly 32760 prompt tokens without exceeding the asserted 32768-token context. The profile uses an explicit 10% GPU-memory-utilization allocation and records configured and expected percentages as reviewable measurements. It deliberately makes no concurrency, latency, throughput or sustained-load claim.

## Test same-version restart recovery on GB10

```bash
go run ./cmd/yara contract lifecycle \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-lifecycle \
  --output .yara/contracts/gb10-qwen-coder-lifecycle.yaml \
  --audit-output .yara/audit/gb10-qwen-coder-lifecycle.jsonl
```

The lifecycle gate requires health and one bounded inference before restart, restarts the same isolated container, then repeats health and inference. It compares digests of the pinned image, command, model mount and bounded serving configuration and requires the container identity to remain stable while its start timestamp advances. A pass proves only one operator-requested same-version restart. It does not establish upgrade, rollback, high availability, crash-loop recovery, backup/restore or disaster recovery.
