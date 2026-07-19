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

Artifact verification proves identity; it does not prove operational compatibility. Six positive Ada assertions remain experimental and selectable. Both GB10 assertions remain knowledge-only even though each has passed artifact verification and a bounded runtime/CUDA smoke: no model was loaded and health, inference, capacity, policy and lifecycle gates remain open.

Read-only contract preflight and isolated runtime smoke are implemented. Both write content-addressed evidence plus mandatory audit chains. Neither satisfies the promotion gate by itself; see the [contract-testing guide](../../docs/implementation/contract-testing.md).

The first two GB10 smoke results and their verified audit chains are archived under [`evidence/gb10/`](evidence/gb10/README.md). They remain bounded evidence, not a support declaration.

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
