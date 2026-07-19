# YARA catalog v0.2

This snapshot is YARA's first evidence-backed catalog of real upstream software, model artifacts and hardware. It replaces the placeholder records from `v0.1` for development of the next planner slice.

## Coverage

| Kind | Count | Selectable | Purpose |
|---|---:|---:|---|
| Capabilities | 13 | 13 | Stable YARA taxonomy and interface contracts |
| Components | 10 | 2 | vLLM and LiteLLM form the selectable serving path; eight suite components are researched but not yet contract-tested |
| Models | 2 | 2 | Immutable Qwen AWQ snapshots for chat and coding |
| Hardware profiles | 3 | 3 | NVIDIA Ada devices with 24 or 48 GiB VRAM |
| Compatibility assertions | 6 | 6 | Every model across every included hardware profile |
| Topology templates | 1 | 1 | Local LiteLLM-to-vLLM chat/coding path |

Selectable means the manifest status is `experimental` or `supported`. Every generated v0.2 plan therefore carries `YARA-CAT-055` and requires expert review. `known` records are catalog knowledge only and cannot enter a plan.

## Evidence standard

Each real component records its exact upstream version, license facts, health contract, source links and an immutable OCI index digest. Each model records an immutable Git revision plus the size and SHA-256 digest of every weight shard. Compatibility assertions bind a runtime version and model revision to a hardware profile and execution envelope.

Artifact verification proves identity; it does not prove operational compatibility. The six positive compatibility assertions remain experimental until the same tuple passes the planned startup, health, inference, policy and restart contract tests on the named hardware.

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

```bash
yara catalog validate catalog/v0.2/snapshot.yaml \
  --audit-output .yara/audit/catalog-v0.2.jsonl
```
