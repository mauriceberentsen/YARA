# YARA catalog v0.3

This is the next knowledge snapshot after the evidence-frozen v0.2 catalog. It preserves the v0.2 manifests and compatibility assertions, then adds six current suite components and three interface capabilities:

- Ollama and SGLang as alternative inference runtimes;
- Milvus as an alternative vector database;
- Keycloak for OIDC identity;
- Traefik for reverse-proxy routing;
- OpenTelemetry Collector Contrib for OTLP telemetry pipelines.

Every added component is `known`. Release, license and immutable multi-platform OCI index facts were researched on 2026-07-19, but no YARA component-smoke or topology-end-to-end result exists. Therefore none of these additions is planner-selectable and this snapshot makes no runtime compatibility, security-hardening, performance or production-support claim.

The v0.2 catalog and its evidence remain unchanged and independently reproducible. Evidence must never be copied forward across catalog digests. A later validation run should create a new v0.3 coverage ledger with zero accepted v0.2 evidence unless results have been deliberately re-executed against this exact snapshot.

## Knowledge validation

The following checks only schema, references, provenance freshness and deterministic compilation; it does not test the software:

```bash
go run ./cmd/yara catalog validate catalog/v0.3/snapshot.yaml \
  --audit-output .yara/audit/catalog-v0.3.jsonl
```

Operational testing belongs to `IntegrationTestResult` evidence and is intentionally deferred.
