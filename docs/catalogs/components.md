# Component catalog

## Model

A component record describes a product identity and one supported upstream version. Deployment variants, artifact platforms and configured instances are separate nested records or references.

## Required fields

The executable v0.2 subset requires identity/governance, category, exact upstream version, homepage, structured license facts, immutable artifacts, one protocol-specific health check, roles, provided/consumed contracts, runtime overhead and policy facts. The broader production target below remains the promotion checklist; fields not yet represented in v1alpha1 must be added before a component depending on them can become `supported`.

- upstream project identity and source;
- upstream version and release date;
- license and redistribution facts;
- maintenance status and ownership;
- supplied and consumed capability contracts;
- required dependencies and alternative providers;
- supported platforms and architectures;
- immutable artifact references and signatures/digests;
- resource baseline methodology;
- configuration intent supported by adapters;
- network, storage and privilege requirements;
- telemetry and external-service behavior;
- health, backup, restore, upgrade and removal contracts;
- known incompatibilities and security notes;
- evidence and freshness.

## Illustrative manifest

```yaml
apiVersion: yara.dev/v1alpha1
kind: Component
metadata:
  id: core.example-ui
  version: 1.0.0
  status: experimental
  owners: [yara-core]
provenance:
  sources:
    - type: upstream-release
      ref: https://example.invalid/releases/1.0.0
  verifiedAt: 2026-07-14T00:00:00Z
  reviewAfter: 2026-10-14T00:00:00Z
  confidence: low
spec:
  category: user-interface
  upstreamVersion: "1.0.0"
  homepage: https://example.invalid/
  license:
    id: Apache-2.0
    source: https://example.invalid/LICENSE
    osiApproved: true
    redistribution: allowed
  artifacts:
    - type: oci-image
      ref: registry.invalid/example-ui:1.0.0
      digest: sha256:0000000000000000000000000000000000000000000000000000000000000000
      platforms: [linux/amd64]
  health: {protocol: http, path: /health}
  roles: [interface.web-chat]
  provides: [experience.web-chat/v1]
  consumes: [integration.api.openai-chat/v1]
  apiContracts: [experience.web-chat/v1, integration.api.openai-chat/v1]
  runtimeOverheadGiB: 1
  policy:
    openSource: true
    externalEgress: false
    telemetry: false
    artifactVerified: true
```

This example is illustrative and does not describe a supported YARA component.

## Roles versus products

A topology asks for roles such as UI, gateway, inference or identity. One product may satisfy multiple roles, and multiple instances of a product may satisfy one role. The planner scores the resulting topology rather than always selecting one product per category.

## Integration adapters

Catalog data declares supported configuration intent. Trusted adapter code maps that intent to concrete version-specific configuration. Every supported component/version/renderer combination requires contract tests. Unsupported fields cause an error; adapters never silently drop configuration.

## Operational completeness

Stateful components need data ownership, backup consistency, restore verification and upgrade/migration contracts. Components requiring privileged containers, host mounts, root, external egress or embedded telemetry expose those facts for policy evaluation.

The current `known` PostgreSQL, Redis, ClickHouse, Qdrant and Langfuse records are not operationally complete merely because they have artifact and health metadata. They need persistence, backup/restore and upgrade contracts before promotion. Langfuse additionally has no cataloged S3 provider, so its dependency graph is deliberately incomplete and ineligible.

## Project health

Maintenance signals may influence soft scoring but cannot by themselves prove quality or security. Signals include release cadence, support policy, maintainer activity and vulnerability response. Popularity and star count are not support evidence.
