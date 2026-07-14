# Component catalog

## Model

A component record describes a product identity and one supported upstream version. Deployment variants, artifact platforms and configured instances are separate nested records or references.

## Required fields

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
  licenses: [Apache-2.0]
  provides:
    - capabilityRef: experience.chat/v1
  consumes:
    - capabilityRef: integration.api.openai-chat/v1
  artifacts:
    - platform: linux/amd64
      image: registry.invalid/example-ui@sha256:...
  deployment:
    privilege: unprivileged
    network:
      inbound: [http]
      outbound: [inference-api]
  lifecycle:
    healthContractRef: core.http-health/v1
    upgradeStrategy: replace-stateless
```

This example is illustrative and does not describe a supported YARA component.

## Roles versus products

A topology asks for roles such as UI, gateway, inference or identity. One product may satisfy multiple roles, and multiple instances of a product may satisfy one role. The planner scores the resulting topology rather than always selecting one product per category.

## Integration adapters

Catalog data declares supported configuration intent. Trusted adapter code maps that intent to concrete version-specific configuration. Every supported component/version/renderer combination requires contract tests. Unsupported fields cause an error; adapters never silently drop configuration.

## Operational completeness

Stateful components need data ownership, backup consistency, restore verification and upgrade/migration contracts. Components requiring privileged containers, host mounts, root, external egress or embedded telemetry expose those facts for policy evaluation.

## Project health

Maintenance signals may influence soft scoring but cannot by themselves prove quality or security. Signals include release cadence, support policy, maintainer activity and vulnerability response. Popularity and star count are not support evidence.
