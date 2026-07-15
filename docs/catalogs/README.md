# Catalogs

Catalogs are YARA's versioned knowledge source. They describe what is known, what is supported and why. Catalog data is declarative and reviewable; executable integration code lives behind separately trusted adapters.

## Catalog types

| Type | Describes | Key relations |
|---|---|---|
| Capability | Stable functional or operational contract | required by use case, supplied/consumed by component |
| Component | Software product, versions and deployable roles | implements capability, depends on component/interface |
| Model | Family, variant, artifact and task evidence | served by runtime, requires hardware/resources |
| Hardware | Accelerator/CPU/storage profile and identifiers | supports stack, provides capacity |
| Compatibility | Bounded positive or negative assertion | subject, relation, object, conditions, evidence |
| Policy | Constraint, exception model and rationale | filters topology, component, artifact or data flow |
| Topology template | Abstract role and interface graph | satisfies a capability set |
| Benchmark | Reproducible observation | measures a concrete configuration |

## Proposed repository layout

```text
catalog/
  capabilities/<namespace>/<capability>.yaml
  components/<component>/<version>.yaml
  models/<family>/<variant>.yaml
  hardware/<vendor>/<device>.yaml
  compatibility/<namespace>/<assertion>.yaml
  policies/<namespace>/<policy>.yaml
  topologies/<use-case>/<template>.yaml
  benchmarks/<environment>/<observation>.yaml
schemas/
  <kind>/<api-version>.json
```

The repository should introduce these directories only with executable schema validation and a small curated dataset. Documentation examples are not a substitute for that implementation.

The executable v0.1 fixture follows this model under `catalog/v0.1/`. Its `CatalogSnapshot` indexes relative manifest paths. The strict loader prevents path traversal, rejects unknown fields and validates typed references. Only explicit `compatibility: supported` assertions become serving candidates; `unsupported` takes precedence and conflicts emit `YARA-CAT-040`. The first `TopologyTemplate` declares product-neutral gateway and inference roles plus their required interface. YARA resolves those roles separately and derives a dependency-safe stage order. This fixture is intentionally not a production support claim.

## Common envelope

All manifests contain:

```yaml
apiVersion: yara.dev/v1alpha1
kind: Component
metadata:
  id: core.example
  version: 1.2.3
  status: experimental
  owners: [team-or-handle]
  labels: {}
provenance:
  sources: []
  verifiedAt: 2026-07-14T00:00:00Z
  reviewAfter: 2026-10-14T00:00:00Z
  confidence: medium
spec: {}
```

IDs are immutable and namespaced. Human-readable names, URLs and descriptions are not identifiers.

## Entry status

- `known`: minimally described; not eligible for automatic selection.
- `experimental`: may be selected only when explicitly enabled and always warns.
- `supported`: meets metadata, freshness, ownership and automated-test requirements.
- `deprecated`: still resolvable for existing plans; not selected for new plans.
- `quarantined`: known trust, security or evidence problem; cannot be selected or rendered.

## Inclusion requirements

All entries require:

- valid schema and stable ID;
- source and ownership;
- license facts where applicable;
- bounded, non-marketing capability claims;
- verification and review dates;
- confidence and status;
- references that pass integrity checks.

Supported entries additionally require:

- immutable artifacts or release identities;
- compatibility contract tests for the supported path;
- lifecycle and health contracts for components;
- resource methodology for model/runtime combinations;
- a maintainer response/removal policy;
- no expired material evidence.

## Catalog compilation

Release tooling should:

1. validate all schemas;
2. resolve and type-check references;
3. detect duplicate IDs and contradictory assertions;
4. execute catalog policy and contract tests;
5. sort and canonically serialize entries;
6. generate indexes and coverage reports;
7. create a content digest and optional signature;
8. publish an immutable snapshot, never rewrite one.

The current in-process compiler implements schema-shaped strict decoding, reference resolution, stable sorting, content digests and deterministic contradiction quarantine. These checks alone do not make a catalog entry production-supported.

Ownership and freshness are now executable v0.1 gates. Every manifest requires at least one owner and a provenance record containing sources, confidence, `verifiedAt` and `reviewAfter`. A snapshot provides `publishedAt`; validation compares evidence to that timestamp rather than the operator's wall clock. This preserves offline reproducibility. Evidence verified after publication or due for review at publication fails with `YARA-CAT-054`. The remaining production gates are signed releases, immutable upstream artifacts and contract-test-backed evidence.

## Compatibility policy

YARA does not infer general compatibility from broad version claims. A supported path needs a positive assertion covering the selected versions, interfaces, hardware stack and relevant conditions. Negative assertions always win within overlapping scope. Conflicting equally trusted assertions quarantine the combination until reviewed.

## Licensing

Catalog licensing has three distinct fields:

- software/model license identity;
- permission to use under declared scenario;
- permission for YARA or a distributor to redistribute the artifact.

They must never be collapsed into `openSource: true`. Model licenses may include use restrictions even when weights are downloadable. YARA reports structured facts and policy matches; it does not provide legal advice.

## Maintenance

Catalog breadth creates a permanent maintenance obligation. New entries should be accepted only when tied to a validated scenario, maintained by a named owner and covered by automation. Removal from new recommendations is preferable to retaining stale, unsafe support claims.

See also [schema conventions](schema-conventions.md), [capabilities](capabilities.md), [components](components.md), [models](models.md), [hardware](hardware.md) and [policies](policies.md).
