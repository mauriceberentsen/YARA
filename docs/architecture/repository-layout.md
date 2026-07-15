# Repository layout

## Target layout

The repository should grow by responsibility, not by creating a directory for every aspirational subsystem immediately.

```text
YARA/
  README.md
  CONTRIBUTING.md
  LICENSE
  docs/
    adr/
    architecture/
    catalogs/
    examples/
    operations/
    product/
    research/
  schemas/                 # public JSON Schemas and canonicalization fixtures
  catalog/                 # curated manifests introduced with validation
  scenarios/               # executable golden planning cases
  cmd/yara/                 # CLI entry point
  internal/                # non-public implementation packages/modules
    application/
    audit/
    catalog/
    domain/
    debugbundle/
    plandiff/
    planner/
    scenario/
    policy/
    validation/
  adapters/                # versioned discovery/renderer/executor adapters
  tests/
    contract/
    integration/
    security/
  tools/                   # development and catalog release tooling
```

Language-specific conventions may change names such as `cmd` and `internal`; this document defines boundaries, not a language decision.

## Dependency direction

```text
CLI/API -> application -> domain/planner
                          ^      |
catalog/policy adapters --+      v
                         PlatformPlan
                              |
renderer adapters ------------+
executor adapters consume bundles, never planner internals
```

- Domain types do not import CLI, storage, network or deployment packages.
- Planner depends on typed catalog/policy interfaces, not file formats.
- YAML/JSON parsing is at boundaries.
- Adapters cannot import internal planner implementation details.
- Scenarios depend on public schemas and catalog snapshots.

## When to add directories

- Add `schemas/` with the first executable schema and validation test.
- Add `catalog/` with the snapshot compiler and initial golden-scenario slice.
- Add implementation directories only after a language/toolchain ADR.
- Add `adapters/renderers` only after the first target ADR.
- Do not create empty marketplace, UI, SaaS or multi-cluster packages.

## Generated files

Generated schemas, indexes or API clients are clearly marked and reproduced by one documented command. Source manifests remain authoritative. CI fails if committed generated output is stale.

## Public versus internal contracts

Public contracts are resource schemas, CLI behavior, plugin protocol and artifact bundle formats. Internal package names and algorithms remain changeable. Catalog IDs and diagnostic codes become public once released and follow deprecation policy.
