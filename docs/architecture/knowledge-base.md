# Knowledge base

## Purpose

YARA's knowledge base connects desired capabilities to compatible implementations. It is not a scrape of upstream marketing pages and not initially a graph database. It is a versioned set of typed manifests and relationships that can be validated, reviewed and compiled into an in-memory query model.

## Contents

- capability definitions and interface contracts;
- component and version manifests;
- model families, variants and artifact records;
- hardware profiles and discovered identifiers;
- compatibility and incompatibility assertions;
- benchmark observations and resource-estimation models;
- policies and planner rules;
- topology templates;
- provenance, freshness and ownership metadata.

## Why not start with a graph database

The domain is graph-shaped, but a database would add operational complexity before query patterns are stable. v0.1 stores reviewable YAML manifests in Git, validates them against JSON Schema and builds indexes at load time. A graph or relational backend can be introduced behind the catalog interface if scale or queries justify it.

## Evidence model

Every non-trivial compatibility, performance or licensing assertion includes:

- source type and location;
- upstream version or commit when available;
- collection or verification date;
- verification method: documentation, automated test, benchmark or maintainer attestation;
- environment in which it was observed;
- confidence: high, medium, low or unknown;
- expiry or review interval;
- contributor and reviewer identity where policy permits.

Sources are not equal. A passing contract test for the exact version combination carries more compatibility weight than an undated documentation claim. A benchmark is an observation for a defined environment, not a universal property.

## Assertion semantics

Assertions are positive, negative or unknown and always bounded by conditions. Examples:

```text
component/version --implements--> capability/interface
runtime/version   --serves-------> model-artifact/format
artifact          --requires-----> accelerator-stack/range
component         --conflicts----> policy/value
topology          --requires-----> lifecycle-capability
```

YARA uses an open-world assumption for compatibility: absence of a negative assertion does not imply compatibility. Supported paths need positive evidence.

## Freshness

Each assertion class has a review window. Expired data remains available for reproducibility but loses eligibility for a supported recommendation unless policy explicitly allows stale evidence. Planning output distinguishes:

- verified and current;
- verified but stale;
- inferred from related evidence;
- unverified/experimental.

Catalog releases are immutable. Updating evidence creates a new snapshot and never changes an existing plan. Freshness is evaluated against the snapshot's explicit publication timestamp, never the machine's current clock; replaying an old snapshot therefore produces the same result while a newly published snapshot must consciously renew or quarantine expired evidence.

## Provenance chain

A plan records catalog snapshot digest and the IDs of assertions used by material decisions. A reviewer can therefore traverse:

```text
selected model -> compatibility assertion -> contract test -> environment -> source commit
```

If evidence must remain private, the plan may record an opaque organization-controlled evidence ID and digest, but not silently omit provenance.

## Curation workflow

1. Contributor adds or updates a manifest with evidence.
2. Schema and referential-integrity checks run.
3. Contract tests run for supported combinations where feasible.
4. Reviewer assesses scope, source and confidence.
5. Catalog release tooling produces a canonical snapshot and digest.
6. Release is optionally signed and published through a channel.
7. Consumers opt into the new snapshot and re-plan explicitly.

## Trust levels

Suggested catalog channels:

- **core:** maintained by YARA, conservative and release-gated;
- **verified partner:** signed and contract-tested against declared criteria;
- **community:** namespaced, clearly unverified and disabled by default;
- **organization:** private policy, components and evidence under local control.

Trust level affects eligibility and confidence, not namespace precedence. A plugin cannot replace a core identifier.

## Data quality controls

- unique namespaced IDs and explicit versions;
- canonical units and enumerations;
- no floating artifact tags in supported records;
- valid licenses and redistribution status represented separately;
- bidirectional reference checks;
- contradiction detection for overlapping assertions;
- required ownership and review dates;
- generated catalog coverage reports;
- quarantine for entries that lose evidence or maintenance.

## Benchmark limitations

Benchmark data must record hardware, driver, runtime, model artifact, precision, context length, batch/concurrency, input/output shape, settings, tool version and statistical summary. YARA should use benchmark evidence for relative guidance only within its validity bounds. It must not combine incomparable measurements into a precise universal score.
