# ADR-0003: Use Git-versioned manifests for the v0 knowledge base

- Status: Accepted
- Date: 2026-07-14
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

YARA knowledge is graph-shaped and could be stored in a graph or relational database. During early development, schemas and query patterns will change frequently, while review, provenance and reproducibility are more important than high query volume.

## Decision

Author knowledge as schema-validated YAML manifests in Git. Compile immutable snapshots and in-memory indexes for planner use. Access occurs behind a catalog interface so storage can change later.

## Consequences

### Positive

- Human review, version history and contributions use familiar tooling.
- Catalog releases are easy to content-address and use offline.
- No database service is required for the v0 CLI.

### Negative

- Large-scale relationship queries and concurrent editing are less efficient.
- Referential integrity and contradiction detection require custom tooling.
- YAML authoring needs strict canonicalization and feature restrictions.

### Neutral / follow-up

- A service may import snapshots into a database as a derived index.
- Git is the v0 source format, not a permanent claim that all runtime data belongs in Git.

## Alternatives considered

### Graph database as source of truth

Matches the domain shape but adds operations, migrations and review/export complexity before scale justifies it.

### Embedded relational database

Good query semantics but less friendly for direct contributions and diff review; it may later become a compiled representation.

## Validation

Reconsider when catalog compilation or common queries exceed defined performance budgets, or concurrent curation becomes the dominant bottleneck. Any replacement must preserve immutable snapshots and offline reproducibility.
