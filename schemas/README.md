# Public resource schemas

This directory contains the first executable `v1alpha1` wire contracts. JSON Schema validates structure; Go domain validation enforces cross-field semantics such as objective weights summing to one and allocatable resources not exceeding installed resources.

Current schemas:

Shared catalog metadata and provenance definitions live in `catalog-manifest-common.schema.json`.

- `PlatformRequest`
- `Inventory`
- `AuditEvent`
- `CatalogSnapshot`
- `Capability`
- `Component`
- `Model`
- `HardwareProfile`
- `CompatibilityAssertion`
- `TopologyTemplate`
- `PlatformPlan`
- `PlatformPlanDiff`
- `DebugBundle`

These schemas are alpha contracts and may change with an explicit migration before v0.1. Unknown fields are rejected. Catalog resources share mandatory lifecycle, ownership and provenance definitions. `PlatformPlan` requires explicit bounded-search counts and ordinal confidence factors so feasibility is not presented as global or high-confidence optimization. `DebugBundle` exposes only content-addressed support metadata under an explicit redaction and secret-scan contract. The Go tests parse every schema and validate the repository examples through the strict typed loader.
