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
- `GoldenScenario`
- `ScenarioReview`
- `AcceptanceGateReview`
- `ContractTestResult`
- `CatalogCoverageReport`

These schemas are alpha contracts and may change only with an explicit migration. Unknown fields are rejected. Catalog resources share mandatory lifecycle, ownership and provenance definitions; the v0.2-compatible fields add license, artifact, health, hardware-memory kind and bounded compatibility evidence without invalidating the frozen v0.1 resources. `PlatformPlan` requires explicit bounded-search counts and ordinal confidence factors so feasibility is not presented as global or high-confidence optimization. `DebugBundle` exposes only content-addressed support metadata under an explicit redaction and secret-scan contract. `GoldenScenario`, `ScenarioReview` and `AcceptanceGateReview` pin exact inputs, expected outcomes, safety assertions and independent-review evidence. `ContractTestResult` binds a compatibility assertion to pseudonymized environment observations, check evidence and explicit limitations for preflight, runtime-smoke, model-inference, capacity-boundary, sustained-capacity, policy-contract and lifecycle-contract modes. `CatalogCoverageReport` accepts only evidence bound to the exact catalog and an adjacent verified audit chain, then exposes every remaining promotion blocker without upgrading manifest status. New results optionally bind runner version and executable digest while retaining validation compatibility with earlier archived v1alpha1 evidence. The Go tests parse every schema and validate repository examples through the strict typed loader.
