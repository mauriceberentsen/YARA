# Public resource schemas

This directory contains the first executable `v1alpha1` wire contracts. JSON Schema validates structure; Go domain validation enforces cross-field semantics such as objective weights summing to one and allocatable resources not exceeding installed resources.

Current schemas:

- `PlatformRequest`
- `Inventory`
- `AuditEvent`
- `CatalogSnapshot`
- `Capability`
- `Component`
- `Model`
- `HardwareProfile`
- `CompatibilityAssertion`
- `PlatformPlan`

These schemas are alpha contracts and may change with an explicit migration before v0.1. Unknown fields are rejected. The Go tests parse every schema and validate the repository examples through the strict typed loader.
