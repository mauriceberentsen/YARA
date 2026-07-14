# Glossary

| Term | Definition |
|---|---|
| Adapter | Code that translates a YARA interface into interaction with an external system or format. |
| Artifact | A rendered file, image reference, chart, manifest or bundle used to execute a plan. |
| AuditEvent | Append-only, integrity-protected evidence of who or what performed a significant action, against which immutable resources, why and with what result. |
| Audit trail | Ordered set of correlated audit events used to reconstruct planning and lifecycle activity; distinct from debug logs and planner explanations. |
| Capability | A normalized function such as `chat.ui`, `inference.text-generation` or `identity.oidc`. |
| Catalog | Versioned manifests describing known components, models, hardware, policies and compatibility evidence. |
| Constraint | A condition that must hold for a plan to be valid. Hard constraints eliminate candidates; soft constraints influence ranking. |
| Decision | A selected option plus alternatives, facts, rules, scores, assumptions and explanation. |
| Desired state | What the user wants to achieve, independent of products or deployment syntax. |
| Discovery | Collection of facts about an environment. Discovery reports evidence; it does not make recommendations. |
| Evidence | A sourced fact with provenance, collection time, scope and confidence. |
| Executor | A backend that applies an approved plan or rendered artifacts to a target environment. |
| Fact | A normalized value derived from user input, discovery or catalog data. |
| Inventory | A point-in-time description of hardware, software and platform resources available to YARA. |
| Knowledge base | The set of catalogs, relationships, rules, provenance and validation needed by the planner. |
| Objective | A dimension to optimize, such as quality, latency, throughput, cost, simplicity or energy use. |
| Override | An explicit user instruction replacing a planner choice; it remains subject to non-overridable safety policy unless policy permits an exception. |
| PlatformPlan | Immutable intermediate representation of selected architecture, configuration intent, dependencies, decisions and provenance. |
| PlatformRequest | Versioned declaration of use cases, workload, environment, policies and objectives. |
| Planner | Pure logical subsystem that transforms normalized inputs and a catalog snapshot into a `PlatformPlan`. |
| Plugin | A versioned extension package contributing catalog data, rules or adapters through declared interfaces. |
| Policy | An organizational or user constraint such as no telemetry, approved licenses or data residency. |
| Renderer | Pure transformation from a `PlatformPlan` to target-specific artifacts. It performs no mutation. |
| Rule | A versioned expression that derives a fact, rejects a candidate, adds a requirement or changes a score. |
| Runtime manager | Future subsystem that observes a deployed plan and coordinates health, drift and lifecycle actions. |
| Semantic plan | The normalized meaning of a plan excluding volatile presentation fields such as timestamps. |
| Supported | A versioned combination backed by required metadata, evidence, automated tests and maintenance ownership. |
| Topology | Components, instances, relationships, trust boundaries and placement decisions forming the platform. |
