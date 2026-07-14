# Domain model

## Aggregate flow

```text
PlatformRequest -----+
Inventory -----------+--> PlanningContext --> CandidateSet --> PlatformPlan
ResolvedPolicy ------+          ^                  |               |
CatalogSnapshot -----+----------+                  +--> Decisions -+
```

## Core entities

### PlatformRequest

The user's desired outcome. It contains:

- metadata and schema version;
- use cases and required capabilities;
- workload shape: users, concurrency, request mix, context and data volume;
- environment constraints: location, connectivity and existing platform;
- service objectives: availability, latency, throughput and recovery;
- optimization objectives and weights;
- policy references and local policy values;
- declared inventory reference;
- explicit preferences or overrides.

A request SHOULD avoid component names. A preference such as "prefer component X" is allowed but represented as an override or scoring preference, never disguised as a requirement.

### Inventory

A point-in-time set of resources and platform facts:

- hosts, CPU architecture, instruction sets and NUMA topology;
- system and accelerator memory;
- accelerator vendor, model, count, interconnect and driver stack;
- storage capacity, class and measured characteristics;
- network interfaces, bandwidth and topology;
- operating system, container runtime and orchestrator;
- existing services and reserved capacity.

Each observation carries a source, time, collection method and confidence. Declared and discovered facts can coexist; conflicts produce diagnostics and precedence is visible.

### Policy

A constraint or governance rule with:

- stable identifier and version;
- scope and priority;
- condition and effect;
- enforcement level: mandatory, waivable or advisory;
- exception requirements;
- human-readable rationale;
- source and ownership.

### CatalogSnapshot

An immutable, content-addressed collection of compatible manifest versions. A snapshot contains component, model, hardware, capability, policy and compatibility records plus provenance metadata.

### PlanningContext

Normalized, immutable input to the decision pipeline. It includes merged facts, derived capabilities, effective policies, explicit unknowns, objective weights and snapshot identifiers. Raw discovery output is retained separately for audit.

### Candidate

A proposed component or topology option being evaluated. It records:

- supplied and required capabilities;
- constraints satisfied or violated;
- unresolved dependencies;
- resource demand range;
- objective score vector;
- assumptions and confidence;
- evidence references.

Candidates are ephemeral planner state and do not appear in full in the final plan, except selected and materially rejected alternatives.

### Component

A deployable software role, not necessarily a single process. It provides capabilities, consumes interfaces, requires dependencies and resources, exposes health and lifecycle contracts and references versioned artifacts. Product identity and configured instance are separate concepts.

### Model

A model family, concrete variant or deployable artifact. The domain distinguishes:

- model family and upstream version;
- task capabilities;
- artifact format and quantization;
- serving compatibility;
- license and distribution conditions;
- measured performance observations;
- resource estimates for a workload shape.

The same model variant may have several artifacts with different trust and redistribution properties.

### Capability

A stable hierarchical identifier with a contract. Example levels:

```text
experience.chat
experience.coding
inference.text-generation
inference.embeddings
gateway.openai-compatible
identity.oidc
data.vector-search
operations.metrics
```

Capabilities connect intent to implementations without hard-coded product names.

### CompatibilityAssertion

A claim about a bounded combination, for example "runtime version range R serves model format F on accelerator stack A." Assertions specify subject, relation, object, conditions, evidence, confidence, verification date and expiry. Missing an assertion is **unknown**, not compatible.

### PlatformPlan

The immutable intermediate representation consumed by reviewers, renderers and future executors. It contains selected instances, topology, placements, configuration intent, resource allocations, artifact references, lifecycle contracts, decisions, diagnostics and complete provenance.

### Decision

A structured explanation for a material planner outcome:

- question being decided;
- selected option;
- feasible and rejected alternatives;
- hard constraints and rule evaluations;
- normalized objective scores and weights;
- assumptions, evidence and confidence;
- consequences and possible overrides.

### DeploymentReceipt

Future immutable record binding a plan, rendered artifact bundle, approval, executor version, target identity and result. It is operational evidence, not the active desired state.

### AuditEvent

Append-only evidence of a security-relevant or state-changing action. An event identifies actor, action, subject/resource digests, reason, effective policy, target, outcome, correlation/causation IDs, time source and integrity metadata. Payloads contain references and redacted summaries, never secrets or full sensitive resources by default.

### Observation

Future runtime fact such as health, version, capacity or latency. Observations are append-only inputs to drift analysis and re-planning. They do not directly change configuration.

## Relationships and cardinality

- One request resolves to one planning context per catalog/policy/inventory snapshot.
- One planning context can yield zero or more feasible candidates.
- One successful planning run yields one preferred plan and zero or more summarized alternatives.
- One plan has many component and model instances and one dependency DAG.
- One selected instance has one or more decisions and evidence references.
- One plan may have many deployment receipts across retries or targets, but receipts never alter it.
- One planning or lifecycle operation emits one or more ordered audit events linked through correlation and causation IDs.
- A later plan supersedes, rather than mutates, an earlier plan.

## Identity and versioning

Domain resources use stable lowercase identifiers plus explicit semantic schema versions. Human names are presentation fields. References are typed and include version constraints or immutable digests. Mutable tags such as `latest` are forbidden in an approved plan.

## Unknown, absent and false

These states are distinct:

- **unknown:** no reliable fact is available;
- **absent:** observation reliably confirms a resource or capability is not present;
- **false:** a boolean value was explicitly declared or observed;
- **not applicable:** the field does not apply to this topology.

Collapsing them creates unsafe defaults and must be prevented by schemas and typed domain values.
