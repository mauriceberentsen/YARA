# Planning pipeline

## Contract

The planner is a deterministic transformation:

```text
plan(request, inventory, effectivePolicy, catalogSnapshot, engineVersion)
  -> PlatformPlan | DiagnosticReport
```

It performs no network access, environment mutation, secret resolution or dynamic plugin installation. All inputs are explicit and hashable.

## Stages

### 1. Structural validation

Validate schema versions, types, ranges and references. Reject duplicate identifiers, unsupported API versions and ambiguous units. Structural validation never fills domain defaults.

### 2. Normalization

Convert units and aliases to canonical forms, expand shorthand, apply documented non-controversial defaults and retain the original paths. Examples include GiB units, canonical architecture names and normalized capability IDs.

Defaults that could materially change a result become explicit assumptions and require a warning or confirmation policy.

### 3. Fact reconciliation

Merge user-declared, discovered and organization-provided facts according to source precedence. Report contradictions. Mandatory policies cannot be overridden by lower-precedence request values.

Suggested precedence for facts:

1. signed authoritative inventory;
2. fresh local discovery;
3. explicit user declaration;
4. catalog inference;
5. default.

Precedence does not erase disagreement; all sources remain in the trace.

### 4. Capability derivation

Translate use cases into required and optional capabilities. For example, a private coding assistant may require text generation, an API compatible with the chosen client, authentication and audit policy, while chat UI may remain optional.

Derivation rules also add operational capabilities required by service objectives, such as durable state, metrics or multiple replicas.

### 5. Feasibility gate

Test global conditions before searching components:

- required hardware or provider capacity exists;
- connectivity permits required artifact and service access;
- mandatory policies are mutually satisfiable;
- requested minimum objectives are not clearly impossible;
- executor-independent platform prerequisites are present.

An impossible request returns diagnostics and remediation options, not a degraded plan unless the request explicitly permits trade-offs.

### 6. Topology templates

Select abstract role graphs that can satisfy the capabilities, such as:

```text
client -> identity-aware UI -> gateway -> inference
                                   |       |
                                   |       +-> generation model
                                   +-> audit/telemetry contract
```

Templates describe roles and interfaces, not products. This bounds the search space while keeping product choice data-driven.

### 7. Candidate generation

Query the catalog for implementations of each role. Expand dependency alternatives and valid model/runtime/artifact combinations. Candidate generation is bounded by declared catalog support and planner limits to avoid combinatorial explosion.

### 8. Hard-constraint filtering

Eliminate candidates that violate:

- hardware or memory limits;
- component, protocol or version compatibility;
- mandatory license, connectivity, residency or telemetry policy;
- required capabilities;
- lifecycle requirements such as backup or high availability;
- trust or artifact-verification requirements.

Each elimination records a stable reason code. No scoring occurs until this stage succeeds.

### 9. Resource estimation

Estimate memory, compute, storage and network demand as ranges tied to workload assumptions. Reserve system and operational headroom. Model weight fit alone is insufficient: context cache, concurrency, runtime overhead and co-located services are included.

Estimates carry methodology, confidence and validity bounds. Low-confidence estimates can be feasible for experimentation but must not be presented as production capacity.

### 10. Scoring and Pareto analysis

Normalize soft objective scores within comparable candidates. Produce a vector for quality, latency, throughput, cost, simplicity, energy and evidence confidence. User-selected weights yield a preferred option, while Pareto-relevant alternatives remain visible.

### 11. Dependency and version resolution

Resolve concrete component versions, API contracts and artifact digests. Build a directed acyclic graph. Cycles, unsatisfied interfaces or version ranges without a supported intersection invalidate the candidate.

### 12. Placement and capacity validation

Assign instances to inventory resources, honoring reservations, affinity, isolation and failure-domain constraints. v0.1 uses a single-node deterministic allocator. Later allocators may use constraint solvers, but their output remains explainable and repeatable.

### 13. Policy re-evaluation

Evaluate the fully resolved topology. Some rules, such as data flow or external egress, are only decidable after all components and connections are known.

### 14. Plan construction

Create the immutable `PlatformPlan`, material decisions, assumptions, warnings, rejected alternatives, resource budgets, dependency stages and provenance fingerprints.

### 15. Independent plan validation

Run validation against the serialized plan rather than trusting planner internals. This catches construction bugs and enables the same validator in CI, review and executor preflight.

## Backtracking and exhaustion

If resolution invalidates the top-ranked candidate, the planner tries the next feasible candidate in deterministic order. Limits on candidate count, topology depth and execution time are explicit inputs. Exhaustion produces a diagnostic describing where the search was truncated.

## Deterministic ordering

All unordered inputs are canonicalized. Ties use stable catalog identifiers, never map iteration order or current time. Timestamps and run IDs are excluded from semantic comparison. Any optional randomness requires an explicit seed recorded in the plan; v0.1 uses none.

## Diagnostics

Diagnostic codes follow a stable namespace, for example:

```text
YARA-REQ-001  missing workload concurrency
YARA-HW-004   insufficient accelerator memory with required headroom
YARA-POL-012  component conflicts with no-telemetry policy
YARA-COMP-007 no verified runtime/model compatibility assertion
YARA-PLAN-003 dependency cycle
```

Each diagnostic contains severity, summary, affected paths, evidence, remediation hints and whether an override is possible.

## Testing

- Stage-level unit tests for normalization, rules, estimation and scoring.
- Property tests for units, ordering and idempotent normalization.
- Golden scenarios comparing semantic plans.
- Mutation tests ensuring hard constraints cannot be bypassed.
- Counterexample tests for every rule.
- Metamorphic tests, such as increasing available memory never making a previously feasible identical candidate infeasible without another changed constraint.
- Plan-validator tests independent of planner construction.
