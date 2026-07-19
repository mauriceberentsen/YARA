# Testing strategy

## Testing objective

YARA's tests must prove more than code execution: supported recommendations are valid within stated assumptions, unsafe combinations are rejected and outputs remain reproducible.

## Test pyramid

### Schema and manifest tests

- valid/invalid fixtures for every public resource version;
- unknown-field, unit and reference rejection;
- catalog ownership, evidence and freshness policy;
- canonicalization and digest test vectors;
- schema migration round trips.

### Unit and property tests

- normalization and fact precedence;
- each rule's match, non-match, boundary and unknown cases;
- resource estimate arithmetic and headroom;
- objective normalization and deterministic ties;
- graph construction and cycle detection;
- redaction and diagnostic stability;
- deterministic debug-bundle identity, allowlisted section digests and secret-pattern false-positive/false-negative fixtures.

Property/metamorphic examples:

- reordering semantically unordered input does not change plan ID;
- normalization is idempotent;
- a mandatory deny cannot be overcome by score;
- adding a candidate cannot invalidate a different already feasible candidate before ranking;
- increasing a resource budget does not reduce raw feasibility absent another constraint.

### Golden scenario tests

Each scenario contains:

- request, inventory, policy and catalog snapshot;
- expected required capabilities;
- selected or acceptable alternative outcomes;
- explicitly forbidden outcomes;
- expected diagnostics and key decision factors;
- expert reviewer and review date.

`GoldenScenario` validates exact input digests, semantic plan ID, required decisions/selections, forbidden outcomes and diagnostic codes offline. Golden tests compare semantic plans. Presentation text can change through separately reviewed snapshots. The suite validator requires at least ten unique cases, deterministic discovery order and conformance of every case; the v0.1 suite contains seven planned and three infeasible outcomes. The CLI counts approved `ScenarioReview` and `AcceptanceGateReview` resources and reports release eligibility when all are present.

Every implemented hard constraint has a focused failing counterexample that first satisfies all earlier constraints. This prevents a negative test from appearing to cover a rule while actually failing at an unrelated earlier gate. Adding or reordering a hard constraint requires updating the counterexample table.

### Compatibility contract tests

For supported component/model combinations:

- acquire exact artifacts by digest;
- start in a clean isolated environment;
- block undeclared egress;
- exercise supplied interface contracts;
- verify health, shutdown and relevant lifecycle behavior;
- emit an evidence record tied to versions and environment.

Passing once does not guarantee permanent support; evidence freshness policy applies.

The first implemented [contract-testing slice](../implementation/contract-testing.md) is a read-only SSH preflight. It records host, Docker and accelerator eligibility as a content-addressed result with mandatory audit evidence. Preflight is intentionally weaker than the workload contract above and cannot promote a catalog assertion.

### Renderer tests (future)

- deterministic artifact snapshots;
- every plan intent consumed exactly once or rejected;
- secure default configuration assertions;
- valid target-native syntax;
- no plaintext secrets or mutable tags;
- adapter conformance across supported version matrix.

### Executor tests (future)

- clean apply and functional verification;
- second apply idempotency;
- interruption at every checkpoint;
- ownership-safe cleanup;
- approval replay/target mismatch rejection;
- partial failure and rollback/roll-forward behavior;
- no mutation during dry-run.

### Security tests

- malicious/oversized YAML and expression inputs;
- catalog namespace and signature violations;
- plugin timeout and permission denial;
- secret canaries through plans, logs and bundles;
- debug-bundle output rollback when required audit persistence fails;
- supply-chain digest substitution;
- authorization and separation-of-duties checks;
- required audit event, ordering, redaction, integrity-chain and audit-sink failure tests;
- empty-cache blocked-network air-gap tests.

## Environment matrix

The supported matrix is generated from catalog claims. CI tiers:

- fast deterministic unit/schema tests on every change;
- container contract tests on relevant catalog changes;
- hardware tests on controlled runners for affected combinations;
- scheduled freshness and vulnerability checks;
- release qualification over every supported golden path.

An unavailable hardware runner means that path cannot receive fresh supported evidence; tests are not marked passed by omission.

## Test evidence

Compatibility and benchmark jobs output structured evidence with environment, commit, artifact digests and results. The implemented `ContractTestResult` establishes this boundary for preflight observations; later modes must extend it without weakening content identity or explicit limitations. Catalog promotion consumes reviewed evidence. Test logs alone are not durable catalog facts.

## Failure triage

Classify a failure as engine regression, catalog contradiction/staleness, upstream break, environment issue or invalid support claim. Quarantine affected combinations first; restoring broad support is secondary to preventing unsafe recommendations.
