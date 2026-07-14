# Rule engine

## Responsibilities

Rules express inspectable domain logic that changes facts, constraints, candidate eligibility, requirements or scores. They do not deploy resources, fetch network data or execute arbitrary scripts.

Rule effects are limited to:

- derive a fact or capability;
- add a hard or soft constraint;
- require a topology role or dependency;
- reject a candidate with a reason code;
- add a bounded score contribution;
- emit a question, warning or advisory;
- require explicit approval or policy exception.

## Evaluation phases

Rules declare one phase:

1. `derive` — normalize and derive facts/capabilities;
2. `feasibility` — detect globally impossible requests;
3. `candidate` — filter products, versions and model combinations;
4. `score` — calculate soft preference contributions;
5. `topology` — validate resolved connections and data flows;
6. `plan` — validate final plan invariants.

A rule cannot depend on facts created in a later phase. Within a phase, dependency declarations create a DAG; cycles are invalid.

## Declarative form

Illustrative syntax:

```yaml
apiVersion: yara.dev/v1alpha1
kind: Rule
metadata:
  id: core.policy.no-external-egress
  version: 1.0.0
spec:
  phase: topology
  when:
    all:
      - fact: policy.network.egress
        equals: forbidden
      - pathExists: topology.connections[?(@.destination.scope == "external")]
  effects:
    - reject:
        code: YARA-POL-003
        message: The topology requires external network egress.
  rationale: Enforces the effective network policy after topology resolution.
```

The final expression language should be deliberately small, typed and non-Turing-complete. It must support boolean logic, comparisons, set membership, version ranges, quantified collection checks and unit-aware arithmetic. It must not support file, clock, network, process or environment access.

## Facts

Facts use a typed namespace and include source lineage. Rules read canonical facts such as:

```text
inventory.accelerators.totalMemory
request.workload.peakConcurrent
policy.network.egress
candidate.model.contextLimit
topology.dataFlows
```

Derived facts retain the rule ID and input fact IDs that produced them.

## Conflicts and precedence

Hard rejects are monotonic: another rule cannot restore a rejected candidate. Contradictory derived facts are an error unless the fact type explicitly defines aggregation. Score effects are additive only after normalization and bounded per rule group.

Policy precedence is resolved before rule evaluation:

```text
built-in non-waivable safety
    > organization mandatory
    > organization default
    > request policy
    > catalog recommendation
```

Exceptions are explicit resources containing approver, reason, scope and expiry. An exception disables a waivable constraint by ID; it does not change precedence globally.

## Versioning

Rules are immutable once released. Behavioral changes require a new version. A catalog snapshot selects exact rule versions, and plans record every rule that materially affected output. Rule-engine semantic version is also pinned because evaluation behavior may change independently from rule data.

## Explainability

Each evaluation records:

- rule ID and version;
- phase and outcome;
- facts read, including value and source;
- effect produced;
- affected candidate or plan path;
- human rationale and remediation;
- whether an exception is allowed.

Routine passing evaluations may be compacted in default output, but the full trace remains available.

## Safety limits

- Bound collection sizes, expression depth and total evaluations.
- Reject unknown functions and implicit type coercion.
- Use checked unit arithmetic and detect overflow.
- Treat evaluation errors as planning errors for material rules.
- Never load unsigned executable code as a rule.
- Do not use an LLM to decide whether a rule passed.

## Testing rules

Every rule contribution includes:

- one positive match;
- one non-match;
- one boundary case;
- one missing/unknown input case;
- one conflict or counterexample where relevant;
- expected reason code and trace fields.

Rule-set tests also verify determinism, phase ordering, bounded scores and absence of dependency cycles.
