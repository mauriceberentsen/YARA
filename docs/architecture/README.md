# Architecture

YARA separates deciding **what should exist** from deciding **how to create it**. Its core is an explainable planner over versioned knowledge; deployment and operations are downstream consumers of the resulting plan.

## Architectural layers

```text
Interfaces       CLI | API | future web UI
                       |
Intent           request | inventory | policies | objectives
                       |
Reasoning        normalization | constraints | candidates | scoring
                       |
Knowledge        catalogs | rules | evidence | compatibility
                       |
Intermediate     immutable PlatformPlan + decision trace
representation         |
Execution        renderers | approval | executors | verification
                       |
Operations       observation | drift | upgrade | backup | recovery
```

Dependencies point downward. Knowledge packages do not call deployment code. The planner does not mutate infrastructure. Executors do not reinterpret user intent or silently select different components.

## Core invariants

1. A `PlatformRequest` contains goals and constraints, not rendered infrastructure.
2. Discovery records facts and provenance; it does not recommend.
3. The planner is deterministic for a fixed request, inventory, policy set, engine version and catalog snapshot.
4. Hard constraints run before scoring.
5. Every material decision is explainable and identifies its evidence.
6. A `PlatformPlan` is immutable; change creates a new plan and diff.
7. Rendering is pure; applying is explicit and auditable.
8. Secrets are referenced, never embedded in requests, plans or catalogs.
9. Observed runtime data cannot silently rewrite desired state.
10. Unknown critical information fails closed.
11. Every security-relevant or state-changing action emits an append-only audit event; audit failure blocks production mutation.

## Documents

- [System overview](system-overview.md)
- [Domain model](domain-model.md)
- [Planning pipeline](planning-pipeline.md)
- [Knowledge base](knowledge-base.md)
- [Rule engine](rule-engine.md)
- [Recommendation engine](recommendation-engine.md)
- [Platform plan](platform-plan.md)
- [Data and state](data-and-state.md)
- [Deployment engine](deployment-engine.md)
- [Runtime and lifecycle](runtime-lifecycle.md)
- [Plugin system](plugin-system.md)
- [API](api.md)
- [Security](security.md)
- [Auditing](auditing.md)
- [Observability](observability.md)
- [Testing strategy](testing-strategy.md)
- [Repository layout](repository-layout.md)

## Quality attributes

| Attribute | Architectural response |
|---|---|
| Safety | Fail-closed constraints, explicit approval, trust boundaries and no implicit mutation |
| Explainability | Decision records containing facts, rules, alternatives, scores and evidence |
| Reproducibility | Immutable inputs, content hashes, versioned schemas and pinned catalogs |
| Accountability | Append-only audit events bound to actors, resource digests, reasons and outcomes |
| Extensibility | Data-driven catalogs and narrow plugin interfaces |
| Testability | Pure planning stages, golden scenarios and renderer contract tests |
| Portability | Platform plan independent of Docker, Kubernetes or a cloud vendor |
| Operability | Health, backup and upgrade contracts included in selection metadata |
| Privacy | Local-first processing, no default telemetry and secret references only |

## Architecture maturity

This is a proposed target architecture. v0.1 implements only the request, inventory, catalog, planning, explanation and plan-validation path. Deployment, runtime control and remote APIs are documented now to keep boundaries coherent, not because they are committed to the first release.
