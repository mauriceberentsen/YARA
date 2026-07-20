# Architecture

YARA separates deciding **what should exist** from deciding **how to create it**. Its core is an explainable planner over versioned knowledge; deployment and operations are downstream consumers of the resulting plan.

## Status legend

- **Implemented now**: behavior that exists in the repository and current CLI/docs flow.
- **Planned/future**: architectural target state or roadmap scope not fully shipped.

## Architectural layers

```text
Interfaces       CLI | planned API | planned web UI
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
Operations       observation | planned drift | planned upgrade | planned backup/recovery
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

## Implemented now (architecture surfaces)

- [System overview](system-overview.md) - active architecture map for current scope.
- [Domain model](domain-model.md) - implemented resource and contract boundaries.
- [Planning pipeline](planning-pipeline.md) - deterministic planning stages and constraints.
- [Knowledge base](knowledge-base.md) - curated catalog/evidence model used by planning.
- [Rule engine](rule-engine.md) - current rule and constraint posture.
- [Recommendation engine](recommendation-engine.md) - implemented recommendation logic boundary.
- [Platform plan](platform-plan.md) - immutable plan and explainability contract.
- [Data and state](data-and-state.md) - current state model and evidence boundaries.
- [Deployment engine](deployment-engine.md) - bounded preflight/change-set/approval/authorization/executor path.
- [Security](security.md) - active trust and safety boundary.
- [Auditing](auditing.md) - append-only audit/event integrity model.
- [Observability](observability.md) - current diagnostic and evidence surfaces.
- [Testing strategy](testing-strategy.md) - current verification approach.
- [Repository layout](repository-layout.md) - package boundaries in current implementation.

## Planned/future architecture areas

- [Runtime and lifecycle](runtime-lifecycle.md) - includes future runtime-manager scope beyond current bounded executor paths.
- [Plugin system](plugin-system.md) - extension architecture target, not a completed plugin transport runtime.
- [API](api.md) - remote/service API direction, currently not the primary shipped interface.

Planned/future documents are maintained for design coherence and review, but they are not claims that full corresponding product surfaces are already shipped.

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

This index intentionally distinguishes implemented versus planned areas. Use `README.md`, `docs/quickstart.md`, and `docs/reference/commands.md` for user-facing "what works now" boundaries, and treat planned/future architecture docs as design direction unless explicitly marked as implemented.
