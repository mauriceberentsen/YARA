# YARA documentation

This documentation is the design contract for YARA. It distinguishes committed architecture from hypotheses, future work and illustrative examples. A document describing a future capability does not imply that the capability is implemented.

## Reading paths

### New contributors

1. [Vision](vision.md)
2. [Product scope](product/scope.md)
3. [System overview](architecture/system-overview.md)
4. [Domain model](architecture/domain-model.md)
5. [Roadmap](roadmap.md)
6. [Contributing](../CONTRIBUTING.md)

### Planner and catalog contributors

1. [Planning pipeline](architecture/planning-pipeline.md)
2. [Knowledge base](architecture/knowledge-base.md)
3. [Rule engine](architecture/rule-engine.md)
4. [Recommendation engine](architecture/recommendation-engine.md)
5. [Catalogs](catalogs/README.md)
6. [Schema conventions](catalogs/schema-conventions.md)

### Deployment and operations contributors

1. [Platform plan](architecture/platform-plan.md)
2. [Deployment engine](architecture/deployment-engine.md)
3. [Runtime and lifecycle](architecture/runtime-lifecycle.md)
4. [Security](architecture/security.md)
5. [Observability](architecture/observability.md)

### First implementation contributors

1. [Implementation guide](implementation/README.md)
2. [First vertical slice](implementation/first-vertical-slice.md)
3. [Testing strategy](architecture/testing-strategy.md)
4. [Repository layout](architecture/repository-layout.md)
5. [Architectural decisions](adr/README.md)
6. [v0.1 acceptance status](implementation/v0.1-acceptance-status.md)

## Document map

| Area | Documents | Purpose |
|---|---|---|
| Product | [positioning](product/positioning.md), [scope](product/scope.md), [validation](product/validation.md), [business model](product/business-model.md), [go to market](product/go-to-market.md) | Identify the user, problem, boundaries, validation and sustainability strategy |
| Architecture | [index](architecture/README.md), [system overview](architecture/system-overview.md), [domain model](architecture/domain-model.md) | Define system responsibilities and boundaries |
| Planning | [pipeline](architecture/planning-pipeline.md), [rules](architecture/rule-engine.md), [recommendations](architecture/recommendation-engine.md) | Define how YARA turns requirements into decisions |
| Knowledge | [knowledge base](architecture/knowledge-base.md), [catalogs](catalogs/README.md) | Define evidence, manifests, relationships and provenance |
| Execution | [plan](architecture/platform-plan.md), [deployment](architecture/deployment-engine.md), [runtime](architecture/runtime-lifecycle.md) | Separate desired state, planning and mutation |
| Platform | [API](architecture/api.md), [plugins](architecture/plugin-system.md), [data and state](architecture/data-and-state.md) | Define extension and integration boundaries |
| Assurance | [security](architecture/security.md), [auditing](architecture/auditing.md), [observability](architecture/observability.md), [risks](risk-register.md) | Define trust, accountability, diagnostics and major failure modes |
| Operations | [air-gapped operation](operations/air-gapped.md), [upgrades, backup and recovery](operations/upgrades-backup-recovery.md) | Define operational reference workflows |
| Delivery | [implementation guide](implementation/README.md), [v0.1 acceptance status](implementation/v0.1-acceptance-status.md), [roadmap](roadmap.md), [ADRs](adr/README.md), [examples](examples/README.md) | Make implementation, release gates and decisions concrete |

## Normative language

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** indicate requirement strength. Until a schema or implementation exists, these requirements are architectural intent and should be converted into executable validation as early as possible.

## Status labels

- **Accepted:** current architectural direction, recorded in an ADR where material.
- **Proposed:** sufficiently developed for review, not yet accepted.
- **Experimental:** intended for learning and may be discarded.
- **Future:** deliberately outside the current milestone.

Unless a document states otherwise, architecture in this tree is **Proposed** and v0.1 scope in [the roadmap](roadmap.md) is **Accepted**.

## Documentation rules

- Keep one primary responsibility per document.
- Link to definitions instead of redefining terms.
- Mark examples as illustrative when they are not schema-valid fixtures.
- Record irreversible or cross-cutting decisions as ADRs.
- Put volatile compatibility facts in catalogs, not prose.
- State uncertainty, evidence source and freshness for recommendations.
- Update documentation in the same change as the behavior it describes.
