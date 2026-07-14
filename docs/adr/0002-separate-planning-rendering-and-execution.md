# ADR-0002: Separate planning, rendering and execution

- Status: Accepted
- Date: 2026-07-14
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

Selecting architecture, translating it to a target format and mutating infrastructure have different trust, test and permission needs. Combining them would give recommendation code credentials and allow target adapters to make hidden choices.

## Decision

Use three boundaries:

- planner: pure selection and validation;
- renderer: pure plan-to-artifact translation;
- executor: explicitly approved target mutation.

Executors and renderers may reject unsupported plan intent but cannot replace selections or relax constraints.

## Consequences

### Positive

- Planner runs without target credentials.
- Rendering can be tested with deterministic fixtures.
- Users can review artifacts/change sets or use external GitOps execution.
- New deployment targets do not change core planning semantics.

### Negative

- Adapter compatibility matrix and handoff schemas add work.
- Some target capabilities require careful abstraction in the plan.
- Validation occurs at several layers.

### Neutral / follow-up

- First renderer/executor target remains a separate decision after prototypes.

## Alternatives considered

### One end-to-end installer

Faster for a fixed stack, but creates an unsafe privilege boundary and makes target support inseparable from recommendation logic.

### Renderers that choose target-specific alternatives

Convenient when a target lacks support, but makes an approved plan no longer describe what is actually deployed.

## Validation

Contract tests must prove a renderer is deterministic and errors on unknown intent. Executor tests must show apply approval is bound to exact plan, bundle, change set and target.
