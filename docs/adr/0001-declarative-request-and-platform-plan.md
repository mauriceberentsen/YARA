# ADR-0001: Separate declarative request and immutable platform plan

- Status: Accepted
- Date: 2026-07-14
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

YARA must accept user goals without forcing product choices, while downstream deployment needs concrete versions, topology and configuration intent. Combining both in one mutable file would make intent target-specific and obscure why choices changed.

## Decision

Represent desired outcomes in a versioned `PlatformRequest`. Compile it with inventory, policy and catalog snapshots into a separate immutable, content-addressed `PlatformPlan`. Any semantic change creates a new plan.

## Consequences

### Positive

- User intent remains portable across deployment targets and catalog updates.
- Plans can be reviewed, approved, diffed and reproduced.
- Deployment never needs to rerun recommendations.

### Negative

- More schemas, migration logic and intermediate data to maintain.
- Users must understand the distinction between a request and a plan.
- Not every target-specific feature maps neatly to portable intent.

### Neutral / follow-up

- Define canonical serialization and plan-diff semantics before v0.1 release.
- Namespaced extensions may represent unavoidable target-specific intent.

## Alternatives considered

### Generate deployment files directly from a wizard

Simpler initially, but couples selection to a target and loses durable reasoning.

### Use one mutable desired-state file with resolved defaults

Reduces resource count but makes it unclear which values are user intent versus planner decisions and invalidates prior approvals when regenerated.

## Validation

Golden scenarios must show the same request producing explainable different plans when inventory or catalog changes, while a pinned input set reproduces the same semantic plan.
