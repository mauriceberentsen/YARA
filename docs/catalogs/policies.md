# Policies

## Purpose

Policies turn organizational, security, licensing and operational requirements into enforceable planner constraints. They are not prose checklists attached after selection.

## Policy domains

- network connectivity and allowed endpoints;
- data classification, residency and retention;
- license allow/deny lists and use restrictions;
- artifact provenance, registries and signature requirements;
- telemetry, analytics and update checks;
- identity, access control and audit;
- encryption and secret providers;
- privilege, host access and workload isolation;
- availability, backup, recovery and maintenance;
- approved vendors/components/versions;
- experimental or stale evidence allowance.

## Enforcement levels

- `mandatory`: cannot be overridden within the request.
- `waivable`: can be bypassed only by a scoped, expiring approval.
- `default`: organization preference that a request may replace.
- `advisory`: emits diagnostics but does not affect validity.

Built-in invariants such as no plaintext secrets in plans are non-waivable application safety properties, not ordinary policies.

## Example

```yaml
apiVersion: yara.dev/v1alpha1
kind: Policy
metadata:
  id: organization.air-gap
  version: 1.0.0
spec:
  enforcement: mandatory
  scope:
    environments: [restricted]
  constraints:
    - field: topology.externalEgress
      operator: equals
      value: false
    - field: artifacts.availability
      operator: in
      value: [present, importable]
  rationale: Restricted environments have no route to external services.
```

## Precedence and merging

Policies are resolved into one effective set before planning. Merge behavior is typed:

- deny sets union;
- allow sets intersect when both are mandatory;
- numeric maximums choose the strictest lower bound;
- numeric minimums choose the strictest upper bound;
- contradictory mandatory constraints fail planning;
- defaults are replaced only by explicitly authorized lower-scope values.

Generic deep-merge semantics are forbidden because they hide policy conflicts.

## Exceptions

An exception includes policy/constraint ID, environment and resource scope, approver, rationale, issue/reference, creation and expiry. Plans expose active exceptions prominently. Expired exceptions invalidate new apply operations and trigger re-review; they do not mutate historical receipts.

## Air-gap semantics

`air-gapped` is more than "no cloud models." It constrains:

- artifact and model acquisition;
- DNS, certificate and time dependencies;
- update checks and telemetry;
- identity provider reachability;
- license validation behavior;
- documentation and recovery material availability;
- vulnerability-data import and catalog freshness.

YARA must validate a complete offline supply path, not only select local inference.
