# Component and topology integration evidence

YARA separates catalog knowledge, compatibility assertions and observed integration evidence. A valid component manifest says what a component is expected to provide. A `ContractTestResult` observes one runtime/model/hardware compatibility assertion. An `IntegrationTestResult` observes either a component boundary or a complete catalog topology. None of these resources silently upgrades another.

## Evidence modes

`component-smoke` binds one or more exact `component-id@version` references. It is intended for bounded checks of the component's declared health endpoint, consumed and provided contracts, immutable artifact identity and required dependencies. It does not prove that an entire suite works.

`topology-end-to-end` binds an exact `topology-id@version` and at least two exact component versions. It is intended for a bounded request across the declared connections in that topology. It does not establish latency, throughput, availability or production readiness unless separate contracts explicitly measure those properties.

Both modes require:

- the exact catalog digest;
- a content-addressed result identity;
- a pseudonymized local or SSH target identity;
- observed OS, architecture, Docker and accelerator facts;
- sorted checks with content-addressed evidence;
- explicit, sorted limitations;
- optional runner version and executable digest.

## Validation is not execution

```bash
go run ./cmd/yara integration validate result.yaml \
  --audit-output result.validation.audit.jsonl
```

This command validates the resource and produces an audit trail for that validation. It does not execute containers and its `integration.validate.*` events are deliberately rejected by the catalog coverage compiler as operational evidence.

Coverage accepts an integration result only when an adjacent audit chain:

1. is structurally and cryptographically valid;
2. is bound to the same catalog and result digests;
3. records the same pseudonymized target;
4. ends in the matching `integration.component-smoke.*` or `integration.topology-end-to-end.*` execution action;
5. records an outcome consistent with the result checks.

The execution command that produces this evidence is the next implementation boundary. Until it exists, catalog entries may be expanded as `known` knowledge, but component and topology coverage correctly remains missing.

## Coverage semantics

A component can be partially covered by compatibility-contract evidence or an observed integration attempt. Complete integration coverage requires the selected component-smoke and topology-end-to-end observations to pass. Related compatibility assertions must also be promotion-eligible before the component can be reported complete.

A topology is complete only when the latest accepted end-to-end result for its exact version passed. A failed or blocked observation remains partial coverage with the outcome exposed as a blocker. Missing evidence means `none`; it never means incompatible.

Promotion remains a separate reviewed action. An integration pass cannot edit manifest maturity and cannot substitute for independent review.
