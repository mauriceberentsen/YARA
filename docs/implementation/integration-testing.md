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

Generate bounded execution evidence with explicit immutable catalog confirmation:

```bash
go run ./cmd/yara integration component-smoke \
  --catalog catalog/v0.2/snapshot.yaml \
  --target local \
  --component core.litellm@1.93.0 \
  --confirm-catalog-digest sha256:<catalog-digest> \
  --name litellm-smoke \
  --output litellm-smoke.integration.yaml \
  --audit-output litellm-smoke.integration.audit.jsonl

go run ./cmd/yara integration topology-end-to-end \
  --catalog catalog/v0.2/snapshot.yaml \
  --target local \
  --topology core.local-chat-coding-vllm@1.0.0 \
  --component core.litellm@1.93.0 \
  --component core.vllm@0.8.5-post1 \
  --confirm-catalog-digest sha256:<catalog-digest> \
  --name private-chat-coding-e2e \
  --output private-chat-coding.e2e.integration.yaml \
  --audit-output private-chat-coding.e2e.integration.audit.jsonl

go run ./cmd/yara integration execute topology-end-to-end \
  --catalog catalog/v0.2/snapshot.yaml \
  --target local \
  --topology core.local-chat-coding-vllm@1.0.0 \
  --component core.litellm@1.93.0 \
  --component core.vllm@0.8.5-post1 \
  --confirm-catalog-digest sha256:<catalog-digest> \
  --name private-chat-coding-e2e \
  --output private-chat-coding.e2e.integration.yaml \
  --audit-output private-chat-coding.e2e.integration.audit.jsonl
```

The execution path remains bounded: it validates exact catalog references, records pseudonymized local/SSH target facts, emits sorted content-addressed checks, and fails closed on audit persistence errors. `integration execute` dispatches only `component-smoke` and `topology-end-to-end`; unsupported modes and stale topology/component bindings are rejected before executor dispatch.

`integration execute` now emits bounded explainability metadata in CLI output:

- `modePath: integration.execute.component-smoke`
- `modePath: integration.execute.topology-end-to-end`

Direct mode commands keep `modePath` empty to preserve existing output shape expectations.

Operator remediation guidance for generic execute failures:

- `YARA-INT-111`: unsupported generic mode; remediation is to choose `component-smoke` or `topology-end-to-end`.
- `YARA-INT-109`: selected topology components are not bound to a supported compatibility runtime assertion; remediation is to include an assertion-bound runtime component.
- `YARA-INT-110`: selected components do not satisfy every topology role; remediation is to select components that satisfy all topology roles declared in the topology reference.

Catalog coverage convergence rules for direct and generic integration evidence:

- accepted integration evidence is deduplicated by immutable `IntegrationTestResult` identity;
- reused result identities must bind the same verified audit-chain head, otherwise coverage fails closed;
- mixed direct-mode and `integration execute` evidence cannot inflate accepted evidence counts.

Publication diagnostics now require independent integration publication attestation evidence for assertions that require integration execution evidence. Record immutable attestation evidence with explicit selected integration result IDs:

```bash
go run ./cmd/yara integration publish attest \
  --catalog catalog/v0.2/snapshot.yaml \
  --evidence-dir catalog/v0.2/evidence \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --evidence sha256:<integration-result-id> \
  --reviewer-role release-manager \
  --decision approved \
  --reason-reference ticket-integration-publication-123 \
  --max-evidence-age 720h \
  --name qwen-coder-integration-publication \
  --output qwen-coder.integration-publication-attestation.yaml \
  --audit-output qwen-coder.integration-publication-attestation.audit.jsonl
```

The attestation path is fail-closed:

- selected integration evidence must already be accepted execution evidence bound to the same catalog and assertion runtime;
- each selected evidence ID must remain within `--max-evidence-age`;
- the generated attestation remains immutable and content-addressed;
- audit subjects bind the catalog digest, attestation ID, and selected integration evidence IDs.

## Coverage semantics

A component can be partially covered by compatibility-contract evidence or an observed integration attempt. Complete integration coverage requires the selected component-smoke and topology-end-to-end observations to pass. Related compatibility assertions must also be promotion-eligible before the component can be reported complete.

A topology is complete only when the latest accepted end-to-end result for its exact version passed. A failed or blocked observation remains partial coverage with the outcome exposed as a blocker. Missing evidence means `none`; it never means incompatible.

Promotion remains a separate reviewed action. An integration pass cannot edit manifest maturity and cannot substitute for independent review.

Lifecycle claim publication is now surfaced explicitly in catalog coverage summaries:

- `summary.lifecyclePublicationReadyAssertions`
- `summary.lifecyclePublicationBlockedAssertions`

Each assertion also carries:

- `lifecyclePublicationReady`
- `lifecyclePublicationBlocker`

`lifecyclePublicationBlocker` is deterministic and remediation-oriented (for example `lifecycle-proof-approval-not-recorded|remediation:record-lifecycle-proof-approval` or `selected-approval-expired-for-lifecycle-evidence|remediation:renew-lifecycle-proof-approval`). This keeps publication policy diagnostics operator-actionable without exposing secret material.

To inspect lifecycle publication policy diagnostics from one immutable report identity:

```bash
go run ./cmd/yara catalog coverage lifecycle-publication-policy \
  --report catalog-v0.2-coverage.yaml \
  --audit-output catalog-v0.2-coverage.lifecycle-publication-policy.audit.jsonl
```

The command does not mutate manifests or execution evidence. It emits bounded diagnostics only, and fails closed when report structure, lifecycle blocker encoding, or summary counts drift from deterministic coverage semantics.

To verify publication-chain signing-authority separation between air-gap gate evaluation signers and deployment authorization issuers:

```bash
go run ./cmd/yara catalog coverage signing-authority-boundary \
  --report catalog-v0.2-coverage.yaml \
  --trust-policy airgap-gate-trust-policy.yaml \
  --authorization deployment-authorization.yaml \
  --audit-output catalog-v0.2-coverage.signing-authority-boundary.audit.jsonl
```

The boundary command fails closed when:

- any trusted active gate signer key material overlaps with deployment authorization issuer key material;
- key-role reuse is ambiguous (for example the same key ID appears with different digests across role evidence);
- trust-policy or authorization evidence is malformed.

`catalog coverage create` and `catalog coverage lifecycle-publication-policy` now emit a shared deterministic explainability surface across:

- lifecycle publication readiness and blocker taxonomy;
- integration evidence convergence (`identityCount`, `deduplicatedCount`);
- signing-authority boundary report-limitation state (`status`, `overlapCount`, `ambiguityCount`, `evaluated`).

Both commands fail closed when signing-authority boundary limitation records are missing, duplicated, malformed, or internally inconsistent.

Phase 5 kickoff adds a bounded non-mutating publication-chain rehearsal:

```bash
go run ./cmd/yara publication chain rehearse \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --lifecycle-proof-approval lifecycle-proof-approval.yaml \
  --confirm-lifecycle-proof-approval sha256:<approval-id> \
  --integration-publication-attestation integration-publication-attestation.yaml \
  --confirm-integration-publication-attestation sha256:<attestation-id> \
  --coverage-report catalog-v0.2-coverage.yaml \
  --confirm-coverage-report sha256:<report-id> \
  --trust-policy airgap-gate-trust-policy.yaml \
  --confirm-trust-policy sha256:<policy-id> \
  --signing-boundary-audit signing-authority-boundary.audit.jsonl \
  --authorization deployment-authorization.yaml \
  --reviewer-role release-manager \
  --decision approved \
  --reason-reference ticket-publication-chain-rehearsal-123 \
  --max-evidence-age 720h \
  --name publication-chain-rehearsal \
  --output publication-chain-rehearsal.yaml \
  --audit-output publication-chain-rehearsal.audit.jsonl
```

Canonical lifecycle publication blocker taxonomy:

- `lifecycle-proof-approval-not-recorded` -> `record-lifecycle-proof-approval`
- `no-accepted-lifecycle-contract-evidence` -> `run-lifecycle-contract`
- `selected-approval-catalog-mismatch` -> `reissue-approval-for-catalog`
- `selected-approval-decision-abstained` -> `collect-explicit-approval-decision`
- `selected-approval-decision-changes-required` -> `address-review-feedback-and-reapprove`
- `selected-approval-does-not-bind-lifecycle-evidence` -> `reissue-approval-with-lifecycle-evidence`
- `selected-approval-expiry-invalid` -> `reissue-approval-with-valid-expiry`
- `selected-approval-expired-for-lifecycle-evidence` -> `renew-lifecycle-proof-approval`
- `integration-publication-attestation-not-recorded` -> `record-integration-publication-attestation`
- `no-accepted-integration-evidence` -> `run-integration-execute`
- `selected-integration-attestation-catalog-mismatch` -> `reissue-integration-attestation-for-catalog`
- `selected-integration-attestation-decision-abstained` -> `collect-explicit-integration-attestation-decision`
- `selected-integration-attestation-decision-changes-required` -> `address-integration-review-feedback-and-reattest`
- `selected-integration-attestation-does-not-bind-integration-evidence` -> `reissue-integration-attestation-with-bound-evidence`
- `selected-integration-attestation-expiry-invalid` -> `reissue-integration-attestation-with-valid-expiry`
- `selected-integration-attestation-expired-for-integration-evidence` -> `renew-integration-publication-attestation`

`catalog coverage lifecycle-publication-policy` fails closed when blockers use unknown codes, mismatched remediation text, or ambiguous remediation encoding.
