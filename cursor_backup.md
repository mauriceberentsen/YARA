# Cursor handoff

## Current repository state

- Repository: `YARA` (audit-first deterministic planner with bounded lifecycle execution).
- Branch baseline before this slice: `main` at `07b8dba` (`Converge integration evidence identities in catalog coverage.`).
- ADR scope remains `0001`-`0011`; direct fail-closed Kubernetes mutation boundary remains ADR-0011.
- Public resource schema set now includes:
  - `PromotionReview` (`schemas/yara.dev/v1alpha1/promotion-review.schema.json`);
  - `ArtifactTransferReceipt` (`schemas/yara.dev/v1alpha1/artifact-transfer-receipt.schema.json`);
  - `ArtifactScanReceipt` (`schemas/yara.dev/v1alpha1/artifact-scan-receipt.schema.json`);
  - `AirgapProvenanceGateResult` (`schemas/yara.dev/v1alpha1/airgap-provenance-gate-result.schema.json`);
  - `AirgapGateTrustPolicy` (`schemas/yara.dev/v1alpha1/airgap-gate-trust-policy.schema.json`);
  - `AirgapGateTransitionReview` (`schemas/yara.dev/v1alpha1/airgap-gate-transition-review.schema.json`);
  - `LifecycleProofLedger` (`schemas/yara.dev/v1alpha1/lifecycle-proof-ledger.schema.json`);
  - `LifecycleProofApproval` (`schemas/yara.dev/v1alpha1/lifecycle-proof-approval.schema.json`);
  - `IntegrationPublicationAttestation` (`schemas/yara.dev/v1alpha1/integration-publication-attestation.schema.json`);
  - `PublicationChainRehearsal` (`schemas/yara.dev/v1alpha1/publication-chain-rehearsal.schema.json`).
- Latest archived catalog coverage artifact remains `catalog/v0.2/coverage.yaml` with report ID `sha256:b1f2379eb930d431b2cbe1543ec38fb243580213c76ca56be96def47883beb83`.

## Current product boundary

- Implemented lifecycle chain:
  - deterministic plan/render;
  - read-only Kubernetes preflight and change-set;
  - review-only approval;
  - short-lived signed authorization;
  - bounded apply/retire/rollback executor commands;
  - bounded integration execution evidence commands.
- Promotion governance:
  - `promotion review record` emits immutable `PromotionReview` evidence and audit chains;
  - coverage compilation deterministically resolves `independent-promotion-review` from accepted review evidence.
- Lifecycle proof kickoff:
  - `lifecycle proof record` emits immutable `LifecycleProofLedger` evidence linking exact apply/retire/rollback receipt IDs into one reviewed lifecycle narrative;
  - lifecycle proof recording is read-only and fail-closed on foreign chains (plan/bundle/target mismatch), stale receipt windows, invalid ordering, or incomplete/non-succeeded lifecycle stages.
  - `contract lifecycle` now requires explicit lifecycle-proof inputs (`--lifecycle-proof-ledger`, linked apply/retire/rollback receipts, explicit ledger ID confirmation, explicit reason-reference confirmation, and bounded max-age policy) and fails closed when ledger identity, stage ordering, receipt bindings, or freshness drift.
  - `lifecycle proof approve-publication` emits immutable `LifecycleProofApproval` evidence that independently reviews one lifecycle ledger identity for one catalog assertion using explicit selected lifecycle evidence IDs and bounded freshness policy;
  - catalog coverage now gates lifecycle publication claims on `lifecycle-proof-publication-approval` and fails closed when lifecycle approvals are missing, unapproved, unbound to lifecycle evidence, catalog-mismatched, or stale relative to selected lifecycle evidence.
  - catalog coverage summaries now surface lifecycle publication readiness explicitly through `lifecyclePublicationReadyAssertions` and `lifecyclePublicationBlockedAssertions`, and assertion-level diagnostics through `lifecyclePublicationReady` plus deterministic remediation-coded `lifecyclePublicationBlocker` values;
  - catalog coverage now rejects malformed lifecycle-proof approval audits and ledger/approval subject-binding drift in evidence compilation.
  - `catalog coverage create` now surfaces lifecycle publication-readiness counts directly in CLI response output (`lifecyclePublicationReadyAssertions`, `lifecyclePublicationBlockedAssertions`);
  - `catalog coverage lifecycle-publication-policy --report <file>` now emits bounded policy diagnostics for blocked assertions with deterministic remediation extraction, and writes dedicated audit chains;
  - catalog coverage validation now fails closed when lifecycle publication blockers use malformed encoding or summary readiness counts drift from assertion-level evidence.
  - lifecycle publication blocker taxonomy is now centralized and canonicalized in one deterministic machine-readable map, and policy diagnostics fail closed when blocker codes are unknown, remediation text drifts, or encoding is ambiguous;
  - lifecycle publication policy diagnostics now emit bounded explainability metadata (`reportSubject`, `assertionScope`) and expose taxonomy definitions with each response for auditable operator interpretation.
  - new `integration execute <component-smoke|topology-end-to-end>` dispatches to the existing bounded integration executors without adding mutation authority;
  - topology `integration execute` now fails closed before executor dispatch when selected components are stale versus assertion/runtime bindings or do not satisfy topology-role coverage.
  - generic integration executor diagnostics now provide explicit remediation guidance for unsupported mode (`YARA-INT-111`), stale runtime-binding drift (`YARA-INT-109`), and topology-role drift (`YARA-INT-110`);
  - generic `integration execute` output now includes bounded explainability metadata (`modePath`) while durable `IntegrationTestResult` and audit schemas remain unchanged;
  - deterministic parity tests now prove `integration execute` preserves sorted/unique component normalization and deterministic result identity parity with direct mode-specific integration commands.
  - catalog coverage now deduplicates accepted integration evidence by immutable `IntegrationTestResult` identity so mixed direct and generic execution artifacts cannot inflate accepted evidence counts;
  - catalog coverage now fails closed when one integration result identity is reused with mismatched verified audit-chain heads;
  - integration policy docs now describe convergence semantics for direct and generic integration evidence identity reuse.
  - `catalog coverage create` and `catalog coverage lifecycle-publication-policy` now surface converged integration evidence diagnostics (`integrationEvidenceConvergence.identityCount`, `deduplicatedCount`, `deduplicationApplied`) without changing durable resource schemas;
  - publication-facing convergence diagnostics now fail closed when report convergence limitation records are malformed or ambiguous;
  - mixed direct/generic integration evidence publication diagnostics are now covered by deterministic CLI tests proving deduplication-state stability.
  - `integration publish attest` now emits immutable `IntegrationPublicationAttestation` evidence that binds one catalog assertion to selected converged integration evidence IDs, reviewer decision, bounded validity, and deterministic fail-closed freshness checks;
  - catalog coverage now gates publication diagnostics on accepted integration publication attestation evidence for assertions requiring integration execution evidence;
  - integration publication attestation audits are now fail-closed on malformed action/subject bindings and require explicit selected integration evidence subject linkage.
  - `catalog coverage signing-authority-boundary` now emits bounded publication diagnostics proving gate-evaluation signer authority is independent from deployment-authorization issuers;
  - signing-authority boundary diagnostics now fail closed on key-material overlap (`publicKeyDigest`) between active gate signers and authorization issuers;
  - signing-authority boundary diagnostics now fail closed on ambiguous key-role reuse (same key ID with different digests or same digest with different key IDs across role evidence) without exposing secret key material.
  - catalog coverage report limitations now encode deterministic signing-authority boundary state (`signing-authority-boundary:status=...,overlap-count=...,ambiguity-count=...`);
  - `catalog coverage create` and `catalog coverage lifecycle-publication-policy` now emit one shared explainability surface covering lifecycle readiness, integration convergence, and signing-authority boundary limitation state;
  - policy diagnostics now fail closed when signing-authority boundary limitation records are missing, duplicated, malformed, or internally inconsistent.
  - `publication chain rehearse` now emits immutable `PublicationChainRehearsal` evidence for one assertion-scoped publication identity set (lifecycle approval + integration attestation + coverage report + trust policy + signing-boundary audit + authorization IDs) without mutation authority;
  - publication-chain rehearsal now fails closed on stale evidence windows, foreign catalog/assertion bindings, approval/attestation confirmation mismatches, malformed signing-boundary audits, or non-independent signer-boundary evidence.
  - publication-policy diagnostics now include assertion-scoped `publication-chain-rehearsal` gate state sourced from immutable coverage evidence;
  - assertion-scoped lifecycle publication policy diagnostics now fail closed when publication-chain rehearsal evidence is missing or non-passing for the selected assertion.
- Air-gap provenance:
  - `artifact transfer record` emits immutable `ArtifactTransferReceipt` evidence bound to exact bundle/import identities;
  - `artifact scan record` emits immutable `ArtifactScanReceipt` evidence bound to exact transferred artifact identities and scanner policy/tool identities;
  - `airgap provenance-gate evaluate` now emits a signed `AirgapProvenanceGateResult` (Ed25519 signer identity, key digest, expiry, detached signature) over exact import/transfer/scan bindings;
  - `airgap gate-trust-policy record` now emits immutable `AirgapGateTrustPolicy` resources from explicit signer inputs and dedicated audit chains;
  - `airgap gate-trust-policy diff` now emits immutable `AirgapGateTrustPolicyDiff` transition evidence with signer change classification/impact and one-step active-signer replacement safety checks;
  - `airgap gate-trust-policy review-transition` now emits immutable `AirgapGateTransitionReview` approval evidence for destructive policy-diff transitions;
  - `airgap provenance-gate verify` validates gate-result identity, signer status/bounds and signature validity against an immutable `AirgapGateTrustPolicy`, requires explicit `--confirm-policy`, and can bind reviewed policy-diff evidence via `--policy-diff --confirm-policy-diff`; destructive diffs now fail closed unless an approved `--transition-review --confirm-transition-review` artifact is provided;
  - `deployment apply kubernetes` can fail closed on `--airgap-gate-result` only when verification passes under `--airgap-gate-trust-policy` and explicit `--confirm-airgap-gate-trust-policy`, with optional policy-diff binding (`--airgap-gate-policy-diff --confirm-airgap-gate-policy-diff`); destructive diffs now fail closed unless approved transition review evidence is supplied (`--airgap-gate-transition-review --confirm-airgap-gate-transition-review`).
- Apply remains explicit and bounded to exact rendered objects; it still does not implicitly delete/prune/adopt.
- Mutating commands still require durable started audit before mutation and fail closed when terminal audit/receipt persistence cannot complete.

## Verified capabilities

- **Implemented + locally validated in repository tests/schemas/docs:**
  - content-addressed resources and schema/Go validation for apply/import/transfer/scan/air-gap gate/retire/rollback/integration/promotion review;
  - transfer chain receipts bind exact immutable model artifact identities and prior receipt IDs;
  - scan receipts bind scanner name/version/profile + policy digest and non-secret verdict references to exact transferred model artifact identities;
  - air-gap gate results bind exact plan/bundle/catalog/target/import identities, transfer/scan receipt sets, deterministic gate status, signer identity, trust-key digest, signature, and expiry;
  - trust-policy inputs are content-addressed (`policyId`), include sorted signer allow-lists with status + optional validity windows, and verify key bytes against declared digests;
  - trust-policy recording now requires explicit signer declarations (`key-id`, `public-key`, status, optional validity bounds) and emits immutable audit evidence for policy creation;
  - trust-policy diff evidence is content-addressed (`diffId`), sorted signer-delta projections, and deterministic highest-impact derivation (`review`/`destructive`);
  - trust-policy diff command fails closed when a single transition would replace every active signer identity in one step;
  - destructive transition review evidence is content-addressed (`reviewId`), bound to exact `policyDiffId`/`fromPolicyId`/`toPolicyId`/target identities, and required for destructive transition consumption in verify/apply;
  - lifecycle proof ledger evidence is content-addressed (`ledgerId`), binds exact apply/retire/rollback receipt IDs plus execution correlations in strict stage order, and records reviewed operator intent without mutation authority;
  - lifecycle contract execution now binds deterministic lifecycle-proof checks (`lifecycle.proof-ledger.binding`, `lifecycle.proof-ledger.freshness-policy`) into `ContractTestResult` evidence and audit subjects, including explicit freshness-policy and reviewed-reason references;
  - lifecycle proof publication approvals are content-addressed (`approvalId`), bind exact `catalogDigest`/`assertionRef`/`ledgerId`/selected evidence IDs with bounded validity and reviewer decision, and are consumed by catalog-coverage lifecycle publication gating;
  - lifecycle publication diagnostics now provide deterministic operator remediation hints (`...|remediation:<action>`) for missing, stale, unbound, or decision-mismatched lifecycle approvals;
  - lifecycle publication policy diagnostics are now available via both coverage create output and the dedicated policy command, with fail-closed validation of blocker encoding parity and strict taxonomy matching;
  - generic integration execution dispatch (`integration execute`) now preserves deterministic `IntegrationTestResult` semantics by reusing existing mode-specific bounded executors with unchanged output contracts;
  - integration execution now fails closed on unsupported generic modes and stale topology/component assertion drift prior to executor invocation;
  - integration execute diagnostics now include deterministic remediation guidance for unsupported mode and stale binding/role drift, and generic execution output includes explicit mode-path explainability metadata;
  - catalog coverage now enforces identity-equivalent integration evidence convergence for mixed direct/generic execution artifacts and rejects audit-binding drift for reused result identities;
  - publication-facing coverage diagnostics now expose integration convergence state deterministically for both create and lifecycle-policy command paths;
  - integration publication attestations are content-addressed (`attestationId`), bind exact catalog/assertion/selected integration evidence IDs with bounded freshness policy, and remain independently auditable;
  - `integration publish attest` now enforces fail-closed selected-evidence binding to accepted integration execution evidence (catalog-bound, runtime-bound, audit-verified) before writing immutable attestation output;
  - catalog publication diagnostics now require accepted integration publication attestation evidence in addition to lifecycle publication approval evidence for assertions requiring integration execution evidence;
  - lifecycle publication blocker taxonomy now includes deterministic remediation-coded integration attestation blocker classes;
  - publication-facing signing-authority boundary diagnostics are now available through a bounded audited CLI path requiring immutable coverage report, trust-policy, and execution-authorization evidence;
  - signing-authority boundary diagnostics remain deterministic and non-secret while rejecting overlapping or ambiguous signer/issuer role bindings;
  - publication diagnostics now preserve deterministic parity between create and lifecycle-policy outputs for lifecycle, integration convergence, and signing-authority boundary explainability fields;
  - publication-chain rehearsals are content-addressed (`rehearsalId`), bind exact publication-chain identity subjects plus verified signing-boundary audit head, and record non-mutating reviewer readiness decisions;
  - `publication chain rehearse` plus `publication-chain-rehearsal validate` provide bounded pre-live publication readiness checks with deterministic audit chains;
  - assertion-scoped lifecycle publication policy now reports deterministic publication-chain rehearsal readiness diagnostics (`status`, `blocker`, selected rehearsal ID) and rejects non-ready assertion scopes fail-closed;
  - apply-time provenance rejects missing, mismatched or unlinked transfer/scan chains for air-gapped policy bundles, and rejects non-passed/unsigned/untrusted/revoked/expired gate results when configured;
  - deployment receipts now carry optional `transferReceiptIds`, `scanReceiptIds`, `airgapGateResultId`, `airgapGateTrustPolicyId`, `airgapGateTrustPolicyDiffId`, and `airgapGateTransitionReviewId` provenance bindings;
  - separate command paths:
    - `deployment apply kubernetes`,
    - `deployment retire kubernetes`,
    - `deployment rollback kubernetes`,
    - `integration component-smoke`,
    - `integration topology-end-to-end`,
    - `integration execute`,
    - `promotion review record`,
    - `artifact transfer record`,
    - `artifact scan record`,
    - `airgap provenance-gate evaluate`,
    - `airgap gate-trust-policy record`,
    - `airgap gate-trust-policy diff`,
    - `airgap gate-trust-policy review-transition`,
    - `lifecycle proof record`,
    - `lifecycle proof approve-publication`,
    - `contract lifecycle` (with explicit lifecycle-proof evidence binding),
    - `airgap provenance-gate verify`,
    - `airgap-gate-trust-policy validate`,
    - `airgap-gate-trust-policy-diff validate`,
    - `airgap-gate-transition-review validate`,
    - `lifecycle-proof-ledger validate`,
    - `lifecycle-proof-approval validate`.
- **Validated on live environment (historical evidence already present):**
  - one successful authorized apply with receipt `sha256:e584d749052c4b389e9013745337d76ccf02862d5fda900eec6c90c8d634944f`;
  - one separately reviewed idempotent apply with 12 no-op operations and receipt `sha256:caa1d717287be833152da68101dc61a52ad0bac54509132413e93adab79c7e7d`.
- **Validated in this run (simulated/local only):**
  - `gofmt -w <changed-go-files>` passed;
  - `git diff --check` passed;
  - `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check` passed;
  - `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...` passed.

## Current branch and working tree

- Branch: `main` tracking `origin/main` (local ahead by eleven commits before this uncommitted work).
- Recent commits before this slice (newest first): `9c7414c`, `cdf8393`, `3ff1b5d`, `10de4ec`, `86c7a32`.
- This slice closes Phase 5 assertion-scoped publication-chain policy diagnostics parity.
- Phase 5 milestone plan now tracks three ordered slices:
  - slice 1 completed: publication-chain rehearsal resource/command/validation closure with fail-closed chain binding checks;
  - slice 2 completed in this run: assertion-scoped publication-chain policy diagnostics parity in coverage policy output;
  - slice 3 pending: publication-chain reviewer decision convergence for promotion-review entry points.
- Working tree is expected to be clean after committing this slice.
- Required git author for this stream remains: `Maurice Berentsen <mauriceberentsen@live.nl>`.

## Open limitations and unproven claims

- No live validation was executed for rollback, integration execution, promotion-review recording, lifecycle-proof ledger recording/consumption/publication approval, catalog-publication gating, transfer/scan receipt enforcement, trust-policy recording/diffing/review-transition, or trust-policy gate verification/enforcement in this run.
- Air-gap completeness remains unproven end-to-end: acquisition execution, transfer medium attestation trust chain, and scanning attestations remain external.
- Clean-cluster bootstrap (namespace/PVC/storage provisioning) remains out of scope.
- Integration execution remains bounded to catalog/target contract checks and does not prove latency, throughput, availability, or production readiness.

## Next implementation slice

Implement **Phase 5 milestone completion: publication-chain reviewer decision convergence for promotion-review entry points**:

- require an explicit publication-chain rehearsal identity binding when recording promotion reviews for assertions requiring integration publication evidence;
- fail closed on stale/foreign/non-approved rehearsal evidence or assertion-scope mismatch at promotion-review recording time;
- preserve deterministic non-secret evidence boundaries and existing mutation-authority constraints.

Acceptance criteria:

- promotion-review recording fails closed when required publication-chain rehearsal evidence is missing, stale, foreign, unapproved, or mismatched to selected assertion scope;
- promotion entry-point diagnostics remain deterministic and non-secret while exposing bounded publication-chain rehearsal readiness binding state;
- lifecycle and integration publication diagnostics remain deterministic and non-secret with no mutation authority added;
- lifecycle publication taxonomy and diagnostics remain unchanged by executor work;
- durable audit chains still prove deterministic linkage from lifecycle ledger to lifecycle approval and publication outputs;
- apply-side provenance remains fail-closed and unaffected by lifecycle publication-policy UX additions;
- schema validation and Go validation remain aligned with focused CLI and negative tests.

## Validation requirements

Run at minimum for each new slice:

```bash
gofmt -w <changed-go-files>
git diff --check
GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check
GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...
```

Required test depth for lifecycle slices:

- focused unit tests for resource contracts and validation invariants;
- negative tests for stale/foreign/unauthorized execution paths;
- determinism tests for content-addressed identities and sorted operation/check ordering;
- CLI tests for changed command behavior and confirmation mismatch paths;
- fail-closed tests proving no execution/mutation when required audit/receipt preconditions fail.

Validation classification rules:

- classify unit/CLI/fake-runner coverage as **simulated/local**;
- classify as **live** only when an actual cluster execution was run in this session;
- never promote simulated/local results to live claims.

## Publishing requirements

- Review full diff for scope coherence and exclude unrelated changes.
- Keep `.yara/` outputs and machine-local artifacts unstaged.
- Do not persist secrets/private keys/kubeconfig/raw target addresses/prompts/completions/env vars/raw logs/raw Kubernetes object bodies.
- Keep docs, schemas, CLI behavior, and Go validation in sync.
- Update this handoff after each completed slice with:
  - completed slice outcome;
  - actual branch and commit state;
  - exact validation commands that passed;
  - explicit simulated/local/live distinction;
  - exactly one next recommended slice.
- Do not merge or push unless explicitly authorized by repository policy and access context.
