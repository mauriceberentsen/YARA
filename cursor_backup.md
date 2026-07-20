# Cursor handoff

## Current repository state

- Repository: `YARA` (audit-first deterministic planner with bounded lifecycle execution).
- Branch baseline before this slice: `main` at `3539f29` (`Add signed air-gap gate attestation verification policy.`).
- ADR scope remains `0001`-`0011`; direct fail-closed Kubernetes mutation boundary remains ADR-0011.
- Public resource schema set now includes:
  - `PromotionReview` (`schemas/yara.dev/v1alpha1/promotion-review.schema.json`);
  - `ArtifactTransferReceipt` (`schemas/yara.dev/v1alpha1/artifact-transfer-receipt.schema.json`);
  - `ArtifactScanReceipt` (`schemas/yara.dev/v1alpha1/artifact-scan-receipt.schema.json`);
  - `AirgapProvenanceGateResult` (`schemas/yara.dev/v1alpha1/airgap-provenance-gate-result.schema.json`);
  - `AirgapGateTrustPolicy` (`schemas/yara.dev/v1alpha1/airgap-gate-trust-policy.schema.json`).
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
- Air-gap provenance:
  - `artifact transfer record` emits immutable `ArtifactTransferReceipt` evidence bound to exact bundle/import identities;
  - `artifact scan record` emits immutable `ArtifactScanReceipt` evidence bound to exact transferred artifact identities and scanner policy/tool identities;
  - `airgap provenance-gate evaluate` now emits a signed `AirgapProvenanceGateResult` (Ed25519 signer identity, key digest, expiry, detached signature) over exact import/transfer/scan bindings;
  - `airgap provenance-gate verify` validates gate-result identity, signer status/bounds and signature validity against an immutable `AirgapGateTrustPolicy`;
  - `deployment apply kubernetes` can fail closed on `--airgap-gate-result` only when verification passes under `--airgap-gate-trust-policy`; otherwise apply rejects the gate result.
- Apply remains explicit and bounded to exact rendered objects; it still does not implicitly delete/prune/adopt.
- Mutating commands still require durable started audit before mutation and fail closed when terminal audit/receipt persistence cannot complete.

## Verified capabilities

- **Implemented + locally validated in repository tests/schemas/docs:**
  - content-addressed resources and schema/Go validation for apply/import/transfer/scan/air-gap gate/retire/rollback/integration/promotion review;
  - transfer chain receipts bind exact immutable model artifact identities and prior receipt IDs;
  - scan receipts bind scanner name/version/profile + policy digest and non-secret verdict references to exact transferred model artifact identities;
  - air-gap gate results bind exact plan/bundle/catalog/target/import identities, transfer/scan receipt sets, deterministic gate status, signer identity, trust-key digest, signature, and expiry;
  - trust-policy inputs are content-addressed (`policyId`), include sorted signer allow-lists with status + optional validity windows, and verify key bytes against declared digests;
  - apply-time provenance rejects missing, mismatched or unlinked transfer/scan chains for air-gapped policy bundles, and rejects non-passed/unsigned/untrusted/revoked/expired gate results when configured;
  - deployment receipts now carry optional `transferReceiptIds`, `scanReceiptIds`, `airgapGateResultId`, and `airgapGateTrustPolicyId` provenance bindings;
  - separate command paths:
    - `deployment apply kubernetes`,
    - `deployment retire kubernetes`,
    - `deployment rollback kubernetes`,
    - `integration component-smoke`,
    - `integration topology-end-to-end`,
    - `promotion review record`,
    - `artifact transfer record`,
    - `artifact scan record`,
    - `airgap provenance-gate evaluate`,
    - `airgap provenance-gate verify`,
    - `airgap-gate-trust-policy validate`.
- **Validated on live environment (historical evidence already present):**
  - one successful authorized apply with receipt `sha256:e584d749052c4b389e9013745337d76ccf02862d5fda900eec6c90c8d634944f`;
  - one separately reviewed idempotent apply with 12 no-op operations and receipt `sha256:caa1d717287be833152da68101dc61a52ad0bac54509132413e93adab79c7e7d`.
- **Validated in this run (simulated/local only):**
  - `gofmt -w <changed-go-files>` passed;
  - `git diff --check` passed;
  - `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check` passed;
  - `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...` passed.

## Current branch and working tree

- Branch: `main` tracking `origin/main` (local ahead by two committed slices before this uncommitted work).
- Recent commits before this slice (newest first): `3539f29`, `8a4a7a9`, `00671cb`, `a266358`, `b0a2ce0`.
- This slice adds trust-policy-driven multi-key gate verification (new resource/schema, verify/apply trust-policy enforcement, receipt/audit bindings) with aligned tests/docs.
- Working tree is expected to be clean after committing this slice.
- Required git author for this stream remains: `Maurice Berentsen <mauriceberentsen@live.nl>`.

## Open limitations and unproven claims

- No live validation was executed for rollback, integration execution, promotion-review recording, transfer/scan receipt enforcement, or trust-policy gate verification/enforcement in this run.
- Air-gap completeness remains unproven end-to-end: acquisition execution, transfer medium attestation trust chain, and scanning attestations remain external.
- Clean-cluster bootstrap (namespace/PVC/storage provisioning) remains out of scope.
- Integration execution remains bounded to catalog/target contract checks and does not prove latency, throughput, availability, or production readiness.

## Next implementation slice

Implement **audited trust-policy recording workflow**:

- add `airgap gate-trust-policy record` to generate immutable, content-addressed trust-policy resources from explicit signer inputs and persist dedicated audit chains;
- require verify/apply trust-policy consumption paths to bind to operator-confirmed `policyId` (explicit confirmation flag) so accidental policy drift fails closed;
- keep gate-evaluation signing authority independent from deployment authorization keys while preserving deterministic, content-addressed evidence;
- preserve non-secret durable evidence boundaries (no raw scanner logs, payloads, secrets, kubeconfig, or host addresses).

Acceptance criteria:

- recorded trust policies are deterministic, content-addressed resources with immutable signer identity/digest/status evidence;
- durable receipts/audit prove deterministic gate evaluation plus trust-policy-based signature verification evidence and explicit policy confirmation;
- apply-side provenance accepts only valid, trusted, non-expired signed gate results under confirmed trust policy and otherwise fails closed;
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
