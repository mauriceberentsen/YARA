# Cursor handoff

## Current repository state

- Repository: `YARA` (audit-first deterministic planner with bounded lifecycle execution).
- Branch baseline before this slice: `main` at `75da913` (`Refresh handoff after integration executor commit.`).
- ADR scope remains `0001`-`0011`; direct fail-closed Kubernetes mutation boundary remains ADR-0011.
- Public resource schema set now includes `PromotionReview` (`schemas/yara.dev/v1alpha1/promotion-review.schema.json`).
- Coverage gate `independent-promotion-review` is now evaluable from immutable review evidence, not permanently missing-only.
- Latest archived catalog coverage artifact remains `catalog/v0.2/coverage.yaml` with report ID `sha256:b1f2379eb930d431b2cbe1543ec38fb243580213c76ca56be96def47883beb83` (historical snapshot; new logic can evaluate promotion reviews when provided).

## Current product boundary

- Implemented lifecycle chain is now:
  - deterministic plan/render;
  - read-only Kubernetes preflight and change-set;
  - review-only approval;
  - short-lived signed authorization;
  - separate bounded executor commands for apply, retirement, rollback, and integration evidence execution.
- Promotion governance now includes a separate immutable review record path:
  - `promotion review record` emits a content-addressed `PromotionReview` plus two-event audit evidence;
  - catalog coverage compilation binds those reviews into assertion-level `independent-promotion-review` gate outcomes.
- Apply remains explicit and bounded to exact rendered objects; it does not implicitly delete/prune/adopt.
- Retirement remains separate delete-only authority with exact owned no-op baseline requirements.
- Rollback remains separate non-delete authority bound to exact reviewed rollback actions and operation count.
- Integration execution now has explicit `component-smoke` and `topology-end-to-end` commands that emit content-addressed `IntegrationTestResult` resources and two-event execution audits.
- Mutating lifecycle commands still require durable started audit before mutation and fail closed when receipt/audit persistence cannot complete.

## Verified capabilities

- **Implemented + locally validated in repository tests/schemas/docs:**
  - content-addressed resources and schema/Go validation for apply (`DeploymentReceipt`), import (`ArtifactImportReceipt`), retirement (`RetirementReceipt`), rollback (`RollbackReceipt`), integration (`IntegrationTestResult`), and promotion review (`PromotionReview`);
  - separate authorization issuance paths:
    - `authorization issue` (apply profile),
    - `authorization issue-retirement` (delete-only),
    - `authorization issue-rollback` (non-delete rollback profile);
  - separate executor command paths:
    - `deployment apply kubernetes`,
    - `deployment retire kubernetes`,
    - `deployment rollback kubernetes`,
    - `integration component-smoke`,
    - `integration topology-end-to-end`;
    - `promotion review record`;
  - rollback lock-and-recheck execution with stale/foreign-state rejection before object mutation;
  - integration execution emits coverage-compatible terminal actions (`integration.component-smoke.*`, `integration.topology-end-to-end.*`) with pseudonymized target identities and deterministic check ordering;
  - coverage compiler now accepts verified adjacent promotion-review audit chains and deterministically resolves `independent-promotion-review` to `passed`, `failed`, `blocked`, or `missing` based on latest review evidence.
- **Validated on live environment (historical evidence already present):**
  - one successful authorized apply with receipt `sha256:e584d749052c4b389e9013745337d76ccf02862d5fda900eec6c90c8d634944f`;
  - one separately reviewed idempotent apply with 12 no-op operations and receipt `sha256:caa1d717287be833152da68101dc61a52ad0bac54509132413e93adab79c7e7d`.
- **Validated in this run (simulated/local only):**
  - `gofmt -w <changed-go-files>` passed;
  - `git diff --check` passed;
  - `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check` passed;
  - `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...` passed.

## Current branch and working tree

- Branch: `main` tracking `origin/main`.
- Recent commits before this slice (newest first): `75da913`, `ce5b80d`, `3bde317`, `272e99e`, `0c5e134`.
- This slice adds promotion-review resource/CLI/coverage binding and related tests/docs as one coherent vertical change.
- Working tree is expected to be clean after committing this slice.
- Required git author for this stream remains: `Maurice Berentsen <mauriceberentsen@live.nl>`.

## Open limitations and unproven claims

- No live validation was executed for rollback, integration execution, or promotion-review recording in this run; all remain proven only through local/simulated tests.
- Air-gap completeness remains unproven: import execution, transfer chain-of-custody, and scanning attestations remain external.
- Clean-cluster bootstrap (namespace/PVC/storage provisioning) remains out of scope.
- Integration execution is currently bounded to catalog/target contract checks and does not prove latency, throughput, availability, or production readiness.

## Next implementation slice

Implement **artifact transfer chain-of-custody receipts for air-gap completeness**:

- add an explicit immutable receipt resource and CLI path for offline transfer stages between import and deployment contexts;
- bind transfer receipts to exact artifact digest identities plus source/destination attestation references without exposing secrets or raw host addresses;
- require apply-time artifact provenance to include the transfer receipt chain when policy marks the path as air-gapped;
- preserve separation between transfer evidence authority and mutation authority.

Acceptance criteria:

- transfer receipts can only reference immutable artifact and prior-receipt identities;
- durable receipts/audit prove transfer step completion and bounded operator context without secrets;
- apply-side provenance validation deterministically rejects incomplete or inconsistent transfer chains;
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
