# Cursor handoff

## Current repository state

- Repository: `YARA` (audit-first deterministic planner with bounded lifecycle execution).
- Branch baseline: `main` at `272e99e` (`Add separately authorized Kubernetes rollback path.`).
- Local state: `main` is ahead of `origin/main` by three commits (`a77fccf`, `8746cdf`, `272e99e`).
- ADR scope remains `0001`-`0011`; direct fail-closed Kubernetes mutation boundary remains ADR-0011.
- Latest archived catalog coverage remains `catalog/v0.2/coverage.yaml` with report ID `sha256:b1f2379eb930d431b2cbe1543ec38fb243580213c76ca56be96def47883beb83`.

## Current product boundary

- Implemented lifecycle chain is now:
  - deterministic plan/render;
  - read-only Kubernetes preflight and change-set;
  - review-only approval;
  - short-lived signed authorization;
  - separate bounded executor commands for apply, retirement, and rollback.
- Apply remains explicit and bounded to exact rendered objects; it does not implicitly delete/prune/adopt.
- Retirement remains separate delete-only authority with exact owned no-op baseline requirements.
- Rollback is now a separate non-delete authority and command, bound to exact reviewed rollback actions and operation count.
- All three mutating commands require durable started audit before mutation and fail closed when receipt/audit persistence cannot complete.

## Verified capabilities

- **Implemented + locally validated in repository tests/schemas/docs:**
  - content-addressed resources and schema/Go validation for apply (`DeploymentReceipt`), import (`ArtifactImportReceipt`), retirement (`RetirementReceipt`), and rollback (`RollbackReceipt`);
  - separate authorization issuance paths:
    - `authorization issue` (apply profile),
    - `authorization issue-retirement` (delete-only),
    - `authorization issue-rollback` (non-delete rollback profile);
  - separate executor command paths:
    - `deployment apply kubernetes`,
    - `deployment retire kubernetes`,
    - `deployment rollback kubernetes`;
  - rollback lock-and-recheck execution with stale/foreign-state rejection before object mutation;
  - rollback durable evidence path with sorted deterministic operation ordering and stable diagnostics.
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
- Recent commits (newest first): `272e99e`, `0c5e134`, `8746cdf`, `fe846fb`, `a77fccf`.
- Working tree is clean after the rollback slice commit.
- Required git author for this stream remains: `Maurice Berentsen <mauriceberentsen@live.nl>`.

## Open limitations and unproven claims

- No new live rollback validation was executed in this run; rollback is proven only through local/simulated tests.
- Air-gap completeness remains unproven: import execution, transfer chain-of-custody, and scanning attestations remain external.
- Clean-cluster bootstrap (namespace/PVC/storage provisioning) remains out of scope.
- Integration execution evidence (`component-smoke` and `topology-end-to-end`) remains unimplemented.
- Independent promotion review gate remains unresolved for promotion eligibility.

## Next implementation slice

Implement **generic integration executor for the bounded LiteLLM-to-vLLM topology**:

- add an explicit non-planner integration execution command path that consumes immutable reviewed inputs;
- emit content-addressed integration execution receipts and audit chains for `component-smoke` and `topology-end-to-end`;
- preserve pseudonymized targets and keep no secrets/raw logs/object bodies in durable evidence;
- fail closed on stale inputs, target drift, or evidence persistence failure;
- keep integration mutation authority narrower than review/observation authority.

Acceptance criteria:

- integration execution can run only from exact reviewed/authorized immutable inputs;
- durable receipts/audit prove what was executed, what was skipped, and why;
- schema validation and Go validation stay aligned and deterministic;
- executor-ordering and stale-state failures are covered by focused tests.

## Validation requirements

Run at minimum for each new slice:

```bash
gofmt -w <changed-go-files>
git diff --check
GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check
GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...
```

Required test depth for mutating lifecycle slices:

- focused unit tests for new resource contracts and validation invariants;
- negative tests for stale/foreign/unauthorized mutation paths;
- determinism tests for content-addressed receipt identities and operation ordering;
- CLI tests for changed command behavior and authorization confirmation mismatch paths;
- fail-closed tests proving no mutation when required audit/receipt preconditions fail.

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
