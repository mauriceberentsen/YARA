# Cursor handoff

## Current repository state

- Repository: `YARA` (audit-first deterministic planner plus bounded deployment path).
- Branch baseline: `main` with local commits ahead of `origin/main`.
- Current run state: local `main` is ahead of `origin/main` with unpushed commits.
- Accepted ADRs include `0001`-`0011`; direct apply boundary is in ADR-0011.
- Latest archived coverage remains `catalog/v0.2/coverage.yaml` with report ID `sha256:b1f2379eb930d431b2cbe1543ec38fb243580213c76ca56be96def47883beb83`.

## Current product boundary

- Implemented boundary is still narrow and fail-closed:
  - deterministic offline planning and rendering;
  - read-only Kubernetes preflight and change-set observation;
  - review-only approval plus short-lived signed execution authorization;
  - direct Kubernetes apply for the exact rendered LiteLLM-vLLM bundle only;
  - separate signed delete-only retirement path for owned rendered resources.
- Apply requires pre-existing owned namespace and bound `yara-model` PVC.
- Apply supports only authorized `create`/`update`/`no-op`; namespace must be exact `no-op`.
- Apply still has no implicit delete, prune, adoption, rollback, bootstrap provisioning, or model import path.

## Verified capabilities

- **Implemented + locally validated (tests/docs/schemas in repo):**
  - strict content-addressed resources and schemas for bundle, preflight, change set, approval, authorization, receipt;
  - fail-closed audit chains with durable `deployment.apply.started` before mutation;
  - lock-and-recheck executor ordering and stale/foreign-state rejection before apply;
  - verifier Pod hardened profile and explicit `/usr/bin/python3` entrypoint;
  - deterministic normalization updates for Kubernetes 1.35 server defaults;
  - vLLM writable cache redirection while keeping read-only root and model mount separation.
  - new strict `ArtifactImportReceipt` resource/schema/validation command and fail-closed binding into `deployment apply kubernetes`;
  - apply now requires `--import-receipt`, verifies exact plan/bundle/target/model-file bindings before mutation, and binds `importReceiptId` into `DeploymentReceipt` and apply audit subjects.
  - `authorization issue-retirement` issues delete-only signed constraints from a fresh exact owned no-op baseline;
  - `deployment retire kubernetes` performs lock-scoped fail-closed owned deletion with `RetirementReceipt` evidence and dedicated retirement audit actions.
- **Validated on live environment (documented controlled run in this handoff history):**
  - one successful authorized Kubernetes apply with receipt `sha256:e584d749052c4b389e9013745337d76ccf02862d5fda900eec6c90c8d634944f`;
  - one separately reviewed idempotency apply with 12 no-op operations and receipt `sha256:caa1d717287be833152da68101dc61a52ad0bac54509132413e93adab79c7e7d`.
- **Archived operational evidence in repo (contract scope):**
  - GB10 Qwen Coder and Qwen3 sustained-capacity passes:
    - `sha256:5387ae8f8e8a7869f15ae0285012f3de7f37136e86bebf7969261e70e369b65f`
    - `sha256:825cca84c847f1f65deb6dbe3c5f4eb30b8f75814ecba0f30e6dc414268357dd`
  - coverage still blocks promotion on independent review and integration gates.
- **Validated in this run (local/simulated only):**
  - `gofmt -w <changed-go-files>` passed;
  - `git diff --check` passed;
  - `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check` passed;
  - `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...` passed.

## Current branch and working tree

- Branch: `main` tracking `origin/main` with local commits ahead.
- Recent commits at run start (newest first): `fe846fb`, `a77fccf`, `8ae7502`, `08f774e`, `cc1f0a5`.
- Working tree must be verified at session start with `git status --short --branch`; keep unrelated changes out of slice commits.
- Git author to use for new commit: `Maurice Berentsen <mauriceberentsen@live.nl>`.

## Open limitations and unproven claims

- Air-gap completeness is still unproven: import execution, transfer chain-of-custody and scanning attestations remain external to apply.
- Clean-cluster bootstrap (namespace/PVC/storage provisioning) is out of scope.
- Safe owned retirement is implemented; rollback primitives remain unimplemented.
- Integration execution evidence (`component-smoke` / `topology-end-to-end`) remains unimplemented; only validation contract exists.
- Independent promotion review is still missing for promotion eligibility.

## Next implementation slice

Implement **safe separately authorized rollback primitives**:

- Add a distinct rollback command/contract (not apply, not retirement) that can restore a reviewed prior owned state from explicit immutable inputs.
- Require fresh preflight/change-set/review/signed authorization constraints specific to rollback scope and operation count.
- Keep rollback explicit and bounded; never add implicit prune/adoption and never infer prior desired state from live drift.

Acceptance criteria for this slice:

- rollback fails closed when ownership, target identity, or approved rollback set drifts;
- durable receipt/audit prove exactly what was reverted and what was skipped/blocked;
- no secret material, raw object bodies, kubeconfig/context/raw target address in durable evidence;
- schema validation and Go validation stay aligned;
- determinism: identical rollback inputs produce identical operation ordering/evidence identities.

## Validation requirements

Run at minimum after implementation:

```bash
gofmt -w <changed-go-files>
git diff --check
GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check
GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...
```

Additional required coverage for this slice:

- focused unit tests for the rollback contract and ownership constraints;
- negative validation tests (foreign ownership, stale state, unauthorized rollback set);
- determinism tests for receipt identity and operation ordering;
- CLI tests for changed command behavior and authorization mismatch paths;
- fail-closed mutation tests proving no delete occurs when audit/receipt preconditions fail.

Validation classification rules:

- mark as **simulated/local** for unit/CLI/fake-kubectl tests;
- mark as **live** only for actually executed cluster runs;
- do not claim new live validation unless this run performs it.

## Publishing requirements

- Review full diff for scope coherence; exclude unrelated files.
- Ensure no secrets, private keys, kubeconfig content, raw target addresses, prompts/completions, env vars, raw logs, or Kubernetes object bodies are introduced in durable evidence.
- Ensure `.yara/` artifacts remain unstaged.
- Ensure docs, schemas, and Go validation remain consistent.
- Update this handoff again after implementation with:
  - completed slice outcome;
  - actual branch + commit state;
  - exact validation commands that passed;
  - simulated/local/live distinction;
  - one new recommended next slice.
- Commit with author `Maurice Berentsen <mauriceberentsen@live.nl>`.
- Do not merge or push unless explicitly authorized by current repo policy and access context.
