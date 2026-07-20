# Cursor handoff

## Current repository state

- Repository: `YARA` on branch `main` (tracking `origin/main`).
- Scope baseline remains ADRs `0001`-`0011`; bounded direct Kubernetes executor remains ADR-0011.
- First pre-alpha tag is published: `v0.1.0-alpha.1`.
- Recent commits (newest first): `0359114`, `c96f21b`, `3695a18`, `88a4f9b`, `0118b61`.
- Public schema surface includes deployment, approval, lifecycle-proof, integration-publication, publication-chain, bootstrap, air-gap provenance, and runtime drift contracts under `schemas/yara.dev/v1alpha1`.

## Current product boundary

- Deterministic plan/render + read-only preflight/change-set + review-first approval + short-lived authorization + bounded apply/retire/rollback execution are implemented.
- Air-gap provenance chain is implemented as immutable receipts/gates (import, transfer, scan, gate result, trust policy, trust policy diff, transition review) and bound into apply-time validation.
- Lifecycle publication readiness for integration-required assertions is fail-closed and requires all four pillars:
  - lifecycle proof approval;
  - integration publication attestation;
  - publication-chain rehearsal;
  - publication-chain renewal review.
- `catalog coverage create` and `catalog coverage lifecycle-publication-policy` expose deterministic assertion-scoped blocker/remediation diagnostics and fail-closed parity checks.
- Runtime drift signaling is now implemented as a read-only evidence contract:
  - `runtime drift-signal record` emits immutable `RuntimeDriftSignal` resources bound to catalog/assertion/runtime/bundle/preflight/target identities;
  - `runtime-drift-signal validate` enforces schema + deterministic identity checks;
  - catalog coverage responses now expose assertion-scoped `runtimeDriftPosture` diagnostics derived from deterministic limitation records.
- Bootstrap + first-use path is implemented:
  - `deployment bootstrap kubernetes` (bounded namespace/PVC provisioning with `BootstrapReceipt`);
  - `deployment import kubernetes` (bounded single-model local staging into bootstrap PVC with `ArtifactImportReceipt`).
- CI and release automation is implemented:
  - CI gates on PR/push: `make check`, `go test -race ./...`, schema draft-2020-12 validation, `git diff --check`;
  - release builds `linux/amd64`, `linux/arm64`, `darwin/arm64` binaries, publishes `checksums.txt`, and attaches deterministic `yara-schemas-v1alpha1.tar.gz`.

## Verified capabilities

- **Local/simulated verification:** Go/unit/CLI/schema tests prove deterministic IDs, fail-closed stale/foreign/mismatch paths, and bounded mutation authority.
- **Published release verification:** `v0.1.0-alpha.1` assets are downloadable and checksum-verifiable via `gh release download` and `shasum -a 256 -c checksums.txt`.
- **Canonical release notes enforcement:** tag publish flow now applies repository-owned notes template to release body after GoReleaser upload.
- **Pre-alpha docs clarity:** `README.md`, `docs/quickstart.md`, `docs/reference/commands.md`, and `docs/architecture/README.md` separate implemented behavior from deferred roadmap scope.
- **Runtime drift contract verification:** new schema/resource/CLI/catalog-coverage wiring validates deterministic IDs, stale/foreign preflight rejection, audited target binding, and fail-closed malformed diagnostics parsing.

## Current branch and working tree

- Branch: `main` tracking `origin/main`.
- Tag: `v0.1.0-alpha.1` exists on origin and release workflow succeeded.
- This slice completed:
  - new `RuntimeDriftSignal` resource + schema + validators/tests;
  - new `runtime drift-signal record` command and `runtime-drift-signal validate` path;
  - catalog coverage runtime drift posture diagnostics wiring and tests;
  - command reference updates.
- Working tree should be clean after committing this slice.
- Required git author for this stream: `Maurice Berentsen <mauriceberentsen@live.nl>`.

## MVP milestone path

### M1 — Publication gating closure

- Completed.
- Exit satisfied: lifecycle publication readiness enforces the full four-pillar chain for integration-required assertions.

### M2 — Artifact import receipt chain

- Completed.
- Exit satisfied: acquisition-to-deployment artifact chain has immutable receipt coverage at each handoff.

### M3 — Bootstrap and first-use path

- Completed.
- Exit satisfied: fresh-operator documented path exists from planning through apply receipt validation.

### M4 — CI and binary release

- Completed.
- Exit satisfied:
  - CI blocks breaking merges;
  - `gh release download v0.1.0-alpha.1` yields working release artifacts with verified checksums.

### M5 — Public documentation and honest scope statement

- Completed.
- Exit satisfied: implemented versus deferred scope is explicit across top-level docs.

## Open limitations and unproven claims

- No live cluster validation was executed in this run for rollback/integration/promotion/lifecycle publication paths; this run validated release publication and artifacts only.
- Air-gap external trust chain (acquisition execution, transfer-medium attestation chain, external scanner attestations) remains outside YARA proof boundary.
- Bootstrap remains intentionally narrow (single YARA-owned namespace + model PVC); full cluster install/orchestration is deferred.
- Team API, web UI, runtime manager/drift detection, backup/restore, upgrades, multi-node topology, and broader vendor support remain post-MVP.

## Next implementation slice

Implement **Post-MVP slice: runtime drift policy gate command (read-only fail-closed)**:

- add a dedicated policy command that evaluates `runtimeDriftPosture` from a coverage report for all assertions or one selected assertion;
- fail closed when posture records are missing, malformed, duplicated, or inconsistent with assertion scope;
- return deterministic remediation for drifted assertions without adding deployment/publication mutation authority.

Acceptance criteria:

- command emits deterministic assertion-scoped pass/fail policy diagnostics from coverage report only;
- single-assertion mode fails with infeasible exit when selected assertion posture is `drifted` or `missing`;
- malformed runtime drift limitation records fail closed as internal errors;
- no mutation authority is added and no existing lifecycle/publication gates are weakened.

## Validation requirements

Run at minimum for each slice:

```bash
gofmt -w <changed-go-files>
git diff --check
GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check
GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...
```

Classification rules:

- mark unit/CLI/fake-runner/schema/doc checks as **simulated/local**;
- mark as **live** only when actual cluster execution occurs in-session;
- do not promote simulated/local checks to live claims.

## Publishing requirements

- Keep `.yara/`, generated release output directories, and machine-local artifacts unstaged.
- Do not commit secrets/private keys/kubeconfig/raw target addresses/prompts/completions/env vars/raw logs/raw object bodies.
- Keep docs, schemas, CLI behavior, and Go validation in sync.
- Each completed slice must update this handoff with:
  - current branch/commit/tag reality;
  - exact validation commands and outcomes;
  - explicit simulated/local/live distinction;
  - exactly one next recommended slice.
