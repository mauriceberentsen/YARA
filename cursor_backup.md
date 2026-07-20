# Cursor handoff

## Current repository state

- Repository: `YARA` on branch `main` (tracking `origin/main`).
- Scope baseline remains ADRs `0001`-`0011`; bounded direct Kubernetes executor remains ADR-0011.
- First pre-alpha tag is published: `v0.1.0-alpha.1`.
- Recent commits (newest first): `3695a18`, `88a4f9b`, `0118b61`, `6c5fe38`, `d9b12f8`.
- Public schema surface includes deployment, approval, lifecycle-proof, integration-publication, publication-chain, bootstrap, and air-gap provenance contracts under `schemas/yara.dev/v1alpha1`.

## Current product boundary

- Deterministic plan/render + read-only preflight/change-set + review-first approval + short-lived authorization + bounded apply/retire/rollback execution are implemented.
- Air-gap provenance chain is implemented as immutable receipts/gates (import, transfer, scan, gate result, trust policy, trust policy diff, transition review) and bound into apply-time validation.
- Lifecycle publication readiness for integration-required assertions is fail-closed and requires all four pillars:
  - lifecycle proof approval;
  - integration publication attestation;
  - publication-chain rehearsal;
  - publication-chain renewal review.
- `catalog coverage create` and `catalog coverage lifecycle-publication-policy` expose deterministic assertion-scoped blocker/remediation diagnostics and fail-closed parity checks.
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

## Current branch and working tree

- Branch: `main` tracking `origin/main`.
- Tag: `v0.1.0-alpha.1` exists on origin and release workflow succeeded.
- Working tree currently contains this slice changes:
  - finalized `.github/release-notes/v0.1.0-alpha.1.md` with published digests;
  - `.github/workflows/release.yml` updated to apply canonical release notes body;
  - this handoff rewrite.
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

Implement **Post-MVP slice: runtime-manager drift signal contract (read-only)**:

- define a deterministic, non-mutating runtime drift signal resource + schema for observed-vs-expected runtime state;
- add bounded CLI emission/validation path that cannot mutate targets and binds drift signal identity to existing target/preflight evidence;
- add coverage diagnostics wiring so drift posture is visible without altering publication/apply authority.

Acceptance criteria:

- new drift signal schema validates with draft-2020-12 and Go validators;
- CLI path emits content-addressed drift signal evidence with deterministic ordering/identity;
- negative tests fail closed on stale/foreign target evidence and malformed drift payloads;
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
