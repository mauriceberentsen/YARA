# Cursor handoff

## Current repository state

- Repository: `YARA` on branch `main` (tracking `origin/main`).
- Scope baseline remains ADRs `0001`-`0011`; bounded direct Kubernetes executor remains ADR-0011.
- First pre-alpha tag is published: `v0.1.0-alpha.1`.
- Recent commits (newest first): `b1c3ef0`, `204b6ba`, `0359114`, `c96f21b`, `3695a18`.
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
- Runtime drift policy gating is now implemented as a read-only fail-closed decision path:
  - `catalog coverage runtime-drift-policy` evaluates `runtimeDriftPosture` for all assertions or one selected assertion;
  - assertion-scoped checks fail with infeasible exit when posture is `missing` or `drifted`;
  - malformed/incomplete posture records fail closed before policy output.
- Web UI backend foundation (W1) is now implemented as a bounded local read-only HTTP API:
  - `yara serve --catalog <file> --coverage-report <file> [--port <port>]` starts a local `net/http` server;
  - read-only endpoints exposed: `/api/v1/catalog`, `/api/v1/assertions`, `/api/v1/coverage`, `/api/v1/drift-posture`, `/api/v1/lifecycle-policy`;
  - unknown routes and unsupported methods fail closed with structured `404` diagnostics and no mutation surface.
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
- **Runtime drift policy gate verification:** dedicated policy command emits deterministic blocker/remediation output, produces auditable pass/fail responses, and enforces assertion-scoped infeasible exits for non-`in-sync` posture.
- **Web UI API verification (simulated/local):** endpoint tests validate deterministic read responses from real catalog/coverage fixtures and fail-closed handling for unknown routes and non-read methods.

## Current branch and working tree

- Branch: `main` tracking `origin/main`.
- Tag: `v0.1.0-alpha.1` exists on origin and release workflow succeeded.
- This slice completed:
  - new `yara serve` command with bounded local read-only API surface and configurable `--catalog` / `--coverage-report` / `--port`;
  - strict read-only API routes for catalog snapshot, assertion list, coverage report, runtime drift posture, and lifecycle publication policy blockers;
  - fail-closed `404` responses for unknown routes and unsupported methods;
  - endpoint tests over real catalog/coverage fixtures;
  - command reference updates.
- Working tree should be clean after committing this slice.
- Required git author for this stream: `Maurice Berentsen <mauriceberentsen@live.nl>`.

## MVP milestone path

- M1 Publication gating closure — completed.
- M2 Artifact import receipt chain — completed.
- M3 Bootstrap and first-use path — completed.
- M4 CI and binary release — completed.
- M5 Public documentation and honest scope statement — completed.

## Open limitations and unproven claims

- No live cluster validation was executed in this run for rollback/integration/promotion/lifecycle publication paths; this run validated release publication and artifacts only.
- Air-gap external trust chain (acquisition execution, transfer-medium attestation chain, external scanner attestations) remains outside YARA proof boundary.
- Bootstrap remains intentionally narrow (single YARA-owned namespace + model PVC); full cluster install/orchestration is deferred.
- Web UI remains local-only and read-only in this stage (no auth, no multi-user/session model, no mutation endpoints).
- Backup/restore, upgrades, multi-node topology, and broader vendor support remain post-alpha.

## MVP-2 milestone path — Web UI

Goal: a minimal browser-based operator interface that surfaces existing CLI capabilities without weakening any existing gates or mutation controls.

### W1 — Backend HTTP API layer

- Expose a bounded, read-mostly local HTTP server (`yara serve`) backed by the existing resource/catalog/coverage packages.
- Endpoints: catalog snapshot, assertion list, coverage report (read), runtime drift posture, lifecycle publication policy status.
- No write/mutation endpoints in this milestone; fail closed on any unrecognised route.
- Exit criteria: `yara serve` starts on a configurable local port, responds to documented read endpoints with valid JSON, and exits cleanly on signal; unit + integration tests pass.

### W2 — Minimal dashboard shell

- Implement a single-page app shell (React + Vite) served by `yara serve` from an embedded filesystem.
- Top-level nav: Catalog, Coverage, Drift, Lifecycle.
- Each view fetches from W1 API endpoints and renders assertion-scoped status rows.
- No mutation controls in the UI in this milestone.
- Exit criteria: `yara serve --ui` opens the shell in a browser; each nav view loads and renders real catalog/coverage data without errors.

### W3 — Runtime drift posture view

- Implement the Drift view with per-assertion posture cards (in-sync / missing / drifted), blocker/remediation display, and audit trail link.
- Assertion-scoped filter maps directly to `catalog coverage runtime-drift-policy --assertion`.
- Exit criteria: Drift view correctly reflects `missing` posture for all assertions in a fresh catalog, and switches to `in-sync` after a valid `RuntimeDriftSignal` is imported via CLI and coverage report is refreshed.

### W4 — Lifecycle publication readiness view

- Implement the Lifecycle view with per-assertion four-pillar status indicators.
- Display blocker codes and remediation hints from `lifecycle-publication-policy` output.
- Exit criteria: Lifecycle view correctly displays blocked/unblocked state per assertion; state updates on coverage report reload.

### W5 — Web UI release and public documentation

- Bundle and embed the built UI into the binary via Go embed; no separate build artefact required at runtime.
- Update `README.md`, `docs/quickstart.md`, and `docs/reference/commands.md` to document `yara serve` and the web UI.
- Publish `v0.2.0-alpha.1` with all W1–W4 capabilities and honest scope statement (read-only, local-only, no auth in pre-alpha).
- Exit criteria: `gh release download v0.2.0-alpha.1` yields a binary where `yara serve` boots the UI with catalog and coverage data.

## Next implementation slice

Implement **W2 — Minimal dashboard shell**:

- add a minimal React + Vite single-page shell under an embedded static directory served by `yara serve`;
- include four top-level views: Catalog, Coverage, Drift, Lifecycle;
- wire each view to existing W1 endpoints only (read-only) with deterministic empty/error states;
- keep CLI and API behavior unchanged: UI must not introduce mutation authority;
- add deterministic frontend build/test checks wired into repository validation flow.

Acceptance criteria:

- `yara serve --ui` serves the embedded shell and all four views render from live API responses without JavaScript runtime errors;
- each view handles empty or blocked policy states without changing backend responses;
- no mutation authority is added and no existing CLI gates are weakened;
- backend and frontend checks both pass in `make check` and `go test -race ./...` (frontend checks classified simulated/local).

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
