# Cursor handoff

## Current repository state

- Repository: `YARA` on branch `main` (tracking `origin/main`).
- Scope baseline remains ADRs `0001`-`0011`; bounded direct Kubernetes executor remains ADR-0011.
- First pre-alpha tag is published: `v0.1.0-alpha.1`.
- Recent commits (newest first): `9d2c86a`, `eb0be72`, `3438071`, `2c15d1d`, `b1c3ef0`.
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
- Web UI shell (W2) is now implemented as an embedded React + Vite SPA served by `yara serve --ui`:
  - top-level views: Catalog, Coverage, Drift, Lifecycle;
  - each view fetches existing W1 read-only endpoints with deterministic loading/empty/error states;
  - no mutation endpoints or mutation controls are exposed in the UI.
- Runtime drift posture view (W3) is now implemented as a dedicated read-only drift interface:
  - assertion-scoped filtering is supported via `/api/v1/drift-posture?assertion=<id>`;
  - drift posture cards render deterministic status, blocker, remediation, selected signal, and audit reference fields;
  - malformed/unsupported posture payloads fail closed in UI with non-destructive error rendering.
- Lifecycle publication readiness view (W4) is now implemented as a dedicated read-only lifecycle interface:
  - assertion-scoped filtering is supported via `/api/v1/lifecycle-policy?assertion=<id>`;
  - lifecycle rows render deterministic four-pillar statuses (proof, integration, rehearsal, renewal) plus blocker code/remediation;
  - malformed/inconsistent lifecycle payloads fail closed in UI with non-destructive error rendering.
- Web UI release and documentation slice (W5) is now implemented:
  - release workflow now references `.github/release-notes/v0.2.0-alpha.1.md` for canonical publication notes;
  - docs + release notes now align on Web UI startup and local-only/read-only pre-alpha scope.
- Bootstrap + first-use path is implemented:
  - `deployment bootstrap kubernetes` (bounded namespace/PVC provisioning with `BootstrapReceipt`);
  - `deployment import kubernetes` (bounded single-model local staging into bootstrap PVC with `ArtifactImportReceipt`).
- CI and release automation is implemented:
  - CI gates on PR/push: `make check`, `go test -race ./...`, schema draft-2020-12 validation, `git diff --check`;
  - release builds `linux/amd64`, `linux/arm64`, `darwin/arm64` binaries, publishes `checksums.txt`, and attaches deterministic `yara-schemas-v1alpha1.tar.gz`.

## Verified capabilities

- **Local/simulated verification:** Go/unit/CLI/schema tests prove deterministic IDs, fail-closed stale/foreign/mismatch paths, and bounded mutation authority.
- **Pre-alpha docs clarity:** `README.md`, `docs/quickstart.md`, `docs/reference/commands.md`, and `docs/architecture/README.md` separate implemented behavior from deferred roadmap scope.
- **Runtime drift contract verification:** new schema/resource/CLI/catalog-coverage wiring validates deterministic IDs, stale/foreign preflight rejection, audited target binding, and fail-closed malformed diagnostics parsing.
- **Runtime drift policy gate verification:** dedicated policy command emits deterministic blocker/remediation output, produces auditable pass/fail responses, and enforces assertion-scoped infeasible exits for non-`in-sync` posture.
- **Web UI API verification (simulated/local):** endpoint tests validate deterministic read responses from real catalog/coverage fixtures and fail-closed handling for unknown routes and non-read methods.
- **Web UI drift posture verification (simulated/local):** tests cover assertion-scoped filter success/failure, payload validation failures, deterministic rendering order, and status-to-remediation mapping.
- **Web UI lifecycle readiness verification (simulated/local):** tests cover lifecycle assertion filtering, deterministic four-pillar rendering, taxonomy/scope metadata display, and malformed payload fail-closed behavior.

## Current branch and working tree

- Branch: `main` tracking `origin/main`.
- This slice completed:
  - release workflow/template and top-level docs now align on Web UI startup and corrected scope (implemented local read-only UI, deferred team API/auth/mutations);
  - release notes template now documents W1-W4 behavior, known limitations, and support boundary for `v0.2.0-alpha.1`;
  - built-binary smoke test confirmed `yara serve --ui` serves `index.html` and `/api/v1/lifecycle-policy`.
- Validation (simulated/local) passed:
  - built binary smoke check (`go build` + `catalog coverage create` + `serve --ui` + `curl` UI + `curl` lifecycle endpoint) succeeded.
  - `git diff --check`, `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check`, and `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...`.
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

## MVP-2 milestone path — Web UI

### W1 — Backend HTTP API layer

- Bounded local read-only HTTP server and policy endpoints.
- Status: completed.

### W2 — Minimal dashboard shell

- Embedded React + Vite shell with Catalog/Coverage/Drift/Lifecycle views over W1 endpoints.
- Status: completed.

### W3 — Runtime drift posture view

- Drift cards + assertion-scoped filtering + fail-closed payload handling.
- Status: completed.

### W4 — Lifecycle publication readiness view

- Lifecycle table + assertion-scoped filtering + fail-closed payload handling.
- Status: completed.

### W5 — Web UI release and public documentation

- Release notes template + workflow + docs alignment for Web UI publication.
- Status: completed.

## Next implementation slice

Implement **Post-MVP-2 slice — Web UI read-only auth boundary (fail-closed)**:

- add optional local auth token requirement for `yara serve` API/UI access (disabled by default, explicit opt-in flag);
- enforce fail-closed `401` responses for missing/invalid tokens across all `/api/v1/*` endpoints;
- keep mutation authority absent and preserve deterministic response schemas for authorized reads;
- update docs/reference with explicit local-auth threat model limits (still single-user local pre-alpha).

Acceptance criteria:

- opt-in auth mode blocks unauthenticated reads and admits only exact-token requests;
- UI shell can load successfully when token is present and fail closed otherwise;
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
