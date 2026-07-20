# Cursor handoff

## Current repository state

- Repository: `YARA` on branch `main` (tracking `origin/main`).
- Scope baseline remains ADRs `0001`-`0011`; bounded direct Kubernetes executor remains ADR-0011.
- First pre-alpha tag is published: `v0.1.0-alpha.1`.
- Recent commits (newest first): `1c0d65d`, `a16f6e2`, `7d0528d`, `8bba86a`, `534f10e`.
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
- Web UI (MVP-2, W1–W5) is fully implemented as a local-only, read-only embedded React/Vite SPA served by `yara serve --ui`; see MVP-2 milestone path below for detail; `v0.2.0-alpha.1` release notes and docs are aligned.
- Interactive workflow cockpit I1 is implemented:
  - `yara serve --workspace <dir>` and `GET /api/v1/workspace` provide deterministic stage discovery (plan/bundle/preflight/change-set/approval/authorization/receipt);
  - Pipeline view now renders stage status and artifact paths using fail-closed workspace payload validation.
- Interactive workflow cockpit I2 is implemented:
  - `POST /api/v1/workflow/plan` executes bounded `plan create` using explicit request/inventory/catalog/output/audit paths;
  - output and audit artifacts are restricted to the configured workspace and fail closed on invalid or out-of-workspace paths;
  - Plan create UI form now writes plan artifacts and renders deterministic summary metadata in-session.
- Bootstrap + first-use path is implemented (`deployment bootstrap kubernetes` + `deployment import kubernetes`) with bounded namespace/PVC and import receipt enforcement.
- CI and release automation is implemented:
  - CI gates on PR/push: `make check`, `go test -race ./...`, schema draft-2020-12 validation, `git diff --check`;
  - release builds `linux/amd64`, `linux/arm64`, `darwin/arm64` binaries, publishes `checksums.txt`, and attaches deterministic `yara-schemas-v1alpha1.tar.gz`.

## Verified capabilities

- **Local/simulated verification:** Go/unit/CLI/schema tests prove deterministic IDs, fail-closed stale/foreign/mismatch paths, and bounded mutation authority.
- **Pre-alpha docs clarity:** `README.md`, `docs/quickstart.md`, `docs/reference/commands.md`, and `docs/architecture/README.md` separate implemented behavior from deferred roadmap scope.
- **Runtime drift policy gate verification:** dedicated policy command emits deterministic blocker/remediation output, produces auditable pass/fail responses, and enforces assertion-scoped infeasible exits for non-`in-sync` posture.
- **Web UI verification (simulated/local):** endpoint tests cover read endpoints (including workspace pipeline discovery), assertion-scoped drift/lifecycle filtering, payload validation failures, and fail-closed handling.

## Current branch and working tree

- Branch: `main` tracking `origin/main`.
- This slice completed:
  - `POST /api/v1/workflow/plan` endpoint implemented with strict JSON decoding, structured failure responses, and exit-code aware HTTP status mapping;
  - workspace-bounded plan/audit output paths now enforced fail-closed for workflow plan creation;
  - Plan create UI form implemented with no-reload result panel and automatic Pipeline refresh after successful plan creation.
- Validation (simulated/local) passed:
  - `gofmt -w internal/cli/serve.go internal/cli/serve_test.go internal/cli/run.go`;
  - `npm run check --prefix internal/cli/webui`;
  - `git diff --check`, `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check`, and `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...`.
- Required git author for this stream: `Maurice Berentsen <mauriceberentsen@live.nl>`.

## MVP milestone path

- M1–M5 — completed (publication gating, artifact import, bootstrap, CI/release, public documentation).

## Open limitations and unproven claims

- No live cluster validation was executed in this run; run validated release publication and artifacts only.
- Air-gap external trust chain remains outside YARA proof boundary.
- Bootstrap remains intentionally narrow (single YARA-owned namespace + model PVC).
- Web UI remains local-only in this stage (no auth, no multi-user/session); workflow mutation endpoints are not yet implemented.

## MVP-2 milestone path — Web UI

- W1 Backend HTTP API, W2 Dashboard shell, W3 Drift posture view, W4 Lifecycle readiness view, W5 Release/docs — all completed.
- Running the UI: `yara serve --catalog catalog/v0.2/snapshot.yaml --coverage-report .yara/catalog-v0.2-coverage.yaml --ui --port 7474` then open `http://127.0.0.1:7474`.

## MVP-3 milestone path — Interactive Workflow Cockpit

Goal: a browser-based operator cockpit where the complete plan-to-apply rollout workflow can be driven through the UI, with all existing audit, approval, and fail-closed gates preserved. The server remains local-only. Private keys are never sent to the server; the authorization signing step shows the exact CLI command for the operator to run or executes it only after explicit UI confirmation.

### I1 — Workspace and pipeline overview

- `serve --workspace` + `GET /api/v1/workspace` + UI Pipeline view for deterministic seven-stage discovery/status; no mutation.
- Status: completed.

### I2 — Plan creation form

- `POST /api/v1/workflow/plan` + Plan create form + deterministic result panel + workspace path bounding.
- Status: completed.

### I3 — Bundle render

- new `POST /api/v1/workflow/render` endpoint invokes `render kubernetes-gitops` (or `docker-compose`) and writes bundle to workspace;
- UI shows target format selector, bundle name field, and inline bundle summary (manifest count, artifact inventory);
- fail closed on render error; existing bundle is not overwritten unless operator explicitly requests it.

### I4 — Preflight and change-set observation

- new `POST /api/v1/workflow/preflight` and `POST /api/v1/workflow/changeset` endpoints invoke the respective read-only Kubernetes observation commands;
- UI shows kubeconfig/context input fields and renders the change inspector: adds/modifies/deletions per object with severity;
- blocked change-sets are surfaced as hard blockers — the UI prevents advancing to approval when the change-set status is `blocked`.

### I5 — Approval form

- new `POST /api/v1/workflow/approval` endpoint invokes `approval record` with the decision, reason-reference, and bound artifact identities;
- UI shows a review checklist that surfaces plan summary, bundle digest, preflight target, and change-set object list before the approve/reject form;
- no implicit approval — the operator must explicitly choose `approve` or `reject` and supply a reason-reference string;
- result shows approval summary and content-addressed approval ID.

### I6 — Authorization CLI generator and apply confirmation

- for authorization, the UI generates and displays the exact `yara authorization issue` CLI command with all workspace-resolved paths — the private key is never sent to the server;
- once the authorization file appears in the workspace (operator runs the command externally), the UI detects it via `GET /api/v1/workspace` polling and advances to the apply stage;
- new `POST /api/v1/workflow/apply` endpoint invokes `deployment apply kubernetes` only after the operator confirms via an explicit UI dialog that shows the full evidence chain (plan → bundle → preflight → change-set → approval → authorization digests) and requires typing the confirm-authorization hash;
- apply result shows receipt summary and audit chain link.

## Next implementation slice

Implement **I3 — Bundle render**:

- add bounded `POST /api/v1/workflow/render` endpoint that executes `render kubernetes-gitops` or `render docker-compose` into workspace-managed output paths;
- accept explicit `planPath`, `catalogPath`, `target`, `bundleName`, `outputPath`, and `auditPath` fields; fail closed when paths are outside workspace;
- return deterministic response metadata: bundle path, bundle ID, audit path, renderer target, and summary counts;
- extend UI with Render form + result panel and trigger Pipeline refresh on success.

Acceptance criteria:

- render endpoint rejects unsupported targets and invalid paths with structured diagnostics;
- successful render writes bundle and audit artifacts in workspace and Pipeline shows Bundle stage as complete;
- UI render flow completes without page reload and shows bundle identity + summary metadata;
- backend and frontend checks both pass in `make check` and `go test -race ./...`.

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
