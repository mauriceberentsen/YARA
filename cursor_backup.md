# Cursor handoff

## Current repository state

- Repository: `YARA` on branch `main` (tracking `origin/main`).
- Scope baseline remains ADRs `0001`-`0011`; bounded direct Kubernetes executor remains ADR-0011.
- First pre-alpha tag is published: `v0.1.0-alpha.1`.
- Recent commits (newest first): `534f10e`, `9d2c86a`, `eb0be72`, `3438071`, `2c15d1d`.
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
- Bootstrap + first-use path is implemented:
  - `deployment bootstrap kubernetes` (bounded namespace/PVC provisioning with `BootstrapReceipt`);
  - `deployment import kubernetes` (bounded single-model local staging into bootstrap PVC with `ArtifactImportReceipt`).
- CI and release automation is implemented:
  - CI gates on PR/push: `make check`, `go test -race ./...`, schema draft-2020-12 validation, `git diff --check`;
  - release builds `linux/amd64`, `linux/arm64`, `darwin/arm64` binaries, publishes `checksums.txt`, and attaches deterministic `yara-schemas-v1alpha1.tar.gz`.

## Verified capabilities

- **Local/simulated verification:** Go/unit/CLI/schema tests prove deterministic IDs, fail-closed stale/foreign/mismatch paths, and bounded mutation authority.
- **Pre-alpha docs clarity:** `README.md`, `docs/quickstart.md`, `docs/reference/commands.md`, and `docs/architecture/README.md` separate implemented behavior from deferred roadmap scope.
- **Runtime drift policy gate verification:** dedicated policy command emits deterministic blocker/remediation output, produces auditable pass/fail responses, and enforces assertion-scoped infeasible exits for non-`in-sync` posture.
- **Web UI verification (simulated/local):** endpoint tests cover all read endpoints, assertion-scoped drift/lifecycle filtering, payload validation failures, and fail-closed handling; binary smoke test confirmed `yara serve --ui` serves embedded UI and policy endpoints.

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

- M1–M5 — completed (publication gating, artifact import, bootstrap, CI/release, public documentation).

## Open limitations and unproven claims

- No live cluster validation was executed in this run; run validated release publication and artifacts only.
- Air-gap external trust chain remains outside YARA proof boundary.
- Bootstrap remains intentionally narrow (single YARA-owned namespace + model PVC).
- Web UI remains local-only and read-only in this stage (no auth, no multi-user/session, no mutation endpoints).

## MVP-2 milestone path — Web UI

- W1 Backend HTTP API, W2 Dashboard shell, W3 Drift posture view, W4 Lifecycle readiness view, W5 Release/docs — all completed.
- Running the UI: `yara serve --catalog catalog/v0.2/snapshot.yaml --coverage-report .yara/catalog-v0.2-coverage.yaml --ui --port 7474` then open `http://127.0.0.1:7474`.

## MVP-3 milestone path — Interactive Workflow Cockpit

Goal: a browser-based operator cockpit where the complete plan-to-apply rollout workflow can be driven through the UI, with all existing audit, approval, and fail-closed gates preserved. The server remains local-only. Private keys are never sent to the server; the authorization signing step shows the exact CLI command for the operator to run or executes it only after explicit UI confirmation.

### I1 — Workspace and pipeline overview

- `yara serve --workspace <dir>` introduces a named local artifact directory;
- new `GET /api/v1/workspace` endpoint scans the workspace for known artifact files and maps them to pipeline stages (plan, bundle, preflight, change-set, approval, authorization, receipt);
- UI renders a visual pipeline with per-stage status badges (not-started / inputs-ready / complete / failed);
- no mutation — discovery only.

### I2 — Plan creation form

- new `POST /api/v1/workflow/plan` endpoint invokes `plan create` with operator-supplied inputs and writes outputs to the workspace;
- UI exposes a form: model/hardware assertion selector (populated from `/api/v1/assertions`), request name, request and inventory file paths;
- result shows plan summary (selected components, confidence, top decision factors) inline;
- fail closed: endpoint returns structured diagnostics on non-zero exit; no partial outputs are accepted.

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

Implement **I1 — Workspace and pipeline overview**:

- add `--workspace <dir>` flag to `yara serve`; reject startup if the directory does not exist;
- implement `GET /api/v1/workspace` that scans the workspace for known artifact filenames and returns a structured pipeline stage map with per-stage status (`not-started`, `ready`, `complete`) derived from artifact presence and validity;
- extend the UI with a Pipeline view (new top-level nav item) that renders the seven stages as a visual pipeline column with status badges and artifact path labels;
- no forms, no mutation — this slice is discovery and display only.

Acceptance criteria:

- `yara serve --workspace .yara/workspaces/default --catalog ... --coverage-report ...` starts successfully only when the workspace directory exists;
- `GET /api/v1/workspace` returns deterministic stage status for an empty workspace and for a workspace containing a real plan file from `plan create`;
- Pipeline view renders all seven stages; a workspace with only a plan file shows "complete" for stage 1 and "not-started" for stages 2–7;
- unknown or malformed artifact files in the workspace fail closed with a diagnostic, not a silent success;
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
