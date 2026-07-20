# Cursor handoff
## Current repository state
- Repository: `YARA` on branch `main` (tracking `origin/main`).
- Scope baseline remains ADRs `0001`-`0011`; bounded direct Kubernetes executor remains ADR-0011.
- First pre-alpha tag is published: `v0.1.0-alpha.1`.
- Recent commits (newest first): `2dffa71`, `041903c`, `840e289`, `ee70422`, `e2c01ae`.
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
- Interactive workflow cockpit I3 is implemented:
  - `POST /api/v1/workflow/render` executes bounded bundle rendering (`kubernetes-gitops` or `docker-compose`) with explicit path/target inputs;
  - bundle and audit outputs are restricted to workspace-managed output paths and fail closed on invalid targets/paths;
  - Render UI form now writes bundle artifacts and renders deterministic bundle summary metadata in-session.
- Interactive workflow cockpit I4 is implemented:
  - `POST /api/v1/workflow/preflight` and `POST /api/v1/workflow/changeset` execute bounded read-only Kubernetes observation commands with explicit input/output paths;
  - preflight and changeset outputs are restricted to workspace-managed output paths and fail closed on invalid/out-of-workspace paths;
  - Preflight and Change-set UI forms now render deterministic summaries and change inspector output, including hard blocker signaling for blocked change-sets.
- Interactive workflow cockpit I5 is implemented:
  - `POST /api/v1/workflow/approval` executes bounded `approval record` with explicit bundle/preflight/change-set evidence bindings and decision inputs;
  - approval and audit outputs are restricted to workspace-managed output paths and fail closed on invalid decisions/paths or broken evidence bindings;
  - Approval UI now renders a review checklist, enforces explicit decision + reason-reference input, and returns deterministic approval identity metadata in-session.
- Interactive workflow cockpit I6 is implemented:
  - `GET /api/v1/workflow/authorization-command` returns the deterministic `yara authorization issue` command with workspace-resolved bundle/preflight/change-set/approval paths and no private key material in API payloads;
  - `POST /api/v1/workflow/apply` executes bounded `deployment apply kubernetes` with explicit confirmation binding (`confirmAuthorization` + `typedConfirmationDigest`) and workspace-bounded receipt/audit outputs;
  - apply responses return deterministic receipt/evidence bindings, and failures preserve fail-closed diagnostics from CLI validation and stale/mismatch checks.
- Interactive workflow cockpit I7 is implemented:
  - apply API/UI now support optional air-gap gate bindings (`airgapGateResultPath`, trust-policy confirmation, policy-diff confirmation, transition-review confirmation) with fail-closed guardrails;
  - apply responses now include provenance and gate identifiers (transfer/scan receipt IDs and gate policy/review IDs) for deterministic operator verification;
  - fail-closed apply checks are covered for trust-policy mismatch, destructive diff without transition review, and incomplete transfer/scan chain.
- Interactive workflow cockpit I8 is implemented:
  - `GET /api/v1/workflow/runbook` now emits deterministic, redact-safe execution guidance bound to workspace artifacts and evidence IDs;
  - runbook output includes explicit fail-closed checkpoints for authorization confirmation and optional air-gap gate policy/review confirmations;
  - Web UI runbook panel now renders copy-ready steps, evidence chain summary, and operator-facing guardrails for controlled execution sessions.
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
  - `GET /api/v1/workflow/runbook` endpoint implemented with deterministic workspace artifact validation and redact-safe command/checkpoint output;
  - runbook endpoint enforces fail-closed prerequisites for plan/bundle/preflight/change-set/approval/authorization artifacts and rejects malformed/missing workspace evidence;
  - Web UI adds `Runbook` panel with evidence IDs, artifact paths, fail-closed checklist, step commands, and copy-ready markdown output.
- Validation (simulated/local) passed:
  - `gofmt -w internal/cli/serve.go internal/cli/serve_test.go`;
  - `npm run check --prefix internal/cli/webui`;
  - `git diff --check`, `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check`, and `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...`.
- Required git author for this stream: `Maurice Berentsen <mauriceberentsen@live.nl>`.
## MVP milestone path
- M1–M5 — completed (publication gating, artifact import, bootstrap, CI/release, public documentation).
## Open limitations and unproven claims
- No live cluster validation was executed in this run; run validated release publication and artifacts only.
- Air-gap external trust chain remains outside YARA proof boundary.
- Bootstrap remains intentionally narrow (single YARA-owned namespace + model PVC).
- Web UI remains local-only in this stage (no auth, no multi-user/session); private-key signing still runs outside the server boundary.
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
- `POST /api/v1/workflow/render` + Render form + deterministic bundle result panel + workspace path bounding.
- Status: completed.
### I4 — Preflight and change-set observation
- `POST /api/v1/workflow/preflight` + `POST /api/v1/workflow/changeset` + Preflight/Change-set forms + deterministic result/inspector panels + workspace path bounding.
- Status: completed.
### I5 — Approval form
- `POST /api/v1/workflow/approval` + Approval checklist/form + deterministic result panel + workspace path bounding.
- Status: completed.
### I6 — Authorization CLI generator and apply confirmation
- for authorization, the UI generates and displays the exact `yara authorization issue` CLI command with all workspace-resolved paths — the private key is never sent to the server;
- once the authorization file appears in the workspace (operator runs the command externally), the UI detects it via `GET /api/v1/workspace` polling and advances to the apply stage;
- new `POST /api/v1/workflow/apply` endpoint invokes `deployment apply kubernetes` only after the operator confirms via an explicit UI dialog that shows the full evidence chain (plan → bundle → preflight → change-set → approval → authorization digests) and requires typing the confirm-authorization hash;
- apply result shows receipt summary and audit chain link.
- Status: completed.
### I7 — Air-gap gate and provenance controls in apply cockpit
- extend `POST /api/v1/workflow/apply` request/response coverage and UI to drive optional air-gap gate inputs (`airgapGateResultPath`, trust-policy confirmation, policy-diff/transition-review confirmations) with explicit fail-closed diagnostics;
- expose deterministic transfer + scan receipt chain assistant fields in the UI with pre-submit validation and clear blocker remediation;
- add end-to-end API/UI tests for optional gate paths (including destructive trust-policy transition review requirement) so cockpit behavior matches CLI policy gates exactly.
- Status: completed.
### I8 — Workflow execution runbook export
- add `GET /api/v1/workflow/runbook` that emits a deterministic, redact-safe step list for plan→render→preflight→change-set→approval→authorization→apply using current workspace artifact paths and IDs;
- include explicit fail-closed reminders for private-key handling, digest confirmation, and air-gap gate decision points;
- extend UI with a runbook panel that operators can copy as a single artifact for review and controlled execution sessions.
- Status: completed.
### I9 — Runbook artifact persistence
- add `POST /api/v1/workflow/runbook/export` to persist the generated runbook markdown/JSON into workspace-bounded files with immutable naming conventions and audit output;
- add UI action to export the active runbook and show resulting artifact/audit paths;
- enforce fail-closed behavior for overwrite attempts and out-of-workspace export paths.
## Next implementation slice
Implement **I9 — Runbook artifact persistence**:
- add `POST /api/v1/workflow/runbook/export` producing workspace-bounded runbook markdown/json outputs and mandatory audit output;
- preserve redact-safe runbook constraints in exported artifacts and reject overwrite/duplicate output paths fail closed;
- add UI export action with explicit output/audit path inputs and deterministic result panel;
- add backend/frontend tests for successful export, duplicate-path rejection, and out-of-workspace path rejection.
Acceptance criteria:
- runbook export writes deterministic markdown/json + audit artifacts to workspace-managed paths only;
- export fails closed for duplicate/out-of-workspace paths and does not overwrite existing runbooks;
- UI export flow surfaces artifact paths and diagnostics without exposing secret-bearing fields;
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
