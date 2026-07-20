# Cursor handoff
## Current repository state
- Repository: `YARA` on branch `main` (tracking `origin/main`).
- Recent commits (newest first): `e76c71f`, `ff5bf04`, `81f6421`, `6f08227`, `cfaa249`.
- Public schema surface includes deployment, approval, lifecycle-proof, integration-publication, publication-chain, bootstrap, air-gap provenance, and runtime drift contracts under `schemas/yara.dev/v1alpha1`.
## Current product boundary
- Deterministic plan/render + read-only preflight/change-set + review-first approval + short-lived authorization + bounded apply/retire/rollback execution are implemented.
- Air-gap provenance chain is implemented as immutable receipts/gates (import, transfer, scan, gate result, trust policy, trust policy diff, transition review) and bound into apply-time validation.
- Lifecycle publication readiness for integration-required assertions is fail-closed and requires all four pillars: lifecycle proof approval, integration publication attestation, publication-chain rehearsal, and publication-chain renewal review.
- `catalog coverage create` and `catalog coverage lifecycle-publication-policy` expose deterministic assertion-scoped blocker/remediation diagnostics and fail-closed parity checks.
- `runtime drift-signal record` emits immutable `RuntimeDriftSignal` resources bound to catalog/assertion/runtime/bundle/preflight/target identities, `runtime-drift-signal validate` enforces schema + deterministic identity checks, catalog coverage exposes assertion-scoped `runtimeDriftPosture`, and `catalog coverage runtime-drift-policy` fails assertion-scoped checks on `missing`/`drifted` posture or malformed/incomplete records.
- Web UI (MVP-2, W1–W5) is fully implemented as a local-only, read-only embedded React/Vite SPA served by `yara serve --ui`.
- Interactive workflow cockpit I1 is implemented:
  - `yara serve --workspace <dir>` and `GET /api/v1/workspace` provide deterministic stage discovery (plan/bundle/preflight/change-set/approval/authorization/receipt);
  - Pipeline view now renders stage status and artifact paths using fail-closed workspace payload validation.
- Interactive workflow cockpit I2-I5 are implemented (plan/render/preflight/change-set/approval endpoints and forms) with workspace-bounded outputs and fail-closed validation.
- Interactive workflow cockpit I6 is implemented:
  - `GET /api/v1/workflow/authorization-command` returns the deterministic `yara authorization issue` command with workspace-resolved bundle/preflight/change-set/approval paths and no private key material in API payloads;
  - `POST /api/v1/workflow/apply` executes bounded `deployment apply kubernetes` with explicit confirmation binding (`confirmAuthorization` + `typedConfirmationDigest`) and workspace-bounded receipt/audit outputs;
  - apply responses return deterministic receipt/evidence bindings, and failures preserve fail-closed diagnostics from CLI validation and stale/mismatch checks.
- Interactive workflow cockpit I7 is implemented:
  - apply API/UI now support optional air-gap gate bindings (`airgapGateResultPath`, trust-policy confirmation, policy-diff confirmation, transition-review confirmation) with fail-closed guardrails;
  - apply responses now include provenance and gate identifiers (transfer/scan receipt IDs and gate policy/review IDs) for deterministic operator verification;
  - fail-closed apply checks are covered for trust-policy mismatch, destructive diff without transition review, and incomplete transfer/scan chain.
- Interactive workflow cockpit I8 is implemented:
  - `GET /api/v1/workflow/runbook` + Web UI runbook panel provide deterministic, redact-safe execution guidance with fail-closed authorization and optional air-gap gate checkpoints.
- Interactive workflow cockpit I9 is implemented:
  - `POST /api/v1/workflow/runbook/export` + runbook UI export persist deterministic markdown/json/audit outputs with workspace-bounded, no-overwrite, fail-closed path checks.
- Interactive workflow cockpit I10 is implemented:
  - `GET /api/v1/workflow/capsule` now emits one deterministic readiness payload with stage status, evidence IDs, runbook export references, and fail-closed blocker diagnostics;
  - capsule readiness fails closed when prerequisite stages are incomplete or evidence bindings are mismatched;
  - Web UI now includes an `Execution capsule` panel with readiness summary cards, stage table, runbook export references, and blocker/remediation table.
- Interactive workflow cockpit I11 is implemented:
  - `POST /api/v1/workflow/capsule/export` persists deterministic capsule markdown/json outputs plus mandatory audit output with workspace-bounded path enforcement;
  - blocked capsules fail closed by default and require explicit `allowBlocked=true` plus `allowBlockedReasonReference` to archive blocked gate posture;
  - capsule export audit includes blocker diagnostic codes for blocked archival snapshots and UI now supports ready/blocked snapshot export with policy diagnostics.
- Interactive workflow cockpit I12 is implemented:
  - `POST /api/v1/workflow/evidence-bundle/export` persists a deterministic manifest + mandatory audit output that references plan/bundle/preflight/change-set/approval/authorization and exported runbook/capsule artifacts by immutable IDs and workspace paths;
  - export fails closed when runbook or capsule export artifacts are missing, malformed, unpaired, or bound to a mismatched evidence chain;
  - capsule UI now supports evidence-bundle export actions with fail-closed diagnostics and deterministic artifact path outputs for operator handoff.
- Interactive workflow cockpit I13 is implemented:
  - `GET /api/v1/workflow/receipt-timeline` derives deterministic latest/prior deployment receipt chronology from workspace artifacts with explicit authorization and target-digest continuity checks;
  - `POST /api/v1/workflow/receipt-timeline/export` persists timeline markdown/json + mandatory audit outputs with workspace-bounded no-overwrite enforcement and fail-closed linkage/digest diagnostics surfaced in the capsule UI.
- Interactive workflow cockpit I14 is implemented:
  - `POST /api/v1/workflow/closure-package/export` persists deterministic closure package manifests + mandatory audit outputs that bind evidence-bundle, receipt-timeline, runbook, and capsule exports by immutable digests;
  - closure package export requires explicit `releaseReadinessReference` and fails closed on missing/malformed continuity artifacts or authorization/target digest mismatches (`YARA-CLS-*`);
  - capsule UI now supports closure package export actions and operator-facing blocker diagnostics for release handoff readiness.
- Interactive workflow cockpit I15 is implemented:
  - `GET /api/v1/workflow/closure-package/review-gate` evaluates the latest closure package against explicit `releaseReadinessReference`, `reviewerReference`, and `decision` gate inputs without mutation;
  - `POST /api/v1/workflow/closure-package/review-gate/export` persists deterministic markdown/json review-gate artifacts plus mandatory audit outputs with workspace-bounded no-overwrite checks;
  - review gate fails closed on malformed decision payloads, missing gate inputs, and closure continuity mismatches (`YARA-RVG-*`), and capsule UI now surfaces pass/blocked review gate diagnostics.
- Interactive workflow cockpit I16 is implemented:
  - `POST /api/v1/workflow/release-decision/export` persists deterministic release decision ledger entries bound to closure package + review gate digests, continuity IDs, reviewer metadata, and operator/timestamp decision metadata;
  - export fails closed on missing/malformed timestamp/reference metadata, missing review-gate artifacts, and closure/review continuity divergence (`YARA-RDL-*`), with workspace-bounded no-overwrite output enforcement and mandatory audit output;
  - capsule UI now supports release-decision export and shows explicit `ready-to-publish` vs `blocked` publication diagnostics.
- Interactive workflow cockpit I17-I29 are implemented:
  - `POST /api/v1/workflow/release-publication/export`, `.../index/export`, `.../package/export`, `.../envelope/export`, `.../handoff-receipt/export`, `.../acknowledgment/export`, `POST /api/v1/workflow/rollout-closure-summary/export`, `.../rollout-closure-delivery/export`, `.../rollout-closure-acceptance/export`, `.../rollout-closure-certificate/export`, `.../rollout-closure-ledger/export`, `.../rollout-closure-docket/export`, and `.../rollout-closure-bulletin/export` now persist deterministic publication-chain + closure manifests bound to capsule/evidence/closure/review/decision/publication digests;
  - exports fail closed on missing/blocked chain artifacts, malformed publication metadata, and continuity/digest divergence (`YARA-RPB-*`, `YARA-RPI-*`, `YARA-RPK-*`, `YARA-RPE-*`, `YARA-RHR-*`, `YARA-RAK-*`, `YARA-RCS-*`, `YARA-RCD-*`, `YARA-RCA-*`, `YARA-RCC-*`, `YARA-RLG-*`, `YARA-RDK-*`, `YARA-RBL-*`) with workspace-bounded no-overwrite audit outputs;
  - capsule UI now supports publication attestation/index/package/envelope/handoff/acknowledgment/closure-summary/delivery-record/acceptance/certificate/ledger/docket/bulletin export and surfaces explicit `publishable`, `index-ready`, `package-ready`, `delivery-ready`, `handoff-ready`, `acknowledgment-ready`, `summary-ready`, `delivery-record-ready`, `acceptance-ready`, `certificate-ready`, `ledger-ready`, `docket-ready`, and `bulletin-ready` diagnostics.
- Bootstrap + first-use path is implemented (`deployment bootstrap kubernetes` + `deployment import kubernetes`) with bounded namespace/PVC and import receipt enforcement.
- CI and release automation is implemented: CI gates on PR/push with `make check`, `go test -race ./...`, schema draft-2020-12 validation, and `git diff --check`; release builds `linux/amd64`, `linux/arm64`, `darwin/arm64` binaries, publishes `checksums.txt`, and attaches deterministic `yara-schemas-v1alpha1.tar.gz`.
## Verified capabilities
- **Local/simulated verification:** Go/unit/CLI/schema tests prove deterministic IDs, fail-closed stale/foreign/mismatch paths, and bounded mutation authority.
## Current branch and working tree
- Branch: `main` tracking `origin/main`.
- This slice completed:
  - `POST /api/v1/workflow/rollout-closure-bulletin/export` now writes deterministic rollout closure release-bulletin manifests + mandatory audit output with workspace-bounded no-overwrite semantics;
  - bulletin export now requires explicit `bulletinReference` + `publishedByReference` + `publishedTimestamp` and fails closed on missing/blocked docket/publication-chain artifacts or continuity/digest divergence;
  - UI capsule panel now supports bulletin export and surfaces artifact paths plus explicit `bulletin-ready` / `blocked` diagnostics.
- Validation (simulated/local) passed:
  - `gofmt -w internal/cli/serve.go internal/cli/serve_test.go`;
  - `npm run check --prefix internal/cli/webui` and `git diff --check`;
  - `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check`;
  - `GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...`.
- Required git author for this stream: `Maurice Berentsen <mauriceberentsen@live.nl>`.
## Open limitations and unproven claims
- No live cluster validation was executed in this run; run validated release publication and artifacts only.
## MVP-2 milestone path — Web UI
- Running the UI: `yara serve --catalog catalog/v0.2/snapshot.yaml --coverage-report .yara/catalog-v0.2-coverage.yaml --ui --port 7474` then open `http://127.0.0.1:7474`.
## MVP-3 milestone path — Interactive Workflow Cockpit
Goal: a browser-based operator cockpit where the complete plan-to-apply rollout workflow can be driven through the UI, with all existing audit, approval, and fail-closed gates preserved. The server remains local-only. Private keys are never sent to the server; the authorization signing step shows the exact CLI command for the operator to run or executes it only after explicit UI confirmation.
### I1 — Workspace and pipeline overview
- `serve --workspace` + `GET /api/v1/workspace` + UI Pipeline view for deterministic seven-stage discovery/status; no mutation. Status: completed.
### I2 — Plan creation form
- `POST /api/v1/workflow/plan` + deterministic Plan form/result with workspace-bounded outputs. Status: completed.
### I3 — Bundle render
- `POST /api/v1/workflow/render` + deterministic Bundle form/result with workspace-bounded outputs. Status: completed.
### I4 — Preflight and change-set observation
- `POST /api/v1/workflow/preflight` + `POST /api/v1/workflow/changeset` + deterministic observation forms/results with workspace-bounded outputs. Status: completed.
### I5 — Approval form
- `POST /api/v1/workflow/approval` + deterministic approval checklist/form/result with workspace-bounded outputs. Status: completed.
### I6 — Authorization CLI generator and apply confirmation
- UI renders deterministic `yara authorization issue` command (private key stays client-side), detects authorization artifact presence, and runs `POST /api/v1/workflow/apply` only after explicit evidence-chain confirmation. Status: completed.
### I7 — Air-gap gate and provenance controls in apply cockpit
- `POST /api/v1/workflow/apply` + UI support optional air-gap gate inputs with deterministic transfer/scan provenance helpers and fail-closed policy diagnostics. Status: completed.
### I8 — Workflow execution runbook export
- add `GET /api/v1/workflow/runbook` + UI panel for deterministic, redact-safe plan→apply guidance with explicit fail-closed reminders. Status: completed.
### I9 — Runbook artifact persistence
- add `POST /api/v1/workflow/runbook/export` + UI action for deterministic runbook markdown/json/audit export with workspace-bounded no-overwrite fail-closed checks. Status: completed.
### I10 — End-to-end cockpit execution capsule
- add `GET /api/v1/workflow/capsule` plus UI capsule view to surface deterministic stage/evidence readiness, runbook export references, and blocker taxonomy with remediation. Status: completed.
### I11 — Capsule audit export and gating freeze
- add `POST /api/v1/workflow/capsule/export` + UI action for deterministic capsule json/markdown/audit export with blocked-state fail-closed policy (`allowBlocked=true` + reason required). Status: completed.
### I12 — Workflow evidence bundle export index
- add `POST /api/v1/workflow/evidence-bundle/export` + capsule UI action to persist deterministic manifest/audit outputs, with fail-closed validation for missing/malformed/mismatched runbook/capsule exports and strict workspace-bounded no-overwrite paths. Status: completed.
### I13 — Execution receipt timeline and closure export
- add `GET /api/v1/workflow/receipt-timeline` and `POST /api/v1/workflow/receipt-timeline/export` with deterministic latest/prior receipt chronology, mandatory markdown/json/audit outputs, fail-closed malformed/continuity checks, and capsule UI export support. Status: completed.
### I14 — Rollout closure package export
- add `POST /api/v1/workflow/closure-package/export` + capsule UI action to persist deterministic closure manifests/audit outputs linking evidence-bundle, receipt-timeline, runbook, and capsule exports by immutable digest; require explicit `releaseReadinessReference` and fail closed on malformed/mismatched continuity inputs. Status: completed.
### I15 — Closure package review gate snapshot
- add `GET /api/v1/workflow/closure-package/review-gate` and `POST /api/v1/workflow/closure-package/review-gate/export` with deterministic pass/blocked outcomes bound to closure package continuity and reviewer decision inputs; enforce fail-closed malformed/missing gate fields and export markdown/json/audit outputs. Status: completed.
### I16 — Release decision ledger export
- add `POST /api/v1/workflow/release-decision/export` to persist deterministic ledger entries binding closure package + review gate digests, continuity IDs, release readiness/reviewer/operator/timestamp metadata; fail closed on malformed/missing decision inputs or continuity divergence (`YARA-RDL-*`) with mandatory workspace-bounded no-overwrite audit output. Status: completed.
### I17 — Release publication attestation export
- add `POST /api/v1/workflow/release-publication/export` to persist deterministic publication attestations binding release-decision/closure/review digests with explicit publication channel/location/operator/timestamp metadata; fail closed on missing/blocked release decisions or continuity/digest divergence (`YARA-RPB-*`) with mandatory workspace-bounded no-overwrite audit output. Status: completed.
### I18 — Release publication registry index export
- add `POST /api/v1/workflow/release-publication/index/export` to persist deterministic publication-chain index manifests binding closure/review/decision/publication digests with explicit `publicationBatchReference` and `operatorReference`; fail closed on missing/blocked artifacts, malformed index metadata, or continuity/digest divergence (`YARA-RPI-*`) with mandatory workspace-bounded no-overwrite audit output. Status: completed.
### I19 — Release publication package export
- add `POST /api/v1/workflow/release-publication/package/export` to persist deterministic publication package manifests that bind closure/review/decision/publication/index digests with explicit `packageReference`, `publicationWindowReference`, and `operatorReference`; fail closed on missing/blocked artifacts, malformed package metadata, or continuity/digest divergence (`YARA-RPK-*`) with mandatory workspace-bounded no-overwrite audit output. Status: completed.
### I20 — Release publication delivery envelope export
- add `POST /api/v1/workflow/release-publication/envelope/export` to persist deterministic delivery envelope manifests that bind closure/review/decision/publication/index/package digests with explicit `deliveryReference`, `destinationReference`, and `operatorReference`; fail closed on missing/blocked artifacts, malformed envelope metadata, or continuity/digest divergence (`YARA-RPE-*`) with mandatory workspace-bounded no-overwrite audit output. Status: completed.
### I21 — Release publication handoff receipt export
- add `POST /api/v1/workflow/release-publication/handoff-receipt/export` to persist deterministic handoff receipts that bind closure/review/decision/publication/index/package/envelope digests with explicit `receiverReference`, `handoffTimestamp`, and `operatorReference`; fail closed on missing/blocked artifacts, malformed handoff metadata, or continuity/digest divergence (`YARA-RHR-*`) with mandatory workspace-bounded no-overwrite audit output. Status: completed.
### I22 — Release publication acknowledgment export
- add `POST /api/v1/workflow/release-publication/acknowledgment/export` to persist deterministic acknowledgment manifests that bind closure/review/decision/publication/index/package/envelope/handoff digests with explicit `acknowledgmentReference`, `acknowledgedByReference`, and `acknowledgmentTimestamp`; fail closed on missing/blocked artifacts, malformed acknowledgment metadata, or continuity/digest divergence (`YARA-RAK-*`) with mandatory workspace-bounded no-overwrite audit output. Status: completed.
### I23 — Rollout closure summary export
- add `POST /api/v1/workflow/rollout-closure-summary/export` to persist deterministic summary manifests that bind capsule/evidence-bundle/closure/review/decision/publication/index/package/envelope/handoff/acknowledgment digests with explicit `summaryReference`, `operatorReference`, and `summaryTimestamp`; fail closed on missing/blocked artifacts, malformed summary metadata, or continuity/digest divergence (`YARA-RCS-*`) with mandatory workspace-bounded no-overwrite audit output. Status: completed.
### I24 — Rollout closure delivery record export
- add `POST /api/v1/workflow/rollout-closure-delivery/export` to persist deterministic delivery-record manifests that bind closure-summary/acknowledgment/handoff/envelope/package/index/attestation/decision/closure/review digests with explicit `deliveryReference`, `destinationReference`, `operatorReference`, and `deliveryTimestamp`; fail closed on missing/blocked artifacts, malformed delivery metadata, or continuity/digest divergence (`YARA-RCD-*`) with mandatory workspace-bounded no-overwrite audit output. Status: completed.
### I25-I29 — Rollout closure acceptance, certificate, ledger, docket, and bulletin exports
- add `POST /api/v1/workflow/rollout-closure-acceptance/export`, `.../rollout-closure-certificate/export`, `.../rollout-closure-ledger/export`, `.../rollout-closure-docket/export`, and `.../rollout-closure-bulletin/export` to persist deterministic acceptance/certificate/ledger/docket/bulletin manifests that bind delivery/summary/acknowledgment/handoff/envelope/package/index/attestation/decision/closure/review digests with explicit `acceptanceReference`/`acceptedByReference`/`acceptanceTimestamp`, `certificateReference`/`issuedByReference`/`issuedTimestamp`, `ledgerReference`/`recordedByReference`/`recordedTimestamp`, `docketReference`/`preparedByReference`/`preparedTimestamp`, and `bulletinReference`/`publishedByReference`/`publishedTimestamp`; fail closed on missing/blocked artifacts, malformed metadata, or continuity/digest divergence (`YARA-RCA-*`, `YARA-RCC-*`, `YARA-RLG-*`, `YARA-RDK-*`, `YARA-RBL-*`) with mandatory workspace-bounded no-overwrite audit output. Status: completed.
## Next implementation slice
Implement **I30 — Rollout closure release packet export**:
- add `POST /api/v1/workflow/rollout-closure-packet/export` to persist one deterministic release-packet manifest that binds bulletin, docket, ledger, certificate, acceptance-receipt, delivery-record, closure-summary, acknowledgment, handoff, envelope, package, index, attestation, decision, closure, and review digests as the final packaged handoff payload;
- require explicit `packetReference` + `packagedByReference` + `packagedTimestamp`; fail closed when any linked artifact is missing, malformed, blocked, or continuity diverges;
- emit mandatory audit output with workspace-bounded no-overwrite semantics and deterministic blocker codes for packet export failures;
- extend capsule UI with rollout closure packet export action and explicit "packet ready / blocked" diagnostics.
Acceptance criteria:
- rollout closure packet export writes deterministic release-packet manifest + audit artifacts bound to closure/review/decision/publication/index/package/envelope/handoff/acknowledgment/summary/delivery/acceptance/certificate/ledger/docket/bulletin continuity digests;
- rollout closure packet export fails closed on missing/blocked/malformed publication artifacts and out-of-workspace or duplicate output paths;
- UI rollout closure packet export flow surfaces artifact paths and fail-closed diagnostics without exposing secret-bearing fields;
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
- Each completed slice must update this handoff with current branch/commit/tag reality, exact validation outcomes, explicit simulated/local/live distinction, and exactly one next recommended slice.
