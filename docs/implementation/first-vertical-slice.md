# First vertical slice

## Goal

Prove the complete boundary from declared intent to deterministic, explainable and audited output with one deliberately tiny scenario. The slice chooses between two placeholder model/runtime candidates for one local chat/coding request; it does not deploy anything.

## Scenario

Given:

- a valid chat/coding `PlatformRequest`;
- one declared Linux/NVIDIA inventory;
- a small immutable catalog snapshot;
- one candidate that fits memory and one that does not;
- no-external-egress policy.

YARA must:

1. validate and normalize inputs;
2. derive text-generation and API capabilities;
3. reject the oversized candidate with `YARA-HW-004`;
4. select the feasible candidate;
5. emit a stable decision explaining selection and rejection;
6. emit a semantic plan with all input/catalog/engine digests;
7. emit chained planning audit events without sensitive resource bodies;
8. reproduce byte-equivalent canonical semantic output on a second run.

## Non-goals

- Real product manifests or benchmark claims.
- A general expression language.
- Multi-objective optimization beyond one deterministic preference.
- Automatic discovery.
- Plugins, API server, renderer or executor.
- Optimized performance.

## Work units

### 1. Bootstrap and CI

- Initialize Go module and CLI entry point.
- Pin toolchain and dependency policy.
- Add format, unit test, vet/static analysis and offline test jobs.
- Add a make/task entry point only if it simplifies repeatable commands.

### 2. Wire resources

- Write minimal v1alpha1 JSON Schemas.
- Add valid and invalid YAML fixtures.
- Decode strictly and return path-aware diagnostics.
- Convert resources into immutable normalized domain values.

### 3. Canonicalization

- Define canonical JSON test vectors.
- Hash request, inventory, policy/catalog fixture and semantic plan.
- Exclude audit time/event identity and presentation text from plan identity.

### 4. Catalog slice

- Define one capability contract and topology template.
- Define two model/runtime candidates and one hardware profile.
- Add positive/negative compatibility evidence fixtures.
- Validate references and immutable snapshot digest.

### 5. Planner slice

- Derive capability requirements.
- Generate the two candidates in stable order.
- Apply memory/headroom hard constraint.
- Select feasible candidate and construct reason chain.
- Build and independently validate `PlatformPlan`.

### 6. Audit slice

- Implement typed audit action names.
- Create local JSONL sink and previous-event digest chain.
- Emit validation/catalog/policy/planning terminal events.
- Add secret canary/redaction and tamper verification tests.
- Make audit persistence state explicit in output.

### 7. CLI and golden test

- Wire `plan create`, `validate`, `explain` and `audit verify`.
- Add end-to-end golden plan/diagnostic/audit assertions.
- Run with network denied and temporary empty home/cache.
- Document the exact example command and known limitations.

## Acceptance criteria

- All commands return documented stable exit classes.
- Invalid unknown fields are rejected.
- Oversized candidate can never win through preference scoring.
- Selected and rejected choices have structured evidence paths.
- Audit event chain verifies; mutation/reordering is detected.
- No test secret appears in stdout, stderr, plan or audit file.
- Repeated runs produce identical semantic plan and digest.
- Planner packages have no network or deployment imports.
- All checks pass from a clean clone without external services.

## Review checkpoint

After this slice, review whether schemas are understandable, audit data is sufficient but minimal, package boundaries remain clean and the plan genuinely helps explain the scenario. Refactor before adding a second scenario; do not hide structural problems under a larger catalog.
