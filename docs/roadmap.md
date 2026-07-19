# Roadmap

## Planning assumptions

This roadmap assumes one primary maintainer working roughly **10 focused hours per week**. Dates are intentionally expressed as outcome gates rather than promises. The project advances only when exit criteria are met.

The critical path is:

```text
validate problem -> formalize schemas -> curate evidence -> plan scenarios
      -> validate trust -> render one target -> operate one reference path
```

Deployment breadth, UI and marketplace work do not belong on the critical path.

## Phase 0: problem and design validation

Estimated effort: 4–6 weeks.

Deliverables:

- complete proposed architecture and accepted foundational ADRs;
- 10–15 problem interviews across at least two candidate user groups;
- 5 manually produced plans using the proposed request/plan format;
- shortlist of one initial segment and 10 golden scenarios;
- terminology and input questions revised from evidence;
- explicit continue/pivot decision.

Exit criteria:

- users can provide enough input for a useful recommendation;
- at least three users confirm a manual plan would have saved meaningful effort;
- expert reviewers can understand and challenge decision explanations;
- the first supported use case and hardware boundary are defensible.

Do not begin a generic deployment engine in this phase.

## Phase 1: v0.1 explainable planner

Estimated effort: 12–18 weeks after Phase 0.

### Milestone 1 — contracts and fixtures

- JSON Schemas for request, inventory, catalog envelope, diagnostics and plan.
- Canonicalization specification and digest test vectors.
- Audit event schema, local planning receipt and redaction contract.
- Golden scenario fixture format.
- Minimal capability taxonomy and abstract topology templates.
- CLI skeleton with validate commands.

Exit: invalid and ambiguous inputs fail predictably; schemas can evolve through tested migrations.

### Milestone 2 — curated knowledge slice

- Small set of component, model and hardware manifests needed by golden scenarios.
- Evidence and compatibility assertion model.
- Referential-integrity, freshness and catalog-policy checks.
- Immutable local catalog snapshot builder.

Exit: every supported claim used by a scenario has current provenance and an owner.

### Milestone 3 — deterministic planning core

- Normalization, fact reconciliation and capability derivation.
- Topology candidate generation.
- Hard constraint engine with counterexample tests.
- Initial resource estimator and objective scoring.
- Dependency/version resolution and single-node placement.

Exit: all golden scenarios yield valid expected semantic plans or explicit infeasibility diagnostics.

### Milestone 4 — explanations and review

- Structured decision trace and rejected alternatives.
- Local append-only audit output linking request, inventory, policy, catalog, result and actor assurance.
- `plan explain`, `validate` and semantic `diff`.
- Search-bound and confidence reporting.
- Redacted debug bundle.
- Independent domain-expert scenario review.

Exit: all [v0.1 acceptance criteria](product/scope.md#acceptance-criteria) pass offline in CI.

Current gate: all eleven v0.1 acceptance criteria pass with machine-counted review resources. Milestone 4 is complete. See the [acceptance-status ledger](implementation/v0.1-acceptance-status.md).

## Phase 2: v0.2 reference deployment

Estimated effort: 10–16 weeks; starts only after real users approve v0.1 plans.

Decision gate: prototype Docker Compose and one alternative enough to write an ADR selecting the first target.

Current foundation: the evidence-backed v0.2 catalog can already produce a review-required LiteLLM/vLLM/Qwen plan for three NVIDIA Ada profiles and records two knowledge-only hypotheses for GB10 coherent unified memory. Artifact identity, licensing, telemetry posture, health contracts and compatibility bounds are represented. Content-addressed audited preflight, runtime smoke, model inference, capacity boundary, serving policy and same-version lifecycle contracts verify host eligibility, artifact identities, bounded CUDA execution, Qwen Coder load/health, one exact 32768-token envelope at concurrency 1, the narrow container-hardening profile and one restart/recovery cycle on GB10. A content-addressed coverage ledger rejects unaudited evidence and enumerates every missing gate across 38 manifests and eight assertions. No tuple is `supported` until sustained capacity, component-integration coverage, independent review and promotion gates pass.

Deliverables:

- versioned renderer interface and one reference renderer;
- typed adapters for the narrow supported stack;
- artifact bundle, SBOM/license inventory and offline manifest;
- preflight, explicit approval and least-privilege executor;
- health verification, receipts and safe owned-resource removal;
- blocked-egress end-to-end reference test.

Exit criteria:

- clean target can be brought to functional health from an approved plan;
- second apply is idempotent;
- failures stop safely and produce actionable diagnostics;
- every external artifact is immutable and accounted for;
- no architecture decision is made by renderer or executor.

## Phase 3: lifecycle proof

Estimated effort: 12–20 weeks.

Deliverables:

- observation and drift model;
- one tested version upgrade path;
- stateful backup and isolated restore verification;
- model replacement as a plan change;
- capacity and health contracts;
- retirement workflow.

Exit: the reference platform survives a tested upgrade and restore, with complete receipts and no undocumented manual step.

## Phase 4: broaden carefully

Candidate investments, selected from user demand:

- Kubernetes/GitOps renderer;
- RAG topology and embedding/vector catalog slice;
- another accelerator vendor;
- multi-node planning;
- team API and approval workflow;
- signed organization/private catalogs;
- web-based review cockpit.

Each new dimension adds a matrix, not a single feature. Add only one major dimension per milestone and require golden scenarios, evidence owners and lifecycle tests.

## Weekly cadence for a solo maintainer

A sustainable 10-hour week:

- 4 hours: one thin implementation/documentation slice;
- 2 hours: tests, fixtures and negative cases;
- 2 hours: user interview, manual plan or contributor review;
- 1 hour: catalog evidence maintenance;
- 1 hour: public progress note and backlog/decision review.

Do not split every day into four unrelated 30-minute tasks. Two-hour blocks should finish one coherent artifact where possible.

## Backlog priority rule

Rank work by:

1. prevents unsafe or incorrect plans;
2. tests the core product hypothesis;
3. unblocks an accepted milestone;
4. reduces permanent maintenance cost;
5. serves a validated user scenario;
6. expands breadth or presentation.

## Release policy

- Pre-alpha releases make no production support claim.
- Catalog and engine versions are released independently but tested as a compatibility set.
- Every release publishes schemas, migrations, catalog digest, known limitations and golden-scenario results.
- Breaking resource changes require migration tooling before removing old readers.
- A release is delayed rather than shipping expired support evidence as current.

## Success measures

By v0.1:

- zero known unsafe output in supported golden scenarios;
- at least five external users have reviewed a generated plan;
- at least three use a plan in a proof of concept;
- median reviewer can identify the top three decision factors;
- supported catalog evidence is 100% within freshness policy.

By lifecycle proof:

- one reference environment can be recreated, upgraded, restored and retired from versioned records;
- operators report net time saved after including review and maintenance;
- at least one external contributor adds a compliant scenario or catalog assertion without core code changes.

Revenue, stars and catalog entry count may be tracked separately but are not architecture success criteria.
