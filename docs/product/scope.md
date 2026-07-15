# Product scope

## Scope model

YARA's long-term loop is **discover, plan, review, apply, observe, improve and retire**. These stages are intentionally separable. Planning must be valuable without deployment, and deployment must consume an approved immutable plan rather than repeat planner decisions.

## v0.1: explainable local planner

### In scope

- YAML or JSON `PlatformRequest` input.
- Declared hardware inventory, with an optional local discovery prototype.
- One Linux host with one or more NVIDIA GPUs of the same class.
- Chat and coding-assistant use cases.
- Local and air-gapped connectivity modes.
- A curated subset of inference, gateway, UI, identity, database and observability components.
- A curated subset of openly redistributable model metadata.
- Hard constraint filtering and multi-objective scoring.
- Dependency and version resolution for cataloged combinations.
- A versioned, deterministic `PlatformPlan`.
- Human-readable explanations, rejected alternatives, warnings and confidence.
- Exact serving-candidate search counts, explicit search boundaries and no global-optimality claim.
- A local planning audit record containing input/output digests, actor assurance, engine/catalog versions and outcome.
- A deterministic local `DebugBundle` with allowlisted plan metadata, explicit omissions, secret-pattern rejection and mandatory generation audit.
- Dry validation only; no system mutation.

### Acceptance criteria

v0.1 is complete only when:

1. At least ten representative requests have reviewed expected-plan fixtures.
2. Re-running the same input and catalog snapshot is semantically deterministic.
3. Every selected component and model has a machine-readable reason chain.
4. Every hard constraint is tested with a failing counterexample.
5. Unknown or contradictory critical facts fail closed.
6. Catalog manifests pass schema, referential-integrity and provenance checks.
7. A domain expert review finds no known unsafe recommendation in the supported scenarios.
8. The CLI can generate, explain and validate a plan without network access.
9. Every planning run emits a schema-valid, secret-free audit record whose resource digests match its inputs and output.
10. Every successful plan states whether its bounded serving-candidate search was complete and derives ordinal confidence from explicit evidence/method factors.
11. A debug bundle contains no raw request, inventory, plan prose, placement or environment data and is not produced when its bounded secret-pattern gate finds a match.

### Explicitly out of scope

- Applying Docker Compose, Helm, Terraform or Kubernetes resources.
- AMD, Apple Silicon, NPU and mixed accelerator planning.
- Multi-node capacity and scheduler optimization.
- Image, audio, video, agent and production RAG architectures.
- Online discovery of arbitrary community plugins.
- Automated benchmark execution.
- Continuous reconciliation, upgrades or rollback.
- A graphical management interface.
- SaaS or multi-tenant control planes.
- Guarantees of legal compliance, model quality or production capacity.

## v0.2: reviewed deployment prototype

The intended next increment adds exactly one execution target, chosen after v0.1 validation. The current preference is Docker Compose for a local single-node reference path because it minimizes platform prerequisites. Kubernetes remains a likely enterprise backend but is not automatically the right first implementation.

Candidate scope:

- plan-to-artifact rendering;
- explicit approval token before apply;
- preflight checks and secret references;
- idempotent apply for the reference stack;
- health verification and diagnostic bundle;
- destroy of resources owned by the plan.

This scope is provisional and requires an ADR based on prototype results.

## Later scope

- Kubernetes and GitOps renderers.
- Multi-node and heterogeneous hardware planning.
- Model artifact acquisition and verified offline bundles.
- Backup, restore, upgrade and rollback orchestration.
- Observed performance feedback into an explicit re-planning workflow.
- More use cases and accelerator vendors.
- Web UI and organization-level policy management.
- Signed catalog release channels and third-party extensions.

## Boundary with underlying software

YARA owns:

- request and plan schemas;
- catalog semantics and evidence requirements;
- constraint, recommendation and explanation logic;
- cross-component integration contracts;
- orchestration state and lifecycle coordination;
- validation of supported reference paths.

YARA does not own:

- model weights, upstream container images or third-party licenses;
- the internal correctness or security of integrated software;
- cluster, operating-system or hardware support outside declared adapters;
- organization-specific risk acceptance;
- application data managed by deployed components.

## Definition of support

"Supported" means a specific, versioned combination has:

- complete catalog metadata;
- documented provenance;
- automated compatibility and contract tests;
- a named maintainer or ownership state;
- a defined freshness window;
- a known upgrade or removal policy.

Catalog presence alone means **known**, not supported. This distinction prevents breadth from overstating reliability.
