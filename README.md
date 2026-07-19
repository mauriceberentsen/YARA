# YARA

> **Your AI Runtime Architect** — turn hardware, goals and policy constraints into an explainable, reproducible AI-platform plan.

YARA is an open-source project for designing and, eventually, operating a suitable AI platform from a user's desired outcomes. Instead of asking users to assemble inference servers, gateways, user interfaces, data stores, identity providers and observability tools themselves, YARA will reason about the environment and propose a compatible stack.

YARA is currently in its **pre-alpha implementation and validation phase**. The CLI can validate v1alpha1 inputs, generate deterministic plans, explain and compare them, compile exact evidence coverage, run bounded compatibility contracts, and render the narrow v0.2 LiteLLM/vLLM plan into audited content-addressed Docker Compose and Kubernetes/GitOps bundles. A strictly read-only Kubernetes preflight can bind a bundle to a pseudonymous observed target and report proven, failed and blocked prerequisites. Rendering and preflight do not deploy a platform.

## The problem

A useful self-hosted AI platform is rarely one application. It is a system of components with coupled constraints:

- models must fit the available accelerators and memory;
- inference engines must support the selected model, quantization and hardware;
- chat, coding, RAG and agent use cases require different capabilities;
- identity, data residency, licensing and air-gap policies exclude some options;
- concurrency, latency and availability objectives change the topology;
- versions, drivers, protocols and APIs must remain compatible over time.

Installation scripts can automate commands, but they cannot decide which architecture is appropriate. YARA's primary value is the knowledge and reasoning required to make that decision explicit, reviewable and repeatable.

## The intended experience

Users provide a desired state:

```yaml
apiVersion: yara.dev/v1alpha1
kind: PlatformRequest
metadata:
  name: private-coding-assistant
spec:
  useCases: [chat, coding]
  users:
    expected: 25
    peakConcurrent: 8
  environment:
    connectivity: air-gapped
  policies:
    openSourceOnly: true
    telemetry: forbidden
  objectives:
    priority: quality
```

YARA combines this request with discovered or declared hardware, catalog data, compatibility constraints and policies. It returns a plan containing:

- the selected architecture, components and models;
- rejected alternatives and the reasons they were rejected;
- assumptions, warnings and unresolved questions;
- capacity estimates and confidence levels;
- a dependency graph and ordered deployment stages;
- a stable input and catalog fingerprint for reproducibility.

Deployment and lifecycle management will consume this plan in later milestones. The planner never renders or applies infrastructure directly.

## What makes YARA different

- **Goal-driven:** users describe outcomes and constraints, not a shopping list of tools.
- **Hardware-aware:** real compute, memory, storage and network limits are first-class inputs.
- **Policy-aware:** privacy, licensing, connectivity and enterprise requirements are hard constraints where appropriate.
- **Explainable:** every recommendation must cite the facts and rules that produced it.
- **Auditable:** planning, policy, approval and lifecycle actions produce append-only evidence tied to immutable resource digests.
- **Deterministic:** identical versioned inputs produce the same plan.
- **Modular:** components, models, hardware and policies are catalog entries rather than hard-coded product branches.
- **Lifecycle-oriented:** planning anticipates install, health, upgrade, backup, recovery and retirement.

## Architecture at a glance

```text
PlatformRequest + Inventory + Policies
                    |
                    v
          Normalize and validate
                    |
                    v
          Derive required capabilities
                    |
                    v
     Generate -> filter -> score candidates
                    |
                    v
       Resolve dependencies and versions
                    |
                    v
       Validate topology and capacity
                    |
                    v
         Emit explainable PlatformPlan
                    |
          +---------+---------+
          |                   |
        review          future executors
```

The detailed design is in the [architecture documentation](docs/architecture/README.md).

## Scope

The project deliberately starts narrower than its long-term vision.

**v0.1 will:**

- accept a versioned request and hardware inventory;
- use a curated, schema-validated catalog;
- plan one local, Linux-based, NVIDIA GPU deployment profile;
- cover chat and coding use cases;
- produce a deterministic plan with explanations and diagnostics;
- perform no mutations to the target environment.

**v0.1 will not:**

- deploy Docker, Kubernetes or cloud resources;
- claim globally optimal model or component selection;
- dynamically ingest untrusted catalog data;
- support every accelerator vendor or orchestration platform;
- replace security, legal, capacity or architecture review.

See [product scope](docs/product/scope.md) for the complete boundary.

## Documentation

Start at the [documentation index](docs/README.md). Important documents include:

- [Vision and principles](docs/vision.md)
- [Product scope](docs/product/scope.md)
- [System architecture](docs/architecture/system-overview.md)
- [Domain model](docs/architecture/domain-model.md)
- [Planning pipeline](docs/architecture/planning-pipeline.md)
- [Catalog design](docs/catalogs/README.md)
- [Security model](docs/architecture/security.md)
- [Auditing model](docs/architecture/auditing.md)
- [Roadmap](docs/roadmap.md)
- [Architectural decisions](docs/adr/README.md)

## Development

The v0 implementation is written in Go and pins its toolchain through `go.mod`.

```bash
make check
go run ./cmd/yara version
go run ./cmd/yara request validate docs/examples/platform-request.yaml \
  --audit-output request-validation.audit.jsonl
go run ./cmd/yara inventory validate docs/examples/inventory.yaml
go run ./cmd/yara catalog validate catalog/v0.2/snapshot.yaml \
  --audit-output catalog-validation.audit.jsonl
go run ./cmd/yara catalog coverage create \
  --catalog catalog/v0.2/snapshot.yaml \
  --evidence-dir catalog/v0.2/evidence \
  --name catalog-v0.2-coverage \
  --output .yara/catalog-v0.2-coverage.yaml \
  --audit-output .yara/audit/catalog-v0.2-coverage.jsonl
go run ./cmd/yara plan create \
  --request docs/examples/v0.2-platform-request.yaml \
  --inventory docs/examples/v0.2-inventory.yaml \
  --catalog catalog/v0.2/snapshot.yaml \
  --output plan.yaml \
  --audit-output audit.jsonl
go run ./cmd/yara render docker-compose \
  --plan plan.yaml \
  --catalog catalog/v0.2/snapshot.yaml \
  --name reference-stack \
  --output reference-stack.bundle.yaml \
  --audit-output reference-stack.render.audit.jsonl
go run ./cmd/yara render kubernetes-gitops \
  --plan plan.yaml \
  --catalog catalog/v0.2/snapshot.yaml \
  --name reference-stack \
  --output reference-stack.kubernetes.bundle.yaml \
  --audit-output reference-stack.kubernetes.render.audit.jsonl
go run ./cmd/yara bundle validate reference-stack.bundle.yaml
go run ./cmd/yara bundle validate reference-stack.kubernetes.bundle.yaml
go run ./cmd/yara target preflight kubernetes \
  --bundle reference-stack.kubernetes.bundle.yaml \
  --name reference-stack-preflight \
  --output reference-stack.preflight.yaml \
  --audit-output reference-stack.preflight.audit.jsonl
go run ./cmd/yara target-preflight validate reference-stack.preflight.yaml
go run ./cmd/yara audit verify reference-stack.preflight.audit.jsonl
go run ./cmd/yara plan diff docs/examples/platform-plan.yaml plan.yaml \
  --audit-output plan-diff.audit.jsonl
go run ./cmd/yara debug bundle \
  --plan docs/examples/platform-plan.yaml \
  --output debug-bundle.json \
  --audit-output debug-bundle.audit.jsonl
go run ./cmd/yara scenario validate \
  scenarios/v0.1/private-chat-coding/scenario.yaml \
  --audit-output scenario-validation.audit.jsonl
go run ./cmd/yara scenario validate-all scenarios/v0.1 \
  --audit-output v0.1-scenario-suite.audit.jsonl
go run ./cmd/yara contract preflight \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-rtx4090 \
  --target user@host \
  --name rtx4090-preflight \
  --output contract-result.yaml \
  --audit-output contract-preflight.audit.jsonl
go run ./cmd/yara contract runtime-smoke \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-runtime-smoke \
  --output gb10-runtime-smoke.yaml \
  --audit-output gb10-runtime-smoke.audit.jsonl
go run ./cmd/yara contract model-inference \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-model-inference \
  --output gb10-qwen-coder-model-inference.yaml \
  --audit-output gb10-qwen-coder-model-inference.audit.jsonl
go run ./cmd/yara contract capacity-boundary \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-capacity-boundary \
  --output gb10-qwen-coder-capacity-boundary.yaml \
  --audit-output gb10-qwen-coder-capacity-boundary.audit.jsonl
go run ./cmd/yara contract policy \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-policy \
  --output gb10-qwen-coder-policy.yaml \
  --audit-output gb10-qwen-coder-policy.audit.jsonl
go run ./cmd/yara contract lifecycle \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-lifecycle \
  --output gb10-qwen-coder-lifecycle.yaml \
  --audit-output gb10-qwen-coder-lifecycle.audit.jsonl
```

Currently implemented:

- strict YAML and JSON decoding with unknown-field and input-size protection;
- semantic validation for the first `PlatformRequest` and `Inventory` boundary;
- stable machine-readable diagnostics and CLI exit classes;
- public draft-2020-12 schemas for request, inventory, catalog manifests, plan and audit events;
- deterministic SHA-256 content digests;
- append-only audit-event chaining, tamper verification and `audit verify` CLI support;
- a frozen placeholder catalog for v0.1 acceptance plus a curated v0.2 snapshot with ten real components, two immutable model snapshots, three NVIDIA Ada profiles, one GB10 coherent-unified-memory profile, six selectable serving candidates and two knowledge-only GB10 hypotheses;
- open-world compatibility governance where explicit negative evidence overrides positive claims and conflicts are quarantined;
- a deterministic, content-addressed catalog coverage report that accepts only exact-catalog contract results with verified adjacent audit chains and exposes every missing promotion gate;
- a strict component/topology integration result contract whose validation audit cannot be mistaken for execution evidence;
- a pure versioned Docker Compose renderer for the exact LiteLLM/vLLM topology, producing pinned files, artifact/license inventory, checks, limitations and a fail-closed render audit;
- a catalog-authored abstract topology template resolved into gateway and inference component instances;
- mandatory manifest ownership and provenance with deterministic snapshot-time freshness gates;
- a deterministic planner that applies asserted hardware compatibility and memory/policy constraints before scoring;
- independently validated multi-component `PlatformPlan` output with interface connections, dependency-safe deployment stages, explanations, rejected alternatives, explicit search bounds, ordinal confidence factors, governance diagnostics and content integrity;
- deterministic, content-addressed `PlatformPlanDiff` output with provenance causes, decision references and conservative review/redeploy/destructive impact classification;
- targeted `plan explain --decision` output with stable missing-decision diagnostics and optional fail-closed audit evidence bound to the exact explanation digest;
- deterministic, content-addressed `DebugBundle` output containing only an inspectable redacted plan summary, section inventory and successful secret-scan assertion;
- a content-addressed `GoldenScenario` contract and offline validator for exact inputs, plan identity, required decisions, forbidden outcomes, diagnostics and review requirements;
- a bounded, deterministic ten-case acceptance-suite validator with duplicate-identity rejection, planned/infeasible coverage and fail-closed audit evidence;
- a content-addressed `ContractTestResult` across read-only SSH preflight, isolated runtime smoke, bounded model inference, exact advertised-context boundary, serving-container policy and same-version restart lifecycle testing;
- tamper-evident audit chains for validation plus successful, infeasible and input-rejected planning outcomes, containing available input identities and stable diagnostic codes, including material warnings;
- optional fail-closed validation, plan-explanation and plan-diff audit receipts, plus mandatory fail-closed persistence for `plan create` and `debug bundle`, with path- and payload-minimized evidence for resources that cannot be decoded.

Selectable software, model, hardware and compatibility manifests in v0.2 remain explicitly `experimental`; their warning caps recommendation confidence and is preserved in generated plans and audit evidence. Researched suite components that lack YARA contract tests remain `known` and cannot be selected. Ten technically conformant v0.1 golden scenarios exist—seven planned and three infeasible—with approved `ScenarioReview` and `AcceptanceGateReview` resources counted by the CLI. Run `yara scenario validate-all scenarios/v0.1` to confirm `releaseEligible: true`. See the [v0.1 acceptance ledger](docs/implementation/v0.1-acceptance-status.md) and the [v0.2 catalog notes](catalog/v0.2/README.md).

## Project status

YARA is pre-alpha. Validation and audit commands are working foundations, not a platform recommendation or deployment product. Proposed integrations and catalog examples remain illustrative until backed by manifests, tests and maintained compatibility evidence.

## Contributing

Early contributions should improve falsifiability: clearer requirements, counterexamples, schemas, compatibility evidence, test scenarios and small proof-of-concept implementations. Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes.

## License

YARA is licensed under the [Apache License 2.0](LICENSE). Third-party software selected or managed by YARA retains its own license; catalog inclusion never changes or supersedes that license.
