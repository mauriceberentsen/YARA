# YARA

> **Your AI Runtime Architect** — turn hardware, goals and policy constraints into an explainable, reproducible AI-platform plan.

YARA is an open-source project for designing and, eventually, operating a suitable AI platform from a user's desired outcomes. Instead of asking users to assemble inference servers, gateways, user interfaces, data stores, identity providers and observability tools themselves, YARA will reason about the environment and propose a compatible stack.

YARA is currently in its **design and validation phase**. It does not deploy a production platform yet. The first milestone is a deterministic planner that produces a validated plan and explains every material decision.

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

## Project status

YARA is pre-alpha. The current repository is a design contract for the implementation, not evidence of a working product. Proposed integrations and catalog examples are illustrative until backed by manifests, tests and maintained compatibility evidence.

## Contributing

Early contributions should improve falsifiability: clearer requirements, counterexamples, schemas, compatibility evidence, test scenarios and small proof-of-concept implementations. Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes.

## License

YARA is licensed under the [Apache License 2.0](LICENSE). Third-party software selected or managed by YARA retains its own license; catalog inclusion never changes or supersedes that license.
