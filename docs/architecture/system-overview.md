# System overview

## Context

YARA sits between people who specify an AI-platform outcome and tools that create or operate infrastructure.

```text
             +-------------------------+
             | User / platform team    |
             +------------+------------+
                          | request, policy, approval
                          v
  evidence +--------+  +------------------+  plan/artifacts  +--------------+
---------->| Catalog |->|       YARA       |---------------->| Deployment   |
           +--------+  +------------------+                 | targets      |
                          ^        | observations            +--------------+
                          |        v
                    +-----+-------------+
                    | Target inventory  |
                    | and runtime state |
                    +-------------------+
```

External deployment targets include a local container runtime, Kubernetes, Git repositories, identity systems, registries, storage and model sources. Each is outside YARA's trust boundary and accessed through a narrow adapter.

## Logical subsystems

### Interfaces

The CLI is the first interface. A future API and web UI use the same application services and schemas. Interfaces validate syntax, collect missing non-sensitive input and present plans; they contain no selection logic.

### Discovery

Discovery adapters inspect a target or import inventory. They emit signed or locally attested observations with source and timestamp. Discovery may be unavailable in air-gapped or remote planning, so all facts can also be declared.

### Policy loader

Combines built-in safety constraints, organization policy packs and request-specific policy. Precedence and exception rules are explicit. It emits normalized constraints, not executable code.

### Catalog service

Loads an immutable catalog snapshot, validates schemas and references, verifies provenance/signatures when configured and exposes typed queries over components, models, hardware and compatibility.

### Planner

Transforms normalized intent and facts into candidate topologies, filters invalid candidates, ranks feasible alternatives, resolves dependencies and emits a plan plus decision trace. The planner is logically pure and has no credentials for a target environment.

### Plan validator

Checks internal consistency, policy conformance, completeness, dependency acyclicity, resource budgets, interface compatibility and executor support. Validation can run independently during review or CI.

### Audit service

Creates typed, append-only evidence for planning, policy, approval and lifecycle actions. It binds actor and outcome to immutable resource digests, applies redaction before persistence and maintains integrity links. The local v0.1 implementation writes a verifiable audit chain; future services add authenticated actors, durable storage and signed checkpoints.

### Renderer

Converts an approved plan into target-specific artifacts. It may produce Compose files, Helm values or GitOps manifests, but it does not apply them. Rendering is deterministic for pinned inputs.

### Executor

Future subsystem that performs preflight, shows a change set, obtains explicit approval, applies artifacts and verifies health. It has short-lived least-privilege credentials and cannot make new architecture choices.

### Runtime manager

Future subsystem that observes plan instances, identifies drift, coordinates backups and proposes upgrades. It creates new observations and proposed plans; it never silently edits the active plan.

## Primary flows

### Plan

1. Load and schema-validate the request.
2. Acquire or import inventory.
3. Resolve policy and catalog snapshots.
4. Normalize facts and derive required capabilities.
5. Generate, constrain, rank and resolve candidates.
6. Validate resource and integration feasibility.
7. Emit plan, alternatives, diagnostics and provenance.
8. Append a terminal audit event referencing input and result digests.

### Apply (future)

1. Verify the plan signature, schema and supported renderer.
2. Resolve secret references and inspect target preconditions.
3. Render an artifact bundle and compute the change set.
4. Require approval bound to the plan and change-set hashes.
5. Apply in dependency order with checkpoints.
6. Verify declared health contracts.
7. Record an immutable deployment receipt.
8. Durably append the terminal audit event before reporting success.

### Re-plan (future)

1. Collect fresh observations without altering desired state.
2. Compare observations with assumptions and service objectives.
3. Produce recommendations or a new candidate plan.
4. Show semantic differences, risks and migration requirements.
5. Require normal review and approval before change.

## Deployment shapes

### Local mode

The CLI, catalogs and planner run on the operator's machine. No server is required. This is the v0.1 reference shape and must work offline.

### Team mode (future)

A service stores organization policies, catalog channels, requests, plans and approvals. Executors remain close to targets and pull or receive signed work. Tenant isolation and authentication become mandatory.

### Air-gapped mode

Catalog snapshots, application artifacts and model artifacts enter through a controlled import process. YARA produces an inventory of required artifacts and verifies hashes. No path assumes live internet connectivity.

## Failure philosophy

YARA distinguishes:

- **error:** plan would be invalid or unsafe; no plan is emitted as deployable;
- **question:** a required user choice or fact is missing;
- **warning:** plan is feasible but risk or uncertainty needs review;
- **advisory:** improvement that does not affect validity.

A partial diagnostic result is preferable to a confidently wrong plan. Failures include stable codes and affected input paths so interfaces and automation can respond without parsing prose.
