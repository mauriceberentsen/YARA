# Platform plan

## Role

`PlatformPlan` is YARA's intermediate representation. It decouples planning from deployment technology, makes review possible before mutation and preserves the evidence behind an environment.

## Required properties

A plan MUST be:

- schema-versioned;
- immutable and content-addressable;
- deterministic in semantic content;
- free of plaintext secrets;
- complete enough for a renderer without re-running recommendations;
- explicit about assumptions, uncertainty and unsupported areas;
- independently validatable;
- traceable to exact request, inventory, policy, catalog and engine versions.

## Structure

Illustrative outline:

```yaml
apiVersion: yara.dev/v1alpha1
kind: PlatformPlan
metadata:
  name: private-coding-assistant
  planId: sha256:...
  supersedes: null
provenance:
  requestDigest: sha256:...
  inventoryDigest: sha256:...
  policyDigest: sha256:...
  catalogDigest: sha256:...
  plannerVersion: 0.1.0
spec:
  status: review-required
  objectives: {}
  assumptions: []
  topology:
    instances: []
    connections: []
    deploymentStages: []
  allocations: []
  configurationIntent: []
  artifacts: []
  secretReferences: []
  lifecycle: {}
  decisions: []
  alternatives: []
  diagnostics: []
```

The exact schema will be established before implementation; examples in documentation are not yet normative fixtures.

## Instance model

Each instance records:

- stable plan-local ID and role;
- component/model catalog reference and immutable version;
- supplied and consumed interface contracts;
- placement and resource requests/limits;
- non-secret configuration intent;
- artifact digests and origin;
- health, backup and upgrade contract references;
- dependencies and startup stage;
- selected exposure and trust zone.

## Connections and data flows

Connections are explicit, typed edges. They identify protocol/interface, source, destination, authentication mode, encryption requirement, data classifications and network scope. This supports policy validation and future network rendering without embedding target-specific YAML.

## Configuration intent

The plan stores typed intent such as "OIDC issuer reference" or "disable upstream telemetry," not arbitrary generated configuration blobs. Renderers map intent to a supported component/version adapter. Unknown intent is a renderer error, not something to ignore.

## Secrets

Plans contain only typed references, for example:

```yaml
secretRef:
  provider: environment
  name: oidc-client-secret
  key: value
```

Providers and references are validated during preflight. Secret values are neither hashed into the plan nor written to diagnostic output.

## Decisions and alternatives

Material decisions are structured resources, not prose only. Each selected instance and topology choice links to one or more decisions. Alternatives are retained when they are:

- on the Pareto frontier;
- close to the selected weighted score;
- explicitly preferred by the user but rejected;
- useful remediation for a warning;
- architecturally distinct.

## Status

Suggested states:

- `invalid` — emitted only with diagnostics, cannot be rendered;
- `review-required` — valid but assumptions, warnings or policy require review;
- `approved` — separate approval resource binds reviewer to the exact digest;
- `superseded` — a newer desired plan exists;
- `retired` — no longer intended to be active.

Approval is not implemented by editing `status` in the plan. It is an external signed record referencing the immutable plan ID.

## Semantic diff

A plan diff classifies changes:

- no-op/presentation only;
- configuration update;
- artifact or version upgrade;
- scale or placement change;
- stateful migration;
- security/trust-boundary change;
- destructive replacement.

Each difference links to the decisions that changed and the input/evidence change that caused it.

## Validation

Plan validation includes:

- schema and digest verification;
- no mutable artifact references;
- unique IDs and resolvable references;
- acyclic deployment graph;
- all consumed capabilities supplied;
- resource allocation within inventory budgets;
- policy constraints over full topology;
- supported renderer contracts declared;
- lifecycle requirements present for stateful instances;
- no embedded secret-like values;
- decision coverage for material selections.

## Portability boundary

The plan is portable at the architectural level, not necessarily deployable unchanged to every target. Placement describes requirements and logical zones; a renderer binds them to Compose services, Kubernetes workloads or other primitives. Target-specific features may be represented as namespaced extensions, but the core plan remains understandable without them.
