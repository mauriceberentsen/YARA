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
  search:
    strategy: bounded-catalog-enumeration-v1
    completeWithinBounds: true
    truncated: false
    globalOptimalityClaimed: false
    evaluatedServingCandidates: 2
    feasibleServingCandidates: 1
    rejectedServingCandidates: 1
    boundaries: [catalog-snapshot-only]
  confidence:
    level: low
    method: minimum-factor-v1
    factors:
      - id: capacity-method
        level: low
        reasonCode: YARA-CONF-004
        subjectRefs: [candidate-id]
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

This outline also shows later fields that are not yet executable. The current normative wire contract is the public JSON Schema; repository examples are executable fixtures.

## Search bounds and confidence

A successful v0.1 plan records the complete evaluation count for all serving candidates compiled from its pinned catalog snapshot. `completeWithinBounds` means that bounded candidate list was exhausted; it does not mean every possible open-source stack was considered. The plan explicitly sets `globalOptimalityClaimed: false` and lists scope limits such as the first matching topology template, single-host NVIDIA hardware and absence of live benchmark evaluation.

Recommendation confidence is ordinal rather than a misleading percentage. `minimum-factor-v1` sets the overall level to the weakest sorted factor. Current factors cover serving compatibility evidence, catalog maturity, inventory assurance and capacity methodology. Experimental catalog content, an unverified driver or the fixture-only capacity formula therefore prevents a high-confidence claim even when the selected candidate is feasible.

`YARA-CONF-*` reason codes identify why a factor has its level; they are evidence labels, not error diagnostics and cannot override hard constraints. Search and confidence fields participate in the immutable plan ID and semantic diff.

| Reason code | Current factor |
|---|---|
| `YARA-CONF-001` | Confidence of the selected serving-compatibility evidence |
| `YARA-CONF-002` | Snapshot-wide catalog lifecycle maturity |
| `YARA-CONF-003` | Assurance of the selected inventory accelerator facts |
| `YARA-CONF-004` | Validation maturity of the capacity-estimation method |

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

`yara plan explain <file>` emits the complete ordered decision list. Supplying `--decision <id>` returns exactly one structured decision, including its evidence and rejected alternatives; an unknown ID fails with `YARA-PLAN-040`. Optional audit evidence identifies the immutable plan and hashes the explanation content rather than copying potentially sensitive reasons into the event.

## Status

Suggested states:

- `invalid` — emitted only with diagnostics, cannot be rendered;
- `review-required` — valid but assumptions, warnings or policy require review;
- `approved` — separate approval resource binds reviewer to the exact digest;
- `superseded` — a newer desired plan exists;
- `retired` — no longer intended to be active.

Approval is not implemented by editing `status` in the plan. It is an external signed record referencing the immutable plan ID.

## Semantic diff

A `PlatformPlanDiff` is a versioned, content-addressed comparison result. It references the immutable old and new plan IDs, represents compared values by SHA-256 digest and records changed planner inputs as explicit causes. Fixed summaries are presentation text and therefore do not affect the semantic diff ID.

The classification vocabulary is:

- `presentation-only`;
- `provenance-change`;
- `configuration-update`;
- `artifact-or-version-upgrade`;
- `scale-or-placement-change`;
- `stateful-migration`;
- `security-or-trust-boundary-change`;
- `destructive-replacement`.

Material differences link to changed decisions where the current plan contains that relationship. Changed request, inventory, catalog or planner identities are recorded separately as causes.

The v0.1 engine currently derives presentation-only, provenance/evidence, configuration, artifact/model version, scale/placement and destructive topology changes. It treats set ordering as irrelevant and uses the highest classified impact as a review shortcut. `stateful-migration` and `security-or-trust-boundary-change` remain reserved: the engine must not emit them until the plan contains typed state and trust-boundary facts. This prevents a detailed label from overstating what the current plan can prove.

`changed: false` with `highestImpact: none` is a semantic no-op. A presentation-only diff has `changed: true` but retains `highestImpact: none`, allowing interfaces to hide it without claiming the files are byte-identical.

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
