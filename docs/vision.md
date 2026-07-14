# Vision and principles

## Mission

YARA helps people obtain a suitable, maintainable AI platform without requiring them to become experts in every component underneath it.

Its central transformation is:

```text
goals + workload + hardware + policies + budget
                         ->
explainable architecture + reproducible plan + lifecycle intent
```

Long term, YARA should be able to execute and continuously reconcile that plan. Near term, it must first prove that it can produce useful and trustworthy plans.

## User outcomes

YARA is successful when a user can answer outcome-oriented questions such as:

- What do you want to do: chat, coding, RAG, agents, image or voice?
- Who will use it and how many requests may be concurrent?
- What hardware and connectivity are available?
- Which data, licensing, identity and audit policies apply?
- Which objective matters most: quality, latency, throughput, cost, simplicity or energy use?

The user should not need to choose an inference engine, vector database or deployment topology unless they deliberately override the recommendation.

## Design principles

### Desired state before implementation detail

User intent is represented separately from selected products and rendered deployment artifacts. This prevents a preferred tool from shaping the problem statement.

### Constraints before preferences

Security, compatibility, licensing and capacity constraints eliminate invalid candidates. Preferences only rank the remaining valid options. A high score can never compensate for a hard policy violation.

### Explainability is part of correctness

A plan without reasons is incomplete. Each important selection, rejection, warning and assumption must be traceable to input facts, catalog evidence and planner logic.

### Auditability is a foundation, not an add-on

Planning, policy resolution, approval, execution and lifecycle operations create durable audit evidence tied to immutable resource digests. Audit records capture who or what acted, what changed, why, under which policy and with what outcome, without copying secrets or unnecessary sensitive payloads.

### Deterministic core, evidence-based inputs

For identical versioned inputs and catalog snapshots, the core planner produces an identical semantic result. Probabilistic systems may help curate data or summarize explanations, but they are not authoritative decision makers in the planning path.

### Hardware-aware, not hardware-determined

Hardware bounds what can run locally, but user policy and workload may make a remote provider, smaller model or different capability set preferable. Hardware is a first-class constraint, not the only input.

### Prefer integration over reimplementation

YARA composes mature open-source software through stable interfaces. It owns planning, integration contracts and lifecycle coordination, not replacements for every underlying tool.

### Reproducibility over freshness by surprise

A plan pins catalog and component versions. New upstream releases do not silently change an existing environment. Freshness is offered through an explicit re-plan and upgrade workflow.

### Safe failure over plausible output

When facts are missing, stale or contradictory, YARA emits an error, question or low-confidence warning. It must not invent hardware capacity, licenses, compatibility or benchmark results.

### Progressive disclosure

The default path asks few questions and chooses documented defaults. Experts can inspect evidence, compare alternatives and override choices without forking YARA.

### Lifecycle completeness

Selection criteria include operability: health checks, upgrade paths, backup, restore, observability and retirement. A component that is easy to install but unsafe to operate is not a good default.

## Product qualities

YARA optimizes for these qualities in order:

1. Safety and policy compliance.
2. Technical compatibility.
3. Reproducibility and explainability.
4. Fitness for the requested workload.
5. Operational simplicity.
6. Performance and cost objectives chosen by the user.
7. Breadth of supported integrations.

The ordering is intentional. Supporting more software is less valuable than making a smaller catalog reliable.

## What YARA must not become

- A collection of unversioned install scripts.
- A catalog that confuses popularity with suitability.
- A benchmark leaderboard presented as universal truth.
- A thin user interface around hard-coded product combinations.
- A system that sends inventory or workload data to third parties by default.
- A deployment engine that bypasses review and change control.
- A promise that complex enterprise architecture can be made risk-free.

## Long-term north star

A mature YARA can discover an environment, propose several feasible architectures with explicit trade-offs, produce an approved plan, apply it through replaceable executors, observe drift and performance, and recommend safe changes over the full platform lifecycle. Each stage remains inspectable and can be used independently.
