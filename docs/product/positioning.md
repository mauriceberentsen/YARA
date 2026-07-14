# Product positioning

## Category

YARA is an **AI platform planner and lifecycle orchestrator**. "AI platform compiler" is a useful metaphor: YARA compiles a declarative request into an intermediate platform plan, which later backends can render and apply. It is not a literal compiler and should not be marketed as proving mathematical optimality.

## Primary users

### Platform engineer

Needs a reviewable starting architecture, reproducible configuration and integration guidance. Values APIs, policy enforcement, Git workflows and debuggable output.

### AI or ML engineer

Needs suitable models, serving runtimes and supporting capabilities without becoming an infrastructure specialist. Values performance evidence and quick experiments.

### Infrastructure generalist or homelab operator

Needs a coherent stack that fits known hardware. Values sensible defaults, a local-first path and low operational burden.

### Security or architecture reviewer

Needs provenance, data-flow boundaries, policy evidence, licenses and a clear explanation of why components were selected.

YARA initially optimizes for a technical operator who can review YAML and run a CLI. A non-technical wizard is a later interface, not an early architectural dependency.

## Jobs to be done

- Assess what AI workloads are feasible on an environment.
- Compare architectures without manually researching every integration.
- Produce a consistent plan that can be reviewed before mutation.
- Enforce organizational constraints during selection.
- Explain capacity and quality trade-offs.
- Preserve the reasoning behind an environment for later upgrades.
- Identify when a requested outcome is infeasible or underspecified.

## Alternatives

YARA overlaps with several categories but does not replace them:

| Alternative | Strength | Gap YARA addresses |
|---|---|---|
| Helm charts and Compose bundles | Repeatable deployment of a known stack | They generally assume the stack is already chosen |
| Kubernetes distributions | Cluster provisioning and operations | They do not model AI use cases or model fit |
| AI web UIs | Immediate end-user experience | They are one component, not an architecture planner |
| Model launchers | Simple local model execution | Limited cross-component, policy and lifecycle reasoning |
| Cloud AI platforms | Integrated managed experience | May conflict with local, portable or air-gapped requirements |
| Architecture consulting | Deep contextual judgment | Expensive, hard to reproduce and difficult to keep current |

YARA should interoperate with these tools. Its differentiator is the versioned decision model connecting user intent to a whole-platform plan.

## Value hypothesis

The core hypothesis is that users will trust and reuse a curated, explainable recommendation system enough to avoid repeated architecture research. This is unproven. The first product goal is therefore not maximum integration breadth; it is evidence that a narrow planner produces recommendations experts judge useful and non-experts can understand.

## Open-source and commercial boundary

No paid edition is defined yet. Prematurely splitting core safety or explainability features would weaken adoption and trust. The initial recommendation is:

- keep schemas, catalogs, planner, explanations and local execution open source;
- validate demand before choosing a business model;
- consider paid support, certified catalog channels, managed updates, enterprise policy packs or hosted coordination only if users request them;
- never make a generated plan dependent on an opaque proprietary scoring rule.

Any future commercial boundary requires a separate public decision record.

## Messaging

Preferred concise description:

> YARA turns your AI goals, hardware and policies into an explainable platform plan.

Claims to avoid before they can be demonstrated:

- "the best possible platform" without defining the objective;
- "production-ready" without tested operational guarantees;
- "fully automatic" where review remains necessary;
- "enterprise-grade" as a substitute for specific controls;
- exact performance or capacity without measured evidence and uncertainty.
