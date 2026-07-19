# Architectural decision records

ADRs preserve significant decisions and their rationale. Accepted ADRs describe current direction; proposed ADRs are open for review. A later decision supersedes an accepted ADR rather than editing its history.

## Index

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-declarative-request-and-platform-plan.md) | Accepted | Separate declarative intent from an immutable platform plan |
| [0002](0002-separate-planning-rendering-and-execution.md) | Accepted | Separate planner, renderer and executor |
| [0003](0003-git-versioned-manifests-for-v0.md) | Accepted | Use Git-versioned manifests instead of a graph database in v0 |
| [0004](0004-deterministic-explainable-planning-core.md) | Accepted | Keep the authoritative planning core deterministic and explainable |
| [0005](0005-narrow-v0-1-support-boundary.md) | Accepted | Start with a narrow local NVIDIA/chat/coding planning boundary |
| [0006](0006-offline-pure-planner.md) | Accepted | Prohibit network access and mutation in the planner |
| [0007](0007-auditing-is-a-core-domain-capability.md) | Accepted | Treat append-only auditing as a core domain capability |
| [0008](0008-use-go-for-the-v0-cli-and-core.md) | Accepted | Use Go for the v0 CLI and planning core |
| [0009](0009-docker-compose-reference-renderer-prototype.md) | Proposed | Prototype a pure Docker Compose reference renderer before executor selection |

Use [0000-template.md](0000-template.md) for new records.

## When an ADR is required

- public schema or domain boundary changes;
- a persistent dependency or storage choice;
- a trust, security or determinism change;
- selection of a deployment target or extension mechanism;
- a decision difficult or expensive to reverse.
