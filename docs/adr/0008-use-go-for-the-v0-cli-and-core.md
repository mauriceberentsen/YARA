# ADR-0008: Use Go for the v0 CLI and planning core

- Status: Accepted
- Date: 2026-07-14
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

Implementation cannot start coherently without selecting a language. YARA needs a portable offline CLI, deterministic typed domain code, reliable YAML/JSON tooling, graph/planning algorithms, good test support and future integration with container/Kubernetes ecosystems. It is initially maintained part-time by one developer.

## Decision

Implement the v0 CLI, domain model, catalog compiler, rule evaluation and planner in Go. Produce a single native CLI binary where supported. Pin the exact supported Go toolchain in `go.mod` and CI when bootstrapping, rather than encoding a volatile toolchain version in this ADR.

Core packages use the standard library where practical. Dependencies require a concrete capability, active maintenance, compatible license and review. Public contracts are resource schemas and CLI behavior, not Go package APIs.

## Consequences

### Positive

- Simple deployment as a native binary with strong cross-platform tooling.
- Static typing, fast tests and straightforward concurrency for future adapters.
- Strong fit with infrastructure, container and Kubernetes libraries.
- Low runtime operational burden for local and air-gapped use.

### Negative

- Advanced constraint solving and data-science libraries are less extensive than Python's ecosystem.
- YAML and schema discipline still require third-party libraries or generated validation.
- Go is not ideal for every future UI or benchmark workload, so those may use separate processes.

### Neutral / follow-up

- The rule language remains declarative and does not expose Go execution.
- Plugins communicate over versioned protocols and need not be written in Go.
- A solver can later run out of process if a demonstrable planning problem requires it.

## Alternatives considered

### Python

Excellent AI/data ecosystem and rapid prototyping, but packaging an offline cross-platform CLI and constraining runtime/dependency behavior are more involved.

### Rust

Strong safety and performance with excellent single binaries, but likely increases implementation time and contributor friction for the initial part-time project.

### TypeScript

Useful for a future UI and good schema tooling, but less attractive for a native offline infrastructure CLI and privileged adapters.

## Validation

The first vertical slice must build reproducibly, run offline, complete tests quickly and demonstrate readable domain/rule code. Reconsider only if a required planner capability cannot reasonably be implemented or isolated behind an adapter.
