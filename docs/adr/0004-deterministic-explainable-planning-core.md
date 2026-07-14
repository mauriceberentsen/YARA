# ADR-0004: Keep the authoritative planner deterministic and explainable

- Status: Accepted
- Date: 2026-07-14
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

AI platform selection involves incomplete evidence and natural-language requirements, making an LLM-based architect tempting. However, probabilistic output is difficult to reproduce, validate, audit and safely constrain.

## Decision

The authoritative planning path uses typed facts, declarative rules, bounded deterministic algorithms and versioned evidence. Every material outcome has a structured reason chain. LLMs may assist users or catalog maintainers outside the authoritative path, but their output is treated as untrusted input requiring validation.

## Consequences

### Positive

- Identical versioned inputs reproduce semantic output.
- Constraints and policy can be tested with counterexamples.
- Users can audit and override recommendations.
- Offline operation does not require a model.

### Negative

- More domain modeling and curation are needed.
- Natural-language requests require a separate confirmation step.
- The system may cover new ecosystem changes less quickly than generative advice.

### Neutral / follow-up

- An optional assistant can propose a `PlatformRequest`, but users must review the structured resource.
- Determinism does not mean estimates are certain; confidence remains explicit.

## Alternatives considered

### LLM generates the architecture directly

Flexible and quick to prototype but can invent compatibility, ignore policy and change output without traceable evidence.

### LLM plus post-validation

Validation reduces some risk, but the search/ranking logic remains difficult to reproduce and explain. It may be explored as a candidate generator only after the deterministic core is mature.

## Validation

CI checks semantic determinism, decision coverage and rule counterexamples. Any probabilistic subsystem must prove that disabling it preserves authoritative plan correctness.
