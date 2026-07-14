# Contributing to YARA

YARA is currently design-first and pre-alpha. Contributions are welcome, but new integrations should follow a validated use case rather than expand the catalog for its own sake.

## Ways to contribute

- Provide a concrete anonymized deployment scenario.
- Challenge an architectural assumption with a counterexample.
- Improve schemas, terminology or decision explanations.
- Add catalog evidence with provenance and freshness metadata.
- Add validation, referential-integrity or golden-plan tests.
- Prototype a narrow interface described in the architecture.

## Before opening a change

1. Read the [documentation index](docs/README.md) and [scope](docs/product/scope.md).
2. Search existing ADRs and proposals.
3. For a large or irreversible change, open a design discussion before implementation.
4. Keep the change focused; avoid mixing catalog expansion with architecture changes.

## Design contribution rules

- Define the user scenario and failure mode first.
- Separate facts, constraints, preferences and decisions.
- Do not introduce hidden network access or telemetry.
- Preserve deterministic behavior for identical versioned inputs.
- Include a reason chain for new planner behavior.
- Treat unknown critical data as unknown, never as a convenient default.
- Add a counterexample for each hard selection rule.
- Put volatile upstream facts in manifests, not application code or prose.

## Catalog contributions

A catalog entry must include provenance, last verification time, confidence, ownership state and license information where applicable. "Works on my machine" is useful evidence but not enough for a supported compatibility claim. See [catalog requirements](docs/catalogs/README.md).

## Architectural decisions

Use [the ADR template](docs/adr/0000-template.md) when a proposal:

- changes a public schema or system boundary;
- introduces a dependency or extension mechanism;
- changes determinism, trust or security properties;
- selects one deployment strategy over another;
- is costly to reverse.

ADRs describe why a decision was made. Do not rewrite accepted ADR history; supersede it with a new ADR.

## Documentation and tests

Changes must update affected documentation. Once implementation begins, planner behavior requires:

- unit tests for rules and scoring;
- schema tests for inputs and outputs;
- golden scenarios for semantic plan output;
- negative tests for constraints and unsafe combinations;
- deterministic output tests;
- migration tests for public schema changes.

## Commit and review guidance

- Use clear imperative commit subjects.
- Explain risk and validation in the pull request.
- Call out unverified assumptions explicitly.
- Never add secrets, private inventory, proprietary benchmark data or model artifacts to the repository.

## Code of conduct and security

A code of conduct and private vulnerability reporting process must be added before inviting broad public contributions. Until then, do not disclose suspected vulnerabilities in public issues.
