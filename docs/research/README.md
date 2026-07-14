# Research and evidence

Research documents are temporary inputs to catalog assertions and decisions. They are not authoritative merely because they are in the repository.

## Research note template

```markdown
# Question

Status: open | concluded | superseded
Owner:
Reviewed:

## Decision/use case affected

## Hypothesis

## Environment and versions

## Method

## Sources

## Results

## Limitations and counterevidence

## Proposed catalog assertions or ADR
```

## Rules

- State the decision the research can affect.
- Pin software, model, driver and hardware versions.
- Preserve raw measurements outside prose where licensing/privacy permits.
- Distinguish upstream documentation, reproduced test and inference.
- Record failed experiments and negative evidence.
- Never convert one environment's benchmark into a universal model property.
- Move lasting architectural rationale into an ADR and volatile facts into catalog manifests.
