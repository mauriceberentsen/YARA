# Recommendation engine

## Purpose

The recommendation engine chooses among feasible alternatives after the rule engine has eliminated invalid candidates. It must expose trade-offs rather than hide them behind a single unexplained rank.

## Constraints versus objectives

Hard constraints are binary and run first. Examples include insufficient memory, forbidden licenses, missing interfaces and required air-gap compatibility.

Objectives rank only feasible candidates. Initial dimensions are:

- task quality;
- latency;
- throughput;
- acquisition and operating cost;
- operational simplicity;
- energy use;
- maintainability/project health;
- evidence confidence.

Security and mandatory compliance are not soft objectives. They cannot be traded for speed or quality.

## Objective profile

The request chooses a preset or explicit weights. Presets are versioned policy data, for example:

```yaml
objectives:
  preset: balanced
  weights:
    quality: 0.30
    latency: 0.15
    throughput: 0.10
    cost: 0.10
    simplicity: 0.20
    energy: 0.05
    evidenceConfidence: 0.10
```

Weights sum to one after validation. If a user declares a service objective such as p95 latency below a threshold, it becomes a constraint; merely preferring lower latency remains an objective.

## Scoring process

1. Group candidates that satisfy the same required capability contract.
2. Calculate raw metrics or ordinal evidence within validity bounds.
3. Normalize metrics using a versioned method appropriate to the dimension.
4. Penalize uncertainty explicitly rather than filling missing values with an average.
5. Apply bounded preference rules.
6. Produce an objective vector and weighted utility score.
7. Compute the Pareto frontier.
8. Select the highest utility option with deterministic tie-breaking.
9. Preserve materially different Pareto alternatives for review.

## Missing data

Missing evidence is not zero quality and not average quality. Depending on policy, it causes:

- ineligibility for a supported plan;
- an uncertainty interval and confidence penalty;
- an experimental label requiring approval;
- a question requesting a user-supplied benchmark.

The output must distinguish a poor measured result from an unknown result.

## Model and stack selection

Model choice cannot be scored independently of its serving configuration. The candidate unit is a combination of:

- model artifact and quantization;
- inference runtime and version;
- accelerator/driver target;
- context and concurrency assumptions;
- parallelism/offload configuration;
- gateway/API contract;
- lifecycle and artifact availability.

Likewise, component selection considers topology-level effects. A individually high-scoring database may lose because it duplicates state, lacks an offline artifact or increases operational roles.

## Capacity estimates

Capacity calculations return ranges:

```text
estimated accelerator memory = weights + runtime overhead
                             + concurrent context cache
                             + safety headroom
```

Methodology and inputs appear in the decision. Benchmarks measured outside the candidate's relevant context or concurrency range cannot support precise service objectives.

## Explanations

A recommendation explanation answers:

- What was selected?
- Which requirements made it eligible?
- Which facts most affected the ranking?
- Which alternatives were close?
- Why were apparent alternatives rejected?
- Which assumptions or low-confidence facts matter?
- What change in input would likely change the answer?
- How can an expert override the choice?

Example structure:

```text
Selected: runtime-a/model-x-q4
Because: fits 24 GiB with 20% headroom; supports required API; verified offline artifact
Preferred over: runtime-b/model-y because operational simplicity weight is 0.30
Trade-off: model-y has higher measured coding quality but lower evidence confidence
Would change if: expected concurrent contexts increases above 6
```

## Avoiding false optimization

YARA does not claim a global optimum. Catalog coverage is incomplete, workload data is uncertain and quality metrics are context-dependent. Output uses "preferred among evaluated supported candidates" and includes the pinned catalog, exact serving-candidate counts, completion/truncation state and declared search boundaries. v0.1 also reports ordinal confidence using the least-confident evidence/method factor; it does not manufacture a percentage from missing benchmark data.

## Future learning

Observed metrics may improve estimates only through a governed evidence pipeline. Runtime observations are never fed directly into production rules. They are anonymized or kept local, reviewed, bounded to an environment, versioned and introduced through a new catalog snapshot.
