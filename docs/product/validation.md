# Product validation

## Purpose

YARA's largest early risk is not implementation difficulty; it is building a sophisticated planner that users do not trust or need. Validation therefore precedes broad catalog and deployment work.

## Hypotheses

| ID | Hypothesis | Evidence needed |
|---|---|---|
| H1 | Choosing a coherent stack is a recurring, costly problem | At least 10 target users describe recent concrete selection work |
| H2 | A generated plan saves meaningful research time | Users complete a scenario faster than their current process |
| H3 | Explanations create sufficient trust to act | Reviewers can identify and challenge the plan's assumptions |
| H4 | A curated narrow catalog is useful | Users prefer reliable coverage over a large unverified list |
| H5 | Users will maintain declarative requests in version control | Pilot users rerun or modify saved requests |
| H6 | Lifecycle planning is valued beyond installation | Users prioritize upgrades, backup or observability in interviews |

## Validation sequence

### 1. Problem interviews

Interview platform engineers, AI engineers and advanced self-hosters. Ask about a recent deployment, decisions made, evidence used, mistakes, time spent and ongoing maintenance. Do not start by pitching YARA.

Exit signal: the same high-cost decisions recur across several users and at least one initial segment is identifiable.

### 2. Manual plan service

Collect a structured request and manually return the proposed `PlatformPlan` format. This validates input questions and explanation value before implementing the engine.

Measure:

- questions users cannot answer;
- facts the schema fails to collect;
- recommendations users reject and why;
- review time and confidence;
- whether users would use the plan in a real proof of concept.

### 3. Golden scenarios

Convert reviewed cases into anonymized `GoldenScenario` fixtures. Each scenario pins exact input digests, expected selections and plan identity, forbidden outcomes, required diagnostics and independent-review roles. `scenario validate` proves technical conformance offline but always keeps review and release status pending until separate human evidence exists.

### 4. Planner prototype

Implement only enough rules and catalogs to satisfy the golden scenarios. Have independent experts review explanations rather than only output component names.

### 5. Deployment concierge

Before building a generic executor, manually help a small number of users apply a generated plan. Record every step that is environment-specific, unsafe to automate or missing from the plan.

## Metrics

Early metrics:

- percentage of input questions users can answer;
- unsafe recommendation count;
- expert agreement or acceptable-alternative rate;
- explanation challenge rate;
- plan generation determinism;
- catalog evidence coverage and freshness;
- time from request to approved plan;
- number of plans actually used in a proof of concept.

Avoid vanity metrics such as raw catalog entry count, generated plans without review, GitHub stars or supported logos.

## Stop or pivot conditions

Reconsider the approach if:

- users primarily want a fixed turnkey stack rather than recommendations;
- hardware and workload evidence is too weak for useful capacity guidance;
- experts consistently disagree in ways the objective model cannot express;
- maintaining compatibility data costs more than the value users perceive;
- users will not provide the inventory or workload information required;
- explanations remain too complex for users to review.

Possible pivots include a narrower compatibility linter, a catalog/evidence product, or one opinionated reference distribution.
