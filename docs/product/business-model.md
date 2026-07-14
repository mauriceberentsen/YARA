# Business model and project sustainability

## Current decision

YARA begins as an Apache-2.0 open-source project. There is no paid tier, pricing promise or feature split yet. The immediate objective is to validate that users trust and act on explainable plans.

Choosing a business model before that evidence would optimize packaging around an unproven product.

## What must remain trustworthy

Any future commercial model should preserve:

- open request and plan schemas;
- inspectable planner rules and explanations;
- local/offline planning;
- portability of plans and catalog data;
- core security and policy enforcement;
- the ability to reproduce a plan without a paid service.

Safety, explainability and export are poor paywalls because restricting them weakens the product's credibility.

## Candidate revenue streams

### Support and implementation

Paid architecture review, onboarding and supported deployment paths can produce revenue before a large user base exists. It does not scale as well as software, but it generates direct product evidence.

Validation signal: users request help applying a plan or maintaining a reference environment.

### Certified catalog channel

A subscription could provide signed, frequently tested compatibility snapshots, security response and longer support windows while the community catalog remains open.

Validation signal: organizations value evidence freshness and accountability enough to pay for it.

### Managed coordination plane

A hosted or self-hosted enterprise service could manage organization policy, catalog channels, approvals, fleet inventory and lifecycle operations. Local planners and executors would remain usable independently.

Validation signal: multiple environments or teams create real coordination pain.

### Enterprise policy and integration packs

Maintained integrations for identity, private registries, secrets, audit and change management may support subscriptions or contracts.

Validation signal: repeated demand for the same enterprise integration and a sustainable test matrix.

### Training and reference material

Workshops, courses or design reviews can monetize expertise and grow adoption without changing product licensing.

## Recommended sequence

1. Validate planning through interviews and manual plans.
2. Offer a small number of paid or free design pilots to learn what users will fund.
3. Charge for high-touch support before building a SaaS control plane.
4. Track repeated paid needs and productize only the strongest pattern.
5. Record the open/commercial boundary in an ADR before implementing it.

## Economic constraints

At approximately 10 hours per week, support promises can consume all development capacity. Early engagements should be fixed-scope, explicitly time-bounded and feed reusable fixtures or documentation where confidentiality permits.

Costs to track:

- maintainer hours per supported catalog path;
- test hardware and CI/GPU expense;
- artifact storage and bandwidth;
- security and vulnerability response;
- support time by deployment target;
- legal/license review for redistribution.

A revenue stream is unsustainable if it expands the compatibility matrix faster than it funds maintenance.

## Decision metrics

- number of plans used in real proof of concepts;
- percentage of users requesting deployment or lifecycle help;
- support hours per active environment;
- willingness to pay for freshness, accountability or coordination;
- recurring needs shared across at least three organizations;
- gross margin after test infrastructure and support time.

MRR targets should be set only after pricing interviews and a repeatable paid need. Hypothetical tier prices are not product evidence.
