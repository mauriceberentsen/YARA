# Go-to-market and public development

## Initial segment

The working segment is technical teams and advanced self-hosters evaluating private chat or coding assistants on existing local GPU hardware. This is a hypothesis to test, not a permanent market definition.

The segment is narrow enough to reach through technical communities and broad enough to produce diverse planning cases. Large regulated enterprises are valuable design partners, but a solo pre-alpha project should not promise their production support requirements.

## First offer

Before software is usable, offer a structured **AI platform plan review**:

1. User completes the draft request and inventory.
2. Maintainer produces a plan, alternatives and uncertainty manually.
3. A 45-minute review challenges assumptions and decisions.
4. With permission, the anonymized case becomes a golden scenario.

The deliverable tests YARA's core value directly. It is more useful than asking people whether they like the idea.

## Finding design partners

Look for people currently using or evaluating self-hosted inference, private coding assistants, AI gateways or local GPU servers. Reach them through existing professional network, relevant open-source discussions and narrowly focused technical posts.

Outreach should ask about a recent decision rather than advertise a universal platform:

> I am researching how teams choose a private AI stack for their actual hardware and policies. Could I learn how you made your last model/runtime/deployment decision? I can return a documented alternative architecture for comparison.

## Content strategy

Publish evidence from building the planner:

- why model weight size does not equal required VRAM;
- how air-gapped dependencies hide in ordinary AI stacks;
- a transparent comparison of two architectures for one scenario;
- how a planner represents unknown compatibility;
- what failed in a reference deployment and how the catalog changed.

Avoid generic AI news, unsupported benchmark claims and long logo lists. Useful public artifacts should link back to a reproducible scenario or decision.

## Cadence

With ten hours per week:

- one substantive build/research note every one or two weeks;
- one user conversation per week during validation;
- one public demo at each milestone, even if it only generates a plan;
- monthly summary of what was learned, removed from scope and changed.

## Funnel

```text
technical evidence/content
        -> manual plan request
        -> reviewed proof of concept
        -> deployment/lifecycle support need
        -> repeatable paid offering
```

Email lists, community chat and video are optional channels, not products. Add them only when they improve the funnel and can be maintained.

## Launch criteria for v0.1

- CLI and fixtures run offline from a clean checkout.
- Limitations are prominent.
- At least five external reviewers have challenged plans.
- A short end-to-end demo shows request, inventory, plan and explanation.
- There is a clear path to submit a scenario, not just a feature request.
- Security reporting and code of conduct exist before broad promotion.

## Feedback classification

Classify incoming feedback as:

- unsafe/incorrect recommendation;
- missing input or schema concept;
- missing evidence/compatibility;
- new scenario/use case;
- deployment or lifecycle pain;
- interface/usability;
- requested paid support.

Safety and repeated missing-domain concepts outrank integration popularity.

## Avoided tactics

- Announcing dozens of integrations before tested support.
- Building four repositories, a marketplace or a community server on day one.
- Chasing stars without proof plans are used.
- Promising a production SLA as a solo pre-alpha maintainer.
- Treating content production as equal in priority to user validation.
