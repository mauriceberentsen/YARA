# Golden scenarios

Golden scenarios are executable, content-addressed review cases for the v0.1 planner. They pin exact request, inventory and catalog digests and state the expected outcome, plan identity, required decisions, required selections, forbidden selections, diagnostic codes and independent-review requirements.

Validate the complete v0.1 suite offline:

```bash
go run ./cmd/yara scenario validate-all scenarios/v0.1 \
  --audit-output v0.1-scenario-suite.audit.jsonl
```

Use `scenario validate <file>` for one case. Technical conformance is not expert approval. When an approved `review.yaml` is present beside the scenario, single-scenario validation reports `independentReview.status: complete` and `releaseEligible: true` for that scenario.

The v0.1 acceptance criterion requires at least ten representative, reviewed expected-plan fixtures. This directory contains ten technically conformant scenarios with approved `review.yaml` resources and paired human-readable `review.md` narratives. Additional gate reviews live under [docs/implementation/reviews/](../docs/implementation/reviews/).

## v0.1 scenario matrix

| Scenario | Expected outcome | Primary boundary exercised |
|---|---|---|
| `airgapped-coding-low-concurrency` | planned | air-gapped coding with conservative concurrency |
| `concurrency-capacity-exceeded` | infeasible | peak concurrency exceeds the supported local capacity model |
| `connected-chat-evaluation` | planned | connected evaluation profile without weakening policy constraints |
| `custom-objectives-mixed` | planned | deterministic mixed chat/coding objective scoring |
| `insufficient-vram` | infeasible | allocatable accelerator memory is a hard constraint |
| `local-chat-small` | planned | smallest local chat path with verified driver state |
| `local-coding-team` | planned | team coding request within the supported boundary |
| `private-chat-coding` | planned | baseline private chat and coding topology |
| `production-mixed-verified-driver` | planned | production intent with explicitly verified driver state |
| `unasserted-accelerator` | infeasible | unknown hardware compatibility fails closed |

## Directory contract

```text
scenarios/
  REVIEWING.md
  v0.1/
    <scenario-name>/
      scenario.yaml
      review.yaml
      review.md
```

Scenario paths are resolved relative to `scenario.yaml`. Fixtures may initially reference repository examples, but anonymized real-user cases should become self-contained once accepted for review.
