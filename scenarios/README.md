# Golden scenarios

Golden scenarios are executable, content-addressed review cases for the v0.1 planner. They pin exact request, inventory and catalog digests and state the expected outcome, plan identity, required decisions, required selections, forbidden selections, diagnostic codes and independent-review requirements.

Validate the complete v0.1 suite offline:

```bash
go run ./cmd/yara scenario validate-all scenarios/v0.1 \
  --audit-output v0.1-scenario-suite.audit.jsonl
```

Use `scenario validate <file>` for one case. Technical conformance is not expert approval. A successful suite reports `independentReviewStatus: required` and `releaseEligible: false`. Review evidence is deliberately separate from the scenario so expectations cannot be edited and silently retain approval.

The v0.1 acceptance criterion requires at least ten representative, reviewed expected-plan fixtures. This directory contains ten technically conformant scenarios—seven planned and three infeasible—and zero completed independent reviews. See [REVIEWING.md](REVIEWING.md) before proposing or reviewing a scenario and the [acceptance ledger](../docs/implementation/v0.1-acceptance-status.md) for all remaining gates.

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
      review.md
```

Scenario paths are resolved relative to `scenario.yaml`. Fixtures may initially reference repository examples, but anonymized real-user cases should become self-contained once accepted for review.
