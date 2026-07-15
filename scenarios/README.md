# Golden scenarios

Golden scenarios are executable, content-addressed review cases for the v0.1 planner. They pin exact request, inventory and catalog digests and state the expected outcome, plan identity, required decisions, required selections, forbidden selections, diagnostic codes and independent-review requirements.

Run the current scenario offline:

```bash
go run ./cmd/yara scenario validate \
  scenarios/v0.1/private-chat-coding/scenario.yaml \
  --audit-output scenario-validation.audit.jsonl
```

Technical conformance is not expert approval. A successful command reports `independentReview.status: required` and `releaseEligible: false`. Review evidence is deliberately separate from the scenario so expectations cannot be edited and silently retain approval.

The v0.1 acceptance criterion requires at least ten representative, reviewed expected-plan fixtures. This directory currently contains one technical scenario and zero completed independent reviews. See [REVIEWING.md](REVIEWING.md) before proposing or reviewing a scenario.

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
