# Observability

## Two observability planes

YARA distinguishes:

1. **YARA control-plane observability:** planner, API, renderer, executor and lifecycle operations.
2. **Managed platform observability:** inference, gateway, UI, data and identity components selected in a plan.

They may integrate, but access and retention policies can differ.

## Planner diagnostics

Planning is primarily observable through structured traces, not runtime metrics. A trace records stage duration, candidate counts, eliminations by reason, rule evaluations, evidence lookups and search truncation. Default user output is concise; a debug bundle includes the full redacted trace.

Semantic decisions are not buried in free-form logs. They live in `PlatformPlan.decisions` and remain stable after the process exits.

## Control-plane signals

Suggested metrics:

- planning runs and duration by outcome;
- candidate count and search-limit exhaustion;
- invalid/stale catalog entries;
- plan validation failures by code;
- renderer and executor operation duration/outcome;
- approval wait time;
- apply rollback and verification failures;
- plugin timeouts and permission denials.

Logs use correlation IDs for request, plan and operation but avoid full inventory, prompts, secrets and model inputs.

## Managed-platform contract

Instead of hard-coding one monitoring stack, the plan expresses required signals:

- availability/readiness;
- request rate, errors and latency;
- queue and concurrency;
- token or work-unit throughput;
- accelerator utilization and memory;
- storage capacity and backup status;
- certificate/artifact/version status;
- capability-level synthetic checks.

Component adapters map these contracts to actual metrics and probes. The planner may select an observability implementation based on policy and operational simplicity.

## Telemetry policy

YARA emits no remote telemetry by default. Local metrics and logs are configurable and documented. Any future project telemetry is opt-in, data-minimized, inspectable and separable from required product operation. Managed components with unavoidable upstream telemetry are incompatible with a no-telemetry policy.

## Sensitive data

Prompts, completions, retrieved documents, code, tokens, user identifiers and host inventory are sensitive. Their collection requires explicit policy. Traces should store content-free timing and identifiers by default. Redaction is enforced before emission, not only at the display layer.

## Diagnostic bundles

A bundle contains versions, plan/receipt IDs, redacted configuration shape, health results and relevant logs. Generation shows an inventory of included files and scans for secret-like content. The operator approves export; local generation does not upload it.

## Service objectives

YARA distinguishes user-requested SLOs from observed results and estimates. A plan stating an estimated capacity does not establish an SLO. Once running, measured SLO compliance can trigger a warning or re-plan proposal, never an automatic architecture change.
