# Observability

## Two observability planes

YARA distinguishes:

1. **YARA control-plane observability:** planner, API, renderer, executor and lifecycle operations.
2. **Managed platform observability:** inference, gateway, UI, data and identity components selected in a plan.

They may integrate, but access and retention policies can differ.

## Planner diagnostics

Planning is primarily observable through structured decisions and diagnostics rather than runtime metrics. A future trace can record stage duration, candidate counts, eliminations by reason, rule evaluations, evidence lookups and search truncation. Default user output remains concise.

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

The implemented v0.1 `DebugBundle` is a deterministic, content-addressed JSON artifact derived from a validated plan. It includes generator/planner versions, source digests, bounded-search and confidence summaries, topology counts and roles, diagnostic codes, an inventory of its four logical sections, and an explicit list of omitted plan paths. It excludes the plan name, component/model references, placement, allocations, decision reasons, diagnostic text and raw inputs.

Generation scans the complete candidate artifact for a bounded set of secret-like patterns and fails without writing a bundle when it finds one. This heuristic is defense in depth, not proof that arbitrary future inputs are safe. The current command requires fail-closed local audit evidence, never uploads the result and does not collect environment variables. Operators must inspect the JSON before sharing it.

Logs, traces, receipts and health observations are not included because v0.1 does not produce those resources yet. Adding any of them requires typed redaction, classification, bounded size and secret-canary tests before they enter the bundle contract.

## Service objectives

YARA distinguishes user-requested SLOs from observed results and estimates. A plan stating an estimated capacity does not establish an SLO. Once running, measured SLO compliance can trigger a warning or re-plan proposal, never an automatic architecture change.
