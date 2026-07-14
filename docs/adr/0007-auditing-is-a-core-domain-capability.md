# ADR-0007: Treat auditing as a core domain capability

- Status: Accepted
- Date: 2026-07-14
- Owners: YARA maintainers
- Supersedes: none
- Superseded by: none

## Context

YARA makes and eventually applies high-impact platform decisions. Decision explanations show why a plan was generated, but they do not establish who initiated an operation, which policy was active, whether an override was used or how a deployment completed. Reconstructing this later from logs would be incomplete and difficult to secure.

## Decision

Model versioned `AuditEvent` resources from v0.1. Security-relevant and state-changing workflows emit append-only, integrity-linked audit evidence referencing immutable resource digests. Audit, explanations, operational logs and receipts remain separate concepts. Production mutation fails closed when required audit persistence is unavailable.

## Consequences

### Positive

- Accountability and forensic reconstruction exist from the first planning version.
- Plans, policy, approvals and executions can be correlated without copying sensitive payloads.
- Audit requirements influence APIs, domain types, testing and storage before deployment code exists.

### Negative

- Every workflow and schema carries additional implementation and test obligations.
- Retention, privacy and identity assurance require explicit policies.
- Local audit identities have limited assurance and must be labelled honestly.

### Neutral / follow-up

- v0.1 provides local append-only output; service storage and signed checkpoints are later work.
- Hash chaining detects tampering but is not equivalent to third-party notarization.

## Alternatives considered

### Reconstruct audit trails from logs

Logs are presentation/operations oriented, may be sampled or rotated and commonly contain either too little context or too much sensitive data.

### Add auditing with the deployment engine

This misses planning, catalog and policy decisions and would require retrofitting core resource identity and event semantics.

## Validation

Golden planning scenarios include expected audit events. Tests verify redaction, digest binding, chain tamper detection and explicit behavior when audit persistence fails.
