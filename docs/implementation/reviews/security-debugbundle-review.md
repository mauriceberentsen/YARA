# Security review: debug bundle allowlist

Status: **approved**

- Acceptance criterion: #11 — allowlisted, redacted debug bundle with secret-pattern gate
- Review scope: `internal/debugbundle/`, debug-bundle tests, `yara debug bundle` output
- Review date: 2026-07-19

Human approval recorded for v0.1 debug-bundle boundaries. This verdict is not product certification and does not alter CLI release-gate counting.

## Reviewer record

- Reviewer: Maurice Berentsen (repository owner)
- Relevant role: Security reviewer
- Identity assurance: Repository owner; inspection of allowlist, secret-canary tests and sample bundle output
- Review date: 2026-07-19
- Conflict-of-interest statement: Implementation author; review records owner acceptance of debug-bundle evidence
- Verdict: approved

## Checklist

- [x] Bundle contains only allowlisted plan metadata; raw request, inventory and plan prose are omitted.
- [x] Secret-pattern gate rejects canary matches and rolls back on audit persistence failure.
- [x] Determinism and content-addressed bundle ID verified in tests.
- [x] Residual topology disclosure judged acceptable for v0.1 support use case.

## Findings

### Safety-critical

None.

### Material

- Allowlist and omission list match documented v0.1 contract.
- Secret-pattern coverage is sufficient for fixture scope; canary tests pass.

### Advisory

- Pattern coverage should expand before exposing bundles outside trusted operator workflows.
