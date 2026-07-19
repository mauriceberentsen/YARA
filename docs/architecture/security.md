# Security architecture

## Security posture

YARA can influence high-privilege infrastructure and process sensitive inventory. Its planning core should run without target credentials, and mutation must be isolated behind explicit approval and least-privilege executors.

This document is a design threat model, not a security certification.

## Assets

- platform requests, inventories and organization policy;
- catalog trust roots and signing keys;
- plans, approvals and deployment receipts;
- executor and target credentials;
- secret-provider references and access policy;
- artifact/model origins, digests and license records;
- audit records and diagnostic bundles;
- application data handled by deployed components.

## Trust boundaries

```text
untrusted inputs/catalogs
          |
          v validation + signature policy
     planner process (no target credentials)
          |
          v signed/content-addressed plan
     renderer sandbox (no target credentials)
          |
          v artifact bundle + change set + approval
     executor boundary (short-lived credentials)
          |
          v
     target environment and third-party components
```

User-supplied YAML, community catalogs, plugin output, upstream artifacts, model files and target observations are untrusted until validated under their relevant policy.

## Principal threats and controls

### Malicious catalog or plugin

Threats include hidden privileged configuration, data exfiltration, ID shadowing and executable rule payloads.

Controls: schema allowlists, namespaces, signed immutable packages, no executable planner rules, explicit permission manifests, out-of-process adapters and trusted channels disabled by default.

### Supply-chain substitution

Threats include mutable tags, registry compromise and replaced model files.

Controls: artifact digests, optional signature/transparency verification, pinned catalog snapshots, acquisition receipts, private mirror policy and verification again at apply.

### Planner resource exhaustion

Threats include pathological rules, catalog graphs or oversized inputs.

Controls: bounded schema sizes, acyclic rule phases, search/evaluation limits, process limits and no general-purpose expression execution.

### Secret disclosure

Threats include values in plans, logs, command lines, generated files or diagnostic bundles.

Controls: typed references only, provider-side retrieval, redaction at source, safe logging APIs, no secret hashing into plan IDs and user review before diagnostic export. The v0.1 debug bundle is constructed from an allowlisted summary rather than redacting a copied plan, then scanned for common secret patterns; the scan is defense in depth and does not replace review.

### Unauthorized mutation

Threats include compromised UI/API, replayed approval or over-privileged executor.

Controls: plan/bundle/change-set-bound approvals, target binding, short-lived scoped credentials, separation of duties, operation locks, idempotency and append-only receipts.

### Unsafe generated configuration

Threats include dropped security intent, open network exposure and excessive privilege.

Controls: version-specific typed renderer adapters, deny-by-default network intent, contract tests, independent plan/bundle validation and fail on unknown fields.

### Stale or poisoned observations

Threats include manipulated inventory leading to unsafe capacity or compatibility choices.

Controls: provenance, timestamps, source precedence, contradiction reporting, optional attestation and preflight re-verification before mutation.

### Target preflight credential and metadata exposure

Threats include using over-privileged Kubernetes credentials, accidentally issuing a mutating command, and persisting cluster endpoints, contexts or object names in results and audit records.

Controls: a dedicated read-only observer with an allowlisted `config view`/`get` command surface, bounded output and timeout, generic external-command failures, pseudonymous target identity, aggregate facts only, secret-canary tests and mandatory fail-closed audit persistence. This reduces exposure but does not prove the supplied Kubernetes identity is least-privilege; operators remain responsible for its RBAC scope.

## Secure defaults

- No telemetry or external network call without explicit configuration.
- Bind user-facing services to non-public interfaces unless exposure is requested.
- Require authentication for non-local multi-user deployments.
- Encrypt external and cross-trust-zone connections.
- Use unprivileged containers/processes and read-only filesystems where supported.
- Deny host mounts, host network and privileged execution by default.
- Require immutable artifacts for approved plans.
- Avoid default credentials and generated secrets in output.

## Air-gapped supply chain

An offline bundle needs a signed manifest of application images, packages, model artifacts, charts, catalog snapshot, documentation, licenses and verification keys. Import occurs through quarantine, malware/policy scanning where available and digest verification. YARA does not assume air-gapped means trusted.

## Vulnerability response

Before executable releases, the project needs:

- private reporting channel and `SECURITY.md`;
- supported version policy;
- severity/response targets;
- catalog revocation mechanism;
- signed security advisories;
- a way to identify plans affected by component/artifact assertions without collecting user inventories centrally.

## Audit

Auditing is a security control and a core domain capability, not ordinary debug logging. Security-relevant events include trust-root changes, catalog enablement, policy/exception changes, plan creation, approval, secret-provider authorization, apply, drift acceptance and retirement. See the [auditing architecture](auditing.md) for event semantics, integrity, privacy, retention and failure behavior.

## Residual risk

YARA cannot prove third-party software or models are secure, prevent an authorized administrator from accepting risk, guarantee legal compliance or fully validate application-specific data flows. Plans must state these boundaries rather than imply certification.
