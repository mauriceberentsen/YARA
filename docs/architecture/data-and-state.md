# Data and state

## State classes

YARA separates five kinds of state:

| State | Mutability | Owner | Examples |
|---|---|---|---|
| Intent | Versioned, user changed | User/team | Request, objectives, overrides |
| Knowledge | Immutable releases | Catalog maintainers | Manifests, rules, evidence |
| Plan | Immutable | Planner output | Topology, decisions, allocations |
| Operational record | Append-only | Planner/executor/runtime | Audit event, approval, receipt, observation |
| Managed workload data | Mutable | Deployed component/user | Conversations, vectors, traces |

YARA may coordinate workload-data lifecycle but does not place it in its control-plane database.

## Local v0.1 storage

The reference CLI uses files:

- request and optional inventory supplied by the user;
- catalog snapshot from a local directory or verified archive;
- generated plan and diagnostics written to a chosen output path;
- no background service, account or implicit home-directory state required for deterministic planning.

A local cache MAY store compiled catalog indexes, keyed by catalog digest. Cached data is disposable and cannot affect semantic output.

## Future service storage

A team service likely needs relational metadata storage plus object storage for immutable snapshots and artifact manifests. Choice of database is deferred. The logical data model must support:

- organizations, environments and identities;
- request and policy versions;
- plan, approval and receipt records;
- catalog channels and snapshots;
- observations and lifecycle operations;
- audit events;
- retention and deletion policies.

## Content addressing

Canonical serialization feeds SHA-256 digests for requests, inventories, policies, catalog snapshots, plans and rendered bundles. Canonicalization specifies key ordering, numeric/unit representation, omission rules and Unicode normalization. Display formatting is not hashed.

Digests prove identity within YARA workflows but do not prove publisher authenticity. Signatures and trusted keys provide authenticity.

## Schema evolution

- Public resources use `apiVersion` and `kind`.
- Additive compatible changes remain within a version where semantics are preserved.
- Breaking changes introduce a new API version and explicit migration.
- Readers reject unknown required fields or semantics instead of dropping them.
- Migrations are pure, testable transformations and record source digest/version.
- An old approved plan remains readable for its documented support period.

## Concurrency

Immutable plan creation avoids most write conflicts. A future service uses optimistic concurrency on mutable intent resources. Approval binds a specific plan digest, so a new request revision cannot reuse an old approval.

## Retention and privacy

Requests and inventories may reveal sensitive infrastructure, hostnames and policy. Defaults should minimize collection and allow local-only operation. A service must support configurable retention, export and deletion while preserving audit requirements. Diagnostic bundles require explicit redaction and user review.

## Backup boundaries

Control-plane backup covers intent, policy, plans, approvals, catalog references and operational records. Workload backup is component-specific and described by lifecycle contracts. A "YARA backup" must never imply that model artifacts or application data were captured unless the receipt explicitly proves it.
