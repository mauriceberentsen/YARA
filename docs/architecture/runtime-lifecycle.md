# Runtime and lifecycle

## Lifecycle states

```text
proposed -> approved -> applying -> active -> changing -> retiring -> retired
                         |           |
                         v           v
                       failed      degraded
```

State represents a deployed plan instance, not the immutable plan itself.

## Runtime manager boundary

The future runtime manager observes declared plan postconditions and coordinates explicit lifecycle operations. It is not a general replacement for Kubernetes, systemd, Prometheus or application operators. It delegates platform-native reconciliation and adds cross-component intent and evidence.

Responsibilities:

- aggregate component health contracts;
- compare active plan with observed versions/configuration;
- detect material drift;
- coordinate dependency-aware upgrade proposals;
- invoke backup/restore contracts;
- collect capacity evidence and surface threshold risks;
- create diagnostic bundles and lifecycle receipts.

It must not change selected models, topology or policy without a new approved plan.

## Health model

Health has separate dimensions:

- **availability:** process/service reachable;
- **readiness:** can serve intended requests;
- **dependency:** required downstream services healthy;
- **functional:** synthetic capability contract succeeds;
- **capacity:** adequate headroom for declared workload;
- **protection:** backups, certificates and security controls current.

A green process check does not imply platform health. Component adapters define versioned probes and safe frequency/cost limits.

## Drift

Drift classifications:

- benign runtime state;
- expected autoscaling/ephemeral difference;
- configuration drift;
- version/artifact drift;
- topology drift;
- policy/security drift;
- missing or orphaned resource.

Detection compares normalized observed state with plan intent. Default response is report or propose reconciliation, not immediately overwrite an operator's change.

## Upgrade flow

1. Select a new catalog snapshot explicitly.
2. Re-plan the existing request and fresh inventory.
3. Generate semantic diff and migration graph.
4. Validate component-specific version hops and dependencies.
5. Verify backups and rollback/roll-forward path.
6. Test or canary where supported.
7. Approve exact new plan and change set.
8. Apply, verify and record a receipt.

Skipping versions is allowed only when the lifecycle contract confirms it.

## Backup and restore

Each stateful role declares:

- data sets and consistency boundaries;
- backup mechanism and required quiescence;
- retention and encryption;
- external dependencies, keys and metadata;
- restore ordering and target compatibility;
- verification test and last proven restore time;
- recovery point/time objectives when requested.

A successful backup command is not a verified recovery. YARA reports restore-test evidence separately.

## Model lifecycle

Models are immutable artifacts. Updating a model creates a new plan. Acquisition verifies license policy, size, origin and digest before activation. Cache eviction cannot remove artifacts referenced by an active or rollback plan unless policy explicitly accepts losing that recovery path.

## Certificates and secrets

Runtime operations may observe expiry metadata and coordinate rotation through providers, but secret values stay outside YARA records. Rotation dependencies and dual-key transition support must be in lifecycle contracts.

## Retirement

Retirement generates a reviewed operation plan covering:

- user/data export requirements;
- final backup and retention;
- credential and token revocation;
- component and model artifact removal;
- persistent volume disposition;
- external DNS/identity/registry cleanup;
- evidence and audit retention.

Destructive cleanup is never inferred solely from a missing request.
