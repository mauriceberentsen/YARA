# Upgrades, backup and recovery

## Operational principle

Lifecycle operations are planned changes with preconditions, evidence and receipts. They are not special flags on the installer.

## Upgrade readiness checklist

- New plan and semantic diff reviewed.
- Version-hop compatibility verified for every stateful component.
- Required migrations identified and timed.
- Backup completed with applicable consistency contract.
- Restore path tested within its evidence window.
- Rollback or roll-forward boundary understood.
- Capacity exists for surge, parallel or canary operation.
- Offline artifacts available when applicable.
- Maintenance window and user impact approved.
- Observability can distinguish success from partial failure.

## Backup plan contents

A backup operation records plan instance, data sets, component versions, consistency method, encryption/key references, storage destination, retention, start/end time, artifact digest and verification result. Application data and control-plane metadata have separate backup plans.

## Restore testing

Restore tests use an isolated target where possible and verify functional capability, not only file extraction. Evidence records restored version, target differences, duration, data loss window and checks performed. Expired restore evidence lowers protection health.

## Disaster recovery

Requested RPO/RTO values become hard architecture constraints only when backed by a feasible topology and tested procedures. YARA must not claim an RTO from documentation alone. Recovery procedures include identity, secrets, certificates, model artifacts, registries and external dependencies—not just databases.

## Failed upgrade handling

The operation graph identifies the last safe checkpoint. The executor chooses only pre-approved recovery edges: automatic rollback, restore, roll-forward or stop for operator intervention. It never improvises a migration. All partial state and manual actions enter the receipt.
