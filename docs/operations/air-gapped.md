# Air-gapped operation

## Goal

An air-gapped YARA workflow can plan, render, deploy and maintain an environment without live external network access. This requires a supply-chain process, not only offline-capable applications.

## Connected staging side

The reference renderer now emits `sbom.spdx.json` and `offline-acquisition.yaml` inside every `DeploymentBundle`. These are acquisition inputs, not proof that acquisition, scanning, transfer or import occurred.

1. Resolve an approved plan and validate its exact bundle, SPDX inventory and offline-acquisition manifest.
2. Acquire permitted container images, packages, charts, model files and documentation.
3. Record origin, license, size, digest and signature status.
4. Scan and verify according to organization policy.
5. Include catalog snapshot, schemas, renderer/executor binaries and trust keys.
6. Produce a content-addressed bundle and signed inventory.

## Transfer and import

1. Transfer through the organization's controlled medium.
2. Quarantine and verify the bundle before trusting metadata.
3. Recompute every artifact digest.
4. Import into internal registries/model stores without changing identity.
5. Record an import receipt and local location mapping.
6. Run YARA preflight to prove every plan artifact is available.

## Offline operation

- Disable update checks, analytics and remote fonts/assets.
- Use reachable identity, DNS, certificate and time services.
- Resolve secrets through an offline provider.
- Store documentation, license notices and recovery tools locally.
- Export diagnostics only through an explicit reviewed process.

## Updating

Updates arrive as a new catalog and artifact bundle. Operators re-plan, compare, approve and import before applying. Existing catalog snapshots and rollback artifacts remain until retention policy permits removal.

## Common hidden dependencies

- image/chart subdependencies not pinned by digest;
- model tokenizer or configuration files fetched lazily;
- license or authentication calls at startup;
- OCSP/CRL, public DNS or network time requirements;
- UI assets loaded from a CDN;
- package installation in container entrypoints;
- vulnerability databases and certificate trust updates;
- identity-provider dependencies outside the boundary.

Reference tests must start with egress blocked and empty caches to expose these dependencies.
