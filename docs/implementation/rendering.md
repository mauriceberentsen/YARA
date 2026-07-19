# Offline deployment rendering

YARA has two non-mutating deployment renderers. Docker Compose remains the compact single-host reference; Kubernetes/GitOps is the selected first reference deployment target under ADR-0009. Both accept an immutable `PlatformPlan` and the exact catalog snapshot named by that plan, then emit one content-addressed `DeploymentBundle`.

Rendering is pure and offline. It does not inspect Docker, pull images, download models, resolve secrets or create services.

## Current adapter boundary

Renderer versions `yara.docker-compose@0.1.0` and `yara.kubernetes-gitops@0.1.0` deliberately support only:

- LiteLLM `1.93.0` as the OpenAI-compatible gateway;
- vLLM `0.25.1` as the text-generation runtime;
- one exact cataloged Hugging Face model snapshot;
- the direct `integration.api.openai-chat/v1` gateway-to-inference connection;
- a single NVIDIA device reservation.

Unknown roles, versions, topology shapes or catalog mismatches fail instead of triggering target-specific substitutions.

## Generate a Docker Compose review bundle

First create a plan with the v0.2 request, inventory and catalog. Then render it:

```bash
go run ./cmd/yara render docker-compose \
  --plan .yara/platform-plan-v0.2.yaml \
  --catalog catalog/v0.2/snapshot.yaml \
  --name reference-stack \
  --output .yara/reference-stack.bundle.yaml \
  --audit-output .yara/audit/reference-stack.render.jsonl
```

Validate the result and its render audit independently:

```bash
go run ./cmd/yara bundle validate .yara/reference-stack.bundle.yaml
go run ./cmd/yara audit verify .yara/audit/reference-stack.render.jsonl
```

Generate the equivalent Kubernetes/GitOps bundle from the same plan and catalog:

```bash
go run ./cmd/yara render kubernetes-gitops \
  --plan .yara/platform-plan-v0.2.yaml \
  --catalog catalog/v0.2/snapshot.yaml \
  --name reference-stack \
  --output .yara/reference-stack.kubernetes.bundle.yaml \
  --audit-output .yara/audit/reference-stack.kubernetes.render.jsonl
```

The terminal render event binds the exact plan, catalog and bundle digests. If audit persistence fails, the bundle is removed.

## Bundle contents

The bundle contains four embedded, content-addressed files:

- `compose.yaml`, with the pinned service topology;
- `litellm-config.yaml`, with the typed gateway-to-inference connection;
- `sbom.spdx.json`, an SPDX 2.3 inventory of every OCI/model package, catalog-declared license and exact model shard;
- `offline-acquisition.yaml`, a content-addressed `OfflineAcquisitionManifest` containing every immutable source artifact and its required mirroring method.

`spec.supplyChain` names the two supply-chain files explicitly. Bundle validation strictly decodes the offline manifest, validates its own `manifestId`, compares its plan, catalog, renderer and artifact inventory with the enclosing bundle, and checks that the SPDX package inventory preserves every artifact and declared license. Changing either document therefore requires a new manifest ID, file digest and bundle ID.

The acquisition policy makes the phase boundary explicit: connected acquisition requires network access, execution must not, every digest must be verified and partial artifact sets are forbidden. It does not select a mirror, transfer medium or internal destination and does not authorize acquisition. License values are catalog declarations; SPDX `licenseConcluded` remains `NOASSERTION` because YARA has not performed legal review. Packages use `filesAnalyzed: false`: exact model shards are separate checksum-bearing SPDX packages, because rendering has metadata but has not acquired or analyzed their contents and therefore cannot honestly emit a package verification code.

The Compose preview uses a Docker-internal network, publishes no host port, drops all Linux capabilities, enables `no-new-privileges`, uses read-only roots and gives vLLM only its documented executable `/tmp` exception. These are rendered intentions, not proof that a target enforced them.

## Kubernetes/GitOps bundle

The Kubernetes prototype embeds native YAML for one namespace, a content-named immutable LiteLLM ConfigMap, two single-replica Deployments, two ClusterIP Services and explicit NetworkPolicies. It renders:

- digest-pinned images and a read-only pre-provisioned `yara-model` PVC;
- `nvidia.com/gpu: 1` for vLLM;
- disabled service-account-token automounting;
- read-only roots, dropped capabilities, disabled privilege escalation and `RuntimeDefault` seccomp;
- default-deny ingress/egress with only gateway→inference, DNS and labelled verifier paths;
- startup, readiness and liveness probes from cataloged HTTP health contracts;
- no Ingress, Gateway, LoadBalancer, NodePort or host network.

These remain desired-state assertions. Kubernetes documents that NetworkPolicy enforcement depends on the network plugin and that GPU scheduling depends on a vendor device plugin. Preflight observes the available target facts, while the separately authorized executor performs bounded active model/runtime/network checks and records their limitations. Rendering performs none of those operations.

Renderer `0.1.0` bounds its tested server-minor range to Kubernetes 1.34 through 1.36. Strict schema validation covers both endpoints; support outside that range must fail preflight until separately reviewed rather than being inferred from stable API names.

## Deliberate omissions

Rendering still does not materialize files, pull/mirror artifacts, scan contents, inject secrets, contact a target or commit to Git. Separate commands now provide Kubernetes preflight, change-set review, signed authorization and bounded direct apply with a deployment receipt. Acquisition/import receipts, GitOps publication, Docker Compose apply and safe retirement remain unimplemented and must not be folded into the renderer.
