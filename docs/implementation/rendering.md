# Offline deployment rendering

YARA now has its first non-mutating deployment boundary. The Docker Compose reference renderer accepts an immutable `PlatformPlan` and the exact catalog snapshot named by that plan, then emits one content-addressed `DeploymentBundle`.

Rendering is pure and offline. It does not inspect Docker, pull images, download models, resolve secrets or create services.

## Current adapter boundary

Renderer version `yara.docker-compose@0.1.0` deliberately supports only:

- LiteLLM `1.93.0` as the OpenAI-compatible gateway;
- vLLM `0.25.1` as the text-generation runtime;
- one exact cataloged Hugging Face model snapshot;
- the direct `integration.api.openai-chat/v1` gateway-to-inference connection;
- a single NVIDIA device reservation.

Unknown roles, versions, topology shapes or catalog mismatches fail instead of triggering target-specific substitutions.

## Generate a review bundle

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

The terminal render event binds the exact plan, catalog and bundle digests. If audit persistence fails, the bundle is removed.

## Bundle contents

The bundle contains pinned Compose services, a generated LiteLLM configuration, exact model files, license sources, ordered create operations, required inputs, checks and limitations. The Compose preview uses a Docker-internal network, publishes no host port, drops all Linux capabilities, enables `no-new-privileges`, uses read-only roots and gives vLLM only its documented executable `/tmp` exception. These are rendered intentions, not proof that a target enforced them.

## Deliberate omissions

There is no executor yet. YARA does not currently materialize bundle files, acquire artifacts, add an access boundary, calculate an observed change set, request approval, call `docker compose up`, issue a receipt or safely remove owned resources. Those operations require separate target identity, approval and receipt schemas and must not be added to the renderer.
