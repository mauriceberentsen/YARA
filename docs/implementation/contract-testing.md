# Catalog contract testing

## Purpose

Catalog documentation and immutable artifact identities are necessary evidence, but they do not prove that a runtime, model and hardware tuple works. YARA therefore treats every positive `CompatibilityAssertion` as a testable contract. Promotion from `experimental` to `supported` requires evidence for the exact catalog digest, assertion, runtime version, model revision and hardware profile.

Two evidence layers are implemented: a read-only remote preflight and a bounded runtime smoke. Preflight answers whether a named host is eligible. Runtime smoke additionally re-verifies the cataloged OCI/model identities and proves that the exact runtime image can execute a CUDA tensor on the named accelerator. Neither layer loads model weights or proves inference compatibility.

## Implemented preflight

`contract preflight` resolves one testable positive assertion (`known`, `experimental` or `supported`) from a validated catalog snapshot and observes a host over non-interactive SSH. Allowing `known` assertions supports evidence gathering; it does not make them planner-selectable. The fixed probe records:

- target OS and CPU architecture;
- Docker availability, server version, OS and architecture;
- presence of the NVIDIA container runtime;
- accelerator vendor, exact model, driver branch and compute capability.

The evaluator checks Docker/Linux availability, OCI platform coverage, the minimum driver branch and exact hardware-profile identity. It distinguishes dedicated accelerator memory from coherent unified system memory; a GB10 profile is therefore not modeled as 128 GiB of dedicated VRAM. Every check carries a digest of its observed evidence. Raw evidence is not copied into the audit event.

Run from a source checkout:

```bash
go run ./cmd/yara contract preflight \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-rtx4090 \
  --target user@gpu-runner.example \
  --name rtx4090-preflight \
  --output .yara/contracts/rtx4090-preflight.yaml \
  --audit-output .yara/audit/rtx4090-preflight.jsonl
```

The SSH target must be reachable with `BatchMode=yes`; interactive password or host-key prompts are deliberately unsupported. The output and audit paths are created with private permissions and are never overwritten. Use a new filename or remove a disposable local result before retrying.

Validate both artifacts independently:

```bash
go run ./cmd/yara contract validate \
  .yara/contracts/rtx4090-preflight.yaml

go run ./cmd/yara audit verify \
  .yara/audit/rtx4090-preflight.jsonl
```

## Implemented runtime smoke

`contract runtime-smoke` is an explicit mutating test. Before opening SSH it resolves the OCI index and Hugging Face revision metadata and compares the observed OCI digest, model revision, weight-shard digests and sizes with the catalog. It then runs the normal preflight and, only if both gates pass, starts one isolated remote container from the exact digest-pinned image.

The remote image must already be present. YARA does not silently pull it because artifact acquisition changes target state, requires network access and is incompatible with an air-gapped test. Stage the exact cataloged image deliberately, for example:

```bash
ssh user@gb10-runner.example \
  'docker pull vllm/vllm-openai@sha256:e4f88a835143cd22aee2397a26ec6bb80b3a4a6fe0c882bcbc63822904766089'
```

Then run the contract:

```bash
go run ./cmd/yara contract runtime-smoke \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-runtime-smoke \
  --output .yara/contracts/gb10-runtime-smoke.yaml \
  --audit-output .yara/audit/gb10-runtime-smoke.jsonl
```

The container uses a unique `yara-contract-smoke-*` name, no network, no ports or volumes, a read-only root filesystem, bounded PID/memory/tmpfs settings and the NVIDIA GPU device. A cleanup trap removes only that test container. It imports the pinned vLLM and PyTorch installation, checks vLLM/CUDA/device/compute-capability identities and executes one one-element CUDA tensor. It never discovers, stops or reconfigures unrelated containers.

Validate the result and audit chain with the same `contract validate` and `audit verify` commands shown above. A passed GB10 smoke proves the bounded runtime checks recorded in the result; it does not prove that either cataloged Qwen model loads or serves requests.

## Outcomes and exit codes

| Result | Meaning | Exit code |
|---|---|---:|
| `passed` | Every check implemented by the selected mode passed | `0` |
| `blocked` | The host cannot test this tuple, for example because its GPU model differs | `3` |
| `failed` | An observed property contradicts the contract, for example no supported OCI platform | `3` |
| invalid input/evidence | The command, catalog or generated resource is invalid | `2` |
| internal error | YARA could not evaluate or encode trusted evidence | `4` |

A blocked or failed evaluation still produces a valid, content-addressed `ContractTestResult` and audit chain when a trustworthy environment observation exists. This is intentional: negative evidence must remain reviewable. A connection/probe or upstream-metadata failure produces only failure audit evidence because a complete result cannot be established.

## Audit and privacy boundary

Audit persistence is mandatory and fail-closed. The two-event chain binds the exact `CatalogSnapshot` and `ContractTestResult` digests. Its target is `ssh:sha256:...`, derived from the SSH reference; the username, hostname and IP address are not written to the audit file. The result contains observed platform and accelerator facts but not the SSH reference, running-container inventory, environment variables, command output, prompts or secrets.

The actor remains the self-asserted local OS identity. The current hash chain detects modification, removal and reordering but is not remote attestation and does not prove who controlled the target.

## What preflight does not prove

A passing preflight MUST NOT promote an assertion. Runtime smoke now covers immutable identity verification and bounded container/CUDA startup, but neither mode establishes:

- model load, memory fit, context-window behavior or concurrency capacity;
- inference correctness or API compatibility;
- hardened no-egress/telemetry policy;
- restart, upgrade, rollback or recovery behavior;
- repeatability on another machine of the same advertised model.

The result records these limitations explicitly.

## Required promotion sequence

For each exact compatibility tuple, promotion still requires:

1. **Artifact verification and runtime startup:** implemented by runtime smoke, using exact identities and an isolated container.
2. **Health and inference:** prove model load, health, one deterministic request, advertised context bounds and clean diagnostics.
3. **Capacity boundary:** test the asserted memory and concurrency envelope without turning a single sample into a universal performance claim.
4. **Policy contract:** verify egress, telemetry, filesystem, secret and privilege behavior under a YARA-owned hardened profile.
5. **Lifecycle contract:** restart and recover the isolated workload and capture state/health evidence.
6. **Independent review:** review the complete evidence set and record an explicit promotion decision.

Tests on a different accelerator are useful for discovering a new hardware profile, but they cannot approve an existing hardware assertion. The GB10 assertions therefore have their own knowledge-only identities and do not promote or validate an RTX 4090 assertion.

## Safe remote-test rules

- Inspect the target before any mutating phase.
- Never stop, rename or reconfigure existing workloads.
- Use unique container names, ports, networks, volumes and output locations.
- Check available memory and disk before pulling or loading artifacts.
- Apply explicit timeouts and clean up only resources created by that test run.
- Capture exact image/model identities and limitations.
- Treat partial cleanup, resource pressure or an unexpected existing-name collision as a failed test.

Preflight complies by remaining read-only. Runtime smoke complies through exact-image pinning, isolation, resource limits, name-collision rejection and ownership-scoped cleanup. Operators must still review available host capacity before staging an image or progressing to model load.
