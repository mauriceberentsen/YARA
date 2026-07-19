# Catalog contract testing

## Purpose

Catalog documentation and immutable artifact identities are necessary evidence, but they do not prove that a runtime, model and hardware tuple works. YARA therefore treats every positive `CompatibilityAssertion` as a testable contract. Promotion from `experimental` to `supported` requires evidence for the exact catalog digest, assertion, runtime version, model revision and hardware profile.

Six evidence layers are implemented: read-only remote preflight, bounded runtime smoke, bounded model inference, advertised-context capacity boundary, serving-container policy and same-version lifecycle. Preflight answers whether a named host is eligible. Runtime smoke additionally re-verifies cataloged OCI/model identities and proves that the exact runtime image can execute a CUDA tensor. Model inference acquires and locally re-hashes the exact model shards, starts the pinned serving image and executes one constrained API request. Capacity boundary reserves the complete cataloged context envelope for one request. Policy verifies a narrow set of observable container controls. Lifecycle verifies one bounded request before and after an operator-requested restart. Each layer retains explicit limitations and cannot imply broader support.

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

## Implemented model inference

`contract model-inference` applies artifact verification and preflight before any remote mutation. The fixed contract then:

1. requires at least 16 GiB currently available host memory and twice the cataloged shard size plus 2 GiB free disk;
2. downloads the exact public Hugging Face revision into a uniquely named temporary volume;
3. recomputes every cataloged shard size and SHA-256 digest locally;
4. starts the exact digest-pinned vLLM image with a 16-GiB cgroup limit, context 1024 and concurrency 1;
5. keeps the root filesystem and model volume read-only, publishes no ports and gives the serving container `--network none`;
6. provides only bounded private tmpfs paths needed by vLLM/Triton, with executable cache mounts where generated shared objects must be loaded;
7. disables async scheduling and prefix caching for the tested SM 12.1 path, following the [upstream vLLM GB10 workaround](https://github.com/vllm-project/vllm/issues/31588);
8. checks `/health` and one temperature-zero chat request with at most eight completion tokens;
9. stores only evidence digests, HTTP/schema facts and token counts—not the prompt, completion or raw server logs;
10. removes only the uniquely named test containers and volume through an exit trap.

Run from a source checkout:

```bash
go run ./cmd/yara contract model-inference \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-model-inference \
  --output .yara/contracts/gb10-qwen-coder-model-inference.yaml \
  --audit-output .yara/audit/gb10-qwen-coder-model-inference.jsonl
```

Unlike runtime smoke, this command performs explicit networked model acquisition on the target. The serving container itself remains offline. Every newly generated contract result records the YARA version and SHA-256 digest of the exact runner executable, so an audit chain cannot silently substitute a different local binary.

The first GB10 Qwen Coder run exposed that Triton-generated shared objects cannot load from a non-executable tmpfs. That negative result and the final passing configuration are both archived under [`catalog/v0.2/evidence/gb10/`](../../catalog/v0.2/evidence/gb10/README.md). The pass proves only one context-1024, concurrency-1 request. It does not validate the cataloged 32768-token maximum, capacity, performance, restart, lifecycle or air-gap behavior.

## Implemented advertised-context capacity boundary

`contract capacity-boundary` reuses the same artifact, preflight, isolation, privacy and cleanup gates as model inference. It reads `maximumContextTokens` from the exact compatibility assertion, refuses values above its fixed 32768-token safety cap and always uses concurrency 1. For the Qwen Coder GB10 assertion it:

1. starts vLLM with `--max-model-len 32768` and `--max-num-seqs 1`;
2. submits an oversized local chat payload with `truncate_prompt_tokens: 32760`, using the [pinned vLLM ChatCompletion request contract](https://docs.vllm.ai/en/v0.25.1/api/vllm/entrypoints/openai/chat_completion/protocol/);
3. reserves at most eight completion tokens, making the offered envelope exactly 32768 tokens;
4. requires response usage to report exactly 32760 prompt tokens, 1–8 completion tokens, a consistent total and no total above 32768;
5. uses an explicit 10% GPU-memory-utilization allocation, recording configured and expected percentages as reviewable measurements;
6. records only counts, statuses and content digests—not the prompt, completion, raw response or server log. The non-sensitive integer counts remain directly reviewable in `check.measurements` and are also included in the evidence digest and result identity.

```bash
go run ./cmd/yara contract capacity-boundary \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-capacity-boundary \
  --output .yara/contracts/gb10-qwen-coder-capacity-boundary.yaml \
  --audit-output .yara/audit/gb10-qwen-coder-capacity-boundary.jsonl
```

A pass proves acceptance of one exact advertised-context request on the observed host under the recorded allocation. It makes no claim about multiple concurrent requests, sustained load, latency, throughput, output quality or production headroom. Those require separately declared catalog bounds and repeatable tests. An earlier failed allocation remains valid evidence beside a later pass; the coverage ledger preserves both and selects the newest audited observation for the gate.

## Implemented serving-container policy contract

`contract policy` uses the same exact artifact, preflight, model-load, health and request gates, then inspects and actively probes the isolated serving container. The fixed policy profile requires:

- Docker `network none` plus a failed active IPv4 connection attempt;
- no published ports;
- `VLLM_NO_USAGE_STATS=1`, `VLLM_DO_NOT_TRACK=1` and `DO_NOT_TRACK=1`, following the [upstream vLLM opt-out controls](https://docs.vllm.ai/en/v0.9.0/api/vllm/usage/usage_lib.html);
- a read-only root filesystem;
- only the four bounded tmpfs paths needed by Python/CUDA/Triton, with the executable-cache exception recorded explicitly;
- exactly one read-only model volume, no bind mounts and no Docker socket;
- no populated environment variable whose name indicates a secret, password, credential, API key or access token;
- non-privileged Docker mode, no added Linux capabilities, `cap-drop ALL` and `no-new-privileges`;
- successful removal of the uniquely owned containers and model volume before the final observation is emitted.

```bash
go run ./cmd/yara contract policy \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-policy \
  --output .yara/contracts/gb10-qwen-coder-policy.yaml \
  --audit-output .yara/audit/gb10-qwen-coder-policy.jsonl
```

This test does not prove host or daemon hardening, non-root compatibility, universal absence of dependency telemetry, supply-chain security beyond pinned artifacts, or regulatory compliance. Model acquisition occurs before the no-network serving phase and is not air-gap evidence.

## Implemented same-version lifecycle contract

`contract lifecycle` reuses the exact artifact, preflight, isolated serving and bounded inference gates. It performs a fixed sequence:

1. wait for health and complete one context-1024, concurrency-1 request;
2. hash the immutable image, command, model mount and serving-container configuration selected for the test;
3. request a restart of that same container;
4. require a changed start timestamp while preserving the container identity and configuration digest;
5. wait for health and complete the same bounded request again;
6. remove only the uniquely owned containers and volume and verify their absence.

```bash
go run ./cmd/yara contract lifecycle \
  --catalog catalog/v0.2/snapshot.yaml \
  --assertion compat.vllm-qwen-coder-7b-awq-gb10 \
  --target user@gb10-runner.example \
  --name gb10-qwen-coder-lifecycle \
  --output .yara/contracts/gb10-qwen-coder-lifecycle.yaml \
  --audit-output .yara/audit/gb10-qwen-coder-lifecycle.jsonl
```

No raw container ID, start timestamp, prompt, completion or configuration document is persisted. The evidence records only bounded response facts, content digests and boolean identity comparisons. A pass does not establish crash-loop recovery, host failure recovery, version upgrades, rollback, HA, traffic draining, zero downtime, backup/restore or stateful disaster recovery.

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

A passing preflight MUST NOT promote an assertion. Runtime smoke covers immutable identity verification and bounded container/CUDA startup. Model inference additionally covers one narrow model-load/health/request path, but the implemented modes still do not establish:

- concurrency above one;
- generalized inference correctness, quality or API compatibility beyond one fixed request;
- sustained capacity, latency or throughput;
- version upgrade, rollback, HA or stateful recovery behavior;
- repeatability on another machine of the same advertised model.

The result records these limitations explicitly.

## Required promotion sequence

For each exact compatibility tuple, promotion still requires:

1. **Artifact verification and runtime startup:** implemented by runtime smoke, using exact identities and an isolated container.
2. **Health and bounded inference:** implemented for one Qwen Coder/GB10 request; advertised context bounds and broader API conformance remain open.
3. **Advertised-context boundary:** implemented as one exact 32768-token-envelope request; sustained capacity and any concurrency above one remain open until the catalog declares explicit bounds.
4. **Policy contract:** implemented for observable egress, telemetry configuration, filesystem, secret exposure, privilege and cleanup controls; broader host, dependency and compliance claims remain explicitly out of scope.
5. **Lifecycle contract:** implemented for one same-version container restart with pre/post health and inference plus identity-stability evidence; upgrade, rollback, HA and stateful recovery remain open.
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

Preflight complies by remaining read-only. Runtime smoke and model inference use exact-image pinning, isolation, resource limits, name-collision rejection and ownership-scoped cleanup. Model inference additionally fails before acquisition when observed memory or disk is below its fixed safety floor. Operators remain responsible for scheduling downtime or freeing capacity from non-YARA workloads.
