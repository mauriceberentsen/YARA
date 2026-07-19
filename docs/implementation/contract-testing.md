# Catalog contract testing

## Purpose

Catalog documentation and immutable artifact identities are necessary evidence, but they do not prove that a runtime, model and hardware tuple works. YARA therefore treats every positive `CompatibilityAssertion` as a testable contract. Promotion from `experimental` to `supported` requires evidence for the exact catalog digest, assertion, runtime version, model revision and hardware profile.

The first implemented layer is a read-only remote preflight. It answers whether a named host is eligible for a later workload test. It does not start containers, download artifacts or mutate the target.

## Implemented preflight

`contract preflight` resolves one positive selectable assertion from a validated catalog snapshot and observes a host over non-interactive SSH. The fixed probe records:

- target OS and CPU architecture;
- Docker availability, server version, OS and architecture;
- presence of the NVIDIA container runtime;
- accelerator vendor, exact model, driver branch and compute capability.

The evaluator checks Docker/Linux availability, OCI platform coverage, the minimum driver branch and exact hardware-profile identity. Every check carries a digest of its observed evidence. Raw evidence is not copied into the audit event.

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

## Outcomes and exit codes

| Result | Meaning | Exit code |
|---|---|---:|
| `passed` | Every implemented eligibility check passed | `0` |
| `blocked` | The host cannot test this tuple, for example because its GPU model differs | `3` |
| `failed` | An observed property contradicts the contract, for example no supported OCI platform | `3` |
| invalid input/evidence | The command, catalog or generated resource is invalid | `2` |
| internal error | YARA could not evaluate or encode trusted evidence | `4` |

A blocked or failed preflight still produces a valid, content-addressed `ContractTestResult` and audit chain. This is intentional: negative evidence must remain reviewable. A connection/probe failure produces only failure audit evidence because no trustworthy environment observation exists.

## Audit and privacy boundary

Audit persistence is mandatory and fail-closed. The two-event chain binds the exact `CatalogSnapshot` and `ContractTestResult` digests. Its target is `ssh:sha256:...`, derived from the SSH reference; the username, hostname and IP address are not written to the audit file. The result contains observed platform and accelerator facts but not the SSH reference, running-container inventory, environment variables, command output, prompts or secrets.

The actor remains the self-asserted local OS identity. The current hash chain detects modification, removal and reordering but is not remote attestation and does not prove who controlled the target.

## What preflight does not prove

A passing preflight MUST NOT promote an assertion. It does not establish:

- registry artifact availability or re-verify the catalog's immutable digest;
- successful image startup or runtime health;
- model download and file-digest verification;
- model load, memory fit, context-window behavior or concurrency capacity;
- inference correctness or API compatibility;
- hardened no-egress/telemetry policy;
- restart, upgrade, rollback or recovery behavior;
- repeatability on another machine of the same advertised model.

The result records these limitations explicitly.

## Required promotion sequence

For each exact compatibility tuple, later slices must add:

1. **Artifact verification:** resolve the OCI index and model files and compare every immutable digest.
2. **Runtime startup:** launch an isolated, uniquely named workload without reusing production containers, volumes or ports.
3. **Health and inference:** prove health, one deterministic request, advertised context bounds and clean diagnostics.
4. **Capacity boundary:** test the asserted memory and concurrency envelope without turning a single sample into a universal performance claim.
5. **Policy contract:** verify egress, telemetry, filesystem, secret and privilege behavior under a YARA-owned hardened profile.
6. **Lifecycle contract:** restart and recover the isolated workload and capture state/health evidence.
7. **Independent review:** review the complete evidence set and record an explicit promotion decision.

Tests on a different accelerator are useful for discovering a new hardware profile, but they cannot approve an existing hardware assertion. For example, a GB10 host can prove that the vLLM image advertises `linux/arm64` and that its driver/runtime prerequisites exist; it cannot validate the RTX 4090 identity or memory envelope.

## Safe remote-test rules

- Inspect the target before any future mutating phase.
- Never stop, rename or reconfigure existing workloads.
- Use unique container names, ports, networks, volumes and output locations.
- Check available memory and disk before pulling or loading artifacts.
- Apply explicit timeouts and clean up only resources created by that test run.
- Capture exact image/model identities and limitations.
- Treat partial cleanup, resource pressure or an unexpected existing-name collision as a failed test.

The current preflight complies by remaining read-only.
