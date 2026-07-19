# GB10 contract evidence

These resources archive bounded YARA contract runs for the two knowledge-only GB10 compatibility assertions. Each `ContractTestResult` is bound to catalog digest `sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241`; the adjacent JSONL file is its verified two-event audit chain. Newer results also bind the exact runner executable digest.

| Assertion | Result ID | Outcome |
|---|---|---|
| `compat.vllm-qwen-coder-7b-awq-gb10` | `sha256:19440545851599fe81ffe36d77cdcfa00dd945191ba568b1bf04721aaba0400b` | `passed` |
| `compat.vllm-qwen3-8b-awq-gb10` | `sha256:705dfd767bde71df7ee865eafdfe0f223166dfc30acaf9738a5b8c6513e2b4cc` | `passed` |

## Model inference attempts

| Assertion | Result ID | Outcome | Meaning |
|---|---|---|---|
| `compat.vllm-qwen-coder-7b-awq-gb10` | `sha256:c7fe98ed7574cce9ad7044a159703bb9df634f703ce652818cc4ebc7f4c12c99` | `failed` | Read-only root plus non-executable Triton tmpfs correctly exposed a filesystem-policy incompatibility (`YARA-CTR-156`) |
| `compat.vllm-qwen-coder-7b-awq-gb10` | `sha256:5e631233d3936e40c533eb833b11cc7ae98529edc947c1dc30860d1e2ef7bf9b` | `passed` | Exact local shards loaded; health and one context-1024/concurrency-1 no-network chat request passed |
| `compat.vllm-qwen3-8b-awq-gb10` | `sha256:fd5948b05f26d1b2f397c65917d5801bd622c97597b98fb2e7cda431dc1579f2` | `passed` | Exact local shards loaded; health and one context-1024/concurrency-1 no-network chat request passed |

## Advertised-context capacity boundary

| Assertion | Result ID | Outcome | Measurements |
|---|---|---|---|
| `compat.vllm-qwen-coder-7b-awq-gb10` | `sha256:56e08293c73b7b8cf2e6db4a2c824b38cb2bb8ff79fe5cb337cbe62dfb8f2441` | `passed` | Requested/observed prompt 32760; completion 8; total 32768; concurrency 1 |
| `compat.vllm-qwen3-8b-awq-gb10` | `sha256:30f5536136f375aba164c93fbae05a72c3912bdc61f774a945ae138f37f44005` | `failed` | At 8% GPU-memory utilization the server did not become healthy; inference and boundary measurement were blocked (`YARA-CTR-145`, `YARA-CTR-149`) |
| `compat.vllm-qwen3-8b-awq-gb10` | `sha256:4afed044263ef0e422c18512980e6c75d764be9da209441d765fd8da88df7a62` | `passed` | At an explicit, reviewable 10% allocation: prompt 32760; completion 8; total 32768; concurrency 1 |

## Serving-container policy

| Assertion | Result ID | Outcome | Scope |
|---|---|---|---|
| `compat.vllm-qwen-coder-7b-awq-gb10` | `sha256:725b54027506733ff9514e1b2805165389940714b500afa4cd8e44188916ac0d` | `passed` | Egress, ports, telemetry opt-outs, read-only filesystem, tmpfs, mounts/secrets, capabilities, no-new-privileges and owned cleanup |
| `compat.vllm-qwen3-8b-awq-gb10` | `sha256:9dfe0f01949a45348752671de4cf4d04c00f978fbe8da7c26b30482aef6e7321` | `passed` | The same bounded serving-container controls and owned cleanup passed |

## Same-version lifecycle

| Assertion | Result ID | Outcome | Scope |
|---|---|---|---|
| `compat.vllm-qwen-coder-7b-awq-gb10` | `sha256:d2ea66d99b1552f3b12bfd7d4c10c6ac3fda305ce4b60fb784df8c3cfef60e85` | `passed` | Health and bounded inference before/after one restart; stable container/configuration identity; advanced start timestamp; owned cleanup |
| `compat.vllm-qwen3-8b-awq-gb10` | `sha256:75ed1488071d9569e83a34c0b1bdf98367d4e919362f42ef1982e018bd95a156` | `passed` | Health and bounded inference before/after one restart; stable container/configuration identity; advanced start timestamp; owned cleanup |

Verify from a source checkout:

```bash
for result in catalog/v0.2/evidence/gb10/*.yaml; do
  go run ./cmd/yara contract validate "$result"
done

for chain in catalog/v0.2/evidence/gb10/*.audit.jsonl; do
  go run ./cmd/yara audit verify "$chain"
done
```

The target SSH reference is pseudonymized. The actor identity is self-asserted local operating-system identity, not cryptographic attestation. Runtime-smoke verified immutable OCI/model metadata, host eligibility, exact vLLM/CUDA/GB10 identities and one CUDA tensor. Model-inference additionally acquired and locally re-hashed both exact model snapshots, loaded them and completed one bounded request per tuple. Both models accepted one exact 32768-token envelope at concurrency 1. Qwen3 required a 10% GPU-memory-utilization profile; its earlier 8% failure remains archived beside the later pass so the remediation history is not erased. Policy verified the observable serving-container controls listed above. Lifecycle verified one operator-requested restart of each isolated container and bounded requests before and after it. These runs used networked acquisition and do not establish concurrency above one, sustained capacity, latency, throughput, non-root compatibility, host/daemon hardening, upgrade/rollback, HA, stateful recovery or air-gap compatibility. The assertions therefore remain `known` and planner-ineligible.
