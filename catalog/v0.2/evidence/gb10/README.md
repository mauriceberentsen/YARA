# GB10 runtime-smoke evidence

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

## Advertised-context capacity boundary

| Assertion | Result ID | Outcome | Measurements |
|---|---|---|---|
| `compat.vllm-qwen-coder-7b-awq-gb10` | `sha256:56e08293c73b7b8cf2e6db4a2c824b38cb2bb8ff79fe5cb337cbe62dfb8f2441` | `passed` | Requested/observed prompt 32760; completion 8; total 32768; concurrency 1 |

Verify from a source checkout:

```bash
for result in catalog/v0.2/evidence/gb10/*.yaml; do
  go run ./cmd/yara contract validate "$result"
done

for chain in catalog/v0.2/evidence/gb10/*.audit.jsonl; do
  go run ./cmd/yara audit verify "$chain"
done
```

The target SSH reference is pseudonymized. The actor identity is self-asserted local operating-system identity, not cryptographic attestation. Runtime-smoke verified immutable OCI/model metadata, host eligibility, exact vLLM/CUDA/GB10 identities and one CUDA tensor. Model-inference additionally acquired and locally re-hashed the exact Qwen Coder shards, loaded them and completed one bounded request. Capacity-boundary verified one exact 32768-token envelope, with reviewable integer measurements bound into the result. These runs used networked acquisition and do not establish concurrency above one, sustained capacity, latency, throughput, broader policy, restart, lifecycle or air-gap compatibility. The assertions therefore remain `known` and planner-ineligible.
