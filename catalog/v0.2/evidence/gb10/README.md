# GB10 runtime-smoke evidence

These resources archive the first bounded YARA runtime-smoke runs for the two knowledge-only GB10 compatibility assertions. Each `ContractTestResult` is bound to catalog digest `sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241`; the adjacent JSONL file is its verified two-event audit chain.

| Assertion | Result ID | Outcome |
|---|---|---|
| `compat.vllm-qwen-coder-7b-awq-gb10` | `sha256:19440545851599fe81ffe36d77cdcfa00dd945191ba568b1bf04721aaba0400b` | `passed` |
| `compat.vllm-qwen3-8b-awq-gb10` | `sha256:705dfd767bde71df7ee865eafdfe0f223166dfc30acaf9738a5b8c6513e2b4cc` | `passed` |

Verify from a source checkout:

```bash
for result in catalog/v0.2/evidence/gb10/*.yaml; do
  go run ./cmd/yara contract validate "$result"
done

for chain in catalog/v0.2/evidence/gb10/*.audit.jsonl; do
  go run ./cmd/yara audit verify "$chain"
done
```

The target SSH reference is pseudonymized. The actor identity is self-asserted local operating-system identity, not cryptographic attestation. These runs verified immutable OCI/model metadata, host eligibility, exact vLLM/CUDA/GB10 identities and one CUDA tensor inside an isolated no-network container. They did not download or load model weights and are not evidence of inference, context, concurrency, policy, restart or air-gap compatibility. The assertions therefore remain `known` and planner-ineligible.
