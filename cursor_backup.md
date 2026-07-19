# Cursor handoff

Last updated: 2026-07-19

This file is the durable handoff for continuing YARA in Cursor when the current Codex session is unavailable. Update it whenever the active branch, implemented scope, evidence, validation state or next actions change.

## Repository state

- Repository: YARA — an explainable, audit-first AI platform planner and orchestrator.
- Active branch: `feature/v0-2-gb10-capacity-contract`.
- Branch base: `main` at `ad42257` (`Merge audited GB10 model inference contract`).
- Git identity for every commit: `Maurice Berentsen <mauriceberentsen@live.nl>`.
- Working goal: implement and execute the next GB10 promotion gate without declaring the tuple supported prematurely.

## Current product boundary

YARA v0.1 is an offline deterministic planner. The v0.2 catalog introduces a narrow real LiteLLM/vLLM/Qwen stack. The GB10 assertions remain `known` and planner-ineligible. Existing evidence proves:

1. read-only host preflight;
2. exact OCI/model artifact identity;
3. isolated vLLM/PyTorch/CUDA runtime smoke;
4. exact Qwen Coder shard verification, model load, health and one context-1024/concurrency-1 request.

The last merged slice added `yara contract model-inference`. Its positive result is `sha256:5e631233d3936e40c533eb833b11cc7ae98529edc947c1dc30860d1e2ef7bf9b`, with audit head `sha256:ec63273bf89d8a0b5dbaa77cc6b8deac64f94641223f075c50984ee10aadaff3`. The exact runner binary digest is `sha256:448d503b90b40a1262b1d23349f51ecae9ef0961cb4ce05626d50af38dec01ba`.

## Active slice: capacity boundary

Implement a separate, bounded and audited capacity contract for `compat.vllm-qwen-coder-7b-awq-gb10`.

The catalog currently asserts `maximumContextTokens: 32768` but does not declare a supported concurrency or latency/SLO boundary. Therefore:

- test the advertised 32768-token context boundary at concurrency 1;
- do not invent or imply a concurrency, throughput or latency support claim;
- collect only bounded operational measurements needed to establish pass/fail and diagnose resource exhaustion;
- preserve exact catalog, artifact, environment and runner identities;
- keep the serving workload offline and unpublished;
- retain explicit limitations about performance, sustained load and production capacity;
- write negative evidence as a valid `ContractTestResult` when the environment observation is trustworthy;
- make audit persistence mandatory and fail closed.

Implementation status: runner, evaluator, CLI dispatch, schema mode, unit/CLI tests and archived evidence are present in the working tree. The request starts vLLM with `--max-model-len 32768` and `--max-num-seqs 1`, submits an oversized chat payload with `truncate_prompt_tokens: 32760` and reserves eight completion tokens. A pass requires the API usage record to report exactly 32760 prompt tokens, 1–8 completion tokens, a consistent total and no total above 32768. The contract records no prompt, completion or raw log. Non-sensitive integer counts are reviewable in `check.measurements` and remain bound by the evidence digest and result ID.

The final GB10 run passed with result ID `sha256:56e08293c73b7b8cf2e6db4a2c824b38cb2bb8ff79fe5cb337cbe62dfb8f2441`, audit head `sha256:a7b9f4746bbeca827fe157ac4ea9e55cd235c7acbdf86f4229af85fec1452a56` and runner digest `sha256:021d3f399b89400bbb83b3d345f121583b8c222144ead40885971d83fac28148`. Measurements: requested prompt 32760, observed prompt 32760, completion 8 and total 32768 at concurrency 1.

Before executing the remote contract, review host capacity and confirm unrelated GPU workloads may be stopped. Temporary resources must use unique `yara-contract-*` names and cleanup must remove only owned resources. Never store the raw SSH target in results, audit files or this handoff.

## Audit requirements

Auditing is a core domain capability, not an optional log:

- every mutating contract requires `--audit-output`;
- started and terminal events bind the exact catalog and result IDs;
- new results bind the YARA version and exact runner executable SHA-256;
- remote references are pseudonymized;
- output is rolled back if terminal audit persistence fails;
- prompts, completions, raw logs, environment variables and secrets are not durable evidence.

See `docs/architecture/auditing.md`, ADR 0007 and `docs/implementation/contract-testing.md`.

## Likely implementation touchpoints

- `internal/contracttest/`: capacity runner, bounded remote script, evaluator and tests.
- `internal/cli/contract.go`: command orchestration, audit actions and fail-closed output.
- `internal/cli/run.go`: dispatch and usage.
- `internal/resources/contract_test_result.go`: add the mode only if a distinct mode is selected.
- `schemas/yara.dev/v1alpha1/contract-test-result.schema.json`: keep schema and Go validation aligned.
- `catalog/v0.2/evidence/gb10/`: reviewed result and adjacent audit chain.
- `docs/implementation/contract-testing.md`, architecture/testing/auditing docs and roadmap.

Prefer extracting shared model acquisition/server controls from `model_inference.go` over copying a second large shell script if doing so keeps the safety contract explicit and testable.

## Validation before commit

```bash
gofmt -w <changed-go-files>
git diff --check
GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache make check
GOCACHE=/tmp/yara-go-cache GOMODCACHE=/tmp/yara-go-mod-cache go test -race ./...
```

Validate every new result and audit chain independently with the exact built runner. Confirm its SHA-256 matches `spec.runner.binaryDigest`. Confirm the GB10 has no temporary `yara-contract-*` containers or volumes after execution.

Latest validation status: `make check`, `go test -race ./...`, every archived GB10 result, every adjacent audit chain and catalog v0.2 all pass. The final rebuild digest is exactly `sha256:021d3f399b89400bbb83b3d345f121583b8c222144ead40885971d83fac28148`, matching the archived result. Remote cleanup is complete, approximately 127.3 GB host memory is available, and the pre-existing `vllm_qwen` and `vllm_nomic` containers remain stopped.

## Publishing checklist

1. Review `git diff` and confirm no unrelated or secret-bearing files are staged.
2. Confirm `git config user.name` and `git config user.email` match Maurice.
3. Commit the coherent slice on the feature branch.
4. Push the feature branch.
5. Merge with `--no-ff` into `main` only after all tests and evidence validation pass.
6. Push `main`, rerun `make check`, and confirm `origin/main...main` is `0 0`.

## Immediate next actions

1. Review the final diff for scope and secrets.
2. Commit, push, merge and perform post-merge checks.
3. Continue with the policy-contract gate on a new branch; do not promote the GB10 assertion yet.
