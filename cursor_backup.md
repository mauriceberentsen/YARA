# Cursor handoff

Last updated: 2026-07-19

This file is the durable handoff for continuing YARA in Cursor when the current Codex session is unavailable. Update it whenever the active branch, implemented scope, evidence, validation state or next actions change.

## Repository state

- Repository: YARA — an explainable, audit-first AI platform planner and orchestrator.
- Active branch: `feature/v0-2-qwen3-capacity-diagnosis`.
- Branch base: `main` at `32e007d` (`Merge audited Qwen3 GB10 contract evidence`).
- Git identity for every commit: `Maurice Berentsen <mauriceberentsen@live.nl>`.
- Working goal: close the remaining catalog v0.2 evidence gaps without fabricating support for unavailable Ada hardware, unimplemented component/topology integration contracts or sustained capacity.

## Current product boundary

YARA v0.1 is an offline deterministic planner. The v0.2 catalog introduces a narrow real LiteLLM/vLLM/Qwen stack. The GB10 assertions remain `known` and planner-ineligible. Existing evidence proves:

1. read-only host preflight;
2. exact OCI/model artifact identity;
3. isolated vLLM/PyTorch/CUDA runtime smoke;
4. exact Qwen Coder shard verification, model load, health and one context-1024/concurrency-1 request.

The last merged slice added `yara contract model-inference`. Its positive result is `sha256:5e631233d3936e40c533eb833b11cc7ae98529edc947c1dc30860d1e2ef7bf9b`, with audit head `sha256:ec63273bf89d8a0b5dbaa77cc6b8deac64f94641223f075c50984ee10aadaff3`. The exact runner binary digest is `sha256:448d503b90b40a1262b1d23349f51ecae9ef0961cb4ce05626d50af38dec01ba`.

## Completed slice: capacity boundary

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

The slice was committed as `6fcc4a1` and merged to `main` as `037a8f9`. Post-merge `make check` passed and local `main` matched `origin/main` before the next branch was created.

## Completed slice: policy contract

Implement a separate audited policy contract for the same exact Qwen Coder/vLLM/GB10 tuple. The gate must test observable controls, not claim general security or compliance. At minimum, design explicit checks for:

- serving-container egress isolation and absence of published ports;
- telemetry disabled through known runtime controls, while documenting that environment configuration is not proof of all upstream behavior;
- read-only root filesystem plus the smallest explicit writable tmpfs set;
- no secrets, host environment, Docker socket or unrelated host mounts passed to the serving container;
- non-privileged execution, no added Linux capabilities and an explicit privilege-escalation posture;
- ownership-scoped cleanup and fail-closed audit persistence.

First determine which controls can be proved from Docker inspect state and which require an active negative probe. Prefer a fresh `policy-contract` result mode and `contract.policy.*` audit actions. Do not silently weaken the tmpfs controls required for Triton-generated executable objects; record that exception explicitly.

Implementation status: `contract policy`, the `policy-contract` result mode, Docker inspect and active egress probes, hardening flags, cleanup verification, stable diagnostics and unit/CLI/fail-closed tests are implemented. `make check` and `go test -race ./...` pass. The GB10 run passed with result `sha256:725b54027506733ff9514e1b2805165389940714b500afa4cd8e44188916ac0d`, audit head `sha256:23870ef3177e1e4df95caeb41270e7f011b0cacd201f6061d020bbb366400714` and runner digest `sha256:c63f64b2215ba817f61115a54f1c2f2e4cf9f5e7dbf4deb8191dd862e7f8238e`. The profile deliberately retains image-default root while applying `cap-drop ALL`, `no-new-privileges`, non-privileged mode, read-only root and restricted mounts; non-root compatibility remains a documented open claim.

The policy slice was committed as `cdfcfd1`, merged to `main` as `5166c01`, pushed, and passed a post-merge `make check`. Local `main` matched `origin/main` before this lifecycle branch was created.

## Completed slice: lifecycle contract

Implement a separate audited lifecycle contract for the exact Qwen Coder/vLLM/GB10 tuple. Keep the claim deliberately narrow:

- establish health and one bounded inference before a restart;
- restart the same serving container without reacquiring or replacing artifacts;
- establish health and one bounded inference after restart;
- prove the pinned image, model mount, model identity and serving limits did not drift;
- prove ownership-scoped cleanup removed only the temporary contract resources;
- preserve mandatory, fail-closed audit persistence and pseudonymized target references.

This gate proves bounded same-version restart recovery only. It must not imply stateful backup/restore, version upgrades, rollback, high availability, sustained availability, crash-loop recovery or disaster recovery. Prefer a fresh `lifecycle-contract` result mode and `contract.lifecycle.*` audit actions. Reuse the hardened serving profile and exact acquisition checks rather than creating a second independent shell implementation.

Implementation status: `contract lifecycle`, the `lifecycle-contract` result mode, pre/post health and bounded inference, restart, container/configuration identity comparisons, start-timestamp advancement, owned cleanup, stable diagnostics and unit/CLI/fail-closed tests are implemented. The GB10 run passed with result `sha256:d2ea66d99b1552f3b12bfd7d4c10c6ac3fda305ce4b60fb784df8c3cfef60e85`, audit head `sha256:70eb8a0545bee5c8744b0903b2639d7b3586d9a133ac3acf190fbb68fc162354` and runner digest `sha256:f2ea12e312e58c7cf51d4119c4e03ddb9c097af23475210553176bcc752af980`. The archived result and adjacent audit chain are present in the working tree. Remote cleanup is complete and the pre-existing vLLM containers remain stopped.

The lifecycle slice was committed as `339ce98`, merged to `main` as `ae92b33`, pushed, and passed a post-merge `make check`. Local `main` matched `origin/main` before this coverage branch was created.

## Completed slice: catalog coverage

Build a deterministic machine-readable completion report for catalog v0.2. It must validate the snapshot, discover only valid `ContractTestResult` files bound to the exact catalog digest, verify every adjacent audit chain and bind accepted evidence by assertion and mode. The report must distinguish structural catalog validity from operational evidence completeness.

At minimum the report must enumerate all components, models, hardware profiles and compatibility assertions; expose passed, failed, blocked and missing gates; state why no tuple is yet promotion-eligible; and record unavailable Ada targets and missing component integrations as blockers rather than inferred passes. Generation requires fail-closed audit persistence and a content-addressed report identity.

Implementation status: `catalog coverage create` and `catalog coverage validate`, the strict `CatalogCoverageReport` resource/schema, manifest inventory projection, exact evidence/audit binding, report identity, fail-closed generation audit and rollback tests are implemented. The archived report is `catalog/v0.2/coverage.yaml`, report ID `sha256:2f0e078cc921f9522aabe565150e95adefc7c1b59ec18bb2c7fd2dc60720d559`; its audit head is `sha256:5f072b8a7a85470d99af01ad354d197d3b510883be369527a523aeea96d40eb6`. It explicitly enumerates all 38 manifests (13 capabilities, 10 components, 2 models, 4 hardware profiles, 8 assertions and 1 topology), accepts 7 results with 7 individually bound and verified evidence audit chains, and records 0 promotion-eligible assertions.

The coverage slice was committed as `09e676c`, merged to `main` as `4d7898a`, pushed, and passed a post-merge `make check`. Local `main` matched `origin/main` before this Qwen3 evidence branch was created.

## Completed slice: Qwen3 GB10 evidence

Use the already implemented audited contract modes against `compat.vllm-qwen3-8b-awq-gb10` on the authorized GB10 target. Execute model inference, advertised-context capacity boundary, serving policy and same-version lifecycle as separate runs. Build one exact runner binary and bind its digest in every result. Archive each valid result beside its two-event audit chain, verify ownership-scoped cleanup after every run, and keep the pre-existing vLLM containers stopped.

After all four modes pass or produce trustworthy negative evidence, regenerate `catalog/v0.2/coverage.yaml` and its audit. The Qwen3 tuple must remain `known`: sustained capacity and independent promotion review are still open even if every current mode passes.

Execution status: all four modes ran with exact runner digest `sha256:313de6ce350ddb2fce884b7ec7dafb58e77d58f6fc426bf1605a9598782a64b1`. Model inference passed (`sha256:fd5948b05f26d1b2f397c65917d5801bd622c97597b98fb2e7cda431dc1579f2`, audit head `sha256:f6a3c781678ba6d568887e6bff57d4cab8495722f9c3a40a011be02865321656`). Policy passed (`sha256:9dfe0f01949a45348752671de4cf4d04c00f978fbe8da7c26b30482aef6e7321`, audit head `sha256:f8630e10e424bb9158e4c87e357f1f9769fbe85efd5d1ec9649a4c20782a8de9`). Lifecycle passed (`sha256:75ed1488071d9569e83a34c0b1bdf98367d4e919362f42ef1982e018bd95a156`, audit head `sha256:2e9ae2377a7bd6a094b60d8809a7be9cc7bf396badd8c712c51e17e427492eab`). The advertised-context boundary reproducibly failed because the server did not become healthy before inference; the neutrally named archived result is `sha256:30f5536136f375aba164c93fbae05a72c3912bdc61f774a945ae138f37f44005`, audit head `sha256:721d9a930b89da8ba413d58b2cd1c414c67992d4e13a4c300faed19515482b5c`.

That slice initially generated coverage report `sha256:597f1cb7f404b749664cf556c595984c09bada47c94ecbdf4fb8771356bda81b` with audit head `sha256:80c45ab860a73954dea5c07f20f2d820eded071ae1a0536712dbf31d0e0e9a10`. It accepted 11 results/audit chains and selected the Qwen3 capacity failure. The subsequent capacity-diagnosis slice below supersedes that coverage report without deleting the earlier negative result.

The Qwen3 evidence slice was committed as `8ecc3d9`, merged to `main` as `32e007d`, pushed, and passed a post-merge `make check`. Local `main` matched `origin/main` before this diagnosis branch was created.

## Completed slice: Qwen3 capacity diagnosis

Extend the shared serving observation with the configured GPU-memory-utilization percentage and persist it as a reviewable check. Classify vLLM startup failures that explicitly state the configured maximum sequence length exceeds available KV-cache token capacity under a dedicated stable diagnostic code. Keep the ordinary inference, policy and lifecycle profiles at 8%; use 10% only for the advertised-context capacity profile. On 128 GiB coherent unified memory this requests a 12.8 GiB vLLM memory fraction and remains inside the existing 16 GiB container-memory ceiling.

The shared serving profile now records `gpuMemoryUtilizationPercent` for success and failure observations. The corresponding check exposes configured and expected percentages as reviewable integer measurements. Ordinary model-inference, policy and lifecycle contracts remain at 8%; capacity-boundary uses 10%. Explicit vLLM KV-cache token-capacity startup failures map to stable diagnostic `YARA-CTR-179`, while an observed/configured allocation mismatch maps to `YARA-CTR-180`.

The definitive Qwen3 boundary run passed with result `sha256:4afed044263ef0e422c18512980e6c75d764be9da209441d765fd8da88df7a62`, audit head `sha256:64583ce547147375bd5bd315ffb9ae0f4833ae06d2b6a7fd4009387578240c56` and exact runner digest `sha256:2656897254b93ac4e73131061f60f135d833048cf38328d997fd17e2ce57cc04`. Measurements are configured/expected GPU utilization 10%, requested/observed prompt 32760, completion 8 and total 32768 at concurrency 1. The earlier 8% failure remains archived and visible in `observedEvidence` before the later pass.

The regenerated coverage report is `sha256:826432ada6ff003ca5beeda5d72c8aee763fb1d10ca3a27193d21e5f7f852acf` with audit head `sha256:82a2b93e082ccf91f8720dcdccc4ffd1c0e9b3be75826d442053e7f3a3208a43`. It accepts 12 exact results and 12 adjacent verified audit chains. Both GB10 assertions now pass every currently executable contract gate, but remain `known`, planner-ineligible and not promotion-eligible because sustained-capacity and independent-review gates remain open.

Before both remote runs, host capacity and unrelated workloads were reviewed. Temporary resources used unique `yara-contract-*` names, cleanup removed only owned resources and the raw SSH target was not stored in results, audit files or this handoff.

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

- `internal/contracttest/`: shared bounded serving runner, lifecycle runner, evaluator and tests.
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

Latest validation status: `make check` and `go test -race ./...` pass; all 12 archived GB10 results and all 12 adjacent audit chains validate; catalog v0.2, the coverage report and its audit validate; and coverage regeneration is byte-for-byte identical. The exact final capacity runner digest matches the archived result. No raw SSH target occurs in the repository. Remote cleanup is complete, approximately 127.3 GB host memory was available before execution, and the pre-existing `vllm_qwen` and `vllm_nomic` containers remain stopped.

## Publishing checklist

1. Review `git diff` and confirm no unrelated or secret-bearing files are staged.
2. Confirm `git config user.name` and `git config user.email` match Maurice.
3. Commit the coherent slice on the feature branch.
4. Push the feature branch.
5. Merge with `--no-ff` into `main` only after all tests and evidence validation pass.
6. Push `main`, rerun `make check`, and confirm `origin/main...main` is `0 0`.

## Immediate next actions

1. Commit, push and merge this capacity-diagnosis slice.
2. Design an audited sustained-capacity contract with an explicit workload/SLO envelope; do not infer one from a single request.
3. Design component-integration and topology end-to-end evidence contracts before promoting suite components.
4. Acquire authorized Ada targets (RTX 4090, RTX 6000 Ada and L40S) or keep all six external tuples explicitly unobserved.
5. Record independent, identity-bound promotion reviews only after the applicable technical gates pass.
