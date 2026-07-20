# CLI command reference (pre-alpha)

This reference summarizes currently implemented commands and key flags.

Source of truth:

- `go run ./cmd/yara` (usage output)
- command handlers in `internal/cli`

## Core validation and identity

- `yara version` - print CLI version.
- `yara request validate <file>` - validate `PlatformRequest`; key flag: `--audit-output`.
- `yara inventory validate <file>` - validate inventory input; key flag: `--audit-output`.
- `yara catalog validate <snapshot-file>` - validate catalog snapshot; key flag: `--audit-output`.
- `yara audit verify <file>` - verify append-only audit chain integrity.

## Catalog coverage and policy diagnostics

- `yara catalog coverage create` - compile evidence coverage report; key flags: `--catalog`, `--evidence-dir`, `--name`, `--output`, `--audit-output`.
- `yara catalog coverage validate <file>` - validate coverage report; key flag: `--audit-output`.
- `yara catalog coverage lifecycle-publication-policy` - emit lifecycle publication blockers/remediation; key flags: `--report`, `--assertion`, `--audit-output`.
- `yara catalog coverage signing-authority-boundary` - verify signer/issuer independence; key flags: `--report`, `--trust-policy`, `--authorization`, `--audit-output`.

## Planning and debugging

- `yara plan create` - generate deterministic platform plan; key flags: `--request`, `--inventory`, `--catalog`, `--output`, `--audit-output`.
- `yara plan validate <file>` - validate plan resource; key flag: `--audit-output`.
- `yara plan explain <file>` - explain plan decision path; key flags: `--decision`, `--audit-output`.
- `yara plan diff <from-file> <to-file>` - semantic plan diff; key flag: `--audit-output`.
- `yara debug bundle` - produce redacted debug summary; key flags: `--plan`, `--output`, `--audit-output`.

## Rendering

- `yara render docker-compose` - render deterministic Docker Compose bundle; key flags: `--plan`, `--catalog`, `--name`, `--output`, `--audit-output`.
- `yara render kubernetes-gitops` - render deterministic Kubernetes/GitOps bundle; key flags: `--plan`, `--catalog`, `--name`, `--output`, `--audit-output`.
- `yara bundle validate <file>` - validate rendered bundle; key flag: `--audit-output`.

## Kubernetes target observation and review

- `yara target preflight kubernetes` - read-only target preflight; key flags: `--bundle`, `--name`, `--output`, `--audit-output`, `--kubeconfig`, `--context`, `--timeout`.
- `yara target-preflight validate <file>` - validate preflight resource; key flag: `--audit-output`.
- `yara target changeset kubernetes` - derive change set from bundle+preflight; key flags: `--bundle`, `--preflight`, `--name`, `--output`, `--audit-output`, `--kubeconfig`, `--context`, `--timeout`.
- `yara change-set validate <file>` - validate change-set resource; key flag: `--audit-output`.
- `yara approval record` - record reviewed decision on change set; key flags: `--bundle`, `--preflight`, `--change-set`, `--decision`, `--reason-reference`, `--output`, `--audit-output`, `--valid-for`.
- `yara approval validate <file>` - validate approval resource; key flag: `--audit-output`.
- `yara runtime drift-signal record` - record read-only runtime drift posture bound to catalog+bundle+preflight evidence; key flags: `--catalog`, `--assertion`, `--bundle`, `--preflight`, `--confirm-target`, `--observer-name`, `--observer-version`, `--status`, `--check`, `--max-preflight-age`, `--name`, `--output`, `--audit-output`.

## Authorization and deployment execution

- `yara authorization issue` - issue signed apply authorization; key flags: `--bundle`, `--preflight`, `--change-set`, `--approval`, `--private-key`, `--key-id`, `--name`, `--output`, `--audit-output`, `--valid-for`.
- `yara authorization issue-retirement` - issue signed retirement authorization; same key flags as `authorization issue`.
- `yara authorization issue-rollback` - issue signed rollback authorization; same key flags as `authorization issue`.
- `yara authorization verify` - verify authorization signature/binding; key flags: `--authorization`, `--public-key`, `--audit-output`.
- `yara deployment apply kubernetes` - bounded apply execution; key flags: `--bundle`, `--preflight`, `--change-set`, `--approval`, `--import-receipt`, `--authorization`, `--public-key`, `--confirm-authorization`, `--receipt-output`, `--audit-output`.
- `yara deployment bootstrap kubernetes` - create/verify YARA-owned namespace+model PVC; key flags: `--namespace`, `--model-pvc`, `--storage-class`, `--size`, `--target`, `--receipt-output`, `--audit-output`.
- `yara deployment import kubernetes` - stage selected model artifact into bootstrap PVC; key flags: `--bundle`, `--confirm-bundle`, `--preflight`, `--target`, `--artifact-ref`, `--source-dir`, `--internal-root`, `--namespace`, `--model-pvc`, `--output`, `--audit-output`.
- `yara deployment retire kubernetes` - bounded owned-resource retirement; key flags: `--bundle`, `--preflight`, `--change-set`, `--approval`, `--authorization`, `--public-key`, `--confirm-authorization`, `--receipt-output`, `--audit-output`.
- `yara deployment rollback kubernetes` - bounded rollback execution; key flags: `--bundle`, `--preflight`, `--change-set`, `--approval`, `--authorization`, `--public-key`, `--confirm-authorization`, `--receipt-output`, `--audit-output`.

## Receipt and evidence validation

- `yara receipt validate <file>` - validate deployment receipt; key flag: `--audit-output`.
- `yara bootstrap-receipt validate <file>` - validate bootstrap receipt; key flag: `--audit-output`.
- `yara import-receipt validate <file>` - validate artifact import receipt; key flag: `--audit-output`.
- `yara retirement-receipt validate <file>` - validate retirement receipt; key flag: `--audit-output`.
- `yara rollback-receipt validate <file>` - validate rollback receipt; key flag: `--audit-output`.
- `yara promotion-review validate <file>` - validate promotion review; key flag: `--audit-output`.
- `yara artifact-transfer-receipt validate <file>` - validate transfer receipt; key flag: `--audit-output`.
- `yara artifact-scan-receipt validate <file>` - validate scan receipt; key flag: `--audit-output`.
- `yara airgap-provenance-gate-result validate <file>` - validate gate result; key flag: `--audit-output`.
- `yara airgap-gate-trust-policy validate <file>` - validate trust policy; key flag: `--audit-output`.
- `yara airgap-gate-trust-policy-diff validate <file>` - validate trust policy diff; key flag: `--audit-output`.
- `yara airgap-gate-transition-review validate <file>` - validate trust transition review; key flag: `--audit-output`.
- `yara lifecycle-proof-ledger validate <file>` - validate lifecycle proof ledger; key flag: `--audit-output`.
- `yara lifecycle-proof-approval validate <file>` - validate lifecycle proof approval; key flag: `--audit-output`.
- `yara publication-chain-rehearsal validate <file>` - validate publication chain rehearsal; key flag: `--audit-output`.
- `yara publication-chain-renewal-review validate <file>` - validate publication chain renewal review; key flag: `--audit-output`.
- `yara runtime-drift-signal validate <file>` - validate runtime drift signal resource; key flag: `--audit-output`.
- `yara integration-publication-attestation validate <file>` - validate integration publication attestation; key flag: `--audit-output`.
- `yara integration validate <file>` - validate integration test result; key flag: `--audit-output`.

## Scenarios and contract testing

- `yara scenario validate <file>` - validate one golden scenario; key flag: `--audit-output`.
- `yara scenario validate-all <directory>` - validate full scenario suite; key flag: `--audit-output`.
- `yara contract preflight` - record read-only contract preflight evidence; key flags: `--catalog`, `--assertion`, `--target`, `--name`, `--output`, `--audit-output`.
- `yara contract runtime-smoke` - run runtime smoke contract; same key flags as contract preflight.
- `yara contract model-inference` - run model inference contract; same key flags as contract preflight.
- `yara contract capacity-boundary` - run capacity boundary contract; same key flags as contract preflight.
- `yara contract sustained-capacity` - run sustained capacity contract; same key flags as contract preflight.
- `yara contract policy` - run policy contract; same key flags as contract preflight.
- `yara contract lifecycle` - run lifecycle contract with proof bindings; key flags: `--catalog`, `--assertion`, `--target`, `--output`, `--audit-output`, `--lifecycle-proof-ledger`, `--confirm-lifecycle-proof-ledger`, `--lifecycle-apply-receipt`, `--lifecycle-retirement-receipt`, `--lifecycle-rollback-receipt`, `--confirm-lifecycle-reason-reference`, `--lifecycle-proof-max-age`.
- `yara contract validate <file>` - validate contract result; key flag: `--audit-output`.

## Publication and promotion governance

- `yara promotion review record` - record independent promotion review; key flags: `--catalog`, `--assertion`, `--evidence`, `--reviewer-role`, `--decision`, `--reason-reference`, `--name`, `--output`, `--audit-output`.
- `yara lifecycle proof record` - record lifecycle evidence chain review; key flags: `--apply-receipt`, `--retirement-receipt`, `--rollback-receipt`, `--reviewer-role`, `--decision`, `--reason-reference`, `--name`, `--output`, `--audit-output`, `--max-receipt-age`.
- `yara lifecycle proof approve-publication` - approve lifecycle publication claim; key flags: `--catalog`, `--assertion`, `--lifecycle-proof-ledger`, `--confirm-lifecycle-proof-ledger`, `--evidence`, `--reviewer-role`, `--decision`, `--reason-reference`, `--max-ledger-age`, `--valid-for`, `--name`, `--output`, `--audit-output`.
- `yara publication chain rehearse` - record publication chain rehearsal; key flags: `--catalog`, `--assertion`, `--lifecycle-proof-approval`, `--integration-publication-attestation`, `--coverage-report`, `--trust-policy`, `--signing-boundary-audit`, `--authorization`, `--reviewer-role`, `--decision`, `--reason-reference`, `--max-evidence-age`, `--name`, `--output`, `--audit-output`.
- `yara publication chain retention-diagnostics` - classify rehearsal retention posture; key flags: `--catalog`, `--assertion`, `--current-rehearsal`, `--candidate-rehearsal`, `--audit-output`.
- `yara publication chain renewal-review` - record publication-chain renewal review; key flags: `--catalog`, `--assertion`, `--publication-chain-rehearsal`, `--publication-chain-retention-audit`, `--promotion-review`, `--lifecycle-proof-approval`, `--integration-publication-attestation`, `--evidence`, `--reviewer-role`, `--decision`, `--reason-reference`, `--max-evidence-age`, `--valid-for`, `--name`, `--output`, `--audit-output`.

## Air-gap provenance chain

- `yara artifact import record` - record import receipt from bundle/preflight identities; key flags: `--bundle`, `--preflight`, `--importer-name`, `--importer-version`, `--internal-root`, `--name`, `--output`, `--audit-output`.
- `yara artifact transfer record` - record transfer chain-of-custody step; key flags: `--bundle`, `--import-receipt`, `--stage`, `--source-attestation-ref`, `--destination-attestation-ref`, `--prior-receipt`, `--name`, `--output`, `--audit-output`.
- `yara artifact scan record` - record scanning attestation; key flags: `--bundle`, `--transfer-receipt`, `--scanner-name`, `--scanner-version`, `--scanner-profile`, `--policy-digest`, `--verdict`, `--reason-reference`, `--prior-receipt`, `--name`, `--output`, `--audit-output`.
- `yara airgap provenance-gate evaluate` - issue signed gate result; key flags: `--bundle`, `--import-receipt`, `--transfer-receipt`, `--scan-receipt`, `--private-key`, `--key-id`, `--reason-reference`, `--name`, `--output`, `--audit-output`.
- `yara airgap provenance-gate verify` - verify gate result against trust policy; key flags: `--gate-result`, `--trust-policy`, `--confirm-policy`, `--policy-diff`, `--confirm-policy-diff`, `--transition-review`, `--confirm-transition-review`, `--audit-output`.
- `yara airgap gate-trust-policy record` - record signer trust policy; key flags: `--target-reference-digest`, `--signer`, `--name`, `--output`, `--audit-output`.
- `yara airgap gate-trust-policy diff` - diff trust policy transitions; key flags: `--from-policy`, `--to-policy`, `--name`, `--output`, `--audit-output`.
- `yara airgap gate-trust-policy review-transition` - review destructive trust-policy transition; key flags: `--policy-diff`, `--decision`, `--reviewer-role`, `--reason-reference`, `--name`, `--output`, `--audit-output`.

## Integration execution and publication

- `yara integration component-smoke` - run component-smoke integration evidence command; key flags: `--catalog`, `--target`, `--component`, `--confirm-catalog-digest`, `--name`, `--output`, `--audit-output`.
- `yara integration topology-end-to-end` - run topology end-to-end evidence command; key flags: `--catalog`, `--target`, `--topology`, `--component`, `--confirm-catalog-digest`, `--name`, `--output`, `--audit-output`.
- `yara integration execute <component-smoke|topology-end-to-end>` - generic integration dispatcher; key flags depend on selected mode path.
- `yara integration publish attest` - publish integration attestation for catalog assertion; key flags: `--catalog`, `--evidence-dir`, `--assertion`, `--evidence`, `--reviewer-role`, `--decision`, `--reason-reference`, `--max-evidence-age`, `--valid-for`, `--name`, `--output`, `--audit-output`.

## Notes

- This reference intentionally lists only currently implemented commands.
- For exact command syntax, use `go run ./cmd/yara` and command-specific usage output in the current revision.
