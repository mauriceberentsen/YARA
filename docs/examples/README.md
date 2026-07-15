# Examples

Examples illustrate the executable v1alpha1 resource model and review experience. Component names in the sample catalog and plan are intentionally tested placeholders rather than supported products.

- [Platform request](platform-request.yaml)
- [Hardware inventory](inventory.yaml)
- [Generated platform plan](platform-plan.yaml)
- [Planning audit event](audit-event.yaml)

The example represents a local air-gapped coding/chat environment for a small team. Running `yara plan create` reproduces a two-component gateway-to-inference topology with explicit interface wiring and dependency stages. Every fixture manifest has ownership and bounded provenance, but remains experimental; the plan and audit trail say so explicitly. One conflicting compatibility tuple additionally demonstrates quarantine. Its purpose is to prove separation of intent, facts and decisions—not to recommend a real stack.
