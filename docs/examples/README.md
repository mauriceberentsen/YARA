# Examples

Examples illustrate the executable v1alpha1 resource model and review experience. Component names in the sample catalog and plan are intentionally tested placeholders rather than supported products.

- [Platform request](platform-request.yaml)
- [Hardware inventory](inventory.yaml)
- [Generated platform plan](platform-plan.yaml)
- [Planning audit event](audit-event.yaml)

The example represents a local air-gapped coding/chat environment for a small team. Running `yara plan create` with the request, inventory and `catalog/v0.1/snapshot.yaml` reproduces the semantic plan. The fixture deliberately includes one conflicting compatibility tuple to demonstrate quarantine, plan diagnostics and audit propagation. Its purpose is to prove separation of intent, facts and decisions—not to recommend a real stack.
