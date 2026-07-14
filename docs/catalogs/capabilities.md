# Capability taxonomy

## Purpose

Capabilities are the stable language between user intent, topology roles and implementations. They prevent planner logic from becoming a collection of product-specific branches.

## Taxonomy roots

```text
experience.*    End-user outcomes and interfaces
inference.*     Model execution functions
orchestration.* Agent, tool and workflow coordination
data.*          Retrieval, indexing and persistent data functions
identity.*      Authentication and authorization
integration.*   API and protocol contracts
operations.*    Health, metrics, logs, backup and lifecycle
security.*      Encryption, secrets, audit and isolation
platform.*      Scheduling, storage, networking and runtime primitives
```

Initial examples:

```text
experience.chat
experience.coding
inference.text-generation
inference.embeddings
integration.api.openai-chat
identity.oidc
operations.health
operations.metrics
security.audit
```

## Capability manifest

A definition includes:

- stable ID and semantic description;
- input/output or behavioral contract;
- maturity and version;
- parameters and limits;
- whether it is user-facing, implementation or operational;
- composition and implication relations;
- test contract where machine-verifiable.

Example:

```yaml
apiVersion: yara.dev/v1alpha1
kind: Capability
metadata:
  id: integration.api.openai-chat
  version: 1.0.0
spec:
  description: Compatible subset of a versioned chat-completions contract.
  contractRef: core.contract.openai-chat/v1
  parameters:
    streaming: { type: boolean }
    tools: { type: boolean }
```

"OpenAI compatible" without a versioned contract and feature subset is too ambiguous for a supported capability claim.

## Derivation

Use cases map to required and optional capabilities through rules. A use case is not itself a product bundle. For example, coding may derive:

- required text generation;
- one compatible client/API path;
- a minimum context requirement from workload;
- optional fill-in-the-middle or tool calling;
- identity and audit capabilities from policy.

## Composition

Capabilities may imply other capabilities, but implications must be explicit and acyclic. A component can supply a capability directly or a topology can supply it through composition. For example, gateway plus inference runtime may together expose an API contract.

## Versioning

Breaking contract changes create a new capability version. Product version support is asserted against an exact capability contract. Human-facing aliases may evolve without changing IDs.

## Anti-patterns

- Capability IDs named after a product.
- Broad labels such as `enterprise-ready` or `secure`.
- Treating a checkbox feature as proof of its full contract.
- Encoding quality rankings as capabilities.
- Duplicating policy state as capabilities.
