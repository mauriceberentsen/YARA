# Plugin system

## Goals

Extensions should allow new knowledge and deployment integrations without giving arbitrary untrusted code access to the planner or operator's environment.

## Extension types

### Catalog package

Declarative capabilities, components, models, policies, topology templates and assertions. This is the preferred extension type and needs no in-process code.

### Discovery adapter

Read-only collection of inventory from a defined source. Runs out of process with declared permissions and emits a validated inventory fragment.

### Renderer adapter

Pure translation for a component/version and deployment target. Ideally sandboxable and deterministic; network and target credentials are prohibited.

### Executor adapter

Mutating integration for a target. Highest trust level, installed and enabled explicitly, out of process and least-privileged.

### Evidence collector

Runs compatibility or benchmark tests and emits signed observations. Its output enters review; it does not directly change the active catalog.

## Non-goals

- Arbitrary in-process hooks into every planner stage.
- Plugins that replace core IDs or disable built-in invariants.
- Downloading and executing code automatically because a plan references it.
- Treating signatures as proof that a plugin is safe.

## Package manifest

A plugin package declares:

- namespaced ID and version;
- publisher and signature information;
- YARA API compatibility;
- extension types and entrypoints;
- schemas and capability contracts;
- required filesystem, network, device and secret permissions;
- deterministic/offline guarantees;
- included artifact digests and licenses;
- update and support policy.

## Isolation

Code extensions communicate through a versioned protocol over standard input/output or local RPC. They receive only required data, not the entire request and inventory by default. Process sandboxing, time/memory limits and disabled network are the target posture. Platform-specific sandbox support may vary and must be reported.

## Trust and installation

- Catalog-only packages can be inspected before enabling.
- Code packages require explicit installation and trust of a publisher key.
- Permissions are shown and approved separately.
- Upgrade re-evaluates permissions and API compatibility.
- A plan records plugin IDs, versions and digests used.
- Revoked or vulnerable plugins are blocked for new apply operations, while historical plans remain readable.

## Namespacing

Plugins own an immutable namespace. They cannot shadow `core.*` or another publisher. Dependencies reference exact plugin/package versions in approved plans. Cross-plugin capability interoperability uses core or jointly versioned contracts, not direct internal calls.

## Planner extensions

v0.1 does not accept executable planner plugins. New scoring dimensions and rule functions require core review because they affect determinism and trust. Declarative rules can be contributed through trusted catalog channels if they use the fixed expression language and pass policy validation.

## Compatibility lifecycle

The plugin API follows explicit compatibility windows. Deprecated interfaces emit warnings for at least one documented release line. Packages declare minimum and maximum supported YARA versions; the loader fails closed outside that range.
