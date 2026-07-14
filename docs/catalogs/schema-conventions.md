# Schema conventions

## Format

Authoring uses YAML; canonical storage and validation semantics follow JSON. JSON Schema is the proposed validation language because it supports both representations and broad tooling. YAML-specific features such as anchors, custom tags and implicit timestamps are forbidden in canonical manifests.

## Resource envelope

Every public resource has exactly:

- `apiVersion`: schema namespace and version;
- `kind`: resource type;
- `metadata`: identity, version, status, labels and ownership;
- `provenance`: sources, verification and confidence where relevant;
- `spec`: resource-specific desired data.

Runtime outputs may add `status`, but catalog manifests do not use status as mutable reconciliation state.

## Naming

- IDs: lowercase DNS-like namespace plus name, for example `core.open-webui`.
- Capability IDs: lowercase dotted hierarchy, for example `identity.oidc`.
- Field names: lower camel case.
- Enum values: lowercase kebab-case.
- Units: explicit IEC/storage or SI/performance suffixes; no bare ambiguous numbers.
- Versions: semantic versions for YARA resources; upstream versions stored as strings plus a declared comparison scheme.

## Required schema behavior

- Reject unknown fields by default.
- Define numeric ranges and string patterns.
- Use discriminated unions for variants.
- Keep `null`, omitted and empty semantically distinct.
- Require explicit units for resources and durations.
- Represent unknown through omission or a typed evidence state, never sentinel values such as `-1`.
- Avoid free-form maps in core resources; allow them only in namespaced extension fields.

## References

References contain type, stable ID and version constraint or digest:

```yaml
componentRef:
  id: core.example-runtime
  version: ">=1.4.0 <2.0.0"
```

Approved plans use exact versions and artifact digests. Catalog assertions may use ranges when the range semantics and evidence scope are clear.

## Extensions

Extensions are namespaced:

```yaml
extensions:
  example.org/feature:
    enabled: true
```

Core logic ignores only extensions explicitly marked optional. Required unknown extensions cause validation failure. Plugins cannot add fields directly to core schemas.

## Dates and durations

- Timestamps use UTC RFC 3339.
- Durations use an unambiguous restricted ISO 8601 form or typed amount/unit object.
- Relative statements such as "recent" never appear in data.

## Canonicalization

Before hashing:

- resolve YAML to JSON data without aliases;
- normalize Unicode to NFC;
- sort object keys lexicographically;
- preserve array order only where semantic;
- normalize units to the schema's canonical base unit;
- omit fields defined as non-semantic, such as generated display text;
- serialize numbers without alternate equivalent forms.

The canonicalization specification and test vectors are release blockers for plan IDs.

## Validation layers

1. Syntax and schema.
2. Resource identity/version rules.
3. Referential integrity.
4. Cross-resource semantic constraints.
5. Catalog policy: evidence, freshness and support status.
6. Contract tests for supported claims.

Passing JSON Schema alone never establishes support.
