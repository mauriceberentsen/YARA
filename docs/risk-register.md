# Risk register

## Rating

Likelihood and impact are qualitative: low, medium or high. The register should be reviewed at every milestone gate.

| ID | Risk | Likelihood | Impact | Mitigation / trigger |
|---|---|---:|---:|---|
| R1 | Users want a fixed turnkey stack, not a planner | Medium | High | Manual-plan validation before engine work; pivot if users will not review alternatives |
| R2 | Catalog maintenance overwhelms a solo maintainer | High | High | Narrow supported slice, ownership/freshness gates, quarantine stale entries, automate evidence tests |
| R3 | Recommendations imply false precision | High | High | Ranges, confidence, applicability bounds, Pareto alternatives and no global-optimum claims |
| R4 | Compatibility matrix grows combinatorially | High | High | Topology templates, supported paths, bounded assertions and one dimension per expansion milestone |
| R5 | Model/hardware capacity estimates are unreliable | High | High | Explicit workload assumptions, headroom, measured fixtures and experimental label until validated |
| R6 | Upstream releases break integrations | High | Medium | Immutable snapshots, pinned versions, contract tests and explicit re-plan/upgrade |
| R7 | Supply-chain compromise enters through catalogs/plugins | Medium | High | Digests, signatures, namespaces, trust channels, sandboxing and no executable planner rules |
| R8 | Deployment privileges create a severe blast radius | Medium | High | Planner without credentials, isolated executor, bound approval, least privilege and GitOps option |
| R9 | Air-gap claim misses hidden network dependencies | High | High | Empty-cache blocked-egress tests and complete artifact/acquisition manifests |
| R10 | Licenses are misclassified | Medium | High | Structured license facts, provenance, policy review and explicit no-legal-advice boundary |
| R11 | Determinism conflicts with dynamic ecosystem data | Medium | Medium | Immutable snapshots; freshness only through explicit snapshot update and re-plan |
| R12 | Expert disagreement makes one ranking misleading | High | Medium | Explicit objective weights, alternatives, scenario-specific evidence and override path |
| R13 | Documentation architecture never becomes software | Medium | High | Thin milestone deliverables, schemas/fixtures first and time-boxed prototype gates |
| R14 | Too much breadth delays user value | High | High | v0.1 exclusions enforced in roadmap and new integrations require validated scenarios |
| R15 | Generated configuration exposes data or services | Medium | High | Typed intent, versioned adapters, secure defaults, contract and topology policy tests |
| R16 | Runtime feedback creates unsafe autonomous changes | Medium | High | Observations only propose new plans; approval required for semantic change |
| R17 | Project becomes dependent on one vendor despite neutral intent | Medium | Medium | Vendor-neutral domain schemas, namespaced extensions and later second-vendor portability test |
| R18 | Maintainer sustainability fails at 10 hours/week | High | High | Limit support promises, automate checks, publish maintenance status and stop low-value breadth |
| R19 | Audit records are incomplete, tampered with or leak sensitive data | Medium | High | Typed mandatory events, digest chaining/checkpoints, fail-closed mutation, redaction tests and separate access/retention policy |
| R20 | Kubernetes defaulting or normalization hides drift or produces false updates | Medium | High | Narrow versioned projection, remove only known server fields, negative drift fixtures, blocked unknown kinds and revalidation before apply |

## Top risks before implementation

### Product usefulness (R1)

Architecture cannot mitigate a missing market. Complete problem interviews and manual plans before building generalized search or deployment.

### Knowledge maintenance (R2/R4/R6)

The knowledge layer is the differentiator and the largest liability. A "known" catalog can be broad, but automatic supported recommendations must remain deliberately small. Entry count is never a goal.

### False authority (R3/R5/R10/R12)

YARA's presentation could make uncertain advice look authoritative. Confidence, source age, search bounds and alternatives must be first-class data, not disclaimer text at the bottom of a UI.

### Scope and sustainability (R13/R14/R18)

The project is vulnerable to years of architecture work or integration churn without a usable release. Every phase has externally reviewable exit criteria and a stop/pivot gate.

## Review questions

At each milestone ask:

- Which risks increased because of this design?
- Which mitigation now has executable evidence?
- Are any assumptions being presented as support claims?
- What can be removed from scope without invalidating the hypothesis?
- Can one maintainer keep every supported path current?
- Would failure be safe and understandable to the user?
