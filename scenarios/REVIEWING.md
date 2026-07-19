# Independent scenario review

## Purpose

Independent review challenges whether a technically conformant YARA plan is safe, useful and honest within its declared boundary. It is not a code-style review and cannot be replaced by a passing test suite or an AI-generated approval.

## Independence and identity

A reviewer must not be the author of the scenario expectations or the planner change under review. The review records the reviewer identity or organization-approved pseudonym, relevant role, identity-assurance method and review date. v0.1 requires at least the roles and reviewer count declared by the scenario.

## Required procedure

1. Run `yara scenario validate-all scenarios/v0.1` and confirm the suite reports ten technically conformant cases with completed independent and acceptance-gate reviews when approved `review.yaml` resources are present.
2. Verify the individual `GoldenScenario` identity and run `yara scenario validate` offline.
3. Confirm the request and inventory are internally plausible and within v0.1 scope.
4. Review every required selection and forbidden outcome independently of the expected plan ID.
5. Inspect `plan explain` for each required decision and challenge evidence, alternatives and capacity claims.
6. Confirm search boundaries and ordinal confidence do not overstate coverage or quality.
7. Inspect catalog ownership, provenance, lifecycle state and material warnings.
8. Verify audit and debug-bundle outputs minimize sensitive data and bind the expected identities.
9. Record safety-critical, material and advisory findings. Unresolved safety-critical findings require `changes-required`.
10. State one verdict: `approved`, `changes-required` or `abstained`.

## Suggested review order

Review the three fail-closed cases first: `unasserted-accelerator`, `insufficient-vram` and `concurrency-capacity-exceeded`. They challenge the safety boundary. Then review `private-chat-coding` as the baseline feasible plan, followed by the remaining six feasible variations.

For every case, complete its human-readable `review.md` and machine-counted `review.yaml` without changing the pinned scenario or plan identity. Record reviewer identity or approved pseudonym, relevant role, assurance method, date, conflicts, verdict and concrete findings in both artifacts. Do not replace findings with a bare approval.

## Evidence rules

- Bind the review to exact scenario and plan IDs.
- Do not place secrets, private inventory, prompts or customer data in the review.
- State limitations and conflicts of interest.
- Approval means no known unsafe recommendation was found in this scenario; it is not product certification.
- A changed scenario ID or plan ID invalidates the review for release-gate counting.

Cryptographic signatures on review resources are not implemented yet. Until that contract exists, `ScenarioReview` and `AcceptanceGateReview` YAML provide content-addressed identities validated by the CLI. Human-readable Markdown remains supplementary evidence verified through repository history.
