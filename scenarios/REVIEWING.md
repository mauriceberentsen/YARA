# Independent scenario review

## Purpose

Independent review challenges whether a technically conformant YARA plan is safe, useful and honest within its declared boundary. It is not a code-style review and cannot be replaced by a passing test suite or an AI-generated approval.

## Independence and identity

A reviewer must not be the author of the scenario expectations or the planner change under review. The review records the reviewer identity or organization-approved pseudonym, relevant role, identity-assurance method and review date. v0.1 requires at least the roles and reviewer count declared by the scenario.

## Required procedure

1. Verify the `GoldenScenario` identity and run `yara scenario validate` offline.
2. Confirm the request and inventory are internally plausible and within v0.1 scope.
3. Review every required selection and forbidden outcome independently of the expected plan ID.
4. Inspect `plan explain` for each required decision and challenge evidence, alternatives and capacity claims.
5. Confirm search boundaries and ordinal confidence do not overstate coverage or quality.
6. Inspect catalog ownership, provenance, lifecycle state and material warnings.
7. Verify audit and debug-bundle outputs minimize sensitive data and bind the expected identities.
8. Record safety-critical, material and advisory findings. Unresolved safety-critical findings require `changes-required`.
9. State one verdict: `approved`, `changes-required` or `abstained`.

## Evidence rules

- Bind the review to exact scenario and plan IDs.
- Do not place secrets, private inventory, prompts or customer data in the review.
- State limitations and conflicts of interest.
- Approval means no known unsafe recommendation was found in this scenario; it is not product certification.
- A changed scenario ID or plan ID invalidates the review for release-gate counting.

Cryptographically signed `ScenarioReview` resources are not implemented yet. Until that contract exists, review Markdown is human evidence and must be verified through repository history and the stated identity-assurance method. It must never be counted automatically by the CLI.
