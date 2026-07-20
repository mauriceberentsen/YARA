import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

describe("App", () => {
  beforeEach(() => {
    global.fetch = vi.fn((input, init = {}) => {
      const parsed = new URL(String(input), "http://localhost");
      const endpoint = parsed.pathname + (parsed.search || "");
      if (parsed.pathname === "/api/v1/workflow/plan" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          plan: {
            planId: "sha256:plan",
            planPath: ".yara/workspaces/default/reference-stack.plan.yaml",
            auditPath: ".yara/workspaces/default/reference-stack.plan.audit.jsonl",
            confidence: "medium",
            decisions: 4,
            instances: 2,
            components: 2,
            diagnostics: 0,
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/render" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          render: {
            bundleId: "sha256:bundle",
            bundlePath: ".yara/workspaces/default/reference-stack.kubernetes.bundle.yaml",
            auditPath: ".yara/workspaces/default/reference-stack.kubernetes.bundle.audit.jsonl",
            renderer: "kubernetes-gitops",
            manifestCount: 9,
            artifactCount: 3,
            operationCount: 6,
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/preflight" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          preflight: {
            resultId: "sha256:preflight",
            outcome: "passed",
            targetReferenceDigest: "sha256:target",
            resultPath: ".yara/workspaces/default/reference-preflight.yaml",
            auditPath: ".yara/workspaces/default/reference-preflight.audit.jsonl",
            checkCount: 9,
            passedChecks: 9,
            blockedChecks: 0,
            failedChecks: 0,
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/changeset" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          changeSet: {
            changeSetId: "sha256:changeset",
            outcome: "blocked",
            changeSetPath: ".yara/workspaces/default/reference-change-set.yaml",
            auditPath: ".yara/workspaces/default/reference-change-set.audit.jsonl",
            operationCount: 2,
            blockedCount: 1,
            summary: { creates: 1, updates: 0, noOps: 0, conflicts: 1, unresolved: 0, deletes: 0 },
            operations: [
              { resource: "apps/v1/Deployment default/gateway", action: "conflict", ownership: "foreign", severity: "blocker", riskClasses: ["workload-restart"], diagnosticCode: "YARA-CHG-102" },
              { resource: "v1/ConfigMap default/gateway-config", action: "create", ownership: "absent", severity: "review", riskClasses: ["configuration"], diagnosticCode: "none" },
            ],
          },
        }), { status: 422 }));
      }
      if (parsed.pathname === "/api/v1/workflow/approval" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          approval: {
            approvalId: "sha256:approval",
            decision: "approved",
            effect: "review-only",
            approvalPath: ".yara/workspaces/default/reference-approval.yaml",
            auditPath: ".yara/workspaces/default/reference-approval.audit.jsonl",
            planId: "sha256:plan",
            bundleId: "sha256:bundle",
            preflightResultId: "sha256:preflight",
            changeSetId: "sha256:changeset",
            targetReferenceDigest: "sha256:target",
            reasonReference: "ticket-123",
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/authorization-command" && (init.method || "GET").toUpperCase() === "GET") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          command: "yara authorization issue --bundle '.yara/workspaces/default/reference-stack.kubernetes.bundle.yaml' --preflight '.yara/workspaces/default/reference-preflight.yaml' --change-set '.yara/workspaces/default/reference-change-set.yaml' --approval '.yara/workspaces/default/reference-approval.yaml' --private-key '<private-key-path>' --key-id '<key-id>' --name 'reference-authorization' --output '.yara/workspaces/default/reference-authorization.yaml' --audit-output '.yara/workspaces/default/reference-authorization.audit.jsonl'",
          bundlePath: ".yara/workspaces/default/reference-stack.kubernetes.bundle.yaml",
          preflightPath: ".yara/workspaces/default/reference-preflight.yaml",
          changeSetPath: ".yara/workspaces/default/reference-change-set.yaml",
          approvalPath: ".yara/workspaces/default/reference-approval.yaml",
          outputPath: ".yara/workspaces/default/reference-authorization.yaml",
          auditPath: ".yara/workspaces/default/reference-authorization.audit.jsonl",
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/apply" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        if (requestPayload.airgapGateResultPath && requestPayload.confirmAirgapGateTrustPolicy === "sha256:mismatch") {
          return Promise.resolve(new Response(JSON.stringify({
            valid: false,
            diagnostics: [{ code: "YARA-EXE-119", message: "explicit trust-policy confirmation does not match the supplied policy", severity: "error" }],
          }), { status: 422 }));
        }
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          apply: {
            outcome: "succeeded",
            receiptId: "sha256:receipt",
            authorizationId: "sha256:authorization",
            receiptPath: ".yara/workspaces/default/reference-receipt.yaml",
            auditPath: ".yara/workspaces/default/reference-apply.audit.jsonl",
            planId: "sha256:plan",
            bundleId: "sha256:bundle",
            preflightResultId: "sha256:preflight",
            changeSetId: "sha256:changeset",
            approvalId: "sha256:approval",
            targetReferenceDigest: "sha256:target",
            transferReceiptIds: ["sha256:transfer"],
            scanReceiptIds: ["sha256:scan"],
            airgapGateResultId: "sha256:gate",
            airgapTrustPolicyId: "sha256:policy",
            airgapPolicyDiffId: "sha256:diff",
            airgapReviewId: "sha256:review",
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/runbook" && (init.method || "GET").toUpperCase() === "GET") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          runbook: {
            workspacePath: ".yara/workspaces/default",
            artifacts: {
              planPath: ".yara/workspaces/default/reference-stack.plan.yaml",
              bundlePath: ".yara/workspaces/default/reference-stack.kubernetes.bundle.yaml",
              preflightPath: ".yara/workspaces/default/reference-preflight.yaml",
              changeSetPath: ".yara/workspaces/default/reference-change-set.yaml",
              approvalPath: ".yara/workspaces/default/reference-approval.yaml",
              authorizationPath: ".yara/workspaces/default/reference-authorization.yaml",
            },
            evidence: {
              planId: "sha256:plan",
              bundleId: "sha256:bundle",
              preflightResultId: "sha256:preflight",
              changeSetId: "sha256:changeset",
              approvalId: "sha256:approval",
              authorizationId: "sha256:authorization",
              targetReferenceDigest: "sha256:target",
            },
            failClosedCheckpoints: [
              "Never send private key material to the API; run authorization signing locally.",
              "Before apply, --confirm-authorization must equal the authorization ID and typed confirmation digest.",
            ],
            steps: [
              { id: "review-evidence", title: "Review immutable evidence chain", description: "Verify artifact and digest bindings." },
              { id: "deployment-apply", title: "Execute bounded apply", description: "Run apply with explicit confirmation.", command: "yara deployment apply kubernetes ..." },
            ],
            markdown: "# YARA workflow runbook\n\n## Evidence chain\n- Authorization ID: sha256:authorization",
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/capsule" && (init.method || "GET").toUpperCase() === "GET") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          capsule: {
            workspacePath: ".yara/workspaces/default",
            ready: true,
            stages: [
              { id: "plan", label: "Plan", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.plan.yaml" },
              { id: "bundle", label: "Bundle", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.kubernetes.bundle.yaml" },
              { id: "preflight", label: "Preflight", status: "complete", artifactPath: ".yara/workspaces/default/reference-preflight.yaml" },
              { id: "changeset", label: "Change-set", status: "complete", artifactPath: ".yara/workspaces/default/reference-change-set.yaml" },
              { id: "approval", label: "Approval", status: "complete", artifactPath: ".yara/workspaces/default/reference-approval.yaml" },
              { id: "authorization", label: "Authorization", status: "complete", artifactPath: ".yara/workspaces/default/reference-authorization.yaml" },
              { id: "receipt", label: "Apply receipt", status: "complete", artifactPath: ".yara/workspaces/default/reference-receipt.yaml" },
            ],
            evidence: {
              planId: "sha256:plan",
              bundleId: "sha256:bundle",
              preflightResultId: "sha256:preflight",
              changeSetId: "sha256:changeset",
              approvalId: "sha256:approval",
              authorizationId: "sha256:authorization",
              targetReferenceDigest: "sha256:target",
            },
            runbookExports: {
              markdownPaths: [".yara/workspaces/default/workflow.runbook.md"],
              jsonPaths: [".yara/workspaces/default/workflow.runbook.json"],
            },
            blockers: [],
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/runbook/export" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        if (requestPayload.markdownPath === requestPayload.jsonPath) {
          return Promise.resolve(new Response(JSON.stringify({
            valid: false,
            diagnostics: [{ code: "YARA-SRV-025", message: "markdownPath, jsonPath and auditPath must be different files", severity: "error" }],
          }), { status: 400 }));
        }
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          export: {
            markdownPath: requestPayload.markdownPath,
            jsonPath: requestPayload.jsonPath,
            auditPath: requestPayload.auditPath,
            stepCount: 3,
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/capsule/export" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          export: {
            markdownPath: requestPayload.markdownPath,
            jsonPath: requestPayload.jsonPath,
            auditPath: requestPayload.auditPath,
            ready: true,
            blockedArchival: false,
            blockerCount: 0,
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/evidence-bundle/export" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          export: {
            manifestPath: requestPayload.manifestPath,
            auditPath: requestPayload.auditPath,
            runbookExportCount: 1,
            capsuleExportCount: 1,
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/receipt-timeline/export" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          export: {
            markdownPath: requestPayload.markdownPath,
            jsonPath: requestPayload.jsonPath,
            auditPath: requestPayload.auditPath,
            receiptCount: 2,
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/closure-package/export" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          export: {
            manifestPath: requestPayload.manifestPath,
            auditPath: requestPayload.auditPath,
            evidenceBundleCount: 1,
            receiptTimelineCount: 1,
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/closure-package/review-gate/export" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          export: {
            markdownPath: requestPayload.markdownPath,
            jsonPath: requestPayload.jsonPath,
            auditPath: requestPayload.auditPath,
            outcome: requestPayload.decision === "blocked" ? "blocked" : "passed",
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/release-decision/export" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          export: {
            ledgerPath: requestPayload.ledgerPath,
            auditPath: requestPayload.auditPath,
            publicationState: requestPayload.decision === "blocked" ? "blocked" : "ready-to-publish",
            blockerCode: requestPayload.decision === "blocked" ? "YARA-RDL-010" : "",
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/release-publication/export" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          export: {
            attestationPath: requestPayload.attestationPath,
            auditPath: requestPayload.auditPath,
            publicationState: "publishable",
            blockerCode: "",
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/release-publication/index/export" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          export: {
            manifestPath: requestPayload.manifestPath,
            auditPath: requestPayload.auditPath,
            indexState: "index-ready",
            blockerCode: "",
          },
        }), { status: 200 }));
      }
      const payloads = {
        "/api/v1/assertions": { valid: true, assertions: [{ id: "compat.a" }, { id: "compat.b" }] },
        "/api/v1/workspace?refresh=0": {
          valid: true,
          workspace: {
            path: ".yara/workspaces/default",
            stages: [
              { id: "plan", label: "Plan", status: "ready" },
              { id: "bundle", label: "Bundle", status: "not-started" },
              { id: "preflight", label: "Preflight", status: "not-started" },
              { id: "changeset", label: "Change-set", status: "not-started" },
              { id: "approval", label: "Approval", status: "not-started" },
              { id: "authorization", label: "Authorization", status: "not-started" },
              { id: "receipt", label: "Apply receipt", status: "not-started" },
            ],
          },
        },
        "/api/v1/workspace?refresh=1": {
          valid: true,
          workspace: {
            path: ".yara/workspaces/default",
            stages: [
              { id: "plan", label: "Plan", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.plan.yaml" },
              { id: "bundle", label: "Bundle", status: "not-started" },
              { id: "preflight", label: "Preflight", status: "not-started" },
              { id: "changeset", label: "Change-set", status: "not-started" },
              { id: "approval", label: "Approval", status: "not-started" },
              { id: "authorization", label: "Authorization", status: "not-started" },
              { id: "receipt", label: "Apply receipt", status: "not-started" },
            ],
          },
        },
        "/api/v1/workspace?refresh=2": {
          valid: true,
          workspace: {
            path: ".yara/workspaces/default",
            stages: [
              { id: "plan", label: "Plan", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.plan.yaml" },
              { id: "bundle", label: "Bundle", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.kubernetes.bundle.yaml" },
              { id: "preflight", label: "Preflight", status: "not-started" },
              { id: "changeset", label: "Change-set", status: "not-started" },
              { id: "approval", label: "Approval", status: "not-started" },
              { id: "authorization", label: "Authorization", status: "not-started" },
              { id: "receipt", label: "Apply receipt", status: "not-started" },
            ],
          },
        },
        "/api/v1/workspace?refresh=3": {
          valid: true,
          workspace: {
            path: ".yara/workspaces/default",
            stages: [
              { id: "plan", label: "Plan", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.plan.yaml" },
              { id: "bundle", label: "Bundle", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.kubernetes.bundle.yaml" },
              { id: "preflight", label: "Preflight", status: "complete", artifactPath: ".yara/workspaces/default/reference-preflight.yaml" },
              { id: "changeset", label: "Change-set", status: "not-started" },
              { id: "approval", label: "Approval", status: "not-started" },
              { id: "authorization", label: "Authorization", status: "not-started" },
              { id: "receipt", label: "Apply receipt", status: "not-started" },
            ],
          },
        },
        "/api/v1/workspace?refresh=4": {
          valid: true,
          workspace: {
            path: ".yara/workspaces/default",
            stages: [
              { id: "plan", label: "Plan", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.plan.yaml" },
              { id: "bundle", label: "Bundle", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.kubernetes.bundle.yaml" },
              { id: "preflight", label: "Preflight", status: "complete", artifactPath: ".yara/workspaces/default/reference-preflight.yaml" },
              { id: "changeset", label: "Change-set", status: "complete", artifactPath: ".yara/workspaces/default/reference-change-set.yaml" },
              { id: "approval", label: "Approval", status: "not-started" },
              { id: "authorization", label: "Authorization", status: "not-started" },
              { id: "receipt", label: "Apply receipt", status: "not-started" },
            ],
          },
        },
        "/api/v1/workspace?refresh=5": {
          valid: true,
          workspace: {
            path: ".yara/workspaces/default",
            stages: [
              { id: "plan", label: "Plan", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.plan.yaml" },
              { id: "bundle", label: "Bundle", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.kubernetes.bundle.yaml" },
              { id: "preflight", label: "Preflight", status: "complete", artifactPath: ".yara/workspaces/default/reference-preflight.yaml" },
              { id: "changeset", label: "Change-set", status: "complete", artifactPath: ".yara/workspaces/default/reference-change-set.yaml" },
              { id: "approval", label: "Approval", status: "complete", artifactPath: ".yara/workspaces/default/reference-approval.yaml" },
              { id: "authorization", label: "Authorization", status: "complete", artifactPath: ".yara/workspaces/default/reference-authorization.yaml" },
              { id: "receipt", label: "Apply receipt", status: "not-started" },
            ],
          },
        },
        "/api/v1/workspace?refresh=6": {
          valid: true,
          workspace: {
            path: ".yara/workspaces/default",
            stages: [
              { id: "plan", label: "Plan", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.plan.yaml" },
              { id: "bundle", label: "Bundle", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.kubernetes.bundle.yaml" },
              { id: "preflight", label: "Preflight", status: "complete", artifactPath: ".yara/workspaces/default/reference-preflight.yaml" },
              { id: "changeset", label: "Change-set", status: "complete", artifactPath: ".yara/workspaces/default/reference-change-set.yaml" },
              { id: "approval", label: "Approval", status: "complete", artifactPath: ".yara/workspaces/default/reference-approval.yaml" },
              { id: "authorization", label: "Authorization", status: "complete", artifactPath: ".yara/workspaces/default/reference-authorization.yaml" },
              { id: "receipt", label: "Apply receipt", status: "complete", artifactPath: ".yara/workspaces/default/reference-receipt.yaml" },
            ],
          },
        },
        "/api/v1/catalog": { valid: true, catalog: { digest: "sha256:test", metadata: { version: "v0.2" } }, summary: { assertions: 1, components: 2 } },
        "/api/v1/coverage": { valid: true, report: { metadata: { reportId: "sha256:report" }, spec: { complete: true, summary: { assertionCount: 1, lifecyclePublicationReadyAssertions: 0 } } } },
        "/api/v1/drift-posture": {
          valid: true,
          runtimeDriftPosture: [
            { assertion: "compat.a", status: "missing", blocker: "no-signal", selectedSignal: "none", auditReference: "report:sha256:report" },
            { assertion: "compat.b", status: "in-sync", blocker: "none", selectedSignal: "sha256:signal", auditReference: "report:sha256:report" },
          ],
        },
        "/api/v1/drift-posture?assertion=compat.a": {
          valid: true,
          runtimeDriftPosture: [
            { assertion: "compat.a", status: "missing", blocker: "no-signal", selectedSignal: "none", auditReference: "report:sha256:report" },
          ],
        },
        "/api/v1/lifecycle-policy?assertion=compat.a": {
          valid: true,
          assertionScope: { mode: "single-assertion", assertion: "compat.a" },
          taxonomy: [{ code: "missing-proof", remediation: "record-proof" }],
          lifecyclePosture: [
            {
              assertion: "compat.a",
              ready: false,
              lifecycleProof: "missing",
              integrationAttestation: "passed",
              publicationRehearsal: "missing",
              renewalReview: "missing",
              code: "missing-proof",
              remediation: "record-proof",
            },
          ],
        },
        "/api/v1/lifecycle-policy": {
          valid: true,
          assertionScope: { mode: "all", assertion: "all" },
          taxonomy: [{ code: "missing-proof", remediation: "record-proof" }],
          lifecyclePosture: [
            {
              assertion: "compat.a",
              ready: false,
              lifecycleProof: "missing",
              integrationAttestation: "passed",
              publicationRehearsal: "missing",
              renewalReview: "missing",
              code: "missing-proof",
              remediation: "record-proof",
            },
            {
              assertion: "compat.b",
              ready: true,
              lifecycleProof: "passed",
              integrationAttestation: "passed",
              publicationRehearsal: "passed",
              renewalReview: "passed",
            },
          ],
        },
      };
      const body = payloads[endpoint];
      if (!body) {
        return Promise.resolve(new Response(JSON.stringify({ valid: false }), { status: 404 }));
      }
      return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
    });
  });

  it("renders nav and loads each view", async () => {
    render(<App />);
    expect(screen.getByText("YARA Web UI (Read-only)")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Plan")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Plan create" }));
    await waitFor(() => expect(screen.getByText("Workspace: .yara/workspaces/default")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Create plan" }));
    await waitFor(() => expect(screen.getByText("sha256:plan")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Render" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Render bundle" })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Render bundle" }));
    await waitFor(() => expect(screen.getByText("sha256:bundle")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Preflight" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Run preflight" })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Run preflight" }));
    await waitFor(() => expect(screen.getByText("sha256:preflight")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Change-set" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Compute change-set" })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Compute change-set" }));
    await waitFor(() => expect(screen.getByText("sha256:changeset")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("Hard blocker: approval remains disabled until conflicts or unresolved objects are cleared.")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Approval" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Record approval" })).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Decision"), { target: { value: "approve" } });
    fireEvent.change(screen.getByLabelText("Reason reference"), { target: { value: "ticket-123" } });
    fireEvent.click(screen.getByRole("button", { name: "Record approval" }));
    await waitFor(() => expect(screen.getByText("sha256:approval")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Authorization + apply" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Refresh authorization command" })).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText(/yara authorization issue/)).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Import receipt path"), { target: { value: ".yara/workspaces/default/reference-import-receipt.yaml" } });
    fireEvent.change(screen.getByLabelText("Public key path"), { target: { value: ".yara/keys/operations.pub.pem" } });
    fireEvent.change(screen.getByLabelText("Confirm authorization digest"), { target: { value: "sha256:authorization" } });
    fireEvent.change(screen.getByLabelText("Type confirmation digest"), { target: { value: "sha256:authorization" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm and apply" }));
    await waitFor(() => expect(screen.getByText("sha256:receipt")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Runbook" }));
    await waitFor(() => expect(screen.getByText("Copy-ready runbook")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("Review immutable evidence chain")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Export runbook" }));
    await waitFor(() => expect(screen.getByText(".yara/workspaces/default/workflow.runbook.md")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Execution capsule" }));
    await waitFor(() => expect(screen.getByText("No blockers. Capsule is ready.")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Export capsule" }));
    await waitFor(() => expect(screen.getByText(".yara/workspaces/default/workflow.capsule.md")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Export evidence bundle" }));
    await waitFor(() => expect(screen.getByText(".yara/workspaces/default/workflow.evidence-bundle.json")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Export receipt timeline" }));
    await waitFor(() => expect(screen.getByText(".yara/workspaces/default/workflow.receipt-timeline.json")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Release readiness reference"), { target: { value: "release-checklist-001" } });
    fireEvent.click(screen.getByRole("button", { name: "Export closure package" }));
    await waitFor(() => expect(screen.getByText(".yara/workspaces/default/workflow.closure-package.json")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Review gate release readiness reference"), { target: { value: "release-checklist-001" } });
    fireEvent.change(screen.getByLabelText("Reviewer reference"), { target: { value: "ticket-456" } });
    fireEvent.click(screen.getByRole("button", { name: "Export closure review gate" }));
    await waitFor(() => expect(screen.getByText(".yara/workspaces/default/workflow.closure-review-gate.json")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Release decision release readiness reference"), { target: { value: "release-checklist-001" } });
    fireEvent.change(screen.getByLabelText("Release decision reviewer reference"), { target: { value: "ticket-456" } });
    fireEvent.change(screen.getByLabelText("Release decision operator reference"), { target: { value: "operator-1" } });
    fireEvent.change(screen.getByLabelText("Decision timestamp (RFC3339)"), { target: { value: "2026-07-21T00:05:00Z" } });
    fireEvent.click(screen.getByRole("button", { name: "Export release decision" }));
    await waitFor(() => expect(screen.getByText(".yara/workspaces/default/workflow.release-decision.json")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Publication channel"), { target: { value: "github-release" } });
    fireEvent.change(screen.getByLabelText("Artifact location reference"), { target: { value: "gh://releases/v0.2.0-alpha.2" } });
    fireEvent.change(screen.getByLabelText("Publication timestamp (RFC3339)"), { target: { value: "2026-07-21T00:10:00Z" } });
    fireEvent.change(screen.getByLabelText("Publication operator reference"), { target: { value: "operator-2" } });
    fireEvent.click(screen.getByRole("button", { name: "Export release publication" }));
    await waitFor(() => expect(screen.getByText(".yara/workspaces/default/workflow.release-publication.json")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Publication batch reference"), { target: { value: "batch-2026-07-21" } });
    fireEvent.change(screen.getByLabelText("Publication index operator reference"), { target: { value: "operator-3" } });
    fireEvent.click(screen.getByRole("button", { name: "Export publication index" }));
    await waitFor(() => expect(screen.getByText(".yara/workspaces/default/workflow.release-publication.index.json")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Catalog" }));
    await waitFor(() => expect(screen.getByText("sha256:test")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Coverage" }));
    await waitFor(() => expect(screen.getByText("sha256:report")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Drift" }));
    await waitFor(() => expect(screen.getByText("Assertion filter")).toBeInTheDocument());
    await waitFor(() => expect(screen.getAllByText("Selected signal:").length).toBeGreaterThan(0));
    fireEvent.change(screen.getByLabelText("Assertion filter"), { target: { value: "compat.a" } });
    await waitFor(() => expect(screen.getAllByText("Remediation:").length).toBeGreaterThan(0));
    await waitFor(() => expect(screen.getByText("record-runtime-drift-signal")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Lifecycle" }));
    await waitFor(() => expect(screen.getByText(/Taxonomy entries:\s*1/)).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Assertion filter"), { target: { value: "compat.a" } });
    await waitFor(() => expect(screen.getByText("missing-proof")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("record-proof")).toBeInTheDocument());
  });

  it("enforces air-gap apply guardrails in UI", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Authorization + apply" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Refresh authorization command" })).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Import receipt path"), { target: { value: ".yara/workspaces/default/reference-import-receipt.yaml" } });
    fireEvent.change(screen.getByLabelText("Public key path"), { target: { value: ".yara/keys/operations.pub.pem" } });
    fireEvent.change(screen.getByLabelText("Confirm authorization digest"), { target: { value: "sha256:authorization" } });
    fireEvent.change(screen.getByLabelText("Type confirmation digest"), { target: { value: "sha256:authorization" } });
    fireEvent.change(screen.getByLabelText("Air-gap gate result path (optional)"), { target: { value: ".yara/workspaces/default/airgap-gate.yaml" } });
    await waitFor(() => expect(screen.getByText("Providing an air-gap gate result also requires trust policy path and confirmed trust policy ID.")).toBeInTheDocument());
  });

  it("renders blocked capsule diagnostics", async () => {
    global.fetch = vi.fn((input, init = {}) => {
      const parsed = new URL(String(input), "http://localhost");
      const endpoint = parsed.pathname + (parsed.search || "");
      if (parsed.pathname === "/api/v1/workflow/capsule/export" && (init.method || "GET").toUpperCase() === "POST") {
        const requestPayload = JSON.parse(String(init.body || "{}"));
        if (!requestPayload.allowBlocked) {
          return Promise.resolve(new Response(JSON.stringify({
            valid: false,
            diagnostics: [{ code: "YARA-SRV-027", message: "capsule is blocked; set allowBlocked=true with allowBlockedReasonReference to archive blocked state", severity: "error" }],
          }), { status: 422 }));
        }
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          export: {
            markdownPath: requestPayload.markdownPath,
            jsonPath: requestPayload.jsonPath,
            auditPath: requestPayload.auditPath,
            ready: false,
            blockedArchival: true,
            blockerCount: 1,
          },
        }), { status: 200 }));
      }
      if (parsed.pathname === "/api/v1/workflow/evidence-bundle/export" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: false,
          diagnostics: [{ code: "YARA-SRV-028", message: "evidence bundle requires runbook markdown and json exports in workspace", severity: "error" }],
        }), { status: 400 }));
      }
      if (parsed.pathname === "/api/v1/workflow/receipt-timeline/export" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: false,
          diagnostics: [{ code: "YARA-SRV-030", message: "receipt authorization binding does not match workspace authorization", severity: "error" }],
        }), { status: 400 }));
      }
      if (parsed.pathname === "/api/v1/workflow/closure-package/export" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: false,
          diagnostics: [{ code: "YARA-SRV-031", message: "YARA-CLS-003: evidence bundle and receipt timeline authorization continuity is mismatched", severity: "error" }],
        }), { status: 400 }));
      }
      if (parsed.pathname === "/api/v1/workflow/closure-package/review-gate/export" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: false,
          diagnostics: [{ code: "YARA-SRV-033", message: "YARA-RVG-006: closure package continuity is mismatched against current evidence bundle and receipt timeline exports", severity: "error" }],
        }), { status: 422 }));
      }
      if (parsed.pathname === "/api/v1/workflow/release-decision/export" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: false,
          diagnostics: [{ code: "YARA-SRV-034", message: "YARA-RDL-006: closure package and review gate continuity chains are mismatched", severity: "error" }],
        }), { status: 422 }));
      }
      if (parsed.pathname === "/api/v1/workflow/release-publication/export" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: false,
          diagnostics: [{ code: "YARA-SRV-035", message: "YARA-RPB-003: latest release decision is blocked and cannot be published", severity: "error" }],
        }), { status: 422 }));
      }
      if (parsed.pathname === "/api/v1/workflow/release-publication/index/export" && (init.method || "GET").toUpperCase() === "POST") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: false,
          diagnostics: [{ code: "YARA-SRV-036", message: "YARA-RPI-003: latest release publication attestation is blocked", severity: "error" }],
        }), { status: 422 }));
      }
      if (endpoint === "/api/v1/assertions") {
        return Promise.resolve(new Response(JSON.stringify({ valid: true, assertions: [{ id: "compat.a" }] }), { status: 200 }));
      }
      if (endpoint === "/api/v1/workflow/capsule") {
        return Promise.resolve(new Response(JSON.stringify({
          valid: true,
          capsule: {
            workspacePath: ".yara/workspaces/default",
            ready: false,
            stages: [{ id: "plan", label: "Plan", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.plan.yaml" }],
            runbookExports: { markdownPaths: [], jsonPaths: [] },
            blockers: [{ code: "YARA-CAP-013", severity: "error", message: "evidence mismatch", remediation: "regenerate evidence chain" }],
          },
        }), { status: 200 }));
      }
      if (endpoint === "/api/v1/workspace?refresh=0") {
        return Promise.resolve(new Response(JSON.stringify({ valid: true, workspace: { path: ".yara/workspaces/default", stages: [{ id: "plan", label: "Plan", status: "complete", artifactPath: ".yara/workspaces/default/reference-stack.plan.yaml" }] } }), { status: 200 }));
      }
      return Promise.resolve(new Response(JSON.stringify({ valid: true }), { status: 200 }));
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Execution capsule" }));
    await waitFor(() => expect(screen.getByText("evidence mismatch")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("regenerate evidence chain")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Export capsule" }));
    await waitFor(() => expect(screen.getByText(/allowBlocked=true/)).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("Allow blocked archival"));
    fireEvent.change(screen.getByLabelText("Blocked archival reason reference"), { target: { value: "ticket-42" } });
    fireEvent.click(screen.getByRole("button", { name: "Export capsule" }));
    await waitFor(() => expect(screen.getByText(".yara/workspaces/default/workflow.capsule.export.audit.jsonl")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Export evidence bundle" }));
    await waitFor(() => expect(screen.getByText(/runbook markdown and json exports/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Export receipt timeline" }));
    await waitFor(() => expect(screen.getByText(/does not match workspace authorization/)).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Release readiness reference"), { target: { value: "release-checklist-001" } });
    fireEvent.click(screen.getByRole("button", { name: "Export closure package" }));
    await waitFor(() => expect(screen.getByText(/continuity is mismatched/)).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Review gate release readiness reference"), { target: { value: "release-checklist-001" } });
    fireEvent.change(screen.getByLabelText("Reviewer reference"), { target: { value: "ticket-456" } });
    fireEvent.click(screen.getByRole("button", { name: "Export closure review gate" }));
    await waitFor(() => expect(screen.getByText(/YARA-RVG-006/)).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Release decision release readiness reference"), { target: { value: "release-checklist-001" } });
    fireEvent.change(screen.getByLabelText("Release decision reviewer reference"), { target: { value: "ticket-456" } });
    fireEvent.change(screen.getByLabelText("Release decision operator reference"), { target: { value: "operator-1" } });
    fireEvent.change(screen.getByLabelText("Decision timestamp (RFC3339)"), { target: { value: "2026-07-21T00:05:00Z" } });
    fireEvent.click(screen.getByRole("button", { name: "Export release decision" }));
    await waitFor(() => expect(screen.getByText(/YARA-RDL-006/)).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Publication channel"), { target: { value: "github-release" } });
    fireEvent.change(screen.getByLabelText("Artifact location reference"), { target: { value: "gh://releases/v0.2.0-alpha.2" } });
    fireEvent.change(screen.getByLabelText("Publication timestamp (RFC3339)"), { target: { value: "2026-07-21T00:10:00Z" } });
    fireEvent.change(screen.getByLabelText("Publication operator reference"), { target: { value: "operator-2" } });
    fireEvent.click(screen.getByRole("button", { name: "Export release publication" }));
    await waitFor(() => expect(screen.getByText(/Publication readiness: blocked/)).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText(/YARA-RPB-003/)).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Publication batch reference"), { target: { value: "batch-2026-07-21" } });
    fireEvent.change(screen.getByLabelText("Publication index operator reference"), { target: { value: "operator-3" } });
    fireEvent.click(screen.getByRole("button", { name: "Export publication index" }));
    await waitFor(() => expect(screen.getByText(/Index readiness: blocked/)).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText(/YARA-RPI-003/)).toBeInTheDocument());
  });

  it("fails closed on malformed drift payload", async () => {
    global.fetch = vi.fn((input) => {
      const parsed = new URL(String(input), "http://localhost");
      const endpoint = parsed.pathname + (parsed.search || "");
      if (endpoint === "/api/v1/assertions") {
        return Promise.resolve(new Response(JSON.stringify({ valid: true, assertions: [{ id: "compat.a" }] }), { status: 200 }));
      }
      if (endpoint === "/api/v1/drift-posture") {
        return Promise.resolve(new Response(JSON.stringify({ valid: true, runtimeDriftPosture: [{ assertion: "compat.a", status: "unknown" }] }), { status: 200 }));
      }
      return Promise.resolve(new Response(JSON.stringify({ valid: true }), { status: 200 }));
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Drift" }));
    await waitFor(() => expect(screen.getByText(/Malformed runtime drift posture payload|Unsupported runtime drift posture status/)).toBeInTheDocument());
  });

  it("fails closed on malformed lifecycle payload", async () => {
    global.fetch = vi.fn((input) => {
      const parsed = new URL(String(input), "http://localhost");
      const endpoint = parsed.pathname + (parsed.search || "");
      if (endpoint === "/api/v1/assertions") {
        return Promise.resolve(new Response(JSON.stringify({ valid: true, assertions: [{ id: "compat.a" }] }), { status: 200 }));
      }
      if (endpoint === "/api/v1/lifecycle-policy") {
        return Promise.resolve(new Response(JSON.stringify({ valid: true, lifecyclePosture: [{ assertion: "compat.a", ready: true, lifecycleProof: "unknown" }], taxonomy: [] }), { status: 200 }));
      }
      return Promise.resolve(new Response(JSON.stringify({ valid: true }), { status: 200 }));
    });
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "Lifecycle" }));
    await waitFor(() => expect(screen.getByText(/Malformed lifecycle publication payload|Malformed lifecycle gate status/)).toBeInTheDocument());
  });

  it("fails closed on malformed workspace payload", async () => {
    global.fetch = vi.fn((input) => {
      const parsed = new URL(String(input), "http://localhost");
      const endpoint = parsed.pathname + (parsed.search || "");
      if (endpoint === "/api/v1/assertions") {
        return Promise.resolve(new Response(JSON.stringify({ valid: true, assertions: [{ id: "compat.a" }] }), { status: 200 }));
      }
      if (endpoint === "/api/v1/workspace?refresh=0") {
        return Promise.resolve(new Response(JSON.stringify({ valid: true, workspace: { path: ".yara", stages: [{ id: "plan", label: "Plan", status: "invalid" }] } }), { status: 200 }));
      }
      return Promise.resolve(new Response(JSON.stringify({ valid: true }), { status: 200 }));
    });
    render(<App />);
    await waitFor(() => expect(screen.getByText(/Malformed workspace pipeline payload|Unsupported workspace stage status/)).toBeInTheDocument());
  });
});
