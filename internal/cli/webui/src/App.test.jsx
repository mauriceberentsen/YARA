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
