import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

describe("App", () => {
  beforeEach(() => {
    global.fetch = vi.fn((input) => {
      const endpoint = String(input);
      const payloads = {
        "/api/v1/catalog": { valid: true, catalog: { digest: "sha256:test", metadata: { version: "v0.2" } }, summary: { assertions: 1, components: 2 } },
        "/api/v1/coverage": { valid: true, report: { metadata: { reportId: "sha256:report" }, spec: { complete: true, summary: { assertionCount: 1, lifecyclePublicationReadyAssertions: 0 } } } },
        "/api/v1/drift-posture": { valid: true, runtimeDriftPosture: [{ assertion: "compat.a", status: "missing", blocker: "no-signal" }] },
        "/api/v1/lifecycle-policy": { valid: true, lifecyclePublicationPolicy: { policyPassed: false }, blockedAssertions: [{ assertion: "compat.a", code: "missing-proof", remediation: "record-proof" }] },
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
    await waitFor(() => expect(screen.getByText("sha256:test")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Coverage" }));
    await waitFor(() => expect(screen.getByText("sha256:report")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Drift" }));
    await waitFor(() => expect(screen.getByText("compat.a")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Lifecycle" }));
    await waitFor(() => expect(screen.getByText("record-proof")).toBeInTheDocument());
  });
});
