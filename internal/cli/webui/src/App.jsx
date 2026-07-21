import { useEffect, useMemo, useState } from "react";

const views = [
  { id: "pipeline", label: "Pipeline", endpoint: "/api/v1/workspace" },
  { id: "plan-create", label: "Plan create", endpoint: "/api/v1/workspace" },
  { id: "render", label: "Render", endpoint: "/api/v1/workspace" },
  { id: "preflight", label: "Preflight", endpoint: "/api/v1/workspace" },
  { id: "changeset", label: "Change-set", endpoint: "/api/v1/workspace" },
  { id: "approval", label: "Approval", endpoint: "/api/v1/workspace" },
  { id: "apply", label: "Authorization + apply", endpoint: "/api/v1/workspace" },
  { id: "runbook", label: "Runbook", endpoint: "/api/v1/workflow/runbook" },
  { id: "capsule", label: "Execution capsule", endpoint: "/api/v1/workflow/capsule" },
  { id: "catalog", label: "Catalog", endpoint: "/api/v1/catalog" },
  { id: "coverage", label: "Coverage", endpoint: "/api/v1/coverage" },
  { id: "drift", label: "Drift", endpoint: "/api/v1/drift-posture" },
  { id: "lifecycle", label: "Lifecycle", endpoint: "/api/v1/lifecycle-policy" },
];

const identityDecoder = (payload) => payload;

const driftStatusRemediation = {
  "in-sync": "none",
  missing: "record-runtime-drift-signal",
  drifted: "resolve-runtime-drift-and-rerecord-signal",
};

const lifecycleStatuses = ["passed", "missing", "blocked", "failed"];
const pipelineStatuses = ["not-started", "ready", "complete"];

function useEndpoint(endpoint, decoder = identityDecoder) {
  const [state, setState] = useState({ loading: true, payload: null, error: "" });
  useEffect(() => {
    const controller = new AbortController();
    setState({ loading: true, payload: null, error: "" });
    fetch(endpoint, { method: "GET", signal: controller.signal })
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload?.diagnostics?.[0]?.message || "Request failed");
        }
        const decoded = decoder(payload);
        setState({ loading: false, payload: decoded, error: "" });
      })
      .catch((error) => {
        if (error.name === "AbortError") {
          return;
        }
        setState({ loading: false, payload: null, error: error.message || "Request failed" });
      });
    return () => controller.abort();
  }, [endpoint, decoder]);
  return state;
}

function decodeDriftPayload(payload) {
  if (!payload || payload.valid !== true || !Array.isArray(payload.runtimeDriftPosture)) {
    throw new Error("Malformed runtime drift posture payload.");
  }
  const seen = new Set();
  const posture = payload.runtimeDriftPosture.map((item) => {
    if (!item || typeof item.assertion !== "string" || typeof item.status !== "string") {
      throw new Error("Malformed runtime drift posture record.");
    }
    if (seen.has(item.assertion)) {
      throw new Error("Duplicate runtime drift posture assertion.");
    }
    if (!["in-sync", "missing", "drifted"].includes(item.status)) {
      throw new Error("Unsupported runtime drift posture status.");
    }
    seen.add(item.assertion);
    return {
      assertion: item.assertion,
      status: item.status,
      blocker: item.blocker || "none",
      selectedSignal: item.selectedSignal || "none",
      auditReference: item.auditReference || "none",
      remediation: driftStatusRemediation[item.status] || "none",
    };
  });
  posture.sort((left, right) => left.assertion.localeCompare(right.assertion));
  return {
    ...payload,
    runtimeDriftPosture: posture,
  };
}

function DriftView({ driftAssertion, setDriftAssertion, payload, assertions }) {
  const posture = payload.runtimeDriftPosture || [];
  return (
    <>
      <div className="filterRow">
        <label htmlFor="drift-assertion">Assertion filter</label>
        <select id="drift-assertion" value={driftAssertion} onChange={(event) => setDriftAssertion(event.target.value)}>
          <option value="">All assertions</option>
          {assertions.map((assertion) => (
            <option key={assertion} value={assertion}>
              {assertion}
            </option>
          ))}
        </select>
      </div>
      {posture.length === 0 ? (
        <p className="empty">No runtime drift posture records.</p>
      ) : (
        <div className="cardGrid">
          {posture.map((row) => (
            <article key={row.assertion} className={`driftCard status-${row.status}`}>
              <h3>{row.assertion}</h3>
              <p><strong>Status:</strong> {row.status}</p>
              <p><strong>Blocker:</strong> {row.blocker}</p>
              <p><strong>Remediation:</strong> {row.remediation}</p>
              <p><strong>Selected signal:</strong> {row.selectedSignal}</p>
              <p><strong>Audit reference:</strong> {row.auditReference}</p>
            </article>
          ))}
        </div>
      )}
    </>
  );
}

function decodeLifecyclePayload(payload) {
  if (!payload || payload.valid !== true || !Array.isArray(payload.lifecyclePosture) || !Array.isArray(payload.taxonomy)) {
    throw new Error("Malformed lifecycle publication payload.");
  }
  const seen = new Set();
  const posture = payload.lifecyclePosture.map((item) => {
    if (!item || typeof item.assertion !== "string" || typeof item.ready !== "boolean") {
      throw new Error("Malformed lifecycle posture record.");
    }
    if (seen.has(item.assertion)) {
      throw new Error("Duplicate lifecycle posture assertion.");
    }
    seen.add(item.assertion);
    const pillars = [item.lifecycleProof, item.integrationAttestation, item.publicationRehearsal, item.renewalReview];
    for (const pillar of pillars) {
      if (typeof pillar !== "string" || !lifecycleStatuses.includes(pillar)) {
        throw new Error("Malformed lifecycle gate status.");
      }
    }
    return {
      assertion: item.assertion,
      ready: item.ready,
      lifecycleProof: item.lifecycleProof,
      integrationAttestation: item.integrationAttestation,
      publicationRehearsal: item.publicationRehearsal,
      renewalReview: item.renewalReview,
      code: item.code || "none",
      remediation: item.remediation || "none",
    };
  });
  posture.sort((left, right) => left.assertion.localeCompare(right.assertion));
  return {
    ...payload,
    lifecyclePosture: posture,
  };
}

function LifecycleView({ lifecycleAssertion, setLifecycleAssertion, payload, assertions }) {
  const posture = payload.lifecyclePosture || [];
  return (
    <>
      <div className="filterRow">
        <label htmlFor="lifecycle-assertion">Assertion filter</label>
        <select id="lifecycle-assertion" value={lifecycleAssertion} onChange={(event) => setLifecycleAssertion(event.target.value)}>
          <option value="">All assertions</option>
          {assertions.map((assertion) => (
            <option key={assertion} value={assertion}>
              {assertion}
            </option>
          ))}
        </select>
      </div>
      <p>
        Policy scope: {payload.assertionScope?.mode || "unknown"} | Taxonomy entries: {Array.isArray(payload.taxonomy) ? payload.taxonomy.length : 0}
      </p>
      {posture.length === 0 ? (
        <p className="empty">No lifecycle posture records.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Assertion</th>
              <th>Ready</th>
              <th>Lifecycle proof</th>
              <th>Integration</th>
              <th>Rehearsal</th>
              <th>Renewal</th>
              <th>Blocker code</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody>
            {posture.map((row) => (
              <tr key={row.assertion}>
                <td>{row.assertion}</td>
                <td>{String(row.ready)}</td>
                <td>{row.lifecycleProof}</td>
                <td>{row.integrationAttestation}</td>
                <td>{row.publicationRehearsal}</td>
                <td>{row.renewalReview}</td>
                <td>{row.code}</td>
                <td>{row.remediation}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function decodeWorkspacePayload(payload) {
  if (!payload || payload.valid !== true || !payload.workspace || !Array.isArray(payload.workspace.stages)) {
    throw new Error("Malformed workspace pipeline payload.");
  }
  const seen = new Set();
  const stages = payload.workspace.stages.map((item) => {
    if (!item || typeof item.id !== "string" || typeof item.label !== "string" || typeof item.status !== "string") {
      throw new Error("Malformed workspace stage record.");
    }
    if (seen.has(item.id)) {
      throw new Error("Duplicate workspace stage record.");
    }
    if (!pipelineStatuses.includes(item.status)) {
      throw new Error("Unsupported workspace stage status.");
    }
    seen.add(item.id);
    return {
      id: item.id,
      label: item.label,
      status: item.status,
      artifactPath: typeof item.artifactPath === "string" && item.artifactPath !== "" ? item.artifactPath : "none",
    };
  });
  return {
    ...payload,
    workspace: {
      path: payload.workspace.path || "unknown",
      stages,
    },
  };
}

function PipelineView({ payload }) {
  const stages = payload.workspace?.stages || [];
  return (
    <>
      <p>Workspace: {payload.workspace?.path || "unknown"}</p>
      {stages.length === 0 ? (
        <p className="empty">No pipeline stages available.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Stage</th>
              <th>Status</th>
              <th>Artifact</th>
            </tr>
          </thead>
          <tbody>
            {stages.map((stage) => (
              <tr key={stage.id}>
                <td>{stage.label}</td>
                <td>{stage.status}</td>
                <td>{stage.artifactPath}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function PlanCreateView({ workspacePayload, onPlanCreated }) {
  const workspacePath = workspacePayload?.workspace?.path || "";
  const [form, setForm] = useState(() => ({
    requestPath: "docs/examples/v0.2-platform-request.yaml",
    inventoryPath: "docs/examples/v0.2-inventory.yaml",
    catalogPath: "catalog/v0.2/snapshot.yaml",
    outputPath: workspacePath ? `${workspacePath}/reference-stack.plan.yaml` : "",
    auditPath: workspacePath ? `${workspacePath}/reference-stack.plan.audit.jsonl` : "",
  }));
  const [submitState, setSubmitState] = useState({ loading: false, error: "", result: null });

  useEffect(() => {
    if (!workspacePath) {
      return;
    }
    setForm((previous) => {
      const next = { ...previous };
      if (!previous.outputPath) {
        next.outputPath = `${workspacePath}/reference-stack.plan.yaml`;
      }
      if (!previous.auditPath) {
        next.auditPath = `${workspacePath}/reference-stack.plan.audit.jsonl`;
      }
      return next;
    });
  }, [workspacePath]);

  const update = (key) => (event) => {
    setForm((previous) => ({ ...previous, [key]: event.target.value }));
  };

  const submit = async (event) => {
    event.preventDefault();
    setSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.diagnostics?.[0]?.message || "Plan creation failed");
      }
      setSubmitState({ loading: false, error: "", result: payload.plan || null });
      onPlanCreated();
    } catch (error) {
      setSubmitState({ loading: false, error: error.message || "Plan creation failed", result: null });
    }
  };

  return (
    <>
      <p>Workspace: {workspacePath || "unknown"}</p>
      <form onSubmit={submit}>
        <div className="formRow">
          <label htmlFor="plan-request-path">Request path</label>
          <input id="plan-request-path" value={form.requestPath} onChange={update("requestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="plan-inventory-path">Inventory path</label>
          <input id="plan-inventory-path" value={form.inventoryPath} onChange={update("inventoryPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="plan-catalog-path">Catalog path</label>
          <input id="plan-catalog-path" value={form.catalogPath} onChange={update("catalogPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="plan-output-path">Plan output path</label>
          <input id="plan-output-path" value={form.outputPath} onChange={update("outputPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="plan-audit-path">Audit output path</label>
          <input id="plan-audit-path" value={form.auditPath} onChange={update("auditPath")} />
        </div>
        <button type="submit" disabled={submitState.loading}>
          {submitState.loading ? "Creating plan..." : "Create plan"}
        </button>
      </form>
      {submitState.error && <p className="error">Error: {submitState.error}</p>}
      {submitState.result && (
        <dl className="grid">
          <div><dt>Plan ID</dt><dd>{submitState.result.planId || "n/a"}</dd></div>
          <div><dt>Confidence</dt><dd>{submitState.result.confidence || "n/a"}</dd></div>
          <div><dt>Plan path</dt><dd>{submitState.result.planPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{submitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Decisions</dt><dd>{String(submitState.result.decisions ?? 0)}</dd></div>
          <div><dt>Instances</dt><dd>{String(submitState.result.instances ?? 0)}</dd></div>
          <div><dt>Components</dt><dd>{String(submitState.result.components ?? 0)}</dd></div>
          <div><dt>Diagnostics</dt><dd>{String(submitState.result.diagnostics ?? 0)}</dd></div>
        </dl>
      )}
    </>
  );
}

function RenderView({ workspacePayload, onRenderCreated }) {
  const workspacePath = workspacePayload?.workspace?.path || "";
  const [form, setForm] = useState(() => ({
    planPath: workspacePath ? `${workspacePath}/reference-stack.plan.yaml` : "",
    catalogPath: "catalog/v0.2/snapshot.yaml",
    target: "kubernetes-gitops",
    bundleName: "reference-stack",
    outputPath: workspacePath ? `${workspacePath}/reference-stack.kubernetes.bundle.yaml` : "",
    auditPath: workspacePath ? `${workspacePath}/reference-stack.kubernetes.bundle.audit.jsonl` : "",
  }));
  const [submitState, setSubmitState] = useState({ loading: false, error: "", result: null });

  useEffect(() => {
    if (!workspacePath) {
      return;
    }
    setForm((previous) => {
      const next = { ...previous };
      if (!previous.planPath) {
        next.planPath = `${workspacePath}/reference-stack.plan.yaml`;
      }
      if (!previous.outputPath) {
        next.outputPath = `${workspacePath}/reference-stack.kubernetes.bundle.yaml`;
      }
      if (!previous.auditPath) {
        next.auditPath = `${workspacePath}/reference-stack.kubernetes.bundle.audit.jsonl`;
      }
      return next;
    });
  }, [workspacePath]);

  const update = (key) => (event) => {
    setForm((previous) => ({ ...previous, [key]: event.target.value }));
  };

  const submit = async (event) => {
    event.preventDefault();
    setSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/render", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.diagnostics?.[0]?.message || "Render failed");
      }
      setSubmitState({ loading: false, error: "", result: payload.render || null });
      onRenderCreated();
    } catch (error) {
      setSubmitState({ loading: false, error: error.message || "Render failed", result: null });
    }
  };

  return (
    <>
      <p>Workspace: {workspacePath || "unknown"}</p>
      <form onSubmit={submit}>
        <div className="formRow">
          <label htmlFor="render-plan-path">Plan path</label>
          <input id="render-plan-path" value={form.planPath} onChange={update("planPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="render-catalog-path">Catalog path</label>
          <input id="render-catalog-path" value={form.catalogPath} onChange={update("catalogPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="render-target">Target</label>
          <select id="render-target" value={form.target} onChange={update("target")}>
            <option value="kubernetes-gitops">kubernetes-gitops</option>
            <option value="docker-compose">docker-compose</option>
          </select>
        </div>
        <div className="formRow">
          <label htmlFor="render-bundle-name">Bundle name</label>
          <input id="render-bundle-name" value={form.bundleName} onChange={update("bundleName")} />
        </div>
        <div className="formRow">
          <label htmlFor="render-output-path">Bundle output path</label>
          <input id="render-output-path" value={form.outputPath} onChange={update("outputPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="render-audit-path">Audit output path</label>
          <input id="render-audit-path" value={form.auditPath} onChange={update("auditPath")} />
        </div>
        <button type="submit" disabled={submitState.loading}>
          {submitState.loading ? "Rendering bundle..." : "Render bundle"}
        </button>
      </form>
      {submitState.error && <p className="error">Error: {submitState.error}</p>}
      {submitState.result && (
        <dl className="grid">
          <div><dt>Bundle ID</dt><dd>{submitState.result.bundleId || "n/a"}</dd></div>
          <div><dt>Renderer</dt><dd>{submitState.result.renderer || "n/a"}</dd></div>
          <div><dt>Bundle path</dt><dd>{submitState.result.bundlePath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{submitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Manifests</dt><dd>{String(submitState.result.manifestCount ?? 0)}</dd></div>
          <div><dt>Artifacts</dt><dd>{String(submitState.result.artifactCount ?? 0)}</dd></div>
          <div><dt>Operations</dt><dd>{String(submitState.result.operationCount ?? 0)}</dd></div>
        </dl>
      )}
    </>
  );
}

function PreflightView({ workspacePayload, onPreflightCreated }) {
  const workspacePath = workspacePayload?.workspace?.path || "";
  const [form, setForm] = useState(() => ({
    bundlePath: workspacePath ? `${workspacePath}/reference-stack.kubernetes.bundle.yaml` : "",
    name: "reference-preflight",
    outputPath: workspacePath ? `${workspacePath}/reference-preflight.yaml` : "",
    auditPath: workspacePath ? `${workspacePath}/reference-preflight.audit.jsonl` : "",
    kubeconfig: "",
    context: "",
    timeout: "30s",
  }));
  const [submitState, setSubmitState] = useState({ loading: false, error: "", result: null });

  useEffect(() => {
    if (!workspacePath) {
      return;
    }
    setForm((previous) => {
      const next = { ...previous };
      if (!previous.bundlePath) {
        next.bundlePath = `${workspacePath}/reference-stack.kubernetes.bundle.yaml`;
      }
      if (!previous.outputPath) {
        next.outputPath = `${workspacePath}/reference-preflight.yaml`;
      }
      if (!previous.auditPath) {
        next.auditPath = `${workspacePath}/reference-preflight.audit.jsonl`;
      }
      return next;
    });
  }, [workspacePath]);

  const update = (key) => (event) => {
    setForm((previous) => ({ ...previous, [key]: event.target.value }));
  };

  const submit = async (event) => {
    event.preventDefault();
    setSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/preflight", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const payload = await response.json();
      if (!response.ok && !payload?.preflight) {
        throw new Error(payload?.diagnostics?.[0]?.message || "Preflight failed");
      }
      setSubmitState({
        loading: false,
        error: response.ok ? "" : payload?.diagnostics?.[0]?.message || "Preflight returned blockers",
        result: payload.preflight || null,
      });
      onPreflightCreated();
    } catch (error) {
      setSubmitState({ loading: false, error: error.message || "Preflight failed", result: null });
    }
  };

  return (
    <>
      <p>Workspace: {workspacePath || "unknown"}</p>
      <form onSubmit={submit}>
        <div className="formRow">
          <label htmlFor="preflight-bundle-path">Bundle path</label>
          <input id="preflight-bundle-path" value={form.bundlePath} onChange={update("bundlePath")} />
        </div>
        <div className="formRow">
          <label htmlFor="preflight-name">Preflight name</label>
          <input id="preflight-name" value={form.name} onChange={update("name")} />
        </div>
        <div className="formRow">
          <label htmlFor="preflight-output-path">Preflight output path</label>
          <input id="preflight-output-path" value={form.outputPath} onChange={update("outputPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="preflight-audit-path">Audit output path</label>
          <input id="preflight-audit-path" value={form.auditPath} onChange={update("auditPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="preflight-kubeconfig">Kubeconfig path (optional)</label>
          <input id="preflight-kubeconfig" value={form.kubeconfig} onChange={update("kubeconfig")} />
        </div>
        <div className="formRow">
          <label htmlFor="preflight-context">Context (optional)</label>
          <input id="preflight-context" value={form.context} onChange={update("context")} />
        </div>
        <div className="formRow">
          <label htmlFor="preflight-timeout">Timeout</label>
          <input id="preflight-timeout" value={form.timeout} onChange={update("timeout")} />
        </div>
        <button type="submit" disabled={submitState.loading}>
          {submitState.loading ? "Running preflight..." : "Run preflight"}
        </button>
      </form>
      {submitState.error && <p className="error">Error: {submitState.error}</p>}
      {submitState.result && (
        <dl className="grid">
          <div><dt>Result ID</dt><dd>{submitState.result.resultId || "n/a"}</dd></div>
          <div><dt>Outcome</dt><dd>{submitState.result.outcome || "n/a"}</dd></div>
          <div><dt>Target digest</dt><dd>{submitState.result.targetReferenceDigest || "n/a"}</dd></div>
          <div><dt>Result path</dt><dd>{submitState.result.resultPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{submitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Checks</dt><dd>{String(submitState.result.checkCount ?? 0)}</dd></div>
          <div><dt>Passed</dt><dd>{String(submitState.result.passedChecks ?? 0)}</dd></div>
          <div><dt>Blocked</dt><dd>{String(submitState.result.blockedChecks ?? 0)}</dd></div>
          <div><dt>Failed</dt><dd>{String(submitState.result.failedChecks ?? 0)}</dd></div>
        </dl>
      )}
    </>
  );
}

function ChangeSetView({ workspacePayload, onChangeSetCreated }) {
  const workspacePath = workspacePayload?.workspace?.path || "";
  const [form, setForm] = useState(() => ({
    bundlePath: workspacePath ? `${workspacePath}/reference-stack.kubernetes.bundle.yaml` : "",
    preflightPath: workspacePath ? `${workspacePath}/reference-preflight.yaml` : "",
    name: "reference-change-set",
    outputPath: workspacePath ? `${workspacePath}/reference-change-set.yaml` : "",
    auditPath: workspacePath ? `${workspacePath}/reference-change-set.audit.jsonl` : "",
    kubeconfig: "",
    context: "",
    timeout: "30s",
  }));
  const [submitState, setSubmitState] = useState({ loading: false, error: "", result: null });

  useEffect(() => {
    if (!workspacePath) {
      return;
    }
    setForm((previous) => {
      const next = { ...previous };
      if (!previous.bundlePath) {
        next.bundlePath = `${workspacePath}/reference-stack.kubernetes.bundle.yaml`;
      }
      if (!previous.preflightPath) {
        next.preflightPath = `${workspacePath}/reference-preflight.yaml`;
      }
      if (!previous.outputPath) {
        next.outputPath = `${workspacePath}/reference-change-set.yaml`;
      }
      if (!previous.auditPath) {
        next.auditPath = `${workspacePath}/reference-change-set.audit.jsonl`;
      }
      return next;
    });
  }, [workspacePath]);

  const update = (key) => (event) => {
    setForm((previous) => ({ ...previous, [key]: event.target.value }));
  };

  const submit = async (event) => {
    event.preventDefault();
    setSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/changeset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const payload = await response.json();
      if (!response.ok && !payload?.changeSet) {
        throw new Error(payload?.diagnostics?.[0]?.message || "Change-set failed");
      }
      const blocked = payload?.changeSet?.outcome === "blocked";
      setSubmitState({
        loading: false,
        error: blocked ? "Change-set is blocked; approval cannot proceed." : "",
        result: payload.changeSet || null,
      });
      onChangeSetCreated();
    } catch (error) {
      setSubmitState({ loading: false, error: error.message || "Change-set failed", result: null });
    }
  };

  const operations = Array.isArray(submitState.result?.operations) ? submitState.result.operations : [];
  const blocked = submitState.result?.outcome === "blocked";
  return (
    <>
      <p>Workspace: {workspacePath || "unknown"}</p>
      <form onSubmit={submit}>
        <div className="formRow">
          <label htmlFor="changeset-bundle-path">Bundle path</label>
          <input id="changeset-bundle-path" value={form.bundlePath} onChange={update("bundlePath")} />
        </div>
        <div className="formRow">
          <label htmlFor="changeset-preflight-path">Preflight path</label>
          <input id="changeset-preflight-path" value={form.preflightPath} onChange={update("preflightPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="changeset-name">Change-set name</label>
          <input id="changeset-name" value={form.name} onChange={update("name")} />
        </div>
        <div className="formRow">
          <label htmlFor="changeset-output-path">Change-set output path</label>
          <input id="changeset-output-path" value={form.outputPath} onChange={update("outputPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="changeset-audit-path">Audit output path</label>
          <input id="changeset-audit-path" value={form.auditPath} onChange={update("auditPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="changeset-kubeconfig">Kubeconfig path (optional)</label>
          <input id="changeset-kubeconfig" value={form.kubeconfig} onChange={update("kubeconfig")} />
        </div>
        <div className="formRow">
          <label htmlFor="changeset-context">Context (optional)</label>
          <input id="changeset-context" value={form.context} onChange={update("context")} />
        </div>
        <div className="formRow">
          <label htmlFor="changeset-timeout">Timeout</label>
          <input id="changeset-timeout" value={form.timeout} onChange={update("timeout")} />
        </div>
        <button type="submit" disabled={submitState.loading}>
          {submitState.loading ? "Computing change-set..." : "Compute change-set"}
        </button>
      </form>
      {submitState.error && <p className="error">Error: {submitState.error}</p>}
      {submitState.result && (
        <>
          <dl className="grid">
            <div><dt>Change-set ID</dt><dd>{submitState.result.changeSetId || "n/a"}</dd></div>
            <div><dt>Outcome</dt><dd>{submitState.result.outcome || "n/a"}</dd></div>
            <div><dt>Change-set path</dt><dd>{submitState.result.changeSetPath || "n/a"}</dd></div>
            <div><dt>Audit path</dt><dd>{submitState.result.auditPath || "n/a"}</dd></div>
            <div><dt>Operations</dt><dd>{String(submitState.result.operationCount ?? 0)}</dd></div>
            <div><dt>Blocked operations</dt><dd>{String(submitState.result.blockedCount ?? 0)}</dd></div>
          </dl>
          {blocked && <p className="error">Hard blocker: approval remains disabled until conflicts or unresolved objects are cleared.</p>}
          {operations.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>Resource</th>
                  <th>Action</th>
                  <th>Ownership</th>
                  <th>Severity</th>
                  <th>Risks</th>
                  <th>Diagnostic</th>
                </tr>
              </thead>
              <tbody>
                {operations.map((row) => (
                  <tr key={`${row.resource}:${row.action}`}>
                    <td>{row.resource}</td>
                    <td>{row.action}</td>
                    <td>{row.ownership}</td>
                    <td>{row.severity}</td>
                    <td>{Array.isArray(row.riskClasses) ? row.riskClasses.join(", ") : "none"}</td>
                    <td>{row.diagnosticCode || "none"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <button type="button" disabled={blocked}>Proceed to approval (I5)</button>
        </>
      )}
    </>
  );
}

function ApprovalView({ workspacePayload, onApprovalCreated }) {
  const workspacePath = workspacePayload?.workspace?.path || "";
  const stages = Array.isArray(workspacePayload?.workspace?.stages) ? workspacePayload.workspace.stages : [];
  const stageByID = new Map(stages.map((stage) => [stage.id, stage]));
  const [form, setForm] = useState(() => ({
    bundlePath: stageByID.get("bundle")?.artifactPath !== "none" ? stageByID.get("bundle")?.artifactPath || "" : "",
    preflightPath: stageByID.get("preflight")?.artifactPath !== "none" ? stageByID.get("preflight")?.artifactPath || "" : "",
    changeSetPath: stageByID.get("changeset")?.artifactPath !== "none" ? stageByID.get("changeset")?.artifactPath || "" : "",
    decision: "",
    reasonReference: "",
    outputPath: workspacePath ? `${workspacePath}/reference-approval.yaml` : "",
    auditPath: workspacePath ? `${workspacePath}/reference-approval.audit.jsonl` : "",
  }));
  const [submitState, setSubmitState] = useState({ loading: false, error: "", result: null });

  useEffect(() => {
    const nextBundle = stageByID.get("bundle")?.artifactPath || "";
    const nextPreflight = stageByID.get("preflight")?.artifactPath || "";
    const nextChangeSet = stageByID.get("changeset")?.artifactPath || "";
    setForm((previous) => {
      const next = { ...previous };
      let changed = false;
      if (!previous.bundlePath && nextBundle !== "none") {
        next.bundlePath = nextBundle;
        changed = true;
      }
      if (!previous.preflightPath && nextPreflight !== "none") {
        next.preflightPath = nextPreflight;
        changed = true;
      }
      if (!previous.changeSetPath && nextChangeSet !== "none") {
        next.changeSetPath = nextChangeSet;
        changed = true;
      }
      if (!previous.outputPath && workspacePath) {
        next.outputPath = `${workspacePath}/reference-approval.yaml`;
        changed = true;
      }
      if (!previous.auditPath && workspacePath) {
        next.auditPath = `${workspacePath}/reference-approval.audit.jsonl`;
        changed = true;
      }
      return changed ? next : previous;
    });
  }, [stages, workspacePath]);

  const update = (key) => (event) => {
    setForm((previous) => ({ ...previous, [key]: event.target.value }));
  };

  const canSubmit = form.decision !== "" && form.reasonReference.trim() !== "";

  const submit = async (event) => {
    event.preventDefault();
    if (!canSubmit) {
      return;
    }
    setSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/approval", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.diagnostics?.[0]?.message || "Approval failed");
      }
      setSubmitState({ loading: false, error: "", result: payload.approval || null });
      onApprovalCreated();
    } catch (error) {
      setSubmitState({ loading: false, error: error.message || "Approval failed", result: null });
    }
  };

  return (
    <>
      <p>Workspace: {workspacePath || "unknown"}</p>
      <h3>Review checklist</h3>
      <ul>
        <li>Plan artifact: {stageByID.get("plan")?.artifactPath || "none"}</li>
        <li>Bundle artifact: {form.bundlePath || "none"}</li>
        <li>Preflight artifact: {form.preflightPath || "none"}</li>
        <li>Change-set artifact: {form.changeSetPath || "none"}</li>
      </ul>
      <form onSubmit={submit}>
        <div className="formRow">
          <label htmlFor="approval-bundle-path">Bundle path</label>
          <input id="approval-bundle-path" value={form.bundlePath} onChange={update("bundlePath")} />
        </div>
        <div className="formRow">
          <label htmlFor="approval-preflight-path">Preflight path</label>
          <input id="approval-preflight-path" value={form.preflightPath} onChange={update("preflightPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="approval-changeset-path">Change-set path</label>
          <input id="approval-changeset-path" value={form.changeSetPath} onChange={update("changeSetPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="approval-decision">Decision</label>
          <select id="approval-decision" value={form.decision} onChange={update("decision")}>
            <option value="">Select decision</option>
            <option value="approve">approve</option>
            <option value="reject">reject</option>
          </select>
        </div>
        <div className="formRow">
          <label htmlFor="approval-reason-reference">Reason reference</label>
          <input id="approval-reason-reference" value={form.reasonReference} onChange={update("reasonReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="approval-output-path">Approval output path</label>
          <input id="approval-output-path" value={form.outputPath} onChange={update("outputPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="approval-audit-path">Audit output path</label>
          <input id="approval-audit-path" value={form.auditPath} onChange={update("auditPath")} />
        </div>
        <button type="submit" disabled={submitState.loading || !canSubmit}>
          {submitState.loading ? "Recording approval..." : "Record approval"}
        </button>
      </form>
      {submitState.error && <p className="error">Error: {submitState.error}</p>}
      {submitState.result && (
        <dl className="grid">
          <div><dt>Approval ID</dt><dd>{submitState.result.approvalId || "n/a"}</dd></div>
          <div><dt>Decision</dt><dd>{submitState.result.decision || "n/a"}</dd></div>
          <div><dt>Effect</dt><dd>{submitState.result.effect || "n/a"}</dd></div>
          <div><dt>Approval path</dt><dd>{submitState.result.approvalPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{submitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Plan ID</dt><dd>{submitState.result.planId || "n/a"}</dd></div>
          <div><dt>Bundle ID</dt><dd>{submitState.result.bundleId || "n/a"}</dd></div>
          <div><dt>Preflight ID</dt><dd>{submitState.result.preflightResultId || "n/a"}</dd></div>
          <div><dt>Change-set ID</dt><dd>{submitState.result.changeSetId || "n/a"}</dd></div>
          <div><dt>Target digest</dt><dd>{submitState.result.targetReferenceDigest || "n/a"}</dd></div>
          <div><dt>Reason reference</dt><dd>{submitState.result.reasonReference || "n/a"}</dd></div>
        </dl>
      )}
    </>
  );
}

function AuthorizationApplyView({ workspacePayload, onApplyCreated }) {
  const workspacePath = workspacePayload?.workspace?.path || "";
  const stages = Array.isArray(workspacePayload?.workspace?.stages) ? workspacePayload.workspace.stages : [];
  const stageByID = new Map(stages.map((stage) => [stage.id, stage]));
  const [commandState, setCommandState] = useState({ loading: false, error: "", result: null });
  const [form, setForm] = useState(() => ({
    importReceiptPath: "",
    transferReceiptPaths: "",
    scanReceiptPaths: "",
    airgapGateResultPath: "",
    airgapGateTrustPolicyPath: "",
    confirmAirgapGateTrustPolicy: "",
    airgapGatePolicyDiffPath: "",
    confirmAirgapGatePolicyDiff: "",
    airgapGateTransitionReviewPath: "",
    confirmAirgapGateTransitionReview: "",
    publicKeyPath: "",
    authorizationPath: stageByID.get("authorization")?.artifactPath !== "none" ? stageByID.get("authorization")?.artifactPath || "" : "",
    confirmAuthorization: "",
    typedConfirmationDigest: "",
    name: "reference-receipt",
    receiptPath: workspacePath ? `${workspacePath}/reference-receipt.yaml` : "",
    auditPath: workspacePath ? `${workspacePath}/reference-apply.audit.jsonl` : "",
    kubeconfig: "",
    context: "",
    timeout: "30m",
  }));
  const [submitState, setSubmitState] = useState({ loading: false, error: "", result: null });

  useEffect(() => {
    if (!workspacePath) {
      return;
    }
    setForm((previous) => {
      const next = { ...previous };
      let changed = false;
      const authorizationPath = stageByID.get("authorization")?.artifactPath || "";
      if (!previous.authorizationPath && authorizationPath && authorizationPath !== "none") {
        next.authorizationPath = authorizationPath;
        changed = true;
      }
      if (!previous.receiptPath) {
        next.receiptPath = `${workspacePath}/reference-receipt.yaml`;
        changed = true;
      }
      if (!previous.auditPath) {
        next.auditPath = `${workspacePath}/reference-apply.audit.jsonl`;
        changed = true;
      }
      return changed ? next : previous;
    });
  }, [stages, workspacePath]);

  const refreshCommand = async () => {
    setCommandState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/authorization-command", { method: "GET" });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.diagnostics?.[0]?.message || "Authorization command request failed");
      }
      setCommandState({ loading: false, error: "", result: payload });
      setForm((previous) => ({
        ...previous,
        authorizationPath: previous.authorizationPath || payload.outputPath || previous.authorizationPath,
        confirmAuthorization: previous.confirmAuthorization || "",
        typedConfirmationDigest: previous.typedConfirmationDigest || "",
      }));
    } catch (error) {
      setCommandState({ loading: false, error: error.message || "Authorization command request failed", result: null });
    }
  };

  useEffect(() => {
    refreshCommand();
  }, [workspacePath]);

  const update = (key) => (event) => {
    setForm((previous) => ({ ...previous, [key]: event.target.value }));
  };

  const parseCSV = (value) => value.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
  const transferReceipts = parseCSV(form.transferReceiptPaths);
  const scanReceipts = parseCSV(form.scanReceiptPaths);
  const validationErrors = [];
  if (form.confirmAuthorization === "" || form.confirmAuthorization !== form.typedConfirmationDigest) {
    validationErrors.push("Typed confirmation digest must exactly match the authorization digest.");
  }
  if (form.airgapGateResultPath.trim() !== "" && (form.airgapGateTrustPolicyPath.trim() === "" || form.confirmAirgapGateTrustPolicy.trim() === "")) {
    validationErrors.push("Providing an air-gap gate result also requires trust policy path and confirmed trust policy ID.");
  }
  if ((form.airgapGatePolicyDiffPath.trim() === "") !== (form.confirmAirgapGatePolicyDiff.trim() === "")) {
    validationErrors.push("Trust policy diff path and confirmed trust policy diff ID must be provided together.");
  }
  if ((form.airgapGateTransitionReviewPath.trim() === "") !== (form.confirmAirgapGateTransitionReview.trim() === "")) {
    validationErrors.push("Transition review path and confirmed transition review ID must be provided together.");
  }
  if (form.airgapGateResultPath.trim() === "" && ((transferReceipts.length > 0 && scanReceipts.length === 0) || (scanReceipts.length > 0 && transferReceipts.length === 0))) {
    validationErrors.push("Without a gate result, transfer and scan receipt chains must both be provided or both omitted.");
  }
  const canSubmit = validationErrors.length === 0;

  const submit = async (event) => {
    event.preventDefault();
    if (!canSubmit) {
      return;
    }
    setSubmitState({ loading: true, error: "", result: null });
    try {
      const payload = {
        bundlePath: commandState.result?.bundlePath || stageByID.get("bundle")?.artifactPath || "",
        preflightPath: commandState.result?.preflightPath || stageByID.get("preflight")?.artifactPath || "",
        changeSetPath: commandState.result?.changeSetPath || stageByID.get("changeset")?.artifactPath || "",
        approvalPath: commandState.result?.approvalPath || stageByID.get("approval")?.artifactPath || "",
        importReceiptPath: form.importReceiptPath,
        transferReceiptPaths: transferReceipts,
        scanReceiptPaths: scanReceipts,
        airgapGateResultPath: form.airgapGateResultPath,
        airgapGateTrustPolicyPath: form.airgapGateTrustPolicyPath,
        confirmAirgapGateTrustPolicy: form.confirmAirgapGateTrustPolicy,
        airgapGatePolicyDiffPath: form.airgapGatePolicyDiffPath,
        confirmAirgapGatePolicyDiff: form.confirmAirgapGatePolicyDiff,
        airgapGateTransitionReviewPath: form.airgapGateTransitionReviewPath,
        confirmAirgapGateTransitionReview: form.confirmAirgapGateTransitionReview,
        authorizationPath: form.authorizationPath,
        publicKeyPath: form.publicKeyPath,
        confirmAuthorization: form.confirmAuthorization,
        typedConfirmationDigest: form.typedConfirmationDigest,
        name: form.name,
        receiptPath: form.receiptPath,
        auditPath: form.auditPath,
        kubeconfig: form.kubeconfig,
        context: form.context,
        timeout: form.timeout,
      };
      const response = await fetch("/api/v1/workflow/apply", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Apply failed");
      }
      setSubmitState({ loading: false, error: "", result: responsePayload.apply || null });
      onApplyCreated();
    } catch (error) {
      setSubmitState({ loading: false, error: error.message || "Apply failed", result: null });
    }
  };

  return (
    <>
      <p>Workspace: {workspacePath || "unknown"}</p>
      <h3>Authorization command</h3>
      <p>Private key material is never posted to the API. Run this command in your own shell.</p>
      <button type="button" onClick={refreshCommand} disabled={commandState.loading}>
        {commandState.loading ? "Refreshing command..." : "Refresh authorization command"}
      </button>
      {commandState.error && <p className="error">Error: {commandState.error}</p>}
      {commandState.result && <pre>{commandState.result.command}</pre>}
      <h3>Apply confirmation</h3>
      <ul>
        <li>Plan artifact: {stageByID.get("plan")?.artifactPath || "none"}</li>
        <li>Bundle artifact: {commandState.result?.bundlePath || stageByID.get("bundle")?.artifactPath || "none"}</li>
        <li>Preflight artifact: {commandState.result?.preflightPath || stageByID.get("preflight")?.artifactPath || "none"}</li>
        <li>Change-set artifact: {commandState.result?.changeSetPath || stageByID.get("changeset")?.artifactPath || "none"}</li>
        <li>Approval artifact: {commandState.result?.approvalPath || stageByID.get("approval")?.artifactPath || "none"}</li>
        <li>Authorization artifact: {form.authorizationPath || stageByID.get("authorization")?.artifactPath || "none"}</li>
      </ul>
      <form onSubmit={submit}>
        <div className="formRow">
          <label htmlFor="apply-import-receipt-path">Import receipt path</label>
          <input id="apply-import-receipt-path" value={form.importReceiptPath} onChange={update("importReceiptPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-transfer-receipts">Transfer receipt paths (comma-separated, optional)</label>
          <input id="apply-transfer-receipts" value={form.transferReceiptPaths} onChange={update("transferReceiptPaths")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-scan-receipts">Scan receipt paths (comma-separated, optional)</label>
          <input id="apply-scan-receipts" value={form.scanReceiptPaths} onChange={update("scanReceiptPaths")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-airgap-gate-result-path">Air-gap gate result path (optional)</label>
          <input id="apply-airgap-gate-result-path" value={form.airgapGateResultPath} onChange={update("airgapGateResultPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-airgap-trust-policy-path">Air-gap trust policy path (optional)</label>
          <input id="apply-airgap-trust-policy-path" value={form.airgapGateTrustPolicyPath} onChange={update("airgapGateTrustPolicyPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-airgap-trust-policy-confirm">Confirm air-gap trust policy ID (optional)</label>
          <input id="apply-airgap-trust-policy-confirm" value={form.confirmAirgapGateTrustPolicy} onChange={update("confirmAirgapGateTrustPolicy")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-airgap-policy-diff-path">Air-gap trust policy diff path (optional)</label>
          <input id="apply-airgap-policy-diff-path" value={form.airgapGatePolicyDiffPath} onChange={update("airgapGatePolicyDiffPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-airgap-policy-diff-confirm">Confirm air-gap trust policy diff ID (optional)</label>
          <input id="apply-airgap-policy-diff-confirm" value={form.confirmAirgapGatePolicyDiff} onChange={update("confirmAirgapGatePolicyDiff")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-airgap-review-path">Air-gap transition review path (optional)</label>
          <input id="apply-airgap-review-path" value={form.airgapGateTransitionReviewPath} onChange={update("airgapGateTransitionReviewPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-airgap-review-confirm">Confirm air-gap transition review ID (optional)</label>
          <input id="apply-airgap-review-confirm" value={form.confirmAirgapGateTransitionReview} onChange={update("confirmAirgapGateTransitionReview")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-authorization-path">Authorization path</label>
          <input id="apply-authorization-path" value={form.authorizationPath} onChange={update("authorizationPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-public-key-path">Public key path</label>
          <input id="apply-public-key-path" value={form.publicKeyPath} onChange={update("publicKeyPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-confirm-authorization">Confirm authorization digest</label>
          <input id="apply-confirm-authorization" value={form.confirmAuthorization} onChange={update("confirmAuthorization")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-typed-confirmation">Type confirmation digest</label>
          <input id="apply-typed-confirmation" value={form.typedConfirmationDigest} onChange={update("typedConfirmationDigest")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-name">Receipt name</label>
          <input id="apply-name" value={form.name} onChange={update("name")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-receipt-path">Receipt output path</label>
          <input id="apply-receipt-path" value={form.receiptPath} onChange={update("receiptPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-audit-path">Audit output path</label>
          <input id="apply-audit-path" value={form.auditPath} onChange={update("auditPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-kubeconfig">Kubeconfig path (optional)</label>
          <input id="apply-kubeconfig" value={form.kubeconfig} onChange={update("kubeconfig")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-context">Context (optional)</label>
          <input id="apply-context" value={form.context} onChange={update("context")} />
        </div>
        <div className="formRow">
          <label htmlFor="apply-timeout">Timeout</label>
          <input id="apply-timeout" value={form.timeout} onChange={update("timeout")} />
        </div>
        <button type="submit" disabled={submitState.loading || !canSubmit}>
          {submitState.loading ? "Applying..." : "Confirm and apply"}
        </button>
      </form>
      {!canSubmit && validationErrors.map((message) => <p key={message} className="error">{message}</p>)}
      {submitState.error && <p className="error">Error: {submitState.error}</p>}
      {submitState.result && (
        <dl className="grid">
          <div><dt>Outcome</dt><dd>{submitState.result.outcome || "n/a"}</dd></div>
          <div><dt>Receipt ID</dt><dd>{submitState.result.receiptId || "n/a"}</dd></div>
          <div><dt>Authorization ID</dt><dd>{submitState.result.authorizationId || "n/a"}</dd></div>
          <div><dt>Receipt path</dt><dd>{submitState.result.receiptPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{submitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Plan ID</dt><dd>{submitState.result.planId || "n/a"}</dd></div>
          <div><dt>Bundle ID</dt><dd>{submitState.result.bundleId || "n/a"}</dd></div>
          <div><dt>Preflight ID</dt><dd>{submitState.result.preflightResultId || "n/a"}</dd></div>
          <div><dt>Change-set ID</dt><dd>{submitState.result.changeSetId || "n/a"}</dd></div>
          <div><dt>Approval ID</dt><dd>{submitState.result.approvalId || "n/a"}</dd></div>
          <div><dt>Target digest</dt><dd>{submitState.result.targetReferenceDigest || "n/a"}</dd></div>
          <div><dt>Transfer receipts</dt><dd>{Array.isArray(submitState.result.transferReceiptIds) && submitState.result.transferReceiptIds.length > 0 ? submitState.result.transferReceiptIds.join(", ") : "none"}</dd></div>
          <div><dt>Scan receipts</dt><dd>{Array.isArray(submitState.result.scanReceiptIds) && submitState.result.scanReceiptIds.length > 0 ? submitState.result.scanReceiptIds.join(", ") : "none"}</dd></div>
          <div><dt>Air-gap gate result ID</dt><dd>{submitState.result.airgapGateResultId || "none"}</dd></div>
          <div><dt>Air-gap trust policy ID</dt><dd>{submitState.result.airgapTrustPolicyId || "none"}</dd></div>
          <div><dt>Air-gap policy diff ID</dt><dd>{submitState.result.airgapPolicyDiffId || "none"}</dd></div>
          <div><dt>Air-gap transition review ID</dt><dd>{submitState.result.airgapReviewId || "none"}</dd></div>
        </dl>
      )}
    </>
  );
}

function RunbookView({ payload }) {
  const runbook = payload?.runbook || {};
  const artifacts = runbook.artifacts || {};
  const evidence = runbook.evidence || {};
  const checkpoints = Array.isArray(runbook.failClosedCheckpoints) ? runbook.failClosedCheckpoints : [];
  const steps = Array.isArray(runbook.steps) ? runbook.steps : [];
  const workspacePath = runbook.workspacePath || "";
  const [form, setForm] = useState(() => ({
    markdownPath: workspacePath ? `${workspacePath}/workflow.runbook.md` : "",
    jsonPath: workspacePath ? `${workspacePath}/workflow.runbook.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.runbook.export.audit.jsonl` : "",
  }));
  const [submitState, setSubmitState] = useState({ loading: false, error: "", result: null });

  useEffect(() => {
    if (!workspacePath) {
      return;
    }
    setForm((previous) => {
      const next = { ...previous };
      let changed = false;
      if (!previous.markdownPath) {
        next.markdownPath = `${workspacePath}/workflow.runbook.md`;
        changed = true;
      }
      if (!previous.jsonPath) {
        next.jsonPath = `${workspacePath}/workflow.runbook.json`;
        changed = true;
      }
      if (!previous.auditPath) {
        next.auditPath = `${workspacePath}/workflow.runbook.export.audit.jsonl`;
        changed = true;
      }
      return changed ? next : previous;
    });
  }, [workspacePath]);

  const update = (key) => (event) => {
    setForm((previous) => ({ ...previous, [key]: event.target.value }));
  };

  const canExport = form.markdownPath !== "" && form.jsonPath !== "" && form.auditPath !== "" && form.markdownPath !== form.jsonPath && form.markdownPath !== form.auditPath && form.jsonPath !== form.auditPath;

  const submit = async (event) => {
    event.preventDefault();
    if (!canExport) {
      return;
    }
    setSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/runbook/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Runbook export failed");
      }
      setSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setSubmitState({ loading: false, error: error.message || "Runbook export failed", result: null });
    }
  };

  return (
    <>
      <p>Workspace: {workspacePath || "unknown"}</p>
      <h3>Evidence chain</h3>
      <dl className="grid">
        <div><dt>Plan ID</dt><dd>{evidence.planId || "n/a"}</dd></div>
        <div><dt>Bundle ID</dt><dd>{evidence.bundleId || "n/a"}</dd></div>
        <div><dt>Preflight ID</dt><dd>{evidence.preflightResultId || "n/a"}</dd></div>
        <div><dt>Change-set ID</dt><dd>{evidence.changeSetId || "n/a"}</dd></div>
        <div><dt>Approval ID</dt><dd>{evidence.approvalId || "n/a"}</dd></div>
        <div><dt>Authorization ID</dt><dd>{evidence.authorizationId || "n/a"}</dd></div>
      </dl>
      <h3>Artifact paths</h3>
      <ul>
        <li>Plan: {artifacts.planPath || "none"}</li>
        <li>Bundle: {artifacts.bundlePath || "none"}</li>
        <li>Preflight: {artifacts.preflightPath || "none"}</li>
        <li>Change-set: {artifacts.changeSetPath || "none"}</li>
        <li>Approval: {artifacts.approvalPath || "none"}</li>
        <li>Authorization: {artifacts.authorizationPath || "none"}</li>
      </ul>
      <h3>Fail-closed checkpoints</h3>
      <ul>
        {checkpoints.map((checkpoint) => (
          <li key={checkpoint}>{checkpoint}</li>
        ))}
      </ul>
      <h3>Execution steps</h3>
      {steps.map((step) => (
        <article key={step.id}>
          <h4>{step.title || step.id}</h4>
          <p>{step.description || ""}</p>
          {step.command && <pre>{step.command}</pre>}
        </article>
      ))}
      <h3>Copy-ready runbook</h3>
      <textarea readOnly value={runbook.markdown || ""} rows={14} />
      <h3>Export runbook artifacts</h3>
      <form onSubmit={submit}>
        <div className="formRow">
          <label htmlFor="runbook-markdown-path">Markdown output path</label>
          <input id="runbook-markdown-path" value={form.markdownPath} onChange={update("markdownPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="runbook-json-path">JSON output path</label>
          <input id="runbook-json-path" value={form.jsonPath} onChange={update("jsonPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="runbook-audit-path">Audit output path</label>
          <input id="runbook-audit-path" value={form.auditPath} onChange={update("auditPath")} />
        </div>
        <button type="submit" disabled={submitState.loading || !canExport}>
          {submitState.loading ? "Exporting runbook..." : "Export runbook"}
        </button>
      </form>
      {!canExport && <p className="error">Runbook markdown/json/audit paths are required and must all be different.</p>}
      {submitState.error && <p className="error">Error: {submitState.error}</p>}
      {submitState.result && (
        <dl className="grid">
          <div><dt>Markdown path</dt><dd>{submitState.result.markdownPath || "n/a"}</dd></div>
          <div><dt>JSON path</dt><dd>{submitState.result.jsonPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{submitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Step count</dt><dd>{String(submitState.result.stepCount ?? 0)}</dd></div>
        </dl>
      )}
    </>
  );
}

function CapsuleView({ payload }) {
  const capsule = payload?.capsule || {};
  const stages = Array.isArray(capsule.stages) ? capsule.stages : [];
  const blockers = Array.isArray(capsule.blockers) ? capsule.blockers : [];
  const evidence = capsule.evidence || {};
  const exports = capsule.runbookExports || {};
  const markdownExports = Array.isArray(exports.markdownPaths) ? exports.markdownPaths : [];
  const jsonExports = Array.isArray(exports.jsonPaths) ? exports.jsonPaths : [];
  const workspacePath = capsule.workspacePath || "";
  const [form, setForm] = useState(() => ({
    markdownPath: workspacePath ? `${workspacePath}/workflow.capsule.md` : "",
    jsonPath: workspacePath ? `${workspacePath}/workflow.capsule.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.capsule.export.audit.jsonl` : "",
    allowBlocked: false,
    allowBlockedReasonReference: "",
  }));
  const [submitState, setSubmitState] = useState({ loading: false, error: "", result: null });
  const [bundleForm, setBundleForm] = useState(() => ({
    manifestPath: workspacePath ? `${workspacePath}/workflow.evidence-bundle.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.evidence-bundle.export.audit.jsonl` : "",
  }));
  const [bundleSubmitState, setBundleSubmitState] = useState({ loading: false, error: "", result: null });
  const [timelineForm, setTimelineForm] = useState(() => ({
    markdownPath: workspacePath ? `${workspacePath}/workflow.receipt-timeline.md` : "",
    jsonPath: workspacePath ? `${workspacePath}/workflow.receipt-timeline.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.receipt-timeline.export.audit.jsonl` : "",
  }));
  const [timelineSubmitState, setTimelineSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureForm, setClosureForm] = useState(() => ({
    manifestPath: workspacePath ? `${workspacePath}/workflow.closure-package.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.closure-package.export.audit.jsonl` : "",
    releaseReadinessReference: "",
  }));
  const [closureSubmitState, setClosureSubmitState] = useState({ loading: false, error: "", result: null });
  const [reviewGateForm, setReviewGateForm] = useState(() => ({
    releaseReadinessReference: "",
    reviewerReference: "",
    decision: "approved",
    markdownPath: workspacePath ? `${workspacePath}/workflow.closure-review-gate.md` : "",
    jsonPath: workspacePath ? `${workspacePath}/workflow.closure-review-gate.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.closure-review-gate.export.audit.jsonl` : "",
  }));
  const [reviewGateSubmitState, setReviewGateSubmitState] = useState({ loading: false, error: "", result: null });
  const [releaseDecisionForm, setReleaseDecisionForm] = useState(() => ({
    releaseReadinessReference: "",
    reviewerReference: "",
    decision: "approved",
    operatorReference: "",
    decisionTimestamp: "",
    ledgerPath: workspacePath ? `${workspacePath}/workflow.release-decision.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.release-decision.export.audit.jsonl` : "",
  }));
  const [releaseDecisionSubmitState, setReleaseDecisionSubmitState] = useState({ loading: false, error: "", result: null });
  const [releasePublicationForm, setReleasePublicationForm] = useState(() => ({
    publicationChannel: "",
    artifactLocationReference: "",
    publicationTimestamp: "",
    operatorReference: "",
    attestationPath: workspacePath ? `${workspacePath}/workflow.release-publication.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.release-publication.export.audit.jsonl` : "",
  }));
  const [releasePublicationSubmitState, setReleasePublicationSubmitState] = useState({ loading: false, error: "", result: null });
  const [publicationIndexForm, setPublicationIndexForm] = useState(() => ({
    publicationBatchReference: "",
    operatorReference: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.release-publication.index.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.release-publication.index.export.audit.jsonl` : "",
  }));
  const [publicationIndexSubmitState, setPublicationIndexSubmitState] = useState({ loading: false, error: "", result: null });
  const [publicationPackageForm, setPublicationPackageForm] = useState(() => ({
    packageReference: "",
    publicationWindowReference: "",
    operatorReference: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.release-publication.package.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.release-publication.package.export.audit.jsonl` : "",
  }));
  const [publicationPackageSubmitState, setPublicationPackageSubmitState] = useState({ loading: false, error: "", result: null });
  const [publicationEnvelopeForm, setPublicationEnvelopeForm] = useState(() => ({
    deliveryReference: "",
    destinationReference: "",
    operatorReference: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.release-publication.envelope.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.release-publication.envelope.export.audit.jsonl` : "",
  }));
  const [publicationEnvelopeSubmitState, setPublicationEnvelopeSubmitState] = useState({ loading: false, error: "", result: null });
  const [handoffReceiptForm, setHandoffReceiptForm] = useState(() => ({
    receiverReference: "",
    handoffTimestamp: "",
    operatorReference: "",
    receiptPath: workspacePath ? `${workspacePath}/workflow.release-publication.handoff-receipt.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.release-publication.handoff-receipt.export.audit.jsonl` : "",
  }));
  const [handoffReceiptSubmitState, setHandoffReceiptSubmitState] = useState({ loading: false, error: "", result: null });
  const [acknowledgmentForm, setAcknowledgmentForm] = useState(() => ({
    acknowledgmentReference: "",
    acknowledgedByReference: "",
    acknowledgmentTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.release-publication.acknowledgment.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.release-publication.acknowledgment.export.audit.jsonl` : "",
  }));
  const [acknowledgmentSubmitState, setAcknowledgmentSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureSummaryForm, setClosureSummaryForm] = useState(() => ({
    summaryReference: "",
    operatorReference: "",
    summaryTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-summary.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-summary.export.audit.jsonl` : "",
  }));
  const [closureSummarySubmitState, setClosureSummarySubmitState] = useState({ loading: false, error: "", result: null });
  const [closureDeliveryForm, setClosureDeliveryForm] = useState(() => ({
    deliveryReference: "",
    destinationReference: "",
    operatorReference: "",
    deliveryTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-delivery.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-delivery.export.audit.jsonl` : "",
  }));
  const [closureDeliverySubmitState, setClosureDeliverySubmitState] = useState({ loading: false, error: "", result: null });
  const [closureAcceptanceForm, setClosureAcceptanceForm] = useState(() => ({
    acceptanceReference: "",
    acceptedByReference: "",
    acceptanceTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-acceptance.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-acceptance.export.audit.jsonl` : "",
  }));
  const [closureAcceptanceSubmitState, setClosureAcceptanceSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureCertificateForm, setClosureCertificateForm] = useState(() => ({
    certificateReference: "",
    issuedByReference: "",
    issuedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-certificate.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-certificate.export.audit.jsonl` : "",
  }));
  const [closureCertificateSubmitState, setClosureCertificateSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureLedgerForm, setClosureLedgerForm] = useState(() => ({
    ledgerReference: "",
    recordedByReference: "",
    recordedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-ledger.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-ledger.export.audit.jsonl` : "",
  }));
  const [closureLedgerSubmitState, setClosureLedgerSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureDocketForm, setClosureDocketForm] = useState(() => ({
    docketReference: "",
    preparedByReference: "",
    preparedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-docket.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-docket.export.audit.jsonl` : "",
  }));
  const [closureDocketSubmitState, setClosureDocketSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureBulletinForm, setClosureBulletinForm] = useState(() => ({
    bulletinReference: "",
    publishedByReference: "",
    publishedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-bulletin.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-bulletin.export.audit.jsonl` : "",
  }));
  const [closureBulletinSubmitState, setClosureBulletinSubmitState] = useState({ loading: false, error: "", result: null });
  const [closurePacketForm, setClosurePacketForm] = useState(() => ({
    packetReference: "",
    packagedByReference: "",
    packagedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-packet.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-packet.export.audit.jsonl` : "",
  }));
  const [closurePacketSubmitState, setClosurePacketSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureRecipientPackageForm, setClosureRecipientPackageForm] = useState(() => ({
    recipientPackageReference: "",
    preparedForReference: "",
    preparedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-recipient-package.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-recipient-package.export.audit.jsonl` : "",
  }));
  const [closureRecipientPackageSubmitState, setClosureRecipientPackageSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifySubmitState, setClosureVerifySubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyExportForm, setClosureVerifyExportForm] = useState(() => ({
    verificationReference: "",
    operatorReference: "",
    verificationTimestamp: "",
    markdownPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.md` : "",
    jsonPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.export.audit.jsonl` : "",
    allowBlocked: false,
    allowBlockedReasonReference: "",
  }));
  const [closureVerifyExportSubmitState, setClosureVerifyExportSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyAttestationForm, setClosureVerifyAttestationForm] = useState(() => ({
    attestationReference: "",
    attestedByReference: "",
    attestationTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.attestation.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.attestation.export.audit.jsonl` : "",
  }));
  const [closureVerifyAttestationSubmitState, setClosureVerifyAttestationSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyAttestationIndexForm, setClosureVerifyAttestationIndexForm] = useState(() => ({
    attestationIndexReference: "",
    publishedByReference: "",
    publishedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.attestation.index.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.attestation.index.export.audit.jsonl` : "",
  }));
  const [closureVerifyAttestationIndexSubmitState, setClosureVerifyAttestationIndexSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationPackageForm, setClosureVerifyPublicationPackageForm] = useState(() => ({
    verificationPackageReference: "",
    packagedByReference: "",
    packagedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-package.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-package.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationPackageSubmitState, setClosureVerifyPublicationPackageSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationAttestationForm, setClosureVerifyPublicationAttestationForm] = useState(() => ({
    verificationPublicationReference: "",
    publishedByReference: "",
    publishedTimestamp: "",
    publicationChannel: "",
    publicationLocationReference: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-attestation.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-attestation.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationAttestationSubmitState, setClosureVerifyPublicationAttestationSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationIndexForm, setClosureVerifyPublicationIndexForm] = useState(() => ({
    verificationPublicationIndexReference: "",
    indexedByReference: "",
    indexedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-index.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-index.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationIndexSubmitState, setClosureVerifyPublicationIndexSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationEnvelopeForm, setClosureVerifyPublicationEnvelopeForm] = useState(() => ({
    verificationPublicationEnvelopeReference: "",
    deliveredByReference: "",
    deliveryTimestamp: "",
    deliveryDestinationReference: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-envelope.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-envelope.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationEnvelopeSubmitState, setClosureVerifyPublicationEnvelopeSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationHandoffForm, setClosureVerifyPublicationHandoffForm] = useState(() => ({
    verificationPublicationHandoffReference: "",
    receivedByReference: "",
    handoffTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-handoff.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-handoff.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationHandoffSubmitState, setClosureVerifyPublicationHandoffSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationAcknowledgmentForm, setClosureVerifyPublicationAcknowledgmentForm] = useState(() => ({
    verificationPublicationAcknowledgmentReference: "",
    acknowledgedByReference: "",
    acknowledgmentTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-acknowledgment.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-acknowledgment.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationAcknowledgmentSubmitState, setClosureVerifyPublicationAcknowledgmentSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationArchiveIndexForm, setClosureVerifyPublicationArchiveIndexForm] = useState(() => ({
    verificationPublicationArchiveIndexReference: "",
    indexedByReference: "",
    indexedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-index.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-index.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationArchiveIndexSubmitState, setClosureVerifyPublicationArchiveIndexSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationArchivePackageForm, setClosureVerifyPublicationArchivePackageForm] = useState(() => ({
    verificationPublicationArchivePackageReference: "",
    packagedByReference: "",
    packagedTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-package.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-package.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationArchivePackageSubmitState, setClosureVerifyPublicationArchivePackageSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationArchiveEnvelopeForm, setClosureVerifyPublicationArchiveEnvelopeForm] = useState(() => ({
    verificationPublicationArchiveEnvelopeReference: "",
    deliveredByReference: "",
    deliveryTimestamp: "",
    deliveryDestinationReference: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-envelope.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-envelope.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationArchiveEnvelopeSubmitState, setClosureVerifyPublicationArchiveEnvelopeSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationArchiveHandoffForm, setClosureVerifyPublicationArchiveHandoffForm] = useState(() => ({
    verificationPublicationArchiveHandoffReference: "",
    receivedByReference: "",
    handoffTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-handoff.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-handoff.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationArchiveHandoffSubmitState, setClosureVerifyPublicationArchiveHandoffSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationArchiveAcknowledgmentForm, setClosureVerifyPublicationArchiveAcknowledgmentForm] = useState(() => ({
    verificationPublicationArchiveAcknowledgmentReference: "",
    acknowledgedByReference: "",
    acknowledgmentTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-acknowledgment.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-acknowledgment.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationArchiveAcknowledgmentSubmitState, setClosureVerifyPublicationArchiveAcknowledgmentSubmitState] = useState({ loading: false, error: "", result: null });
  const [closureVerifyPublicationArchiveAttestationForm, setClosureVerifyPublicationArchiveAttestationForm] = useState(() => ({
    verificationPublicationArchiveAttestationReference: "",
    attestedByReference: "",
    attestationTimestamp: "",
    manifestPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-attestation.json` : "",
    auditPath: workspacePath ? `${workspacePath}/workflow.rollout-closure-verify.publication-archive-attestation.export.audit.jsonl` : "",
  }));
  const [closureVerifyPublicationArchiveAttestationSubmitState, setClosureVerifyPublicationArchiveAttestationSubmitState] = useState({ loading: false, error: "", result: null });

  useEffect(() => {
    if (!workspacePath) {
      return;
    }
    setForm((previous) => ({
      ...previous,
      markdownPath: previous.markdownPath || `${workspacePath}/workflow.capsule.md`,
      jsonPath: previous.jsonPath || `${workspacePath}/workflow.capsule.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.capsule.export.audit.jsonl`,
    }));
    setBundleForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.evidence-bundle.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.evidence-bundle.export.audit.jsonl`,
    }));
    setTimelineForm((previous) => ({
      ...previous,
      markdownPath: previous.markdownPath || `${workspacePath}/workflow.receipt-timeline.md`,
      jsonPath: previous.jsonPath || `${workspacePath}/workflow.receipt-timeline.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.receipt-timeline.export.audit.jsonl`,
    }));
    setClosureForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.closure-package.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.closure-package.export.audit.jsonl`,
    }));
    setReviewGateForm((previous) => ({
      ...previous,
      markdownPath: previous.markdownPath || `${workspacePath}/workflow.closure-review-gate.md`,
      jsonPath: previous.jsonPath || `${workspacePath}/workflow.closure-review-gate.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.closure-review-gate.export.audit.jsonl`,
    }));
    setReleaseDecisionForm((previous) => ({
      ...previous,
      ledgerPath: previous.ledgerPath || `${workspacePath}/workflow.release-decision.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.release-decision.export.audit.jsonl`,
    }));
    setReleasePublicationForm((previous) => ({
      ...previous,
      attestationPath: previous.attestationPath || `${workspacePath}/workflow.release-publication.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.release-publication.export.audit.jsonl`,
    }));
    setPublicationIndexForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.release-publication.index.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.release-publication.index.export.audit.jsonl`,
    }));
    setPublicationPackageForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.release-publication.package.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.release-publication.package.export.audit.jsonl`,
    }));
    setPublicationEnvelopeForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.release-publication.envelope.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.release-publication.envelope.export.audit.jsonl`,
    }));
    setHandoffReceiptForm((previous) => ({
      ...previous,
      receiptPath: previous.receiptPath || `${workspacePath}/workflow.release-publication.handoff-receipt.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.release-publication.handoff-receipt.export.audit.jsonl`,
    }));
    setAcknowledgmentForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.release-publication.acknowledgment.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.release-publication.acknowledgment.export.audit.jsonl`,
    }));
    setClosureSummaryForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-summary.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-summary.export.audit.jsonl`,
    }));
    setClosureDeliveryForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-delivery.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-delivery.export.audit.jsonl`,
    }));
    setClosureAcceptanceForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-acceptance.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-acceptance.export.audit.jsonl`,
    }));
    setClosureCertificateForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-certificate.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-certificate.export.audit.jsonl`,
    }));
    setClosureLedgerForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-ledger.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-ledger.export.audit.jsonl`,
    }));
    setClosureDocketForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-docket.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-docket.export.audit.jsonl`,
    }));
    setClosureBulletinForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-bulletin.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-bulletin.export.audit.jsonl`,
    }));
    setClosurePacketForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-packet.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-packet.export.audit.jsonl`,
    }));
    setClosureRecipientPackageForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-recipient-package.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-recipient-package.export.audit.jsonl`,
    }));
    setClosureVerifyExportForm((previous) => ({
      ...previous,
      markdownPath: previous.markdownPath || `${workspacePath}/workflow.rollout-closure-verify.md`,
      jsonPath: previous.jsonPath || `${workspacePath}/workflow.rollout-closure-verify.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.export.audit.jsonl`,
    }));
    setClosureVerifyAttestationForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.attestation.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.attestation.export.audit.jsonl`,
    }));
    setClosureVerifyAttestationIndexForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.attestation.index.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.attestation.index.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationPackageForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-package.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-package.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationAttestationForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-attestation.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-attestation.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationIndexForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-index.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-index.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationEnvelopeForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-envelope.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-envelope.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationHandoffForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-handoff.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-handoff.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationAcknowledgmentForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-acknowledgment.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-acknowledgment.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationArchiveIndexForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-index.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-index.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationArchivePackageForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-package.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-package.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationArchiveEnvelopeForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-envelope.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-envelope.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationArchiveHandoffForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-handoff.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-handoff.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationArchiveAcknowledgmentForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-acknowledgment.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-acknowledgment.export.audit.jsonl`,
    }));
    setClosureVerifyPublicationArchiveAttestationForm((previous) => ({
      ...previous,
      manifestPath: previous.manifestPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-attestation.json`,
      auditPath: previous.auditPath || `${workspacePath}/workflow.rollout-closure-verify.publication-archive-attestation.export.audit.jsonl`,
    }));
  }, [workspacePath]);

  const update = (key) => (event) => {
    const value = event.target.type === "checkbox" ? event.target.checked : event.target.value;
    setForm((previous) => ({ ...previous, [key]: value }));
  };

  const canExport = form.markdownPath !== "" &&
    form.jsonPath !== "" &&
    form.auditPath !== "" &&
    form.markdownPath !== form.jsonPath &&
    form.markdownPath !== form.auditPath &&
    form.jsonPath !== form.auditPath &&
    (!form.allowBlocked || form.allowBlockedReasonReference.trim() !== "");

  const submit = async (event) => {
    event.preventDefault();
    if (!canExport) {
      return;
    }
    setSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/capsule/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Capsule export failed");
      }
      setSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setSubmitState({ loading: false, error: error.message || "Capsule export failed", result: null });
    }
  };
  const updateBundle = (key) => (event) => {
    setBundleForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportBundle = bundleForm.manifestPath !== "" && bundleForm.auditPath !== "" && bundleForm.manifestPath !== bundleForm.auditPath;
  const submitBundle = async (event) => {
    event.preventDefault();
    if (!canExportBundle) {
      return;
    }
    setBundleSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/evidence-bundle/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bundleForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Evidence bundle export failed");
      }
      setBundleSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setBundleSubmitState({ loading: false, error: error.message || "Evidence bundle export failed", result: null });
    }
  };
  const updateTimeline = (key) => (event) => {
    setTimelineForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportTimeline = timelineForm.markdownPath !== "" &&
    timelineForm.jsonPath !== "" &&
    timelineForm.auditPath !== "" &&
    timelineForm.markdownPath !== timelineForm.jsonPath &&
    timelineForm.markdownPath !== timelineForm.auditPath &&
    timelineForm.jsonPath !== timelineForm.auditPath;
  const submitTimeline = async (event) => {
    event.preventDefault();
    if (!canExportTimeline) {
      return;
    }
    setTimelineSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/receipt-timeline/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(timelineForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Receipt timeline export failed");
      }
      setTimelineSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setTimelineSubmitState({ loading: false, error: error.message || "Receipt timeline export failed", result: null });
    }
  };
  const updateClosure = (key) => (event) => {
    setClosureForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosure = closureForm.manifestPath !== "" &&
    closureForm.auditPath !== "" &&
    closureForm.releaseReadinessReference.trim() !== "" &&
    closureForm.manifestPath !== closureForm.auditPath;
  const submitClosure = async (event) => {
    event.preventDefault();
    if (!canExportClosure) {
      return;
    }
    setClosureSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/closure-package/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Closure package export failed");
      }
      setClosureSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureSubmitState({ loading: false, error: error.message || "Closure package export failed", result: null });
    }
  };
  const updateReviewGate = (key) => (event) => {
    setReviewGateForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportReviewGate = reviewGateForm.releaseReadinessReference.trim() !== "" &&
    reviewGateForm.reviewerReference.trim() !== "" &&
    reviewGateForm.decision.trim() !== "" &&
    reviewGateForm.markdownPath !== "" &&
    reviewGateForm.jsonPath !== "" &&
    reviewGateForm.auditPath !== "" &&
    reviewGateForm.markdownPath !== reviewGateForm.jsonPath &&
    reviewGateForm.markdownPath !== reviewGateForm.auditPath &&
    reviewGateForm.jsonPath !== reviewGateForm.auditPath;
  const submitReviewGate = async (event) => {
    event.preventDefault();
    if (!canExportReviewGate) {
      return;
    }
    setReviewGateSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/closure-package/review-gate/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reviewGateForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Closure review gate export failed");
      }
      setReviewGateSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setReviewGateSubmitState({ loading: false, error: error.message || "Closure review gate export failed", result: null });
    }
  };
  const updateReleaseDecision = (key) => (event) => {
    setReleaseDecisionForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportReleaseDecision = releaseDecisionForm.releaseReadinessReference.trim() !== "" &&
    releaseDecisionForm.reviewerReference.trim() !== "" &&
    releaseDecisionForm.decision.trim() !== "" &&
    releaseDecisionForm.operatorReference.trim() !== "" &&
    releaseDecisionForm.decisionTimestamp.trim() !== "" &&
    releaseDecisionForm.ledgerPath !== "" &&
    releaseDecisionForm.auditPath !== "" &&
    releaseDecisionForm.ledgerPath !== releaseDecisionForm.auditPath;
  const submitReleaseDecision = async (event) => {
    event.preventDefault();
    if (!canExportReleaseDecision) {
      return;
    }
    setReleaseDecisionSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/release-decision/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(releaseDecisionForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Release decision export failed");
      }
      setReleaseDecisionSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setReleaseDecisionSubmitState({ loading: false, error: error.message || "Release decision export failed", result: null });
    }
  };
  const updateReleasePublication = (key) => (event) => {
    setReleasePublicationForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportReleasePublication = releasePublicationForm.publicationChannel.trim() !== "" &&
    releasePublicationForm.artifactLocationReference.trim() !== "" &&
    releasePublicationForm.publicationTimestamp.trim() !== "" &&
    releasePublicationForm.operatorReference.trim() !== "" &&
    releasePublicationForm.attestationPath !== "" &&
    releasePublicationForm.auditPath !== "" &&
    releasePublicationForm.attestationPath !== releasePublicationForm.auditPath;
  const submitReleasePublication = async (event) => {
    event.preventDefault();
    if (!canExportReleasePublication) {
      return;
    }
    setReleasePublicationSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/release-publication/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(releasePublicationForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Release publication export failed");
      }
      setReleasePublicationSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setReleasePublicationSubmitState({ loading: false, error: error.message || "Release publication export failed", result: null });
    }
  };
  const updatePublicationIndex = (key) => (event) => {
    setPublicationIndexForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportPublicationIndex = publicationIndexForm.publicationBatchReference.trim() !== "" &&
    publicationIndexForm.operatorReference.trim() !== "" &&
    publicationIndexForm.manifestPath !== "" &&
    publicationIndexForm.auditPath !== "" &&
    publicationIndexForm.manifestPath !== publicationIndexForm.auditPath;
  const submitPublicationIndex = async (event) => {
    event.preventDefault();
    if (!canExportPublicationIndex) {
      return;
    }
    setPublicationIndexSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/release-publication/index/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(publicationIndexForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Release publication index export failed");
      }
      setPublicationIndexSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setPublicationIndexSubmitState({ loading: false, error: error.message || "Release publication index export failed", result: null });
    }
  };
  const updatePublicationPackage = (key) => (event) => {
    setPublicationPackageForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportPublicationPackage = publicationPackageForm.packageReference.trim() !== "" &&
    publicationPackageForm.publicationWindowReference.trim() !== "" &&
    publicationPackageForm.operatorReference.trim() !== "" &&
    publicationPackageForm.manifestPath !== "" &&
    publicationPackageForm.auditPath !== "" &&
    publicationPackageForm.manifestPath !== publicationPackageForm.auditPath;
  const submitPublicationPackage = async (event) => {
    event.preventDefault();
    if (!canExportPublicationPackage) {
      return;
    }
    setPublicationPackageSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/release-publication/package/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(publicationPackageForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Release publication package export failed");
      }
      setPublicationPackageSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setPublicationPackageSubmitState({ loading: false, error: error.message || "Release publication package export failed", result: null });
    }
  };
  const updatePublicationEnvelope = (key) => (event) => {
    setPublicationEnvelopeForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportPublicationEnvelope = publicationEnvelopeForm.deliveryReference.trim() !== "" &&
    publicationEnvelopeForm.destinationReference.trim() !== "" &&
    publicationEnvelopeForm.operatorReference.trim() !== "" &&
    publicationEnvelopeForm.manifestPath !== "" &&
    publicationEnvelopeForm.auditPath !== "" &&
    publicationEnvelopeForm.manifestPath !== publicationEnvelopeForm.auditPath;
  const submitPublicationEnvelope = async (event) => {
    event.preventDefault();
    if (!canExportPublicationEnvelope) {
      return;
    }
    setPublicationEnvelopeSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/release-publication/envelope/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(publicationEnvelopeForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Release publication envelope export failed");
      }
      setPublicationEnvelopeSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setPublicationEnvelopeSubmitState({ loading: false, error: error.message || "Release publication envelope export failed", result: null });
    }
  };
  const updateHandoffReceipt = (key) => (event) => {
    setHandoffReceiptForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportHandoffReceipt = handoffReceiptForm.receiverReference.trim() !== "" &&
    handoffReceiptForm.handoffTimestamp.trim() !== "" &&
    handoffReceiptForm.operatorReference.trim() !== "" &&
    handoffReceiptForm.receiptPath !== "" &&
    handoffReceiptForm.auditPath !== "" &&
    handoffReceiptForm.receiptPath !== handoffReceiptForm.auditPath;
  const submitHandoffReceipt = async (event) => {
    event.preventDefault();
    if (!canExportHandoffReceipt) {
      return;
    }
    setHandoffReceiptSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/release-publication/handoff-receipt/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(handoffReceiptForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Release publication handoff receipt export failed");
      }
      setHandoffReceiptSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setHandoffReceiptSubmitState({ loading: false, error: error.message || "Release publication handoff receipt export failed", result: null });
    }
  };
  const updateAcknowledgment = (key) => (event) => {
    setAcknowledgmentForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportAcknowledgment = acknowledgmentForm.acknowledgmentReference.trim() !== "" &&
    acknowledgmentForm.acknowledgedByReference.trim() !== "" &&
    acknowledgmentForm.acknowledgmentTimestamp.trim() !== "" &&
    acknowledgmentForm.manifestPath !== "" &&
    acknowledgmentForm.auditPath !== "" &&
    acknowledgmentForm.manifestPath !== acknowledgmentForm.auditPath;
  const submitAcknowledgment = async (event) => {
    event.preventDefault();
    if (!canExportAcknowledgment) {
      return;
    }
    setAcknowledgmentSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/release-publication/acknowledgment/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(acknowledgmentForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Release publication acknowledgment export failed");
      }
      setAcknowledgmentSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setAcknowledgmentSubmitState({ loading: false, error: error.message || "Release publication acknowledgment export failed", result: null });
    }
  };
  const updateClosureSummary = (key) => (event) => {
    setClosureSummaryForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureSummary = closureSummaryForm.summaryReference.trim() !== "" &&
    closureSummaryForm.operatorReference.trim() !== "" &&
    closureSummaryForm.summaryTimestamp.trim() !== "" &&
    closureSummaryForm.manifestPath !== "" &&
    closureSummaryForm.auditPath !== "" &&
    closureSummaryForm.manifestPath !== closureSummaryForm.auditPath;
  const submitClosureSummary = async (event) => {
    event.preventDefault();
    if (!canExportClosureSummary) {
      return;
    }
    setClosureSummarySubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure-summary/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureSummaryForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure summary export failed");
      }
      setClosureSummarySubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureSummarySubmitState({ loading: false, error: error.message || "Rollout closure summary export failed", result: null });
    }
  };
  const updateClosureDelivery = (key) => (event) => {
    setClosureDeliveryForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureDelivery = closureDeliveryForm.deliveryReference.trim() !== "" &&
    closureDeliveryForm.destinationReference.trim() !== "" &&
    closureDeliveryForm.operatorReference.trim() !== "" &&
    closureDeliveryForm.deliveryTimestamp.trim() !== "" &&
    closureDeliveryForm.manifestPath !== "" &&
    closureDeliveryForm.auditPath !== "" &&
    closureDeliveryForm.manifestPath !== closureDeliveryForm.auditPath;
  const submitClosureDelivery = async (event) => {
    event.preventDefault();
    if (!canExportClosureDelivery) {
      return;
    }
    setClosureDeliverySubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure-delivery/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureDeliveryForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure delivery export failed");
      }
      setClosureDeliverySubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureDeliverySubmitState({ loading: false, error: error.message || "Rollout closure delivery export failed", result: null });
    }
  };
  const updateClosureAcceptance = (key) => (event) => {
    setClosureAcceptanceForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureAcceptance = closureAcceptanceForm.acceptanceReference.trim() !== "" &&
    closureAcceptanceForm.acceptedByReference.trim() !== "" &&
    closureAcceptanceForm.acceptanceTimestamp.trim() !== "" &&
    closureAcceptanceForm.manifestPath !== "" &&
    closureAcceptanceForm.auditPath !== "" &&
    closureAcceptanceForm.manifestPath !== closureAcceptanceForm.auditPath;
  const submitClosureAcceptance = async (event) => {
    event.preventDefault();
    if (!canExportClosureAcceptance) {
      return;
    }
    setClosureAcceptanceSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure-acceptance/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureAcceptanceForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure acceptance export failed");
      }
      setClosureAcceptanceSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureAcceptanceSubmitState({ loading: false, error: error.message || "Rollout closure acceptance export failed", result: null });
    }
  };
  const updateClosureCertificate = (key) => (event) => {
    setClosureCertificateForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureCertificate = closureCertificateForm.certificateReference.trim() !== "" &&
    closureCertificateForm.issuedByReference.trim() !== "" &&
    closureCertificateForm.issuedTimestamp.trim() !== "" &&
    closureCertificateForm.manifestPath !== "" &&
    closureCertificateForm.auditPath !== "" &&
    closureCertificateForm.manifestPath !== closureCertificateForm.auditPath;
  const submitClosureCertificate = async (event) => {
    event.preventDefault();
    if (!canExportClosureCertificate) {
      return;
    }
    setClosureCertificateSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure-certificate/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureCertificateForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure certificate export failed");
      }
      setClosureCertificateSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureCertificateSubmitState({ loading: false, error: error.message || "Rollout closure certificate export failed", result: null });
    }
  };
  const updateClosureLedger = (key) => (event) => {
    setClosureLedgerForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureLedger = closureLedgerForm.ledgerReference.trim() !== "" &&
    closureLedgerForm.recordedByReference.trim() !== "" &&
    closureLedgerForm.recordedTimestamp.trim() !== "" &&
    closureLedgerForm.manifestPath !== "" &&
    closureLedgerForm.auditPath !== "" &&
    closureLedgerForm.manifestPath !== closureLedgerForm.auditPath;
  const submitClosureLedger = async (event) => {
    event.preventDefault();
    if (!canExportClosureLedger) {
      return;
    }
    setClosureLedgerSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure-ledger/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureLedgerForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure ledger export failed");
      }
      setClosureLedgerSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureLedgerSubmitState({ loading: false, error: error.message || "Rollout closure ledger export failed", result: null });
    }
  };
  const updateClosureDocket = (key) => (event) => {
    setClosureDocketForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureDocket = closureDocketForm.docketReference.trim() !== "" &&
    closureDocketForm.preparedByReference.trim() !== "" &&
    closureDocketForm.preparedTimestamp.trim() !== "" &&
    closureDocketForm.manifestPath !== "" &&
    closureDocketForm.auditPath !== "" &&
    closureDocketForm.manifestPath !== closureDocketForm.auditPath;
  const submitClosureDocket = async (event) => {
    event.preventDefault();
    if (!canExportClosureDocket) {
      return;
    }
    setClosureDocketSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure-docket/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureDocketForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure docket export failed");
      }
      setClosureDocketSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureDocketSubmitState({ loading: false, error: error.message || "Rollout closure docket export failed", result: null });
    }
  };
  const updateClosureBulletin = (key) => (event) => {
    setClosureBulletinForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureBulletin = closureBulletinForm.bulletinReference.trim() !== "" &&
    closureBulletinForm.publishedByReference.trim() !== "" &&
    closureBulletinForm.publishedTimestamp.trim() !== "" &&
    closureBulletinForm.manifestPath !== "" &&
    closureBulletinForm.auditPath !== "" &&
    closureBulletinForm.manifestPath !== closureBulletinForm.auditPath;
  const submitClosureBulletin = async (event) => {
    event.preventDefault();
    if (!canExportClosureBulletin) {
      return;
    }
    setClosureBulletinSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure-bulletin/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureBulletinForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure bulletin export failed");
      }
      setClosureBulletinSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureBulletinSubmitState({ loading: false, error: error.message || "Rollout closure bulletin export failed", result: null });
    }
  };
  const updateClosurePacket = (key) => (event) => {
    setClosurePacketForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosurePacket = closurePacketForm.packetReference.trim() !== "" &&
    closurePacketForm.packagedByReference.trim() !== "" &&
    closurePacketForm.packagedTimestamp.trim() !== "" &&
    closurePacketForm.manifestPath !== "" &&
    closurePacketForm.auditPath !== "" &&
    closurePacketForm.manifestPath !== closurePacketForm.auditPath;
  const submitClosurePacket = async (event) => {
    event.preventDefault();
    if (!canExportClosurePacket) {
      return;
    }
    setClosurePacketSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure-packet/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closurePacketForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure packet export failed");
      }
      setClosurePacketSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosurePacketSubmitState({ loading: false, error: error.message || "Rollout closure packet export failed", result: null });
    }
  };
  const updateClosureRecipientPackage = (key) => (event) => {
    setClosureRecipientPackageForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureRecipientPackage = closureRecipientPackageForm.recipientPackageReference.trim() !== "" &&
    closureRecipientPackageForm.preparedForReference.trim() !== "" &&
    closureRecipientPackageForm.preparedTimestamp.trim() !== "" &&
    closureRecipientPackageForm.manifestPath !== "" &&
    closureRecipientPackageForm.auditPath !== "" &&
    closureRecipientPackageForm.manifestPath !== closureRecipientPackageForm.auditPath;
  const submitClosureRecipientPackage = async (event) => {
    event.preventDefault();
    if (!canExportClosureRecipientPackage) {
      return;
    }
    setClosureRecipientPackageSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure-recipient-package/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureRecipientPackageForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure recipient package export failed");
      }
      setClosureRecipientPackageSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureRecipientPackageSubmitState({ loading: false, error: error.message || "Rollout closure recipient package export failed", result: null });
    }
  };
  const submitClosureVerify = async () => {
    setClosureVerifySubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify");
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify failed");
      }
      setClosureVerifySubmitState({ loading: false, error: "", result: responsePayload.verification || null });
    } catch (error) {
      setClosureVerifySubmitState({ loading: false, error: error.message || "Rollout closure verify failed", result: null });
    }
  };
  const updateClosureVerifyExport = (key) => (event) => {
    const value = event.target.type === "checkbox" ? event.target.checked : event.target.value;
    setClosureVerifyExportForm((previous) => ({ ...previous, [key]: value }));
  };
  const canExportClosureVerify = closureVerifyExportForm.verificationReference.trim() !== "" &&
    closureVerifyExportForm.operatorReference.trim() !== "" &&
    closureVerifyExportForm.verificationTimestamp.trim() !== "" &&
    closureVerifyExportForm.markdownPath !== "" &&
    closureVerifyExportForm.jsonPath !== "" &&
    closureVerifyExportForm.auditPath !== "" &&
    closureVerifyExportForm.markdownPath !== closureVerifyExportForm.jsonPath &&
    closureVerifyExportForm.markdownPath !== closureVerifyExportForm.auditPath &&
    closureVerifyExportForm.jsonPath !== closureVerifyExportForm.auditPath &&
    (!closureVerifyExportForm.allowBlocked || closureVerifyExportForm.allowBlockedReasonReference.trim() !== "");
  const submitClosureVerifyExport = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerify) {
      return;
    }
    setClosureVerifyExportSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyExportForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify export failed");
      }
      setClosureVerifyExportSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyExportSubmitState({ loading: false, error: error.message || "Rollout closure verify export failed", result: null });
    }
  };
  const updateClosureVerifyAttestation = (key) => (event) => {
    setClosureVerifyAttestationForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyAttestation = closureVerifyAttestationForm.attestationReference.trim() !== "" &&
    closureVerifyAttestationForm.attestedByReference.trim() !== "" &&
    closureVerifyAttestationForm.attestationTimestamp.trim() !== "" &&
    closureVerifyAttestationForm.manifestPath !== "" &&
    closureVerifyAttestationForm.auditPath !== "" &&
    closureVerifyAttestationForm.manifestPath !== closureVerifyAttestationForm.auditPath;
  const submitClosureVerifyAttestation = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyAttestation) {
      return;
    }
    setClosureVerifyAttestationSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/attest", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyAttestationForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify attestation export failed");
      }
      setClosureVerifyAttestationSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyAttestationSubmitState({ loading: false, error: error.message || "Rollout closure verify attestation export failed", result: null });
    }
  };
  const updateClosureVerifyAttestationIndex = (key) => (event) => {
    setClosureVerifyAttestationIndexForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyAttestationIndex = closureVerifyAttestationIndexForm.attestationIndexReference.trim() !== "" &&
    closureVerifyAttestationIndexForm.publishedByReference.trim() !== "" &&
    closureVerifyAttestationIndexForm.publishedTimestamp.trim() !== "" &&
    closureVerifyAttestationIndexForm.manifestPath !== "" &&
    closureVerifyAttestationIndexForm.auditPath !== "" &&
    closureVerifyAttestationIndexForm.manifestPath !== closureVerifyAttestationIndexForm.auditPath;
  const submitClosureVerifyAttestationIndex = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyAttestationIndex) {
      return;
    }
    setClosureVerifyAttestationIndexSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/attest/index/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyAttestationIndexForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify attestation index export failed");
      }
      setClosureVerifyAttestationIndexSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyAttestationIndexSubmitState({ loading: false, error: error.message || "Rollout closure verify attestation index export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationPackage = (key) => (event) => {
    setClosureVerifyPublicationPackageForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationPackage = closureVerifyPublicationPackageForm.verificationPackageReference.trim() !== "" &&
    closureVerifyPublicationPackageForm.packagedByReference.trim() !== "" &&
    closureVerifyPublicationPackageForm.packagedTimestamp.trim() !== "" &&
    closureVerifyPublicationPackageForm.manifestPath !== "" &&
    closureVerifyPublicationPackageForm.auditPath !== "" &&
    closureVerifyPublicationPackageForm.manifestPath !== closureVerifyPublicationPackageForm.auditPath;
  const submitClosureVerifyPublicationPackage = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationPackage) {
      return;
    }
    setClosureVerifyPublicationPackageSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-package/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationPackageForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication package export failed");
      }
      setClosureVerifyPublicationPackageSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationPackageSubmitState({ loading: false, error: error.message || "Rollout closure verify publication package export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationAttestation = (key) => (event) => {
    setClosureVerifyPublicationAttestationForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationAttestation = closureVerifyPublicationAttestationForm.verificationPublicationReference.trim() !== "" &&
    closureVerifyPublicationAttestationForm.publishedByReference.trim() !== "" &&
    closureVerifyPublicationAttestationForm.publishedTimestamp.trim() !== "" &&
    closureVerifyPublicationAttestationForm.publicationChannel.trim() !== "" &&
    closureVerifyPublicationAttestationForm.publicationLocationReference.trim() !== "" &&
    closureVerifyPublicationAttestationForm.manifestPath !== "" &&
    closureVerifyPublicationAttestationForm.auditPath !== "" &&
    closureVerifyPublicationAttestationForm.manifestPath !== closureVerifyPublicationAttestationForm.auditPath;
  const submitClosureVerifyPublicationAttestation = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationAttestation) {
      return;
    }
    setClosureVerifyPublicationAttestationSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-attestation/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationAttestationForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication attestation export failed");
      }
      setClosureVerifyPublicationAttestationSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationAttestationSubmitState({ loading: false, error: error.message || "Rollout closure verify publication attestation export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationIndex = (key) => (event) => {
    setClosureVerifyPublicationIndexForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationIndex = closureVerifyPublicationIndexForm.verificationPublicationIndexReference.trim() !== "" &&
    closureVerifyPublicationIndexForm.indexedByReference.trim() !== "" &&
    closureVerifyPublicationIndexForm.indexedTimestamp.trim() !== "" &&
    closureVerifyPublicationIndexForm.manifestPath !== "" &&
    closureVerifyPublicationIndexForm.auditPath !== "" &&
    closureVerifyPublicationIndexForm.manifestPath !== closureVerifyPublicationIndexForm.auditPath;
  const submitClosureVerifyPublicationIndex = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationIndex) {
      return;
    }
    setClosureVerifyPublicationIndexSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-index/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationIndexForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication index export failed");
      }
      setClosureVerifyPublicationIndexSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationIndexSubmitState({ loading: false, error: error.message || "Rollout closure verify publication index export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationEnvelope = (key) => (event) => {
    setClosureVerifyPublicationEnvelopeForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationEnvelope = closureVerifyPublicationEnvelopeForm.verificationPublicationEnvelopeReference.trim() !== "" &&
    closureVerifyPublicationEnvelopeForm.deliveredByReference.trim() !== "" &&
    closureVerifyPublicationEnvelopeForm.deliveryTimestamp.trim() !== "" &&
    closureVerifyPublicationEnvelopeForm.deliveryDestinationReference.trim() !== "" &&
    closureVerifyPublicationEnvelopeForm.manifestPath !== "" &&
    closureVerifyPublicationEnvelopeForm.auditPath !== "" &&
    closureVerifyPublicationEnvelopeForm.manifestPath !== closureVerifyPublicationEnvelopeForm.auditPath;
  const submitClosureVerifyPublicationEnvelope = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationEnvelope) {
      return;
    }
    setClosureVerifyPublicationEnvelopeSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-envelope/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationEnvelopeForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication envelope export failed");
      }
      setClosureVerifyPublicationEnvelopeSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationEnvelopeSubmitState({ loading: false, error: error.message || "Rollout closure verify publication envelope export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationHandoff = (key) => (event) => {
    setClosureVerifyPublicationHandoffForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationHandoff = closureVerifyPublicationHandoffForm.verificationPublicationHandoffReference.trim() !== "" &&
    closureVerifyPublicationHandoffForm.receivedByReference.trim() !== "" &&
    closureVerifyPublicationHandoffForm.handoffTimestamp.trim() !== "" &&
    closureVerifyPublicationHandoffForm.manifestPath !== "" &&
    closureVerifyPublicationHandoffForm.auditPath !== "" &&
    closureVerifyPublicationHandoffForm.manifestPath !== closureVerifyPublicationHandoffForm.auditPath;
  const submitClosureVerifyPublicationHandoff = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationHandoff) {
      return;
    }
    setClosureVerifyPublicationHandoffSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-handoff/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationHandoffForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication handoff export failed");
      }
      setClosureVerifyPublicationHandoffSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationHandoffSubmitState({ loading: false, error: error.message || "Rollout closure verify publication handoff export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationAcknowledgment = (key) => (event) => {
    setClosureVerifyPublicationAcknowledgmentForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationAcknowledgment = closureVerifyPublicationAcknowledgmentForm.verificationPublicationAcknowledgmentReference.trim() !== "" &&
    closureVerifyPublicationAcknowledgmentForm.acknowledgedByReference.trim() !== "" &&
    closureVerifyPublicationAcknowledgmentForm.acknowledgmentTimestamp.trim() !== "" &&
    closureVerifyPublicationAcknowledgmentForm.manifestPath !== "" &&
    closureVerifyPublicationAcknowledgmentForm.auditPath !== "" &&
    closureVerifyPublicationAcknowledgmentForm.manifestPath !== closureVerifyPublicationAcknowledgmentForm.auditPath;
  const submitClosureVerifyPublicationAcknowledgment = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationAcknowledgment) {
      return;
    }
    setClosureVerifyPublicationAcknowledgmentSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-acknowledgment/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationAcknowledgmentForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication acknowledgment export failed");
      }
      setClosureVerifyPublicationAcknowledgmentSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationAcknowledgmentSubmitState({ loading: false, error: error.message || "Rollout closure verify publication acknowledgment export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationArchiveIndex = (key) => (event) => {
    setClosureVerifyPublicationArchiveIndexForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationArchiveIndex = closureVerifyPublicationArchiveIndexForm.verificationPublicationArchiveIndexReference.trim() !== "" &&
    closureVerifyPublicationArchiveIndexForm.indexedByReference.trim() !== "" &&
    closureVerifyPublicationArchiveIndexForm.indexedTimestamp.trim() !== "" &&
    closureVerifyPublicationArchiveIndexForm.manifestPath !== "" &&
    closureVerifyPublicationArchiveIndexForm.auditPath !== "" &&
    closureVerifyPublicationArchiveIndexForm.manifestPath !== closureVerifyPublicationArchiveIndexForm.auditPath;
  const submitClosureVerifyPublicationArchiveIndex = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationArchiveIndex) {
      return;
    }
    setClosureVerifyPublicationArchiveIndexSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-archive-index/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationArchiveIndexForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication archive index export failed");
      }
      setClosureVerifyPublicationArchiveIndexSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationArchiveIndexSubmitState({ loading: false, error: error.message || "Rollout closure verify publication archive index export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationArchivePackage = (key) => (event) => {
    setClosureVerifyPublicationArchivePackageForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationArchivePackage = closureVerifyPublicationArchivePackageForm.verificationPublicationArchivePackageReference.trim() !== "" &&
    closureVerifyPublicationArchivePackageForm.packagedByReference.trim() !== "" &&
    closureVerifyPublicationArchivePackageForm.packagedTimestamp.trim() !== "" &&
    closureVerifyPublicationArchivePackageForm.manifestPath !== "" &&
    closureVerifyPublicationArchivePackageForm.auditPath !== "" &&
    closureVerifyPublicationArchivePackageForm.manifestPath !== closureVerifyPublicationArchivePackageForm.auditPath;
  const submitClosureVerifyPublicationArchivePackage = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationArchivePackage) {
      return;
    }
    setClosureVerifyPublicationArchivePackageSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-archive-package/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationArchivePackageForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication archive package export failed");
      }
      setClosureVerifyPublicationArchivePackageSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationArchivePackageSubmitState({ loading: false, error: error.message || "Rollout closure verify publication archive package export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationArchiveEnvelope = (key) => (event) => {
    setClosureVerifyPublicationArchiveEnvelopeForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationArchiveEnvelope = closureVerifyPublicationArchiveEnvelopeForm.verificationPublicationArchiveEnvelopeReference.trim() !== "" &&
    closureVerifyPublicationArchiveEnvelopeForm.deliveredByReference.trim() !== "" &&
    closureVerifyPublicationArchiveEnvelopeForm.deliveryTimestamp.trim() !== "" &&
    closureVerifyPublicationArchiveEnvelopeForm.deliveryDestinationReference.trim() !== "" &&
    closureVerifyPublicationArchiveEnvelopeForm.manifestPath !== "" &&
    closureVerifyPublicationArchiveEnvelopeForm.auditPath !== "" &&
    closureVerifyPublicationArchiveEnvelopeForm.manifestPath !== closureVerifyPublicationArchiveEnvelopeForm.auditPath;
  const submitClosureVerifyPublicationArchiveEnvelope = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationArchiveEnvelope) {
      return;
    }
    setClosureVerifyPublicationArchiveEnvelopeSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-archive-envelope/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationArchiveEnvelopeForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication archive envelope export failed");
      }
      setClosureVerifyPublicationArchiveEnvelopeSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationArchiveEnvelopeSubmitState({ loading: false, error: error.message || "Rollout closure verify publication archive envelope export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationArchiveHandoff = (key) => (event) => {
    setClosureVerifyPublicationArchiveHandoffForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationArchiveHandoff = closureVerifyPublicationArchiveHandoffForm.verificationPublicationArchiveHandoffReference.trim() !== "" &&
    closureVerifyPublicationArchiveHandoffForm.receivedByReference.trim() !== "" &&
    closureVerifyPublicationArchiveHandoffForm.handoffTimestamp.trim() !== "" &&
    closureVerifyPublicationArchiveHandoffForm.manifestPath !== "" &&
    closureVerifyPublicationArchiveHandoffForm.auditPath !== "" &&
    closureVerifyPublicationArchiveHandoffForm.manifestPath !== closureVerifyPublicationArchiveHandoffForm.auditPath;
  const submitClosureVerifyPublicationArchiveHandoff = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationArchiveHandoff) {
      return;
    }
    setClosureVerifyPublicationArchiveHandoffSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-archive-handoff/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationArchiveHandoffForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication archive handoff export failed");
      }
      setClosureVerifyPublicationArchiveHandoffSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationArchiveHandoffSubmitState({ loading: false, error: error.message || "Rollout closure verify publication archive handoff export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationArchiveAcknowledgment = (key) => (event) => {
    setClosureVerifyPublicationArchiveAcknowledgmentForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationArchiveAcknowledgment = closureVerifyPublicationArchiveAcknowledgmentForm.verificationPublicationArchiveAcknowledgmentReference.trim() !== "" &&
    closureVerifyPublicationArchiveAcknowledgmentForm.acknowledgedByReference.trim() !== "" &&
    closureVerifyPublicationArchiveAcknowledgmentForm.acknowledgmentTimestamp.trim() !== "" &&
    closureVerifyPublicationArchiveAcknowledgmentForm.manifestPath !== "" &&
    closureVerifyPublicationArchiveAcknowledgmentForm.auditPath !== "" &&
    closureVerifyPublicationArchiveAcknowledgmentForm.manifestPath !== closureVerifyPublicationArchiveAcknowledgmentForm.auditPath;
  const submitClosureVerifyPublicationArchiveAcknowledgment = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationArchiveAcknowledgment) {
      return;
    }
    setClosureVerifyPublicationArchiveAcknowledgmentSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-archive-acknowledgment/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationArchiveAcknowledgmentForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication archive acknowledgment export failed");
      }
      setClosureVerifyPublicationArchiveAcknowledgmentSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationArchiveAcknowledgmentSubmitState({ loading: false, error: error.message || "Rollout closure verify publication archive acknowledgment export failed", result: null });
    }
  };
  const updateClosureVerifyPublicationArchiveAttestation = (key) => (event) => {
    setClosureVerifyPublicationArchiveAttestationForm((previous) => ({ ...previous, [key]: event.target.value }));
  };
  const canExportClosureVerifyPublicationArchiveAttestation = closureVerifyPublicationArchiveAttestationForm.verificationPublicationArchiveAttestationReference.trim() !== "" &&
    closureVerifyPublicationArchiveAttestationForm.attestedByReference.trim() !== "" &&
    closureVerifyPublicationArchiveAttestationForm.attestationTimestamp.trim() !== "" &&
    closureVerifyPublicationArchiveAttestationForm.manifestPath !== "" &&
    closureVerifyPublicationArchiveAttestationForm.auditPath !== "" &&
    closureVerifyPublicationArchiveAttestationForm.manifestPath !== closureVerifyPublicationArchiveAttestationForm.auditPath;
  const submitClosureVerifyPublicationArchiveAttestation = async (event) => {
    event.preventDefault();
    if (!canExportClosureVerifyPublicationArchiveAttestation) {
      return;
    }
    setClosureVerifyPublicationArchiveAttestationSubmitState({ loading: true, error: "", result: null });
    try {
      const response = await fetch("/api/v1/workflow/rollout-closure/verify/publication-archive-attestation/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(closureVerifyPublicationArchiveAttestationForm),
      });
      const responsePayload = await response.json();
      if (!response.ok) {
        throw new Error(responsePayload?.diagnostics?.[0]?.message || "Rollout closure verify publication archive attestation export failed");
      }
      setClosureVerifyPublicationArchiveAttestationSubmitState({ loading: false, error: "", result: responsePayload.export || null });
    } catch (error) {
      setClosureVerifyPublicationArchiveAttestationSubmitState({ loading: false, error: error.message || "Rollout closure verify publication archive attestation export failed", result: null });
    }
  };
  return (
    <>
      <p>Workspace: {workspacePath || "unknown"}</p>
      <dl className="grid">
        <div><dt>Readiness</dt><dd>{capsule.ready ? "ready" : "blocked"}</dd></div>
        <div><dt>Blocker count</dt><dd>{String(blockers.length)}</dd></div>
        <div><dt>Plan ID</dt><dd>{evidence.planId || "n/a"}</dd></div>
        <div><dt>Bundle ID</dt><dd>{evidence.bundleId || "n/a"}</dd></div>
        <div><dt>Preflight ID</dt><dd>{evidence.preflightResultId || "n/a"}</dd></div>
        <div><dt>Change-set ID</dt><dd>{evidence.changeSetId || "n/a"}</dd></div>
        <div><dt>Approval ID</dt><dd>{evidence.approvalId || "n/a"}</dd></div>
        <div><dt>Authorization ID</dt><dd>{evidence.authorizationId || "n/a"}</dd></div>
      </dl>
      <h3>Stage status</h3>
      <table>
        <thead>
          <tr><th>Stage</th><th>Status</th><th>Artifact</th></tr>
        </thead>
        <tbody>
          {stages.map((stage) => (
            <tr key={stage.id}>
              <td>{stage.label}</td>
              <td>{stage.status}</td>
              <td>{stage.artifactPath || "none"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h3>Runbook exports</h3>
      <ul>
        <li>Markdown exports: {markdownExports.length > 0 ? markdownExports.join(", ") : "none"}</li>
        <li>JSON exports: {jsonExports.length > 0 ? jsonExports.join(", ") : "none"}</li>
      </ul>
      <h3>Blockers</h3>
      {blockers.length === 0 ? (
        <p>No blockers. Capsule is ready.</p>
      ) : (
        <table>
          <thead>
            <tr><th>Code</th><th>Severity</th><th>Message</th><th>Remediation</th></tr>
          </thead>
          <tbody>
            {blockers.map((blocker) => (
              <tr key={blocker.code}>
                <td>{blocker.code}</td>
                <td>{blocker.severity}</td>
                <td>{blocker.message}</td>
                <td>{blocker.remediation}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h3>Verify rollout closure chain</h3>
      <button type="button" onClick={submitClosureVerify} disabled={closureVerifySubmitState.loading}>
        {closureVerifySubmitState.loading ? "Verifying closure chain..." : "Verify rollout closure chain"}
      </button>
      {closureVerifySubmitState.error && <p className="error">Closure chain verification: blocked ({closureVerifySubmitState.error})</p>}
      {closureVerifySubmitState.result && (
        <>
          <dl className="grid">
            <div><dt>Verification readiness</dt><dd>{closureVerifySubmitState.result.ready ? "pass" : "blocked"}</dd></div>
            <div><dt>Verification state</dt><dd>{closureVerifySubmitState.result.verificationState || "n/a"}</dd></div>
            <div><dt>Blocker code</dt><dd>{closureVerifySubmitState.result.blockerCode || "none"}</dd></div>
          </dl>
          <h4>Chain coverage</h4>
          <table>
            <thead>
              <tr><th>Artifact</th><th>Status</th><th>State</th><th>Digest</th></tr>
            </thead>
            <tbody>
              {(closureVerifySubmitState.result.coverage || []).map((entry) => (
                <tr key={entry.artifact}>
                  <td>{entry.artifact}</td>
                  <td>{entry.status || "n/a"}</td>
                  <td>{entry.state || "n/a"}</td>
                  <td>{entry.digest || "n/a"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h4>Verification diagnostics</h4>
          {Array.isArray(closureVerifySubmitState.result.diagnostics) && closureVerifySubmitState.result.diagnostics.length > 0 ? (
            <table>
              <thead>
                <tr><th>Code</th><th>Severity</th><th>Message</th><th>Remediation</th></tr>
              </thead>
              <tbody>
                {closureVerifySubmitState.result.diagnostics.map((diagnostic) => (
                  <tr key={diagnostic.code}>
                    <td>{diagnostic.code}</td>
                    <td>{diagnostic.severity || "n/a"}</td>
                    <td>{diagnostic.message || "n/a"}</td>
                    <td>{diagnostic.remediation || "n/a"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p>No closure chain diagnostics.</p>
          )}
        </>
      )}
      <h3>Export closure chain verification bundle</h3>
      <form onSubmit={submitClosureVerifyExport}>
        <div className="formRow">
          <label htmlFor="closure-verify-reference">Verification reference</label>
          <input id="closure-verify-reference" value={closureVerifyExportForm.verificationReference} onChange={updateClosureVerifyExport("verificationReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-operator-reference">Verification operator reference</label>
          <input id="closure-verify-operator-reference" value={closureVerifyExportForm.operatorReference} onChange={updateClosureVerifyExport("operatorReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-timestamp">Verification timestamp (RFC3339)</label>
          <input id="closure-verify-timestamp" value={closureVerifyExportForm.verificationTimestamp} onChange={updateClosureVerifyExport("verificationTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-markdown-path">Verification markdown output path</label>
          <input id="closure-verify-markdown-path" value={closureVerifyExportForm.markdownPath} onChange={updateClosureVerifyExport("markdownPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-json-path">Verification JSON output path</label>
          <input id="closure-verify-json-path" value={closureVerifyExportForm.jsonPath} onChange={updateClosureVerifyExport("jsonPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-audit-path">Verification audit output path</label>
          <input id="closure-verify-audit-path" value={closureVerifyExportForm.auditPath} onChange={updateClosureVerifyExport("auditPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-allow-blocked">Allow blocked verification export</label>
          <input id="closure-verify-allow-blocked" type="checkbox" checked={closureVerifyExportForm.allowBlocked} onChange={updateClosureVerifyExport("allowBlocked")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-blocked-reason">Blocked export reason reference</label>
          <input id="closure-verify-blocked-reason" value={closureVerifyExportForm.allowBlockedReasonReference} onChange={updateClosureVerifyExport("allowBlockedReasonReference")} />
        </div>
        <button type="submit" disabled={closureVerifyExportSubmitState.loading || !canExportClosureVerify}>
          {closureVerifyExportSubmitState.loading ? "Exporting verification bundle..." : "Export closure verification bundle"}
        </button>
      </form>
      {!canExportClosureVerify && <p className="error">Verification export requires references, timestamp, distinct output paths, and a blocked reason when blocked export is allowed.</p>}
      {closureVerifyExportSubmitState.error && <p className="error">Verification export: blocked ({closureVerifyExportSubmitState.error})</p>}
      {closureVerifyExportSubmitState.result && (
        <dl className="grid">
          <div><dt>Markdown path</dt><dd>{closureVerifyExportSubmitState.result.markdownPath || "n/a"}</dd></div>
          <div><dt>JSON path</dt><dd>{closureVerifyExportSubmitState.result.jsonPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyExportSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Verification state</dt><dd>{closureVerifyExportSubmitState.result.verificationState || "n/a"}</dd></div>
          <div><dt>Blocked archival</dt><dd>{String(Boolean(closureVerifyExportSubmitState.result.blockedArchival))}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyExportSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification attestation</h3>
      <form onSubmit={submitClosureVerifyAttestation}>
        <div className="formRow">
          <label htmlFor="closure-verify-attestation-reference">Attestation reference</label>
          <input id="closure-verify-attestation-reference" value={closureVerifyAttestationForm.attestationReference} onChange={updateClosureVerifyAttestation("attestationReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-attested-by-reference">Attested by reference</label>
          <input id="closure-verify-attested-by-reference" value={closureVerifyAttestationForm.attestedByReference} onChange={updateClosureVerifyAttestation("attestedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-attestation-timestamp">Attestation timestamp (RFC3339)</label>
          <input id="closure-verify-attestation-timestamp" value={closureVerifyAttestationForm.attestationTimestamp} onChange={updateClosureVerifyAttestation("attestationTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-attestation-manifest-path">Attestation manifest output path</label>
          <input id="closure-verify-attestation-manifest-path" value={closureVerifyAttestationForm.manifestPath} onChange={updateClosureVerifyAttestation("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-attestation-audit-path">Attestation audit output path</label>
          <input id="closure-verify-attestation-audit-path" value={closureVerifyAttestationForm.auditPath} onChange={updateClosureVerifyAttestation("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyAttestationSubmitState.loading || !canExportClosureVerifyAttestation}>
          {closureVerifyAttestationSubmitState.loading ? "Exporting verification attestation..." : "Export closure verification attestation"}
        </button>
      </form>
      {!canExportClosureVerifyAttestation && <p className="error">Verification attestation export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyAttestationSubmitState.error && <p className="error">Verification attestation: blocked ({closureVerifyAttestationSubmitState.error})</p>}
      {closureVerifyAttestationSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyAttestationSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyAttestationSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Attestation state</dt><dd>{closureVerifyAttestationSubmitState.result.attestationState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyAttestationSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification attestation index</h3>
      <form onSubmit={submitClosureVerifyAttestationIndex}>
        <div className="formRow">
          <label htmlFor="closure-verify-attestation-index-reference">Attestation index reference</label>
          <input id="closure-verify-attestation-index-reference" value={closureVerifyAttestationIndexForm.attestationIndexReference} onChange={updateClosureVerifyAttestationIndex("attestationIndexReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-attestation-index-published-by-reference">Attestation index published by reference</label>
          <input id="closure-verify-attestation-index-published-by-reference" value={closureVerifyAttestationIndexForm.publishedByReference} onChange={updateClosureVerifyAttestationIndex("publishedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-attestation-index-published-timestamp">Attestation index published timestamp (RFC3339)</label>
          <input id="closure-verify-attestation-index-published-timestamp" value={closureVerifyAttestationIndexForm.publishedTimestamp} onChange={updateClosureVerifyAttestationIndex("publishedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-attestation-index-manifest-path">Attestation index manifest output path</label>
          <input id="closure-verify-attestation-index-manifest-path" value={closureVerifyAttestationIndexForm.manifestPath} onChange={updateClosureVerifyAttestationIndex("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-attestation-index-audit-path">Attestation index audit output path</label>
          <input id="closure-verify-attestation-index-audit-path" value={closureVerifyAttestationIndexForm.auditPath} onChange={updateClosureVerifyAttestationIndex("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyAttestationIndexSubmitState.loading || !canExportClosureVerifyAttestationIndex}>
          {closureVerifyAttestationIndexSubmitState.loading ? "Exporting verification attestation index..." : "Export closure verification attestation index"}
        </button>
      </form>
      {!canExportClosureVerifyAttestationIndex && <p className="error">Verification attestation index export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyAttestationIndexSubmitState.error && <p className="error">Verification attestation index: blocked ({closureVerifyAttestationIndexSubmitState.error})</p>}
      {closureVerifyAttestationIndexSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyAttestationIndexSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyAttestationIndexSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Index state</dt><dd>{closureVerifyAttestationIndexSubmitState.result.indexState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyAttestationIndexSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication package</h3>
      <form onSubmit={submitClosureVerifyPublicationPackage}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-package-reference">Verification package reference</label>
          <input id="closure-verify-publication-package-reference" value={closureVerifyPublicationPackageForm.verificationPackageReference} onChange={updateClosureVerifyPublicationPackage("verificationPackageReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-package-packaged-by-reference">Verification package packaged by reference</label>
          <input id="closure-verify-publication-package-packaged-by-reference" value={closureVerifyPublicationPackageForm.packagedByReference} onChange={updateClosureVerifyPublicationPackage("packagedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-package-packaged-timestamp">Verification package timestamp (RFC3339)</label>
          <input id="closure-verify-publication-package-packaged-timestamp" value={closureVerifyPublicationPackageForm.packagedTimestamp} onChange={updateClosureVerifyPublicationPackage("packagedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-package-manifest-path">Verification package manifest output path</label>
          <input id="closure-verify-publication-package-manifest-path" value={closureVerifyPublicationPackageForm.manifestPath} onChange={updateClosureVerifyPublicationPackage("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-package-audit-path">Verification package audit output path</label>
          <input id="closure-verify-publication-package-audit-path" value={closureVerifyPublicationPackageForm.auditPath} onChange={updateClosureVerifyPublicationPackage("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationPackageSubmitState.loading || !canExportClosureVerifyPublicationPackage}>
          {closureVerifyPublicationPackageSubmitState.loading ? "Exporting verification publication package..." : "Export closure verification publication package"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationPackage && <p className="error">Verification publication package export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationPackageSubmitState.error && <p className="error">Verification publication package: blocked ({closureVerifyPublicationPackageSubmitState.error})</p>}
      {closureVerifyPublicationPackageSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationPackageSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationPackageSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Package state</dt><dd>{closureVerifyPublicationPackageSubmitState.result.packageState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationPackageSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication attestation</h3>
      <form onSubmit={submitClosureVerifyPublicationAttestation}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-attestation-reference">Verification publication reference</label>
          <input id="closure-verify-publication-attestation-reference" value={closureVerifyPublicationAttestationForm.verificationPublicationReference} onChange={updateClosureVerifyPublicationAttestation("verificationPublicationReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-attestation-published-by-reference">Verification publication published by reference</label>
          <input id="closure-verify-publication-attestation-published-by-reference" value={closureVerifyPublicationAttestationForm.publishedByReference} onChange={updateClosureVerifyPublicationAttestation("publishedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-attestation-published-timestamp">Verification publication timestamp (RFC3339)</label>
          <input id="closure-verify-publication-attestation-published-timestamp" value={closureVerifyPublicationAttestationForm.publishedTimestamp} onChange={updateClosureVerifyPublicationAttestation("publishedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-attestation-channel">Verification publication channel</label>
          <input id="closure-verify-publication-attestation-channel" value={closureVerifyPublicationAttestationForm.publicationChannel} onChange={updateClosureVerifyPublicationAttestation("publicationChannel")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-attestation-location">Verification publication location reference</label>
          <input id="closure-verify-publication-attestation-location" value={closureVerifyPublicationAttestationForm.publicationLocationReference} onChange={updateClosureVerifyPublicationAttestation("publicationLocationReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-attestation-manifest-path">Verification publication attestation manifest output path</label>
          <input id="closure-verify-publication-attestation-manifest-path" value={closureVerifyPublicationAttestationForm.manifestPath} onChange={updateClosureVerifyPublicationAttestation("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-attestation-audit-path">Verification publication attestation audit output path</label>
          <input id="closure-verify-publication-attestation-audit-path" value={closureVerifyPublicationAttestationForm.auditPath} onChange={updateClosureVerifyPublicationAttestation("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationAttestationSubmitState.loading || !canExportClosureVerifyPublicationAttestation}>
          {closureVerifyPublicationAttestationSubmitState.loading ? "Exporting verification publication attestation..." : "Export closure verification publication attestation"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationAttestation && <p className="error">Verification publication attestation export requires references, channel metadata, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationAttestationSubmitState.error && <p className="error">Verification publication attestation: blocked ({closureVerifyPublicationAttestationSubmitState.error})</p>}
      {closureVerifyPublicationAttestationSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationAttestationSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationAttestationSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Publication state</dt><dd>{closureVerifyPublicationAttestationSubmitState.result.publicationState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationAttestationSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication index</h3>
      <form onSubmit={submitClosureVerifyPublicationIndex}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-index-reference">Verification publication index reference</label>
          <input id="closure-verify-publication-index-reference" value={closureVerifyPublicationIndexForm.verificationPublicationIndexReference} onChange={updateClosureVerifyPublicationIndex("verificationPublicationIndexReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-indexed-by-reference">Verification publication index by reference</label>
          <input id="closure-verify-publication-indexed-by-reference" value={closureVerifyPublicationIndexForm.indexedByReference} onChange={updateClosureVerifyPublicationIndex("indexedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-indexed-timestamp">Verification publication index timestamp (RFC3339)</label>
          <input id="closure-verify-publication-indexed-timestamp" value={closureVerifyPublicationIndexForm.indexedTimestamp} onChange={updateClosureVerifyPublicationIndex("indexedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-index-manifest-path">Verification publication index manifest output path</label>
          <input id="closure-verify-publication-index-manifest-path" value={closureVerifyPublicationIndexForm.manifestPath} onChange={updateClosureVerifyPublicationIndex("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-index-audit-path">Verification publication index audit output path</label>
          <input id="closure-verify-publication-index-audit-path" value={closureVerifyPublicationIndexForm.auditPath} onChange={updateClosureVerifyPublicationIndex("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationIndexSubmitState.loading || !canExportClosureVerifyPublicationIndex}>
          {closureVerifyPublicationIndexSubmitState.loading ? "Exporting verification publication index..." : "Export closure verification publication index"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationIndex && <p className="error">Verification publication index export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationIndexSubmitState.error && <p className="error">Verification publication index: blocked ({closureVerifyPublicationIndexSubmitState.error})</p>}
      {closureVerifyPublicationIndexSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationIndexSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationIndexSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Index state</dt><dd>{closureVerifyPublicationIndexSubmitState.result.indexState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationIndexSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication envelope</h3>
      <form onSubmit={submitClosureVerifyPublicationEnvelope}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-envelope-reference">Verification publication envelope reference</label>
          <input id="closure-verify-publication-envelope-reference" value={closureVerifyPublicationEnvelopeForm.verificationPublicationEnvelopeReference} onChange={updateClosureVerifyPublicationEnvelope("verificationPublicationEnvelopeReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-envelope-delivered-by-reference">Verification publication envelope delivered by reference</label>
          <input id="closure-verify-publication-envelope-delivered-by-reference" value={closureVerifyPublicationEnvelopeForm.deliveredByReference} onChange={updateClosureVerifyPublicationEnvelope("deliveredByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-envelope-delivery-timestamp">Verification publication envelope delivery timestamp (RFC3339)</label>
          <input id="closure-verify-publication-envelope-delivery-timestamp" value={closureVerifyPublicationEnvelopeForm.deliveryTimestamp} onChange={updateClosureVerifyPublicationEnvelope("deliveryTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-envelope-destination-reference">Verification publication envelope destination reference</label>
          <input id="closure-verify-publication-envelope-destination-reference" value={closureVerifyPublicationEnvelopeForm.deliveryDestinationReference} onChange={updateClosureVerifyPublicationEnvelope("deliveryDestinationReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-envelope-manifest-path">Verification publication envelope manifest output path</label>
          <input id="closure-verify-publication-envelope-manifest-path" value={closureVerifyPublicationEnvelopeForm.manifestPath} onChange={updateClosureVerifyPublicationEnvelope("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-envelope-audit-path">Verification publication envelope audit output path</label>
          <input id="closure-verify-publication-envelope-audit-path" value={closureVerifyPublicationEnvelopeForm.auditPath} onChange={updateClosureVerifyPublicationEnvelope("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationEnvelopeSubmitState.loading || !canExportClosureVerifyPublicationEnvelope}>
          {closureVerifyPublicationEnvelopeSubmitState.loading ? "Exporting verification publication envelope..." : "Export closure verification publication envelope"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationEnvelope && <p className="error">Verification publication envelope export requires references, destination, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationEnvelopeSubmitState.error && <p className="error">Verification publication envelope: blocked ({closureVerifyPublicationEnvelopeSubmitState.error})</p>}
      {closureVerifyPublicationEnvelopeSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationEnvelopeSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationEnvelopeSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Envelope state</dt><dd>{closureVerifyPublicationEnvelopeSubmitState.result.envelopeState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationEnvelopeSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication handoff</h3>
      <form onSubmit={submitClosureVerifyPublicationHandoff}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-handoff-reference">Verification publication handoff reference</label>
          <input id="closure-verify-publication-handoff-reference" value={closureVerifyPublicationHandoffForm.verificationPublicationHandoffReference} onChange={updateClosureVerifyPublicationHandoff("verificationPublicationHandoffReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-handoff-received-by-reference">Verification publication handoff received by reference</label>
          <input id="closure-verify-publication-handoff-received-by-reference" value={closureVerifyPublicationHandoffForm.receivedByReference} onChange={updateClosureVerifyPublicationHandoff("receivedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-handoff-timestamp">Verification publication handoff timestamp (RFC3339)</label>
          <input id="closure-verify-publication-handoff-timestamp" value={closureVerifyPublicationHandoffForm.handoffTimestamp} onChange={updateClosureVerifyPublicationHandoff("handoffTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-handoff-manifest-path">Verification publication handoff manifest output path</label>
          <input id="closure-verify-publication-handoff-manifest-path" value={closureVerifyPublicationHandoffForm.manifestPath} onChange={updateClosureVerifyPublicationHandoff("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-handoff-audit-path">Verification publication handoff audit output path</label>
          <input id="closure-verify-publication-handoff-audit-path" value={closureVerifyPublicationHandoffForm.auditPath} onChange={updateClosureVerifyPublicationHandoff("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationHandoffSubmitState.loading || !canExportClosureVerifyPublicationHandoff}>
          {closureVerifyPublicationHandoffSubmitState.loading ? "Exporting verification publication handoff..." : "Export closure verification publication handoff"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationHandoff && <p className="error">Verification publication handoff export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationHandoffSubmitState.error && <p className="error">Verification publication handoff: blocked ({closureVerifyPublicationHandoffSubmitState.error})</p>}
      {closureVerifyPublicationHandoffSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationHandoffSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationHandoffSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Handoff state</dt><dd>{closureVerifyPublicationHandoffSubmitState.result.handoffState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationHandoffSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication acknowledgment</h3>
      <form onSubmit={submitClosureVerifyPublicationAcknowledgment}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-acknowledgment-reference">Verification publication acknowledgment reference</label>
          <input id="closure-verify-publication-acknowledgment-reference" value={closureVerifyPublicationAcknowledgmentForm.verificationPublicationAcknowledgmentReference} onChange={updateClosureVerifyPublicationAcknowledgment("verificationPublicationAcknowledgmentReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-acknowledged-by-reference">Verification publication acknowledgment acknowledged by reference</label>
          <input id="closure-verify-publication-acknowledged-by-reference" value={closureVerifyPublicationAcknowledgmentForm.acknowledgedByReference} onChange={updateClosureVerifyPublicationAcknowledgment("acknowledgedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-acknowledgment-timestamp">Verification publication acknowledgment timestamp (RFC3339)</label>
          <input id="closure-verify-publication-acknowledgment-timestamp" value={closureVerifyPublicationAcknowledgmentForm.acknowledgmentTimestamp} onChange={updateClosureVerifyPublicationAcknowledgment("acknowledgmentTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-acknowledgment-manifest-path">Verification publication acknowledgment manifest output path</label>
          <input id="closure-verify-publication-acknowledgment-manifest-path" value={closureVerifyPublicationAcknowledgmentForm.manifestPath} onChange={updateClosureVerifyPublicationAcknowledgment("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-acknowledgment-audit-path">Verification publication acknowledgment audit output path</label>
          <input id="closure-verify-publication-acknowledgment-audit-path" value={closureVerifyPublicationAcknowledgmentForm.auditPath} onChange={updateClosureVerifyPublicationAcknowledgment("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationAcknowledgmentSubmitState.loading || !canExportClosureVerifyPublicationAcknowledgment}>
          {closureVerifyPublicationAcknowledgmentSubmitState.loading ? "Exporting verification publication acknowledgment..." : "Export closure verification publication acknowledgment"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationAcknowledgment && <p className="error">Verification publication acknowledgment export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationAcknowledgmentSubmitState.error && <p className="error">Verification publication acknowledgment: blocked ({closureVerifyPublicationAcknowledgmentSubmitState.error})</p>}
      {closureVerifyPublicationAcknowledgmentSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationAcknowledgmentSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationAcknowledgmentSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Acknowledgment state</dt><dd>{closureVerifyPublicationAcknowledgmentSubmitState.result.acknowledgmentState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationAcknowledgmentSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication archive index</h3>
      <form onSubmit={submitClosureVerifyPublicationArchiveIndex}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-index-reference">Verification publication archive index reference</label>
          <input id="closure-verify-publication-archive-index-reference" value={closureVerifyPublicationArchiveIndexForm.verificationPublicationArchiveIndexReference} onChange={updateClosureVerifyPublicationArchiveIndex("verificationPublicationArchiveIndexReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-indexed-by-reference">Verification publication archive indexed by reference</label>
          <input id="closure-verify-publication-archive-indexed-by-reference" value={closureVerifyPublicationArchiveIndexForm.indexedByReference} onChange={updateClosureVerifyPublicationArchiveIndex("indexedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-indexed-timestamp">Verification publication archive indexed timestamp (RFC3339)</label>
          <input id="closure-verify-publication-archive-indexed-timestamp" value={closureVerifyPublicationArchiveIndexForm.indexedTimestamp} onChange={updateClosureVerifyPublicationArchiveIndex("indexedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-index-manifest-path">Verification publication archive index manifest output path</label>
          <input id="closure-verify-publication-archive-index-manifest-path" value={closureVerifyPublicationArchiveIndexForm.manifestPath} onChange={updateClosureVerifyPublicationArchiveIndex("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-index-audit-path">Verification publication archive index audit output path</label>
          <input id="closure-verify-publication-archive-index-audit-path" value={closureVerifyPublicationArchiveIndexForm.auditPath} onChange={updateClosureVerifyPublicationArchiveIndex("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationArchiveIndexSubmitState.loading || !canExportClosureVerifyPublicationArchiveIndex}>
          {closureVerifyPublicationArchiveIndexSubmitState.loading ? "Exporting verification publication archive index..." : "Export closure verification publication archive index"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationArchiveIndex && <p className="error">Verification publication archive index export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationArchiveIndexSubmitState.error && <p className="error">Verification publication archive index: blocked ({closureVerifyPublicationArchiveIndexSubmitState.error})</p>}
      {closureVerifyPublicationArchiveIndexSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationArchiveIndexSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationArchiveIndexSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Archive index state</dt><dd>{closureVerifyPublicationArchiveIndexSubmitState.result.archiveIndexState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationArchiveIndexSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication archive package</h3>
      <form onSubmit={submitClosureVerifyPublicationArchivePackage}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-package-reference">Verification publication archive package reference</label>
          <input id="closure-verify-publication-archive-package-reference" value={closureVerifyPublicationArchivePackageForm.verificationPublicationArchivePackageReference} onChange={updateClosureVerifyPublicationArchivePackage("verificationPublicationArchivePackageReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-packaged-by-reference">Verification publication archive packaged by reference</label>
          <input id="closure-verify-publication-archive-packaged-by-reference" value={closureVerifyPublicationArchivePackageForm.packagedByReference} onChange={updateClosureVerifyPublicationArchivePackage("packagedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-packaged-timestamp">Verification publication archive packaged timestamp (RFC3339)</label>
          <input id="closure-verify-publication-archive-packaged-timestamp" value={closureVerifyPublicationArchivePackageForm.packagedTimestamp} onChange={updateClosureVerifyPublicationArchivePackage("packagedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-package-manifest-path">Verification publication archive package manifest output path</label>
          <input id="closure-verify-publication-archive-package-manifest-path" value={closureVerifyPublicationArchivePackageForm.manifestPath} onChange={updateClosureVerifyPublicationArchivePackage("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-package-audit-path">Verification publication archive package audit output path</label>
          <input id="closure-verify-publication-archive-package-audit-path" value={closureVerifyPublicationArchivePackageForm.auditPath} onChange={updateClosureVerifyPublicationArchivePackage("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationArchivePackageSubmitState.loading || !canExportClosureVerifyPublicationArchivePackage}>
          {closureVerifyPublicationArchivePackageSubmitState.loading ? "Exporting verification publication archive package..." : "Export closure verification publication archive package"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationArchivePackage && <p className="error">Verification publication archive package export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationArchivePackageSubmitState.error && <p className="error">Verification publication archive package: blocked ({closureVerifyPublicationArchivePackageSubmitState.error})</p>}
      {closureVerifyPublicationArchivePackageSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationArchivePackageSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationArchivePackageSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Archive package state</dt><dd>{closureVerifyPublicationArchivePackageSubmitState.result.archivePackageState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationArchivePackageSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication archive envelope</h3>
      <form onSubmit={submitClosureVerifyPublicationArchiveEnvelope}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-envelope-reference">Verification publication archive envelope reference</label>
          <input id="closure-verify-publication-archive-envelope-reference" value={closureVerifyPublicationArchiveEnvelopeForm.verificationPublicationArchiveEnvelopeReference} onChange={updateClosureVerifyPublicationArchiveEnvelope("verificationPublicationArchiveEnvelopeReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-envelope-delivered-by-reference">Verification publication archive envelope delivered by reference</label>
          <input id="closure-verify-publication-archive-envelope-delivered-by-reference" value={closureVerifyPublicationArchiveEnvelopeForm.deliveredByReference} onChange={updateClosureVerifyPublicationArchiveEnvelope("deliveredByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-envelope-delivery-timestamp">Verification publication archive envelope delivery timestamp (RFC3339)</label>
          <input id="closure-verify-publication-archive-envelope-delivery-timestamp" value={closureVerifyPublicationArchiveEnvelopeForm.deliveryTimestamp} onChange={updateClosureVerifyPublicationArchiveEnvelope("deliveryTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-envelope-destination-reference">Verification publication archive envelope destination reference</label>
          <input id="closure-verify-publication-archive-envelope-destination-reference" value={closureVerifyPublicationArchiveEnvelopeForm.deliveryDestinationReference} onChange={updateClosureVerifyPublicationArchiveEnvelope("deliveryDestinationReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-envelope-manifest-path">Verification publication archive envelope manifest output path</label>
          <input id="closure-verify-publication-archive-envelope-manifest-path" value={closureVerifyPublicationArchiveEnvelopeForm.manifestPath} onChange={updateClosureVerifyPublicationArchiveEnvelope("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-envelope-audit-path">Verification publication archive envelope audit output path</label>
          <input id="closure-verify-publication-archive-envelope-audit-path" value={closureVerifyPublicationArchiveEnvelopeForm.auditPath} onChange={updateClosureVerifyPublicationArchiveEnvelope("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationArchiveEnvelopeSubmitState.loading || !canExportClosureVerifyPublicationArchiveEnvelope}>
          {closureVerifyPublicationArchiveEnvelopeSubmitState.loading ? "Exporting verification publication archive envelope..." : "Export closure verification publication archive envelope"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationArchiveEnvelope && <p className="error">Verification publication archive envelope export requires references, destination, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationArchiveEnvelopeSubmitState.error && <p className="error">Verification publication archive envelope: blocked ({closureVerifyPublicationArchiveEnvelopeSubmitState.error})</p>}
      {closureVerifyPublicationArchiveEnvelopeSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationArchiveEnvelopeSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationArchiveEnvelopeSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Archive envelope state</dt><dd>{closureVerifyPublicationArchiveEnvelopeSubmitState.result.archiveEnvelopeState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationArchiveEnvelopeSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication archive handoff</h3>
      <form onSubmit={submitClosureVerifyPublicationArchiveHandoff}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-handoff-reference">Verification publication archive handoff reference</label>
          <input id="closure-verify-publication-archive-handoff-reference" value={closureVerifyPublicationArchiveHandoffForm.verificationPublicationArchiveHandoffReference} onChange={updateClosureVerifyPublicationArchiveHandoff("verificationPublicationArchiveHandoffReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-handoff-received-by-reference">Verification publication archive handoff received by reference</label>
          <input id="closure-verify-publication-archive-handoff-received-by-reference" value={closureVerifyPublicationArchiveHandoffForm.receivedByReference} onChange={updateClosureVerifyPublicationArchiveHandoff("receivedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-handoff-timestamp">Verification publication archive handoff timestamp (RFC3339)</label>
          <input id="closure-verify-publication-archive-handoff-timestamp" value={closureVerifyPublicationArchiveHandoffForm.handoffTimestamp} onChange={updateClosureVerifyPublicationArchiveHandoff("handoffTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-handoff-manifest-path">Verification publication archive handoff manifest output path</label>
          <input id="closure-verify-publication-archive-handoff-manifest-path" value={closureVerifyPublicationArchiveHandoffForm.manifestPath} onChange={updateClosureVerifyPublicationArchiveHandoff("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-handoff-audit-path">Verification publication archive handoff audit output path</label>
          <input id="closure-verify-publication-archive-handoff-audit-path" value={closureVerifyPublicationArchiveHandoffForm.auditPath} onChange={updateClosureVerifyPublicationArchiveHandoff("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationArchiveHandoffSubmitState.loading || !canExportClosureVerifyPublicationArchiveHandoff}>
          {closureVerifyPublicationArchiveHandoffSubmitState.loading ? "Exporting verification publication archive handoff..." : "Export closure verification publication archive handoff"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationArchiveHandoff && <p className="error">Verification publication archive handoff export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationArchiveHandoffSubmitState.error && <p className="error">Verification publication archive handoff: blocked ({closureVerifyPublicationArchiveHandoffSubmitState.error})</p>}
      {closureVerifyPublicationArchiveHandoffSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationArchiveHandoffSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationArchiveHandoffSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Archive handoff state</dt><dd>{closureVerifyPublicationArchiveHandoffSubmitState.result.archiveHandoffState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationArchiveHandoffSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication archive acknowledgment</h3>
      <form onSubmit={submitClosureVerifyPublicationArchiveAcknowledgment}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-acknowledgment-reference">Verification publication archive acknowledgment reference</label>
          <input id="closure-verify-publication-archive-acknowledgment-reference" value={closureVerifyPublicationArchiveAcknowledgmentForm.verificationPublicationArchiveAcknowledgmentReference} onChange={updateClosureVerifyPublicationArchiveAcknowledgment("verificationPublicationArchiveAcknowledgmentReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-acknowledged-by-reference">Verification publication archive acknowledgment by reference</label>
          <input id="closure-verify-publication-archive-acknowledged-by-reference" value={closureVerifyPublicationArchiveAcknowledgmentForm.acknowledgedByReference} onChange={updateClosureVerifyPublicationArchiveAcknowledgment("acknowledgedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-acknowledgment-timestamp">Verification publication archive acknowledgment timestamp (RFC3339)</label>
          <input id="closure-verify-publication-archive-acknowledgment-timestamp" value={closureVerifyPublicationArchiveAcknowledgmentForm.acknowledgmentTimestamp} onChange={updateClosureVerifyPublicationArchiveAcknowledgment("acknowledgmentTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-acknowledgment-manifest-path">Verification publication archive acknowledgment manifest output path</label>
          <input id="closure-verify-publication-archive-acknowledgment-manifest-path" value={closureVerifyPublicationArchiveAcknowledgmentForm.manifestPath} onChange={updateClosureVerifyPublicationArchiveAcknowledgment("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-acknowledgment-audit-path">Verification publication archive acknowledgment audit output path</label>
          <input id="closure-verify-publication-archive-acknowledgment-audit-path" value={closureVerifyPublicationArchiveAcknowledgmentForm.auditPath} onChange={updateClosureVerifyPublicationArchiveAcknowledgment("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationArchiveAcknowledgmentSubmitState.loading || !canExportClosureVerifyPublicationArchiveAcknowledgment}>
          {closureVerifyPublicationArchiveAcknowledgmentSubmitState.loading ? "Exporting verification publication archive acknowledgment..." : "Export closure verification publication archive acknowledgment"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationArchiveAcknowledgment && <p className="error">Verification publication archive acknowledgment export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationArchiveAcknowledgmentSubmitState.error && <p className="error">Verification publication archive acknowledgment: blocked ({closureVerifyPublicationArchiveAcknowledgmentSubmitState.error})</p>}
      {closureVerifyPublicationArchiveAcknowledgmentSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationArchiveAcknowledgmentSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationArchiveAcknowledgmentSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Archive acknowledgment state</dt><dd>{closureVerifyPublicationArchiveAcknowledgmentSubmitState.result.archiveAcknowledgmentState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationArchiveAcknowledgmentSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export closure verification publication archive attestation</h3>
      <form onSubmit={submitClosureVerifyPublicationArchiveAttestation}>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-attestation-reference">Verification publication archive attestation reference</label>
          <input id="closure-verify-publication-archive-attestation-reference" value={closureVerifyPublicationArchiveAttestationForm.verificationPublicationArchiveAttestationReference} onChange={updateClosureVerifyPublicationArchiveAttestation("verificationPublicationArchiveAttestationReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-attested-by-reference">Verification publication archive attested by reference</label>
          <input id="closure-verify-publication-archive-attested-by-reference" value={closureVerifyPublicationArchiveAttestationForm.attestedByReference} onChange={updateClosureVerifyPublicationArchiveAttestation("attestedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-attestation-timestamp">Verification publication archive attestation timestamp (RFC3339)</label>
          <input id="closure-verify-publication-archive-attestation-timestamp" value={closureVerifyPublicationArchiveAttestationForm.attestationTimestamp} onChange={updateClosureVerifyPublicationArchiveAttestation("attestationTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-attestation-manifest-path">Verification publication archive attestation manifest output path</label>
          <input id="closure-verify-publication-archive-attestation-manifest-path" value={closureVerifyPublicationArchiveAttestationForm.manifestPath} onChange={updateClosureVerifyPublicationArchiveAttestation("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-verify-publication-archive-attestation-audit-path">Verification publication archive attestation audit output path</label>
          <input id="closure-verify-publication-archive-attestation-audit-path" value={closureVerifyPublicationArchiveAttestationForm.auditPath} onChange={updateClosureVerifyPublicationArchiveAttestation("auditPath")} />
        </div>
        <button type="submit" disabled={closureVerifyPublicationArchiveAttestationSubmitState.loading || !canExportClosureVerifyPublicationArchiveAttestation}>
          {closureVerifyPublicationArchiveAttestationSubmitState.loading ? "Exporting verification publication archive attestation..." : "Export closure verification publication archive attestation"}
        </button>
      </form>
      {!canExportClosureVerifyPublicationArchiveAttestation && <p className="error">Verification publication archive attestation export requires references, timestamp, and distinct manifest/audit paths.</p>}
      {closureVerifyPublicationArchiveAttestationSubmitState.error && <p className="error">Verification publication archive attestation: blocked ({closureVerifyPublicationArchiveAttestationSubmitState.error})</p>}
      {closureVerifyPublicationArchiveAttestationSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureVerifyPublicationArchiveAttestationSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureVerifyPublicationArchiveAttestationSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Archive attestation state</dt><dd>{closureVerifyPublicationArchiveAttestationSubmitState.result.archiveAttestationState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureVerifyPublicationArchiveAttestationSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export capsule snapshot</h3>
      <form onSubmit={submit}>
        <div className="formRow">
          <label htmlFor="capsule-markdown-path">Markdown output path</label>
          <input id="capsule-markdown-path" value={form.markdownPath} onChange={update("markdownPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="capsule-json-path">JSON output path</label>
          <input id="capsule-json-path" value={form.jsonPath} onChange={update("jsonPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="capsule-audit-path">Audit output path</label>
          <input id="capsule-audit-path" value={form.auditPath} onChange={update("auditPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="capsule-allow-blocked">Allow blocked archival</label>
          <input id="capsule-allow-blocked" type="checkbox" checked={form.allowBlocked} onChange={update("allowBlocked")} />
        </div>
        <div className="formRow">
          <label htmlFor="capsule-blocked-reason">Blocked archival reason reference</label>
          <input id="capsule-blocked-reason" value={form.allowBlockedReasonReference} onChange={update("allowBlockedReasonReference")} />
        </div>
        <button type="submit" disabled={submitState.loading || !canExport}>
          {submitState.loading ? "Exporting capsule..." : "Export capsule"}
        </button>
      </form>
      {!canExport && <p className="error">Capsule export requires distinct output paths and a reason reference when blocked archival is enabled.</p>}
      {submitState.error && <p className="error">Error: {submitState.error}</p>}
      {submitState.result && (
        <dl className="grid">
          <div><dt>Markdown path</dt><dd>{submitState.result.markdownPath || "n/a"}</dd></div>
          <div><dt>JSON path</dt><dd>{submitState.result.jsonPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{submitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Ready snapshot</dt><dd>{String(Boolean(submitState.result.ready))}</dd></div>
          <div><dt>Blocked archival</dt><dd>{String(Boolean(submitState.result.blockedArchival))}</dd></div>
          <div><dt>Blocker count</dt><dd>{String(submitState.result.blockerCount ?? 0)}</dd></div>
        </dl>
      )}
      <h3>Export evidence bundle</h3>
      <form onSubmit={submitBundle}>
        <div className="formRow">
          <label htmlFor="evidence-bundle-manifest-path">Manifest output path</label>
          <input id="evidence-bundle-manifest-path" value={bundleForm.manifestPath} onChange={updateBundle("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="evidence-bundle-audit-path">Audit output path</label>
          <input id="evidence-bundle-audit-path" value={bundleForm.auditPath} onChange={updateBundle("auditPath")} />
        </div>
        <button type="submit" disabled={bundleSubmitState.loading || !canExportBundle}>
          {bundleSubmitState.loading ? "Exporting evidence bundle..." : "Export evidence bundle"}
        </button>
      </form>
      {!canExportBundle && <p className="error">Evidence bundle export requires distinct manifest and audit paths.</p>}
      {bundleSubmitState.error && <p className="error">Error: {bundleSubmitState.error}</p>}
      {bundleSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{bundleSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{bundleSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Runbook exports</dt><dd>{String(bundleSubmitState.result.runbookExportCount ?? 0)}</dd></div>
          <div><dt>Capsule exports</dt><dd>{String(bundleSubmitState.result.capsuleExportCount ?? 0)}</dd></div>
        </dl>
      )}
      <h3>Export receipt timeline</h3>
      <form onSubmit={submitTimeline}>
        <div className="formRow">
          <label htmlFor="receipt-timeline-markdown-path">Markdown output path</label>
          <input id="receipt-timeline-markdown-path" value={timelineForm.markdownPath} onChange={updateTimeline("markdownPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="receipt-timeline-json-path">JSON output path</label>
          <input id="receipt-timeline-json-path" value={timelineForm.jsonPath} onChange={updateTimeline("jsonPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="receipt-timeline-audit-path">Audit output path</label>
          <input id="receipt-timeline-audit-path" value={timelineForm.auditPath} onChange={updateTimeline("auditPath")} />
        </div>
        <button type="submit" disabled={timelineSubmitState.loading || !canExportTimeline}>
          {timelineSubmitState.loading ? "Exporting receipt timeline..." : "Export receipt timeline"}
        </button>
      </form>
      {!canExportTimeline && <p className="error">Receipt timeline export requires distinct markdown/json/audit paths.</p>}
      {timelineSubmitState.error && <p className="error">Error: {timelineSubmitState.error}</p>}
      {timelineSubmitState.result && (
        <dl className="grid">
          <div><dt>Markdown path</dt><dd>{timelineSubmitState.result.markdownPath || "n/a"}</dd></div>
          <div><dt>JSON path</dt><dd>{timelineSubmitState.result.jsonPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{timelineSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Receipt count</dt><dd>{String(timelineSubmitState.result.receiptCount ?? 0)}</dd></div>
        </dl>
      )}
      <h3>Export closure package</h3>
      <form onSubmit={submitClosure}>
        <div className="formRow">
          <label htmlFor="closure-package-manifest-path">Manifest output path</label>
          <input id="closure-package-manifest-path" value={closureForm.manifestPath} onChange={updateClosure("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-package-audit-path">Audit output path</label>
          <input id="closure-package-audit-path" value={closureForm.auditPath} onChange={updateClosure("auditPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-package-reference">Release readiness reference</label>
          <input id="closure-package-reference" value={closureForm.releaseReadinessReference} onChange={updateClosure("releaseReadinessReference")} />
        </div>
        <button type="submit" disabled={closureSubmitState.loading || !canExportClosure}>
          {closureSubmitState.loading ? "Exporting closure package..." : "Export closure package"}
        </button>
      </form>
      {!canExportClosure && <p className="error">Closure package export requires distinct manifest/audit paths and a release readiness reference.</p>}
      {closureSubmitState.error && <p className="error">Error: {closureSubmitState.error}</p>}
      {closureSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Evidence bundles</dt><dd>{String(closureSubmitState.result.evidenceBundleCount ?? 0)}</dd></div>
          <div><dt>Receipt timelines</dt><dd>{String(closureSubmitState.result.receiptTimelineCount ?? 0)}</dd></div>
        </dl>
      )}
      <h3>Export closure review gate</h3>
      <form onSubmit={submitReviewGate}>
        <div className="formRow">
          <label htmlFor="review-gate-release-reference">Review gate release readiness reference</label>
          <input id="review-gate-release-reference" value={reviewGateForm.releaseReadinessReference} onChange={updateReviewGate("releaseReadinessReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="review-gate-reviewer-reference">Reviewer reference</label>
          <input id="review-gate-reviewer-reference" value={reviewGateForm.reviewerReference} onChange={updateReviewGate("reviewerReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="review-gate-decision">Decision</label>
          <select id="review-gate-decision" value={reviewGateForm.decision} onChange={updateReviewGate("decision")}>
            <option value="approved">approved</option>
            <option value="blocked">blocked</option>
          </select>
        </div>
        <div className="formRow">
          <label htmlFor="review-gate-markdown-path">Markdown output path</label>
          <input id="review-gate-markdown-path" value={reviewGateForm.markdownPath} onChange={updateReviewGate("markdownPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="review-gate-json-path">JSON output path</label>
          <input id="review-gate-json-path" value={reviewGateForm.jsonPath} onChange={updateReviewGate("jsonPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="review-gate-audit-path">Audit output path</label>
          <input id="review-gate-audit-path" value={reviewGateForm.auditPath} onChange={updateReviewGate("auditPath")} />
        </div>
        <button type="submit" disabled={reviewGateSubmitState.loading || !canExportReviewGate}>
          {reviewGateSubmitState.loading ? "Exporting closure review gate..." : "Export closure review gate"}
        </button>
      </form>
      {!canExportReviewGate && <p className="error">Closure review gate export requires references plus distinct markdown/json/audit paths.</p>}
      {reviewGateSubmitState.error && <p className="error">Error: {reviewGateSubmitState.error}</p>}
      {reviewGateSubmitState.result && (
        <dl className="grid">
          <div><dt>Markdown path</dt><dd>{reviewGateSubmitState.result.markdownPath || "n/a"}</dd></div>
          <div><dt>JSON path</dt><dd>{reviewGateSubmitState.result.jsonPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{reviewGateSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Outcome</dt><dd>{reviewGateSubmitState.result.outcome || "n/a"}</dd></div>
        </dl>
      )}
      <h3>Export release decision ledger</h3>
      <form onSubmit={submitReleaseDecision}>
        <div className="formRow">
          <label htmlFor="release-decision-release-reference">Release decision release readiness reference</label>
          <input id="release-decision-release-reference" value={releaseDecisionForm.releaseReadinessReference} onChange={updateReleaseDecision("releaseReadinessReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="release-decision-reviewer-reference">Release decision reviewer reference</label>
          <input id="release-decision-reviewer-reference" value={releaseDecisionForm.reviewerReference} onChange={updateReleaseDecision("reviewerReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="release-decision-value">Decision</label>
          <select id="release-decision-value" value={releaseDecisionForm.decision} onChange={updateReleaseDecision("decision")}>
            <option value="approved">approved</option>
            <option value="blocked">blocked</option>
          </select>
        </div>
        <div className="formRow">
          <label htmlFor="release-decision-operator-reference">Release decision operator reference</label>
          <input id="release-decision-operator-reference" value={releaseDecisionForm.operatorReference} onChange={updateReleaseDecision("operatorReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="release-decision-timestamp">Decision timestamp (RFC3339)</label>
          <input id="release-decision-timestamp" value={releaseDecisionForm.decisionTimestamp} onChange={updateReleaseDecision("decisionTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="release-decision-ledger-path">Ledger output path</label>
          <input id="release-decision-ledger-path" value={releaseDecisionForm.ledgerPath} onChange={updateReleaseDecision("ledgerPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="release-decision-audit-path">Audit output path</label>
          <input id="release-decision-audit-path" value={releaseDecisionForm.auditPath} onChange={updateReleaseDecision("auditPath")} />
        </div>
        <button type="submit" disabled={releaseDecisionSubmitState.loading || !canExportReleaseDecision}>
          {releaseDecisionSubmitState.loading ? "Exporting release decision..." : "Export release decision"}
        </button>
      </form>
      {!canExportReleaseDecision && <p className="error">Release decision export requires references, timestamp, and distinct ledger/audit paths.</p>}
      {releaseDecisionSubmitState.error && <p className="error">Error: {releaseDecisionSubmitState.error}</p>}
      {releaseDecisionSubmitState.result && (
        <dl className="grid">
          <div><dt>Ledger path</dt><dd>{releaseDecisionSubmitState.result.ledgerPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{releaseDecisionSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Publication state</dt><dd>{releaseDecisionSubmitState.result.publicationState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{releaseDecisionSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export release publication attestation</h3>
      <form onSubmit={submitReleasePublication}>
        <div className="formRow">
          <label htmlFor="release-publication-channel">Publication channel</label>
          <input id="release-publication-channel" value={releasePublicationForm.publicationChannel} onChange={updateReleasePublication("publicationChannel")} />
        </div>
        <div className="formRow">
          <label htmlFor="release-publication-artifact-reference">Artifact location reference</label>
          <input id="release-publication-artifact-reference" value={releasePublicationForm.artifactLocationReference} onChange={updateReleasePublication("artifactLocationReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="release-publication-timestamp">Publication timestamp (RFC3339)</label>
          <input id="release-publication-timestamp" value={releasePublicationForm.publicationTimestamp} onChange={updateReleasePublication("publicationTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="release-publication-operator-reference">Publication operator reference</label>
          <input id="release-publication-operator-reference" value={releasePublicationForm.operatorReference} onChange={updateReleasePublication("operatorReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="release-publication-attestation-path">Attestation output path</label>
          <input id="release-publication-attestation-path" value={releasePublicationForm.attestationPath} onChange={updateReleasePublication("attestationPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="release-publication-audit-path">Audit output path</label>
          <input id="release-publication-audit-path" value={releasePublicationForm.auditPath} onChange={updateReleasePublication("auditPath")} />
        </div>
        <button type="submit" disabled={releasePublicationSubmitState.loading || !canExportReleasePublication}>
          {releasePublicationSubmitState.loading ? "Exporting release publication..." : "Export release publication"}
        </button>
      </form>
      {!canExportReleasePublication && <p className="error">Release publication export requires channel, artifact reference, timestamp, operator reference, and distinct attestation/audit paths.</p>}
      {releasePublicationSubmitState.error && <p className="error">Publication readiness: blocked ({releasePublicationSubmitState.error})</p>}
      {releasePublicationSubmitState.result && (
        <dl className="grid">
          <div><dt>Attestation path</dt><dd>{releasePublicationSubmitState.result.attestationPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{releasePublicationSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Publication readiness</dt><dd>{releasePublicationSubmitState.result.publicationState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{releasePublicationSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export release publication index</h3>
      <form onSubmit={submitPublicationIndex}>
        <div className="formRow">
          <label htmlFor="publication-index-batch-reference">Publication batch reference</label>
          <input id="publication-index-batch-reference" value={publicationIndexForm.publicationBatchReference} onChange={updatePublicationIndex("publicationBatchReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-index-operator-reference">Publication index operator reference</label>
          <input id="publication-index-operator-reference" value={publicationIndexForm.operatorReference} onChange={updatePublicationIndex("operatorReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-index-manifest-path">Manifest output path</label>
          <input id="publication-index-manifest-path" value={publicationIndexForm.manifestPath} onChange={updatePublicationIndex("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-index-audit-path">Audit output path</label>
          <input id="publication-index-audit-path" value={publicationIndexForm.auditPath} onChange={updatePublicationIndex("auditPath")} />
        </div>
        <button type="submit" disabled={publicationIndexSubmitState.loading || !canExportPublicationIndex}>
          {publicationIndexSubmitState.loading ? "Exporting publication index..." : "Export publication index"}
        </button>
      </form>
      {!canExportPublicationIndex && <p className="error">Publication index export requires batch reference, operator reference, and distinct manifest/audit paths.</p>}
      {publicationIndexSubmitState.error && <p className="error">Index readiness: blocked ({publicationIndexSubmitState.error})</p>}
      {publicationIndexSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{publicationIndexSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{publicationIndexSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Index readiness</dt><dd>{publicationIndexSubmitState.result.indexState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{publicationIndexSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export release publication package</h3>
      <form onSubmit={submitPublicationPackage}>
        <div className="formRow">
          <label htmlFor="publication-package-reference">Package reference</label>
          <input id="publication-package-reference" value={publicationPackageForm.packageReference} onChange={updatePublicationPackage("packageReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-package-window-reference">Publication window reference</label>
          <input id="publication-package-window-reference" value={publicationPackageForm.publicationWindowReference} onChange={updatePublicationPackage("publicationWindowReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-package-operator-reference">Publication package operator reference</label>
          <input id="publication-package-operator-reference" value={publicationPackageForm.operatorReference} onChange={updatePublicationPackage("operatorReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-package-manifest-path">Manifest output path</label>
          <input id="publication-package-manifest-path" value={publicationPackageForm.manifestPath} onChange={updatePublicationPackage("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-package-audit-path">Audit output path</label>
          <input id="publication-package-audit-path" value={publicationPackageForm.auditPath} onChange={updatePublicationPackage("auditPath")} />
        </div>
        <button type="submit" disabled={publicationPackageSubmitState.loading || !canExportPublicationPackage}>
          {publicationPackageSubmitState.loading ? "Exporting publication package..." : "Export publication package"}
        </button>
      </form>
      {!canExportPublicationPackage && <p className="error">Publication package export requires package reference, publication window reference, operator reference, and distinct manifest/audit paths.</p>}
      {publicationPackageSubmitState.error && <p className="error">Package readiness: blocked ({publicationPackageSubmitState.error})</p>}
      {publicationPackageSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{publicationPackageSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{publicationPackageSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Package readiness</dt><dd>{publicationPackageSubmitState.result.packageState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{publicationPackageSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export release publication delivery envelope</h3>
      <form onSubmit={submitPublicationEnvelope}>
        <div className="formRow">
          <label htmlFor="publication-envelope-delivery-reference">Delivery reference</label>
          <input id="publication-envelope-delivery-reference" value={publicationEnvelopeForm.deliveryReference} onChange={updatePublicationEnvelope("deliveryReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-envelope-destination-reference">Destination reference</label>
          <input id="publication-envelope-destination-reference" value={publicationEnvelopeForm.destinationReference} onChange={updatePublicationEnvelope("destinationReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-envelope-operator-reference">Delivery envelope operator reference</label>
          <input id="publication-envelope-operator-reference" value={publicationEnvelopeForm.operatorReference} onChange={updatePublicationEnvelope("operatorReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-envelope-manifest-path">Manifest output path</label>
          <input id="publication-envelope-manifest-path" value={publicationEnvelopeForm.manifestPath} onChange={updatePublicationEnvelope("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="publication-envelope-audit-path">Audit output path</label>
          <input id="publication-envelope-audit-path" value={publicationEnvelopeForm.auditPath} onChange={updatePublicationEnvelope("auditPath")} />
        </div>
        <button type="submit" disabled={publicationEnvelopeSubmitState.loading || !canExportPublicationEnvelope}>
          {publicationEnvelopeSubmitState.loading ? "Exporting delivery envelope..." : "Export delivery envelope"}
        </button>
      </form>
      {!canExportPublicationEnvelope && <p className="error">Delivery envelope export requires delivery reference, destination reference, operator reference, and distinct manifest/audit paths.</p>}
      {publicationEnvelopeSubmitState.error && <p className="error">Delivery readiness: blocked ({publicationEnvelopeSubmitState.error})</p>}
      {publicationEnvelopeSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{publicationEnvelopeSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{publicationEnvelopeSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Delivery readiness</dt><dd>{publicationEnvelopeSubmitState.result.deliveryState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{publicationEnvelopeSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export release publication handoff receipt</h3>
      <form onSubmit={submitHandoffReceipt}>
        <div className="formRow">
          <label htmlFor="handoff-receiver-reference">Receiver reference</label>
          <input id="handoff-receiver-reference" value={handoffReceiptForm.receiverReference} onChange={updateHandoffReceipt("receiverReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="handoff-timestamp">Handoff timestamp (RFC3339)</label>
          <input id="handoff-timestamp" value={handoffReceiptForm.handoffTimestamp} onChange={updateHandoffReceipt("handoffTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="handoff-operator-reference">Handoff operator reference</label>
          <input id="handoff-operator-reference" value={handoffReceiptForm.operatorReference} onChange={updateHandoffReceipt("operatorReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="handoff-receipt-path">Receipt output path</label>
          <input id="handoff-receipt-path" value={handoffReceiptForm.receiptPath} onChange={updateHandoffReceipt("receiptPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="handoff-audit-path">Audit output path</label>
          <input id="handoff-audit-path" value={handoffReceiptForm.auditPath} onChange={updateHandoffReceipt("auditPath")} />
        </div>
        <button type="submit" disabled={handoffReceiptSubmitState.loading || !canExportHandoffReceipt}>
          {handoffReceiptSubmitState.loading ? "Exporting handoff receipt..." : "Export handoff receipt"}
        </button>
      </form>
      {!canExportHandoffReceipt && <p className="error">Handoff receipt export requires receiver reference, handoff timestamp, operator reference, and distinct receipt/audit paths.</p>}
      {handoffReceiptSubmitState.error && <p className="error">Handoff readiness: blocked ({handoffReceiptSubmitState.error})</p>}
      {handoffReceiptSubmitState.result && (
        <dl className="grid">
          <div><dt>Receipt path</dt><dd>{handoffReceiptSubmitState.result.receiptPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{handoffReceiptSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Handoff readiness</dt><dd>{handoffReceiptSubmitState.result.handoffState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{handoffReceiptSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export release publication acknowledgment</h3>
      <form onSubmit={submitAcknowledgment}>
        <div className="formRow">
          <label htmlFor="ack-reference">Acknowledgment reference</label>
          <input id="ack-reference" value={acknowledgmentForm.acknowledgmentReference} onChange={updateAcknowledgment("acknowledgmentReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="ack-by-reference">Acknowledged by reference</label>
          <input id="ack-by-reference" value={acknowledgmentForm.acknowledgedByReference} onChange={updateAcknowledgment("acknowledgedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="ack-timestamp">Acknowledgment timestamp (RFC3339)</label>
          <input id="ack-timestamp" value={acknowledgmentForm.acknowledgmentTimestamp} onChange={updateAcknowledgment("acknowledgmentTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="ack-manifest-path">Manifest output path</label>
          <input id="ack-manifest-path" value={acknowledgmentForm.manifestPath} onChange={updateAcknowledgment("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="ack-audit-path">Audit output path</label>
          <input id="ack-audit-path" value={acknowledgmentForm.auditPath} onChange={updateAcknowledgment("auditPath")} />
        </div>
        <button type="submit" disabled={acknowledgmentSubmitState.loading || !canExportAcknowledgment}>
          {acknowledgmentSubmitState.loading ? "Exporting acknowledgment..." : "Export acknowledgment"}
        </button>
      </form>
      {!canExportAcknowledgment && <p className="error">Acknowledgment export requires acknowledgment reference, acknowledged-by reference, timestamp, and distinct manifest/audit paths.</p>}
      {acknowledgmentSubmitState.error && <p className="error">Acknowledgment readiness: blocked ({acknowledgmentSubmitState.error})</p>}
      {acknowledgmentSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{acknowledgmentSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{acknowledgmentSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Acknowledgment readiness</dt><dd>{acknowledgmentSubmitState.result.acknowledgmentState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{acknowledgmentSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export rollout closure summary</h3>
      <form onSubmit={submitClosureSummary}>
        <div className="formRow">
          <label htmlFor="closure-summary-reference">Summary reference</label>
          <input id="closure-summary-reference" value={closureSummaryForm.summaryReference} onChange={updateClosureSummary("summaryReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-summary-operator-reference">Summary operator reference</label>
          <input id="closure-summary-operator-reference" value={closureSummaryForm.operatorReference} onChange={updateClosureSummary("operatorReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-summary-timestamp">Summary timestamp (RFC3339)</label>
          <input id="closure-summary-timestamp" value={closureSummaryForm.summaryTimestamp} onChange={updateClosureSummary("summaryTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-summary-manifest-path">Manifest output path</label>
          <input id="closure-summary-manifest-path" value={closureSummaryForm.manifestPath} onChange={updateClosureSummary("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-summary-audit-path">Audit output path</label>
          <input id="closure-summary-audit-path" value={closureSummaryForm.auditPath} onChange={updateClosureSummary("auditPath")} />
        </div>
        <button type="submit" disabled={closureSummarySubmitState.loading || !canExportClosureSummary}>
          {closureSummarySubmitState.loading ? "Exporting closure summary..." : "Export closure summary"}
        </button>
      </form>
      {!canExportClosureSummary && <p className="error">Closure summary export requires summary reference, operator reference, timestamp, and distinct manifest/audit paths.</p>}
      {closureSummarySubmitState.error && <p className="error">Summary readiness: blocked ({closureSummarySubmitState.error})</p>}
      {closureSummarySubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureSummarySubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureSummarySubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Summary readiness</dt><dd>{closureSummarySubmitState.result.summaryState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureSummarySubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export rollout closure delivery record</h3>
      <form onSubmit={submitClosureDelivery}>
        <div className="formRow">
          <label htmlFor="closure-delivery-reference">Delivery record reference</label>
          <input id="closure-delivery-reference" value={closureDeliveryForm.deliveryReference} onChange={updateClosureDelivery("deliveryReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-delivery-destination-reference">Delivery record destination reference</label>
          <input id="closure-delivery-destination-reference" value={closureDeliveryForm.destinationReference} onChange={updateClosureDelivery("destinationReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-delivery-operator-reference">Delivery operator reference</label>
          <input id="closure-delivery-operator-reference" value={closureDeliveryForm.operatorReference} onChange={updateClosureDelivery("operatorReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-delivery-timestamp">Delivery timestamp (RFC3339)</label>
          <input id="closure-delivery-timestamp" value={closureDeliveryForm.deliveryTimestamp} onChange={updateClosureDelivery("deliveryTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-delivery-manifest-path">Manifest output path</label>
          <input id="closure-delivery-manifest-path" value={closureDeliveryForm.manifestPath} onChange={updateClosureDelivery("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-delivery-audit-path">Audit output path</label>
          <input id="closure-delivery-audit-path" value={closureDeliveryForm.auditPath} onChange={updateClosureDelivery("auditPath")} />
        </div>
        <button type="submit" disabled={closureDeliverySubmitState.loading || !canExportClosureDelivery}>
          {closureDeliverySubmitState.loading ? "Exporting delivery record..." : "Export delivery record"}
        </button>
      </form>
      {!canExportClosureDelivery && <p className="error">Delivery record export requires delivery reference, destination reference, operator reference, timestamp, and distinct manifest/audit paths.</p>}
      {closureDeliverySubmitState.error && <p className="error">Delivery record readiness: blocked ({closureDeliverySubmitState.error})</p>}
      {closureDeliverySubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureDeliverySubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureDeliverySubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Delivery record readiness</dt><dd>{closureDeliverySubmitState.result.deliveryRecordState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureDeliverySubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export rollout closure acceptance receipt</h3>
      <form onSubmit={submitClosureAcceptance}>
        <div className="formRow">
          <label htmlFor="closure-acceptance-reference">Acceptance reference</label>
          <input id="closure-acceptance-reference" value={closureAcceptanceForm.acceptanceReference} onChange={updateClosureAcceptance("acceptanceReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-acceptance-accepted-by-reference">Accepted by reference</label>
          <input id="closure-acceptance-accepted-by-reference" value={closureAcceptanceForm.acceptedByReference} onChange={updateClosureAcceptance("acceptedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-acceptance-timestamp">Acceptance timestamp (RFC3339)</label>
          <input id="closure-acceptance-timestamp" value={closureAcceptanceForm.acceptanceTimestamp} onChange={updateClosureAcceptance("acceptanceTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-acceptance-manifest-path">Acceptance manifest output path</label>
          <input id="closure-acceptance-manifest-path" value={closureAcceptanceForm.manifestPath} onChange={updateClosureAcceptance("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-acceptance-audit-path">Acceptance audit output path</label>
          <input id="closure-acceptance-audit-path" value={closureAcceptanceForm.auditPath} onChange={updateClosureAcceptance("auditPath")} />
        </div>
        <button type="submit" disabled={closureAcceptanceSubmitState.loading || !canExportClosureAcceptance}>
          {closureAcceptanceSubmitState.loading ? "Exporting acceptance receipt..." : "Export acceptance receipt"}
        </button>
      </form>
      {!canExportClosureAcceptance && <p className="error">Acceptance export requires acceptance reference, accepted-by reference, timestamp, and distinct manifest/audit paths.</p>}
      {closureAcceptanceSubmitState.error && <p className="error">Acceptance readiness: blocked ({closureAcceptanceSubmitState.error})</p>}
      {closureAcceptanceSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureAcceptanceSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureAcceptanceSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Acceptance readiness</dt><dd>{closureAcceptanceSubmitState.result.acceptanceState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureAcceptanceSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export rollout closure publication certificate</h3>
      <form onSubmit={submitClosureCertificate}>
        <div className="formRow">
          <label htmlFor="closure-certificate-reference">Certificate reference</label>
          <input id="closure-certificate-reference" value={closureCertificateForm.certificateReference} onChange={updateClosureCertificate("certificateReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-certificate-issued-by-reference">Issued by reference</label>
          <input id="closure-certificate-issued-by-reference" value={closureCertificateForm.issuedByReference} onChange={updateClosureCertificate("issuedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-certificate-issued-timestamp">Issued timestamp (RFC3339)</label>
          <input id="closure-certificate-issued-timestamp" value={closureCertificateForm.issuedTimestamp} onChange={updateClosureCertificate("issuedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-certificate-manifest-path">Certificate manifest output path</label>
          <input id="closure-certificate-manifest-path" value={closureCertificateForm.manifestPath} onChange={updateClosureCertificate("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-certificate-audit-path">Certificate audit output path</label>
          <input id="closure-certificate-audit-path" value={closureCertificateForm.auditPath} onChange={updateClosureCertificate("auditPath")} />
        </div>
        <button type="submit" disabled={closureCertificateSubmitState.loading || !canExportClosureCertificate}>
          {closureCertificateSubmitState.loading ? "Exporting publication certificate..." : "Export publication certificate"}
        </button>
      </form>
      {!canExportClosureCertificate && <p className="error">Certificate export requires certificate reference, issued-by reference, issued timestamp, and distinct manifest/audit paths.</p>}
      {closureCertificateSubmitState.error && <p className="error">Certificate readiness: blocked ({closureCertificateSubmitState.error})</p>}
      {closureCertificateSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureCertificateSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureCertificateSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Certificate readiness</dt><dd>{closureCertificateSubmitState.result.certificateState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureCertificateSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export rollout closure archival ledger</h3>
      <form onSubmit={submitClosureLedger}>
        <div className="formRow">
          <label htmlFor="closure-ledger-reference">Ledger reference</label>
          <input id="closure-ledger-reference" value={closureLedgerForm.ledgerReference} onChange={updateClosureLedger("ledgerReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-ledger-recorded-by-reference">Recorded by reference</label>
          <input id="closure-ledger-recorded-by-reference" value={closureLedgerForm.recordedByReference} onChange={updateClosureLedger("recordedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-ledger-recorded-timestamp">Recorded timestamp (RFC3339)</label>
          <input id="closure-ledger-recorded-timestamp" value={closureLedgerForm.recordedTimestamp} onChange={updateClosureLedger("recordedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-ledger-manifest-path">Ledger manifest output path</label>
          <input id="closure-ledger-manifest-path" value={closureLedgerForm.manifestPath} onChange={updateClosureLedger("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-ledger-audit-path">Ledger audit output path</label>
          <input id="closure-ledger-audit-path" value={closureLedgerForm.auditPath} onChange={updateClosureLedger("auditPath")} />
        </div>
        <button type="submit" disabled={closureLedgerSubmitState.loading || !canExportClosureLedger}>
          {closureLedgerSubmitState.loading ? "Exporting closure ledger..." : "Export closure ledger"}
        </button>
      </form>
      {!canExportClosureLedger && <p className="error">Ledger export requires ledger reference, recorded-by reference, recorded timestamp, and distinct manifest/audit paths.</p>}
      {closureLedgerSubmitState.error && <p className="error">Ledger readiness: blocked ({closureLedgerSubmitState.error})</p>}
      {closureLedgerSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureLedgerSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureLedgerSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Ledger readiness</dt><dd>{closureLedgerSubmitState.result.ledgerState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureLedgerSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export rollout closure handoff docket</h3>
      <form onSubmit={submitClosureDocket}>
        <div className="formRow">
          <label htmlFor="closure-docket-reference">Docket reference</label>
          <input id="closure-docket-reference" value={closureDocketForm.docketReference} onChange={updateClosureDocket("docketReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-docket-prepared-by-reference">Prepared by reference</label>
          <input id="closure-docket-prepared-by-reference" value={closureDocketForm.preparedByReference} onChange={updateClosureDocket("preparedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-docket-prepared-timestamp">Prepared timestamp (RFC3339)</label>
          <input id="closure-docket-prepared-timestamp" value={closureDocketForm.preparedTimestamp} onChange={updateClosureDocket("preparedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-docket-manifest-path">Docket manifest output path</label>
          <input id="closure-docket-manifest-path" value={closureDocketForm.manifestPath} onChange={updateClosureDocket("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-docket-audit-path">Docket audit output path</label>
          <input id="closure-docket-audit-path" value={closureDocketForm.auditPath} onChange={updateClosureDocket("auditPath")} />
        </div>
        <button type="submit" disabled={closureDocketSubmitState.loading || !canExportClosureDocket}>
          {closureDocketSubmitState.loading ? "Exporting closure docket..." : "Export closure docket"}
        </button>
      </form>
      {!canExportClosureDocket && <p className="error">Docket export requires docket reference, prepared-by reference, prepared timestamp, and distinct manifest/audit paths.</p>}
      {closureDocketSubmitState.error && <p className="error">Docket readiness: blocked ({closureDocketSubmitState.error})</p>}
      {closureDocketSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureDocketSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureDocketSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Docket readiness</dt><dd>{closureDocketSubmitState.result.docketState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureDocketSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export rollout closure release bulletin</h3>
      <form onSubmit={submitClosureBulletin}>
        <div className="formRow">
          <label htmlFor="closure-bulletin-reference">Bulletin reference</label>
          <input id="closure-bulletin-reference" value={closureBulletinForm.bulletinReference} onChange={updateClosureBulletin("bulletinReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-bulletin-published-by-reference">Published by reference</label>
          <input id="closure-bulletin-published-by-reference" value={closureBulletinForm.publishedByReference} onChange={updateClosureBulletin("publishedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-bulletin-published-timestamp">Published timestamp (RFC3339)</label>
          <input id="closure-bulletin-published-timestamp" value={closureBulletinForm.publishedTimestamp} onChange={updateClosureBulletin("publishedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-bulletin-manifest-path">Bulletin manifest output path</label>
          <input id="closure-bulletin-manifest-path" value={closureBulletinForm.manifestPath} onChange={updateClosureBulletin("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-bulletin-audit-path">Bulletin audit output path</label>
          <input id="closure-bulletin-audit-path" value={closureBulletinForm.auditPath} onChange={updateClosureBulletin("auditPath")} />
        </div>
        <button type="submit" disabled={closureBulletinSubmitState.loading || !canExportClosureBulletin}>
          {closureBulletinSubmitState.loading ? "Exporting closure bulletin..." : "Export closure bulletin"}
        </button>
      </form>
      {!canExportClosureBulletin && <p className="error">Bulletin export requires bulletin reference, published-by reference, published timestamp, and distinct manifest/audit paths.</p>}
      {closureBulletinSubmitState.error && <p className="error">Bulletin readiness: blocked ({closureBulletinSubmitState.error})</p>}
      {closureBulletinSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureBulletinSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureBulletinSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Bulletin readiness</dt><dd>{closureBulletinSubmitState.result.bulletinState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureBulletinSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export rollout closure release packet</h3>
      <form onSubmit={submitClosurePacket}>
        <div className="formRow">
          <label htmlFor="closure-packet-reference">Packet reference</label>
          <input id="closure-packet-reference" value={closurePacketForm.packetReference} onChange={updateClosurePacket("packetReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-packet-packaged-by-reference">Packaged by reference</label>
          <input id="closure-packet-packaged-by-reference" value={closurePacketForm.packagedByReference} onChange={updateClosurePacket("packagedByReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-packet-packaged-timestamp">Packaged timestamp (RFC3339)</label>
          <input id="closure-packet-packaged-timestamp" value={closurePacketForm.packagedTimestamp} onChange={updateClosurePacket("packagedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-packet-manifest-path">Packet manifest output path</label>
          <input id="closure-packet-manifest-path" value={closurePacketForm.manifestPath} onChange={updateClosurePacket("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-packet-audit-path">Packet audit output path</label>
          <input id="closure-packet-audit-path" value={closurePacketForm.auditPath} onChange={updateClosurePacket("auditPath")} />
        </div>
        <button type="submit" disabled={closurePacketSubmitState.loading || !canExportClosurePacket}>
          {closurePacketSubmitState.loading ? "Exporting closure packet..." : "Export closure packet"}
        </button>
      </form>
      {!canExportClosurePacket && <p className="error">Packet export requires packet reference, packaged-by reference, packaged timestamp, and distinct manifest/audit paths.</p>}
      {closurePacketSubmitState.error && <p className="error">Packet readiness: blocked ({closurePacketSubmitState.error})</p>}
      {closurePacketSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closurePacketSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closurePacketSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Packet readiness</dt><dd>{closurePacketSubmitState.result.packetState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closurePacketSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
      <h3>Export rollout closure recipient acknowledgment package</h3>
      <form onSubmit={submitClosureRecipientPackage}>
        <div className="formRow">
          <label htmlFor="closure-recipient-package-reference">Recipient package reference</label>
          <input id="closure-recipient-package-reference" value={closureRecipientPackageForm.recipientPackageReference} onChange={updateClosureRecipientPackage("recipientPackageReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-recipient-package-prepared-for-reference">Prepared for reference</label>
          <input id="closure-recipient-package-prepared-for-reference" value={closureRecipientPackageForm.preparedForReference} onChange={updateClosureRecipientPackage("preparedForReference")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-recipient-package-prepared-timestamp">Recipient prepared timestamp (RFC3339)</label>
          <input id="closure-recipient-package-prepared-timestamp" value={closureRecipientPackageForm.preparedTimestamp} onChange={updateClosureRecipientPackage("preparedTimestamp")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-recipient-package-manifest-path">Recipient package manifest output path</label>
          <input id="closure-recipient-package-manifest-path" value={closureRecipientPackageForm.manifestPath} onChange={updateClosureRecipientPackage("manifestPath")} />
        </div>
        <div className="formRow">
          <label htmlFor="closure-recipient-package-audit-path">Recipient package audit output path</label>
          <input id="closure-recipient-package-audit-path" value={closureRecipientPackageForm.auditPath} onChange={updateClosureRecipientPackage("auditPath")} />
        </div>
        <button type="submit" disabled={closureRecipientPackageSubmitState.loading || !canExportClosureRecipientPackage}>
          {closureRecipientPackageSubmitState.loading ? "Exporting recipient package..." : "Export recipient package"}
        </button>
      </form>
      {!canExportClosureRecipientPackage && <p className="error">Recipient package export requires recipient package reference, prepared-for reference, prepared timestamp, and distinct manifest/audit paths.</p>}
      {closureRecipientPackageSubmitState.error && <p className="error">Recipient package readiness: blocked ({closureRecipientPackageSubmitState.error})</p>}
      {closureRecipientPackageSubmitState.result && (
        <dl className="grid">
          <div><dt>Manifest path</dt><dd>{closureRecipientPackageSubmitState.result.manifestPath || "n/a"}</dd></div>
          <div><dt>Audit path</dt><dd>{closureRecipientPackageSubmitState.result.auditPath || "n/a"}</dd></div>
          <div><dt>Recipient package readiness</dt><dd>{closureRecipientPackageSubmitState.result.recipientPackageState || "n/a"}</dd></div>
          <div><dt>Blocker code</dt><dd>{closureRecipientPackageSubmitState.result.blockerCode || "none"}</dd></div>
        </dl>
      )}
    </>
  );
}

function renderView(viewID, payload, extra = {}) {
  if (viewID === "pipeline") {
    return <PipelineView payload={payload} />;
  }
  if (viewID === "plan-create") {
    return <PlanCreateView workspacePayload={payload} onPlanCreated={extra.onPlanCreated || (() => {})} />;
  }
  if (viewID === "render") {
    return <RenderView workspacePayload={payload} onRenderCreated={extra.onRenderCreated || (() => {})} />;
  }
  if (viewID === "preflight") {
    return <PreflightView workspacePayload={payload} onPreflightCreated={extra.onPreflightCreated || (() => {})} />;
  }
  if (viewID === "changeset") {
    return <ChangeSetView workspacePayload={payload} onChangeSetCreated={extra.onChangeSetCreated || (() => {})} />;
  }
  if (viewID === "approval") {
    return <ApprovalView workspacePayload={payload} onApprovalCreated={extra.onApprovalCreated || (() => {})} />;
  }
  if (viewID === "apply") {
    return <AuthorizationApplyView workspacePayload={payload} onApplyCreated={extra.onApplyCreated || (() => {})} />;
  }
  if (viewID === "runbook") {
    return <RunbookView payload={payload} />;
  }
  if (viewID === "capsule") {
    return <CapsuleView payload={payload} />;
  }
  if (viewID === "catalog") {
    return (
      <dl className="grid">
        <div><dt>Digest</dt><dd>{payload.catalog?.digest || "n/a"}</dd></div>
        <div><dt>Version</dt><dd>{payload.catalog?.metadata?.version || "n/a"}</dd></div>
        <div><dt>Assertions</dt><dd>{String(payload.summary?.assertions ?? 0)}</dd></div>
        <div><dt>Components</dt><dd>{String(payload.summary?.components ?? 0)}</dd></div>
      </dl>
    );
  }
  if (viewID === "coverage") {
    const report = payload.report || {};
    return (
      <dl className="grid">
        <div><dt>Report ID</dt><dd>{report.metadata?.reportId || "n/a"}</dd></div>
        <div><dt>Complete</dt><dd>{String(Boolean(report.spec?.complete))}</dd></div>
        <div><dt>Assertions</dt><dd>{String(report.spec?.summary?.assertionCount ?? 0)}</dd></div>
        <div><dt>Ready</dt><dd>{String(report.spec?.summary?.lifecyclePublicationReadyAssertions ?? 0)}</dd></div>
      </dl>
    );
  }
  if (viewID === "drift") {
    return <DriftView driftAssertion={extra.driftAssertion} setDriftAssertion={extra.setDriftAssertion} payload={payload} assertions={extra.assertions || []} />;
  }
  return <LifecycleView lifecycleAssertion={extra.lifecycleAssertion} setLifecycleAssertion={extra.setLifecycleAssertion} payload={payload} assertions={extra.assertions || []} />;
}

export function App() {
  const [activeViewID, setActiveViewID] = useState(views[0].id);
  const [driftAssertion, setDriftAssertion] = useState("");
  const [lifecycleAssertion, setLifecycleAssertion] = useState("");
  const [workspaceRefresh, setWorkspaceRefresh] = useState(0);
  const assertionEndpoint = "/api/v1/assertions";
  const workspaceEndpoint = `/api/v1/workspace?refresh=${workspaceRefresh}`;
  const driftEndpoint = driftAssertion ? `/api/v1/drift-posture?assertion=${encodeURIComponent(driftAssertion)}` : "/api/v1/drift-posture";
  const lifecycleEndpoint = lifecycleAssertion ? `/api/v1/lifecycle-policy?assertion=${encodeURIComponent(lifecycleAssertion)}` : "/api/v1/lifecycle-policy";
  const activeView = useMemo(() => views.find((view) => view.id === activeViewID) || views[0], [activeViewID]);
  const endpoint = activeView.id === "drift" ? driftEndpoint : activeView.id === "lifecycle" ? lifecycleEndpoint : activeView.id === "pipeline" || activeView.id === "plan-create" || activeView.id === "render" || activeView.id === "preflight" || activeView.id === "changeset" || activeView.id === "approval" || activeView.id === "apply" ? workspaceEndpoint : activeView.endpoint;
  const decoder =
    activeView.id === "drift"
      ? decodeDriftPayload
      : activeView.id === "lifecycle"
        ? decodeLifecyclePayload
        : activeView.id === "pipeline" || activeView.id === "plan-create" || activeView.id === "render" || activeView.id === "preflight" || activeView.id === "changeset" || activeView.id === "approval" || activeView.id === "apply"
          ? decodeWorkspacePayload
          : undefined;
  const { loading, payload, error } = useEndpoint(endpoint, decoder);
  const assertionsResponse = useEndpoint(assertionEndpoint);
  const assertionIDs = useMemo(() => {
    const rows = assertionsResponse.payload?.assertions;
    if (!Array.isArray(rows)) {
      return [];
    }
    return rows
      .map((item) => item?.id)
      .filter((item) => typeof item === "string")
      .sort((left, right) => left.localeCompare(right));
  }, [assertionsResponse.payload]);
  return (
    <main>
      <h1>YARA Web UI (Read-only)</h1>
      <nav>
        {views.map((view) => (
          <button key={view.id} type="button" className={view.id === activeViewID ? "active" : ""} onClick={() => setActiveViewID(view.id)}>
            {view.label}
          </button>
        ))}
      </nav>
      <section>
        <h2>{activeView.label}</h2>
        {loading && <p>Loading {activeView.label}...</p>}
        {!loading && error && <p className="error">Error: {error}</p>}
        {!loading &&
          !error &&
          payload &&
          renderView(activeView.id, payload, {
            driftAssertion,
            setDriftAssertion,
            lifecycleAssertion,
            setLifecycleAssertion,
            assertions: assertionIDs,
            onPlanCreated: () => setWorkspaceRefresh((value) => value + 1),
            onRenderCreated: () => setWorkspaceRefresh((value) => value + 1),
            onPreflightCreated: () => setWorkspaceRefresh((value) => value + 1),
            onChangeSetCreated: () => setWorkspaceRefresh((value) => value + 1),
            onApprovalCreated: () => setWorkspaceRefresh((value) => value + 1),
            onApplyCreated: () => setWorkspaceRefresh((value) => value + 1),
          })}
      </section>
    </main>
  );
}
