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
