import { useEffect, useMemo, useState } from "react";

const views = [
  { id: "pipeline", label: "Pipeline", endpoint: "/api/v1/workspace" },
  { id: "plan-create", label: "Plan create", endpoint: "/api/v1/workspace" },
  { id: "render", label: "Render", endpoint: "/api/v1/workspace" },
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
  const endpoint = activeView.id === "drift" ? driftEndpoint : activeView.id === "lifecycle" ? lifecycleEndpoint : activeView.id === "pipeline" || activeView.id === "plan-create" || activeView.id === "render" ? workspaceEndpoint : activeView.endpoint;
  const decoder =
    activeView.id === "drift"
      ? decodeDriftPayload
      : activeView.id === "lifecycle"
        ? decodeLifecyclePayload
        : activeView.id === "pipeline" || activeView.id === "plan-create" || activeView.id === "render"
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
          })}
      </section>
    </main>
  );
}
