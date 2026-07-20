import { useEffect, useMemo, useState } from "react";

const views = [
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

function renderView(viewID, payload, extra = {}) {
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
  const blocked = payload.blockedAssertions || [];
  return (
    <>
      <p>Policy passed: {String(Boolean(payload.lifecyclePublicationPolicy?.policyPassed))}</p>
      {blocked.length === 0 ? (
        <p className="empty">No blocked lifecycle assertions.</p>
      ) : (
        <table>
          <thead>
            <tr><th>Assertion</th><th>Code</th><th>Remediation</th></tr>
          </thead>
          <tbody>
            {blocked.map((row) => (
              <tr key={row.assertion}>
                <td>{row.assertion}</td><td>{row.code || "n/a"}</td><td>{row.remediation || "n/a"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

export function App() {
  const [activeViewID, setActiveViewID] = useState(views[0].id);
  const [driftAssertion, setDriftAssertion] = useState("");
  const assertionEndpoint = "/api/v1/assertions";
  const driftEndpoint = driftAssertion ? `/api/v1/drift-posture?assertion=${encodeURIComponent(driftAssertion)}` : "/api/v1/drift-posture";
  const activeView = useMemo(() => views.find((view) => view.id === activeViewID) || views[0], [activeViewID]);
  const endpoint = activeView.id === "drift" ? driftEndpoint : activeView.endpoint;
  const decoder = activeView.id === "drift" ? decodeDriftPayload : undefined;
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
            assertions: assertionIDs,
          })}
      </section>
    </main>
  );
}
