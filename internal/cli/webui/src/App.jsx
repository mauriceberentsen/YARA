import { useEffect, useMemo, useState } from "react";

const views = [
  { id: "catalog", label: "Catalog", endpoint: "/api/v1/catalog" },
  { id: "coverage", label: "Coverage", endpoint: "/api/v1/coverage" },
  { id: "drift", label: "Drift", endpoint: "/api/v1/drift-posture" },
  { id: "lifecycle", label: "Lifecycle", endpoint: "/api/v1/lifecycle-policy" },
];

function useEndpoint(endpoint) {
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
        setState({ loading: false, payload, error: "" });
      })
      .catch((error) => {
        if (error.name === "AbortError") {
          return;
        }
        setState({ loading: false, payload: null, error: error.message || "Request failed" });
      });
    return () => controller.abort();
  }, [endpoint]);
  return state;
}

function renderView(viewID, payload) {
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
    const posture = payload.runtimeDriftPosture || [];
    if (posture.length === 0) {
      return <p className="empty">No runtime drift posture records.</p>;
    }
    return (
      <table>
        <thead>
          <tr><th>Assertion</th><th>Status</th><th>Blocker</th></tr>
        </thead>
        <tbody>
          {posture.map((row) => (
            <tr key={row.assertion}>
              <td>{row.assertion}</td><td>{row.status}</td><td>{row.blocker || "none"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
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
  const activeView = useMemo(() => views.find((view) => view.id === activeViewID) || views[0], [activeViewID]);
  const { loading, payload, error } = useEndpoint(activeView.endpoint);
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
        {!loading && !error && payload && renderView(activeView.id, payload)}
      </section>
    </main>
  );
}
