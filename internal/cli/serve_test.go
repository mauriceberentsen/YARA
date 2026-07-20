package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
)

func TestServeRequiresCatalogAndCoverageReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"serve"}, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input for missing serve flags, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
}

func TestServeAPIEndpoints(t *testing.T) {
	handler := serveHandlerFixture(t, false)
	tests := []struct {
		name string
		path string
	}{
		{name: "catalog", path: "/api/v1/catalog"},
		{name: "assertions", path: "/api/v1/assertions"},
		{name: "coverage", path: "/api/v1/coverage"},
		{name: "drift posture", path: "/api/v1/drift-posture"},
		{name: "lifecycle policy", path: "/api/v1/lifecycle-policy"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, testCase.path, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("expected status 200 for %s, got %d: %s", testCase.path, recorder.Code, recorder.Body.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode %s response: %v", testCase.path, err)
			}
			if valid, ok := payload["valid"].(bool); !ok || !valid {
				t.Fatalf("endpoint %s did not report valid response: %#v", testCase.path, payload)
			}
		})
	}
}

func TestServeDriftPostureSupportsAssertionFilter(t *testing.T) {
	handler := serveHandlerFixture(t, false)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/drift-posture?assertion=compat.vllm-qwen-coder-7b-awq-gb10", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200 for assertion-scoped drift posture, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode assertion-scoped drift posture response: %v", err)
	}
	rows, ok := payload["runtimeDriftPosture"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("unexpected assertion-scoped posture rows: %#v", payload["runtimeDriftPosture"])
	}
	row, _ := rows[0].(map[string]any)
	if row["assertion"] != "compat.vllm-qwen-coder-7b-awq-gb10" || row["auditReference"] == "" {
		t.Fatalf("assertion-scoped drift posture omits expected fields: %#v", row)
	}
}

func TestServeDriftPostureRejectsUnknownAssertionFilter(t *testing.T) {
	handler := serveHandlerFixture(t, false)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/drift-posture?assertion=compat.unknown", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown assertion filter, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-007") {
		t.Fatalf("expected structured unknown assertion error, got %s", recorder.Body.String())
	}
}

func TestServeLifecyclePolicySupportsAssertionFilter(t *testing.T) {
	handler := serveHandlerFixture(t, false)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/lifecycle-policy?assertion=compat.vllm-qwen-coder-7b-awq-gb10", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200 for assertion-scoped lifecycle policy, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode assertion-scoped lifecycle response: %v", err)
	}
	rows, ok := payload["lifecyclePosture"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("unexpected lifecycle posture rows: %#v", payload["lifecyclePosture"])
	}
	row, _ := rows[0].(map[string]any)
	if row["assertion"] != "compat.vllm-qwen-coder-7b-awq-gb10" {
		t.Fatalf("unexpected lifecycle posture assertion: %#v", row)
	}
}

func TestServeLifecyclePolicyRejectsUnknownAssertionFilter(t *testing.T) {
	handler := serveHandlerFixture(t, false)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/lifecycle-policy?assertion=compat.unknown", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown lifecycle assertion filter, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-008") {
		t.Fatalf("expected structured lifecycle filter error, got %s", recorder.Body.String())
	}
}

func TestServeRejectsUnknownRoute(t *testing.T) {
	handler := serveHandlerFixture(t, false)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/unknown", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected not found for unknown route, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-404") {
		t.Fatalf("expected structured not found response, got %s", recorder.Body.String())
	}
}

func TestServeRejectsMutationMethodOnReadOnlyEndpoint(t *testing.T) {
	handler := serveHandlerFixture(t, false)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/catalog", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected not found for unsupported method, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-404") {
		t.Fatalf("expected structured not found response, got %s", recorder.Body.String())
	}
}

func TestServeUIShellRoute(t *testing.T) {
	handler := serveHandlerFixture(t, true)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected ui shell response, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA Web UI") {
		t.Fatalf("ui shell response did not include app title: %s", recorder.Body.String())
	}
}

func serveHandlerFixture(t *testing.T, uiEnabled bool) http.Handler {
	t.Helper()
	temp := t.TempDir()
	coveragePath := filepath.Join(temp, "coverage.yaml")
	coverageAuditPath := filepath.Join(temp, "coverage.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run(catalogCoverageArgs(coveragePath, coverageAuditPath), &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("create coverage report failed: exit=%d stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	report, err := catalogcoverage.Load(coveragePath)
	if err != nil {
		t.Fatalf("load coverage report: %v", err)
	}
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatalf("load catalog snapshot: %v", err)
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatalf("digest catalog snapshot: %v", err)
	}
	handler, err := newServeAPIHandler(snapshot, digest, report, uiEnabled)
	if err != nil {
		t.Fatalf("build serve handler: %v", err)
	}
	return handler
}
