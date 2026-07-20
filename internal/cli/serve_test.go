package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
	"github.com/mauriceberentsen/YARA/internal/changeset"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/targetpreflight"
)

func TestServeRequiresCatalogAndCoverageReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"serve"}, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input for missing serve flags, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
}

func TestServeRejectsMissingWorkspaceDirectory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"serve",
		"--catalog", filepath.Join("catalog", "v0.2", "snapshot.yaml"),
		"--coverage-report", filepath.Join("catalog", "v0.2", "evidence", "catalog-coverage.yaml"),
		"--workspace", filepath.Join(t.TempDir(), "missing-workspace"),
	}
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input for missing workspace, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "--workspace must point to an existing directory") {
		t.Fatalf("expected workspace validation error, got stderr=%s", stderr.String())
	}
}

func TestServeAPIEndpoints(t *testing.T) {
	handler := serveHandlerFixture(t, false, t.TempDir())
	tests := []struct {
		name string
		path string
	}{
		{name: "catalog", path: "/api/v1/catalog"},
		{name: "assertions", path: "/api/v1/assertions"},
		{name: "coverage", path: "/api/v1/coverage"},
		{name: "drift posture", path: "/api/v1/drift-posture"},
		{name: "lifecycle policy", path: "/api/v1/lifecycle-policy"},
		{name: "workspace", path: "/api/v1/workspace"},
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

func TestServeWorkspaceReturnsDeterministicStages(t *testing.T) {
	workspacePath := t.TempDir()
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workspace", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected workspace status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode workspace response: %v", err)
	}
	workspace, _ := payload["workspace"].(map[string]any)
	stages, ok := workspace["stages"].([]any)
	if !ok || len(stages) != 7 {
		t.Fatalf("expected seven workspace stages, got %#v", workspace["stages"])
	}
	first, _ := stages[0].(map[string]any)
	if first["id"] != "plan" || first["status"] != "ready" {
		t.Fatalf("expected empty workspace plan stage ready, got %#v", first)
	}
}

func TestServeWorkspacePlanOnlyShowsFirstStageComplete(t *testing.T) {
	workspacePath := t.TempDir()
	planSource := filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml")
	planBody, err := os.ReadFile(planSource)
	if err != nil {
		t.Fatalf("read plan fixture: %v", err)
	}
	planTarget := filepath.Join(workspacePath, "reference-stack.plan.yaml")
	if err := os.WriteFile(planTarget, planBody, 0o600); err != nil {
		t.Fatalf("write plan fixture into workspace: %v", err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workspace", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected workspace status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode workspace response: %v", err)
	}
	workspace, _ := payload["workspace"].(map[string]any)
	stages, _ := workspace["stages"].([]any)
	for index, raw := range stages {
		stage, _ := raw.(map[string]any)
		if index == 0 {
			if stage["status"] != "complete" {
				t.Fatalf("expected stage 1 complete, got %#v", stage)
			}
			continue
		}
		if stage["status"] != "not-started" {
			t.Fatalf("expected stage %d not-started for plan-only workspace, got %#v", index+1, stage)
		}
	}
}

func TestServeWorkspaceRejectsUnknownArtifact(t *testing.T) {
	workspacePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspacePath, "mystery.yaml"), []byte("hello: world\n"), 0o600); err != nil {
		t.Fatalf("write malformed workspace artifact: %v", err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workspace", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown workspace artifact, got %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-010") {
		t.Fatalf("expected structured workspace artifact error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowPlanCreateRejectsInvalidRequest(t *testing.T) {
	workspacePath := t.TempDir()
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/plan", strings.NewReader(`{"requestPath":"docs/examples/v0.2-platform-request.yaml"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid workflow request, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-011") {
		t.Fatalf("expected structured invalid request error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowPlanCreateWritesPlanAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{
		"requestPath": "%s",
		"inventoryPath": "%s",
		"catalogPath": "%s",
		"outputPath": "%s",
		"auditPath": "%s"
	}`,
		filepath.Join("..", "..", "docs", "examples", "v0.2-platform-request.yaml"),
		filepath.Join("..", "..", "docs", "examples", "v0.2-inventory.yaml"),
		filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		filepath.Join(workspacePath, "reference-stack.plan.yaml"),
		filepath.Join(workspacePath, "reference-stack.plan.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/plan", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected workflow plan creation success, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode workflow plan response: %v", err)
	}
	plan, _ := payload["plan"].(map[string]any)
	if plan["planId"] == "" || plan["planPath"] == "" || plan["auditPath"] == "" {
		t.Fatalf("workflow plan response omitted expected fields: %#v", plan)
	}
	workspaceRequest := httptest.NewRequest(http.MethodGet, "/api/v1/workspace", nil)
	workspaceRecorder := httptest.NewRecorder()
	handler.ServeHTTP(workspaceRecorder, workspaceRequest)
	if workspaceRecorder.Code != http.StatusOK {
		t.Fatalf("expected workspace success after plan creation, got %d: %s", workspaceRecorder.Code, workspaceRecorder.Body.String())
	}
	var workspacePayload map[string]any
	if err := json.Unmarshal(workspaceRecorder.Body.Bytes(), &workspacePayload); err != nil {
		t.Fatalf("decode workspace response: %v", err)
	}
	workspace, _ := workspacePayload["workspace"].(map[string]any)
	stages, _ := workspace["stages"].([]any)
	first, _ := stages[0].(map[string]any)
	if first["status"] != "complete" {
		t.Fatalf("expected plan stage complete after workflow creation, got %#v", first)
	}
}

func TestServeWorkflowRenderRejectsUnsupportedTarget(t *testing.T) {
	workspacePath := t.TempDir()
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{
		"planPath": "%s",
		"catalogPath": "%s",
		"target": "unknown-target",
		"bundleName": "reference-stack",
		"outputPath": "%s",
		"auditPath": "%s"
	}`,
		filepath.Join(workspacePath, "reference-stack.plan.yaml"),
		filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		filepath.Join(workspacePath, "reference-stack.bundle.yaml"),
		filepath.Join(workspacePath, "reference-stack.bundle.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/render", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported render target, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-013") {
		t.Fatalf("expected structured render target error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRenderWritesBundleAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	handler := serveHandlerFixture(t, false, workspacePath)
	planRequest := fmt.Sprintf(`{
		"requestPath": "%s",
		"inventoryPath": "%s",
		"catalogPath": "%s",
		"outputPath": "%s",
		"auditPath": "%s"
	}`,
		filepath.Join("..", "..", "docs", "examples", "v0.2-platform-request.yaml"),
		filepath.Join("..", "..", "docs", "examples", "v0.2-inventory.yaml"),
		filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		filepath.Join(workspacePath, "reference-stack.plan.yaml"),
		filepath.Join(workspacePath, "reference-stack.plan.audit.jsonl"),
	)
	planRequestRecorder := httptest.NewRecorder()
	planHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/plan", strings.NewReader(planRequest))
	planHTTP.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(planRequestRecorder, planHTTP)
	if planRequestRecorder.Code != http.StatusOK {
		t.Fatalf("expected plan creation success before render, got %d: %s", planRequestRecorder.Code, planRequestRecorder.Body.String())
	}
	renderRequest := fmt.Sprintf(`{
		"planPath": "%s",
		"catalogPath": "%s",
		"target": "kubernetes-gitops",
		"bundleName": "reference-stack",
		"outputPath": "%s",
		"auditPath": "%s"
	}`,
		filepath.Join(workspacePath, "reference-stack.plan.yaml"),
		filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		filepath.Join(workspacePath, "reference-stack.kubernetes.bundle.yaml"),
		filepath.Join(workspacePath, "reference-stack.kubernetes.bundle.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/render", strings.NewReader(renderRequest))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected render success, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode workflow render response: %v", err)
	}
	renderPayload, _ := payload["render"].(map[string]any)
	if renderPayload["bundleId"] == "" || renderPayload["bundlePath"] == "" || renderPayload["auditPath"] == "" {
		t.Fatalf("workflow render response omitted expected fields: %#v", renderPayload)
	}
	workspaceRequest := httptest.NewRequest(http.MethodGet, "/api/v1/workspace", nil)
	workspaceRecorder := httptest.NewRecorder()
	handler.ServeHTTP(workspaceRecorder, workspaceRequest)
	if workspaceRecorder.Code != http.StatusOK {
		t.Fatalf("expected workspace success after render, got %d: %s", workspaceRecorder.Code, workspaceRecorder.Body.String())
	}
	var workspacePayload map[string]any
	if err := json.Unmarshal(workspaceRecorder.Body.Bytes(), &workspacePayload); err != nil {
		t.Fatalf("decode workspace response: %v", err)
	}
	workspace, _ := workspacePayload["workspace"].(map[string]any)
	stages, _ := workspace["stages"].([]any)
	if len(stages) < 2 {
		t.Fatalf("expected two stages at minimum, got %#v", stages)
	}
	second, _ := stages[1].(map[string]any)
	if second["status"] != "complete" {
		t.Fatalf("expected bundle stage complete after render, got %#v", second)
	}
}

func TestServeWorkflowPreflightRejectsOutOfWorkspaceOutput(t *testing.T) {
	workspacePath := t.TempDir()
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{
		"bundlePath": "%s",
		"name": "reference-preflight",
		"outputPath": "%s",
		"auditPath": "%s"
	}`,
		filepath.Join(workspacePath, "reference-stack.kubernetes.bundle.yaml"),
		filepath.Join("..", "..", "outside-preflight.yaml"),
		filepath.Join(workspacePath, "reference-preflight.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/preflight", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for out-of-workspace preflight output, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-015") {
		t.Fatalf("expected structured preflight path error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowPreflightAndChangeSetWriteArtifacts(t *testing.T) {
	workspacePath := t.TempDir()
	restorePreflightRunner, restoreChangeSetRunner := workflowPreflightRunner, workflowChangeSetRunner
	t.Cleanup(func() {
		workflowPreflightRunner = restorePreflightRunner
		workflowChangeSetRunner = restoreChangeSetRunner
	})
	workflowPreflightRunner = func(args []string, stdout, stderr io.Writer) int {
		observation := targetpreflight.Observation{
			ReferenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			ServerVersion:   "v1.35.2", CoreV1: true, AppsV1: true, NetworkingV1: true,
			NodesReadable: true, GPUCount: 1, NodePlatforms: []string{"linux/amd64"}, DNSReadable: true, DNSPodCount: 1,
			NamespaceReadable: true, PVCReadable: true, PVCExists: true, PVCPhase: "Bound",
		}
		factory := func(_, _ string) (targetpreflight.Observer, error) {
			return fixedTargetObserver{observation: observation}, nil
		}
		return runKubernetesTargetPreflight(args, stdout, stderr, factory, func() time.Time {
			return time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
		})
	}
	workflowChangeSetRunner = func(args []string, stdout, stderr io.Writer) int {
		factory := func(_, _ string) (changeset.Observer, error) {
			options, ok := parseChangeSetOptions(args, stderr)
			if !ok {
				return nil, fmt.Errorf("parse change-set options")
			}
			bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
			if err != nil {
				return nil, err
			}
			desired, err := changeset.DesiredObjects(bundle)
			if err != nil {
				return nil, err
			}
			observation := changeset.Observation{
				Target: resources.TargetIdentity{
					Type:            "kubernetes",
					ReferenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
					ServerVersion:   "v1.35.2",
				},
			}
			for _, object := range desired {
				observation.Objects = append(observation.Objects, changeset.ObjectObservation{
					Reference: object.Reference,
					Readable:  true,
					Exists:    false,
					Owned:     false,
					PlanMatch: false,
				})
			}
			return fixedChangeSetObserver{observation: observation}, nil
		}
		return runKubernetesChangeSet(args, stdout, stderr, factory, func() time.Time {
			return time.Date(2026, 7, 20, 12, 1, 0, 0, time.UTC)
		})
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	planRequest := fmt.Sprintf(`{
		"requestPath": "%s",
		"inventoryPath": "%s",
		"catalogPath": "%s",
		"outputPath": "%s",
		"auditPath": "%s"
	}`,
		filepath.Join("..", "..", "docs", "examples", "v0.2-platform-request.yaml"),
		filepath.Join("..", "..", "docs", "examples", "v0.2-inventory.yaml"),
		filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		filepath.Join(workspacePath, "reference-stack.plan.yaml"),
		filepath.Join(workspacePath, "reference-stack.plan.audit.jsonl"),
	)
	planRecorder := httptest.NewRecorder()
	planHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/plan", strings.NewReader(planRequest))
	planHTTP.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(planRecorder, planHTTP)
	if planRecorder.Code != http.StatusOK {
		t.Fatalf("expected plan creation success before preflight, got %d: %s", planRecorder.Code, planRecorder.Body.String())
	}
	renderRequest := fmt.Sprintf(`{
		"planPath": "%s",
		"catalogPath": "%s",
		"target": "kubernetes-gitops",
		"bundleName": "reference-stack",
		"outputPath": "%s",
		"auditPath": "%s"
	}`,
		filepath.Join(workspacePath, "reference-stack.plan.yaml"),
		filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml"),
		filepath.Join(workspacePath, "reference-stack.kubernetes.bundle.yaml"),
		filepath.Join(workspacePath, "reference-stack.kubernetes.bundle.audit.jsonl"),
	)
	renderRecorder := httptest.NewRecorder()
	renderHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/render", strings.NewReader(renderRequest))
	renderHTTP.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(renderRecorder, renderHTTP)
	if renderRecorder.Code != http.StatusOK {
		t.Fatalf("expected render success before preflight, got %d: %s", renderRecorder.Code, renderRecorder.Body.String())
	}
	preflightRequest := fmt.Sprintf(`{
		"bundlePath": "%s",
		"name": "reference-preflight",
		"outputPath": "%s",
		"auditPath": "%s",
		"kubeconfig": "/private/admin.conf",
		"context": "production-admin",
		"timeout": "30s"
	}`,
		filepath.Join(workspacePath, "reference-stack.kubernetes.bundle.yaml"),
		filepath.Join(workspacePath, "reference-preflight.yaml"),
		filepath.Join(workspacePath, "reference-preflight.audit.jsonl"),
	)
	preflightRecorder := httptest.NewRecorder()
	preflightHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/preflight", strings.NewReader(preflightRequest))
	preflightHTTP.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(preflightRecorder, preflightHTTP)
	if preflightRecorder.Code != http.StatusOK && preflightRecorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected preflight success or blocked response, got %d: %s", preflightRecorder.Code, preflightRecorder.Body.String())
	}
	var preflightPayload map[string]any
	if err := json.Unmarshal(preflightRecorder.Body.Bytes(), &preflightPayload); err != nil {
		t.Fatalf("decode preflight response: %v", err)
	}
	preflight, _ := preflightPayload["preflight"].(map[string]any)
	if preflight["resultId"] == "" || preflight["resultPath"] == "" || preflight["auditPath"] == "" {
		t.Fatalf("preflight response omitted expected fields: %#v", preflight)
	}
	changeSetRequest := fmt.Sprintf(`{
		"bundlePath": "%s",
		"preflightPath": "%s",
		"name": "reference-change-set",
		"outputPath": "%s",
		"auditPath": "%s",
		"kubeconfig": "/private/admin.conf",
		"context": "production-admin",
		"timeout": "30s"
	}`,
		filepath.Join(workspacePath, "reference-stack.kubernetes.bundle.yaml"),
		filepath.Join(workspacePath, "reference-preflight.yaml"),
		filepath.Join(workspacePath, "reference-change-set.yaml"),
		filepath.Join(workspacePath, "reference-change-set.audit.jsonl"),
	)
	changeSetRecorder := httptest.NewRecorder()
	changeSetHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/changeset", strings.NewReader(changeSetRequest))
	changeSetHTTP.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(changeSetRecorder, changeSetHTTP)
	if changeSetRecorder.Code != http.StatusOK {
		t.Fatalf("expected change-set success, got %d: %s", changeSetRecorder.Code, changeSetRecorder.Body.String())
	}
	var changeSetPayload map[string]any
	if err := json.Unmarshal(changeSetRecorder.Body.Bytes(), &changeSetPayload); err != nil {
		t.Fatalf("decode changeset response: %v", err)
	}
	changeSet, _ := changeSetPayload["changeSet"].(map[string]any)
	if changeSet["changeSetId"] == "" || changeSet["changeSetPath"] == "" || changeSet["auditPath"] == "" {
		t.Fatalf("changeset response omitted expected fields: %#v", changeSet)
	}
	workspaceRequest := httptest.NewRequest(http.MethodGet, "/api/v1/workspace", nil)
	workspaceRecorder := httptest.NewRecorder()
	handler.ServeHTTP(workspaceRecorder, workspaceRequest)
	if workspaceRecorder.Code != http.StatusOK {
		t.Fatalf("expected workspace success after changeset, got %d: %s", workspaceRecorder.Code, workspaceRecorder.Body.String())
	}
	var workspacePayload map[string]any
	if err := json.Unmarshal(workspaceRecorder.Body.Bytes(), &workspacePayload); err != nil {
		t.Fatalf("decode workspace response: %v", err)
	}
	workspace, _ := workspacePayload["workspace"].(map[string]any)
	stages, _ := workspace["stages"].([]any)
	if len(stages) < 4 {
		t.Fatalf("expected at least four stages, got %#v", stages)
	}
	preflightStage, _ := stages[2].(map[string]any)
	if preflightStage["status"] != "complete" {
		t.Fatalf("expected preflight stage complete, got %#v", preflightStage)
	}
	changeSetStage, _ := stages[3].(map[string]any)
	if changeSetStage["status"] != "complete" {
		t.Fatalf("expected changeset stage complete, got %#v", changeSetStage)
	}
}

func TestServeDriftPostureSupportsAssertionFilter(t *testing.T) {
	handler := serveHandlerFixture(t, false, t.TempDir())
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
	handler := serveHandlerFixture(t, false, t.TempDir())
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
	handler := serveHandlerFixture(t, false, t.TempDir())
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
	handler := serveHandlerFixture(t, false, t.TempDir())
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
	handler := serveHandlerFixture(t, false, t.TempDir())
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
	handler := serveHandlerFixture(t, false, t.TempDir())
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
	handler := serveHandlerFixture(t, true, t.TempDir())
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

func serveHandlerFixture(t *testing.T, uiEnabled bool, workspacePath string) http.Handler {
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
	handler, err := newServeAPIHandler(snapshot, digest, report, uiEnabled, workspacePath)
	if err != nil {
		t.Fatalf("build serve handler: %v", err)
	}
	return handler
}
