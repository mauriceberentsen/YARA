package cli

import (
	"bytes"
	"context"
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

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
	"github.com/mauriceberentsen/YARA/internal/changeset"
	"github.com/mauriceberentsen/YARA/internal/executor"
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
	restorePreflightRunner, restoreChangeSetRunner, restoreApprovalRunner := workflowPreflightRunner, workflowChangeSetRunner, workflowApprovalRunner
	t.Cleanup(func() {
		workflowPreflightRunner = restorePreflightRunner
		workflowChangeSetRunner = restoreChangeSetRunner
		workflowApprovalRunner = restoreApprovalRunner
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
	workflowApprovalRunner = func(args []string, stdout, stderr io.Writer) int {
		return recordDeploymentApprovalAt(args, stdout, stderr, func() time.Time {
			return time.Date(2026, 7, 20, 12, 2, 0, 0, time.UTC)
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
	approvalRequest := fmt.Sprintf(`{
		"bundlePath": "%s",
		"preflightPath": "%s",
		"changeSetPath": "%s",
		"decision": "approve",
		"reasonReference": "ticket-123",
		"outputPath": "%s",
		"auditPath": "%s"
	}`,
		filepath.Join(workspacePath, "reference-stack.kubernetes.bundle.yaml"),
		filepath.Join(workspacePath, "reference-preflight.yaml"),
		filepath.Join(workspacePath, "reference-change-set.yaml"),
		filepath.Join(workspacePath, "reference-approval.yaml"),
		filepath.Join(workspacePath, "reference-approval.audit.jsonl"),
	)
	approvalRecorder := httptest.NewRecorder()
	approvalHTTP := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/approval", strings.NewReader(approvalRequest))
	approvalHTTP.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(approvalRecorder, approvalHTTP)
	if approvalRecorder.Code != http.StatusOK {
		t.Fatalf("expected approval success, got %d: %s", approvalRecorder.Code, approvalRecorder.Body.String())
	}
	var approvalPayload map[string]any
	if err := json.Unmarshal(approvalRecorder.Body.Bytes(), &approvalPayload); err != nil {
		t.Fatalf("decode approval response: %v", err)
	}
	approval, _ := approvalPayload["approval"].(map[string]any)
	if approval["approvalId"] == "" || approval["approvalPath"] == "" || approval["auditPath"] == "" || approval["bundleId"] == "" || approval["preflightResultId"] == "" || approval["changeSetId"] == "" {
		t.Fatalf("approval response omitted expected fields: %#v", approval)
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
	approvalStage, _ := stages[4].(map[string]any)
	if approvalStage["status"] != "complete" {
		t.Fatalf("expected approval stage complete, got %#v", approvalStage)
	}
}

func TestServeWorkflowApprovalRejectsInvalidDecision(t *testing.T) {
	workspacePath := t.TempDir()
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{
		"bundlePath": "%s",
		"preflightPath": "%s",
		"changeSetPath": "%s",
		"decision": "maybe",
		"reasonReference": "ticket-123",
		"outputPath": "%s",
		"auditPath": "%s"
	}`,
		filepath.Join(workspacePath, "reference-stack.kubernetes.bundle.yaml"),
		filepath.Join(workspacePath, "reference-preflight.yaml"),
		filepath.Join(workspacePath, "reference-change-set.yaml"),
		filepath.Join(workspacePath, "reference-approval.yaml"),
		filepath.Join(workspacePath, "reference-approval.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/approval", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid approval decision, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-019") {
		t.Fatalf("expected structured approval decision error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowAuthorizationCommandUsesWorkspaceArtifacts(t *testing.T) {
	workspacePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	sourcePath := t.TempDir()
	paths, _ := writeExecutionInputs(t, sourcePath, now)
	for _, flag := range []string{"--bundle", "--preflight", "--change-set", "--approval"} {
		sourceArtifactPath := valueForFlag(paths, flag)
		data, err := os.ReadFile(sourceArtifactPath)
		if err != nil {
			t.Fatalf("read source artifact %s: %v", sourceArtifactPath, err)
		}
		targetArtifactPath := filepath.Join(workspacePath, filepath.Base(sourceArtifactPath))
		if err := os.WriteFile(targetArtifactPath, data, 0o600); err != nil {
			t.Fatalf("write workspace artifact %s: %v", targetArtifactPath, err)
		}
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/authorization-command", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for authorization command endpoint, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode authorization command response: %v", err)
	}
	command, _ := payload["command"].(string)
	if !strings.Contains(command, "yara authorization issue") || !strings.Contains(command, "--private-key '<private-key-path>'") {
		t.Fatalf("authorization command omitted deterministic CLI text or leaked key placeholder: %q", command)
	}
}

func TestServeWorkflowApplyWritesReceiptAndCompletesStage(t *testing.T) {
	workspacePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	sourcePath := t.TempDir()
	paths, authorization := writeExecutionInputs(t, sourcePath, now)
	restoreApplyRunner := workflowApplyRunner
	restoreFactory := newKubernetesExecutor
	t.Cleanup(func() {
		workflowApplyRunner = restoreApplyRunner
		newKubernetesExecutor = restoreFactory
	})
	workflowApplyRunner = func(args []string, stdout, stderr io.Writer) int {
		newKubernetesExecutor = func(string, string) (kubernetesExecutor, error) {
			return fixedKubernetesExecutor{execute: func(_ context.Context, _ resources.DeploymentBundle, changeSet resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization, _ resources.ArtifactImportReceipt, started time.Time) (executor.ExecutionResult, error) {
				operations := make([]resources.DeploymentOperationReceipt, 0, len(changeSet.Spec.Operations))
				for _, operation := range changeSet.Spec.Operations {
					operations = append(operations, resources.DeploymentOperationReceipt{Resource: operation.Resource, Action: operation.Action, Outcome: "applied", AfterDigest: operation.DesiredDigest})
				}
				evidence, _ := canonical.Digest(struct{ Passed bool }{true})
				return executor.ExecutionResult{
					StartedAt: started, CompletedAt: started.Add(time.Minute), Target: authorization.Spec.Target, MutationStarted: true,
					Operations: operations,
					Postflight: []resources.DeploymentPostflightCheck{{ID: "workloads.available", Status: "passed", EvidenceDigest: evidence}},
					Limitations: []string{
						"Serve apply fixture.",
					},
				}, nil
			}}, nil
		}
		return applyKubernetesDeploymentAt(args, stdout, stderr, func() time.Time {
			return now.Add(3 * time.Minute)
		})
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	receiptPath := filepath.Join(workspacePath, "reference-receipt.yaml")
	auditPath := filepath.Join(workspacePath, "reference-apply.audit.jsonl")
	requestBody := fmt.Sprintf(`{
		"bundlePath": "%s",
		"preflightPath": "%s",
		"changeSetPath": "%s",
		"approvalPath": "%s",
		"importReceiptPath": "%s",
		"transferReceiptPaths": ["%s"],
		"scanReceiptPaths": ["%s"],
		"authorizationPath": "%s",
		"publicKeyPath": "%s",
		"confirmAuthorization": "%s",
		"typedConfirmationDigest": "%s",
		"name": "reference-receipt",
		"receiptPath": "%s",
		"auditPath": "%s",
		"timeout": "30m"
	}`,
		valueForFlag(paths, "--bundle"),
		valueForFlag(paths, "--preflight"),
		valueForFlag(paths, "--change-set"),
		valueForFlag(paths, "--approval"),
		valueForFlag(paths, "--import-receipt"),
		valueForFlag(paths, "--transfer-receipt"),
		valueForFlag(paths, "--scan-receipt"),
		valueForFlag(paths, "--authorization"),
		valueForFlag(paths, "--public-key"),
		authorization.Metadata.AuthorizationID,
		authorization.Metadata.AuthorizationID,
		receiptPath,
		auditPath,
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/apply", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected apply success response, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var applyPayload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &applyPayload); err != nil {
		t.Fatalf("decode apply payload: %v", err)
	}
	apply, _ := applyPayload["apply"].(map[string]any)
	if apply["receiptId"] == "" || apply["transferReceiptIds"] == nil || apply["scanReceiptIds"] == nil {
		t.Fatalf("apply response omitted provenance identifiers: %#v", apply)
	}
	workspaceRequest := httptest.NewRequest(http.MethodGet, "/api/v1/workspace", nil)
	workspaceRecorder := httptest.NewRecorder()
	handler.ServeHTTP(workspaceRecorder, workspaceRequest)
	if workspaceRecorder.Code != http.StatusOK {
		t.Fatalf("expected workspace response after apply, got %d: %s", workspaceRecorder.Code, workspaceRecorder.Body.String())
	}
	var workspacePayload map[string]any
	if err := json.Unmarshal(workspaceRecorder.Body.Bytes(), &workspacePayload); err != nil {
		t.Fatalf("decode workspace payload: %v", err)
	}
	workspace, _ := workspacePayload["workspace"].(map[string]any)
	stages, _ := workspace["stages"].([]any)
	receiptStage, _ := stages[6].(map[string]any)
	if receiptStage["status"] != "complete" {
		t.Fatalf("expected receipt stage complete, got %#v", receiptStage)
	}
}

func TestServeWorkflowApplyRejectsAirgapTrustPolicyConfirmationMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, authorization := writeExecutionInputs(t, sourcePath, now)
	gatePath := filepath.Join(sourcePath, "airgap-gate.yaml")
	gateTrustPolicyPath := writeAirgapGateFixture(t, gatePath, paths)
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{
		"bundlePath": "%s",
		"preflightPath": "%s",
		"changeSetPath": "%s",
		"approvalPath": "%s",
		"importReceiptPath": "%s",
		"authorizationPath": "%s",
		"publicKeyPath": "%s",
		"confirmAuthorization": "%s",
		"typedConfirmationDigest": "%s",
		"name": "reference-receipt",
		"receiptPath": "%s",
		"auditPath": "%s",
		"airgapGateResultPath": "%s",
		"airgapGateTrustPolicyPath": "%s",
		"confirmAirgapGateTrustPolicy": "%s"
	}`,
		valueForFlag(paths, "--bundle"),
		valueForFlag(paths, "--preflight"),
		valueForFlag(paths, "--change-set"),
		valueForFlag(paths, "--approval"),
		valueForFlag(paths, "--import-receipt"),
		valueForFlag(paths, "--authorization"),
		valueForFlag(paths, "--public-key"),
		authorization.Metadata.AuthorizationID,
		authorization.Metadata.AuthorizationID,
		filepath.Join(workspacePath, "reference-receipt.yaml"),
		filepath.Join(workspacePath, "reference-apply.audit.jsonl"),
		gatePath,
		gateTrustPolicyPath,
		testCLIDigest('f'),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/apply", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for trust policy confirmation mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestServeWorkflowApplyRejectsDestructivePolicyDiffWithoutTransitionReview(t *testing.T) {
	workspacePath := t.TempDir()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, authorization := writeExecutionInputs(t, sourcePath, now)
	gatePath := filepath.Join(sourcePath, "airgap-gate.yaml")
	gateTrustPolicyPath := writeAirgapGateFixture(t, gatePath, paths)
	gateTrustPolicy, err := resources.LoadAirgapGateTrustPolicy(gateTrustPolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	diff := resources.AirgapGateTrustPolicyDiff{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicyDiff",
		Metadata:   resources.AirgapGateTrustPolicyDiffMetadata{Name: "destructive-policy-diff"},
		Spec: resources.AirgapGateTrustPolicyDiffSpec{
			RecordedAt:            now.Add(2 * time.Minute).Format(time.RFC3339Nano),
			FromPolicyID:          testCLIDigest('e'),
			ToPolicyID:            gateTrustPolicy.Metadata.PolicyID,
			TargetReferenceDigest: gateTrustPolicy.Spec.TargetReferenceDigest,
			HighestImpact:         "destructive",
			Changes: []resources.AirgapGateTrustPolicyChange{{
				ID:       "change-001",
				KeyID:    "operations-key-1",
				Digest:   gateTrustPolicy.Spec.TrustedSignerIdentities[0].PublicKeyDigest,
				Category: "removed",
				Impact:   "destructive",
				Summary:  "Signer removed.",
			}},
			Limitations: []string{"Policy diff fixture."},
		},
	}
	diff, err = diff.AssignDiffID()
	if err != nil {
		t.Fatal(err)
	}
	diffPath := filepath.Join(sourcePath, "destructive-policy-diff.yaml")
	writeYAMLFixture(t, diffPath, diff)
	requestBody := fmt.Sprintf(`{
		"bundlePath": "%s",
		"preflightPath": "%s",
		"changeSetPath": "%s",
		"approvalPath": "%s",
		"importReceiptPath": "%s",
		"authorizationPath": "%s",
		"publicKeyPath": "%s",
		"confirmAuthorization": "%s",
		"typedConfirmationDigest": "%s",
		"name": "reference-receipt",
		"receiptPath": "%s",
		"auditPath": "%s",
		"airgapGateResultPath": "%s",
		"airgapGateTrustPolicyPath": "%s",
		"confirmAirgapGateTrustPolicy": "%s",
		"airgapGatePolicyDiffPath": "%s",
		"confirmAirgapGatePolicyDiff": "%s"
	}`,
		valueForFlag(paths, "--bundle"),
		valueForFlag(paths, "--preflight"),
		valueForFlag(paths, "--change-set"),
		valueForFlag(paths, "--approval"),
		valueForFlag(paths, "--import-receipt"),
		valueForFlag(paths, "--authorization"),
		valueForFlag(paths, "--public-key"),
		authorization.Metadata.AuthorizationID,
		authorization.Metadata.AuthorizationID,
		filepath.Join(workspacePath, "reference-receipt.yaml"),
		filepath.Join(workspacePath, "reference-apply.audit.jsonl"),
		gatePath,
		gateTrustPolicyPath,
		gateTrustPolicy.Metadata.PolicyID,
		diffPath,
		diff.Metadata.DiffID,
	)
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/apply", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for missing destructive transition review, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestServeWorkflowApplyRejectsIncompleteTransferScanChain(t *testing.T) {
	workspacePath := t.TempDir()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, authorization := writeExecutionInputs(t, sourcePath, now)
	requestBody := fmt.Sprintf(`{
		"bundlePath": "%s",
		"preflightPath": "%s",
		"changeSetPath": "%s",
		"approvalPath": "%s",
		"importReceiptPath": "%s",
		"transferReceiptPaths": ["%s"],
		"authorizationPath": "%s",
		"publicKeyPath": "%s",
		"confirmAuthorization": "%s",
		"typedConfirmationDigest": "%s",
		"name": "reference-receipt",
		"receiptPath": "%s",
		"auditPath": "%s"
	}`,
		valueForFlag(paths, "--bundle"),
		valueForFlag(paths, "--preflight"),
		valueForFlag(paths, "--change-set"),
		valueForFlag(paths, "--approval"),
		valueForFlag(paths, "--import-receipt"),
		valueForFlag(paths, "--transfer-receipt"),
		valueForFlag(paths, "--authorization"),
		valueForFlag(paths, "--public-key"),
		authorization.Metadata.AuthorizationID,
		authorization.Metadata.AuthorizationID,
		filepath.Join(workspacePath, "reference-receipt.yaml"),
		filepath.Join(workspacePath, "reference-apply.audit.jsonl"),
	)
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/apply", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for incomplete transfer/scan chain, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestServeWorkflowRunbookReturnsDeterministicSteps(t *testing.T) {
	workspacePath := t.TempDir()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, authorization := writeExecutionInputs(t, sourcePath, now)
	planPath, _ := writeV02Plan(t, sourcePath)
	copyIntoWorkspace := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		target := filepath.Join(workspacePath, filepath.Base(path))
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	copyIntoWorkspace(planPath)
	for _, flag := range []string{"--bundle", "--preflight", "--change-set", "--approval", "--authorization"} {
		copyIntoWorkspace(valueForFlag(paths, flag))
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/runbook", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for workflow runbook, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode runbook response: %v", err)
	}
	runbook, _ := payload["runbook"].(map[string]any)
	steps, _ := runbook["steps"].([]any)
	if len(steps) == 0 {
		t.Fatalf("runbook omitted steps: %#v", runbook)
	}
	evidence, _ := runbook["evidence"].(map[string]any)
	if evidence["authorizationId"] != authorization.Metadata.AuthorizationID {
		t.Fatalf("runbook authorization ID mismatch: %#v", evidence)
	}
	markdown, _ := runbook["markdown"].(string)
	if !strings.Contains(markdown, authorization.Metadata.AuthorizationID) || strings.Contains(markdown, "BEGIN PRIVATE KEY") {
		t.Fatalf("runbook markdown missing expected digest or leaked secrets: %q", markdown)
	}
}

func TestServeWorkflowRunbookRejectsMissingPrerequisites(t *testing.T) {
	workspacePath := t.TempDir()
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/runbook", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing runbook prerequisites, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-024") {
		t.Fatalf("expected structured runbook prerequisite error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRunbookRejectsMalformedWorkspaceArtifacts(t *testing.T) {
	workspacePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspacePath, "plan.yaml"), []byte("apiVersion: yara.dev/v1alpha1\nkind: PlatformPlan\nmetadata:\n  name: malformed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/runbook", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed workspace artifact, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-024") {
		t.Fatalf("expected structured malformed runbook error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRunbookExportWritesArtifactsAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, sourcePath, now)
	planPath, _ := writeV02Plan(t, sourcePath)
	copyIntoWorkspace := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		target := filepath.Join(workspacePath, filepath.Base(path))
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	copyIntoWorkspace(planPath)
	for _, flag := range []string{"--bundle", "--preflight", "--change-set", "--approval", "--authorization"} {
		copyIntoWorkspace(valueForFlag(paths, flag))
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	markdownPath := filepath.Join(workspacePath, "workflow.runbook.md")
	jsonPath := filepath.Join(workspacePath, "workflow.runbook.json")
	auditPath := filepath.Join(workspacePath, "workflow.runbook.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"markdownPath":"%s","jsonPath":"%s","auditPath":"%s"}`, markdownPath, jsonPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/runbook/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected runbook export success, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, err := os.Stat(markdownPath); err != nil {
		t.Fatalf("expected markdown export file, got %v", err)
	}
	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("expected json export file, got %v", err)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load export audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify export audit: %v", err)
	}
}

func TestServeWorkflowRunbookExportRejectsDuplicatePaths(t *testing.T) {
	workspacePath := t.TempDir()
	handler := serveHandlerFixture(t, false, workspacePath)
	path := filepath.Join(workspacePath, "same-path")
	requestBody := fmt.Sprintf(`{"markdownPath":"%s","jsonPath":"%s","auditPath":"%s"}`, path, path, filepath.Join(workspacePath, "audit.jsonl"))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/runbook/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for duplicate runbook export paths, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-025") {
		t.Fatalf("expected structured duplicate-path error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRunbookExportRejectsOutOfWorkspacePath(t *testing.T) {
	workspacePath := t.TempDir()
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"markdownPath":"%s","jsonPath":"%s","auditPath":"%s"}`,
		filepath.Join("..", "outside.md"),
		filepath.Join(workspacePath, "inside.json"),
		filepath.Join(workspacePath, "inside.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/runbook/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for out-of-workspace export path, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-SRV-025") {
		t.Fatalf("expected structured out-of-workspace export path error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowCapsuleReadyPath(t *testing.T) {
	workspacePath := t.TempDir()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, sourcePath, now)
	planPath, _ := writeV02Plan(t, sourcePath)
	copyIntoWorkspace := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		target := filepath.Join(workspacePath, filepath.Base(path))
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	copyIntoWorkspace(planPath)
	for _, flag := range []string{"--bundle", "--preflight", "--change-set", "--approval", "--authorization"} {
		copyIntoWorkspace(valueForFlag(paths, flag))
	}
	if err := os.WriteFile(filepath.Join(workspacePath, "workflow.runbook.md"), []byte("# runbook"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspacePath, "workflow.runbook.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/capsule", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected capsule success, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode capsule response: %v", err)
	}
	capsule, _ := payload["capsule"].(map[string]any)
	if ready, _ := capsule["ready"].(bool); !ready {
		t.Fatalf("expected ready capsule, got %#v", capsule)
	}
	exports, _ := capsule["runbookExports"].(map[string]any)
	markdownPaths, _ := exports["markdownPaths"].([]any)
	if len(markdownPaths) == 0 {
		t.Fatalf("expected runbook export references, got %#v", exports)
	}
}

func TestServeWorkflowCapsuleBlockedPath(t *testing.T) {
	workspacePath := t.TempDir()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, sourcePath, now)
	planPath, _ := writeV02Plan(t, sourcePath)
	copyIntoWorkspace := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		target := filepath.Join(workspacePath, filepath.Base(path))
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	copyIntoWorkspace(planPath)
	for _, flag := range []string{"--bundle", "--preflight", "--change-set", "--approval", "--authorization"} {
		copyIntoWorkspace(valueForFlag(paths, flag))
	}
	approvalPath := filepath.Join(workspacePath, filepath.Base(valueForFlag(paths, "--approval")))
	approval, err := resources.LoadDeploymentApproval(approvalPath)
	if err != nil {
		t.Fatal(err)
	}
	approval.Spec.BundleID = testCLIDigest('f')
	approval, err = approval.AssignApprovalID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, approvalPath, approval)
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/capsule", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected capsule response, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode capsule response: %v", err)
	}
	capsule, _ := payload["capsule"].(map[string]any)
	if ready, _ := capsule["ready"].(bool); ready {
		t.Fatalf("expected blocked capsule, got %#v", capsule)
	}
	blockers, _ := capsule["blockers"].([]any)
	if len(blockers) == 0 {
		t.Fatalf("expected blockers in blocked capsule, got %#v", capsule)
	}
}

func TestServeWorkflowCapsuleExportWritesArtifactsAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, sourcePath, now)
	planPath, _ := writeV02Plan(t, sourcePath)
	copyIntoWorkspace := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		target := filepath.Join(workspacePath, filepath.Base(path))
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	copyIntoWorkspace(planPath)
	for _, flag := range []string{"--bundle", "--preflight", "--change-set", "--approval", "--authorization"} {
		copyIntoWorkspace(valueForFlag(paths, flag))
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	markdownPath := filepath.Join(workspacePath, "workflow.capsule.md")
	jsonPath := filepath.Join(workspacePath, "workflow.capsule.json")
	auditPath := filepath.Join(workspacePath, "workflow.capsule.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"markdownPath":%q,"jsonPath":%q,"auditPath":%q}`, markdownPath, jsonPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/capsule/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for capsule export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	exportJSONBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read capsule json export: %v", err)
	}
	exportJSON := map[string]any{}
	if err := json.Unmarshal(exportJSONBytes, &exportJSON); err != nil {
		t.Fatalf("decode capsule json export: %v", err)
	}
	if _, ok := exportJSON["capsule"]; !ok {
		t.Fatalf("expected capsule payload in export json, got %#v", exportJSON)
	}
	markdownBytes, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatalf("read capsule markdown export: %v", err)
	}
	if !strings.Contains(string(markdownBytes), "## Readiness") {
		t.Fatalf("expected readiness section in capsule markdown, got %s", string(markdownBytes))
	}
	auditLog, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load capsule export audit: %v", err)
	}
	if len(auditLog) == 0 {
		t.Fatalf("expected audit entries for capsule export")
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode capsule export response: %v", err)
	}
	export, _ := payload["export"].(map[string]any)
	if blocked, _ := export["blockedArchival"].(bool); blocked {
		t.Fatalf("expected ready capsule export to report blockedArchival=false, got %#v", export)
	}
}

func TestServeWorkflowCapsuleExportRejectsBlockedWithoutAllow(t *testing.T) {
	workspacePath := t.TempDir()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, sourcePath, now)
	planPath, _ := writeV02Plan(t, sourcePath)
	copyIntoWorkspace := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		target := filepath.Join(workspacePath, filepath.Base(path))
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	copyIntoWorkspace(planPath)
	for _, flag := range []string{"--bundle", "--preflight", "--change-set", "--approval", "--authorization"} {
		copyIntoWorkspace(valueForFlag(paths, flag))
	}
	approvalPath := filepath.Join(workspacePath, filepath.Base(valueForFlag(paths, "--approval")))
	approval, err := resources.LoadDeploymentApproval(approvalPath)
	if err != nil {
		t.Fatal(err)
	}
	approval.Spec.BundleID = testCLIDigest('f')
	approval, err = approval.AssignApprovalID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, approvalPath, approval)
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"markdownPath":%q,"jsonPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "blocked.capsule.md"),
		filepath.Join(workspacePath, "blocked.capsule.json"),
		filepath.Join(workspacePath, "blocked.capsule.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/capsule/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked capsule export without allow, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "allowBlocked=true") {
		t.Fatalf("expected allowBlocked diagnostic, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowCapsuleExportAllowsBlockedWithReason(t *testing.T) {
	workspacePath := t.TempDir()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, sourcePath, now)
	planPath, _ := writeV02Plan(t, sourcePath)
	copyIntoWorkspace := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		target := filepath.Join(workspacePath, filepath.Base(path))
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	copyIntoWorkspace(planPath)
	for _, flag := range []string{"--bundle", "--preflight", "--change-set", "--approval", "--authorization"} {
		copyIntoWorkspace(valueForFlag(paths, flag))
	}
	approvalPath := filepath.Join(workspacePath, filepath.Base(valueForFlag(paths, "--approval")))
	approval, err := resources.LoadDeploymentApproval(approvalPath)
	if err != nil {
		t.Fatal(err)
	}
	approval.Spec.BundleID = testCLIDigest('f')
	approval, err = approval.AssignApprovalID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, approvalPath, approval)
	handler := serveHandlerFixture(t, false, workspacePath)
	markdownPath := filepath.Join(workspacePath, "blocked.capsule.md")
	jsonPath := filepath.Join(workspacePath, "blocked.capsule.json")
	auditPath := filepath.Join(workspacePath, "blocked.capsule.audit.jsonl")
	requestBody := fmt.Sprintf(`{"markdownPath":%q,"jsonPath":%q,"auditPath":%q,"allowBlocked":true,"allowBlockedReasonReference":"ticket-rollback-42"}`,
		markdownPath,
		jsonPath,
		auditPath,
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/capsule/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for blocked capsule export with allow, got %d: %s", recorder.Code, recorder.Body.String())
	}
	markdownBytes, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatalf("read capsule markdown export: %v", err)
	}
	if !strings.Contains(string(markdownBytes), "ticket-rollback-42") {
		t.Fatalf("expected blocked reason reference in markdown export, got %s", string(markdownBytes))
	}
	auditLog, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load capsule export audit: %v", err)
	}
	if len(auditLog) == 0 {
		t.Fatalf("expected blocked archival diagnostic code in audit log")
	}
	lastEvent := auditLog[len(auditLog)-1]
	if len(lastEvent.Spec.DiagnosticCodes) == 0 {
		t.Fatalf("expected blocked archival diagnostic code in audit log")
	}
}

func TestServeWorkflowEvidenceBundleExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeEvidenceBundleFixtures(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.evidence-bundle.json")
	auditPath := filepath.Join(workspacePath, "workflow.evidence-bundle.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/evidence-bundle/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for evidence bundle export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read evidence bundle manifest: %v", err)
	}
	manifest := workflowEvidenceBundleManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode evidence bundle manifest: %v", err)
	}
	if len(manifest.Manifest.RunbookExports) == 0 || len(manifest.Manifest.CapsuleExports) == 0 {
		t.Fatalf("expected runbook and capsule export references, got %#v", manifest.Manifest)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load evidence bundle export audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit records for evidence bundle export")
	}
}

func TestServeWorkflowEvidenceBundleExportRejectsMissingExports(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.evidence-bundle.json"),
		filepath.Join(workspacePath, "workflow.evidence-bundle.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/evidence-bundle/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing exports, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "runbook markdown and json exports") {
		t.Fatalf("expected missing export diagnostic, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowEvidenceBundleExportRejectsMismatchedRunbookExport(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeEvidenceBundleFixtures(t, workspacePath)
	runbookJSONPath := filepath.Join(workspacePath, "workflow.runbook.json")
	runbookExport := workflowRunbookResponse{}
	runbookJSONBytes, err := os.ReadFile(runbookJSONPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(runbookJSONBytes, &runbookExport); err != nil {
		t.Fatal(err)
	}
	runbookExport.Runbook.Evidence.PlanID = testCLIDigest('c')
	corruptedRunbookJSON, err := json.MarshalIndent(runbookExport, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corruptedRunbookJSON = append(corruptedRunbookJSON, '\n')
	if err := os.WriteFile(runbookJSONPath, corruptedRunbookJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.evidence-bundle.json"),
		filepath.Join(workspacePath, "workflow.evidence-bundle.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/evidence-bundle/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mismatched runbook export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "not bound to current workflow evidence chain") {
		t.Fatalf("expected mismatch diagnostic, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReceiptTimelineReturnsLatestAndPrior(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	receipts := writeDeploymentReceiptFixtures(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/receipt-timeline", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for receipt timeline, got %d: %s", recorder.Code, recorder.Body.String())
	}
	payload := workflowReceiptTimelineResponse{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode receipt timeline response: %v", err)
	}
	if payload.Timeline.Latest.ReceiptID != receipts[1].Metadata.ReceiptID {
		t.Fatalf("expected latest receipt id %s, got %s", receipts[1].Metadata.ReceiptID, payload.Timeline.Latest.ReceiptID)
	}
	if len(payload.Timeline.Prior) != 1 || payload.Timeline.Prior[0].ReceiptID != receipts[0].Metadata.ReceiptID {
		t.Fatalf("expected one prior receipt with id %s, got %#v", receipts[0].Metadata.ReceiptID, payload.Timeline.Prior)
	}
}

func TestServeWorkflowReceiptTimelineRejectsDivergedTargetDigest(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	receipts := writeDeploymentReceiptFixtures(t, workspacePath)
	receiptPath := filepath.Join(workspacePath, "reference-receipt-older.yaml")
	corrupted := receipts[0]
	corrupted.Spec.Target.ReferenceDigest = testCLIDigest('e')
	corrupted, err := corrupted.AssignReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	writeYAMLFixture(t, receiptPath, corrupted)
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/receipt-timeline", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for diverged target digest, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "target digest diverges") {
		t.Fatalf("expected target divergence diagnostic, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReceiptTimelineExportWritesArtifactsAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeDeploymentReceiptFixtures(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	markdownPath := filepath.Join(workspacePath, "workflow.receipt-timeline.md")
	jsonPath := filepath.Join(workspacePath, "workflow.receipt-timeline.json")
	auditPath := filepath.Join(workspacePath, "workflow.receipt-timeline.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"markdownPath":%q,"jsonPath":%q,"auditPath":%q}`, markdownPath, jsonPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/receipt-timeline/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for receipt timeline export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	markdownBytes, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatalf("read receipt timeline markdown: %v", err)
	}
	if !strings.Contains(string(markdownBytes), "## Latest receipt") {
		t.Fatalf("expected latest receipt section in markdown export, got %s", string(markdownBytes))
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load receipt timeline audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for receipt timeline export")
	}
}

func TestServeWorkflowClosurePackageExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.closure-package.export.json")
	auditPath := filepath.Join(workspacePath, "workflow.closure-package.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"manifestPath":%q,"auditPath":%q,"releaseReadinessReference":"release-checklist-001"}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/closure-package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for closure package export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read closure package manifest: %v", err)
	}
	manifest := workflowClosurePackageManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode closure package manifest: %v", err)
	}
	if manifest.Package.ReleaseReadinessReference != "release-checklist-001" {
		t.Fatalf("expected release readiness reference in closure package, got %#v", manifest.Package)
	}
	if len(manifest.Package.EvidenceBundles) == 0 || len(manifest.Package.ReceiptTimelines) == 0 {
		t.Fatalf("expected closure package references, got %#v", manifest.Package)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load closure package export audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for closure package export")
	}
}

func TestServeWorkflowClosurePackageExportRejectsMissingReleaseReadinessReference(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.closure-package.missing-ref.json"),
		filepath.Join(workspacePath, "workflow.closure-package.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/closure-package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing release readiness reference, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "releaseReadinessReference") {
		t.Fatalf("expected release readiness validation diagnostic, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowClosurePackageExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	timelineJSONPath := filepath.Join(workspacePath, "workflow.receipt-timeline.json")
	timeline := workflowReceiptTimelineResponse{}
	timelineBytes, err := os.ReadFile(timelineJSONPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(timelineBytes, &timeline); err != nil {
		t.Fatal(err)
	}
	timeline.Timeline.Continuity.AuthorizationID = testCLIDigest('d')
	corruptedTimeline, err := json.MarshalIndent(timeline, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corruptedTimeline = append(corruptedTimeline, '\n')
	if err := os.WriteFile(timelineJSONPath, corruptedTimeline, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"manifestPath":%q,"auditPath":%q,"releaseReadinessReference":"release-checklist-001"}`,
		filepath.Join(workspacePath, "workflow.closure-package.mismatch.json"),
		filepath.Join(workspacePath, "workflow.closure-package.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/closure-package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-CLS-003") {
		t.Fatalf("expected deterministic closure blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowClosureReviewGateEvaluatesApprovedDecision(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/closure-package/review-gate?releaseReadinessReference=release-checklist-001&reviewerReference=ticket-456&decision=approve", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for closure review gate, got %d: %s", recorder.Code, recorder.Body.String())
	}
	payload := workflowClosureReviewGateResponse{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode closure review gate response: %v", err)
	}
	if payload.Gate.Outcome != "passed" || payload.Gate.Decision != "approved" {
		t.Fatalf("expected passed approved review gate, got %#v", payload.Gate)
	}
}

func TestServeWorkflowClosureReviewGateRejectsMalformedDecision(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/closure-package/review-gate?releaseReadinessReference=release-checklist-001&reviewerReference=ticket-456&decision=ship-it", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed review decision, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "decision must be one of") {
		t.Fatalf("expected decision validation diagnostic, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowClosureReviewGateExportWritesArtifactsAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	markdownPath := filepath.Join(workspacePath, "workflow.closure-review-gate.export.md")
	jsonPath := filepath.Join(workspacePath, "workflow.closure-review-gate.export.json")
	auditPath := filepath.Join(workspacePath, "workflow.closure-review-gate.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"releaseReadinessReference":"release-checklist-001","reviewerReference":"ticket-456","decision":"blocked","markdownPath":%q,"jsonPath":%q,"auditPath":%q}`, markdownPath, jsonPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/closure-package/review-gate/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for closure review gate export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	markdownBytes, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatalf("read closure review gate markdown: %v", err)
	}
	if !strings.Contains(string(markdownBytes), "## Decision") {
		t.Fatalf("expected decision section in closure review gate markdown, got %s", string(markdownBytes))
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load closure review gate audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for closure review gate export")
	}
}

func TestServeWorkflowReleaseDecisionExportWritesLedgerAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	ledgerPath := filepath.Join(workspacePath, "workflow.release-decision.json")
	auditPath := filepath.Join(workspacePath, "workflow.release-decision.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"releaseReadinessReference":"release-checklist-001","reviewerReference":"ticket-456","decision":"approved","operatorReference":"operator-1","decisionTimestamp":"2026-07-21T00:05:00Z","ledgerPath":%q,"auditPath":%q}`, ledgerPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-decision/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for release decision export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	ledgerBytes, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("read release decision ledger: %v", err)
	}
	ledger := workflowReleaseDecisionLedger{}
	if err := json.Unmarshal(ledgerBytes, &ledger); err != nil {
		t.Fatalf("decode release decision ledger: %v", err)
	}
	if ledger.Ledger.PublicationState != "ready-to-publish" {
		t.Fatalf("expected ready-to-publish ledger state, got %#v", ledger.Ledger)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load release decision audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for release decision export")
	}
}

func TestServeWorkflowReleaseDecisionExportRejectsMissingDecisionTimestamp(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"releaseReadinessReference":"release-checklist-001","reviewerReference":"ticket-456","decision":"approved","operatorReference":"operator-1","ledgerPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-decision.json"),
		filepath.Join(workspacePath, "workflow.release-decision.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-decision/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing decision timestamp, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "decisionTimestamp") {
		t.Fatalf("expected decision timestamp diagnostic, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleaseDecisionExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	reviewGatePath := filepath.Join(workspacePath, "workflow.closure-review-gate.json")
	gate := workflowClosureReviewGateResponse{}
	gateBytes, err := os.ReadFile(reviewGatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(gateBytes, &gate); err != nil {
		t.Fatal(err)
	}
	gate.Gate.Continuity.AuthorizationID = testCLIDigest('f')
	corrupted, err := json.MarshalIndent(gate, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(reviewGatePath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"releaseReadinessReference":"release-checklist-001","reviewerReference":"ticket-456","decision":"approved","operatorReference":"operator-1","decisionTimestamp":"2026-07-21T00:05:00Z","ledgerPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-decision.mismatch.json"),
		filepath.Join(workspacePath, "workflow.release-decision.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-decision/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RDL-006") {
		t.Fatalf("expected deterministic release-decision blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationExportWritesAttestationAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	handler := serveHandlerFixture(t, false, workspacePath)
	attestationPath := filepath.Join(workspacePath, "workflow.release-publication.json")
	auditPath := filepath.Join(workspacePath, "workflow.release-publication.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"publicationChannel":"github-release","artifactLocationReference":"gh://releases/v0.2.0-alpha.2","publicationTimestamp":"2026-07-21T00:10:00Z","operatorReference":"operator-2","attestationPath":%q,"auditPath":%q}`, attestationPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for release publication export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	attestationBytes, err := os.ReadFile(attestationPath)
	if err != nil {
		t.Fatalf("read release publication attestation: %v", err)
	}
	attestation := workflowReleasePublicationAttestation{}
	if err := json.Unmarshal(attestationBytes, &attestation); err != nil {
		t.Fatalf("decode release publication attestation: %v", err)
	}
	if attestation.Publication.PublicationState != "publishable" {
		t.Fatalf("expected publishable attestation state, got %#v", attestation.Publication)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load release publication audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for release publication export")
	}
}

func TestServeWorkflowReleasePublicationExportRejectsBlockedReleaseDecision(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "blocked")
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"publicationChannel":"github-release","artifactLocationReference":"gh://releases/v0.2.0-alpha.2","publicationTimestamp":"2026-07-21T00:10:00Z","operatorReference":"operator-2","attestationPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.json"),
		filepath.Join(workspacePath, "workflow.release-publication.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked release decision, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPB-003") {
		t.Fatalf("expected release publication blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	ledgerPath := writeReleaseDecisionFixture(t, workspacePath, "approved")
	ledger := workflowReleaseDecisionLedger{}
	ledgerBytes, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ledgerBytes, &ledger); err != nil {
		t.Fatal(err)
	}
	ledger.Ledger.ClosurePackage.Digest = testCLIDigest('e')
	corrupted, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(ledgerPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"publicationChannel":"github-release","artifactLocationReference":"gh://releases/v0.2.0-alpha.2","publicationTimestamp":"2026-07-21T00:10:00Z","operatorReference":"operator-2","attestationPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.mismatch.json"),
		filepath.Join(workspacePath, "workflow.release-publication.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for release publication continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPB-005") {
		t.Fatalf("expected release publication continuity blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationIndexExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.release-publication.index.json")
	auditPath := filepath.Join(workspacePath, "workflow.release-publication.index.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"publicationBatchReference":"batch-2026-07-21","operatorReference":"operator-3","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/index/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for release publication index export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read release publication index manifest: %v", err)
	}
	manifest := workflowReleasePublicationIndexManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode release publication index manifest: %v", err)
	}
	if manifest.Index.IndexState != "index-ready" {
		t.Fatalf("expected index-ready state, got %#v", manifest.Index)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load release publication index audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for release publication index export")
	}
}

func TestServeWorkflowReleasePublicationIndexExportRejectsBlockedAttestation(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	attestationPath := writeReleasePublicationFixture(t, workspacePath)
	attestation := workflowReleasePublicationAttestation{}
	attestationBytes, err := os.ReadFile(attestationPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(attestationBytes, &attestation); err != nil {
		t.Fatal(err)
	}
	attestation.Publication.PublicationState = "blocked"
	attestation.Publication.BlockerCode = "YARA-RPB-003"
	corrupted, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(attestationPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"publicationBatchReference":"batch-2026-07-21","operatorReference":"operator-3","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.index.json"),
		filepath.Join(workspacePath, "workflow.release-publication.index.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/index/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked release publication attestation, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPI-003") {
		t.Fatalf("expected release publication index blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationIndexExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	attestationPath := writeReleasePublicationFixture(t, workspacePath)
	attestation := workflowReleasePublicationAttestation{}
	attestationBytes, err := os.ReadFile(attestationPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(attestationBytes, &attestation); err != nil {
		t.Fatal(err)
	}
	attestation.Publication.ReleaseDecision.Digest = testCLIDigest('d')
	corrupted, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(attestationPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"publicationBatchReference":"batch-2026-07-21","operatorReference":"operator-3","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.index.mismatch.json"),
		filepath.Join(workspacePath, "workflow.release-publication.index.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/index/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for release publication index digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPI-007") {
		t.Fatalf("expected release publication index digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationPackageExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.release-publication.package.json")
	auditPath := filepath.Join(workspacePath, "workflow.release-publication.package.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"packageReference":"package-2026-07-21","publicationWindowReference":"window-2026w30","operatorReference":"operator-4","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for release publication package export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read release publication package manifest: %v", err)
	}
	manifest := workflowReleasePublicationPackageManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode release publication package manifest: %v", err)
	}
	if manifest.Package.PackageState != "package-ready" {
		t.Fatalf("expected package-ready state, got %#v", manifest.Package)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load release publication package audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for release publication package export")
	}
}

func TestServeWorkflowReleasePublicationPackageExportRejectsBlockedIndex(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	indexPath := writeReleasePublicationIndexFixture(t, workspacePath)
	index := workflowReleasePublicationIndexManifest{}
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatal(err)
	}
	index.Index.IndexState = "blocked"
	index.Index.BlockerCode = "YARA-RPI-003"
	corrupted, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(indexPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"packageReference":"package-2026-07-21","publicationWindowReference":"window-2026w30","operatorReference":"operator-4","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.package.json"),
		filepath.Join(workspacePath, "workflow.release-publication.package.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked release publication index, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPK-003") {
		t.Fatalf("expected release publication package blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationPackageExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	indexPath := writeReleasePublicationIndexFixture(t, workspacePath)
	index := workflowReleasePublicationIndexManifest{}
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatal(err)
	}
	index.Index.ReleasePublication.Digest = testCLIDigest('c')
	corrupted, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(indexPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"packageReference":"package-2026-07-21","publicationWindowReference":"window-2026w30","operatorReference":"operator-4","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.package.mismatch.json"),
		filepath.Join(workspacePath, "workflow.release-publication.package.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for release publication package digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPK-006") {
		t.Fatalf("expected release publication package digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationEnvelopeExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.release-publication.envelope.json")
	auditPath := filepath.Join(workspacePath, "workflow.release-publication.envelope.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"deliveryReference":"delivery-2026-07-21","destinationReference":"release-ops://handoff","operatorReference":"operator-5","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/envelope/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for release publication envelope export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read release publication envelope manifest: %v", err)
	}
	manifest := workflowReleasePublicationEnvelopeManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode release publication envelope manifest: %v", err)
	}
	if manifest.Envelope.DeliveryState != "delivery-ready" {
		t.Fatalf("expected delivery-ready state, got %#v", manifest.Envelope)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load release publication envelope audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for release publication envelope export")
	}
}

func TestServeWorkflowReleasePublicationEnvelopeExportRejectsBlockedPackage(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	packagePath := writeReleasePublicationPackageFixture(t, workspacePath)
	manifest := workflowReleasePublicationPackageManifest{}
	manifestBytes, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Package.PackageState = "blocked"
	manifest.Package.BlockerCode = "YARA-RPK-003"
	corrupted, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(packagePath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"deliveryReference":"delivery-2026-07-21","destinationReference":"release-ops://handoff","operatorReference":"operator-5","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.envelope.json"),
		filepath.Join(workspacePath, "workflow.release-publication.envelope.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/envelope/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked release publication package, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPE-003") {
		t.Fatalf("expected release publication envelope blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationEnvelopeExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	packagePath := writeReleasePublicationPackageFixture(t, workspacePath)
	manifest := workflowReleasePublicationPackageManifest{}
	manifestBytes, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Package.ReleasePublicationIndex.Digest = testCLIDigest('b')
	corrupted, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(packagePath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"deliveryReference":"delivery-2026-07-21","destinationReference":"release-ops://handoff","operatorReference":"operator-5","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.envelope.mismatch.json"),
		filepath.Join(workspacePath, "workflow.release-publication.envelope.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/envelope/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for release publication envelope digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPE-005") {
		t.Fatalf("expected release publication envelope digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationHandoffReceiptExportWritesReceiptAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	receiptPath := filepath.Join(workspacePath, "workflow.release-publication.handoff-receipt.json")
	auditPath := filepath.Join(workspacePath, "workflow.release-publication.handoff-receipt.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"receiverReference":"release-ops-team","handoffTimestamp":"2026-07-21T00:20:00Z","operatorReference":"operator-6","receiptPath":%q,"auditPath":%q}`, receiptPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/handoff-receipt/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for release publication handoff receipt export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	receiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read release publication handoff receipt: %v", err)
	}
	receipt := workflowReleasePublicationHandoffReceipt{}
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatalf("decode release publication handoff receipt: %v", err)
	}
	if receipt.Handoff.HandoffState != "handoff-ready" {
		t.Fatalf("expected handoff-ready state, got %#v", receipt.Handoff)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load release publication handoff receipt audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for release publication handoff receipt export")
	}
}

func TestServeWorkflowReleasePublicationHandoffReceiptExportRejectsBlockedEnvelope(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	envelopePath := writeReleasePublicationEnvelopeFixture(t, workspacePath)
	manifest := workflowReleasePublicationEnvelopeManifest{}
	manifestBytes, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Envelope.DeliveryState = "blocked"
	manifest.Envelope.BlockerCode = "YARA-RPE-003"
	corrupted, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(envelopePath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"receiverReference":"release-ops-team","handoffTimestamp":"2026-07-21T00:20:00Z","operatorReference":"operator-6","receiptPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.handoff-receipt.json"),
		filepath.Join(workspacePath, "workflow.release-publication.handoff-receipt.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/handoff-receipt/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked release publication envelope, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RHR-003") {
		t.Fatalf("expected release publication handoff receipt blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationHandoffReceiptExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	envelopePath := writeReleasePublicationEnvelopeFixture(t, workspacePath)
	manifest := workflowReleasePublicationEnvelopeManifest{}
	manifestBytes, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Envelope.ReleasePublicationPackage.Digest = testCLIDigest('a')
	corrupted, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(envelopePath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"receiverReference":"release-ops-team","handoffTimestamp":"2026-07-21T00:20:00Z","operatorReference":"operator-6","receiptPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.handoff-receipt.mismatch.json"),
		filepath.Join(workspacePath, "workflow.release-publication.handoff-receipt.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/handoff-receipt/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for release publication handoff receipt digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RHR-005") {
		t.Fatalf("expected release publication handoff receipt digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationAcknowledgmentExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.release-publication.acknowledgment.json")
	auditPath := filepath.Join(workspacePath, "workflow.release-publication.acknowledgment.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"acknowledgmentReference":"ack-2026-07-21","acknowledgedByReference":"release-ops-team","acknowledgmentTimestamp":"2026-07-21T00:30:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/acknowledgment/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for release publication acknowledgment export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read release publication acknowledgment manifest: %v", err)
	}
	manifest := workflowReleasePublicationAcknowledgmentManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode release publication acknowledgment manifest: %v", err)
	}
	if manifest.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" {
		t.Fatalf("expected acknowledgment-ready state, got %#v", manifest.Acknowledgment)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load release publication acknowledgment audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for release publication acknowledgment export")
	}
}

func TestServeWorkflowReleasePublicationAcknowledgmentExportRejectsBlockedHandoff(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	handoffPath := writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	receipt := workflowReleasePublicationHandoffReceipt{}
	receiptBytes, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.Handoff.HandoffState = "blocked"
	receipt.Handoff.BlockerCode = "YARA-RHR-003"
	corrupted, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(handoffPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"acknowledgmentReference":"ack-2026-07-21","acknowledgedByReference":"release-ops-team","acknowledgmentTimestamp":"2026-07-21T00:30:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.acknowledgment.json"),
		filepath.Join(workspacePath, "workflow.release-publication.acknowledgment.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/acknowledgment/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked handoff receipt, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RAK-003") {
		t.Fatalf("expected release publication acknowledgment blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowReleasePublicationAcknowledgmentExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	handoffPath := writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	receipt := workflowReleasePublicationHandoffReceipt{}
	receiptBytes, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.Handoff.ReleasePublicationEnvelope.Digest = testCLIDigest('9')
	corrupted, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(handoffPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"acknowledgmentReference":"ack-2026-07-21","acknowledgedByReference":"release-ops-team","acknowledgmentTimestamp":"2026-07-21T00:30:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.release-publication.acknowledgment.mismatch.json"),
		filepath.Join(workspacePath, "workflow.release-publication.acknowledgment.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/release-publication/acknowledgment/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for release publication acknowledgment digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RAK-005") {
		t.Fatalf("expected release publication acknowledgment digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureSummaryExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-summary.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-summary.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"summaryReference":"closure-summary-2026-07-21","operatorReference":"operator-8","summaryTimestamp":"2026-07-21T00:40:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-summary/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for rollout closure summary export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read rollout closure summary manifest: %v", err)
	}
	manifest := workflowRolloutClosureSummaryManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode rollout closure summary manifest: %v", err)
	}
	if manifest.Summary.SummaryState != "summary-ready" {
		t.Fatalf("expected summary-ready state, got %#v", manifest.Summary)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load rollout closure summary audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for rollout closure summary export")
	}
}

func TestServeWorkflowRolloutClosureSummaryExportRejectsBlockedAcknowledgment(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	acknowledgmentPath := writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	manifest := workflowReleasePublicationAcknowledgmentManifest{}
	manifestBytes, err := os.ReadFile(acknowledgmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Acknowledgment.AcknowledgmentState = "blocked"
	manifest.Acknowledgment.BlockerCode = "YARA-RAK-003"
	corrupted, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(acknowledgmentPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"summaryReference":"closure-summary-2026-07-21","operatorReference":"operator-8","summaryTimestamp":"2026-07-21T00:40:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-summary.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-summary.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-summary/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked acknowledgment, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCS-006") {
		t.Fatalf("expected rollout closure summary blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureSummaryExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	acknowledgmentPath := writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	manifest := workflowReleasePublicationAcknowledgmentManifest{}
	manifestBytes, err := os.ReadFile(acknowledgmentPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Acknowledgment.ReleasePublicationEnvelope.Digest = testCLIDigest('1')
	corrupted, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(acknowledgmentPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"summaryReference":"closure-summary-2026-07-21","operatorReference":"operator-8","summaryTimestamp":"2026-07-21T00:40:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-summary.mismatch.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-summary.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-summary/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for rollout closure summary digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCS-009") {
		t.Fatalf("expected rollout closure summary digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureDeliveryExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-delivery.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-delivery.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"deliveryReference":"closure-delivery-2026-07-21","destinationReference":"release-ops://final-transfer","operatorReference":"operator-9","deliveryTimestamp":"2026-07-21T00:50:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-delivery/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for rollout closure delivery export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read rollout closure delivery manifest: %v", err)
	}
	manifest := workflowRolloutClosureDeliveryManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode rollout closure delivery manifest: %v", err)
	}
	if manifest.Delivery.DeliveryRecordState != "delivery-record-ready" {
		t.Fatalf("expected delivery-record-ready state, got %#v", manifest.Delivery)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load rollout closure delivery audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for rollout closure delivery export")
	}
}

func TestServeWorkflowRolloutClosureDeliveryExportRejectsBlockedSummary(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	summaryPath := writeRolloutClosureSummaryFixture(t, workspacePath)
	summary := workflowRolloutClosureSummaryManifest{}
	summaryBytes, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatal(err)
	}
	summary.Summary.SummaryState = "blocked"
	summary.Summary.BlockerCode = "YARA-RCS-006"
	corrupted, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(summaryPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"deliveryReference":"closure-delivery-2026-07-21","destinationReference":"release-ops://final-transfer","operatorReference":"operator-9","deliveryTimestamp":"2026-07-21T00:50:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-delivery.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-delivery.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-delivery/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked rollout closure summary, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCD-003") {
		t.Fatalf("expected rollout closure delivery blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureDeliveryExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	summaryPath := writeRolloutClosureSummaryFixture(t, workspacePath)
	summary := workflowRolloutClosureSummaryManifest{}
	summaryBytes, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatal(err)
	}
	summary.Summary.Acknowledgment.Digest = testCLIDigest('2')
	corrupted, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(summaryPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"deliveryReference":"closure-delivery-2026-07-21","destinationReference":"release-ops://final-transfer","operatorReference":"operator-9","deliveryTimestamp":"2026-07-21T00:50:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-delivery.mismatch.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-delivery.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-delivery/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for rollout closure delivery digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCD-007") {
		t.Fatalf("expected rollout closure delivery digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureAcceptanceExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-acceptance.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-acceptance.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"acceptanceReference":"closure-acceptance-2026-07-21","acceptedByReference":"receiver-team-1","acceptanceTimestamp":"2026-07-21T00:55:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-acceptance/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for rollout closure acceptance export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read rollout closure acceptance manifest: %v", err)
	}
	manifest := workflowRolloutClosureAcceptanceManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode rollout closure acceptance manifest: %v", err)
	}
	if manifest.Acceptance.AcceptanceState != "acceptance-ready" {
		t.Fatalf("expected acceptance-ready state, got %#v", manifest.Acceptance)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load rollout closure acceptance audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for rollout closure acceptance export")
	}
}

func TestServeWorkflowRolloutClosureAcceptanceExportRejectsBlockedDeliveryRecord(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	deliveryPath := writeRolloutClosureDeliveryFixture(t, workspacePath)
	delivery := workflowRolloutClosureDeliveryManifest{}
	deliveryBytes, err := os.ReadFile(deliveryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(deliveryBytes, &delivery); err != nil {
		t.Fatal(err)
	}
	delivery.Delivery.DeliveryRecordState = "blocked"
	delivery.Delivery.BlockerCode = "YARA-RCD-003"
	corrupted, err := json.MarshalIndent(delivery, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(deliveryPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"acceptanceReference":"closure-acceptance-2026-07-21","acceptedByReference":"receiver-team-1","acceptanceTimestamp":"2026-07-21T00:55:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-acceptance.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-acceptance.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-acceptance/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked rollout closure delivery record, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCA-003") {
		t.Fatalf("expected rollout closure acceptance blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureAcceptanceExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	deliveryPath := writeRolloutClosureDeliveryFixture(t, workspacePath)
	delivery := workflowRolloutClosureDeliveryManifest{}
	deliveryBytes, err := os.ReadFile(deliveryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(deliveryBytes, &delivery); err != nil {
		t.Fatal(err)
	}
	delivery.Delivery.ClosureSummary.Digest = testCLIDigest('3')
	corrupted, err := json.MarshalIndent(delivery, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(deliveryPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"acceptanceReference":"closure-acceptance-2026-07-21","acceptedByReference":"receiver-team-1","acceptanceTimestamp":"2026-07-21T00:55:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-acceptance.mismatch.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-acceptance.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-acceptance/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for rollout closure acceptance digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCA-006") {
		t.Fatalf("expected rollout closure acceptance digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureCertificateExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-certificate.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-certificate.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"certificateReference":"closure-certificate-2026-07-21","issuedByReference":"release-authority-1","issuedTimestamp":"2026-07-21T01:00:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-certificate/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for rollout closure certificate export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read rollout closure certificate manifest: %v", err)
	}
	manifest := workflowRolloutClosureCertificateManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode rollout closure certificate manifest: %v", err)
	}
	if manifest.Certificate.CertificateState != "certificate-ready" {
		t.Fatalf("expected certificate-ready state, got %#v", manifest.Certificate)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load rollout closure certificate audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for rollout closure certificate export")
	}
}

func TestServeWorkflowRolloutClosureCertificateExportRejectsBlockedAcceptance(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	acceptancePath := writeRolloutClosureAcceptanceFixture(t, workspacePath)
	acceptance := workflowRolloutClosureAcceptanceManifest{}
	acceptanceBytes, err := os.ReadFile(acceptancePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(acceptanceBytes, &acceptance); err != nil {
		t.Fatal(err)
	}
	acceptance.Acceptance.AcceptanceState = "blocked"
	acceptance.Acceptance.BlockerCode = "YARA-RCA-003"
	corrupted, err := json.MarshalIndent(acceptance, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(acceptancePath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"certificateReference":"closure-certificate-2026-07-21","issuedByReference":"release-authority-1","issuedTimestamp":"2026-07-21T01:00:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-certificate.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-certificate.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-certificate/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked rollout closure acceptance receipt, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCC-003") {
		t.Fatalf("expected rollout closure certificate blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureCertificateExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	acceptancePath := writeRolloutClosureAcceptanceFixture(t, workspacePath)
	acceptance := workflowRolloutClosureAcceptanceManifest{}
	acceptanceBytes, err := os.ReadFile(acceptancePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(acceptanceBytes, &acceptance); err != nil {
		t.Fatal(err)
	}
	acceptance.Acceptance.DeliveryRecord.Digest = testCLIDigest('4')
	corrupted, err := json.MarshalIndent(acceptance, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(acceptancePath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"certificateReference":"closure-certificate-2026-07-21","issuedByReference":"release-authority-1","issuedTimestamp":"2026-07-21T01:00:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-certificate.mismatch.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-certificate.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-certificate/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for rollout closure certificate digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCC-006") {
		t.Fatalf("expected rollout closure certificate digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureLedgerExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-ledger.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-ledger.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"ledgerReference":"closure-ledger-2026-07-21","recordedByReference":"archive-operator-1","recordedTimestamp":"2026-07-21T01:05:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-ledger/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for rollout closure ledger export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read rollout closure ledger manifest: %v", err)
	}
	manifest := workflowRolloutClosureLedgerManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode rollout closure ledger manifest: %v", err)
	}
	if manifest.Ledger.LedgerState != "ledger-ready" {
		t.Fatalf("expected ledger-ready state, got %#v", manifest.Ledger)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load rollout closure ledger audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for rollout closure ledger export")
	}
}

func TestServeWorkflowRolloutClosureLedgerExportRejectsBlockedCertificate(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	certificatePath := writeRolloutClosureCertificateFixture(t, workspacePath)
	certificate := workflowRolloutClosureCertificateManifest{}
	certificateBytes, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(certificateBytes, &certificate); err != nil {
		t.Fatal(err)
	}
	certificate.Certificate.CertificateState = "blocked"
	certificate.Certificate.BlockerCode = "YARA-RCC-003"
	corrupted, err := json.MarshalIndent(certificate, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(certificatePath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"ledgerReference":"closure-ledger-2026-07-21","recordedByReference":"archive-operator-1","recordedTimestamp":"2026-07-21T01:05:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-ledger.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-ledger.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-ledger/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked rollout closure certificate, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RLG-003") {
		t.Fatalf("expected rollout closure ledger blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureLedgerExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	certificatePath := writeRolloutClosureCertificateFixture(t, workspacePath)
	certificate := workflowRolloutClosureCertificateManifest{}
	certificateBytes, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(certificateBytes, &certificate); err != nil {
		t.Fatal(err)
	}
	certificate.Certificate.AcceptanceReceipt.Digest = testCLIDigest('5')
	corrupted, err := json.MarshalIndent(certificate, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(certificatePath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"ledgerReference":"closure-ledger-2026-07-21","recordedByReference":"archive-operator-1","recordedTimestamp":"2026-07-21T01:05:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-ledger.mismatch.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-ledger.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-ledger/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for rollout closure ledger digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RLG-006") {
		t.Fatalf("expected rollout closure ledger digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureDocketExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-docket.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-docket.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"docketReference":"closure-docket-2026-07-21","preparedByReference":"handoff-preparer-1","preparedTimestamp":"2026-07-21T01:10:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-docket/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for rollout closure docket export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read rollout closure docket manifest: %v", err)
	}
	manifest := workflowRolloutClosureDocketManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode rollout closure docket manifest: %v", err)
	}
	if manifest.Docket.DocketState != "docket-ready" {
		t.Fatalf("expected docket-ready state, got %#v", manifest.Docket)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load rollout closure docket audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for rollout closure docket export")
	}
}

func TestServeWorkflowRolloutClosureDocketExportRejectsBlockedLedger(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	ledgerPath := writeRolloutClosureLedgerFixture(t, workspacePath)
	ledger := workflowRolloutClosureLedgerManifest{}
	ledgerBytes, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ledgerBytes, &ledger); err != nil {
		t.Fatal(err)
	}
	ledger.Ledger.LedgerState = "blocked"
	ledger.Ledger.BlockerCode = "YARA-RLG-003"
	corrupted, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(ledgerPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"docketReference":"closure-docket-2026-07-21","preparedByReference":"handoff-preparer-1","preparedTimestamp":"2026-07-21T01:10:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-docket.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-docket.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-docket/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked rollout closure ledger, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RDK-003") {
		t.Fatalf("expected rollout closure docket blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureDocketExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	ledgerPath := writeRolloutClosureLedgerFixture(t, workspacePath)
	ledger := workflowRolloutClosureLedgerManifest{}
	ledgerBytes, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ledgerBytes, &ledger); err != nil {
		t.Fatal(err)
	}
	ledger.Ledger.PublicationCertificate.Digest = testCLIDigest('6')
	corrupted, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(ledgerPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"docketReference":"closure-docket-2026-07-21","preparedByReference":"handoff-preparer-1","preparedTimestamp":"2026-07-21T01:10:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-docket.mismatch.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-docket.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-docket/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for rollout closure docket digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RDK-006") {
		t.Fatalf("expected rollout closure docket digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureBulletinExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-bulletin.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-bulletin.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"bulletinReference":"closure-bulletin-2026-07-21","publishedByReference":"release-publisher-1","publishedTimestamp":"2026-07-21T01:15:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-bulletin/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for rollout closure bulletin export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read rollout closure bulletin manifest: %v", err)
	}
	manifest := workflowRolloutClosureBulletinManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode rollout closure bulletin manifest: %v", err)
	}
	if manifest.Bulletin.BulletinState != "bulletin-ready" {
		t.Fatalf("expected bulletin-ready state, got %#v", manifest.Bulletin)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load rollout closure bulletin audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for rollout closure bulletin export")
	}
}

func TestServeWorkflowRolloutClosureBulletinExportRejectsBlockedDocket(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	docketPath := writeRolloutClosureDocketFixture(t, workspacePath)
	docket := workflowRolloutClosureDocketManifest{}
	docketBytes, err := os.ReadFile(docketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(docketBytes, &docket); err != nil {
		t.Fatal(err)
	}
	docket.Docket.DocketState = "blocked"
	docket.Docket.BlockerCode = "YARA-RDK-003"
	corrupted, err := json.MarshalIndent(docket, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(docketPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"bulletinReference":"closure-bulletin-2026-07-21","publishedByReference":"release-publisher-1","publishedTimestamp":"2026-07-21T01:15:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-bulletin.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-bulletin.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-bulletin/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked rollout closure docket, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RBL-003") {
		t.Fatalf("expected rollout closure bulletin blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureBulletinExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	docketPath := writeRolloutClosureDocketFixture(t, workspacePath)
	docket := workflowRolloutClosureDocketManifest{}
	docketBytes, err := os.ReadFile(docketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(docketBytes, &docket); err != nil {
		t.Fatal(err)
	}
	docket.Docket.ArchivalLedger.Digest = testCLIDigest('7')
	corrupted, err := json.MarshalIndent(docket, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(docketPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"bulletinReference":"closure-bulletin-2026-07-21","publishedByReference":"release-publisher-1","publishedTimestamp":"2026-07-21T01:15:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-bulletin.mismatch.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-bulletin.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-bulletin/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for rollout closure bulletin digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RBL-006") {
		t.Fatalf("expected rollout closure bulletin digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosurePacketExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-packet.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-packet.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"packetReference":"closure-packet-2026-07-21","packagedByReference":"release-packager-1","packagedTimestamp":"2026-07-21T01:20:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-packet/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for rollout closure packet export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read rollout closure packet manifest: %v", err)
	}
	manifest := workflowRolloutClosurePacketManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode rollout closure packet manifest: %v", err)
	}
	if manifest.Packet.PacketState != "packet-ready" {
		t.Fatalf("expected packet-ready state, got %#v", manifest.Packet)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load rollout closure packet audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for rollout closure packet export")
	}
}

func TestServeWorkflowRolloutClosurePacketExportRejectsBlockedBulletin(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	bulletinPath := writeRolloutClosureBulletinFixture(t, workspacePath)
	bulletin := workflowRolloutClosureBulletinManifest{}
	bulletinBytes, err := os.ReadFile(bulletinPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bulletinBytes, &bulletin); err != nil {
		t.Fatal(err)
	}
	bulletin.Bulletin.BulletinState = "blocked"
	bulletin.Bulletin.BlockerCode = "YARA-RBL-003"
	corrupted, err := json.MarshalIndent(bulletin, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(bulletinPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"packetReference":"closure-packet-2026-07-21","packagedByReference":"release-packager-1","packagedTimestamp":"2026-07-21T01:20:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-packet.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-packet.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-packet/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked rollout closure bulletin, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPT-003") {
		t.Fatalf("expected rollout closure packet blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosurePacketExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	bulletinPath := writeRolloutClosureBulletinFixture(t, workspacePath)
	bulletin := workflowRolloutClosureBulletinManifest{}
	bulletinBytes, err := os.ReadFile(bulletinPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bulletinBytes, &bulletin); err != nil {
		t.Fatal(err)
	}
	bulletin.Bulletin.HandoffDocket.Digest = testCLIDigest('8')
	corrupted, err := json.MarshalIndent(bulletin, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(bulletinPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"packetReference":"closure-packet-2026-07-21","packagedByReference":"release-packager-1","packagedTimestamp":"2026-07-21T01:20:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-packet.mismatch.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-packet.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-packet/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for rollout closure packet digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPT-006") {
		t.Fatalf("expected rollout closure packet digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureRecipientPackageExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-recipient-package.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-recipient-package.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"recipientPackageReference":"recipient-package-2026-07-21","preparedForReference":"recipient-ops-1","preparedTimestamp":"2026-07-21T01:25:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-recipient-package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for rollout closure recipient package export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read rollout closure recipient package manifest: %v", err)
	}
	manifest := workflowRolloutClosureRecipientPackageManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode rollout closure recipient package manifest: %v", err)
	}
	if manifest.RecipientPackage.RecipientPackageState != "recipient-package-ready" {
		t.Fatalf("expected recipient-package-ready state, got %#v", manifest.RecipientPackage)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load rollout closure recipient package audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected audit events for rollout closure recipient package export")
	}
}

func TestServeWorkflowRolloutClosureRecipientPackageExportRejectsBlockedPacket(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	packetPath := writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	packet := workflowRolloutClosurePacketManifest{}
	packetBytes, err := os.ReadFile(packetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(packetBytes, &packet); err != nil {
		t.Fatal(err)
	}
	packet.Packet.PacketState = "blocked"
	packet.Packet.BlockerCode = "YARA-RPT-003"
	corrupted, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(packetPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"recipientPackageReference":"recipient-package-2026-07-21","preparedForReference":"recipient-ops-1","preparedTimestamp":"2026-07-21T01:25:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-recipient-package.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-recipient-package.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-recipient-package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked rollout closure packet, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPKG-003") {
		t.Fatalf("expected rollout closure recipient package blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureRecipientPackageExportRejectsDigestMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	packetPath := writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	packet := workflowRolloutClosurePacketManifest{}
	packetBytes, err := os.ReadFile(packetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(packetBytes, &packet); err != nil {
		t.Fatal(err)
	}
	packet.Packet.ReleaseBulletin.Digest = testCLIDigest('9')
	corrupted, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	corrupted = append(corrupted, '\n')
	if err := os.WriteFile(packetPath, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"recipientPackageReference":"recipient-package-2026-07-21","preparedForReference":"recipient-ops-1","preparedTimestamp":"2026-07-21T01:25:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-recipient-package.mismatch.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-recipient-package.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure-recipient-package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for rollout closure recipient package digest mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RPKG-006") {
		t.Fatalf("expected rollout closure recipient package digest blocker code, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPassesForReadyChain(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/rollout-closure/verify", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200 for rollout closure verify, got %d: %s", recorder.Code, recorder.Body.String())
	}
	response := workflowRolloutClosureVerifyResponse{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode rollout closure verify response: %v", err)
	}
	if !response.Verification.Ready || response.Verification.VerificationState != "pass" {
		t.Fatalf("expected pass verification, got %#v", response.Verification)
	}
	if len(response.Verification.Coverage) != 18 {
		t.Fatalf("expected 18 coverage entries, got %d", len(response.Verification.Coverage))
	}
}

func TestServeWorkflowRolloutClosureVerifyFailsClosedOnBlockedState(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	packetPath := writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	packet := workflowRolloutClosurePacketManifest{}
	packetBytes, err := os.ReadFile(packetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(packetBytes, &packet); err != nil {
		t.Fatal(err)
	}
	packet.Packet.PacketState = "blocked"
	packet.Packet.BlockerCode = "YARA-RPT-003"
	updatedPacket, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedPacket = append(updatedPacket, '\n')
	if err := os.WriteFile(packetPath, updatedPacket, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/workflow/rollout-closure/verify", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200 for blocked rollout closure verify, got %d: %s", recorder.Code, recorder.Body.String())
	}
	response := workflowRolloutClosureVerifyResponse{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode rollout closure verify response: %v", err)
	}
	if response.Verification.Ready || response.Verification.VerificationState != "blocked" {
		t.Fatalf("expected blocked verification response, got %#v", response.Verification)
	}
	if response.Verification.BlockerCode != "YARA-RCV-003" {
		t.Fatalf("expected YARA-RCV-003 blocker code, got %#v", response.Verification.BlockerCode)
	}
}

func TestServeWorkflowRolloutClosureVerifyExportWritesBundleAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	handler := serveHandlerFixture(t, false, workspacePath)
	markdownPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.md")
	jsonPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationReference":"verify-2026-07-21","operatorReference":"operator-verify-1","verificationTimestamp":"2026-07-21T01:35:00Z","markdownPath":%q,"jsonPath":%q,"auditPath":%q}`, markdownPath, jsonPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200 for rollout closure verify export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, err := os.ReadFile(markdownPath); err != nil {
		t.Fatalf("read verify export markdown: %v", err)
	}
	jsonBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read verify export json: %v", err)
	}
	bundle := workflowRolloutClosureVerifyExportBundle{}
	if err := json.Unmarshal(jsonBytes, &bundle); err != nil {
		t.Fatalf("decode verify export json: %v", err)
	}
	if !bundle.Export.Ready || bundle.Export.VerificationState != "pass" {
		t.Fatalf("expected pass verify export bundle, got %#v", bundle.Export)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify export audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify export audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyExportRejectsBlockedWithoutOverride(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	packetPath := writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	packet := workflowRolloutClosurePacketManifest{}
	packetBytes, err := os.ReadFile(packetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(packetBytes, &packet); err != nil {
		t.Fatal(err)
	}
	packet.Packet.PacketState = "blocked"
	packet.Packet.BlockerCode = "YARA-RPT-003"
	updatedPacket, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedPacket = append(updatedPacket, '\n')
	if err := os.WriteFile(packetPath, updatedPacket, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationReference":"verify-2026-07-21","operatorReference":"operator-verify-1","verificationTimestamp":"2026-07-21T01:35:00Z","markdownPath":%q,"jsonPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.md"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected status 422 for blocked verify export without override, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVX-003") {
		t.Fatalf("expected YARA-RCVX-003 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyAttestationExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.attestation.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.attestation.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"attestationReference":"attestation-2026-07-21","attestedByReference":"audit-operator-1","attestationTimestamp":"2026-07-21T01:40:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/attest", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify attestation export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify attestation manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyAttestationManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify attestation manifest: %v", err)
	}
	if manifest.Attestation.AttestationState != "attestation-ready" {
		t.Fatalf("expected attestation-ready state, got %#v", manifest.Attestation)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify attestation audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify attestation audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyAttestationExportRejectsBlockedWithoutArchivedReason(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, false, "")
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"attestationReference":"attestation-2026-07-21","attestedByReference":"audit-operator-1","attestationTimestamp":"2026-07-21T01:40:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.attestation.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.attestation.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/attest", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for blocked verify export without archived reason, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVA-003") {
		t.Fatalf("expected YARA-RCVA-003 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyAttestationIndexExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.attestation.index.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.attestation.index.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"attestationIndexReference":"attestation-index-2026-07-21","publishedByReference":"release-publisher-1","publishedTimestamp":"2026-07-21T01:45:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/attest/index/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify attestation index export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify attestation index manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyAttestationIndexManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify attestation index manifest: %v", err)
	}
	if manifest.Index.IndexState != "index-ready" {
		t.Fatalf("expected index-ready state, got %#v", manifest.Index)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify attestation index audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify attestation index audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyAttestationIndexExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	attestationPath := writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	attestationBytes, err := os.ReadFile(attestationPath)
	if err != nil {
		t.Fatal(err)
	}
	attestation := workflowRolloutClosureVerifyAttestationManifest{}
	if err := json.Unmarshal(attestationBytes, &attestation); err != nil {
		t.Fatal(err)
	}
	attestation.Attestation.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(attestationPath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"attestationIndexReference":"attestation-index-2026-07-21","publishedByReference":"release-publisher-1","publishedTimestamp":"2026-07-21T01:45:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.attestation.index.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.attestation.index.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/attest/index/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify attestation index continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVAI-006") {
		t.Fatalf("expected YARA-RCVAI-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationPackageExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-package.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-package.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPackageReference":"verify-package-2026-07-21","packagedByReference":"reviewer-handoff-1","packagedTimestamp":"2026-07-21T01:50:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication package export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication package manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationPackageManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication package manifest: %v", err)
	}
	if manifest.Package.PackageState != "package-ready" {
		t.Fatalf("expected package-ready state, got %#v", manifest.Package)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication package audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication package audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationPackageExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	indexPath := writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	indexManifest := workflowRolloutClosureVerifyAttestationIndexManifest{}
	if err := json.Unmarshal(indexBytes, &indexManifest); err != nil {
		t.Fatal(err)
	}
	indexManifest.Index.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(indexManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(indexPath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPackageReference":"verify-package-2026-07-21","packagedByReference":"reviewer-handoff-1","packagedTimestamp":"2026-07-21T01:50:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-package.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-package.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication package continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVP-007") {
		t.Fatalf("expected YARA-RCVP-007 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationAttestationExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-attestation.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-attestation.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationReference":"verify-publication-2026-07-21","publishedByReference":"release-ops-1","publishedTimestamp":"2026-07-21T01:55:00Z","publicationChannel":"internal-release-registry","publicationLocationReference":"registry://verification/release/2026-07-21","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-attestation/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication attestation export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication attestation manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationAttestationManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication attestation manifest: %v", err)
	}
	if manifest.Publication.PublicationState != "publication-ready" {
		t.Fatalf("expected publication-ready state, got %#v", manifest.Publication)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication attestation audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication attestation audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationAttestationExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	packagePath := writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	packageBytes, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	packageManifest := workflowRolloutClosureVerifyPublicationPackageManifest{}
	if err := json.Unmarshal(packageBytes, &packageManifest); err != nil {
		t.Fatal(err)
	}
	packageManifest.Package.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(packageManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(packagePath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationReference":"verify-publication-2026-07-21","publishedByReference":"release-ops-1","publishedTimestamp":"2026-07-21T01:55:00Z","publicationChannel":"internal-release-registry","publicationLocationReference":"registry://verification/release/2026-07-21","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-attestation.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-attestation.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-attestation/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication attestation continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPA-006") {
		t.Fatalf("expected YARA-RCVPA-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationIndexExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-index.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-index.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationIndexReference":"verify-publication-index-2026-07-21","indexedByReference":"release-indexer-1","indexedTimestamp":"2026-07-21T02:00:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-index/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication index export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication index manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationIndexManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication index manifest: %v", err)
	}
	if manifest.Index.IndexState != "index-ready" {
		t.Fatalf("expected index-ready state, got %#v", manifest.Index)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication index audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication index audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationIndexExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	publicationPath := writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	publicationBytes, err := os.ReadFile(publicationPath)
	if err != nil {
		t.Fatal(err)
	}
	publicationManifest := workflowRolloutClosureVerifyPublicationAttestationManifest{}
	if err := json.Unmarshal(publicationBytes, &publicationManifest); err != nil {
		t.Fatal(err)
	}
	publicationManifest.Publication.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(publicationManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(publicationPath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationIndexReference":"verify-publication-index-2026-07-21","indexedByReference":"release-indexer-1","indexedTimestamp":"2026-07-21T02:00:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-index.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-index.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-index/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication index continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPI-006") {
		t.Fatalf("expected YARA-RCVPI-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationEnvelopeExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-envelope.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-envelope.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationEnvelopeReference":"verify-publication-envelope-2026-07-21","deliveredByReference":"release-delivery-operator-1","deliveryTimestamp":"2026-07-21T02:05:00Z","deliveryDestinationReference":"release-archive://handoff","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-envelope/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication envelope export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication envelope manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationEnvelopeManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication envelope manifest: %v", err)
	}
	if manifest.Envelope.EnvelopeState != "envelope-ready" {
		t.Fatalf("expected envelope-ready state, got %#v", manifest.Envelope)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication envelope audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication envelope audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationEnvelopeExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	indexPath := writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	indexManifest := workflowRolloutClosureVerifyPublicationIndexManifest{}
	if err := json.Unmarshal(indexBytes, &indexManifest); err != nil {
		t.Fatal(err)
	}
	indexManifest.Index.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(indexManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(indexPath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationEnvelopeReference":"verify-publication-envelope-2026-07-21","deliveredByReference":"release-delivery-operator-1","deliveryTimestamp":"2026-07-21T02:05:00Z","deliveryDestinationReference":"release-archive://handoff","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-envelope.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-envelope.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-envelope/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication envelope continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPE-006") {
		t.Fatalf("expected YARA-RCVPE-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationHandoffExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-handoff.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-handoff.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationHandoffReference":"verify-publication-handoff-2026-07-21","receivedByReference":"receiver-ops-1","handoffTimestamp":"2026-07-21T02:10:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-handoff/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication handoff export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication handoff manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationHandoffManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication handoff manifest: %v", err)
	}
	if manifest.Handoff.HandoffState != "handoff-ready" {
		t.Fatalf("expected handoff-ready state, got %#v", manifest.Handoff)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication handoff audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication handoff audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationHandoffExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	envelopePath := writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	envelopeBytes, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	envelopeManifest := workflowRolloutClosureVerifyPublicationEnvelopeManifest{}
	if err := json.Unmarshal(envelopeBytes, &envelopeManifest); err != nil {
		t.Fatal(err)
	}
	envelopeManifest.Envelope.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(envelopeManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(envelopePath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationHandoffReference":"verify-publication-handoff-2026-07-21","receivedByReference":"receiver-ops-1","handoffTimestamp":"2026-07-21T02:10:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-handoff.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-handoff.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-handoff/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication handoff continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPH-006") {
		t.Fatalf("expected YARA-RCVPH-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationAcknowledgmentExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-acknowledgment.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-acknowledgment.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationAcknowledgmentReference":"verify-publication-acknowledgment-2026-07-21","acknowledgedByReference":"receiver-ops-1","acknowledgmentTimestamp":"2026-07-21T02:15:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-acknowledgment/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication acknowledgment export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication acknowledgment manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationAcknowledgmentManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication acknowledgment manifest: %v", err)
	}
	if manifest.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" {
		t.Fatalf("expected acknowledgment-ready state, got %#v", manifest.Acknowledgment)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication acknowledgment audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication acknowledgment audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationAcknowledgmentExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	handoffPath := writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	handoffBytes, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	handoffManifest := workflowRolloutClosureVerifyPublicationHandoffManifest{}
	if err := json.Unmarshal(handoffBytes, &handoffManifest); err != nil {
		t.Fatal(err)
	}
	handoffManifest.Handoff.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(handoffManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(handoffPath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationAcknowledgmentReference":"verify-publication-acknowledgment-2026-07-21","acknowledgedByReference":"receiver-ops-1","acknowledgmentTimestamp":"2026-07-21T02:15:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-acknowledgment.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-acknowledgment.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-acknowledgment/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication acknowledgment continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPAK-006") {
		t.Fatalf("expected YARA-RCVPAK-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchiveIndexExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-index.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-index.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationArchiveIndexReference":"verify-publication-archive-index-2026-07-21","indexedByReference":"archive-indexer-1","indexedTimestamp":"2026-07-21T02:20:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-index/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication archive index export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication archive index manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationArchiveIndexManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication archive index manifest: %v", err)
	}
	if manifest.ArchiveIndex.ArchiveIndexState != "archive-index-ready" {
		t.Fatalf("expected archive-index-ready state, got %#v", manifest.ArchiveIndex)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication archive index audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication archive index audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchiveIndexExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	ackPath := writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	ackBytes, err := os.ReadFile(ackPath)
	if err != nil {
		t.Fatal(err)
	}
	ackManifest := workflowRolloutClosureVerifyPublicationAcknowledgmentManifest{}
	if err := json.Unmarshal(ackBytes, &ackManifest); err != nil {
		t.Fatal(err)
	}
	ackManifest.Acknowledgment.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(ackManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(ackPath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationArchiveIndexReference":"verify-publication-archive-index-2026-07-21","indexedByReference":"archive-indexer-1","indexedTimestamp":"2026-07-21T02:20:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-index.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-index.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-index/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication archive index continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPAX-006") {
		t.Fatalf("expected YARA-RCVPAX-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchivePackageExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	writeRolloutClosureVerifyPublicationArchiveIndexFixture(t, workspacePath, "archive-index-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-package.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-package.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationArchivePackageReference":"verify-publication-archive-package-2026-07-21","packagedByReference":"archive-packager-1","packagedTimestamp":"2026-07-21T02:25:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication archive package export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication archive package manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationArchivePackageManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication archive package manifest: %v", err)
	}
	if manifest.ArchivePackage.ArchivePackageState != "archive-package-ready" {
		t.Fatalf("expected archive-package-ready state, got %#v", manifest.ArchivePackage)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication archive package audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication archive package audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchivePackageExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	archiveIndexPath := writeRolloutClosureVerifyPublicationArchiveIndexFixture(t, workspacePath, "archive-index-ready")
	archiveIndexBytes, err := os.ReadFile(archiveIndexPath)
	if err != nil {
		t.Fatal(err)
	}
	archiveIndexManifest := workflowRolloutClosureVerifyPublicationArchiveIndexManifest{}
	if err := json.Unmarshal(archiveIndexBytes, &archiveIndexManifest); err != nil {
		t.Fatal(err)
	}
	archiveIndexManifest.ArchiveIndex.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(archiveIndexManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(archiveIndexPath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationArchivePackageReference":"verify-publication-archive-package-2026-07-21","packagedByReference":"archive-packager-1","packagedTimestamp":"2026-07-21T02:25:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-package.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-package.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-package/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication archive package continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPAP-006") {
		t.Fatalf("expected YARA-RCVPAP-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchiveEnvelopeExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	writeRolloutClosureVerifyPublicationArchiveIndexFixture(t, workspacePath, "archive-index-ready")
	writeRolloutClosureVerifyPublicationArchivePackageFixture(t, workspacePath, "archive-package-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-envelope.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-envelope.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationArchiveEnvelopeReference":"verify-publication-archive-envelope-2026-07-21","deliveredByReference":"archive-delivery-operator-1","deliveryTimestamp":"2026-07-21T02:30:00Z","deliveryDestinationReference":"archive://offline-vault","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-envelope/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication archive envelope export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication archive envelope manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationArchiveEnvelopeManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication archive envelope manifest: %v", err)
	}
	if manifest.ArchiveEnvelope.ArchiveEnvelopeState != "archive-envelope-ready" {
		t.Fatalf("expected archive-envelope-ready state, got %#v", manifest.ArchiveEnvelope)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication archive envelope audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication archive envelope audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchiveEnvelopeExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	writeRolloutClosureVerifyPublicationArchiveIndexFixture(t, workspacePath, "archive-index-ready")
	archivePackagePath := writeRolloutClosureVerifyPublicationArchivePackageFixture(t, workspacePath, "archive-package-ready")
	archivePackageBytes, err := os.ReadFile(archivePackagePath)
	if err != nil {
		t.Fatal(err)
	}
	archivePackageManifest := workflowRolloutClosureVerifyPublicationArchivePackageManifest{}
	if err := json.Unmarshal(archivePackageBytes, &archivePackageManifest); err != nil {
		t.Fatal(err)
	}
	archivePackageManifest.ArchivePackage.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(archivePackageManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(archivePackagePath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationArchiveEnvelopeReference":"verify-publication-archive-envelope-2026-07-21","deliveredByReference":"archive-delivery-operator-1","deliveryTimestamp":"2026-07-21T02:30:00Z","deliveryDestinationReference":"archive://offline-vault","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-envelope.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-envelope.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-envelope/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication archive envelope continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPAE-006") {
		t.Fatalf("expected YARA-RCVPAE-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchiveHandoffExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	writeRolloutClosureVerifyPublicationArchiveIndexFixture(t, workspacePath, "archive-index-ready")
	writeRolloutClosureVerifyPublicationArchivePackageFixture(t, workspacePath, "archive-package-ready")
	writeRolloutClosureVerifyPublicationArchiveEnvelopeFixture(t, workspacePath, "archive-envelope-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-handoff.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-handoff.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationArchiveHandoffReference":"verify-publication-archive-handoff-2026-07-21","receivedByReference":"archive-receiver-1","handoffTimestamp":"2026-07-21T02:35:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-handoff/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication archive handoff export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication archive handoff manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationArchiveHandoffManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication archive handoff manifest: %v", err)
	}
	if manifest.ArchiveHandoff.ArchiveHandoffState != "archive-handoff-ready" {
		t.Fatalf("expected archive-handoff-ready state, got %#v", manifest.ArchiveHandoff)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication archive handoff audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication archive handoff audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchiveHandoffExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	writeRolloutClosureVerifyPublicationArchiveIndexFixture(t, workspacePath, "archive-index-ready")
	writeRolloutClosureVerifyPublicationArchivePackageFixture(t, workspacePath, "archive-package-ready")
	archiveEnvelopePath := writeRolloutClosureVerifyPublicationArchiveEnvelopeFixture(t, workspacePath, "archive-envelope-ready")
	archiveEnvelopeBytes, err := os.ReadFile(archiveEnvelopePath)
	if err != nil {
		t.Fatal(err)
	}
	archiveEnvelopeManifest := workflowRolloutClosureVerifyPublicationArchiveEnvelopeManifest{}
	if err := json.Unmarshal(archiveEnvelopeBytes, &archiveEnvelopeManifest); err != nil {
		t.Fatal(err)
	}
	archiveEnvelopeManifest.ArchiveEnvelope.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(archiveEnvelopeManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(archiveEnvelopePath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationArchiveHandoffReference":"verify-publication-archive-handoff-2026-07-21","receivedByReference":"archive-receiver-1","handoffTimestamp":"2026-07-21T02:35:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-handoff.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-handoff.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-handoff/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication archive handoff continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPAH-006") {
		t.Fatalf("expected YARA-RCVPAH-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchiveAcknowledgmentExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	writeRolloutClosureVerifyPublicationArchiveIndexFixture(t, workspacePath, "archive-index-ready")
	writeRolloutClosureVerifyPublicationArchivePackageFixture(t, workspacePath, "archive-package-ready")
	writeRolloutClosureVerifyPublicationArchiveEnvelopeFixture(t, workspacePath, "archive-envelope-ready")
	writeRolloutClosureVerifyPublicationArchiveHandoffFixture(t, workspacePath, "archive-handoff-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-acknowledgment.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-acknowledgment.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationArchiveAcknowledgmentReference":"verify-publication-archive-acknowledgment-2026-07-21","acknowledgedByReference":"archive-reviewer-1","acknowledgmentTimestamp":"2026-07-21T02:40:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-acknowledgment/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication archive acknowledgment export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication archive acknowledgment manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationArchiveAcknowledgmentManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication archive acknowledgment manifest: %v", err)
	}
	if manifest.ArchiveAcknowledgment.ArchiveAcknowledgmentState != "archive-acknowledgment-ready" {
		t.Fatalf("expected archive-acknowledgment-ready state, got %#v", manifest.ArchiveAcknowledgment)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication archive acknowledgment audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication archive acknowledgment audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchiveAcknowledgmentExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	writeRolloutClosureVerifyPublicationArchiveIndexFixture(t, workspacePath, "archive-index-ready")
	writeRolloutClosureVerifyPublicationArchivePackageFixture(t, workspacePath, "archive-package-ready")
	writeRolloutClosureVerifyPublicationArchiveEnvelopeFixture(t, workspacePath, "archive-envelope-ready")
	archiveHandoffPath := writeRolloutClosureVerifyPublicationArchiveHandoffFixture(t, workspacePath, "archive-handoff-ready")
	archiveHandoffBytes, err := os.ReadFile(archiveHandoffPath)
	if err != nil {
		t.Fatal(err)
	}
	archiveHandoffManifest := workflowRolloutClosureVerifyPublicationArchiveHandoffManifest{}
	if err := json.Unmarshal(archiveHandoffBytes, &archiveHandoffManifest); err != nil {
		t.Fatal(err)
	}
	archiveHandoffManifest.ArchiveHandoff.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(archiveHandoffManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(archiveHandoffPath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationArchiveAcknowledgmentReference":"verify-publication-archive-acknowledgment-2026-07-21","acknowledgedByReference":"archive-reviewer-1","acknowledgmentTimestamp":"2026-07-21T02:40:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-acknowledgment.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-acknowledgment.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-acknowledgment/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication archive acknowledgment continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPAA-006") {
		t.Fatalf("expected YARA-RCVPAA-006 error, got %s", recorder.Body.String())
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchiveAttestationExportWritesManifestAndAudit(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	writeRolloutClosureVerifyPublicationArchiveIndexFixture(t, workspacePath, "archive-index-ready")
	writeRolloutClosureVerifyPublicationArchivePackageFixture(t, workspacePath, "archive-package-ready")
	writeRolloutClosureVerifyPublicationArchiveEnvelopeFixture(t, workspacePath, "archive-envelope-ready")
	writeRolloutClosureVerifyPublicationArchiveHandoffFixture(t, workspacePath, "archive-handoff-ready")
	writeRolloutClosureVerifyPublicationArchiveAcknowledgmentFixture(t, workspacePath, "archive-acknowledgment-ready")
	handler := serveHandlerFixture(t, false, workspacePath)
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-attestation.json")
	auditPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-attestation.export.audit.jsonl")
	requestBody := fmt.Sprintf(`{"verificationPublicationArchiveAttestationReference":"verify-publication-archive-attestation-2026-07-21","attestedByReference":"archive-attester-1","attestationTimestamp":"2026-07-21T02:45:00Z","manifestPath":%q,"auditPath":%q}`, manifestPath, auditPath)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-attestation/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for verify publication archive attestation export, got %d: %s", recorder.Code, recorder.Body.String())
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read verify publication archive attestation manifest: %v", err)
	}
	manifest := workflowRolloutClosureVerifyPublicationArchiveAttestationManifest{}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode verify publication archive attestation manifest: %v", err)
	}
	if manifest.ArchiveAttestation.ArchiveAttestationState != "archive-attestation-ready" {
		t.Fatalf("expected archive-attestation-ready state, got %#v", manifest.ArchiveAttestation)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("read verify publication archive attestation audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected verify publication archive attestation audit events")
	}
}

func TestServeWorkflowRolloutClosureVerifyPublicationArchiveAttestationExportRejectsContinuityMismatch(t *testing.T) {
	workspacePath := t.TempDir()
	populateWorkflowWorkspace(t, workspacePath)
	writeClosurePackageFixtures(t, workspacePath)
	writeReleaseDecisionFixture(t, workspacePath, "approved")
	writeReleasePublicationFixture(t, workspacePath)
	writeReleasePublicationIndexFixture(t, workspacePath)
	writeReleasePublicationPackageFixture(t, workspacePath)
	writeReleasePublicationEnvelopeFixture(t, workspacePath)
	writeReleasePublicationHandoffReceiptFixture(t, workspacePath)
	writeReleasePublicationAcknowledgmentFixture(t, workspacePath)
	writeRolloutClosureSummaryFixture(t, workspacePath)
	writeRolloutClosureDeliveryFixture(t, workspacePath)
	writeRolloutClosureAcceptanceFixture(t, workspacePath)
	writeRolloutClosureCertificateFixture(t, workspacePath)
	writeRolloutClosureLedgerFixture(t, workspacePath)
	writeRolloutClosureDocketFixture(t, workspacePath)
	writeRolloutClosureBulletinFixture(t, workspacePath)
	writeRolloutClosurePacketFixture(t, workspacePath)
	writeRolloutClosureRecipientPackageFixture(t, workspacePath)
	writeRolloutClosureVerifyExportFixture(t, workspacePath, true, "")
	writeRolloutClosureVerifyAttestationFixture(t, workspacePath, "attestation-ready")
	writeRolloutClosureVerifyAttestationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationPackageFixture(t, workspacePath, "package-ready")
	writeRolloutClosureVerifyPublicationAttestationFixture(t, workspacePath, "publication-ready")
	writeRolloutClosureVerifyPublicationIndexFixture(t, workspacePath, "index-ready")
	writeRolloutClosureVerifyPublicationEnvelopeFixture(t, workspacePath, "envelope-ready")
	writeRolloutClosureVerifyPublicationHandoffFixture(t, workspacePath, "handoff-ready")
	writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t, workspacePath, "acknowledgment-ready")
	writeRolloutClosureVerifyPublicationArchiveIndexFixture(t, workspacePath, "archive-index-ready")
	writeRolloutClosureVerifyPublicationArchivePackageFixture(t, workspacePath, "archive-package-ready")
	writeRolloutClosureVerifyPublicationArchiveEnvelopeFixture(t, workspacePath, "archive-envelope-ready")
	writeRolloutClosureVerifyPublicationArchiveHandoffFixture(t, workspacePath, "archive-handoff-ready")
	archiveAckPath := writeRolloutClosureVerifyPublicationArchiveAcknowledgmentFixture(t, workspacePath, "archive-acknowledgment-ready")
	archiveAckBytes, err := os.ReadFile(archiveAckPath)
	if err != nil {
		t.Fatal(err)
	}
	archiveAckManifest := workflowRolloutClosureVerifyPublicationArchiveAcknowledgmentManifest{}
	if err := json.Unmarshal(archiveAckBytes, &archiveAckManifest); err != nil {
		t.Fatal(err)
	}
	archiveAckManifest.ArchiveAcknowledgment.Continuity.TargetDigest = "sha256:diverged-target"
	updatedBytes, err := json.MarshalIndent(archiveAckManifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	updatedBytes = append(updatedBytes, '\n')
	if err := os.WriteFile(archiveAckPath, updatedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := serveHandlerFixture(t, false, workspacePath)
	requestBody := fmt.Sprintf(`{"verificationPublicationArchiveAttestationReference":"verify-publication-archive-attestation-2026-07-21","attestedByReference":"archive-attester-1","attestationTimestamp":"2026-07-21T02:45:00Z","manifestPath":%q,"auditPath":%q}`,
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-attestation.json"),
		filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-attestation.export.audit.jsonl"),
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workflow/rollout-closure/verify/publication-archive-attestation/export", strings.NewReader(requestBody))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for verify publication archive attestation continuity mismatch, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "YARA-RCVPAT-006") {
		t.Fatalf("expected YARA-RCVPAT-006 error, got %s", recorder.Body.String())
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

func populateWorkflowWorkspace(t *testing.T, workspacePath string) {
	t.Helper()
	sourcePath := t.TempDir()
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	paths, _ := writeExecutionInputs(t, sourcePath, now)
	planPath, _ := writeV02Plan(t, sourcePath)
	copyIntoWorkspace := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		target := filepath.Join(workspacePath, filepath.Base(path))
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	copyIntoWorkspace(planPath)
	for _, flag := range []string{"--bundle", "--preflight", "--change-set", "--approval", "--authorization"} {
		copyIntoWorkspace(valueForFlag(paths, flag))
	}
}

func writeEvidenceBundleFixtures(t *testing.T, workspacePath string) {
	t.Helper()
	runbook, _, err := buildWorkflowRunbook(workspacePath)
	if err != nil {
		t.Fatalf("build runbook fixture: %v", err)
	}
	runbookMarkdownPath := filepath.Join(workspacePath, "workflow.runbook.md")
	runbookJSONPath := filepath.Join(workspacePath, "workflow.runbook.json")
	if err := os.WriteFile(runbookMarkdownPath, []byte(runbook.Runbook.Markdown+"\n"), 0o600); err != nil {
		t.Fatalf("write runbook markdown fixture: %v", err)
	}
	runbookJSONBytes, err := json.MarshalIndent(runbook, "", "  ")
	if err != nil {
		t.Fatalf("marshal runbook fixture: %v", err)
	}
	runbookJSONBytes = append(runbookJSONBytes, '\n')
	if err := os.WriteFile(runbookJSONPath, runbookJSONBytes, 0o600); err != nil {
		t.Fatalf("write runbook json fixture: %v", err)
	}
	capsule, _, err := buildWorkflowCapsule(workspacePath)
	if err != nil {
		t.Fatalf("build capsule fixture: %v", err)
	}
	capsuleMarkdownPath := filepath.Join(workspacePath, "workflow.capsule.md")
	capsuleJSONPath := filepath.Join(workspacePath, "workflow.capsule.json")
	if err := os.WriteFile(capsuleMarkdownPath, []byte(renderCapsuleMarkdown(capsule, "")+"\n"), 0o600); err != nil {
		t.Fatalf("write capsule markdown fixture: %v", err)
	}
	capsuleJSONBytes, err := json.MarshalIndent(capsule, "", "  ")
	if err != nil {
		t.Fatalf("marshal capsule fixture: %v", err)
	}
	capsuleJSONBytes = append(capsuleJSONBytes, '\n')
	if err := os.WriteFile(capsuleJSONPath, capsuleJSONBytes, 0o600); err != nil {
		t.Fatalf("write capsule json fixture: %v", err)
	}
}

func writeDeploymentReceiptFixtures(t *testing.T, workspacePath string) []resources.DeploymentReceipt {
	t.Helper()
	stageLookup, err := workspaceStageArtifacts(workspacePath)
	if err != nil {
		t.Fatalf("load workspace stage artifacts: %v", err)
	}
	bundle, err := resources.LoadDeploymentBundle(stageLookup["bundle"])
	if err != nil {
		t.Fatalf("load bundle fixture: %v", err)
	}
	preflight, err := resources.LoadTargetPreflightResult(stageLookup["preflight"])
	if err != nil {
		t.Fatalf("load preflight fixture: %v", err)
	}
	changeSet, err := resources.LoadKubernetesChangeSet(stageLookup["changeset"])
	if err != nil {
		t.Fatalf("load change-set fixture: %v", err)
	}
	approval, err := resources.LoadDeploymentApproval(stageLookup["approval"])
	if err != nil {
		t.Fatalf("load approval fixture: %v", err)
	}
	authorization, err := resources.LoadExecutionAuthorization(stageLookup["authorization"])
	if err != nil {
		t.Fatalf("load authorization fixture: %v", err)
	}
	evidenceDigest, err := canonical.Digest(struct {
		Receipt string
	}{Receipt: "timeline"})
	if err != nil {
		t.Fatalf("compute evidence digest: %v", err)
	}
	writeReceipt := func(name string, started, completed time.Time) resources.DeploymentReceipt {
		receipt := resources.DeploymentReceipt{
			APIVersion: resources.APIVersion,
			Kind:       "DeploymentReceipt",
			Metadata: resources.DeploymentReceiptMetadata{
				Name: name,
			},
			Spec: resources.DeploymentReceiptSpec{
				Outcome:                "succeeded",
				StartedAt:              started.Format(time.RFC3339Nano),
				CompletedAt:            completed.Format(time.RFC3339Nano),
				ExecutionCorrelationID: testCLIDigest('7'),
				PlanID:                 bundle.Spec.PlanID,
				BundleID:               bundle.Metadata.BundleID,
				PreflightResultID:      preflight.Metadata.ResultID,
				ChangeSetID:            changeSet.Metadata.ChangeSetID,
				ApprovalID:             approval.Metadata.ApprovalID,
				AuthorizationID:        authorization.Metadata.AuthorizationID,
				ImportReceiptID:        testCLIDigest('8'),
				Target:                 authorization.Spec.Target,
				Executor: resources.DeploymentExecutorIdentity{
					Name:         "yara",
					Version:      "0.1.0",
					BinaryDigest: testCLIDigest('9'),
				},
				Operations: []resources.DeploymentOperationReceipt{
					{
						Resource:    changeSet.Spec.Operations[0].Resource,
						Action:      "create",
						Outcome:     "applied",
						AfterDigest: changeSet.Spec.Operations[0].DesiredDigest,
					},
				},
				Postflight: []resources.DeploymentPostflightCheck{
					{ID: "workloads.available", Status: "passed", EvidenceDigest: evidenceDigest},
				},
				Limitations: []string{"Timeline fixture."},
			},
		}
		receipt, err := receipt.AssignReceiptID()
		if err != nil {
			t.Fatalf("assign receipt id for %s: %v", name, err)
		}
		path := filepath.Join(workspacePath, name+".yaml")
		writeYAMLFixture(t, path, receipt)
		return receipt
	}
	first := writeReceipt("reference-receipt-older", time.Date(2026, 7, 20, 12, 4, 0, 0, time.UTC), time.Date(2026, 7, 20, 12, 5, 0, 0, time.UTC))
	second := writeReceipt("reference-receipt-latest", time.Date(2026, 7, 20, 12, 9, 0, 0, time.UTC), time.Date(2026, 7, 20, 12, 10, 0, 0, time.UTC))
	return []resources.DeploymentReceipt{first, second}
}

func writeClosurePackageFixtures(t *testing.T, workspacePath string) {
	t.Helper()
	writeEvidenceBundleFixtures(t, workspacePath)
	writeDeploymentReceiptFixtures(t, workspacePath)
	timeline, _, err := buildWorkflowReceiptTimeline(workspacePath)
	if err != nil {
		t.Fatalf("build receipt timeline fixture: %v", err)
	}
	timelineMarkdownPath := filepath.Join(workspacePath, "workflow.receipt-timeline.md")
	timelineJSONPath := filepath.Join(workspacePath, "workflow.receipt-timeline.json")
	if err := os.WriteFile(timelineMarkdownPath, []byte(renderReceiptTimelineMarkdown(timeline)+"\n"), 0o600); err != nil {
		t.Fatalf("write receipt timeline markdown fixture: %v", err)
	}
	timelineJSONBytes, err := json.MarshalIndent(timeline, "", "  ")
	if err != nil {
		t.Fatalf("marshal receipt timeline fixture: %v", err)
	}
	timelineJSONBytes = append(timelineJSONBytes, '\n')
	if err := os.WriteFile(timelineJSONPath, timelineJSONBytes, 0o600); err != nil {
		t.Fatalf("write receipt timeline json fixture: %v", err)
	}
	evidenceBundle, _, err := buildWorkflowEvidenceBundleManifest(workspacePath)
	if err != nil {
		t.Fatalf("build evidence bundle fixture: %v", err)
	}
	evidenceBundlePath := filepath.Join(workspacePath, "workflow.evidence-bundle.json")
	evidenceBundleBytes, err := json.MarshalIndent(evidenceBundle, "", "  ")
	if err != nil {
		t.Fatalf("marshal evidence bundle fixture: %v", err)
	}
	evidenceBundleBytes = append(evidenceBundleBytes, '\n')
	if err := os.WriteFile(evidenceBundlePath, evidenceBundleBytes, 0o600); err != nil {
		t.Fatalf("write evidence bundle fixture: %v", err)
	}
	closurePackage, _, err := buildWorkflowClosurePackageManifest(workspacePath, "release-checklist-001")
	if err != nil {
		t.Fatalf("build closure package fixture: %v", err)
	}
	closurePackagePath := filepath.Join(workspacePath, "workflow.closure-package.json")
	closurePackageBytes, err := json.MarshalIndent(closurePackage, "", "  ")
	if err != nil {
		t.Fatalf("marshal closure package fixture: %v", err)
	}
	closurePackageBytes = append(closurePackageBytes, '\n')
	if err := os.WriteFile(closurePackagePath, closurePackageBytes, 0o600); err != nil {
		t.Fatalf("write closure package fixture: %v", err)
	}
	reviewGate, _, err := evaluateWorkflowClosureReviewGate(workspacePath, "release-checklist-001", "ticket-456", "approved")
	if err != nil {
		t.Fatalf("build closure review gate fixture: %v", err)
	}
	reviewGatePath := filepath.Join(workspacePath, "workflow.closure-review-gate.json")
	reviewGateBytes, err := json.MarshalIndent(reviewGate, "", "  ")
	if err != nil {
		t.Fatalf("marshal closure review gate fixture: %v", err)
	}
	reviewGateBytes = append(reviewGateBytes, '\n')
	if err := os.WriteFile(reviewGatePath, reviewGateBytes, 0o600); err != nil {
		t.Fatalf("write closure review gate fixture: %v", err)
	}
}

func writeReleaseDecisionFixture(t *testing.T, workspacePath, decision string) string {
	t.Helper()
	reviewGate, _, err := evaluateWorkflowClosureReviewGate(workspacePath, "release-checklist-001", "ticket-456", decision)
	if err != nil {
		t.Fatalf("build release decision review gate fixture: %v", err)
	}
	reviewGatePath := filepath.Join(workspacePath, "workflow.closure-review-gate.json")
	reviewGateBytes, err := json.MarshalIndent(reviewGate, "", "  ")
	if err != nil {
		t.Fatalf("marshal release decision review gate fixture: %v", err)
	}
	reviewGateBytes = append(reviewGateBytes, '\n')
	if err := os.WriteFile(reviewGatePath, reviewGateBytes, 0o600); err != nil {
		t.Fatalf("write release decision review gate fixture: %v", err)
	}
	ledger, _, err := buildWorkflowReleaseDecisionLedger(workspacePath, workflowReleaseDecisionExportRequest{
		ReleaseReadinessReference: "release-checklist-001",
		ReviewerReference:         "ticket-456",
		Decision:                  decision,
		OperatorReference:         "operator-1",
		DecisionTimestamp:         "2026-07-21T00:05:00Z",
		LedgerPath:                filepath.Join(workspacePath, "workflow.release-decision.json"),
		AuditPath:                 filepath.Join(workspacePath, "workflow.release-decision.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build release decision fixture: %v", err)
	}
	ledgerPath := filepath.Join(workspacePath, "workflow.release-decision.json")
	ledgerBytes, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		t.Fatalf("marshal release decision fixture: %v", err)
	}
	ledgerBytes = append(ledgerBytes, '\n')
	if err := os.WriteFile(ledgerPath, ledgerBytes, 0o600); err != nil {
		t.Fatalf("write release decision fixture: %v", err)
	}
	return ledgerPath
}

func writeReleasePublicationFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	attestation, _, err := buildWorkflowReleasePublicationAttestation(workspacePath, workflowReleasePublicationExportRequest{
		PublicationChannel:        "github-release",
		ArtifactLocationReference: "gh://releases/v0.2.0-alpha.2",
		PublicationTimestamp:      "2026-07-21T00:10:00Z",
		OperatorReference:         "operator-2",
		AttestationPath:           filepath.Join(workspacePath, "workflow.release-publication.json"),
		AuditPath:                 filepath.Join(workspacePath, "workflow.release-publication.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build release publication fixture: %v", err)
	}
	attestationPath := filepath.Join(workspacePath, "workflow.release-publication.json")
	attestationBytes, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		t.Fatalf("marshal release publication fixture: %v", err)
	}
	attestationBytes = append(attestationBytes, '\n')
	if err := os.WriteFile(attestationPath, attestationBytes, 0o600); err != nil {
		t.Fatalf("write release publication fixture: %v", err)
	}
	return attestationPath
}

func writeReleasePublicationIndexFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowReleasePublicationIndexManifest(workspacePath, workflowReleasePublicationIndexExportRequest{
		PublicationBatchReference: "batch-2026-07-21",
		OperatorReference:         "operator-3",
		ManifestPath:              filepath.Join(workspacePath, "workflow.release-publication.index.json"),
		AuditPath:                 filepath.Join(workspacePath, "workflow.release-publication.index.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build release publication index fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.release-publication.index.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal release publication index fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write release publication index fixture: %v", err)
	}
	return manifestPath
}

func writeReleasePublicationPackageFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowReleasePublicationPackageManifest(workspacePath, workflowReleasePublicationPackageExportRequest{
		PackageReference:           "package-2026-07-21",
		PublicationWindowReference: "window-2026w30",
		OperatorReference:          "operator-4",
		ManifestPath:               filepath.Join(workspacePath, "workflow.release-publication.package.json"),
		AuditPath:                  filepath.Join(workspacePath, "workflow.release-publication.package.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build release publication package fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.release-publication.package.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal release publication package fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write release publication package fixture: %v", err)
	}
	return manifestPath
}

func writeReleasePublicationEnvelopeFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowReleasePublicationEnvelopeManifest(workspacePath, workflowReleasePublicationEnvelopeExportRequest{
		DeliveryReference:    "delivery-2026-07-21",
		DestinationReference: "release-ops://handoff",
		OperatorReference:    "operator-5",
		ManifestPath:         filepath.Join(workspacePath, "workflow.release-publication.envelope.json"),
		AuditPath:            filepath.Join(workspacePath, "workflow.release-publication.envelope.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build release publication envelope fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.release-publication.envelope.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal release publication envelope fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write release publication envelope fixture: %v", err)
	}
	return manifestPath
}

func writeReleasePublicationHandoffReceiptFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	receipt, _, err := buildWorkflowReleasePublicationHandoffReceipt(workspacePath, workflowReleasePublicationHandoffReceiptExportRequest{
		ReceiverReference: "release-ops-team",
		HandoffTimestamp:  "2026-07-21T00:20:00Z",
		OperatorReference: "operator-6",
		ReceiptPath:       filepath.Join(workspacePath, "workflow.release-publication.handoff-receipt.json"),
		AuditPath:         filepath.Join(workspacePath, "workflow.release-publication.handoff-receipt.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build release publication handoff receipt fixture: %v", err)
	}
	receiptPath := filepath.Join(workspacePath, "workflow.release-publication.handoff-receipt.json")
	receiptBytes, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatalf("marshal release publication handoff receipt fixture: %v", err)
	}
	receiptBytes = append(receiptBytes, '\n')
	if err := os.WriteFile(receiptPath, receiptBytes, 0o600); err != nil {
		t.Fatalf("write release publication handoff receipt fixture: %v", err)
	}
	return receiptPath
}

func writeReleasePublicationAcknowledgmentFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowReleasePublicationAcknowledgmentManifest(workspacePath, workflowReleasePublicationAcknowledgmentExportRequest{
		AcknowledgmentReference: "ack-2026-07-21",
		AcknowledgedByReference: "release-ops-team",
		AcknowledgmentTimestamp: "2026-07-21T00:30:00Z",
		ManifestPath:            filepath.Join(workspacePath, "workflow.release-publication.acknowledgment.json"),
		AuditPath:               filepath.Join(workspacePath, "workflow.release-publication.acknowledgment.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build release publication acknowledgment fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.release-publication.acknowledgment.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal release publication acknowledgment fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write release publication acknowledgment fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureSummaryFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowRolloutClosureSummaryManifest(workspacePath, workflowRolloutClosureSummaryExportRequest{
		SummaryReference:  "closure-summary-2026-07-21",
		OperatorReference: "operator-8",
		SummaryTimestamp:  "2026-07-21T00:40:00Z",
		ManifestPath:      filepath.Join(workspacePath, "workflow.rollout-closure-summary.json"),
		AuditPath:         filepath.Join(workspacePath, "workflow.rollout-closure-summary.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build rollout closure summary fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-summary.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal rollout closure summary fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write rollout closure summary fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureDeliveryFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowRolloutClosureDeliveryManifest(workspacePath, workflowRolloutClosureDeliveryExportRequest{
		DeliveryReference:    "closure-delivery-2026-07-21",
		DestinationReference: "release-ops://final-transfer",
		OperatorReference:    "operator-9",
		DeliveryTimestamp:    "2026-07-21T00:50:00Z",
		ManifestPath:         filepath.Join(workspacePath, "workflow.rollout-closure-delivery.json"),
		AuditPath:            filepath.Join(workspacePath, "workflow.rollout-closure-delivery.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build rollout closure delivery fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-delivery.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal rollout closure delivery fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write rollout closure delivery fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureAcceptanceFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowRolloutClosureAcceptanceManifest(workspacePath, workflowRolloutClosureAcceptanceExportRequest{
		AcceptanceReference: "closure-acceptance-2026-07-21",
		AcceptedByReference: "receiver-team-1",
		AcceptanceTimestamp: "2026-07-21T00:55:00Z",
		ManifestPath:        filepath.Join(workspacePath, "workflow.rollout-closure-acceptance.json"),
		AuditPath:           filepath.Join(workspacePath, "workflow.rollout-closure-acceptance.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build rollout closure acceptance fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-acceptance.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal rollout closure acceptance fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write rollout closure acceptance fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureCertificateFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowRolloutClosureCertificateManifest(workspacePath, workflowRolloutClosureCertificateExportRequest{
		CertificateReference: "closure-certificate-2026-07-21",
		IssuedByReference:    "release-authority-1",
		IssuedTimestamp:      "2026-07-21T01:00:00Z",
		ManifestPath:         filepath.Join(workspacePath, "workflow.rollout-closure-certificate.json"),
		AuditPath:            filepath.Join(workspacePath, "workflow.rollout-closure-certificate.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build rollout closure certificate fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-certificate.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal rollout closure certificate fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write rollout closure certificate fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureLedgerFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowRolloutClosureLedgerManifest(workspacePath, workflowRolloutClosureLedgerExportRequest{
		LedgerReference:     "closure-ledger-2026-07-21",
		RecordedByReference: "archive-operator-1",
		RecordedTimestamp:   "2026-07-21T01:05:00Z",
		ManifestPath:        filepath.Join(workspacePath, "workflow.rollout-closure-ledger.json"),
		AuditPath:           filepath.Join(workspacePath, "workflow.rollout-closure-ledger.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build rollout closure ledger fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-ledger.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal rollout closure ledger fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write rollout closure ledger fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureDocketFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowRolloutClosureDocketManifest(workspacePath, workflowRolloutClosureDocketExportRequest{
		DocketReference:     "closure-docket-2026-07-21",
		PreparedByReference: "handoff-preparer-1",
		PreparedTimestamp:   "2026-07-21T01:10:00Z",
		ManifestPath:        filepath.Join(workspacePath, "workflow.rollout-closure-docket.json"),
		AuditPath:           filepath.Join(workspacePath, "workflow.rollout-closure-docket.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build rollout closure docket fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-docket.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal rollout closure docket fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write rollout closure docket fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureBulletinFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowRolloutClosureBulletinManifest(workspacePath, workflowRolloutClosureBulletinExportRequest{
		BulletinReference:    "closure-bulletin-2026-07-21",
		PublishedByReference: "release-publisher-1",
		PublishedTimestamp:   "2026-07-21T01:15:00Z",
		ManifestPath:         filepath.Join(workspacePath, "workflow.rollout-closure-bulletin.json"),
		AuditPath:            filepath.Join(workspacePath, "workflow.rollout-closure-bulletin.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build rollout closure bulletin fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-bulletin.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal rollout closure bulletin fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write rollout closure bulletin fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosurePacketFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowRolloutClosurePacketManifest(workspacePath, workflowRolloutClosurePacketExportRequest{
		PacketReference:     "closure-packet-2026-07-21",
		PackagedByReference: "release-packager-1",
		PackagedTimestamp:   "2026-07-21T01:20:00Z",
		ManifestPath:        filepath.Join(workspacePath, "workflow.rollout-closure-packet.json"),
		AuditPath:           filepath.Join(workspacePath, "workflow.rollout-closure-packet.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build rollout closure packet fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-packet.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal rollout closure packet fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write rollout closure packet fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureRecipientPackageFixture(t *testing.T, workspacePath string) string {
	t.Helper()
	manifest, _, err := buildWorkflowRolloutClosureRecipientPackageManifest(workspacePath, workflowRolloutClosureRecipientPackageExportRequest{
		RecipientPackageReference: "recipient-package-2026-07-21",
		PreparedForReference:      "recipient-ops-1",
		PreparedTimestamp:         "2026-07-21T01:25:00Z",
		ManifestPath:              filepath.Join(workspacePath, "workflow.rollout-closure-recipient-package.json"),
		AuditPath:                 filepath.Join(workspacePath, "workflow.rollout-closure-recipient-package.export.audit.jsonl"),
	})
	if err != nil {
		t.Fatalf("build rollout closure recipient package fixture: %v", err)
	}
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-recipient-package.json")
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal rollout closure recipient package fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write rollout closure recipient package fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyExportFixture(t *testing.T, workspacePath string, ready bool, blockedReason string) string {
	t.Helper()
	verification := verifyWorkflowRolloutClosureChain(workspacePath)
	if !ready {
		verification.Verification.Ready = false
		verification.Verification.VerificationState = "blocked"
		if verification.Verification.BlockerCode == "" {
			verification.Verification.BlockerCode = "YARA-RCV-003"
		}
	}
	payload := workflowRolloutClosureVerifyExportRequest{
		VerificationReference:       "verify-2026-07-21",
		OperatorReference:           "operator-verify-1",
		VerificationTimestamp:       "2026-07-21T01:35:00Z",
		AllowBlocked:                !ready,
		AllowBlockedReasonReference: blockedReason,
	}
	markdownPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.md")
	markdownBytes := []byte(renderWorkflowRolloutClosureVerifyMarkdown(payload, verification) + "\n")
	if err := os.WriteFile(markdownPath, markdownBytes, 0o600); err != nil {
		t.Fatalf("write verify export markdown fixture: %v", err)
	}
	bundle := workflowRolloutClosureVerifyExportBundle{Valid: true}
	bundle.Export.WorkspacePath = workspacePath
	bundle.Export.VerificationReference = payload.VerificationReference
	bundle.Export.OperatorReference = payload.OperatorReference
	bundle.Export.VerificationTimestamp = payload.VerificationTimestamp
	bundle.Export.AllowBlocked = payload.AllowBlocked
	bundle.Export.AllowBlockedReasonReference = payload.AllowBlockedReasonReference
	bundle.Export.Ready = verification.Verification.Ready
	bundle.Export.VerificationState = verification.Verification.VerificationState
	bundle.Export.BlockerCode = verification.Verification.BlockerCode
	bundle.Export.Continuity = verification.Verification.Continuity
	bundle.Export.Coverage = verification.Verification.Coverage
	bundle.Export.Diagnostics = verification.Verification.Diagnostics
	jsonPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.json")
	jsonBytes, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify export json fixture: %v", err)
	}
	jsonBytes = append(jsonBytes, '\n')
	if err := os.WriteFile(jsonPath, jsonBytes, 0o600); err != nil {
		t.Fatalf("write verify export json fixture: %v", err)
	}
	return jsonPath
}

func writeRolloutClosureVerifyAttestationFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.attestation.json")
	payload := workflowRolloutClosureVerifyAttestationExportRequest{
		AttestationReference: "attestation-2026-07-21",
		AttestedByReference:  "audit-operator-1",
		AttestationTimestamp: "2026-07-21T01:40:00Z",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyAttestationManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify attestation fixture: %v", err)
	}
	if state != "" {
		manifest.Attestation.AttestationState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify attestation fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify attestation fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyAttestationIndexFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.attestation.index.json")
	payload := workflowRolloutClosureVerifyAttestationIndexExportRequest{
		AttestationIndexReference: "attestation-index-2026-07-21",
		PublishedByReference:      "release-publisher-1",
		PublishedTimestamp:        "2026-07-21T01:45:00Z",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyAttestationIndexManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify attestation index fixture: %v", err)
	}
	if state != "" {
		manifest.Index.IndexState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify attestation index fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify attestation index fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationPackageFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-package.json")
	payload := workflowRolloutClosureVerifyPublicationPackageExportRequest{
		VerificationPackageReference: "verify-package-2026-07-21",
		PackagedByReference:          "reviewer-handoff-1",
		PackagedTimestamp:            "2026-07-21T01:50:00Z",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationPackageManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication package fixture: %v", err)
	}
	if state != "" {
		manifest.Package.PackageState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication package fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication package fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationAttestationFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-attestation.json")
	payload := workflowRolloutClosureVerifyPublicationAttestationExportRequest{
		VerificationPublicationReference: "verify-publication-2026-07-21",
		PublishedByReference:             "release-ops-1",
		PublishedTimestamp:               "2026-07-21T01:55:00Z",
		PublicationChannel:               "internal-release-registry",
		PublicationLocationReference:     "registry://verification/release/2026-07-21",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationAttestationManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication attestation fixture: %v", err)
	}
	if state != "" {
		manifest.Publication.PublicationState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication attestation fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication attestation fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationIndexFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-index.json")
	payload := workflowRolloutClosureVerifyPublicationIndexExportRequest{
		VerificationPublicationIndexReference: "verify-publication-index-2026-07-21",
		IndexedByReference:                    "release-indexer-1",
		IndexedTimestamp:                      "2026-07-21T02:00:00Z",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationIndexManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication index fixture: %v", err)
	}
	if state != "" {
		manifest.Index.IndexState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication index fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication index fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationEnvelopeFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-envelope.json")
	payload := workflowRolloutClosureVerifyPublicationEnvelopeExportRequest{
		VerificationPublicationEnvelopeReference: "verify-publication-envelope-2026-07-21",
		DeliveredByReference:                     "release-delivery-operator-1",
		DeliveryTimestamp:                        "2026-07-21T02:05:00Z",
		DeliveryDestinationReference:             "release-archive://handoff",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationEnvelopeManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication envelope fixture: %v", err)
	}
	if state != "" {
		manifest.Envelope.EnvelopeState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication envelope fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication envelope fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationHandoffFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-handoff.json")
	payload := workflowRolloutClosureVerifyPublicationHandoffExportRequest{
		VerificationPublicationHandoffReference: "verify-publication-handoff-2026-07-21",
		ReceivedByReference:                     "receiver-ops-1",
		HandoffTimestamp:                        "2026-07-21T02:10:00Z",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationHandoffManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication handoff fixture: %v", err)
	}
	if state != "" {
		manifest.Handoff.HandoffState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication handoff fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication handoff fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationAcknowledgmentFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-acknowledgment.json")
	payload := workflowRolloutClosureVerifyPublicationAcknowledgmentExportRequest{
		VerificationPublicationAcknowledgmentReference: "verify-publication-acknowledgment-2026-07-21",
		AcknowledgedByReference:                        "receiver-ops-1",
		AcknowledgmentTimestamp:                        "2026-07-21T02:15:00Z",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationAcknowledgmentManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication acknowledgment fixture: %v", err)
	}
	if state != "" {
		manifest.Acknowledgment.AcknowledgmentState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication acknowledgment fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication acknowledgment fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationArchiveIndexFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-index.json")
	payload := workflowRolloutClosureVerifyPublicationArchiveIndexExportRequest{
		VerificationPublicationArchiveIndexReference: "verify-publication-archive-index-2026-07-21",
		IndexedByReference:                           "archive-indexer-1",
		IndexedTimestamp:                             "2026-07-21T02:20:00Z",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationArchiveIndexManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication archive index fixture: %v", err)
	}
	if state != "" {
		manifest.ArchiveIndex.ArchiveIndexState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication archive index fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication archive index fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationArchivePackageFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-package.json")
	payload := workflowRolloutClosureVerifyPublicationArchivePackageExportRequest{
		VerificationPublicationArchivePackageReference: "verify-publication-archive-package-2026-07-21",
		PackagedByReference:                            "archive-packager-1",
		PackagedTimestamp:                              "2026-07-21T02:25:00Z",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationArchivePackageManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication archive package fixture: %v", err)
	}
	if state != "" {
		manifest.ArchivePackage.ArchivePackageState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication archive package fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication archive package fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationArchiveEnvelopeFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-envelope.json")
	payload := workflowRolloutClosureVerifyPublicationArchiveEnvelopeExportRequest{
		VerificationPublicationArchiveEnvelopeReference: "verify-publication-archive-envelope-2026-07-21",
		DeliveredByReference:                            "archive-delivery-operator-1",
		DeliveryTimestamp:                               "2026-07-21T02:30:00Z",
		DeliveryDestinationReference:                    "archive://offline-vault",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationArchiveEnvelopeManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication archive envelope fixture: %v", err)
	}
	if state != "" {
		manifest.ArchiveEnvelope.ArchiveEnvelopeState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication archive envelope fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication archive envelope fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationArchiveHandoffFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-handoff.json")
	payload := workflowRolloutClosureVerifyPublicationArchiveHandoffExportRequest{
		VerificationPublicationArchiveHandoffReference: "verify-publication-archive-handoff-2026-07-21",
		ReceivedByReference:                            "archive-receiver-1",
		HandoffTimestamp:                               "2026-07-21T02:35:00Z",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationArchiveHandoffManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication archive handoff fixture: %v", err)
	}
	if state != "" {
		manifest.ArchiveHandoff.ArchiveHandoffState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication archive handoff fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication archive handoff fixture: %v", err)
	}
	return manifestPath
}

func writeRolloutClosureVerifyPublicationArchiveAcknowledgmentFixture(t *testing.T, workspacePath, state string) string {
	t.Helper()
	manifestPath := filepath.Join(workspacePath, "workflow.rollout-closure-verify.publication-archive-acknowledgment.json")
	payload := workflowRolloutClosureVerifyPublicationArchiveAcknowledgmentExportRequest{
		VerificationPublicationArchiveAcknowledgmentReference: "verify-publication-archive-acknowledgment-2026-07-21",
		AcknowledgedByReference:                               "archive-reviewer-1",
		AcknowledgmentTimestamp:                               "2026-07-21T02:40:00Z",
	}
	manifest, _, err := buildWorkflowRolloutClosureVerifyPublicationArchiveAcknowledgmentManifest(workspacePath, payload)
	if err != nil {
		t.Fatalf("build verify publication archive acknowledgment fixture: %v", err)
	}
	if state != "" {
		manifest.ArchiveAcknowledgment.ArchiveAcknowledgmentState = state
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal verify publication archive acknowledgment fixture: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write verify publication archive acknowledgment fixture: %v", err)
	}
	return manifestPath
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
