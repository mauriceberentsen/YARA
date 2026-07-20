package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type fixedIntegrationExecutor struct {
	componentSmoke func(context.Context, catalog.Snapshot, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error)
	topology       func(context.Context, catalog.Snapshot, string, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error)
}

func (f fixedIntegrationExecutor) ComponentSmoke(ctx context.Context, snapshot catalog.Snapshot, refs []string, env resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
	return f.componentSmoke(ctx, snapshot, refs, env)
}

func (f fixedIntegrationExecutor) TopologyEndToEnd(ctx context.Context, snapshot catalog.Snapshot, topologyRef string, refs []string, env resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
	return f.topology(ctx, snapshot, topologyRef, refs, env)
}

func TestIntegrationComponentSmokeWritesExecutionAuditAndResult(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "component.yaml")
	auditPath := filepath.Join(directory, "component.audit.jsonl")
	now := time.Date(2026, 7, 20, 10, 30, 0, 0, time.UTC)
	original := integrationRun
	t.Cleanup(func() { integrationRun = original })
	integrationRun = fixedIntegrationExecutor{
		componentSmoke: func(_ context.Context, _ catalog.Snapshot, refs []string, env resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			if len(refs) != 1 || refs[0] != "core.litellm@1.93.0" || env.Transport != "local" {
				t.Fatalf("unexpected integration execution inputs: refs=%#v env=%#v", refs, env)
			}
			return []resources.ContractTestCheck{{
				ID:             "component.health",
				Status:         "passed",
				EvidenceDigest: testCLIDigest('a'),
			}}, []string{"bounded smoke check"}, nil
		},
		topology: func(context.Context, catalog.Snapshot, string, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			t.Fatal("topology executor should not be called")
			return nil, nil, nil
		},
	}
	args := []string{
		"--catalog", catalogPath,
		"--target", "local",
		"--component", "core.litellm@1.93.0",
		"--confirm-catalog-digest", digest,
		"--name", "component-smoke",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := runIntegrationAt("component-smoke", args, &stdout, &stderr, func() time.Time { return now }, ""); exit != ExitSuccess {
		t.Fatalf("component-smoke exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	result, err := resources.LoadIntegrationTestResult(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Spec.Mode != "component-smoke" || result.Spec.Outcome != "passed" || result.Metadata.ResultID == "" {
		t.Fatalf("unexpected integration result: %#v", result)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Spec.Action != "integration.component-smoke.started" || events[1].Spec.Action != "integration.component-smoke.completed" {
		t.Fatalf("unexpected integration audit actions: %#v", events)
	}
}

func TestIntegrationTopologyBlockedProducesBlockedTerminalAudit(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "topology.yaml")
	auditPath := filepath.Join(directory, "topology.audit.jsonl")
	original := integrationRun
	t.Cleanup(func() { integrationRun = original })
	integrationRun = fixedIntegrationExecutor{
		componentSmoke: func(context.Context, catalog.Snapshot, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			t.Fatal("component-smoke executor should not be called")
			return nil, nil, nil
		},
		topology: func(_ context.Context, _ catalog.Snapshot, topologyRef string, refs []string, _ resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			if topologyRef == "" || len(refs) < 2 {
				t.Fatalf("unexpected topology execution inputs: topology=%q refs=%#v", topologyRef, refs)
			}
			return []resources.ContractTestCheck{{
				ID:             "topology.role-coverage",
				Status:         "blocked",
				DiagnosticCode: "YARA-INT-103",
				EvidenceDigest: testCLIDigest('b'),
			}}, []string{"blocked role coverage"}, nil
		},
	}
	args := []string{
		"--catalog", catalogPath,
		"--target", "local",
		"--topology", "core.local-chat-coding-vllm@1.0.0",
		"--component", "core.litellm@1.93.0",
		"--component", "core.vllm@0.25.1",
		"--confirm-catalog-digest", digest,
		"--name", "topology-e2e",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := runIntegrationAt("topology-end-to-end", args, &stdout, &stderr, time.Now, ""); exit != ExitInfeasible {
		t.Fatalf("topology-end-to-end exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "integration.topology-end-to-end.blocked" || events[1].Spec.Outcome != "infeasible" {
		t.Fatalf("unexpected blocked integration audit: %#v", events)
	}
}

func TestIntegrationExecutionDeterministicResultIdentity(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	original := integrationRun
	t.Cleanup(func() { integrationRun = original })
	integrationRun = fixedIntegrationExecutor{
		componentSmoke: func(context.Context, catalog.Snapshot, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			return []resources.ContractTestCheck{
				{ID: "a.check", Status: "passed", EvidenceDigest: testCLIDigest('c')},
				{ID: "b.check", Status: "passed", EvidenceDigest: testCLIDigest('d')},
			}, []string{"deterministic check set"}, nil
		},
		topology: func(context.Context, catalog.Snapshot, string, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			return nil, nil, nil
		},
	}
	run := func(index int) string {
		outputPath := filepath.Join(directory, "component-"+string(rune('0'+index))+".yaml")
		auditPath := filepath.Join(directory, "component-"+string(rune('0'+index))+".audit.jsonl")
		args := []string{
			"--catalog", catalogPath,
			"--target", "local",
			"--component", "core.litellm@1.93.0",
			"--confirm-catalog-digest", digest,
			"--name", "deterministic-component-smoke",
			"--output", outputPath,
			"--audit-output", auditPath,
		}
		var stdout, stderr bytes.Buffer
		if exit := runIntegrationAt("component-smoke", args, &stdout, &stderr, func() time.Time {
			return time.Date(2026, 7, 20, 10, 40, 0, 0, time.UTC)
		}, ""); exit != ExitSuccess {
			t.Fatalf("deterministic run %d exit=%d stdout=%s stderr=%s", index, exit, stdout.String(), stderr.String())
		}
		result, err := resources.LoadIntegrationTestResult(outputPath)
		if err != nil {
			t.Fatal(err)
		}
		return result.Metadata.ResultID
	}
	first, second := run(1), run(2)
	if first != second {
		t.Fatalf("integration result identity is not deterministic: %s != %s", first, second)
	}
}

func TestIntegrationExecuteDispatchesComponentSmokeMode(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "execute-component.yaml")
	auditPath := filepath.Join(directory, "execute-component.audit.jsonl")
	original := integrationRun
	t.Cleanup(func() { integrationRun = original })
	called := false
	integrationRun = fixedIntegrationExecutor{
		componentSmoke: func(_ context.Context, _ catalog.Snapshot, refs []string, _ resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			called = true
			if len(refs) != 1 || refs[0] != "core.litellm@1.93.0" {
				t.Fatalf("unexpected refs: %#v", refs)
			}
			return []resources.ContractTestCheck{{ID: "execute.component.check", Status: "passed", EvidenceDigest: testCLIDigest('e')}}, []string{"generic execute dispatch"}, nil
		},
		topology: func(context.Context, catalog.Snapshot, string, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			t.Fatal("topology executor should not be called")
			return nil, nil, nil
		},
	}
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"integration", "execute", "component-smoke",
		"--catalog", catalogPath,
		"--target", "local",
		"--component", "core.litellm@1.93.0",
		"--confirm-catalog-digest", digest,
		"--name", "generic-component-smoke",
		"--output", outputPath,
		"--audit-output", auditPath,
	}, &stdout, &stderr)
	if exit != ExitSuccess {
		t.Fatalf("integration execute component-smoke failed with %d: stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if !called {
		t.Fatal("component-smoke executor was not dispatched")
	}
}

func TestIntegrationExecuteRejectsUnsupportedModeWithoutExecutorCall(t *testing.T) {
	original := integrationRun
	t.Cleanup(func() { integrationRun = original })
	integrationRun = fixedIntegrationExecutor{
		componentSmoke: func(context.Context, catalog.Snapshot, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			t.Fatal("component executor must not be called for unsupported mode")
			return nil, nil, nil
		},
		topology: func(context.Context, catalog.Snapshot, string, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			t.Fatal("topology executor must not be called for unsupported mode")
			return nil, nil, nil
		},
	}
	var stdout, stderr bytes.Buffer
	exit := Run([]string{"integration", "execute", "unknown-mode"}, &stdout, &stderr)
	if exit != ExitInvalidInput {
		t.Fatalf("unsupported integration execute mode must return invalid input, got %d", exit)
	}
	var failure struct {
		Diagnostics []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &failure); err != nil {
		t.Fatalf("decode unsupported mode response: %v", err)
	}
	if len(failure.Diagnostics) == 0 || failure.Diagnostics[0].Code != "YARA-INT-111" || !strings.Contains(failure.Diagnostics[0].Message, "remediation: choose integration execute component-smoke or topology-end-to-end") {
		t.Fatalf("unsupported mode remediation guidance missing: %#v", failure.Diagnostics)
	}
}

func TestIntegrationTopologyExecuteRejectsStaleBindingWithoutExecutorCall(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "execute-topology.yaml")
	auditPath := filepath.Join(directory, "execute-topology.audit.jsonl")
	original := integrationRun
	t.Cleanup(func() { integrationRun = original })
	integrationRun = fixedIntegrationExecutor{
		componentSmoke: func(context.Context, catalog.Snapshot, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			t.Fatal("component executor must not run for stale topology binding")
			return nil, nil, nil
		},
		topology: func(context.Context, catalog.Snapshot, string, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			t.Fatal("topology executor must not run for stale topology binding")
			return nil, nil, nil
		},
	}
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"integration", "execute", "topology-end-to-end",
		"--catalog", catalogPath,
		"--target", "local",
		"--topology", "core.local-chat-coding-vllm@1.0.0",
		"--component", "core.litellm@1.93.0",
		"--component", "core.open-webui@0.10.2",
		"--confirm-catalog-digest", digest,
		"--name", "stale-topology-binding",
		"--output", outputPath,
		"--audit-output", auditPath,
	}, &stdout, &stderr)
	if exit != ExitInfeasible {
		t.Fatalf("expected infeasible exit for stale topology binding, got %d: stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	var failure struct {
		Diagnostics []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &failure); err != nil {
		t.Fatalf("decode stale binding response: %v", err)
	}
	if len(failure.Diagnostics) == 0 || failure.Diagnostics[0].Code != "YARA-INT-109" || !strings.Contains(failure.Diagnostics[0].Message, "remediation: include a component bound to a supported compatibility runtime assertion") {
		t.Fatalf("stale binding remediation guidance missing: %#v", failure.Diagnostics)
	}
}

func TestIntegrationTopologyExecuteRejectsMissingRoleCoverageWithoutExecutorCall(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "execute-topology-role-drift.yaml")
	auditPath := filepath.Join(directory, "execute-topology-role-drift.audit.jsonl")
	original := integrationRun
	t.Cleanup(func() { integrationRun = original })
	integrationRun = fixedIntegrationExecutor{
		componentSmoke: func(context.Context, catalog.Snapshot, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			t.Fatal("component executor must not run for role-coverage drift")
			return nil, nil, nil
		},
		topology: func(context.Context, catalog.Snapshot, string, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			t.Fatal("topology executor must not run for role-coverage drift")
			return nil, nil, nil
		},
	}
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"integration", "execute", "topology-end-to-end",
		"--catalog", catalogPath,
		"--target", "local",
		"--topology", "core.local-chat-coding-vllm@1.0.0",
		"--component", "core.qdrant@1.18.3",
		"--component", "core.vllm@0.25.1",
		"--confirm-catalog-digest", digest,
		"--name", "role-coverage-drift",
		"--output", outputPath,
		"--audit-output", auditPath,
	}, &stdout, &stderr)
	if exit != ExitInfeasible {
		t.Fatalf("expected infeasible exit for role-coverage drift, got %d: stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	var failure struct {
		Diagnostics []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &failure); err != nil {
		t.Fatalf("decode role drift response: %v", err)
	}
	if len(failure.Diagnostics) == 0 || failure.Diagnostics[0].Code != "YARA-INT-110" || !strings.Contains(failure.Diagnostics[0].Message, "remediation: select components that satisfy every topology role from the catalog topology reference") {
		t.Fatalf("role drift remediation guidance missing: %#v", failure.Diagnostics)
	}
}

func TestIntegrationExecutePreservesNormalizationAndIdentityParity(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	original := integrationRun
	t.Cleanup(func() { integrationRun = original })
	observedRefs := [][]string{}
	integrationRun = fixedIntegrationExecutor{
		componentSmoke: func(_ context.Context, _ catalog.Snapshot, refs []string, _ resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			observedRefs = append(observedRefs, append([]string{}, refs...))
			return []resources.ContractTestCheck{
				{ID: "parity.a", Status: "passed", EvidenceDigest: testCLIDigest('f')},
				{ID: "parity.b", Status: "passed", EvidenceDigest: testCLIDigest('e')},
			}, []string{"parity-check"}, nil
		},
		topology: func(context.Context, catalog.Snapshot, string, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
			t.Fatal("topology executor should not be called for component parity")
			return nil, nil, nil
		},
	}
	runDirect := func(outputPath, auditPath string) (string, string) {
		args := []string{
			"--catalog", catalogPath,
			"--target", "local",
			"--component", "core.vllm@0.25.1",
			"--component", "core.litellm@1.93.0",
			"--component", "core.vllm@0.25.1",
			"--confirm-catalog-digest", digest,
			"--name", "parity-direct",
			"--output", outputPath,
			"--audit-output", auditPath,
		}
		var stdout, stderr bytes.Buffer
		exit := runIntegrationAt("component-smoke", args, &stdout, &stderr, func() time.Time { return time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC) }, "")
		if exit != ExitSuccess {
			t.Fatalf("direct component-smoke failed with %d: stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
		}
		var response struct {
			ResultID string `json:"resultId"`
			ModePath string `json:"modePath"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
			t.Fatalf("decode direct response: %v", err)
		}
		return response.ResultID, response.ModePath
	}
	runGeneric := func(outputPath, auditPath string) (string, string) {
		var stdout, stderr bytes.Buffer
		exit := Run([]string{
			"integration", "execute", "component-smoke",
			"--catalog", catalogPath,
			"--target", "local",
			"--component", "core.vllm@0.25.1",
			"--component", "core.litellm@1.93.0",
			"--component", "core.vllm@0.25.1",
			"--confirm-catalog-digest", digest,
			"--name", "parity-direct",
			"--output", outputPath,
			"--audit-output", auditPath,
		}, &stdout, &stderr)
		if exit != ExitSuccess {
			t.Fatalf("generic execute component-smoke failed with %d: stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
		}
		var response struct {
			ResultID string `json:"resultId"`
			ModePath string `json:"modePath"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
			t.Fatalf("decode generic response: %v", err)
		}
		return response.ResultID, response.ModePath
	}
	directID, directModePath := runDirect(filepath.Join(directory, "parity-direct.yaml"), filepath.Join(directory, "parity-direct.audit.jsonl"))
	genericID, genericModePath := runGeneric(filepath.Join(directory, "parity-generic.yaml"), filepath.Join(directory, "parity-generic.audit.jsonl"))
	if directID != genericID {
		t.Fatalf("generic execute changed deterministic result identity: direct=%s generic=%s", directID, genericID)
	}
	if directModePath != "" {
		t.Fatalf("direct mode-specific path must remain empty, got %q", directModePath)
	}
	if genericModePath != "integration.execute.component-smoke" {
		t.Fatalf("generic execute explainability mode path mismatch: %q", genericModePath)
	}
	if len(observedRefs) != 2 {
		t.Fatalf("expected refs from direct and generic runs, got %d", len(observedRefs))
	}
	expected := []string{"core.litellm@1.93.0", "core.vllm@0.25.1"}
	for _, refs := range observedRefs {
		if len(refs) != len(expected) || refs[0] != expected[0] || refs[1] != expected[1] {
			t.Fatalf("component normalization drifted: got %#v expected %#v", refs, expected)
		}
	}
}
