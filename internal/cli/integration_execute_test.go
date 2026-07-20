package cli

import (
	"bytes"
	"context"
	"path/filepath"
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
	if exit := runIntegrationAt("component-smoke", args, &stdout, &stderr, func() time.Time { return now }); exit != ExitSuccess {
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
	if exit := runIntegrationAt("topology-end-to-end", args, &stdout, &stderr, time.Now); exit != ExitInfeasible {
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
		}); exit != ExitSuccess {
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
