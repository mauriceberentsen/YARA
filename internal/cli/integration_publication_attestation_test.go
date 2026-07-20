package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestIntegrationPublishAttestWritesArtifactAndAudit(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	evidenceDir := filepath.Join(directory, "evidence")
	if err := mkdirAll(evidenceDir); err != nil {
		t.Fatal(err)
	}
	result := deterministicIntegrationResultFixtureForCLI(t, catalogDigest)
	result.Spec.ComponentRefs = []string{"core.vllm@0.25.1"}
	slices.Sort(result.Spec.ComponentRefs)
	var assignErr error
	result, assignErr = result.AssignResultID()
	if assignErr != nil {
		t.Fatalf("assign integration publication evidence id: %v", assignErr)
	}
	evidencePath := filepath.Join(evidenceDir, "component-smoke.yaml")
	writeYAMLFixture(t, evidencePath, result)
	writeIntegrationPublicationEvidenceAuditFixture(t, strings.TrimSuffix(evidencePath, ".yaml")+".audit.jsonl", catalogDigest, result.Metadata.ResultID, result.Spec.Environment.ReferenceDigest, time.Now().UTC().Add(-30*time.Minute))
	outputPath := filepath.Join(directory, "integration-publication-attestation.yaml")
	auditPath := filepath.Join(directory, "integration-publication-attestation.audit.jsonl")
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"integration", "publish", "attest",
		"--catalog", catalogPath,
		"--evidence-dir", evidenceDir,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--evidence", result.Metadata.ResultID,
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-integration-publication-123",
		"--max-evidence-age", "720h",
		"--name", "integration-publication-attestation",
		"--output", outputPath,
		"--audit-output", auditPath,
	}, &stdout, &stderr)
	if exit != ExitSuccess {
		t.Fatalf("integration publish attest failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	attestation, err := resources.LoadIntegrationPublicationAttestation(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !attestation.Validate().Valid || attestation.Spec.AssertionRef != "compat.vllm-qwen-coder-7b-awq-gb10" || attestation.Spec.Decision != resources.PromotionDecisionApproved {
		t.Fatalf("unexpected integration publication attestation output: %#v", attestation.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "integration.publish.attestation.completed" {
		t.Fatalf("terminal integration publication attestation audit missing: %#v", events)
	}
}

func TestIntegrationPublishAttestRejectsStaleEvidence(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		t.Fatal(err)
	}
	evidenceDir := filepath.Join(directory, "evidence")
	if err := mkdirAll(evidenceDir); err != nil {
		t.Fatal(err)
	}
	result := deterministicIntegrationResultFixtureForCLI(t, catalogDigest)
	result.Spec.ComponentRefs = []string{"core.vllm@0.25.1"}
	slices.Sort(result.Spec.ComponentRefs)
	var assignErr error
	result, assignErr = result.AssignResultID()
	if assignErr != nil {
		t.Fatalf("assign integration publication evidence id: %v", assignErr)
	}
	evidencePath := filepath.Join(evidenceDir, "component-smoke.yaml")
	writeYAMLFixture(t, evidencePath, result)
	writeIntegrationPublicationEvidenceAuditFixture(t, strings.TrimSuffix(evidencePath, ".yaml")+".audit.jsonl", catalogDigest, result.Metadata.ResultID, result.Spec.Environment.ReferenceDigest, time.Now().UTC().Add(-48*time.Hour))
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"integration", "publish", "attest",
		"--catalog", catalogPath,
		"--evidence-dir", evidenceDir,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--evidence", result.Metadata.ResultID,
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-integration-publication-123",
		"--max-evidence-age", "1h",
		"--name", "integration-publication-attestation",
		"--output", filepath.Join(directory, "integration-publication-attestation.yaml"),
		"--audit-output", filepath.Join(directory, "integration-publication-attestation.audit.jsonl"),
	}, &stdout, &stderr)
	if exit != ExitInfeasible {
		t.Fatalf("stale integration evidence should fail: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func writeIntegrationPublicationEvidenceAuditFixture(t *testing.T, path, catalogDigest, resultID, targetDigest string, occurredAt time.Time) {
	t.Helper()
	chain := audit.NewChain()
	at := occurredAt.UTC().Format(time.RFC3339Nano)
	started, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "integration-publish-started", OccurredAt: at},
		Spec: audit.Spec{
			CorrelationID: "integration-publish-attestation",
			Actor:         audit.Actor{ID: "local:runner", Type: "user", Assurance: "self-asserted-local"},
			Action:        "integration.component-smoke.started",
			Subjects:      []audit.Subject{{Kind: "CatalogSnapshot", Digest: catalogDigest}},
			Reason:        audit.Reason{Type: "user-request", Reference: "test"},
			Target:        "local:" + targetDigest,
			Outcome:       "started",
		},
	})
	if err != nil {
		t.Fatalf("append started integration evidence audit: %v", err)
	}
	terminal, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "integration-publish-terminal", OccurredAt: at},
		Spec: audit.Spec{
			CorrelationID: "integration-publish-attestation",
			CausationID:   started.Metadata.ID,
			Actor:         audit.Actor{ID: "local:runner", Type: "user", Assurance: "self-asserted-local"},
			Action:        "integration.component-smoke.completed",
			Subjects: []audit.Subject{
				{Kind: "CatalogSnapshot", Digest: catalogDigest},
				{Kind: "IntegrationTestResult", Digest: resultID},
			},
			Reason:  audit.Reason{Type: "user-request", Reference: "test"},
			Target:  "local:" + targetDigest,
			Outcome: "success",
		},
	})
	if err != nil {
		t.Fatalf("append terminal integration evidence audit: %v", err)
	}
	var buffer bytes.Buffer
	if err := audit.EncodeJSONL(&buffer, []audit.Event{started, terminal}); err != nil {
		t.Fatalf("encode integration evidence audit fixture: %v", err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("write integration evidence audit fixture: %v", err)
	}
}

func mkdirAll(path string) error {
	return os.MkdirAll(path, 0o755)
}
