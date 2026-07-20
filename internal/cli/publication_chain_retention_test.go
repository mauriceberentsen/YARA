package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestPublicationChainRetentionDiagnosticsClassifiesRenewableAndNonRenewable(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	catalogDigest := "sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241"
	renewable := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-15*time.Minute).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	renewablePath := filepath.Join(directory, "renewable-rehearsal.yaml")
	writeYAMLFixture(t, renewablePath, renewable)
	nonRenewable := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339Nano), resources.PromotionDecisionChangesRequired)
	nonRenewablePath := filepath.Join(directory, "non-renewable-rehearsal.yaml")
	writeYAMLFixture(t, nonRenewablePath, nonRenewable)
	candidate := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-5*time.Minute).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	candidatePath := filepath.Join(directory, "candidate-rehearsal.yaml")
	writeYAMLFixture(t, candidatePath, candidate)
	auditPath := filepath.Join(directory, "retention.audit.jsonl")
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"publication", "chain", "retention-diagnostics",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--current-rehearsal", renewablePath,
		"--current-rehearsal", nonRenewablePath,
		"--candidate-rehearsal", candidatePath,
		"--audit-output", auditPath,
	}, &stdout, &stderr)
	if exit != ExitSuccess {
		t.Fatalf("publication chain retention diagnostics failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "publication.chain.retention-diagnostics.completed" {
		t.Fatalf("terminal retention diagnostics audit missing: %#v", events)
	}
	var result struct {
		CurrentRehearsals []struct {
			RehearsalID string `json:"rehearsalId"`
			Status      string `json:"status"`
			Reason      string `json:"reason"`
		} `json:"currentRehearsals"`
		CandidateRehearsal struct {
			RehearsalID string `json:"rehearsalId"`
		} `json:"candidateRehearsal"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode retention diagnostics output: %v", err)
	}
	if len(result.CurrentRehearsals) != 2 {
		t.Fatalf("expected 2 rehearsal states, got %d", len(result.CurrentRehearsals))
	}
	statuses := map[string]string{}
	for _, item := range result.CurrentRehearsals {
		statuses[item.RehearsalID] = item.Status
	}
	if statuses[renewable.Metadata.RehearsalID] != "renewable" || statuses[nonRenewable.Metadata.RehearsalID] != "non-renewable" {
		t.Fatalf("unexpected retention classifications: %#v", result.CurrentRehearsals)
	}
	if result.CandidateRehearsal.RehearsalID != candidate.Metadata.RehearsalID {
		t.Fatalf("candidate rehearsal id mismatch: got=%q want=%q", result.CandidateRehearsal.RehearsalID, candidate.Metadata.RehearsalID)
	}
}

func TestPublicationChainRetentionDiagnosticsRejectsCandidateIdentityReuse(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	catalogDigest := "sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241"
	current := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-15*time.Minute).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	currentPath := filepath.Join(directory, "current-rehearsal.yaml")
	writeYAMLFixture(t, currentPath, current)
	candidatePath := filepath.Join(directory, "candidate-rehearsal.yaml")
	writeYAMLFixture(t, candidatePath, current)
	auditPath := filepath.Join(directory, "retention.audit.jsonl")
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"publication", "chain", "retention-diagnostics",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--current-rehearsal", currentPath,
		"--candidate-rehearsal", candidatePath,
		"--audit-output", auditPath,
	}, &stdout, &stderr)
	if exit != ExitInfeasible {
		t.Fatalf("candidate identity reuse should fail infeasible: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestPublicationChainRetentionDiagnosticsRejectsStaleCandidate(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	catalogDigest := "sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241"
	current := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-15*time.Minute).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	currentPath := filepath.Join(directory, "current-rehearsal.yaml")
	writeYAMLFixture(t, currentPath, current)
	candidate := publicationChainRehearsalFixture(t, catalogDigest, "compat.vllm-qwen-coder-7b-awq-gb10", time.Now().UTC().Add(-744*time.Hour).Format(time.RFC3339Nano), resources.PromotionDecisionApproved)
	candidatePath := filepath.Join(directory, "candidate-rehearsal.yaml")
	writeYAMLFixture(t, candidatePath, candidate)
	auditPath := filepath.Join(directory, "retention.audit.jsonl")
	var stdout, stderr bytes.Buffer
	exit := Run([]string{
		"publication", "chain", "retention-diagnostics",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--current-rehearsal", currentPath,
		"--candidate-rehearsal", candidatePath,
		"--audit-output", auditPath,
	}, &stdout, &stderr)
	if exit != ExitInfeasible {
		t.Fatalf("stale candidate should fail infeasible: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}
