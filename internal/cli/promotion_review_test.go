package cli

import (
	"bytes"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestPromotionReviewRecordWritesReviewAndAudit(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	catalogDigest := "sha256:0f7062b289e322a1c676cc52282cb9b0c816894bb3452535b790290e94ca0241"
	outputPath := filepath.Join(directory, "promotion-review.yaml")
	auditPath := filepath.Join(directory, "promotion-review.audit.jsonl")
	args := []string{
		"promotion", "review", "record",
		"--catalog", catalogPath,
		"--assertion", "compat.vllm-qwen-coder-7b-awq-gb10",
		"--evidence", testCLIDigest('a'),
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-promotion-1",
		"--name", "gb10-promotion-review",
		"--output", outputPath,
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("promotion review record failed: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	review, err := resources.LoadPromotionReview(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if review.Spec.CatalogDigest != catalogDigest || review.Spec.Decision != resources.PromotionDecisionApproved {
		t.Fatalf("promotion review missing expected binding: %#v", review.Spec)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "promotion.review.completed" || events[1].Spec.Target != "catalog:"+catalogDigest {
		t.Fatalf("promotion review audit did not bind catalog target: %#v", events)
	}
}

func TestPromotionReviewRecordRejectsUnknownAssertionAndAuditsFailure(t *testing.T) {
	directory := t.TempDir()
	catalogPath := filepath.Join("..", "..", "catalog", "v0.2", "snapshot.yaml")
	auditPath := filepath.Join(directory, "promotion-review.audit.jsonl")
	args := []string{
		"promotion", "review", "record",
		"--catalog", catalogPath,
		"--assertion", "compat.unknown",
		"--evidence", testCLIDigest('a'),
		"--reviewer-role", "release-manager",
		"--decision", "approved",
		"--reason-reference", "ticket-promotion-2",
		"--name", "invalid-promotion-review",
		"--output", filepath.Join(directory, "promotion-review.yaml"),
		"--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exit := Run(args, &stdout, &stderr); exit != ExitInvalidInput {
		t.Fatalf("unknown assertion should fail invalid input: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[1].Spec.Action != "promotion.review.failed" || !slices.Contains(events[1].Spec.DiagnosticCodes, "YARA-PRM-102") {
		t.Fatalf("promotion review failure was not durably audited: %#v", events)
	}
}
