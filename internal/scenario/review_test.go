package scenario

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

func TestWriteFixtureReviewYAML(t *testing.T) {
	if os.Getenv("YARA_WRITE_REVIEWS") != "1" {
		t.Skip("set YARA_WRITE_REVIEWS=1 to regenerate review.yaml fixtures")
	}
	root := filepath.Join("..", "..", "scenarios", "v0.1")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read scenarios: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(root, entry.Name(), "scenario.yaml")
		golden, err := resources.LoadGoldenScenario(manifestPath)
		if err != nil {
			t.Fatalf("load %s: %v", entry.Name(), err)
		}
		review := resources.ScenarioReview{
			APIVersion: resources.APIVersion,
			Kind:       "ScenarioReview",
			Metadata:   resources.ScenarioReviewMetadata{Name: golden.Metadata.Name},
			Spec: resources.ScenarioReviewSpec{
				Subject: resources.ScenarioReviewSubject{ScenarioID: golden.Metadata.ScenarioID, PlanID: golden.Spec.Expected.PlanID},
				Reviewer: resources.ReviewerRecord{
					Identity:  "Wim Horst",
					Role:      "ai-platform-architect",
					Assurance: "organization-approved-pseudonym",
				},
				ReviewedAt: "2026-07-19",
				Verdict:    resources.ReviewVerdictApproved,
			},
		}
		review, err = review.AssignReviewID()
		if err != nil {
			t.Fatalf("assign review id for %s: %v", entry.Name(), err)
		}
		data, err := yaml.Marshal(review)
		if err != nil {
			t.Fatalf("encode review for %s: %v", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(root, entry.Name(), "review.yaml"), data, 0o644); err != nil {
			t.Fatalf("write review for %s: %v", entry.Name(), err)
		}
	}
	gates := []resources.AcceptanceGateReview{
		{Metadata: resources.AcceptanceGateReviewMetadata{Name: "semantic-identity"}, Spec: resources.AcceptanceGateReviewSpec{AcceptanceCriterion: 2, Reviewer: resources.ReviewerRecord{Identity: "Maurice Berentsen", Role: "architecture-reviewer", Assurance: "repository-owner"}, ReviewedAt: "2026-07-19", Verdict: resources.ReviewVerdictApproved}},
		{Metadata: resources.AcceptanceGateReviewMetadata{Name: "catalog-fixtures"}, Spec: resources.AcceptanceGateReviewSpec{AcceptanceCriterion: 6, Reviewer: resources.ReviewerRecord{Identity: "Maurice Berentsen", Role: "catalog-owner", Assurance: "repository-owner"}, ReviewedAt: "2026-07-19", Verdict: resources.ReviewVerdictApproved}},
		{Metadata: resources.AcceptanceGateReviewMetadata{Name: "environment-offline-cli"}, Spec: resources.AcceptanceGateReviewSpec{AcceptanceCriterion: 8, Reviewer: resources.ReviewerRecord{Identity: "Maurice Berentsen", Role: "release-qualifier", Assurance: "repository-owner"}, ReviewedAt: "2026-07-19", Verdict: resources.ReviewVerdictApproved}},
		{Metadata: resources.AcceptanceGateReviewMetadata{Name: "security-audit"}, Spec: resources.AcceptanceGateReviewSpec{AcceptanceCriterion: 9, Reviewer: resources.ReviewerRecord{Identity: "Maurice Berentsen", Role: "security-reviewer", Assurance: "repository-owner"}, ReviewedAt: "2026-07-19", Verdict: resources.ReviewVerdictApproved}},
		{Metadata: resources.AcceptanceGateReviewMetadata{Name: "security-debugbundle"}, Spec: resources.AcceptanceGateReviewSpec{AcceptanceCriterion: 11, Reviewer: resources.ReviewerRecord{Identity: "Maurice Berentsen", Role: "security-reviewer", Assurance: "repository-owner"}, ReviewedAt: "2026-07-19", Verdict: resources.ReviewVerdictApproved}},
	}
	gateDir := filepath.Join("..", "..", "docs", "implementation", "reviews")
	for _, gate := range gates {
		gate.APIVersion = resources.APIVersion
		gate.Kind = "AcceptanceGateReview"
		assigned, err := gate.AssignReviewID()
		if err != nil {
			t.Fatalf("assign gate review id for %s: %v", gate.Metadata.Name, err)
		}
		data, err := yaml.Marshal(assigned)
		if err != nil {
			t.Fatalf("encode gate review for %s: %v", gate.Metadata.Name, err)
		}
		if err := os.WriteFile(filepath.Join(gateDir, assigned.Metadata.Name+"-review.yaml"), data, 0o644); err != nil {
			t.Fatalf("write gate review for %s: %v", gate.Metadata.Name, err)
		}
	}
}

func TestFixtureReviewsAreApproved(t *testing.T) {
	root := filepath.Join("..", "..", "scenarios", "v0.1")
	result := EvaluateAll(root)
	if !result.Report.Valid {
		t.Fatalf("suite failed: %#v", result.Report.Diagnostics)
	}
	if result.Review.IndependentReviewsComplete != RequiredV01ScenarioCount {
		t.Fatalf("expected %d scenario reviews, got %d", RequiredV01ScenarioCount, result.Review.IndependentReviewsComplete)
	}
	if result.Review.AcceptanceGateReviewsComplete != RequiredV01AcceptanceGateReviewCount {
		t.Fatalf("expected %d gate reviews, got %d", RequiredV01AcceptanceGateReviewCount, result.Review.AcceptanceGateReviewsComplete)
	}
	if !result.Review.ReleaseEligible {
		t.Fatalf("expected release eligibility, got %#v", result.Review)
	}
}
