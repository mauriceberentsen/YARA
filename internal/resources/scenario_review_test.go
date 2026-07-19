package resources

import (
	"path/filepath"
	"testing"
)

func TestScenarioReviewConformsToPrivateChatCodingFixture(t *testing.T) {
	golden, err := LoadGoldenScenario(filepath.Join("..", "..", "scenarios", "v0.1", "private-chat-coding", "scenario.yaml"))
	if err != nil {
		t.Fatalf("load scenario: %v", err)
	}
	review, err := LoadScenarioReview(filepath.Join("..", "..", "scenarios", "v0.1", "private-chat-coding", "review.yaml"))
	if err != nil {
		t.Fatalf("load review: %v", err)
	}
	if report := review.ConformsTo(golden); !report.Valid {
		t.Fatalf("review does not conform: %#v", report.Diagnostics)
	}
}

func TestAcceptanceGateReviewFixtureIsApproved(t *testing.T) {
	review, err := LoadAcceptanceGateReview(filepath.Join("..", "..", "docs", "implementation", "reviews", "environment-offline-cli-review.yaml"))
	if err != nil {
		t.Fatalf("load gate review: %v", err)
	}
	if !review.Approved() {
		t.Fatalf("gate review not approved: %#v", review.Validate().Diagnostics)
	}
}
