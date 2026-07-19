package resources

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

var RequiredV01AcceptanceGateCriteria = []int{2, 6, 8, 9, 11}

type AcceptanceGateReview struct {
	APIVersion string                       `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                       `json:"kind" yaml:"kind"`
	Metadata   AcceptanceGateReviewMetadata `json:"metadata" yaml:"metadata"`
	Spec       AcceptanceGateReviewSpec     `json:"spec" yaml:"spec"`
}

type AcceptanceGateReviewMetadata struct {
	Name     string `json:"name" yaml:"name"`
	ReviewID string `json:"reviewId" yaml:"reviewId"`
}

type AcceptanceGateReviewSpec struct {
	AcceptanceCriterion int            `json:"acceptanceCriterion" yaml:"acceptanceCriterion"`
	Reviewer            ReviewerRecord `json:"reviewer" yaml:"reviewer"`
	ReviewedAt          string         `json:"reviewedAt" yaml:"reviewedAt"`
	Verdict             string         `json:"verdict" yaml:"verdict"`
}

func (r AcceptanceGateReview) AssignReviewID() (AcceptanceGateReview, error) {
	r.Metadata.ReviewID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return AcceptanceGateReview{}, fmt.Errorf("digest acceptance gate review: %w", err)
	}
	r.Metadata.ReviewID = digest
	return r, nil
}

func (r AcceptanceGateReview) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "AcceptanceGateReview", "SCN", Metadata{Name: r.Metadata.Name})
	if !sha256DigestPattern.MatchString(r.Metadata.ReviewID) {
		items = append(items, diagnostics.Error("YARA-SCN-060", "metadata.reviewId must be a SHA-256 identity.", "metadata.reviewId"))
	}
	if !slices.Contains(RequiredV01AcceptanceGateCriteria, r.Spec.AcceptanceCriterion) {
		items = append(items, diagnostics.Error("YARA-SCN-061", "Acceptance criterion is not a supported v0.1 gate.", "spec.acceptanceCriterion"))
	}
	if strings.TrimSpace(r.Spec.Reviewer.Identity) == "" || strings.TrimSpace(r.Spec.Reviewer.Role) == "" || strings.TrimSpace(r.Spec.Reviewer.Assurance) == "" {
		items = append(items, diagnostics.Error("YARA-SCN-062", "Reviewer identity, role and assurance are required.", "spec.reviewer"))
	}
	if strings.TrimSpace(r.Spec.ReviewedAt) == "" {
		items = append(items, diagnostics.Error("YARA-SCN-062", "Review date is required.", "spec.reviewedAt"))
	}
	if !validReviewVerdict(r.Spec.Verdict) {
		items = append(items, diagnostics.Error("YARA-SCN-063", "Review verdict must be approved, changes-required or abstained.", "spec.verdict"))
	}
	if r.Metadata.ReviewID != "" {
		claimed := r.Metadata.ReviewID
		recomputed, err := r.AssignReviewID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-SCN-500", "Could not recompute review identity."))
		} else if recomputed.Metadata.ReviewID != claimed {
			items = append(items, diagnostics.Error("YARA-SCN-064", "Review contents do not match metadata.reviewId.", "metadata.reviewId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func (r AcceptanceGateReview) Approved() bool {
	return r.Validate().Valid && r.Spec.Verdict == ReviewVerdictApproved
}
