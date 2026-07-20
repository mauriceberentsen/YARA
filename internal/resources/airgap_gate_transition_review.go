package resources

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type AirgapGateTransitionReview struct {
	APIVersion string                             `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                             `json:"kind" yaml:"kind"`
	Metadata   AirgapGateTransitionReviewMetadata `json:"metadata" yaml:"metadata"`
	Spec       AirgapGateTransitionReviewSpec     `json:"spec" yaml:"spec"`
}

type AirgapGateTransitionReviewMetadata struct {
	Name     string `json:"name" yaml:"name"`
	ReviewID string `json:"reviewId" yaml:"reviewId"`
}

type AirgapGateTransitionReviewSpec struct {
	RecordedAt            string         `json:"recordedAt" yaml:"recordedAt"`
	PolicyDiffID          string         `json:"policyDiffId" yaml:"policyDiffId"`
	FromPolicyID          string         `json:"fromPolicyId" yaml:"fromPolicyId"`
	ToPolicyID            string         `json:"toPolicyId" yaml:"toPolicyId"`
	TargetReferenceDigest string         `json:"targetReferenceDigest" yaml:"targetReferenceDigest"`
	Reviewer              ReviewerRecord `json:"reviewer" yaml:"reviewer"`
	Decision              string         `json:"decision" yaml:"decision"`
	ReasonReference       string         `json:"reasonReference" yaml:"reasonReference"`
	Limitations           []string       `json:"limitations" yaml:"limitations"`
}

func (r AirgapGateTransitionReview) AssignReviewID() (AirgapGateTransitionReview, error) {
	r.Metadata.ReviewID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return AirgapGateTransitionReview{}, fmt.Errorf("digest airgap gate transition review: %w", err)
	}
	r.Metadata.ReviewID = digest
	return r, nil
}

func (r AirgapGateTransitionReview) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "AirgapGateTransitionReview", "AGR", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.reviewId":          r.Metadata.ReviewID,
		"spec.policyDiffId":          r.Spec.PolicyDiffID,
		"spec.fromPolicyId":          r.Spec.FromPolicyID,
		"spec.toPolicyId":            r.Spec.ToPolicyID,
		"spec.targetReferenceDigest": r.Spec.TargetReferenceDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-AGR-010", "Transition-review identities must be SHA-256 digests.", path))
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-AGR-011", "Transition review recordedAt must be RFC3339.", "spec.recordedAt"))
	}
	if strings.TrimSpace(r.Spec.Reviewer.Identity) == "" || strings.TrimSpace(r.Spec.Reviewer.Role) == "" || strings.TrimSpace(r.Spec.Reviewer.Assurance) == "" {
		items = append(items, diagnostics.Error("YARA-AGR-012", "Reviewer identity, role and assurance are required.", "spec.reviewer"))
	}
	if !slices.Contains([]string{PromotionDecisionApproved, PromotionDecisionChangesRequired, PromotionDecisionAbstained}, r.Spec.Decision) {
		items = append(items, diagnostics.Error("YARA-AGR-013", "Decision must be approved, changes-required or abstained.", "spec.decision"))
	}
	if strings.TrimSpace(r.Spec.ReasonReference) == "" {
		items = append(items, diagnostics.Error("YARA-AGR-014", "A non-secret reason reference is required.", "spec.reasonReference"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-AGR-015", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ReviewID != "" {
		claimed := r.Metadata.ReviewID
		recomputed, err := r.AssignReviewID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-AGR-500", "Could not recompute transition review identity."))
		} else if recomputed.Metadata.ReviewID != claimed {
			items = append(items, diagnostics.Error("YARA-AGR-016", "Transition review contents do not match metadata.reviewId.", "metadata.reviewId"))
		}
	}
	return diagnostics.NewReport(items...)
}
