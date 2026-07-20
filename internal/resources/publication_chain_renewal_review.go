package resources

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type PublicationChainRenewalReview struct {
	APIVersion string                            `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                            `json:"kind" yaml:"kind"`
	Metadata   PublicationChainRenewalReviewMeta `json:"metadata" yaml:"metadata"`
	Spec       PublicationChainRenewalReviewSpec `json:"spec" yaml:"spec"`
}

type PublicationChainRenewalReviewMeta struct {
	Name     string `json:"name" yaml:"name"`
	ReviewID string `json:"reviewId" yaml:"reviewId"`
}

type PublicationChainRenewalReviewSpec struct {
	ReviewedAt                          string         `json:"reviewedAt" yaml:"reviewedAt"`
	ExpiresAt                           string         `json:"expiresAt" yaml:"expiresAt"`
	CatalogDigest                       string         `json:"catalogDigest" yaml:"catalogDigest"`
	AssertionRef                        string         `json:"assertionRef" yaml:"assertionRef"`
	PublicationChainRehearsalID         string         `json:"publicationChainRehearsalId" yaml:"publicationChainRehearsalId"`
	PublicationChainRetentionAuditHead  string         `json:"publicationChainRetentionAuditHead" yaml:"publicationChainRetentionAuditHead"`
	PromotionReviewID                   string         `json:"promotionReviewId" yaml:"promotionReviewId"`
	LifecycleProofApprovalID            string         `json:"lifecycleProofApprovalId" yaml:"lifecycleProofApprovalId"`
	IntegrationPublicationAttestationID string         `json:"integrationPublicationAttestationId" yaml:"integrationPublicationAttestationId"`
	SelectedEvidence                    []string       `json:"selectedEvidence" yaml:"selectedEvidence"`
	Reviewer                            ReviewerRecord `json:"reviewer" yaml:"reviewer"`
	Decision                            string         `json:"decision" yaml:"decision"`
	ReasonReference                     string         `json:"reasonReference" yaml:"reasonReference"`
	MaxEvidenceAge                      string         `json:"maxEvidenceAge" yaml:"maxEvidenceAge"`
	Limitations                         []string       `json:"limitations" yaml:"limitations"`
}

func (r PublicationChainRenewalReview) AssignReviewID() (PublicationChainRenewalReview, error) {
	r.Metadata.ReviewID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return PublicationChainRenewalReview{}, fmt.Errorf("digest publication-chain renewal review: %w", err)
	}
	r.Metadata.ReviewID = digest
	return r, nil
}

func (r PublicationChainRenewalReview) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "PublicationChainRenewalReview", "PCRR", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.reviewId":                        r.Metadata.ReviewID,
		"spec.catalogDigest":                       r.Spec.CatalogDigest,
		"spec.publicationChainRehearsalId":         r.Spec.PublicationChainRehearsalID,
		"spec.publicationChainRetentionAuditHead":  r.Spec.PublicationChainRetentionAuditHead,
		"spec.promotionReviewId":                   r.Spec.PromotionReviewID,
		"spec.lifecycleProofApprovalId":            r.Spec.LifecycleProofApprovalID,
		"spec.integrationPublicationAttestationId": r.Spec.IntegrationPublicationAttestationID,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-PCRR-010", "Publication-chain renewal review identities must be SHA-256 digests.", path))
		}
	}
	if strings.TrimSpace(r.Spec.AssertionRef) == "" {
		items = append(items, diagnostics.Error("YARA-PCRR-011", "Assertion reference is required.", "spec.assertionRef"))
	}
	reviewedAt, reviewedErr := time.Parse(time.RFC3339Nano, r.Spec.ReviewedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, r.Spec.ExpiresAt)
	if reviewedErr != nil || expiresErr != nil || !expiresAt.After(reviewedAt) {
		items = append(items, diagnostics.Error("YARA-PCRR-012", "Publication-chain renewal review window must be a valid RFC3339 interval.", "spec.expiresAt"))
	}
	if len(r.Spec.SelectedEvidence) == 0 || !slices.IsSorted(r.Spec.SelectedEvidence) || hasDuplicateStrings(r.Spec.SelectedEvidence) {
		items = append(items, diagnostics.Error("YARA-PCRR-013", "Selected evidence IDs must be unique and sorted.", "spec.selectedEvidence"))
	}
	for index, value := range r.Spec.SelectedEvidence {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-PCRR-014", "Selected evidence IDs must be SHA-256 digests.", fmt.Sprintf("spec.selectedEvidence[%d]", index)))
		}
	}
	if strings.TrimSpace(r.Spec.Reviewer.Identity) == "" || strings.TrimSpace(r.Spec.Reviewer.Role) == "" || strings.TrimSpace(r.Spec.Reviewer.Assurance) == "" {
		items = append(items, diagnostics.Error("YARA-PCRR-015", "Reviewer identity, role and assurance are required.", "spec.reviewer"))
	}
	if !validPromotionDecision(r.Spec.Decision) {
		items = append(items, diagnostics.Error("YARA-PCRR-016", "Decision must be approved, changes-required or abstained.", "spec.decision"))
	}
	if strings.TrimSpace(r.Spec.ReasonReference) == "" {
		items = append(items, diagnostics.Error("YARA-PCRR-017", "Reason reference is required.", "spec.reasonReference"))
	}
	maxEvidenceAge, err := time.ParseDuration(strings.TrimSpace(r.Spec.MaxEvidenceAge))
	if err != nil || maxEvidenceAge <= 0 {
		items = append(items, diagnostics.Error("YARA-PCRR-018", "Max evidence age must be a positive Go duration.", "spec.maxEvidenceAge"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-PCRR-019", "At least one unique sorted limitation is required.", "spec.limitations"))
	}
	if required := []string{
		r.Spec.PublicationChainRehearsalID,
		r.Spec.PublicationChainRetentionAuditHead,
		r.Spec.PromotionReviewID,
		r.Spec.LifecycleProofApprovalID,
		r.Spec.IntegrationPublicationAttestationID,
	}; !allContained(r.Spec.SelectedEvidence, required) {
		items = append(items, diagnostics.Error("YARA-PCRR-020", "Selected evidence must include all bound publication-chain renewal identity inputs.", "spec.selectedEvidence"))
	}
	if r.Metadata.ReviewID != "" {
		claimed := r.Metadata.ReviewID
		recomputed, err := r.AssignReviewID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-PCRR-500", "Could not recompute publication-chain renewal review identity."))
		} else if recomputed.Metadata.ReviewID != claimed {
			items = append(items, diagnostics.Error("YARA-PCRR-021", "Publication-chain renewal review contents do not match metadata.reviewId.", "metadata.reviewId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func allContained(selected []string, required []string) bool {
	seen := map[string]struct{}{}
	for _, item := range selected {
		seen[item] = struct{}{}
	}
	for _, item := range required {
		if _, ok := seen[item]; !ok {
			return false
		}
	}
	return true
}
