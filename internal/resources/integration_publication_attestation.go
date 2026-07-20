package resources

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type IntegrationPublicationAttestation struct {
	APIVersion string                                `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                                `json:"kind" yaml:"kind"`
	Metadata   IntegrationPublicationAttestationMeta `json:"metadata" yaml:"metadata"`
	Spec       IntegrationPublicationAttestationSpec `json:"spec" yaml:"spec"`
}

type IntegrationPublicationAttestationMeta struct {
	Name          string `json:"name" yaml:"name"`
	AttestationID string `json:"attestationId" yaml:"attestationId"`
}

type IntegrationPublicationAttestationSpec struct {
	ReviewedAt       string         `json:"reviewedAt" yaml:"reviewedAt"`
	ExpiresAt        string         `json:"expiresAt" yaml:"expiresAt"`
	CatalogDigest    string         `json:"catalogDigest" yaml:"catalogDigest"`
	AssertionRef     string         `json:"assertionRef" yaml:"assertionRef"`
	SelectedEvidence []string       `json:"selectedEvidence" yaml:"selectedEvidence"`
	Reviewer         ReviewerRecord `json:"reviewer" yaml:"reviewer"`
	Decision         string         `json:"decision" yaml:"decision"`
	ReasonReference  string         `json:"reasonReference" yaml:"reasonReference"`
	MaxEvidenceAge   string         `json:"maxEvidenceAge" yaml:"maxEvidenceAge"`
	Limitations      []string       `json:"limitations" yaml:"limitations"`
}

func (r IntegrationPublicationAttestation) AssignAttestationID() (IntegrationPublicationAttestation, error) {
	r.Metadata.AttestationID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return IntegrationPublicationAttestation{}, fmt.Errorf("digest integration publication attestation: %w", err)
	}
	r.Metadata.AttestationID = digest
	return r, nil
}

func (r IntegrationPublicationAttestation) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "IntegrationPublicationAttestation", "IPA", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.attestationId": r.Metadata.AttestationID,
		"spec.catalogDigest":     r.Spec.CatalogDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-IPA-010", "Integration publication attestation identities must be SHA-256 digests.", path))
		}
	}
	if strings.TrimSpace(r.Spec.AssertionRef) == "" {
		items = append(items, diagnostics.Error("YARA-IPA-011", "Assertion reference is required.", "spec.assertionRef"))
	}
	reviewedAt, reviewedErr := time.Parse(time.RFC3339Nano, r.Spec.ReviewedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, r.Spec.ExpiresAt)
	if reviewedErr != nil || expiresErr != nil || !expiresAt.After(reviewedAt) {
		items = append(items, diagnostics.Error("YARA-IPA-012", "Integration publication reviewed/expires window must be a valid RFC3339 interval.", "spec.expiresAt"))
	}
	if len(r.Spec.SelectedEvidence) == 0 || !slices.IsSorted(r.Spec.SelectedEvidence) || hasDuplicateStrings(r.Spec.SelectedEvidence) {
		items = append(items, diagnostics.Error("YARA-IPA-013", "Selected evidence IDs must be unique and sorted.", "spec.selectedEvidence"))
	}
	for index, value := range r.Spec.SelectedEvidence {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-IPA-014", "Selected evidence IDs must be SHA-256 digests.", fmt.Sprintf("spec.selectedEvidence[%d]", index)))
		}
	}
	if strings.TrimSpace(r.Spec.Reviewer.Identity) == "" || strings.TrimSpace(r.Spec.Reviewer.Role) == "" || strings.TrimSpace(r.Spec.Reviewer.Assurance) == "" {
		items = append(items, diagnostics.Error("YARA-IPA-015", "Reviewer identity, role and assurance are required.", "spec.reviewer"))
	}
	if !validPromotionDecision(r.Spec.Decision) {
		items = append(items, diagnostics.Error("YARA-IPA-016", "Decision must be approved, changes-required or abstained.", "spec.decision"))
	}
	if strings.TrimSpace(r.Spec.ReasonReference) == "" {
		items = append(items, diagnostics.Error("YARA-IPA-017", "Reason reference is required.", "spec.reasonReference"))
	}
	maxEvidenceAge, err := time.ParseDuration(strings.TrimSpace(r.Spec.MaxEvidenceAge))
	if err != nil || maxEvidenceAge <= 0 {
		items = append(items, diagnostics.Error("YARA-IPA-018", "Max evidence age must be a positive Go duration.", "spec.maxEvidenceAge"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-IPA-019", "At least one unique sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.AttestationID != "" {
		claimed := r.Metadata.AttestationID
		recomputed, err := r.AssignAttestationID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-IPA-500", "Could not recompute integration publication attestation identity."))
		} else if recomputed.Metadata.AttestationID != claimed {
			items = append(items, diagnostics.Error("YARA-IPA-020", "Integration publication attestation contents do not match metadata.attestationId.", "metadata.attestationId"))
		}
	}
	return diagnostics.NewReport(items...)
}
