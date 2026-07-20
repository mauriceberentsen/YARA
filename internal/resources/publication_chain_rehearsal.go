package resources

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type PublicationChainRehearsal struct {
	APIVersion string                        `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                        `json:"kind" yaml:"kind"`
	Metadata   PublicationChainRehearsalMeta `json:"metadata" yaml:"metadata"`
	Spec       PublicationChainRehearsalSpec `json:"spec" yaml:"spec"`
}

type PublicationChainRehearsalMeta struct {
	Name        string `json:"name" yaml:"name"`
	RehearsalID string `json:"rehearsalId" yaml:"rehearsalId"`
}

type PublicationChainRehearsalSpec struct {
	RehearsedAt                         string         `json:"rehearsedAt" yaml:"rehearsedAt"`
	CatalogDigest                       string         `json:"catalogDigest" yaml:"catalogDigest"`
	AssertionRef                        string         `json:"assertionRef" yaml:"assertionRef"`
	LifecycleProofApprovalID            string         `json:"lifecycleProofApprovalId" yaml:"lifecycleProofApprovalId"`
	IntegrationPublicationAttestationID string         `json:"integrationPublicationAttestationId" yaml:"integrationPublicationAttestationId"`
	CoverageReportID                    string         `json:"coverageReportId" yaml:"coverageReportId"`
	TrustPolicyID                       string         `json:"trustPolicyId" yaml:"trustPolicyId"`
	BoundaryAuditHead                   string         `json:"boundaryAuditHead" yaml:"boundaryAuditHead"`
	AuthorizationIDs                    []string       `json:"authorizationIds" yaml:"authorizationIds"`
	Reviewer                            ReviewerRecord `json:"reviewer" yaml:"reviewer"`
	Decision                            string         `json:"decision" yaml:"decision"`
	ReasonReference                     string         `json:"reasonReference" yaml:"reasonReference"`
	MaxEvidenceAge                      string         `json:"maxEvidenceAge" yaml:"maxEvidenceAge"`
	Limitations                         []string       `json:"limitations" yaml:"limitations"`
}

func (r PublicationChainRehearsal) AssignRehearsalID() (PublicationChainRehearsal, error) {
	r.Metadata.RehearsalID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return PublicationChainRehearsal{}, fmt.Errorf("digest publication chain rehearsal: %w", err)
	}
	r.Metadata.RehearsalID = digest
	return r, nil
}

func (r PublicationChainRehearsal) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "PublicationChainRehearsal", "PCR", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.rehearsalId":                     r.Metadata.RehearsalID,
		"spec.catalogDigest":                       r.Spec.CatalogDigest,
		"spec.lifecycleProofApprovalId":            r.Spec.LifecycleProofApprovalID,
		"spec.integrationPublicationAttestationId": r.Spec.IntegrationPublicationAttestationID,
		"spec.coverageReportId":                    r.Spec.CoverageReportID,
		"spec.trustPolicyId":                       r.Spec.TrustPolicyID,
		"spec.boundaryAuditHead":                   r.Spec.BoundaryAuditHead,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-PCR-010", "Publication-chain rehearsal bindings must be SHA-256 digests.", path))
		}
	}
	if strings.TrimSpace(r.Spec.AssertionRef) == "" {
		items = append(items, diagnostics.Error("YARA-PCR-011", "Assertion reference is required.", "spec.assertionRef"))
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.RehearsedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-PCR-012", "Publication-chain rehearsal rehearsedAt must be RFC3339.", "spec.rehearsedAt"))
	}
	if len(r.Spec.AuthorizationIDs) == 0 || !slices.IsSorted(r.Spec.AuthorizationIDs) || hasDuplicateStrings(r.Spec.AuthorizationIDs) {
		items = append(items, diagnostics.Error("YARA-PCR-013", "Authorization IDs must be non-empty, unique and sorted.", "spec.authorizationIds"))
	}
	for index, value := range r.Spec.AuthorizationIDs {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-PCR-014", "Authorization IDs must be SHA-256 digests.", fmt.Sprintf("spec.authorizationIds[%d]", index)))
		}
	}
	if strings.TrimSpace(r.Spec.Reviewer.Identity) == "" || strings.TrimSpace(r.Spec.Reviewer.Role) == "" || strings.TrimSpace(r.Spec.Reviewer.Assurance) == "" {
		items = append(items, diagnostics.Error("YARA-PCR-015", "Reviewer identity, role and assurance are required.", "spec.reviewer"))
	}
	if !validPromotionDecision(r.Spec.Decision) {
		items = append(items, diagnostics.Error("YARA-PCR-016", "Decision must be approved, changes-required or abstained.", "spec.decision"))
	}
	if strings.TrimSpace(r.Spec.ReasonReference) == "" {
		items = append(items, diagnostics.Error("YARA-PCR-017", "Reason reference is required.", "spec.reasonReference"))
	}
	maxEvidenceAge, err := time.ParseDuration(strings.TrimSpace(r.Spec.MaxEvidenceAge))
	if err != nil || maxEvidenceAge <= 0 {
		items = append(items, diagnostics.Error("YARA-PCR-018", "Max evidence age must be a positive Go duration.", "spec.maxEvidenceAge"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-PCR-019", "At least one unique sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.RehearsalID != "" {
		claimed := r.Metadata.RehearsalID
		recomputed, err := r.AssignRehearsalID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-PCR-500", "Could not recompute publication-chain rehearsal identity."))
		} else if recomputed.Metadata.RehearsalID != claimed {
			items = append(items, diagnostics.Error("YARA-PCR-020", "Publication-chain rehearsal contents do not match metadata.rehearsalId.", "metadata.rehearsalId"))
		}
	}
	return diagnostics.NewReport(items...)
}
