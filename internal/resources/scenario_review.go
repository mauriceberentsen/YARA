package resources

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

const (
	ReviewVerdictApproved        = "approved"
	ReviewVerdictChangesRequired = "changes-required"
	ReviewVerdictAbstained       = "abstained"
)

type ScenarioReview struct {
	APIVersion string                 `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                 `json:"kind" yaml:"kind"`
	Metadata   ScenarioReviewMetadata `json:"metadata" yaml:"metadata"`
	Spec       ScenarioReviewSpec     `json:"spec" yaml:"spec"`
}

type ScenarioReviewMetadata struct {
	Name     string `json:"name" yaml:"name"`
	ReviewID string `json:"reviewId" yaml:"reviewId"`
}

type ScenarioReviewSpec struct {
	Subject    ScenarioReviewSubject `json:"subject" yaml:"subject"`
	Reviewer   ReviewerRecord        `json:"reviewer" yaml:"reviewer"`
	ReviewedAt string                `json:"reviewedAt" yaml:"reviewedAt"`
	Verdict    string                `json:"verdict" yaml:"verdict"`
}

type ScenarioReviewSubject struct {
	ScenarioID string `json:"scenarioId" yaml:"scenarioId"`
	PlanID     string `json:"planId,omitempty" yaml:"planId,omitempty"`
}

type ReviewerRecord struct {
	Identity  string `json:"identity" yaml:"identity"`
	Role      string `json:"role" yaml:"role"`
	Assurance string `json:"assurance" yaml:"assurance"`
}

func (r ScenarioReview) AssignReviewID() (ScenarioReview, error) {
	r.Metadata.ReviewID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return ScenarioReview{}, fmt.Errorf("digest scenario review: %w", err)
	}
	r.Metadata.ReviewID = digest
	return r, nil
}

func (r ScenarioReview) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "ScenarioReview", "SCN", Metadata{Name: r.Metadata.Name})
	if !sha256DigestPattern.MatchString(r.Metadata.ReviewID) {
		items = append(items, diagnostics.Error("YARA-SCN-050", "metadata.reviewId must be a SHA-256 identity.", "metadata.reviewId"))
	}
	if !sha256DigestPattern.MatchString(r.Spec.Subject.ScenarioID) {
		items = append(items, diagnostics.Error("YARA-SCN-051", "Review subject requires a SHA-256 scenario identity.", "spec.subject.scenarioId"))
	}
	if r.Spec.Subject.PlanID != "" && !sha256DigestPattern.MatchString(r.Spec.Subject.PlanID) {
		items = append(items, diagnostics.Error("YARA-SCN-051", "Reviewed plan identity must be a SHA-256 digest when present.", "spec.subject.planId"))
	}
	if strings.TrimSpace(r.Spec.Reviewer.Identity) == "" || strings.TrimSpace(r.Spec.Reviewer.Role) == "" || strings.TrimSpace(r.Spec.Reviewer.Assurance) == "" {
		items = append(items, diagnostics.Error("YARA-SCN-052", "Reviewer identity, role and assurance are required.", "spec.reviewer"))
	}
	if strings.TrimSpace(r.Spec.ReviewedAt) == "" {
		items = append(items, diagnostics.Error("YARA-SCN-052", "Review date is required.", "spec.reviewedAt"))
	}
	if !validReviewVerdict(r.Spec.Verdict) {
		items = append(items, diagnostics.Error("YARA-SCN-053", "Review verdict must be approved, changes-required or abstained.", "spec.verdict"))
	}
	if r.Metadata.ReviewID != "" {
		claimed := r.Metadata.ReviewID
		recomputed, err := r.AssignReviewID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-SCN-500", "Could not recompute review identity."))
		} else if recomputed.Metadata.ReviewID != claimed {
			items = append(items, diagnostics.Error("YARA-SCN-054", "Review contents do not match metadata.reviewId.", "metadata.reviewId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func (r ScenarioReview) ConformsTo(golden GoldenScenario) diagnostics.Report {
	if report := r.Validate(); !report.Valid {
		return report
	}
	var items []diagnostics.Diagnostic
	if r.Spec.Subject.ScenarioID != golden.Metadata.ScenarioID {
		items = append(items, diagnostics.Error("YARA-SCN-055", "Review subject scenario identity does not match the golden scenario.", "spec.subject.scenarioId"))
	}
	if golden.Spec.Expected.Outcome == ScenarioOutcomePlanned {
		if r.Spec.Subject.PlanID != golden.Spec.Expected.PlanID {
			items = append(items, diagnostics.Error("YARA-SCN-056", "Review subject plan identity does not match the golden scenario.", "spec.subject.planId"))
		}
	} else if r.Spec.Subject.PlanID != "" {
		items = append(items, diagnostics.Error("YARA-SCN-056", "An infeasible scenario review must not claim a plan identity.", "spec.subject.planId"))
	}
	if !slices.Contains(golden.Spec.ReviewRequirements.RequiredRoles, r.Spec.Reviewer.Role) {
		items = append(items, diagnostics.Error("YARA-SCN-057", "Reviewer role is not declared by the golden scenario.", "spec.reviewer.role"))
	}
	if r.Spec.Verdict != ReviewVerdictApproved {
		items = append(items, diagnostics.Error("YARA-SCN-058", "Review verdict is not approved.", "spec.verdict"))
	}
	return diagnostics.NewReport(items...)
}

func validReviewVerdict(verdict string) bool {
	return verdict == ReviewVerdictApproved || verdict == ReviewVerdictChangesRequired || verdict == ReviewVerdictAbstained
}
