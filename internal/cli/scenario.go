package cli

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/scenario"
)

type scenarioValidationResult struct {
	Valid                   bool     `json:"valid"`
	ScenarioID              string   `json:"scenarioId"`
	Outcome                 string   `json:"outcome"`
	PlanID                  string   `json:"planId,omitempty"`
	ObservedDiagnosticCodes []string `json:"observedDiagnosticCodes"`
	IndependentReview       struct {
		Status          string   `json:"status"`
		MinimumRequired int      `json:"minimumRequired"`
		RequiredRoles   []string `json:"requiredRoles"`
		ReviewID        string   `json:"reviewId,omitempty"`
	} `json:"independentReview"`
	ReleaseEligible bool `json:"releaseEligible"`
}

type scenarioSuiteValidationResult struct {
	Valid                         bool                  `json:"valid"`
	RequiredScenarioCount         int                   `json:"requiredScenarioCount"`
	ScenarioCount                 int                   `json:"scenarioCount"`
	TechnicallyConformant         int                   `json:"technicallyConformant"`
	Planned                       int                   `json:"planned"`
	Infeasible                    int                   `json:"infeasible"`
	TechnicalCoverageComplete     bool                  `json:"technicalCoverageComplete"`
	IndependentReviewsComplete    int                   `json:"independentReviewsComplete"`
	IndependentReviewStatus       string                `json:"independentReviewStatus"`
	AcceptanceGateReviewsComplete int                   `json:"acceptanceGateReviewsComplete"`
	AcceptanceGateReviewStatus    string                `json:"acceptanceGateReviewStatus"`
	ReleaseEligible               bool                  `json:"releaseEligible"`
	Scenarios                     []scenario.SuiteEntry `json:"scenarios"`
}

func validateScenario(args []string, stdout, stderr io.Writer) int {
	options, ok := parseValidationOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	golden, err := resources.LoadGoldenScenario(options.inputPath)
	if err != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "scenario.validate", "GoldenScenario", options.inputPath, "YARA-SCN-004", err, nil)
	}
	inputSubject, err := canonicalSubject("GoldenScenario", golden)
	if err != nil {
		return writeLoadError(stdout, "YARA-AUD-500", err)
	}
	scenarioSubject := inputSubject
	if report := golden.Validate(); report.Valid {
		scenarioSubject = audit.Subject{Kind: "GoldenScenario", Digest: golden.Metadata.ScenarioID}
	}
	result := scenario.Evaluate(options.inputPath, golden)
	if !result.Report.Valid {
		if auditErr := persistOperationAudit(options.auditPath, "scenario.validate", "failed", "failed", []audit.Subject{scenarioSubject}, scenarioDiagnosticCodes(result)); auditErr != nil {
			return writeLoadError(stdout, "YARA-AUD-005", auditErr)
		}
		return writeReport(stdout, result.Report, ExitInvalidInput)
	}
	subjects := []audit.Subject{scenarioSubject}
	if result.Outcome == resources.ScenarioOutcomePlanned {
		subjects = append(subjects, audit.Subject{Kind: "PlatformPlan", Digest: result.Plan.Metadata.PlanID})
	}
	if err := persistOperationAudit(options.auditPath, "scenario.validate", "completed", "success", subjects, scenarioDiagnosticCodes(result)); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	response := scenarioValidationResult{
		Valid: true, ScenarioID: golden.Metadata.ScenarioID, Outcome: result.Outcome,
		ObservedDiagnosticCodes: result.ObservedDiagnosticCodes,
	}
	if result.Outcome == resources.ScenarioOutcomePlanned {
		response.PlanID = result.Plan.Metadata.PlanID
	}
	response.IndependentReview.MinimumRequired = golden.Spec.ReviewRequirements.MinimumIndependentReviewers
	response.IndependentReview.RequiredRoles = golden.Spec.ReviewRequirements.RequiredRoles
	response.IndependentReview.Status = "required"
	if review, reviewReport := scenario.EvaluateScenarioReview(options.inputPath, golden); reviewReport.Valid {
		response.IndependentReview.Status = "complete"
		response.IndependentReview.ReviewID = review.Metadata.ReviewID
		response.ReleaseEligible = true
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func validateScenarioSuite(args []string, stdout, stderr io.Writer) int {
	options, ok := parseValidationOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	result := scenario.EvaluateAll(options.inputPath)
	if !result.Report.Valid {
		subject := attemptedInputSubject("GoldenScenarioSuite", options.inputPath)
		if auditErr := persistOperationAudit(options.auditPath, "scenario.validate-all", "failed", "failed", []audit.Subject{subject}, diagnosticCodes(result.Report.Diagnostics)); auditErr != nil {
			return writeLoadError(stdout, "YARA-AUD-005", auditErr)
		}
		return writeReport(stdout, result.Report, ExitInvalidInput)
	}
	subjects := make([]audit.Subject, 0, len(result.Entries)*2)
	codes := make([]string, 0)
	for _, entry := range result.Entries {
		subjects = append(subjects, audit.Subject{Kind: "GoldenScenario", Digest: entry.ScenarioID})
		if entry.PlanID != "" {
			subjects = append(subjects, audit.Subject{Kind: "PlatformPlan", Digest: entry.PlanID})
		}
		codes = append(codes, entry.ObservedDiagnosticCodes...)
	}
	if err := persistOperationAudit(options.auditPath, "scenario.validate-all", "completed", "success", subjects, uniqueSortedStrings(codes)); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	response := scenarioSuiteValidationResult{
		Valid: true, RequiredScenarioCount: scenario.RequiredV01ScenarioCount,
		ScenarioCount: len(result.Entries), TechnicallyConformant: result.TechnicallyConformant,
		Planned: result.Planned, Infeasible: result.Infeasible,
		TechnicalCoverageComplete:     len(result.Entries) >= scenario.RequiredV01ScenarioCount && result.TechnicallyConformant == len(result.Entries),
		IndependentReviewsComplete:    result.Review.IndependentReviewsComplete,
		IndependentReviewStatus:       result.Review.IndependentReviewStatus,
		AcceptanceGateReviewsComplete: result.Review.AcceptanceGateReviewsComplete,
		AcceptanceGateReviewStatus:    result.Review.AcceptanceGateReviewStatus,
		ReleaseEligible:               result.Review.ReleaseEligible,
		Scenarios:                     result.Entries,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func scenarioDiagnosticCodes(result scenario.Result) []string {
	set := make(map[string]struct{}, len(result.ObservedDiagnosticCodes)+len(result.Report.Diagnostics))
	for _, code := range result.ObservedDiagnosticCodes {
		set[code] = struct{}{}
	}
	for _, item := range result.Report.Diagnostics {
		set[item.Code] = struct{}{}
	}
	codes := make([]string, 0, len(set))
	for code := range set {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes
}

func uniqueSortedStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
