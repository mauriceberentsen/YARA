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
	} `json:"independentReview"`
	ReleaseEligible bool `json:"releaseEligible"`
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
		ReleaseEligible:         false,
	}
	if result.Outcome == resources.ScenarioOutcomePlanned {
		response.PlanID = result.Plan.Metadata.PlanID
	}
	response.IndependentReview.Status = "required"
	response.IndependentReview.MinimumRequired = golden.Spec.ReviewRequirements.MinimumIndependentReviewers
	response.IndependentReview.RequiredRoles = golden.Spec.ReviewRequirements.RequiredRoles
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
