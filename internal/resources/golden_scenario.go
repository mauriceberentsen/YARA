package resources

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

const (
	ScenarioOutcomePlanned    = "planned"
	ScenarioOutcomeInfeasible = "infeasible"
)

type GoldenScenario struct {
	APIVersion string                 `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                 `json:"kind" yaml:"kind"`
	Metadata   GoldenScenarioMetadata `json:"metadata" yaml:"metadata"`
	Spec       GoldenScenarioSpec     `json:"spec" yaml:"spec"`
}

type GoldenScenarioMetadata struct {
	Name       string `json:"name" yaml:"name"`
	ScenarioID string `json:"scenarioId" yaml:"scenarioId"`
}

type GoldenScenarioSpec struct {
	Inputs             GoldenScenarioInputs             `json:"inputs" yaml:"inputs"`
	Expected           GoldenScenarioExpected           `json:"expected" yaml:"expected"`
	ReviewRequirements GoldenScenarioReviewRequirements `json:"reviewRequirements" yaml:"reviewRequirements"`
}

type GoldenScenarioInputs struct {
	Request   GoldenScenarioInput `json:"request" yaml:"request"`
	Inventory GoldenScenarioInput `json:"inventory" yaml:"inventory"`
	Catalog   GoldenScenarioInput `json:"catalog" yaml:"catalog"`
}

type GoldenScenarioInput struct {
	Path   string `json:"path" yaml:"path"`
	Digest string `json:"digest" yaml:"digest"`
}

type GoldenScenarioExpected struct {
	Outcome                 string                    `json:"outcome" yaml:"outcome"`
	PlanID                  string                    `json:"planId,omitempty" yaml:"planId,omitempty"`
	RequiredDecisionIDs     []string                  `json:"requiredDecisionIds" yaml:"requiredDecisionIds"`
	RequiredSelections      []GoldenScenarioSelection `json:"requiredSelections" yaml:"requiredSelections"`
	ForbiddenSelections     []string                  `json:"forbiddenSelections" yaml:"forbiddenSelections"`
	RequiredDiagnosticCodes []string                  `json:"requiredDiagnosticCodes" yaml:"requiredDiagnosticCodes"`
}

type GoldenScenarioSelection struct {
	DecisionID string `json:"decisionId" yaml:"decisionId"`
	Selected   string `json:"selected" yaml:"selected"`
}

type GoldenScenarioReviewRequirements struct {
	MinimumIndependentReviewers int      `json:"minimumIndependentReviewers" yaml:"minimumIndependentReviewers"`
	RequiredRoles               []string `json:"requiredRoles" yaml:"requiredRoles"`
}

func (s GoldenScenario) AssignScenarioID() (GoldenScenario, error) {
	s.Metadata.ScenarioID = ""
	digest, err := canonical.Digest(s)
	if err != nil {
		return GoldenScenario{}, fmt.Errorf("digest golden scenario: %w", err)
	}
	s.Metadata.ScenarioID = digest
	return s, nil
}

func (s GoldenScenario) Validate() diagnostics.Report {
	items := validateEnvelope(s.APIVersion, s.Kind, "GoldenScenario", "SCN", Metadata{Name: s.Metadata.Name})
	if !sha256DigestPattern.MatchString(s.Metadata.ScenarioID) {
		items = append(items, diagnostics.Error("YARA-SCN-010", "metadata.scenarioId must be a SHA-256 identity.", "metadata.scenarioId"))
	}
	for _, input := range []struct {
		path  string
		value GoldenScenarioInput
	}{
		{"spec.inputs.request", s.Spec.Inputs.Request},
		{"spec.inputs.inventory", s.Spec.Inputs.Inventory},
		{"spec.inputs.catalog", s.Spec.Inputs.Catalog},
	} {
		if strings.TrimSpace(input.value.Path) == "" || filepath.IsAbs(input.value.Path) || !sha256DigestPattern.MatchString(input.value.Digest) {
			items = append(items, diagnostics.Error("YARA-SCN-011", "Scenario inputs require a relative path and SHA-256 digest.", input.path))
		}
	}
	expected := s.Spec.Expected
	if expected.Outcome != ScenarioOutcomePlanned && expected.Outcome != ScenarioOutcomeInfeasible {
		items = append(items, diagnostics.Error("YARA-SCN-012", "Expected outcome must be planned or infeasible.", "spec.expected.outcome"))
	}
	if expected.Outcome == ScenarioOutcomePlanned {
		if !sha256DigestPattern.MatchString(expected.PlanID) || len(expected.RequiredDecisionIDs) == 0 || len(expected.RequiredSelections) == 0 {
			items = append(items, diagnostics.Error("YARA-SCN-013", "A planned scenario requires the exact plan ID, decisions and selections.", "spec.expected"))
		}
	} else if expected.PlanID != "" || len(expected.RequiredDecisionIDs) != 0 || len(expected.RequiredSelections) != 0 || len(expected.RequiredDiagnosticCodes) == 0 {
		items = append(items, diagnostics.Error("YARA-SCN-013", "An infeasible scenario cannot claim a plan or selections and must require an infeasibility diagnostic.", "spec.expected"))
	}
	for _, field := range []struct {
		path   string
		values []string
	}{
		{"spec.expected.requiredDecisionIds", expected.RequiredDecisionIDs},
		{"spec.expected.forbiddenSelections", expected.ForbiddenSelections},
		{"spec.expected.requiredDiagnosticCodes", expected.RequiredDiagnosticCodes},
		{"spec.reviewRequirements.requiredRoles", s.Spec.ReviewRequirements.RequiredRoles},
	} {
		if !sortedUniqueNonEmpty(field.values) {
			items = append(items, diagnostics.Error("YARA-SCN-014", "Scenario lists must be non-empty where required, unique and sorted.", field.path))
		}
	}
	selectionIDs := make(map[string]struct{}, len(expected.RequiredSelections))
	previousDecisionID := ""
	for index, selection := range expected.RequiredSelections {
		path := fmt.Sprintf("spec.expected.requiredSelections[%d]", index)
		if strings.TrimSpace(selection.DecisionID) == "" || strings.TrimSpace(selection.Selected) == "" || previousDecisionID > selection.DecisionID {
			items = append(items, diagnostics.Error("YARA-SCN-015", "Required selections must be complete and ordered by decision ID.", path))
		}
		if _, exists := selectionIDs[selection.DecisionID]; exists {
			items = append(items, diagnostics.Error("YARA-SCN-015", "Required selection decision IDs must be unique.", path+".decisionId"))
		}
		selectionIDs[selection.DecisionID] = struct{}{}
		previousDecisionID = selection.DecisionID
		if !slices.Contains(expected.RequiredDecisionIDs, selection.DecisionID) {
			items = append(items, diagnostics.Error("YARA-SCN-016", "Every required selection must reference a required decision.", path+".decisionId"))
		}
		if slices.Contains(expected.ForbiddenSelections, selection.Selected) {
			items = append(items, diagnostics.Error("YARA-SCN-016", "A selection cannot be both required and forbidden.", path+".selected"))
		}
	}
	for _, code := range expected.RequiredDiagnosticCodes {
		if !diagnosticCodePattern.MatchString(code) {
			items = append(items, diagnostics.Error("YARA-SCN-017", "Required diagnostic codes must use the YARA code format.", "spec.expected.requiredDiagnosticCodes"))
		}
	}
	if s.Spec.ReviewRequirements.MinimumIndependentReviewers < 1 || len(s.Spec.ReviewRequirements.RequiredRoles) == 0 {
		items = append(items, diagnostics.Error("YARA-SCN-018", "At least one independent reviewer and reviewer role are required.", "spec.reviewRequirements"))
	}
	if s.Metadata.ScenarioID != "" {
		claimed := s.Metadata.ScenarioID
		recomputed, err := s.AssignScenarioID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-SCN-500", "Could not recompute scenario identity."))
		} else if recomputed.Metadata.ScenarioID != claimed {
			items = append(items, diagnostics.Error("YARA-SCN-019", "Scenario contents do not match metadata.scenarioId.", "metadata.scenarioId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func sortedUniqueNonEmpty(values []string) bool {
	if !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if strings.TrimSpace(value) == "" || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}
