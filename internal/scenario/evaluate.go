// Package scenario evaluates golden planner scenarios without network access or target mutation.
package scenario

import (
	"path/filepath"
	"slices"
	"sort"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/planner"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type Result struct {
	Scenario                resources.GoldenScenario
	Outcome                 string
	Plan                    resources.PlatformPlan
	ObservedDiagnosticCodes []string
	Report                  diagnostics.Report
}

func Evaluate(manifestPath string, golden resources.GoldenScenario) Result {
	if report := golden.Validate(); !report.Valid {
		return Result{Scenario: golden, Report: report}
	}
	base := filepath.Dir(manifestPath)
	request, err := resources.LoadPlatformRequest(filepath.Join(base, golden.Spec.Inputs.Request.Path))
	if err != nil {
		return inputFailure(golden, "spec.inputs.request.path")
	}
	if report := request.Validate(); !report.Valid {
		return invalidInputFailure(golden, "spec.inputs.request", report)
	}
	inventory, err := resources.LoadInventory(filepath.Join(base, golden.Spec.Inputs.Inventory.Path))
	if err != nil {
		return inputFailure(golden, "spec.inputs.inventory.path")
	}
	if report := inventory.Validate(); !report.Valid {
		return invalidInputFailure(golden, "spec.inputs.inventory", report)
	}
	snapshot, err := catalog.Load(filepath.Join(base, golden.Spec.Inputs.Catalog.Path))
	if err != nil {
		return inputFailure(golden, "spec.inputs.catalog.path")
	}
	requestDigest, err := canonical.Digest(request)
	if err != nil {
		return internalFailure(golden)
	}
	inventoryDigest, err := canonical.Digest(inventory)
	if err != nil {
		return internalFailure(golden)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return internalFailure(golden)
	}
	var conformance []diagnostics.Diagnostic
	for _, identity := range []struct{ path, actual, expected string }{
		{"spec.inputs.request.digest", requestDigest, golden.Spec.Inputs.Request.Digest},
		{"spec.inputs.inventory.digest", inventoryDigest, golden.Spec.Inputs.Inventory.Digest},
		{"spec.inputs.catalog.digest", catalogDigest, golden.Spec.Inputs.Catalog.Digest},
	} {
		if identity.actual != identity.expected {
			conformance = append(conformance, diagnostics.Error("YARA-SCN-030", "Referenced input does not match its pinned digest.", identity.path))
		}
	}
	if len(conformance) > 0 {
		return Result{Scenario: golden, Report: diagnostics.NewReport(conformance...)}
	}

	planning := planner.Create(request, inventory, snapshot)
	observed := observedDiagnosticCodes(planning)
	if golden.Spec.Expected.Outcome == resources.ScenarioOutcomeInfeasible {
		if planning.Report.Valid {
			conformance = append(conformance, diagnostics.Error("YARA-SCN-037", "Scenario expected infeasibility but the planner produced a plan.", "spec.expected.outcome"))
		}
	} else if !planning.Report.Valid {
		conformance = append(conformance, diagnostics.Error("YARA-SCN-031", "Scenario expected a plan but planning was unsuccessful.", "spec.expected.outcome"))
	} else {
		conformance = append(conformance, comparePlan(golden, planning.Plan)...)
	}
	for _, code := range golden.Spec.Expected.RequiredDiagnosticCodes {
		if !slices.Contains(observed, code) {
			conformance = append(conformance, diagnostics.Error("YARA-SCN-036", "Required diagnostic was not observed.", "spec.expected.requiredDiagnosticCodes"))
		}
	}
	reportItems := append([]diagnostics.Diagnostic{}, conformance...)
	if planning.Report.Valid {
		reportItems = append(reportItems, planning.Plan.Spec.Diagnostics...)
	}
	return Result{
		Scenario: golden, Outcome: actualOutcome(planning), Plan: planning.Plan,
		ObservedDiagnosticCodes: observed, Report: diagnostics.NewReport(reportItems...),
	}
}

func comparePlan(golden resources.GoldenScenario, plan resources.PlatformPlan) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	if plan.Metadata.PlanID != golden.Spec.Expected.PlanID {
		items = append(items, diagnostics.Error("YARA-SCN-032", "Generated plan does not match the expected plan ID.", "spec.expected.planId"))
	}
	decisions := make(map[string]resources.PlanDecision, len(plan.Spec.Decisions))
	selected := make(map[string]struct{}, len(plan.Spec.Decisions))
	for _, decision := range plan.Spec.Decisions {
		decisions[decision.ID] = decision
		selected[decision.Selected] = struct{}{}
	}
	for _, decisionID := range golden.Spec.Expected.RequiredDecisionIDs {
		if _, exists := decisions[decisionID]; !exists {
			items = append(items, diagnostics.Error("YARA-SCN-033", "Required decision is absent from the generated plan.", "spec.expected.requiredDecisionIds"))
		}
	}
	for _, expectation := range golden.Spec.Expected.RequiredSelections {
		decision, exists := decisions[expectation.DecisionID]
		if !exists || decision.Selected != expectation.Selected {
			items = append(items, diagnostics.Error("YARA-SCN-034", "Generated plan does not contain the required selection.", "spec.expected.requiredSelections"))
		}
	}
	for _, forbidden := range golden.Spec.Expected.ForbiddenSelections {
		if _, exists := selected[forbidden]; exists {
			items = append(items, diagnostics.Error("YARA-SCN-035", "Generated plan contains a forbidden selection.", "spec.expected.forbiddenSelections"))
		}
	}
	return items
}

func observedDiagnosticCodes(result planner.Result) []string {
	set := make(map[string]struct{})
	for _, item := range result.Report.Diagnostics {
		set[item.Code] = struct{}{}
	}
	if result.Report.Valid {
		for _, item := range result.Plan.Spec.Diagnostics {
			set[item.Code] = struct{}{}
		}
	}
	codes := make([]string, 0, len(set))
	for code := range set {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes
}

func actualOutcome(result planner.Result) string {
	if result.Report.Valid {
		return resources.ScenarioOutcomePlanned
	}
	return resources.ScenarioOutcomeInfeasible
}

func inputFailure(golden resources.GoldenScenario, path string) Result {
	return Result{Scenario: golden, Report: diagnostics.NewReport(diagnostics.Error("YARA-SCN-004", "Could not load a referenced scenario input.", path))}
}

func invalidInputFailure(golden resources.GoldenScenario, path string, report diagnostics.Report) Result {
	items := []diagnostics.Diagnostic{diagnostics.Error("YARA-SCN-020", "Referenced scenario input is invalid.", path)}
	for _, item := range report.Diagnostics {
		items = append(items, diagnostics.Diagnostic{Code: item.Code, Severity: item.Severity, Message: "Referenced input validation failed."})
	}
	return Result{Scenario: golden, Report: diagnostics.NewReport(items...)}
}

func internalFailure(golden resources.GoldenScenario) Result {
	return Result{Scenario: golden, Report: diagnostics.NewReport(diagnostics.Error("YARA-SCN-500", "Could not compute scenario conformance."))}
}
