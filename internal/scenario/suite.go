package scenario

import (
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

const RequiredV01ScenarioCount = 10

type SuiteEntry struct {
	Name                    string   `json:"name"`
	ScenarioID              string   `json:"scenarioId"`
	Outcome                 string   `json:"outcome"`
	PlanID                  string   `json:"planId,omitempty"`
	Conformant              bool     `json:"conformant"`
	ObservedDiagnosticCodes []string `json:"observedDiagnosticCodes"`
}

type SuiteResult struct {
	Entries               []SuiteEntry
	Planned               int
	Infeasible            int
	TechnicallyConformant int
	Review                ReviewStatus
	Report                diagnostics.Report
}

func EvaluateAll(root string) SuiteResult {
	paths, err := findScenarioManifests(root)
	if err != nil {
		return SuiteResult{Report: diagnostics.NewReport(diagnostics.Error("YARA-SCN-040", "Could not enumerate scenario manifests."))}
	}
	var items []diagnostics.Diagnostic
	if len(paths) < RequiredV01ScenarioCount {
		items = append(items, diagnostics.Error("YARA-SCN-042", "The v0.1 acceptance suite requires at least ten scenarios."))
	}
	result := SuiteResult{Entries: make([]SuiteEntry, 0, len(paths))}
	seenNames := make(map[string]struct{}, len(paths))
	seenIDs := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		golden, err := resources.LoadGoldenScenario(path)
		if err != nil {
			items = append(items, diagnostics.Error("YARA-SCN-004", "Could not load a golden scenario in the suite."))
			continue
		}
		evaluation := Evaluate(path, golden)
		entry := SuiteEntry{
			Name: golden.Metadata.Name, ScenarioID: golden.Metadata.ScenarioID,
			Outcome: evaluation.Outcome, Conformant: evaluation.Report.Valid,
			ObservedDiagnosticCodes: evaluation.ObservedDiagnosticCodes,
		}
		if evaluation.Outcome == resources.ScenarioOutcomePlanned {
			entry.PlanID = evaluation.Plan.Metadata.PlanID
			result.Planned++
		} else if evaluation.Outcome == resources.ScenarioOutcomeInfeasible {
			result.Infeasible++
		}
		if evaluation.Report.Valid {
			result.TechnicallyConformant++
		} else {
			items = append(items, diagnostics.Error("YARA-SCN-043", "A golden scenario does not conform to its pinned expectations.", golden.Metadata.Name))
			for _, item := range evaluation.Report.Diagnostics {
				if item.Severity == diagnostics.SeverityError || item.Severity == diagnostics.SeverityQuestion {
					items = append(items, diagnostics.Diagnostic{Code: item.Code, Severity: item.Severity, Message: "Scenario conformance failed."})
				}
			}
		}
		if _, exists := seenNames[entry.Name]; exists {
			items = append(items, diagnostics.Error("YARA-SCN-041", "Scenario names and identities must be unique."))
		}
		if _, exists := seenIDs[entry.ScenarioID]; exists {
			items = append(items, diagnostics.Error("YARA-SCN-041", "Scenario names and identities must be unique."))
		}
		seenNames[entry.Name] = struct{}{}
		seenIDs[entry.ScenarioID] = struct{}{}
		result.Entries = append(result.Entries, entry)
	}
	sort.Slice(result.Entries, func(i, j int) bool { return result.Entries[i].Name < result.Entries[j].Name })
	result.Review = SummarizeReviewStatus(root, result.Entries, ResolveGateReviewDir(root))
	result.Report = diagnostics.NewReport(items...)
	return result
}

func findScenarioManifests(root string) ([]string, error) {
	paths := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Name() == "scenario.yaml" {
			paths = append(paths, path)
			if len(paths) > 100 {
				return fs.ErrInvalid
			}
		}
		return nil
	})
	sort.Strings(paths)
	return paths, err
}
