package scenario

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

const RequiredV01AcceptanceGateReviewCount = 5

type ReviewStatus struct {
	IndependentReviewsComplete    int
	IndependentReviewStatus       string
	AcceptanceGateReviewsComplete int
	AcceptanceGateReviewStatus    string
	ReleaseEligible               bool
}

func EvaluateScenarioReview(manifestPath string, golden resources.GoldenScenario) (resources.ScenarioReview, diagnostics.Report) {
	reviewPath := filepath.Join(filepath.Dir(manifestPath), "review.yaml")
	review, err := resources.LoadScenarioReview(reviewPath)
	if err != nil {
		return resources.ScenarioReview{}, diagnostics.NewReport(diagnostics.Error("YARA-SCN-050", "Could not load scenario review.", "review.yaml"))
	}
	return review, review.ConformsTo(golden)
}

func EvaluateGateReviews(gateReviewDir string) (complete int, report diagnostics.Report) {
	if strings.TrimSpace(gateReviewDir) == "" {
		return 0, diagnostics.NewReport()
	}
	info, err := os.Stat(gateReviewDir)
	if err != nil || !info.IsDir() {
		return 0, diagnostics.NewReport()
	}
	paths, err := findGateReviewManifests(gateReviewDir)
	if err != nil {
		return 0, diagnostics.NewReport(diagnostics.Error("YARA-SCN-065", "Could not enumerate acceptance gate reviews."))
	}
	seenCriteria := make(map[int]struct{}, len(resources.RequiredV01AcceptanceGateCriteria))
	for _, path := range paths {
		review, err := resources.LoadAcceptanceGateReview(path)
		if err != nil {
			continue
		}
		if !review.Approved() {
			continue
		}
		if _, exists := seenCriteria[review.Spec.AcceptanceCriterion]; exists {
			continue
		}
		seenCriteria[review.Spec.AcceptanceCriterion] = struct{}{}
	}
	return len(seenCriteria), diagnostics.NewReport()
}

func SummarizeReviewStatus(suiteRoot string, entries []SuiteEntry, gateReviewDir string) ReviewStatus {
	status := ReviewStatus{
		IndependentReviewStatus:    "required",
		AcceptanceGateReviewStatus: "required",
	}
	for _, entry := range entries {
		if !entry.Conformant {
			continue
		}
		manifestPath := filepath.Join(suiteRoot, entry.Name, "scenario.yaml")
		golden, err := resources.LoadGoldenScenario(manifestPath)
		if err != nil {
			continue
		}
		if _, report := EvaluateScenarioReview(manifestPath, golden); report.Valid {
			status.IndependentReviewsComplete++
		}
	}
	if status.IndependentReviewsComplete == len(entries) && len(entries) >= RequiredV01ScenarioCount {
		status.IndependentReviewStatus = "complete"
	}
	status.AcceptanceGateReviewsComplete, _ = EvaluateGateReviews(gateReviewDir)
	if status.AcceptanceGateReviewsComplete >= RequiredV01AcceptanceGateReviewCount {
		status.AcceptanceGateReviewStatus = "complete"
	}
	status.ReleaseEligible = len(entries) >= RequiredV01ScenarioCount &&
		status.IndependentReviewsComplete == len(entries) &&
		len(entries) > 0 &&
		status.AcceptanceGateReviewsComplete >= RequiredV01AcceptanceGateReviewCount
	return status
}

func ResolveGateReviewDir(suiteRoot string) string {
	candidate := filepath.Clean(filepath.Join(suiteRoot, "..", "..", "docs", "implementation", "reviews"))
	info, err := os.Stat(candidate)
	if err != nil || !info.IsDir() {
		return ""
	}
	return candidate
}

func findGateReviewManifests(root string) ([]string, error) {
	paths := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && (entry.Name() == "review.yaml" || strings.HasSuffix(entry.Name(), "-review.yaml")) {
			paths = append(paths, path)
		}
		return nil
	})
	sort.Strings(paths)
	return paths, err
}
