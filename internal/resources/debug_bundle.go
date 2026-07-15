package resources

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

var diagnosticCodePattern = regexp.MustCompile(`^YARA-[A-Z]+-[0-9]{3}$`)

type DebugBundle struct {
	APIVersion string              `json:"apiVersion" yaml:"apiVersion"`
	Kind       string              `json:"kind" yaml:"kind"`
	Metadata   DebugBundleMetadata `json:"metadata" yaml:"metadata"`
	Spec       DebugBundleSpec     `json:"spec" yaml:"spec"`
}

type DebugBundleMetadata struct {
	BundleID string `json:"bundleId" yaml:"bundleId"`
}

type DebugBundleSpec struct {
	Generator  DebugBundleGenerator  `json:"generator" yaml:"generator"`
	Source     DebugBundleSource     `json:"source" yaml:"source"`
	Contents   []DebugBundleContent  `json:"contents" yaml:"contents"`
	Summary    DebugBundleSummary    `json:"summary" yaml:"summary"`
	Redaction  DebugBundleRedaction  `json:"redaction" yaml:"redaction"`
	SecretScan DebugBundleSecretScan `json:"secretScan" yaml:"secretScan"`
}

type DebugBundleGenerator struct {
	Version string `json:"version" yaml:"version"`
}

type DebugBundleSource struct {
	PlanID          string `json:"planId" yaml:"planId"`
	RequestDigest   string `json:"requestDigest" yaml:"requestDigest"`
	InventoryDigest string `json:"inventoryDigest" yaml:"inventoryDigest"`
	CatalogDigest   string `json:"catalogDigest" yaml:"catalogDigest"`
	PlannerVersion  string `json:"plannerVersion" yaml:"plannerVersion"`
}

type DebugBundleContent struct {
	Name           string `json:"name" yaml:"name"`
	Classification string `json:"classification" yaml:"classification"`
	Digest         string `json:"digest" yaml:"digest"`
}

type DebugBundleSummary struct {
	Status          string                       `json:"status" yaml:"status"`
	Search          DebugBundleSearchSummary     `json:"search" yaml:"search"`
	Confidence      DebugBundleConfidenceSummary `json:"confidence" yaml:"confidence"`
	Topology        DebugBundleTopologySummary   `json:"topology" yaml:"topology"`
	AllocationCount int                          `json:"allocationCount" yaml:"allocationCount"`
	DecisionCount   int                          `json:"decisionCount" yaml:"decisionCount"`
	DiagnosticCodes []string                     `json:"diagnosticCodes" yaml:"diagnosticCodes"`
}

type DebugBundleSearchSummary struct {
	Strategy                   string `json:"strategy" yaml:"strategy"`
	CompleteWithinBounds       bool   `json:"completeWithinBounds" yaml:"completeWithinBounds"`
	Truncated                  bool   `json:"truncated" yaml:"truncated"`
	GlobalOptimalityClaimed    bool   `json:"globalOptimalityClaimed" yaml:"globalOptimalityClaimed"`
	EvaluatedServingCandidates int    `json:"evaluatedServingCandidates" yaml:"evaluatedServingCandidates"`
	FeasibleServingCandidates  int    `json:"feasibleServingCandidates" yaml:"feasibleServingCandidates"`
	RejectedServingCandidates  int    `json:"rejectedServingCandidates" yaml:"rejectedServingCandidates"`
	BoundaryCount              int    `json:"boundaryCount" yaml:"boundaryCount"`
}

type DebugBundleConfidenceSummary struct {
	Level   string                        `json:"level" yaml:"level"`
	Method  string                        `json:"method" yaml:"method"`
	Factors []DebugBundleConfidenceFactor `json:"factors" yaml:"factors"`
}

type DebugBundleConfidenceFactor struct {
	ID         string `json:"id" yaml:"id"`
	Level      string `json:"level" yaml:"level"`
	ReasonCode string `json:"reasonCode" yaml:"reasonCode"`
}

type DebugBundleTopologySummary struct {
	InstanceCount        int                    `json:"instanceCount" yaml:"instanceCount"`
	ConnectionCount      int                    `json:"connectionCount" yaml:"connectionCount"`
	DeploymentStageCount int                    `json:"deploymentStageCount" yaml:"deploymentStageCount"`
	Roles                []DebugBundleRoleCount `json:"roles" yaml:"roles"`
}

type DebugBundleRoleCount struct {
	Role  string `json:"role" yaml:"role"`
	Count int    `json:"count" yaml:"count"`
}

type DebugBundleRedaction struct {
	Profile      string   `json:"profile" yaml:"profile"`
	OmittedPaths []string `json:"omittedPaths" yaml:"omittedPaths"`
}

type DebugBundleSecretScan struct {
	Ruleset  string `json:"ruleset" yaml:"ruleset"`
	Status   string `json:"status" yaml:"status"`
	Findings int    `json:"findings" yaml:"findings"`
}

func (b DebugBundle) AssignBundleID() (DebugBundle, error) {
	b.Metadata.BundleID = ""
	digest, err := canonical.Digest(b)
	if err != nil {
		return DebugBundle{}, fmt.Errorf("digest debug bundle: %w", err)
	}
	b.Metadata.BundleID = digest
	return b, nil
}

func (b DebugBundle) Validate() diagnostics.Report {
	var items []diagnostics.Diagnostic
	if b.APIVersion != APIVersion {
		items = append(items, diagnostics.Error("YARA-DBG-001", "Unsupported apiVersion; expected "+APIVersion+".", "apiVersion"))
	}
	if b.Kind != "DebugBundle" {
		items = append(items, diagnostics.Error("YARA-DBG-002", "Unexpected resource kind; expected DebugBundle.", "kind"))
	}
	if !sha256DigestPattern.MatchString(b.Metadata.BundleID) {
		items = append(items, diagnostics.Error("YARA-DBG-010", "metadata.bundleId must be a SHA-256 identity.", "metadata.bundleId"))
	}
	for _, field := range []struct{ path, value string }{
		{"spec.source.planId", b.Spec.Source.PlanID},
		{"spec.source.requestDigest", b.Spec.Source.RequestDigest},
		{"spec.source.inventoryDigest", b.Spec.Source.InventoryDigest},
		{"spec.source.catalogDigest", b.Spec.Source.CatalogDigest},
	} {
		if !sha256DigestPattern.MatchString(field.value) {
			items = append(items, diagnostics.Error("YARA-DBG-011", "Bundle source identities must be SHA-256 identities.", field.path))
		}
	}
	if strings.TrimSpace(b.Spec.Generator.Version) == "" || strings.TrimSpace(b.Spec.Source.PlannerVersion) == "" {
		items = append(items, diagnostics.Error("YARA-DBG-012", "Generator and planner versions are required.", "spec"))
	}
	if b.Spec.Summary.Topology.InstanceCount < 1 || b.Spec.Summary.AllocationCount < 1 || b.Spec.Summary.DecisionCount < 1 {
		items = append(items, diagnostics.Error("YARA-DBG-013", "Bundle summary counts must describe a complete plan.", "spec.summary"))
	}
	items = append(items, validateDebugBundleSearch(b.Spec.Summary.Search)...)
	items = append(items, validateDebugBundleConfidence(b.Spec.Summary.Confidence)...)
	items = append(items, validateDebugBundleTopology(b.Spec.Summary.Topology)...)
	if !sortedUniqueDiagnosticCodes(b.Spec.Summary.DiagnosticCodes) {
		items = append(items, diagnostics.Error("YARA-DBG-014", "Diagnostic codes must be valid, unique and sorted.", "spec.summary.diagnosticCodes"))
	}
	if len(b.Spec.Contents) != 4 || !slices.IsSortedFunc(b.Spec.Contents, func(a, c DebugBundleContent) int { return strings.Compare(a.Name, c.Name) }) {
		items = append(items, diagnostics.Error("YARA-DBG-015", "Bundle contents inventory must contain the four supported sections in deterministic order.", "spec.contents"))
	}
	expectedDigests, digestErr := b.expectedContentDigests()
	if digestErr != nil {
		items = append(items, diagnostics.Error("YARA-DBG-500", "Could not recompute bundle section identities."))
	} else {
		seen := make(map[string]struct{}, len(b.Spec.Contents))
		for index, content := range b.Spec.Contents {
			expected, exists := expectedDigests[content.Name]
			if !exists || content.Classification != "support-metadata" || content.Digest != expected {
				items = append(items, diagnostics.Error("YARA-DBG-016", "Bundle content inventory does not match its section.", fmt.Sprintf("spec.contents[%d]", index)))
			}
			if _, exists := seen[content.Name]; exists {
				items = append(items, diagnostics.Error("YARA-DBG-017", "Bundle content names must be unique.", fmt.Sprintf("spec.contents[%d].name", index)))
			}
			seen[content.Name] = struct{}{}
		}
	}
	if b.Spec.Redaction.Profile != "support-minimal-v1" || len(b.Spec.Redaction.OmittedPaths) == 0 || !sortedUniqueStrings(b.Spec.Redaction.OmittedPaths) {
		items = append(items, diagnostics.Error("YARA-DBG-018", "The supported redaction profile and sorted omitted paths are required.", "spec.redaction"))
	}
	if b.Spec.SecretScan.Ruleset != "yara-secret-patterns-v1" || b.Spec.SecretScan.Status != "passed" || b.Spec.SecretScan.Findings != 0 {
		items = append(items, diagnostics.Error("YARA-DBG-019", "A publishable bundle must pass the supported secret scan with zero findings.", "spec.secretScan"))
	}
	if b.Metadata.BundleID != "" {
		claimed := b.Metadata.BundleID
		recomputed, err := b.AssignBundleID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-DBG-500", "Could not recompute debug bundle identity."))
		} else if recomputed.Metadata.BundleID != claimed {
			items = append(items, diagnostics.Error("YARA-DBG-020", "Bundle contents do not match metadata.bundleId.", "metadata.bundleId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func validateDebugBundleSearch(search DebugBundleSearchSummary) []diagnostics.Diagnostic {
	if search.Strategy != "bounded-catalog-enumeration-v1" || !search.CompleteWithinBounds || search.Truncated || search.GlobalOptimalityClaimed ||
		search.EvaluatedServingCandidates < 1 || search.FeasibleServingCandidates < 1 || search.RejectedServingCandidates < 0 ||
		search.EvaluatedServingCandidates != search.FeasibleServingCandidates+search.RejectedServingCandidates || search.BoundaryCount < 1 {
		return []diagnostics.Diagnostic{diagnostics.Error("YARA-DBG-021", "Search summary is inconsistent with a successful bounded v0.1 plan.", "spec.summary.search")}
	}
	return nil
}

func validateDebugBundleConfidence(confidence DebugBundleConfidenceSummary) []diagnostics.Diagnostic {
	if confidence.Method != "minimum-factor-v1" || !validConfidenceLevel(confidence.Level) || len(confidence.Factors) == 0 {
		return []diagnostics.Diagnostic{diagnostics.Error("YARA-DBG-022", "Confidence summary requires the supported method, level and factors.", "spec.summary.confidence")}
	}
	minimum, previous := "high", ""
	seen := make(map[string]struct{}, len(confidence.Factors))
	for _, factor := range confidence.Factors {
		if strings.TrimSpace(factor.ID) == "" || previous > factor.ID || !validConfidenceLevel(factor.Level) || !confidenceReasonCodePattern.MatchString(factor.ReasonCode) {
			return []diagnostics.Diagnostic{diagnostics.Error("YARA-DBG-022", "Confidence factors must be valid and deterministically ordered.", "spec.summary.confidence.factors")}
		}
		if _, exists := seen[factor.ID]; exists {
			return []diagnostics.Diagnostic{diagnostics.Error("YARA-DBG-022", "Confidence factor IDs must be unique.", "spec.summary.confidence.factors")}
		}
		seen[factor.ID] = struct{}{}
		previous = factor.ID
		if confidenceRank(factor.Level) < confidenceRank(minimum) {
			minimum = factor.Level
		}
	}
	if confidence.Level != minimum {
		return []diagnostics.Diagnostic{diagnostics.Error("YARA-DBG-022", "Overall confidence must equal the least-confident factor.", "spec.summary.confidence.level")}
	}
	return nil
}

func validateDebugBundleTopology(topology DebugBundleTopologySummary) []diagnostics.Diagnostic {
	if topology.InstanceCount < 1 || topology.ConnectionCount < 0 || topology.DeploymentStageCount < 1 || len(topology.Roles) == 0 ||
		!slices.IsSortedFunc(topology.Roles, func(a, b DebugBundleRoleCount) int { return strings.Compare(a.Role, b.Role) }) {
		return []diagnostics.Diagnostic{diagnostics.Error("YARA-DBG-023", "Topology summary counts and roles are invalid.", "spec.summary.topology")}
	}
	count, previous := 0, ""
	for _, role := range topology.Roles {
		if strings.TrimSpace(role.Role) == "" || role.Count < 1 || role.Role == previous {
			return []diagnostics.Diagnostic{diagnostics.Error("YARA-DBG-023", "Topology roles must be non-empty, unique and positive.", "spec.summary.topology.roles")}
		}
		previous = role.Role
		count += role.Count
	}
	if count != topology.InstanceCount {
		return []diagnostics.Diagnostic{diagnostics.Error("YARA-DBG-023", "Topology role counts must equal instanceCount.", "spec.summary.topology")}
	}
	return nil
}

func (b DebugBundle) expectedContentDigests() (map[string]string, error) {
	values := map[string]any{
		"generator":        b.Spec.Generator,
		"plan-source":      b.Spec.Source,
		"plan-summary":     b.Spec.Summary,
		"redaction-report": b.Spec.Redaction,
	}
	digests := make(map[string]string, len(values))
	for name, value := range values {
		digest, err := canonical.Digest(value)
		if err != nil {
			return nil, err
		}
		digests[name] = digest
	}
	return digests, nil
}

func sortedUniqueDiagnosticCodes(codes []string) bool {
	if !sort.StringsAreSorted(codes) {
		return false
	}
	for index, code := range codes {
		if !diagnosticCodePattern.MatchString(code) || (index > 0 && code == codes[index-1]) {
			return false
		}
	}
	return true
}

func sortedUniqueStrings(values []string) bool {
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
