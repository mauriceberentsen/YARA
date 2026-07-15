// Package debugbundle constructs privacy-minimized local support artifacts.
package debugbundle

import (
	"encoding/json"
	"regexp"
	"sort"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|client[_-]?secret|private[_-]?key)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9+/_=-]{8,}`),
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/-]{8,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)://[^/\s:@]+:[^/\s@]+@`),
}

var omittedPlanPaths = []string{
	"metadata.name",
	"spec.allocations",
	"spec.confidence.factors[].subjectRefs",
	"spec.decisions",
	"spec.diagnostics[].message",
	"spec.diagnostics[].paths",
	"spec.diagnostics[].remediation",
	"spec.search.boundaries",
	"spec.topology.connections",
	"spec.topology.deploymentStages[]",
	"spec.topology.instances[].apiContracts",
	"spec.topology.instances[].componentRef",
	"spec.topology.instances[].id",
	"spec.topology.instances[].modelRef",
	"spec.topology.instances[].placement",
}

func Build(plan resources.PlatformPlan) (resources.DebugBundle, diagnostics.Report) {
	if report := plan.Validate(); !report.Valid {
		return resources.DebugBundle{}, report
	}
	bundle := resources.DebugBundle{
		APIVersion: resources.APIVersion,
		Kind:       "DebugBundle",
		Spec: resources.DebugBundleSpec{
			Generator: resources.DebugBundleGenerator{Version: version.Version},
			Source: resources.DebugBundleSource{
				PlanID: plan.Metadata.PlanID, RequestDigest: plan.Provenance.RequestDigest,
				InventoryDigest: plan.Provenance.InventoryDigest, CatalogDigest: plan.Provenance.CatalogDigest,
				PlannerVersion: plan.Provenance.PlannerVersion,
			},
			Summary:    summarizePlan(plan),
			Redaction:  resources.DebugBundleRedaction{Profile: "support-minimal-v1", OmittedPaths: append([]string{}, omittedPlanPaths...)},
			SecretScan: resources.DebugBundleSecretScan{Ruleset: "yara-secret-patterns-v1", Status: "passed", Findings: 0},
		},
	}
	var err error
	bundle.Spec.Contents, err = contentInventory(bundle)
	if err != nil {
		return resources.DebugBundle{}, diagnostics.NewReport(diagnostics.Error("YARA-DBG-500", "Could not identify debug bundle sections."))
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		return resources.DebugBundle{}, diagnostics.NewReport(diagnostics.Error("YARA-DBG-500", "Could not encode the candidate debug bundle for scanning."))
	}
	if hasSecretLikeContent(data) {
		return resources.DebugBundle{}, diagnostics.NewReport(diagnostics.Error(
			"YARA-DBG-003",
			"Secret-like content was detected; no debug bundle was produced.",
			"spec.secretScan",
		))
	}
	bundle, err = bundle.AssignBundleID()
	if err != nil {
		return resources.DebugBundle{}, diagnostics.NewReport(diagnostics.Error("YARA-DBG-500", "Could not assign the debug bundle identity."))
	}
	return bundle, bundle.Validate()
}

func summarizePlan(plan resources.PlatformPlan) resources.DebugBundleSummary {
	roles := make(map[string]int)
	for _, instance := range plan.Spec.Topology.Instances {
		roles[instance.Role]++
	}
	roleCounts := make([]resources.DebugBundleRoleCount, 0, len(roles))
	for role, count := range roles {
		roleCounts = append(roleCounts, resources.DebugBundleRoleCount{Role: role, Count: count})
	}
	sort.Slice(roleCounts, func(i, j int) bool { return roleCounts[i].Role < roleCounts[j].Role })

	factors := make([]resources.DebugBundleConfidenceFactor, len(plan.Spec.Confidence.Factors))
	for index, factor := range plan.Spec.Confidence.Factors {
		factors[index] = resources.DebugBundleConfidenceFactor{ID: factor.ID, Level: factor.Level, ReasonCode: factor.ReasonCode}
	}
	sort.Slice(factors, func(i, j int) bool { return factors[i].ID < factors[j].ID })

	codeSet := make(map[string]struct{}, len(plan.Spec.Diagnostics))
	for _, diagnostic := range plan.Spec.Diagnostics {
		codeSet[diagnostic.Code] = struct{}{}
	}
	codes := make([]string, 0, len(codeSet))
	for code := range codeSet {
		codes = append(codes, code)
	}
	sort.Strings(codes)

	search := plan.Spec.Search
	return resources.DebugBundleSummary{
		Status: plan.Spec.Status,
		Search: resources.DebugBundleSearchSummary{
			Strategy: search.Strategy, CompleteWithinBounds: search.CompleteWithinBounds,
			Truncated: search.Truncated, GlobalOptimalityClaimed: search.GlobalOptimalityClaimed,
			EvaluatedServingCandidates: search.EvaluatedServingCandidates,
			FeasibleServingCandidates:  search.FeasibleServingCandidates,
			RejectedServingCandidates:  search.RejectedServingCandidates, BoundaryCount: len(search.Boundaries),
		},
		Confidence: resources.DebugBundleConfidenceSummary{
			Level: plan.Spec.Confidence.Level, Method: plan.Spec.Confidence.Method, Factors: factors,
		},
		Topology: resources.DebugBundleTopologySummary{
			InstanceCount: len(plan.Spec.Topology.Instances), ConnectionCount: len(plan.Spec.Topology.Connections),
			DeploymentStageCount: len(plan.Spec.Topology.DeploymentStages), Roles: roleCounts,
		},
		AllocationCount: len(plan.Spec.Allocations), DecisionCount: len(plan.Spec.Decisions), DiagnosticCodes: codes,
	}
}

func contentInventory(bundle resources.DebugBundle) ([]resources.DebugBundleContent, error) {
	sections := map[string]any{
		"generator":        bundle.Spec.Generator,
		"plan-source":      bundle.Spec.Source,
		"plan-summary":     bundle.Spec.Summary,
		"redaction-report": bundle.Spec.Redaction,
	}
	contents := make([]resources.DebugBundleContent, 0, len(sections))
	for name, section := range sections {
		digest, err := canonical.Digest(section)
		if err != nil {
			return nil, err
		}
		contents = append(contents, resources.DebugBundleContent{Name: name, Classification: "support-metadata", Digest: digest})
	}
	sort.Slice(contents, func(i, j int) bool { return contents[i].Name < contents[j].Name })
	return contents, nil
}

func hasSecretLikeContent(data []byte) bool {
	for _, pattern := range secretPatterns {
		if pattern.Match(data) {
			return true
		}
	}
	return false
}
