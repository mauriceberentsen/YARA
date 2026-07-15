package resources

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

var sha256DigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var confidenceReasonCodePattern = regexp.MustCompile(`^YARA-CONF-[0-9]{3}$`)

type PlatformPlan struct {
	APIVersion string           `json:"apiVersion" yaml:"apiVersion"`
	Kind       string           `json:"kind" yaml:"kind"`
	Metadata   PlanMetadata     `json:"metadata" yaml:"metadata"`
	Provenance PlanProvenance   `json:"provenance" yaml:"provenance"`
	Spec       PlatformPlanSpec `json:"spec" yaml:"spec"`
}

type PlanMetadata struct {
	Name   string `json:"name" yaml:"name"`
	PlanID string `json:"planId" yaml:"planId"`
}

type PlanProvenance struct {
	RequestDigest   string `json:"requestDigest" yaml:"requestDigest"`
	InventoryDigest string `json:"inventoryDigest" yaml:"inventoryDigest"`
	CatalogDigest   string `json:"catalogDigest" yaml:"catalogDigest"`
	PlannerVersion  string `json:"plannerVersion" yaml:"plannerVersion"`
}

type PlatformPlanSpec struct {
	Status      string                   `json:"status" yaml:"status"`
	Search      PlanSearchSummary        `json:"search" yaml:"search"`
	Confidence  PlanConfidenceSummary    `json:"confidence" yaml:"confidence"`
	Topology    PlanTopology             `json:"topology" yaml:"topology"`
	Allocations []PlanAllocation         `json:"allocations" yaml:"allocations"`
	Decisions   []PlanDecision           `json:"decisions" yaml:"decisions"`
	Diagnostics []diagnostics.Diagnostic `json:"diagnostics" yaml:"diagnostics"`
}

type PlanSearchSummary struct {
	Strategy                   string   `json:"strategy" yaml:"strategy"`
	CompleteWithinBounds       bool     `json:"completeWithinBounds" yaml:"completeWithinBounds"`
	Truncated                  bool     `json:"truncated" yaml:"truncated"`
	GlobalOptimalityClaimed    bool     `json:"globalOptimalityClaimed" yaml:"globalOptimalityClaimed"`
	EvaluatedServingCandidates int      `json:"evaluatedServingCandidates" yaml:"evaluatedServingCandidates"`
	FeasibleServingCandidates  int      `json:"feasibleServingCandidates" yaml:"feasibleServingCandidates"`
	RejectedServingCandidates  int      `json:"rejectedServingCandidates" yaml:"rejectedServingCandidates"`
	Boundaries                 []string `json:"boundaries" yaml:"boundaries"`
}

type PlanConfidenceSummary struct {
	Level   string                 `json:"level" yaml:"level"`
	Method  string                 `json:"method" yaml:"method"`
	Factors []PlanConfidenceFactor `json:"factors" yaml:"factors"`
}

type PlanConfidenceFactor struct {
	ID          string   `json:"id" yaml:"id"`
	Level       string   `json:"level" yaml:"level"`
	ReasonCode  string   `json:"reasonCode" yaml:"reasonCode"`
	SubjectRefs []string `json:"subjectRefs" yaml:"subjectRefs"`
}

type PlanTopology struct {
	Instances        []PlanInstance   `json:"instances" yaml:"instances"`
	Connections      []PlanConnection `json:"connections" yaml:"connections"`
	DeploymentStages [][]string       `json:"deploymentStages" yaml:"deploymentStages"`
}

type PlanInstance struct {
	ID           string   `json:"id" yaml:"id"`
	Role         string   `json:"role" yaml:"role"`
	ComponentRef string   `json:"componentRef" yaml:"componentRef"`
	ModelRef     string   `json:"modelRef,omitempty" yaml:"modelRef,omitempty"`
	Placement    string   `json:"placement" yaml:"placement"`
	APIContracts []string `json:"apiContracts" yaml:"apiContracts"`
}

type PlanConnection struct {
	From     string `json:"from" yaml:"from"`
	To       string `json:"to" yaml:"to"`
	Contract string `json:"contract" yaml:"contract"`
}

type PlanAllocation struct {
	InstanceID           string  `json:"instanceId" yaml:"instanceId"`
	AcceleratorID        string  `json:"acceleratorId" yaml:"acceleratorId"`
	EstimatedMemoryGiB   float64 `json:"estimatedMemoryGiB" yaml:"estimatedMemoryGiB"`
	AllocatableMemoryGiB float64 `json:"allocatableMemoryGiB" yaml:"allocatableMemoryGiB"`
}

type PlanDecision struct {
	ID           string            `json:"id" yaml:"id"`
	Selected     string            `json:"selected" yaml:"selected"`
	Reasons      []string          `json:"reasons" yaml:"reasons"`
	Evidence     []string          `json:"evidence" yaml:"evidence"`
	Alternatives []PlanAlternative `json:"alternatives" yaml:"alternatives"`
}

type PlanAlternative struct {
	ID              string  `json:"id" yaml:"id"`
	Outcome         string  `json:"outcome" yaml:"outcome"`
	Code            string  `json:"code,omitempty" yaml:"code,omitempty"`
	Reason          string  `json:"reason" yaml:"reason"`
	EstimatedGiB    float64 `json:"estimatedGiB" yaml:"estimatedGiB"`
	AvailableGiB    float64 `json:"availableGiB" yaml:"availableGiB"`
	PreferenceScore float64 `json:"preferenceScore" yaml:"preferenceScore"`
}

func (p PlatformPlan) Validate() diagnostics.Report {
	items := validateEnvelope(p.APIVersion, p.Kind, "PlatformPlan", "PLAN", Metadata{Name: p.Metadata.Name})
	required := []struct {
		path  string
		value string
	}{
		{path: "metadata.planId", value: p.Metadata.PlanID},
		{path: "provenance.requestDigest", value: p.Provenance.RequestDigest},
		{path: "provenance.inventoryDigest", value: p.Provenance.InventoryDigest},
		{path: "provenance.catalogDigest", value: p.Provenance.CatalogDigest},
		{path: "provenance.plannerVersion", value: p.Provenance.PlannerVersion},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			items = append(items, diagnostics.Error("YARA-PLAN-010", "Required plan provenance or identity is missing.", field.path))
		} else if field.path != "provenance.plannerVersion" && !sha256DigestPattern.MatchString(field.value) {
			items = append(items, diagnostics.Error("YARA-PLAN-013", "Plan identity and provenance digests must be SHA-256 identities.", field.path))
		}
	}
	if p.Spec.Status != "review-required" {
		items = append(items, diagnostics.Error("YARA-PLAN-011", "A newly generated plan must require review.", "spec.status"))
	}
	items = append(items, validatePlanSearch(p.Spec.Search)...)
	items = append(items, validatePlanConfidence(p.Spec.Confidence)...)
	if len(p.Spec.Topology.Instances) == 0 || len(p.Spec.Decisions) == 0 || len(p.Spec.Allocations) == 0 {
		items = append(items, diagnostics.Error("YARA-PLAN-012", "Plan topology, allocation and decision must be present.", "spec"))
	}
	items = append(items, validatePlanTopology(p.Spec.Topology)...)
	if p.Metadata.PlanID != "" {
		claimedID := p.Metadata.PlanID
		recomputed, err := p.AssignPlanID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-PLAN-500", "Could not recompute semantic plan identity."))
		} else if recomputed.Metadata.PlanID != claimedID {
			items = append(items, diagnostics.Error("YARA-PLAN-014", "Plan contents do not match metadata.planId.", "metadata.planId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func validatePlanSearch(search PlanSearchSummary) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	if search.Strategy != "bounded-catalog-enumeration-v1" {
		items = append(items, diagnostics.Error("YARA-PLAN-025", "Search strategy must identify the supported bounded enumeration contract.", "spec.search.strategy"))
	}
	if search.EvaluatedServingCandidates <= 0 || search.FeasibleServingCandidates <= 0 || search.RejectedServingCandidates < 0 || search.EvaluatedServingCandidates != search.FeasibleServingCandidates+search.RejectedServingCandidates {
		items = append(items, diagnostics.Error("YARA-PLAN-026", "Search candidate counts are inconsistent.", "spec.search"))
	}
	if search.Truncated || !search.CompleteWithinBounds {
		items = append(items, diagnostics.Error("YARA-PLAN-027", "A successful v0.1 plan requires an untruncated search complete within its declared bounds.", "spec.search"))
	}
	if search.GlobalOptimalityClaimed {
		items = append(items, diagnostics.Error("YARA-PLAN-028", "v0.1 must not claim global optimality.", "spec.search.globalOptimalityClaimed"))
	}
	if len(search.Boundaries) == 0 || !slices.IsSorted(search.Boundaries) {
		items = append(items, diagnostics.Error("YARA-PLAN-029", "Search boundaries must be present in deterministic order.", "spec.search.boundaries"))
	}
	seen := make(map[string]struct{}, len(search.Boundaries))
	for _, boundary := range search.Boundaries {
		if strings.TrimSpace(boundary) == "" {
			items = append(items, diagnostics.Error("YARA-PLAN-030", "Search boundaries must not be empty.", "spec.search.boundaries"))
		}
		if _, exists := seen[boundary]; exists {
			items = append(items, diagnostics.Error("YARA-PLAN-031", "Search boundaries must be unique.", "spec.search.boundaries"))
		}
		seen[boundary] = struct{}{}
	}
	return items
}

func validatePlanConfidence(confidence PlanConfidenceSummary) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	if confidence.Method != "minimum-factor-v1" || !validConfidenceLevel(confidence.Level) || len(confidence.Factors) == 0 {
		items = append(items, diagnostics.Error("YARA-PLAN-032", "Confidence requires the supported method, level and at least one factor.", "spec.confidence"))
	}
	minimum := "high"
	seen := make(map[string]struct{}, len(confidence.Factors))
	previousID := ""
	for index, factor := range confidence.Factors {
		path := fmt.Sprintf("spec.confidence.factors[%d]", index)
		if factor.ID == "" || !confidenceReasonCodePattern.MatchString(factor.ReasonCode) || !validConfidenceLevel(factor.Level) || len(factor.SubjectRefs) == 0 {
			items = append(items, diagnostics.Error("YARA-PLAN-033", "Confidence factors require an ID, level, reason code and subject reference.", path))
		}
		if _, exists := seen[factor.ID]; exists {
			items = append(items, diagnostics.Error("YARA-PLAN-034", "Confidence factor IDs must be unique.", path+".id"))
		}
		seen[factor.ID] = struct{}{}
		if previousID > factor.ID {
			items = append(items, diagnostics.Error("YARA-PLAN-035", "Confidence factors must use deterministic ID order.", "spec.confidence.factors"))
		}
		previousID = factor.ID
		if confidenceRank(factor.Level) < confidenceRank(minimum) {
			minimum = factor.Level
		}
		if !slices.IsSorted(factor.SubjectRefs) {
			items = append(items, diagnostics.Error("YARA-PLAN-036", "Confidence subject references must use deterministic order.", path+".subjectRefs"))
		}
		subjects := make(map[string]struct{}, len(factor.SubjectRefs))
		for _, reference := range factor.SubjectRefs {
			if strings.TrimSpace(reference) == "" {
				items = append(items, diagnostics.Error("YARA-PLAN-038", "Confidence subject references must not be empty.", path+".subjectRefs"))
			}
			if _, exists := subjects[reference]; exists {
				items = append(items, diagnostics.Error("YARA-PLAN-039", "Confidence subject references must be unique.", path+".subjectRefs"))
			}
			subjects[reference] = struct{}{}
		}
	}
	if validConfidenceLevel(confidence.Level) && confidence.Level != minimum {
		items = append(items, diagnostics.Error("YARA-PLAN-037", "Overall confidence must equal the least-confident factor.", "spec.confidence.level"))
	}
	return items
}

func validConfidenceLevel(value string) bool {
	return value == "low" || value == "medium" || value == "high"
}

func confidenceRank(value string) int {
	switch value {
	case "medium":
		return 1
	case "high":
		return 2
	default:
		return 0
	}
}

func validatePlanTopology(topology PlanTopology) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	instances := make(map[string]PlanInstance, len(topology.Instances))
	for index, instance := range topology.Instances {
		path := fmt.Sprintf("spec.topology.instances[%d]", index)
		if instance.ID == "" || instance.Role == "" || instance.ComponentRef == "" || instance.Placement == "" || len(instance.APIContracts) == 0 {
			items = append(items, diagnostics.Error("YARA-PLAN-015", "Plan instance is incomplete.", path))
		}
		if _, exists := instances[instance.ID]; exists {
			items = append(items, diagnostics.Error("YARA-PLAN-016", "Plan instance IDs must be unique.", path+".id"))
		}
		instances[instance.ID] = instance
	}
	for index, connection := range topology.Connections {
		path := fmt.Sprintf("spec.topology.connections[%d]", index)
		from, fromExists := instances[connection.From]
		to, toExists := instances[connection.To]
		if !fromExists || !toExists || connection.From == connection.To || connection.Contract == "" {
			items = append(items, diagnostics.Error("YARA-PLAN-017", "Plan connection has invalid endpoints or contract.", path))
			continue
		}
		if !contains(from.APIContracts, connection.Contract) || !contains(to.APIContracts, connection.Contract) {
			items = append(items, diagnostics.Error("YARA-PLAN-018", "Both connection endpoints must implement the declared contract.", path+".contract"))
		}
	}
	staged := make(map[string]int, len(instances))
	for stageIndex, stage := range topology.DeploymentStages {
		for _, id := range stage {
			if _, exists := instances[id]; !exists {
				items = append(items, diagnostics.Error("YARA-PLAN-019", "Deployment stage references an unknown instance.", "spec.topology.deploymentStages"))
			}
			if _, exists := staged[id]; exists {
				items = append(items, diagnostics.Error("YARA-PLAN-020", "Each instance must occur in exactly one deployment stage.", "spec.topology.deploymentStages"))
			}
			staged[id] = stageIndex
		}
	}
	if len(staged) != len(instances) {
		items = append(items, diagnostics.Error("YARA-PLAN-021", "Deployment stages must include every plan instance.", "spec.topology.deploymentStages"))
	}
	for _, connection := range topology.Connections {
		fromStage, fromExists := staged[connection.From]
		toStage, toExists := staged[connection.To]
		if fromExists && toExists && toStage >= fromStage {
			items = append(items, diagnostics.Error("YARA-PLAN-022", "A connection target must be deployed before its caller.", "spec.topology.deploymentStages"))
		}
	}
	return items
}

func (p PlatformPlan) AssignPlanID() (PlatformPlan, error) {
	p.Metadata.PlanID = ""
	digest, err := canonical.Digest(p)
	if err != nil {
		return PlatformPlan{}, err
	}
	p.Metadata.PlanID = digest
	return p, nil
}
