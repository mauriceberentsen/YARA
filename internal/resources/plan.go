package resources

import (
	"regexp"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

var sha256DigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

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
	Topology    PlanTopology             `json:"topology" yaml:"topology"`
	Allocations []PlanAllocation         `json:"allocations" yaml:"allocations"`
	Decisions   []PlanDecision           `json:"decisions" yaml:"decisions"`
	Diagnostics []diagnostics.Diagnostic `json:"diagnostics" yaml:"diagnostics"`
}

type PlanTopology struct {
	Instances        []PlanInstance   `json:"instances" yaml:"instances"`
	Connections      []PlanConnection `json:"connections" yaml:"connections"`
	DeploymentStages [][]string       `json:"deploymentStages" yaml:"deploymentStages"`
}

type PlanInstance struct {
	ID          string `json:"id" yaml:"id"`
	Role        string `json:"role" yaml:"role"`
	RuntimeRef  string `json:"runtimeRef" yaml:"runtimeRef"`
	ModelRef    string `json:"modelRef" yaml:"modelRef"`
	Placement   string `json:"placement" yaml:"placement"`
	APIContract string `json:"apiContract" yaml:"apiContract"`
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
	if len(p.Spec.Topology.Instances) == 0 || len(p.Spec.Decisions) == 0 || len(p.Spec.Allocations) == 0 {
		items = append(items, diagnostics.Error("YARA-PLAN-012", "Plan topology, allocation and decision must be present.", "spec"))
	}
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

func (p PlatformPlan) AssignPlanID() (PlatformPlan, error) {
	p.Metadata.PlanID = ""
	digest, err := canonical.Digest(p)
	if err != nil {
		return PlatformPlan{}, err
	}
	p.Metadata.PlanID = digest
	return p, nil
}
