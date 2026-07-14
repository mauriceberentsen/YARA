package resources

import (
	"fmt"
	"math"

	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type PlatformRequest struct {
	APIVersion string              `json:"apiVersion" yaml:"apiVersion"`
	Kind       string              `json:"kind" yaml:"kind"`
	Metadata   Metadata            `json:"metadata" yaml:"metadata"`
	Spec       PlatformRequestSpec `json:"spec" yaml:"spec"`
}

type PlatformRequestSpec struct {
	UseCases    []UseCase          `json:"useCases" yaml:"useCases"`
	Workload    Workload           `json:"workload" yaml:"workload"`
	Environment RequestEnvironment `json:"environment" yaml:"environment"`
	Policies    RequestPolicies    `json:"policies" yaml:"policies"`
	Objectives  Objectives         `json:"objectives" yaml:"objectives"`
	Preferences Preferences        `json:"preferences,omitempty" yaml:"preferences,omitempty"`
}

type UseCase struct {
	ID       string `json:"id" yaml:"id"`
	Required bool   `json:"required" yaml:"required"`
}

type Workload struct {
	ExpectedUsers          int `json:"expectedUsers" yaml:"expectedUsers"`
	PeakConcurrentRequests int `json:"peakConcurrentRequests" yaml:"peakConcurrentRequests"`
	MaximumContextTokens   int `json:"maximumContextTokens" yaml:"maximumContextTokens"`
}

type RequestEnvironment struct {
	Connectivity string `json:"connectivity" yaml:"connectivity"`
	InventoryRef string `json:"inventoryRef" yaml:"inventoryRef"`
	Lifecycle    string `json:"lifecycle" yaml:"lifecycle"`
}

type RequestPolicies struct {
	OpenSourceOnly       *bool  `json:"openSourceOnly" yaml:"openSourceOnly"`
	ExternalEgress       string `json:"externalEgress" yaml:"externalEgress"`
	Telemetry            string `json:"telemetry" yaml:"telemetry"`
	ArtifactVerification string `json:"artifactVerification" yaml:"artifactVerification"`
}

type Objectives struct {
	Preset  string           `json:"preset" yaml:"preset"`
	Weights ObjectiveWeights `json:"weights" yaml:"weights"`
}

type ObjectiveWeights struct {
	Quality            float64 `json:"quality" yaml:"quality"`
	Latency            float64 `json:"latency" yaml:"latency"`
	Throughput         float64 `json:"throughput" yaml:"throughput"`
	Cost               float64 `json:"cost" yaml:"cost"`
	Simplicity         float64 `json:"simplicity" yaml:"simplicity"`
	Energy             float64 `json:"energy" yaml:"energy"`
	EvidenceConfidence float64 `json:"evidenceConfidence" yaml:"evidenceConfidence"`
}

type Preferences struct {
	DeploymentTarget string `json:"deploymentTarget,omitempty" yaml:"deploymentTarget,omitempty"`
}

func (r PlatformRequest) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "PlatformRequest", "REQ", r.Metadata)

	if len(r.Spec.UseCases) == 0 {
		items = append(items, diagnostics.Error("YARA-REQ-010", "At least one use case is required.", "spec.useCases"))
	}
	seen := make(map[string]struct{}, len(r.Spec.UseCases))
	for i, useCase := range r.Spec.UseCases {
		path := fmt.Sprintf("spec.useCases[%d].id", i)
		if !contains([]string{"chat", "coding"}, useCase.ID) {
			items = append(items, diagnostics.Error("YARA-REQ-011", "v0.1 supports only chat and coding use cases.", path))
		}
		if _, exists := seen[useCase.ID]; exists {
			items = append(items, diagnostics.Error("YARA-REQ-012", "Use case IDs must be unique.", path))
		}
		seen[useCase.ID] = struct{}{}
	}

	workload := r.Spec.Workload
	if workload.ExpectedUsers <= 0 {
		items = append(items, diagnostics.Error("YARA-REQ-020", "expectedUsers must be greater than zero.", "spec.workload.expectedUsers"))
	}
	if workload.PeakConcurrentRequests <= 0 || workload.PeakConcurrentRequests > workload.ExpectedUsers {
		items = append(items, diagnostics.Error("YARA-REQ-021", "peakConcurrentRequests must be positive and no greater than expectedUsers.", "spec.workload.peakConcurrentRequests"))
	}
	if workload.MaximumContextTokens <= 0 {
		items = append(items, diagnostics.Error("YARA-REQ-022", "maximumContextTokens must be greater than zero.", "spec.workload.maximumContextTokens"))
	}

	if !contains([]string{"local", "connected", "air-gapped"}, r.Spec.Environment.Connectivity) {
		items = append(items, diagnostics.Error("YARA-REQ-030", "connectivity must be local, connected or air-gapped.", "spec.environment.connectivity"))
	}
	if r.Spec.Environment.InventoryRef == "" {
		items = append(items, diagnostics.Error("YARA-REQ-031", "inventoryRef is required.", "spec.environment.inventoryRef"))
	}
	if !contains([]string{"evaluation", "production"}, r.Spec.Environment.Lifecycle) {
		items = append(items, diagnostics.Error("YARA-REQ-032", "lifecycle must be evaluation or production.", "spec.environment.lifecycle"))
	}

	if r.Spec.Policies.OpenSourceOnly == nil {
		items = append(items, diagnostics.Error("YARA-REQ-040", "openSourceOnly must be explicitly true or false.", "spec.policies.openSourceOnly"))
	}
	if !contains([]string{"allowed", "forbidden"}, r.Spec.Policies.ExternalEgress) {
		items = append(items, diagnostics.Error("YARA-REQ-041", "externalEgress must be allowed or forbidden.", "spec.policies.externalEgress"))
	}
	if !contains([]string{"allowed", "forbidden"}, r.Spec.Policies.Telemetry) {
		items = append(items, diagnostics.Error("YARA-REQ-042", "telemetry must be allowed or forbidden.", "spec.policies.telemetry"))
	}
	if !contains([]string{"required", "preferred", "disabled"}, r.Spec.Policies.ArtifactVerification) {
		items = append(items, diagnostics.Error("YARA-REQ-043", "artifactVerification must be required, preferred or disabled.", "spec.policies.artifactVerification"))
	}

	weights := r.Spec.Objectives.Weights
	allWeights := []float64{weights.Quality, weights.Latency, weights.Throughput, weights.Cost, weights.Simplicity, weights.Energy, weights.EvidenceConfidence}
	total := 0.0
	for _, weight := range allWeights {
		if weight < 0 || weight > 1 {
			items = append(items, diagnostics.Error("YARA-REQ-050", "Each objective weight must be between zero and one.", "spec.objectives.weights"))
			break
		}
		total += weight
	}
	if math.Abs(total-1.0) > 0.000001 {
		items = append(items, diagnostics.Error("YARA-REQ-051", "Objective weights must sum to one.", "spec.objectives.weights"))
	}
	if !contains([]string{"balanced", "custom"}, r.Spec.Objectives.Preset) {
		items = append(items, diagnostics.Error("YARA-REQ-052", "objectives.preset must be balanced or custom.", "spec.objectives.preset"))
	}

	return diagnostics.NewReport(items...)
}
