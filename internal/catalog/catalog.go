// Package catalog loads and validates the small immutable knowledge snapshot
// consumed by the v0 planner. It intentionally models only the first golden
// scenario; breadth is added only with evidence and tests.
package catalog

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

const (
	APIVersion = "yara.dev/v1alpha1"
	Kind       = "CatalogSnapshot"
)

type Snapshot struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}

type Metadata struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}

type Spec struct {
	Candidates []ServingCandidate `json:"candidates" yaml:"candidates"`
}

type ServingCandidate struct {
	ID              string              `json:"id" yaml:"id"`
	RuntimeRef      string              `json:"runtimeRef" yaml:"runtimeRef"`
	ModelRef        string              `json:"modelRef" yaml:"modelRef"`
	Capabilities    []string            `json:"capabilities" yaml:"capabilities"`
	APIContracts    []string            `json:"apiContracts" yaml:"apiContracts"`
	Memory          MemoryModel         `json:"memory" yaml:"memory"`
	Policy          PolicyFacts         `json:"policy" yaml:"policy"`
	PreferenceScore float64             `json:"preferenceScore" yaml:"preferenceScore"`
	Evidence        []EvidenceReference `json:"evidence" yaml:"evidence"`
}

type MemoryModel struct {
	WeightsGiB                     float64 `json:"weightsGiB" yaml:"weightsGiB"`
	RuntimeOverheadGiB             float64 `json:"runtimeOverheadGiB" yaml:"runtimeOverheadGiB"`
	KVCachePerConcurrentRequestGiB float64 `json:"kvCachePerConcurrentRequestGiB" yaml:"kvCachePerConcurrentRequestGiB"`
	HeadroomPercent                float64 `json:"headroomPercent" yaml:"headroomPercent"`
}

type PolicyFacts struct {
	OpenSource       bool `json:"openSource" yaml:"openSource"`
	ExternalEgress   bool `json:"externalEgress" yaml:"externalEgress"`
	Telemetry        bool `json:"telemetry" yaml:"telemetry"`
	ArtifactVerified bool `json:"artifactVerified" yaml:"artifactVerified"`
}

type EvidenceReference struct {
	ID         string `json:"id" yaml:"id"`
	Confidence string `json:"confidence" yaml:"confidence"`
}

func (s Snapshot) Validate() diagnostics.Report {
	var items []diagnostics.Diagnostic
	if s.APIVersion != APIVersion {
		items = append(items, diagnostics.Error("YARA-CAT-001", "Unsupported catalog apiVersion.", "apiVersion"))
	}
	if s.Kind != Kind {
		items = append(items, diagnostics.Error("YARA-CAT-002", "Catalog kind must be CatalogSnapshot.", "kind"))
	}
	if strings.TrimSpace(s.Metadata.Name) == "" || strings.TrimSpace(s.Metadata.Version) == "" {
		items = append(items, diagnostics.Error("YARA-CAT-003", "Catalog name and version are required.", "metadata"))
	}
	if len(s.Spec.Candidates) == 0 {
		items = append(items, diagnostics.Error("YARA-CAT-010", "At least one serving candidate is required.", "spec.candidates"))
	}
	seen := make(map[string]struct{}, len(s.Spec.Candidates))
	for index, candidate := range s.Spec.Candidates {
		base := fmt.Sprintf("spec.candidates[%d]", index)
		if candidate.ID == "" || candidate.RuntimeRef == "" || candidate.ModelRef == "" {
			items = append(items, diagnostics.Error("YARA-CAT-011", "Candidate ID, runtimeRef and modelRef are required.", base))
		}
		if _, exists := seen[candidate.ID]; exists {
			items = append(items, diagnostics.Error("YARA-CAT-012", "Candidate IDs must be unique.", base+".id"))
		}
		seen[candidate.ID] = struct{}{}
		for _, capability := range []string{"chat", "coding"} {
			if !slices.Contains(candidate.Capabilities, capability) {
				items = append(items, diagnostics.Error("YARA-CAT-013", "The first catalog slice requires chat and coding capabilities.", base+".capabilities"))
				break
			}
		}
		if !slices.Contains(candidate.APIContracts, "integration.api.openai-chat/v1") {
			items = append(items, diagnostics.Error("YARA-CAT-014", "Candidate must supply the initial chat API contract.", base+".apiContracts"))
		}
		memory := candidate.Memory
		if memory.WeightsGiB <= 0 || memory.RuntimeOverheadGiB < 0 || memory.KVCachePerConcurrentRequestGiB < 0 || memory.HeadroomPercent < 0 || memory.HeadroomPercent >= 100 {
			items = append(items, diagnostics.Error("YARA-CAT-015", "Candidate memory model contains an invalid value.", base+".memory"))
		}
		if candidate.PreferenceScore < 0 || candidate.PreferenceScore > 1 {
			items = append(items, diagnostics.Error("YARA-CAT-016", "preferenceScore must be between zero and one.", base+".preferenceScore"))
		}
		if len(candidate.Evidence) == 0 {
			items = append(items, diagnostics.Error("YARA-CAT-017", "Candidate requires at least one evidence reference.", base+".evidence"))
		}
		for evidenceIndex, evidence := range candidate.Evidence {
			if evidence.ID == "" || !slices.Contains([]string{"high", "medium", "low"}, evidence.Confidence) {
				path := fmt.Sprintf("%s.evidence[%d]", base, evidenceIndex)
				items = append(items, diagnostics.Error("YARA-CAT-018", "Evidence requires an ID and high, medium or low confidence.", path))
			}
		}
	}
	return diagnostics.NewReport(items...)
}

func (s Snapshot) Digest() (string, error) {
	return canonical.Digest(s)
}
