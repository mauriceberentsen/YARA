// Package catalog compiles versioned, reviewable manifests into the bounded
// serving candidates consumed by the planner. The planner never hard-codes
// product combinations or reads manifest files directly.
package catalog

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

const (
	APIVersion = "yara.dev/v1alpha1"
	Kind       = "CatalogSnapshot"
)

type Snapshot struct {
	APIVersion string           `json:"apiVersion" yaml:"apiVersion"`
	Kind       string           `json:"kind" yaml:"kind"`
	Metadata   SnapshotMetadata `json:"metadata" yaml:"metadata"`
	Spec       SnapshotSpec     `json:"spec" yaml:"spec"`
	manifests  manifestSet
	candidates []ServingCandidate
}

type SnapshotMetadata struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}

type SnapshotSpec struct {
	Manifests []string `json:"manifests" yaml:"manifests"`
}

type ManifestMetadata struct {
	ID      string `json:"id" yaml:"id"`
	Version string `json:"version" yaml:"version"`
}

type CapabilityManifest struct {
	APIVersion string                 `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                 `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata       `json:"metadata" yaml:"metadata"`
	Spec       CapabilityManifestSpec `json:"spec" yaml:"spec"`
}

type CapabilityManifestSpec struct {
	Description string `json:"description" yaml:"description"`
}

type ComponentManifest struct {
	APIVersion string                `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata      `json:"metadata" yaml:"metadata"`
	Spec       ComponentManifestSpec `json:"spec" yaml:"spec"`
}

type ComponentManifestSpec struct {
	Provides           []string        `json:"provides" yaml:"provides"`
	APIContracts       []string        `json:"apiContracts" yaml:"apiContracts"`
	RuntimeOverheadGiB float64         `json:"runtimeOverheadGiB" yaml:"runtimeOverheadGiB"`
	Policy             ComponentPolicy `json:"policy" yaml:"policy"`
}

type ComponentPolicy struct {
	OpenSource     bool `json:"openSource" yaml:"openSource"`
	ExternalEgress bool `json:"externalEgress" yaml:"externalEgress"`
	Telemetry      bool `json:"telemetry" yaml:"telemetry"`
}

type ModelManifest struct {
	APIVersion string            `json:"apiVersion" yaml:"apiVersion"`
	Kind       string            `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata  `json:"metadata" yaml:"metadata"`
	Spec       ModelManifestSpec `json:"spec" yaml:"spec"`
}

type ModelManifestSpec struct {
	Capabilities                   []string `json:"capabilities" yaml:"capabilities"`
	WeightsGiB                     float64  `json:"weightsGiB" yaml:"weightsGiB"`
	KVCachePerConcurrentRequestGiB float64  `json:"kvCachePerConcurrentRequestGiB" yaml:"kvCachePerConcurrentRequestGiB"`
	HeadroomPercent                float64  `json:"headroomPercent" yaml:"headroomPercent"`
	OpenSource                     bool     `json:"openSource" yaml:"openSource"`
	PreferenceScore                float64  `json:"preferenceScore" yaml:"preferenceScore"`
}

type HardwareProfileManifest struct {
	APIVersion string                      `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                      `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata            `json:"metadata" yaml:"metadata"`
	Spec       HardwareProfileManifestSpec `json:"spec" yaml:"spec"`
}

type HardwareProfileManifestSpec struct {
	Vendor string   `json:"vendor" yaml:"vendor"`
	Models []string `json:"models" yaml:"models"`
}

type CompatibilityAssertion struct {
	APIVersion string                     `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                     `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata           `json:"metadata" yaml:"metadata"`
	Spec       CompatibilityAssertionSpec `json:"spec" yaml:"spec"`
}

type CompatibilityAssertionSpec struct {
	RuntimeRef         string              `json:"runtimeRef" yaml:"runtimeRef"`
	ModelRef           string              `json:"modelRef" yaml:"modelRef"`
	HardwareProfileRef string              `json:"hardwareProfileRef" yaml:"hardwareProfileRef"`
	Supported          bool                `json:"supported" yaml:"supported"`
	ArtifactVerified   bool                `json:"artifactVerified" yaml:"artifactVerified"`
	Evidence           []EvidenceReference `json:"evidence" yaml:"evidence"`
}

type EvidenceReference struct {
	ID         string `json:"id" yaml:"id"`
	Confidence string `json:"confidence" yaml:"confidence"`
}

type manifestSet struct {
	Capabilities  []CapabilityManifest      `json:"capabilities"`
	Components    []ComponentManifest       `json:"components"`
	Models        []ModelManifest           `json:"models"`
	Hardware      []HardwareProfileManifest `json:"hardware"`
	Compatibility []CompatibilityAssertion  `json:"compatibility"`
}

type ServingCandidate struct {
	ID                 string
	RuntimeRef         string
	ModelRef           string
	HardwareProfileRef string
	HardwareVendor     string
	HardwareModels     []string
	Capabilities       []string
	APIContracts       []string
	Memory             MemoryModel
	Policy             PolicyFacts
	PreferenceScore    float64
	Evidence           []EvidenceReference
}

type MemoryModel struct {
	WeightsGiB                     float64
	RuntimeOverheadGiB             float64
	KVCachePerConcurrentRequestGiB float64
	HeadroomPercent                float64
}

type PolicyFacts struct {
	OpenSource       bool
	ExternalEgress   bool
	Telemetry        bool
	ArtifactVerified bool
}

func (s Snapshot) Candidates() []ServingCandidate {
	candidates := slices.Clone(s.candidates)
	for index := range candidates {
		candidates[index].HardwareModels = slices.Clone(candidates[index].HardwareModels)
		candidates[index].Capabilities = slices.Clone(candidates[index].Capabilities)
		candidates[index].APIContracts = slices.Clone(candidates[index].APIContracts)
		candidates[index].Evidence = slices.Clone(candidates[index].Evidence)
	}
	return candidates
}

func (s Snapshot) Validate() diagnostics.Report {
	items := validateIndex(s)
	if len(s.manifests.Capabilities) == 0 || len(s.manifests.Components) == 0 || len(s.manifests.Models) == 0 || len(s.manifests.Hardware) == 0 || len(s.manifests.Compatibility) == 0 {
		items = append(items, diagnostics.Error("YARA-CAT-010", "Snapshot must compile capability, component, model, hardware and compatibility manifests.", "spec.manifests"))
	}
	items = append(items, validateManifestSet(s.manifests)...)
	if len(s.candidates) == 0 {
		items = append(items, diagnostics.Error("YARA-CAT-011", "No supported serving candidates could be compiled.", "spec.manifests"))
	}
	return diagnostics.NewReport(items...)
}

func validateIndex(s Snapshot) []diagnostics.Diagnostic {
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
	if len(s.Spec.Manifests) == 0 {
		items = append(items, diagnostics.Error("YARA-CAT-004", "Snapshot must reference at least one manifest.", "spec.manifests"))
	}
	seen := make(map[string]struct{}, len(s.Spec.Manifests))
	for index, reference := range s.Spec.Manifests {
		if strings.TrimSpace(reference) == "" {
			items = append(items, diagnostics.Error("YARA-CAT-005", "Manifest reference cannot be empty.", fmt.Sprintf("spec.manifests[%d]", index)))
		}
		if _, exists := seen[reference]; exists {
			items = append(items, diagnostics.Error("YARA-CAT-006", "Manifest references must be unique.", fmt.Sprintf("spec.manifests[%d]", index)))
		}
		seen[reference] = struct{}{}
	}
	return items
}

func validateManifestSet(set manifestSet) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	capabilities := make(map[string]CapabilityManifest)
	components := make(map[string]ComponentManifest)
	models := make(map[string]ModelManifest)
	hardware := make(map[string]HardwareProfileManifest)
	assertions := make(map[string]CompatibilityAssertion)
	for _, capability := range set.Capabilities {
		if addManifestID(capabilities, capability.Metadata.ID, capability) {
			items = append(items, diagnostics.Error("YARA-CAT-020", "Duplicate capability ID.", capability.Metadata.ID))
		}
		if capability.APIVersion != APIVersion || capability.Kind != "Capability" || capability.Metadata.ID == "" || capability.Metadata.Version == "" || capability.Spec.Description == "" {
			items = append(items, diagnostics.Error("YARA-CAT-021", "Capability manifest is incomplete.", capability.Metadata.ID))
		}
	}
	for _, component := range set.Components {
		if addManifestID(components, component.Metadata.ID, component) {
			items = append(items, diagnostics.Error("YARA-CAT-022", "Duplicate component ID.", component.Metadata.ID))
		}
		if component.APIVersion != APIVersion || component.Kind != "Component" || component.Metadata.ID == "" || component.Metadata.Version == "" || len(component.Spec.Provides) == 0 || len(component.Spec.APIContracts) == 0 || component.Spec.RuntimeOverheadGiB < 0 {
			items = append(items, diagnostics.Error("YARA-CAT-023", "Component manifest is incomplete.", component.Metadata.ID))
		}
	}
	for _, model := range set.Models {
		if addManifestID(models, model.Metadata.ID, model) {
			items = append(items, diagnostics.Error("YARA-CAT-024", "Duplicate model ID.", model.Metadata.ID))
		}
		if model.APIVersion != APIVersion || model.Kind != "Model" || model.Metadata.ID == "" || model.Metadata.Version == "" || len(model.Spec.Capabilities) == 0 || model.Spec.WeightsGiB <= 0 || model.Spec.KVCachePerConcurrentRequestGiB < 0 || model.Spec.HeadroomPercent < 0 || model.Spec.HeadroomPercent >= 100 || model.Spec.PreferenceScore < 0 || model.Spec.PreferenceScore > 1 {
			items = append(items, diagnostics.Error("YARA-CAT-025", "Model manifest contains invalid resource or score data.", model.Metadata.ID))
		}
	}
	for _, profile := range set.Hardware {
		if addManifestID(hardware, profile.Metadata.ID, profile) {
			items = append(items, diagnostics.Error("YARA-CAT-026", "Duplicate hardware profile ID.", profile.Metadata.ID))
		}
		if profile.APIVersion != APIVersion || profile.Kind != "HardwareProfile" || profile.Metadata.ID == "" || profile.Metadata.Version == "" || profile.Spec.Vendor == "" || len(profile.Spec.Models) == 0 {
			items = append(items, diagnostics.Error("YARA-CAT-027", "Hardware profile is incomplete.", profile.Metadata.ID))
		}
	}
	for _, assertion := range set.Compatibility {
		if addManifestID(assertions, assertion.Metadata.ID, assertion) {
			items = append(items, diagnostics.Error("YARA-CAT-036", "Duplicate compatibility assertion ID.", assertion.Metadata.ID))
		}
		if assertion.APIVersion != APIVersion || assertion.Kind != "CompatibilityAssertion" || assertion.Metadata.ID == "" || assertion.Metadata.Version == "" {
			items = append(items, diagnostics.Error("YARA-CAT-028", "Compatibility assertion envelope is incomplete.", assertion.Metadata.ID))
		}
		if _, ok := components[assertion.Spec.RuntimeRef]; !ok {
			items = append(items, diagnostics.Error("YARA-CAT-029", "Compatibility assertion references an unknown component.", assertion.Metadata.ID))
		}
		if _, ok := models[assertion.Spec.ModelRef]; !ok {
			items = append(items, diagnostics.Error("YARA-CAT-030", "Compatibility assertion references an unknown model.", assertion.Metadata.ID))
		}
		if _, ok := hardware[assertion.Spec.HardwareProfileRef]; !ok {
			items = append(items, diagnostics.Error("YARA-CAT-031", "Compatibility assertion references an unknown hardware profile.", assertion.Metadata.ID))
		}
		if len(assertion.Spec.Evidence) == 0 {
			items = append(items, diagnostics.Error("YARA-CAT-032", "Compatibility assertion requires evidence.", assertion.Metadata.ID))
		}
		for _, evidence := range assertion.Spec.Evidence {
			if evidence.ID == "" || !slices.Contains([]string{"high", "medium", "low"}, evidence.Confidence) {
				items = append(items, diagnostics.Error("YARA-CAT-033", "Evidence requires an ID and valid confidence.", assertion.Metadata.ID))
			}
		}
	}
	for _, component := range set.Components {
		for _, capability := range append(slices.Clone(component.Spec.Provides), component.Spec.APIContracts...) {
			if _, ok := capabilities[capability]; !ok {
				items = append(items, diagnostics.Error("YARA-CAT-034", "Component references an unknown capability contract.", component.Metadata.ID))
			}
		}
	}
	for _, model := range set.Models {
		for _, capability := range model.Spec.Capabilities {
			if _, ok := capabilities[capability]; !ok {
				items = append(items, diagnostics.Error("YARA-CAT-035", "Model references an unknown capability.", model.Metadata.ID))
			}
		}
	}
	return items
}

func addManifestID[T any](values map[string]T, id string, value T) bool {
	_, exists := values[id]
	values[id] = value
	return exists
}

func compileCandidates(set manifestSet) []ServingCandidate {
	components := make(map[string]ComponentManifest, len(set.Components))
	models := make(map[string]ModelManifest, len(set.Models))
	hardware := make(map[string]HardwareProfileManifest, len(set.Hardware))
	for _, item := range set.Components {
		components[item.Metadata.ID] = item
	}
	for _, item := range set.Models {
		models[item.Metadata.ID] = item
	}
	for _, item := range set.Hardware {
		hardware[item.Metadata.ID] = item
	}
	candidates := make([]ServingCandidate, 0, len(set.Compatibility))
	for _, assertion := range set.Compatibility {
		if !assertion.Spec.Supported {
			continue
		}
		component, componentOK := components[assertion.Spec.RuntimeRef]
		model, modelOK := models[assertion.Spec.ModelRef]
		profile, profileOK := hardware[assertion.Spec.HardwareProfileRef]
		if !componentOK || !modelOK || !profileOK {
			continue
		}
		candidate := ServingCandidate{
			ID:                 assertion.Metadata.ID,
			RuntimeRef:         component.Metadata.ID + "@" + component.Metadata.Version,
			ModelRef:           model.Metadata.ID + "@" + model.Metadata.Version,
			HardwareProfileRef: profile.Metadata.ID,
			HardwareVendor:     profile.Spec.Vendor,
			HardwareModels:     slices.Clone(profile.Spec.Models),
			Capabilities:       slices.Clone(model.Spec.Capabilities),
			APIContracts:       slices.Clone(component.Spec.APIContracts),
			Memory: MemoryModel{
				WeightsGiB:                     model.Spec.WeightsGiB,
				RuntimeOverheadGiB:             component.Spec.RuntimeOverheadGiB,
				KVCachePerConcurrentRequestGiB: model.Spec.KVCachePerConcurrentRequestGiB,
				HeadroomPercent:                model.Spec.HeadroomPercent,
			},
			Policy: PolicyFacts{
				OpenSource:       component.Spec.Policy.OpenSource && model.Spec.OpenSource,
				ExternalEgress:   component.Spec.Policy.ExternalEgress,
				Telemetry:        component.Spec.Policy.Telemetry,
				ArtifactVerified: assertion.Spec.ArtifactVerified,
			},
			PreferenceScore: model.Spec.PreferenceScore,
			Evidence:        slices.Clone(assertion.Spec.Evidence),
		}
		sort.Strings(candidate.Capabilities)
		sort.Strings(candidate.APIContracts)
		sort.Strings(candidate.HardwareModels)
		sort.SliceStable(candidate.Evidence, func(i, j int) bool { return candidate.Evidence[i].ID < candidate.Evidence[j].ID })
		candidates = append(candidates, candidate)
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	return candidates
}

func (s Snapshot) Digest() (string, error) {
	material := struct {
		APIVersion string           `json:"apiVersion"`
		Kind       string           `json:"kind"`
		Metadata   SnapshotMetadata `json:"metadata"`
		Spec       SnapshotSpec     `json:"spec"`
		Manifests  manifestSet      `json:"compiledManifests"`
	}{s.APIVersion, s.Kind, s.Metadata, s.Spec, s.manifests}
	return canonical.Digest(material)
}
