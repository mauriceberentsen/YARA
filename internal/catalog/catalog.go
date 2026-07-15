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
	APIVersion            string           `json:"apiVersion" yaml:"apiVersion"`
	Kind                  string           `json:"kind" yaml:"kind"`
	Metadata              SnapshotMetadata `json:"metadata" yaml:"metadata"`
	Spec                  SnapshotSpec     `json:"spec" yaml:"spec"`
	manifests             manifestSet
	candidates            []ServingCandidate
	governanceDiagnostics []diagnostics.Diagnostic
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
	Roles              []string        `json:"roles" yaml:"roles"`
	Provides           []string        `json:"provides" yaml:"provides"`
	Consumes           []string        `json:"consumes" yaml:"consumes"`
	APIContracts       []string        `json:"apiContracts" yaml:"apiContracts"`
	RuntimeOverheadGiB float64         `json:"runtimeOverheadGiB" yaml:"runtimeOverheadGiB"`
	Policy             ComponentPolicy `json:"policy" yaml:"policy"`
}

type ComponentPolicy struct {
	OpenSource       bool `json:"openSource" yaml:"openSource"`
	ExternalEgress   bool `json:"externalEgress" yaml:"externalEgress"`
	Telemetry        bool `json:"telemetry" yaml:"telemetry"`
	ArtifactVerified bool `json:"artifactVerified" yaml:"artifactVerified"`
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
	Compatibility      string              `json:"compatibility" yaml:"compatibility"`
	ArtifactVerified   bool                `json:"artifactVerified" yaml:"artifactVerified"`
	Evidence           []EvidenceReference `json:"evidence" yaml:"evidence"`
}

type TopologyTemplateManifest struct {
	APIVersion string                       `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                       `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata             `json:"metadata" yaml:"metadata"`
	Spec       TopologyTemplateManifestSpec `json:"spec" yaml:"spec"`
}

type TopologyTemplateManifestSpec struct {
	SatisfiesUseCases []string             `json:"satisfiesUseCases" yaml:"satisfiesUseCases"`
	Roles             []TopologyRole       `json:"roles" yaml:"roles"`
	Connections       []TopologyConnection `json:"connections" yaml:"connections"`
}

type TopologyRole struct {
	ID                  string `json:"id" yaml:"id"`
	Role                string `json:"role" yaml:"role"`
	RequiresAccelerator bool   `json:"requiresAccelerator" yaml:"requiresAccelerator"`
}

type TopologyConnection struct {
	From     string `json:"from" yaml:"from"`
	To       string `json:"to" yaml:"to"`
	Contract string `json:"contract" yaml:"contract"`
}

type TopologyTemplate struct {
	ID                string
	SatisfiesUseCases []string
	Roles             []TopologyRole
	Connections       []TopologyConnection
	DeploymentStages  [][]string
}

type ComponentCandidate struct {
	ID           string
	ComponentRef string
	Roles        []string
	APIContracts []string
	Policy       PolicyFacts
}

type EvidenceReference struct {
	ID         string `json:"id" yaml:"id"`
	Confidence string `json:"confidence" yaml:"confidence"`
}

type manifestSet struct {
	Capabilities  []CapabilityManifest       `json:"capabilities"`
	Components    []ComponentManifest        `json:"components"`
	Models        []ModelManifest            `json:"models"`
	Hardware      []HardwareProfileManifest  `json:"hardware"`
	Compatibility []CompatibilityAssertion   `json:"compatibility"`
	Topologies    []TopologyTemplateManifest `json:"topologies"`
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

func (s Snapshot) Diagnostics() []diagnostics.Diagnostic {
	items := slices.Clone(s.governanceDiagnostics)
	for index := range items {
		items[index].Paths = slices.Clone(items[index].Paths)
		items[index].Remediation = slices.Clone(items[index].Remediation)
	}
	return items
}

func (s Snapshot) SelectTopology(requiredUseCases []string) (TopologyTemplate, bool) {
	for _, manifest := range s.manifests.Topologies {
		if !isSubset(requiredUseCases, manifest.Spec.SatisfiesUseCases) {
			continue
		}
		stages, ok := topologyStages(manifest.Spec.Roles, manifest.Spec.Connections)
		if !ok {
			continue
		}
		return TopologyTemplate{
			ID: manifest.Metadata.ID, SatisfiesUseCases: slices.Clone(manifest.Spec.SatisfiesUseCases),
			Roles: slices.Clone(manifest.Spec.Roles), Connections: slices.Clone(manifest.Spec.Connections),
			DeploymentStages: stages,
		}, true
	}
	return TopologyTemplate{}, false
}

func (s Snapshot) ComponentsForRole(role string) []ComponentCandidate {
	var candidates []ComponentCandidate
	for _, component := range s.manifests.Components {
		if !slices.Contains(component.Spec.Roles, role) {
			continue
		}
		candidates = append(candidates, ComponentCandidate{
			ID: component.Metadata.ID, ComponentRef: component.Metadata.ID + "@" + component.Metadata.Version,
			Roles: slices.Clone(component.Spec.Roles), APIContracts: slices.Clone(component.Spec.APIContracts),
			Policy: PolicyFacts{OpenSource: component.Spec.Policy.OpenSource, ExternalEgress: component.Spec.Policy.ExternalEgress, Telemetry: component.Spec.Policy.Telemetry, ArtifactVerified: component.Spec.Policy.ArtifactVerified},
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	return candidates
}

func (s Snapshot) Validate() diagnostics.Report {
	items := validateIndex(s)
	if len(s.manifests.Capabilities) == 0 || len(s.manifests.Components) == 0 || len(s.manifests.Models) == 0 || len(s.manifests.Hardware) == 0 || len(s.manifests.Compatibility) == 0 || len(s.manifests.Topologies) == 0 {
		items = append(items, diagnostics.Error("YARA-CAT-010", "Snapshot must compile capability, component, model, hardware, compatibility and topology manifests.", "spec.manifests"))
	}
	items = append(items, validateManifestSet(s.manifests)...)
	items = append(items, s.Diagnostics()...)
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
	topologies := make(map[string]TopologyTemplateManifest)
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
		if component.APIVersion != APIVersion || component.Kind != "Component" || component.Metadata.ID == "" || component.Metadata.Version == "" || len(component.Spec.Roles) == 0 || len(component.Spec.Provides) == 0 || len(component.Spec.APIContracts) == 0 || component.Spec.RuntimeOverheadGiB < 0 {
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
		if !slices.Contains([]string{"supported", "unsupported"}, assertion.Spec.Compatibility) {
			items = append(items, diagnostics.Error("YARA-CAT-038", "Compatibility must be supported or unsupported.", assertion.Metadata.ID))
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
		references := append(slices.Clone(component.Spec.Provides), component.Spec.Consumes...)
		references = append(references, component.Spec.APIContracts...)
		for _, capability := range references {
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
	for _, topology := range set.Topologies {
		if addManifestID(topologies, topology.Metadata.ID, topology) {
			items = append(items, diagnostics.Error("YARA-CAT-041", "Duplicate topology template ID.", topology.Metadata.ID))
		}
		if topology.APIVersion != APIVersion || topology.Kind != "TopologyTemplate" || topology.Metadata.ID == "" || topology.Metadata.Version == "" || len(topology.Spec.SatisfiesUseCases) == 0 || len(topology.Spec.Roles) < 2 {
			items = append(items, diagnostics.Error("YARA-CAT-042", "Topology template is incomplete.", topology.Metadata.ID))
		}
		roleIDs := make(map[string]struct{}, len(topology.Spec.Roles))
		participation := make(map[string]int, len(topology.Spec.Roles))
		acceleratorRoles := 0
		for _, role := range topology.Spec.Roles {
			if role.ID == "" || role.Role == "" {
				items = append(items, diagnostics.Error("YARA-CAT-043", "Topology roles require an ID and abstract role.", topology.Metadata.ID))
			}
			if _, exists := roleIDs[role.ID]; exists {
				items = append(items, diagnostics.Error("YARA-CAT-044", "Topology role IDs must be unique.", topology.Metadata.ID))
			}
			roleIDs[role.ID] = struct{}{}
			if role.RequiresAccelerator {
				acceleratorRoles++
			}
		}
		for _, useCase := range topology.Spec.SatisfiesUseCases {
			if _, exists := capabilities[useCase]; !exists {
				items = append(items, diagnostics.Error("YARA-CAT-045", "Topology references an unknown required use case.", topology.Metadata.ID))
			}
		}
		for _, connection := range topology.Spec.Connections {
			_, fromExists := roleIDs[connection.From]
			_, toExists := roleIDs[connection.To]
			_, contractExists := capabilities[connection.Contract]
			if !fromExists || !toExists || connection.From == connection.To || !contractExists {
				items = append(items, diagnostics.Error("YARA-CAT-046", "Topology connection has invalid endpoints or contract.", topology.Metadata.ID))
			}
			participation[connection.From]++
			participation[connection.To]++
		}
		for roleID := range roleIDs {
			if participation[roleID] == 0 {
				items = append(items, diagnostics.Error("YARA-CAT-048", "Every topology role must participate in at least one connection.", topology.Metadata.ID))
			}
		}
		if acceleratorRoles != 1 {
			items = append(items, diagnostics.Error("YARA-CAT-049", "The v0.1 topology slice requires exactly one accelerator role.", topology.Metadata.ID))
		}
		if _, ok := topologyStages(topology.Spec.Roles, topology.Spec.Connections); !ok {
			items = append(items, diagnostics.Error("YARA-CAT-047", "Topology dependency graph contains a cycle.", topology.Metadata.ID))
		}
	}
	return items
}

func isSubset(required, available []string) bool {
	for _, value := range required {
		if !slices.Contains(available, value) {
			return false
		}
	}
	return true
}

func topologyStages(roles []TopologyRole, connections []TopologyConnection) ([][]string, bool) {
	remaining := make(map[string]struct{}, len(roles))
	dependencies := make(map[string]map[string]struct{}, len(roles))
	for _, role := range roles {
		remaining[role.ID] = struct{}{}
		dependencies[role.ID] = make(map[string]struct{})
	}
	for _, connection := range connections {
		if _, exists := dependencies[connection.From]; exists {
			dependencies[connection.From][connection.To] = struct{}{}
		}
	}
	var stages [][]string
	for len(remaining) > 0 {
		var stage []string
		for id := range remaining {
			ready := true
			for dependency := range dependencies[id] {
				if _, exists := remaining[dependency]; exists {
					ready = false
					break
				}
			}
			if ready {
				stage = append(stage, id)
			}
		}
		if len(stage) == 0 {
			return nil, false
		}
		sort.Strings(stage)
		stages = append(stages, stage)
		for _, id := range stage {
			delete(remaining, id)
		}
	}
	return stages, true
}

func addManifestID[T any](values map[string]T, id string, value T) bool {
	_, exists := values[id]
	values[id] = value
	return exists
}

type compatibilityKey struct {
	RuntimeRef         string
	ModelRef           string
	HardwareProfileRef string
}

func compileCandidates(set manifestSet) ([]ServingCandidate, []diagnostics.Diagnostic) {
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
	groups := make(map[compatibilityKey][]CompatibilityAssertion, len(set.Compatibility))
	for _, assertion := range set.Compatibility {
		key := compatibilityKey{
			RuntimeRef: assertion.Spec.RuntimeRef, ModelRef: assertion.Spec.ModelRef,
			HardwareProfileRef: assertion.Spec.HardwareProfileRef,
		}
		groups[key] = append(groups[key], assertion)
	}
	keys := make([]compatibilityKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		left := keys[i].RuntimeRef + "\x00" + keys[i].ModelRef + "\x00" + keys[i].HardwareProfileRef
		right := keys[j].RuntimeRef + "\x00" + keys[j].ModelRef + "\x00" + keys[j].HardwareProfileRef
		return left < right
	})

	candidates := make([]ServingCandidate, 0, len(set.Compatibility))
	var governanceDiagnostics []diagnostics.Diagnostic
	for _, key := range keys {
		assertions := groups[key]
		var supported, unsupported []CompatibilityAssertion
		for _, assertion := range assertions {
			switch assertion.Spec.Compatibility {
			case "supported":
				supported = append(supported, assertion)
			case "unsupported":
				unsupported = append(unsupported, assertion)
			}
		}
		if len(supported) > 1 {
			governanceDiagnostics = append(governanceDiagnostics, diagnostics.Error(
				"YARA-CAT-039", "Multiple positive compatibility assertions describe the same runtime, model and hardware combination.", assertionIDs(supported)...,
			))
		}
		if len(unsupported) > 0 {
			if len(supported) > 0 {
				ids := assertionIDs(append(slices.Clone(supported), unsupported...))
				governanceDiagnostics = append(governanceDiagnostics, diagnostics.Diagnostic{
					Code: "YARA-CAT-040", Severity: diagnostics.SeverityWarning,
					Message:     "Conflicting compatibility assertions quarantined this runtime, model and hardware combination.",
					Paths:       ids,
					Remediation: []string{"Review the cited assertions and publish a new catalog snapshot with the conflict resolved."},
				})
			}
			continue
		}
		if len(supported) > 1 {
			continue
		}
		if len(supported) == 0 {
			continue
		}
		assertion := supported[0]
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
				ArtifactVerified: assertion.Spec.ArtifactVerified && component.Spec.Policy.ArtifactVerified,
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
	return candidates, governanceDiagnostics
}

func assertionIDs(assertions []CompatibilityAssertion) []string {
	ids := make([]string, 0, len(assertions))
	for _, assertion := range assertions {
		ids = append(ids, assertion.Metadata.ID)
	}
	sort.Strings(ids)
	return ids
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
