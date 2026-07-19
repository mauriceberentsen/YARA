// Package catalog compiles versioned, reviewable manifests into the bounded
// serving candidates consumed by the planner. The planner never hard-codes
// product combinations or reads manifest files directly.
package catalog

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

var (
	sha256ArtifactPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	gitRevisionPattern    = regexp.MustCompile(`^[a-f0-9]{40}$`)
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
	Name        string `json:"name" yaml:"name"`
	Version     string `json:"version" yaml:"version"`
	PublishedAt string `json:"publishedAt" yaml:"publishedAt"`
}

type SnapshotSpec struct {
	Manifests []string `json:"manifests" yaml:"manifests"`
}

type ManifestMetadata struct {
	ID      string   `json:"id" yaml:"id"`
	Version string   `json:"version" yaml:"version"`
	Status  string   `json:"status" yaml:"status"`
	Owners  []string `json:"owners" yaml:"owners"`
}

type ManifestProvenance struct {
	Sources     []ProvenanceSource `json:"sources" yaml:"sources"`
	VerifiedAt  string             `json:"verifiedAt" yaml:"verifiedAt"`
	ReviewAfter string             `json:"reviewAfter" yaml:"reviewAfter"`
	Confidence  string             `json:"confidence" yaml:"confidence"`
}

type ProvenanceSource struct {
	Type string `json:"type" yaml:"type"`
	Ref  string `json:"ref" yaml:"ref"`
}

type CapabilityManifest struct {
	APIVersion string                 `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                 `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata       `json:"metadata" yaml:"metadata"`
	Provenance ManifestProvenance     `json:"provenance" yaml:"provenance"`
	Spec       CapabilityManifestSpec `json:"spec" yaml:"spec"`
}

type CapabilityManifestSpec struct {
	Description string `json:"description" yaml:"description"`
}

type ComponentManifest struct {
	APIVersion string                `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata      `json:"metadata" yaml:"metadata"`
	Provenance ManifestProvenance    `json:"provenance" yaml:"provenance"`
	Spec       ComponentManifestSpec `json:"spec" yaml:"spec"`
}

type ComponentManifestSpec struct {
	Category           string              `json:"category,omitempty" yaml:"category,omitempty"`
	UpstreamVersion    string              `json:"upstreamVersion,omitempty" yaml:"upstreamVersion,omitempty"`
	Homepage           string              `json:"homepage,omitempty" yaml:"homepage,omitempty"`
	License            *LicenseFacts       `json:"license,omitempty" yaml:"license,omitempty"`
	Artifacts          []ArtifactReference `json:"artifacts,omitempty" yaml:"artifacts,omitempty"`
	Health             *HealthContract     `json:"health,omitempty" yaml:"health,omitempty"`
	Roles              []string            `json:"roles" yaml:"roles"`
	Provides           []string            `json:"provides" yaml:"provides"`
	Consumes           []string            `json:"consumes" yaml:"consumes"`
	APIContracts       []string            `json:"apiContracts" yaml:"apiContracts"`
	RuntimeOverheadGiB float64             `json:"runtimeOverheadGiB" yaml:"runtimeOverheadGiB"`
	Policy             ComponentPolicy     `json:"policy" yaml:"policy"`
}

type ArtifactReference struct {
	Type      string         `json:"type" yaml:"type"`
	Ref       string         `json:"ref" yaml:"ref"`
	Digest    string         `json:"digest,omitempty" yaml:"digest,omitempty"`
	Revision  string         `json:"revision,omitempty" yaml:"revision,omitempty"`
	Platforms []string       `json:"platforms,omitempty" yaml:"platforms,omitempty"`
	Files     []ArtifactFile `json:"files,omitempty" yaml:"files,omitempty"`
}

type ArtifactFile struct {
	Path      string `json:"path" yaml:"path"`
	Digest    string `json:"digest" yaml:"digest"`
	SizeBytes int64  `json:"sizeBytes" yaml:"sizeBytes"`
}

type LicenseFacts struct {
	ID             string   `json:"id" yaml:"id"`
	Source         string   `json:"source" yaml:"source"`
	OSIApproved    bool     `json:"osiApproved" yaml:"osiApproved"`
	Redistribution string   `json:"redistribution" yaml:"redistribution"`
	Restrictions   []string `json:"restrictions,omitempty" yaml:"restrictions,omitempty"`
}

type HealthContract struct {
	Protocol string   `json:"protocol" yaml:"protocol"`
	Path     string   `json:"path,omitempty" yaml:"path,omitempty"`
	Port     int      `json:"port,omitempty" yaml:"port,omitempty"`
	Command  []string `json:"command,omitempty" yaml:"command,omitempty"`
}

type ComponentPolicy struct {
	OpenSource       bool `json:"openSource" yaml:"openSource"`
	ExternalEgress   bool `json:"externalEgress" yaml:"externalEgress"`
	Telemetry        bool `json:"telemetry" yaml:"telemetry"`
	ArtifactVerified bool `json:"artifactVerified" yaml:"artifactVerified"`
}

type ModelManifest struct {
	APIVersion string             `json:"apiVersion" yaml:"apiVersion"`
	Kind       string             `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata   `json:"metadata" yaml:"metadata"`
	Provenance ManifestProvenance `json:"provenance" yaml:"provenance"`
	Spec       ModelManifestSpec  `json:"spec" yaml:"spec"`
}

type ModelManifestSpec struct {
	Family                         string             `json:"family,omitempty" yaml:"family,omitempty"`
	Architecture                   string             `json:"architecture,omitempty" yaml:"architecture,omitempty"`
	ParametersB                    float64            `json:"parametersB,omitempty" yaml:"parametersB,omitempty"`
	ContextTokens                  int                `json:"contextTokens,omitempty" yaml:"contextTokens,omitempty"`
	Quantization                   string             `json:"quantization,omitempty" yaml:"quantization,omitempty"`
	Artifact                       *ArtifactReference `json:"artifact,omitempty" yaml:"artifact,omitempty"`
	License                        *LicenseFacts      `json:"license,omitempty" yaml:"license,omitempty"`
	Capabilities                   []string           `json:"capabilities" yaml:"capabilities"`
	WeightsGiB                     float64            `json:"weightsGiB" yaml:"weightsGiB"`
	KVCachePerConcurrentRequestGiB float64            `json:"kvCachePerConcurrentRequestGiB" yaml:"kvCachePerConcurrentRequestGiB"`
	HeadroomPercent                float64            `json:"headroomPercent" yaml:"headroomPercent"`
	OpenSource                     bool               `json:"openSource" yaml:"openSource"`
	PreferenceScore                float64            `json:"preferenceScore" yaml:"preferenceScore"`
}

type HardwareProfileManifest struct {
	APIVersion string                      `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                      `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata            `json:"metadata" yaml:"metadata"`
	Provenance ManifestProvenance          `json:"provenance" yaml:"provenance"`
	Spec       HardwareProfileManifestSpec `json:"spec" yaml:"spec"`
}

type HardwareProfileManifestSpec struct {
	Vendor            string   `json:"vendor" yaml:"vendor"`
	Models            []string `json:"models" yaml:"models"`
	MemoryGiB         int      `json:"memoryGiB,omitempty" yaml:"memoryGiB,omitempty"`
	MemoryKind        string   `json:"memoryKind,omitempty" yaml:"memoryKind,omitempty"`
	Architecture      string   `json:"architecture,omitempty" yaml:"architecture,omitempty"`
	ComputeCapability string   `json:"computeCapability,omitempty" yaml:"computeCapability,omitempty"`
}

type CompatibilityAssertion struct {
	APIVersion string                     `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                     `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata           `json:"metadata" yaml:"metadata"`
	Provenance ManifestProvenance         `json:"provenance" yaml:"provenance"`
	Spec       CompatibilityAssertionSpec `json:"spec" yaml:"spec"`
}

type CompatibilityAssertionSpec struct {
	RuntimeRef         string                   `json:"runtimeRef" yaml:"runtimeRef"`
	ModelRef           string                   `json:"modelRef" yaml:"modelRef"`
	HardwareProfileRef string                   `json:"hardwareProfileRef" yaml:"hardwareProfileRef"`
	Compatibility      string                   `json:"compatibility" yaml:"compatibility"`
	ArtifactVerified   bool                     `json:"artifactVerified" yaml:"artifactVerified"`
	Evidence           []EvidenceReference      `json:"evidence" yaml:"evidence"`
	Conditions         *CompatibilityConditions `json:"conditions,omitempty" yaml:"conditions,omitempty"`
}

type CompatibilityConditions struct {
	RuntimeVersion       string `json:"runtimeVersion,omitempty" yaml:"runtimeVersion,omitempty"`
	ModelRevision        string `json:"modelRevision,omitempty" yaml:"modelRevision,omitempty"`
	MinimumDriverVersion string `json:"minimumDriverVersion,omitempty" yaml:"minimumDriverVersion,omitempty"`
	ComputePlatform      string `json:"computePlatform,omitempty" yaml:"computePlatform,omitempty"`
	MaximumContextTokens int    `json:"maximumContextTokens,omitempty" yaml:"maximumContextTokens,omitempty"`
}

type TopologyTemplateManifest struct {
	APIVersion string                       `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                       `json:"kind" yaml:"kind"`
	Metadata   ManifestMetadata             `json:"metadata" yaml:"metadata"`
	Provenance ManifestProvenance           `json:"provenance" yaml:"provenance"`
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
	Source     string `json:"source,omitempty" yaml:"source,omitempty"`
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
	Conditions         CompatibilityConditions
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

// ManifestDescriptor exposes the immutable governance identity of a compiled
// manifest without leaking the catalog's mutable internal representation.
type ManifestDescriptor struct {
	Kind    string `json:"kind" yaml:"kind"`
	ID      string `json:"id" yaml:"id"`
	Version string `json:"version" yaml:"version"`
	Status  string `json:"status" yaml:"status"`
}

// AssertionDescriptor adds the exact tuple and catalog claim needed to assess
// external contract-test coverage.
type AssertionDescriptor struct {
	ManifestDescriptor `json:",inline" yaml:",inline"`
	RuntimeRef         string `json:"runtimeRef" yaml:"runtimeRef"`
	ModelRef           string `json:"modelRef" yaml:"modelRef"`
	HardwareProfileRef string `json:"hardwareProfileRef" yaml:"hardwareProfileRef"`
	Compatibility      string `json:"compatibility" yaml:"compatibility"`
	ArtifactVerified   bool   `json:"artifactVerified" yaml:"artifactVerified"`
}

type ManifestInventory struct {
	Capabilities  []ManifestDescriptor  `json:"capabilities" yaml:"capabilities"`
	Components    []ManifestDescriptor  `json:"components" yaml:"components"`
	Models        []ManifestDescriptor  `json:"models" yaml:"models"`
	Hardware      []ManifestDescriptor  `json:"hardware" yaml:"hardware"`
	Compatibility []AssertionDescriptor `json:"compatibility" yaml:"compatibility"`
	Topologies    []ManifestDescriptor  `json:"topologies" yaml:"topologies"`
}

func (s Snapshot) ManifestInventory() ManifestInventory {
	inventory := ManifestInventory{
		Capabilities:  make([]ManifestDescriptor, 0, len(s.manifests.Capabilities)),
		Components:    make([]ManifestDescriptor, 0, len(s.manifests.Components)),
		Models:        make([]ManifestDescriptor, 0, len(s.manifests.Models)),
		Hardware:      make([]ManifestDescriptor, 0, len(s.manifests.Hardware)),
		Compatibility: make([]AssertionDescriptor, 0, len(s.manifests.Compatibility)),
		Topologies:    make([]ManifestDescriptor, 0, len(s.manifests.Topologies)),
	}
	descriptor := func(kind string, metadata ManifestMetadata) ManifestDescriptor {
		return ManifestDescriptor{Kind: kind, ID: metadata.ID, Version: metadata.Version, Status: metadata.Status}
	}
	for _, item := range s.manifests.Capabilities {
		inventory.Capabilities = append(inventory.Capabilities, descriptor(item.Kind, item.Metadata))
	}
	for _, item := range s.manifests.Components {
		inventory.Components = append(inventory.Components, descriptor(item.Kind, item.Metadata))
	}
	for _, item := range s.manifests.Models {
		inventory.Models = append(inventory.Models, descriptor(item.Kind, item.Metadata))
	}
	for _, item := range s.manifests.Hardware {
		inventory.Hardware = append(inventory.Hardware, descriptor(item.Kind, item.Metadata))
	}
	for _, item := range s.manifests.Compatibility {
		inventory.Compatibility = append(inventory.Compatibility, AssertionDescriptor{
			ManifestDescriptor: descriptor(item.Kind, item.Metadata),
			RuntimeRef:         item.Spec.RuntimeRef,
			ModelRef:           item.Spec.ModelRef,
			HardwareProfileRef: item.Spec.HardwareProfileRef,
			Compatibility:      item.Spec.Compatibility,
			ArtifactVerified:   item.Spec.ArtifactVerified,
		})
	}
	for _, item := range s.manifests.Topologies {
		inventory.Topologies = append(inventory.Topologies, descriptor(item.Kind, item.Metadata))
	}
	sortDescriptors := func(items []ManifestDescriptor) {
		slices.SortFunc(items, func(left, right ManifestDescriptor) int { return strings.Compare(left.ID, right.ID) })
	}
	sortDescriptors(inventory.Capabilities)
	sortDescriptors(inventory.Components)
	sortDescriptors(inventory.Models)
	sortDescriptors(inventory.Hardware)
	sortDescriptors(inventory.Topologies)
	slices.SortFunc(inventory.Compatibility, func(left, right AssertionDescriptor) int { return strings.Compare(left.ID, right.ID) })
	return inventory
}

// ContractTarget is the immutable catalog projection needed by an external
// compatibility test runner. It intentionally excludes unrelated manifests.
type ContractTarget struct {
	AssertionID               string
	AssertionStatus           string
	RuntimeRef                string
	RuntimeArtifacts          []ArtifactReference
	ModelRef                  string
	ModelArtifact             ArtifactReference
	HardwareProfileID         string
	HardwareVendor            string
	HardwareModels            []string
	HardwareMemoryGiB         int
	HardwareMemoryKind        string
	HardwareComputeCapability string
	Conditions                CompatibilityConditions
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

func (s Snapshot) ContractTarget(assertionID string) (ContractTarget, bool) {
	var assertion *CompatibilityAssertion
	for index := range s.manifests.Compatibility {
		if s.manifests.Compatibility[index].Metadata.ID == assertionID {
			assertion = &s.manifests.Compatibility[index]
			break
		}
	}
	if assertion == nil || assertion.Spec.Compatibility != "supported" || !contractTestableStatus(assertion.Metadata.Status) {
		return ContractTarget{}, false
	}
	var component *ComponentManifest
	for index := range s.manifests.Components {
		if s.manifests.Components[index].Metadata.ID == assertion.Spec.RuntimeRef {
			component = &s.manifests.Components[index]
			break
		}
	}
	var model *ModelManifest
	for index := range s.manifests.Models {
		if s.manifests.Models[index].Metadata.ID == assertion.Spec.ModelRef {
			model = &s.manifests.Models[index]
			break
		}
	}
	var hardware *HardwareProfileManifest
	for index := range s.manifests.Hardware {
		if s.manifests.Hardware[index].Metadata.ID == assertion.Spec.HardwareProfileRef {
			hardware = &s.manifests.Hardware[index]
			break
		}
	}
	if component == nil || model == nil || model.Spec.Artifact == nil || hardware == nil {
		return ContractTarget{}, false
	}
	return ContractTarget{
		AssertionID: assertion.Metadata.ID, AssertionStatus: assertion.Metadata.Status,
		RuntimeRef:        component.Metadata.ID + "@" + component.Metadata.Version,
		RuntimeArtifacts:  cloneArtifacts(component.Spec.Artifacts),
		ModelRef:          model.Metadata.ID + "@" + model.Metadata.Version,
		ModelArtifact:     cloneArtifact(*model.Spec.Artifact),
		HardwareProfileID: hardware.Metadata.ID, HardwareVendor: hardware.Spec.Vendor,
		HardwareModels: slices.Clone(hardware.Spec.Models), HardwareMemoryGiB: hardware.Spec.MemoryGiB,
		HardwareMemoryKind: hardware.Spec.MemoryKind, HardwareComputeCapability: hardware.Spec.ComputeCapability,
		Conditions: compatibilityConditions(assertion.Spec.Conditions),
	}, true
}

func cloneArtifacts(values []ArtifactReference) []ArtifactReference {
	result := make([]ArtifactReference, len(values))
	for index := range values {
		result[index] = cloneArtifact(values[index])
	}
	return result
}

func cloneArtifact(value ArtifactReference) ArtifactReference {
	value.Platforms = slices.Clone(value.Platforms)
	value.Files = slices.Clone(value.Files)
	return value
}

func (s Snapshot) Diagnostics() []diagnostics.Diagnostic {
	items := slices.Clone(s.governanceDiagnostics)
	items = append(items, experimentalManifestDiagnostic(s.manifests)...)
	for index := range items {
		items[index].Paths = slices.Clone(items[index].Paths)
		items[index].Remediation = slices.Clone(items[index].Remediation)
	}
	return items
}

func (s Snapshot) SelectTopology(requiredUseCases []string) (TopologyTemplate, bool) {
	for _, manifest := range s.manifests.Topologies {
		if !selectableStatus(manifest.Metadata.Status) {
			continue
		}
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
		if !selectableStatus(component.Metadata.Status) || !slices.Contains(component.Spec.Roles, role) {
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
	items = append(items, validateManifestSet(s.manifests, s.Metadata.PublishedAt)...)
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
	if strings.TrimSpace(s.Metadata.Name) == "" || strings.TrimSpace(s.Metadata.Version) == "" || strings.TrimSpace(s.Metadata.PublishedAt) == "" {
		items = append(items, diagnostics.Error("YARA-CAT-003", "Catalog name, version and publishedAt are required.", "metadata"))
	} else if _, err := time.Parse(time.RFC3339, s.Metadata.PublishedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-CAT-007", "Catalog publishedAt must be an RFC 3339 timestamp.", "metadata.publishedAt"))
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

func validateManifestSet(set manifestSet, publishedAt string) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	capabilities := make(map[string]CapabilityManifest)
	components := make(map[string]ComponentManifest)
	models := make(map[string]ModelManifest)
	hardware := make(map[string]HardwareProfileManifest)
	assertions := make(map[string]CompatibilityAssertion)
	topologies := make(map[string]TopologyTemplateManifest)
	for _, capability := range set.Capabilities {
		items = append(items, validateManifestGovernance(capability.Metadata, capability.Provenance, publishedAt)...)
		if addManifestID(capabilities, capability.Metadata.ID, capability) {
			items = append(items, diagnostics.Error("YARA-CAT-020", "Duplicate capability ID.", capability.Metadata.ID))
		}
		if capability.APIVersion != APIVersion || capability.Kind != "Capability" || capability.Metadata.ID == "" || capability.Metadata.Version == "" || capability.Spec.Description == "" {
			items = append(items, diagnostics.Error("YARA-CAT-021", "Capability manifest is incomplete.", capability.Metadata.ID))
		}
	}
	for _, component := range set.Components {
		items = append(items, validateManifestGovernance(component.Metadata, component.Provenance, publishedAt)...)
		if addManifestID(components, component.Metadata.ID, component) {
			items = append(items, diagnostics.Error("YARA-CAT-022", "Duplicate component ID.", component.Metadata.ID))
		}
		if component.APIVersion != APIVersion || component.Kind != "Component" || component.Metadata.ID == "" || component.Metadata.Version == "" || len(component.Spec.Roles) == 0 || len(component.Spec.Provides) == 0 || len(component.Spec.APIContracts) == 0 || component.Spec.RuntimeOverheadGiB < 0 {
			items = append(items, diagnostics.Error("YARA-CAT-023", "Component manifest is incomplete.", component.Metadata.ID))
		}
		items = append(items, validateComponentEvidence(component)...)
	}
	for _, model := range set.Models {
		items = append(items, validateManifestGovernance(model.Metadata, model.Provenance, publishedAt)...)
		if addManifestID(models, model.Metadata.ID, model) {
			items = append(items, diagnostics.Error("YARA-CAT-024", "Duplicate model ID.", model.Metadata.ID))
		}
		if model.APIVersion != APIVersion || model.Kind != "Model" || model.Metadata.ID == "" || model.Metadata.Version == "" || len(model.Spec.Capabilities) == 0 || model.Spec.WeightsGiB <= 0 || model.Spec.KVCachePerConcurrentRequestGiB < 0 || model.Spec.HeadroomPercent < 0 || model.Spec.HeadroomPercent >= 100 || model.Spec.PreferenceScore < 0 || model.Spec.PreferenceScore > 1 {
			items = append(items, diagnostics.Error("YARA-CAT-025", "Model manifest contains invalid resource or score data.", model.Metadata.ID))
		}
		items = append(items, validateModelEvidence(model)...)
	}
	for _, profile := range set.Hardware {
		items = append(items, validateManifestGovernance(profile.Metadata, profile.Provenance, publishedAt)...)
		if addManifestID(hardware, profile.Metadata.ID, profile) {
			items = append(items, diagnostics.Error("YARA-CAT-026", "Duplicate hardware profile ID.", profile.Metadata.ID))
		}
		if profile.APIVersion != APIVersion || profile.Kind != "HardwareProfile" || profile.Metadata.ID == "" || profile.Metadata.Version == "" || profile.Spec.Vendor == "" || len(profile.Spec.Models) == 0 {
			items = append(items, diagnostics.Error("YARA-CAT-027", "Hardware profile is incomplete.", profile.Metadata.ID))
		}
		hasHardwareEvidence := profile.Spec.MemoryGiB > 0 || profile.Spec.MemoryKind != "" || profile.Spec.Architecture != "" || profile.Spec.ComputeCapability != ""
		validMemoryKind := profile.Spec.MemoryKind == "dedicated" || profile.Spec.MemoryKind == "coherent-unified"
		if (profile.Metadata.Status == "supported" || hasHardwareEvidence) && (profile.Spec.MemoryGiB <= 0 || !validMemoryKind || profile.Spec.Architecture == "" || profile.Spec.ComputeCapability == "") {
			items = append(items, diagnostics.Error("YARA-CAT-059", "Hardware evidence requires memory amount and kind, architecture and compute capability as one complete set.", profile.Metadata.ID))
		}
	}
	for _, assertion := range set.Compatibility {
		conditions := compatibilityConditions(assertion.Spec.Conditions)
		items = append(items, validateManifestGovernance(assertion.Metadata, assertion.Provenance, publishedAt)...)
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
		hasCompatibilityBounds := conditions.RuntimeVersion != "" || conditions.ModelRevision != "" || conditions.MinimumDriverVersion != "" || conditions.ComputePlatform != "" || conditions.MaximumContextTokens > 0
		if hasCompatibilityBounds {
			for _, evidence := range assertion.Spec.Evidence {
				if strings.TrimSpace(evidence.Source) == "" {
					items = append(items, diagnostics.Error("YARA-CAT-067", "Bounded compatibility evidence requires a traceable source.", assertion.Metadata.ID))
				}
			}
		}
		if assertion.Metadata.Status == "supported" && (!assertion.Spec.ArtifactVerified || conditions.RuntimeVersion == "" || conditions.ModelRevision == "" || conditions.ComputePlatform == "" || conditions.MaximumContextTokens <= 0) {
			items = append(items, diagnostics.Error("YARA-CAT-060", "Supported compatibility requires immutable artifact, version, compute-platform and context bounds.", assertion.Metadata.ID))
		}
		if component, ok := components[assertion.Spec.RuntimeRef]; ok && conditions.RuntimeVersion != "" && conditions.RuntimeVersion != component.Metadata.Version {
			items = append(items, diagnostics.Error("YARA-CAT-061", "Compatibility runtimeVersion does not match the referenced component.", assertion.Metadata.ID))
		}
		if model, ok := models[assertion.Spec.ModelRef]; ok && conditions.ModelRevision != "" {
			if model.Spec.Artifact == nil || conditions.ModelRevision != model.Spec.Artifact.Revision {
				items = append(items, diagnostics.Error("YARA-CAT-062", "Compatibility modelRevision does not match the referenced model artifact.", assertion.Metadata.ID))
			}
		}
		if model, ok := models[assertion.Spec.ModelRef]; ok && conditions.MaximumContextTokens > model.Spec.ContextTokens && model.Spec.ContextTokens > 0 {
			items = append(items, diagnostics.Error("YARA-CAT-069", "Compatibility context bound exceeds the referenced model's recorded context window.", assertion.Metadata.ID))
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
		items = append(items, validateManifestGovernance(topology.Metadata, topology.Provenance, publishedAt)...)
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

func validateComponentEvidence(component ComponentManifest) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	hasRichEvidence := component.Spec.Category != "" || component.Spec.UpstreamVersion != "" || component.Spec.Homepage != "" || len(component.Spec.Artifacts) > 0 || component.Spec.License != nil || component.Spec.Health != nil
	if hasRichEvidence {
		healthValid := component.Spec.Health != nil && ((component.Spec.Health.Protocol == "http" && strings.HasPrefix(component.Spec.Health.Path, "/")) ||
			(component.Spec.Health.Protocol == "tcp" && component.Spec.Health.Port > 0 && component.Spec.Health.Port <= 65535) ||
			(component.Spec.Health.Protocol == "exec" && len(component.Spec.Health.Command) > 0))
		if component.Spec.Category == "" || component.Spec.UpstreamVersion == "" || component.Spec.Homepage == "" || !healthValid {
			items = append(items, diagnostics.Error("YARA-CAT-057", "Component evidence requires category, upstream version, homepage and a valid HTTP, TCP or exec health contract.", component.Metadata.ID))
		}
		if component.Spec.License == nil {
			items = append(items, diagnostics.Error("YARA-CAT-064", "License facts require identity, source and redistribution status.", component.Metadata.ID))
		} else {
			items = append(items, validateLicense(*component.Spec.License, component.Metadata.ID)...)
		}
		for _, artifact := range component.Spec.Artifacts {
			items = append(items, validateArtifact(artifact, component.Metadata.ID)...)
		}
		if len(component.Spec.Artifacts) == 0 {
			items = append(items, diagnostics.Error("YARA-CAT-057", "Component evidence requires at least one immutable artifact.", component.Metadata.ID))
		}
		if component.Spec.License != nil && component.Spec.Policy.OpenSource != component.Spec.License.OSIApproved {
			items = append(items, diagnostics.Error("YARA-CAT-063", "Component open-source policy must match the recorded OSI license fact.", component.Metadata.ID))
		}
		if component.Spec.UpstreamVersion != component.Metadata.Version {
			items = append(items, diagnostics.Error("YARA-CAT-068", "Component metadata version must equal its recorded upstream version.", component.Metadata.ID))
		}
	}
	if component.Metadata.Status == "supported" && !hasRichEvidence {
		items = append(items, diagnostics.Error("YARA-CAT-057", "Supported components require complete release, license, artifact and health evidence.", component.Metadata.ID))
	}
	return items
}

func validateModelEvidence(model ModelManifest) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	hasRichEvidence := model.Spec.Family != "" || model.Spec.Architecture != "" || model.Spec.ParametersB > 0 || model.Spec.ContextTokens > 0 || model.Spec.Quantization != "" || model.Spec.Artifact != nil || model.Spec.License != nil
	if hasRichEvidence {
		if model.Spec.Family == "" || model.Spec.Architecture == "" || model.Spec.ParametersB <= 0 || model.Spec.ContextTokens <= 0 || model.Spec.Quantization == "" {
			items = append(items, diagnostics.Error("YARA-CAT-058", "Model evidence requires family, architecture, parameter count, context and quantization.", model.Metadata.ID))
		}
		if model.Spec.License == nil {
			items = append(items, diagnostics.Error("YARA-CAT-064", "License facts require identity, source and redistribution status.", model.Metadata.ID))
		} else {
			items = append(items, validateLicense(*model.Spec.License, model.Metadata.ID)...)
		}
		if model.Spec.Artifact == nil {
			items = append(items, diagnostics.Error("YARA-CAT-065", "Artifact requires a supported type and non-empty reference.", model.Metadata.ID))
		} else {
			items = append(items, validateArtifact(*model.Spec.Artifact, model.Metadata.ID)...)
		}
		if model.Spec.License != nil && model.Spec.OpenSource != model.Spec.License.OSIApproved {
			items = append(items, diagnostics.Error("YARA-CAT-063", "Model open-source policy must match the recorded OSI license fact.", model.Metadata.ID))
		}
	}
	if model.Metadata.Status == "supported" && !hasRichEvidence {
		items = append(items, diagnostics.Error("YARA-CAT-058", "Supported models require complete artifact, license and resource evidence.", model.Metadata.ID))
	}
	return items
}

func validateLicense(license LicenseFacts, path string) []diagnostics.Diagnostic {
	if license.ID == "" || license.Source == "" || !slices.Contains([]string{"allowed", "allowed-with-conditions", "unknown", "forbidden"}, license.Redistribution) {
		return []diagnostics.Diagnostic{diagnostics.Error("YARA-CAT-064", "License facts require identity, source and redistribution status.", path)}
	}
	return nil
}

func validateArtifact(artifact ArtifactReference, path string) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	if artifact.Ref == "" || !slices.Contains([]string{"oci-image", "huggingface-snapshot"}, artifact.Type) {
		items = append(items, diagnostics.Error("YARA-CAT-065", "Artifact requires a supported type and non-empty reference.", path))
		return items
	}
	switch artifact.Type {
	case "oci-image":
		if !sha256ArtifactPattern.MatchString(artifact.Digest) || len(artifact.Platforms) == 0 {
			items = append(items, diagnostics.Error("YARA-CAT-065", "OCI artifacts require a SHA-256 digest and at least one platform.", path))
		}
	case "huggingface-snapshot":
		if !gitRevisionPattern.MatchString(artifact.Revision) || len(artifact.Files) == 0 {
			items = append(items, diagnostics.Error("YARA-CAT-065", "Model snapshots require an immutable Git revision and verified files.", path))
		}
	}
	for _, file := range artifact.Files {
		if file.Path == "" || !sha256ArtifactPattern.MatchString(file.Digest) || file.SizeBytes <= 0 {
			items = append(items, diagnostics.Error("YARA-CAT-066", "Artifact files require path, SHA-256 digest and positive size.", path))
		}
	}
	return items
}

func compatibilityConditions(conditions *CompatibilityConditions) CompatibilityConditions {
	if conditions == nil {
		return CompatibilityConditions{}
	}
	return *conditions
}

func validateManifestGovernance(metadata ManifestMetadata, provenance ManifestProvenance, publishedAt string) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	path := metadata.ID
	if !slices.Contains([]string{"known", "experimental", "supported", "deprecated", "quarantined"}, metadata.Status) {
		items = append(items, diagnostics.Error("YARA-CAT-050", "Manifest status is not recognized.", path))
	}
	ownersValid := len(metadata.Owners) > 0
	seenOwners := make(map[string]struct{}, len(metadata.Owners))
	for _, owner := range metadata.Owners {
		owner = strings.TrimSpace(owner)
		if owner == "" {
			ownersValid = false
		}
		if _, exists := seenOwners[owner]; exists {
			ownersValid = false
		}
		seenOwners[owner] = struct{}{}
	}
	if !ownersValid {
		items = append(items, diagnostics.Error("YARA-CAT-051", "Manifest requires at least one non-empty, unique owner.", path))
	}
	if len(provenance.Sources) == 0 || !slices.Contains([]string{"high", "medium", "low"}, provenance.Confidence) {
		items = append(items, diagnostics.Error("YARA-CAT-052", "Manifest requires provenance sources and a valid confidence.", path))
	}
	for _, source := range provenance.Sources {
		if strings.TrimSpace(source.Type) == "" || strings.TrimSpace(source.Ref) == "" {
			items = append(items, diagnostics.Error("YARA-CAT-052", "Every provenance source requires a type and reference.", path))
		}
	}
	verifiedAt, verifiedErr := time.Parse(time.RFC3339, provenance.VerifiedAt)
	reviewAfter, reviewErr := time.Parse(time.RFC3339, provenance.ReviewAfter)
	snapshotAt, snapshotErr := time.Parse(time.RFC3339, publishedAt)
	if verifiedErr != nil || reviewErr != nil || !reviewAfter.After(verifiedAt) {
		items = append(items, diagnostics.Error("YARA-CAT-053", "Manifest verification timestamps are invalid or unordered.", path))
	} else if snapshotErr == nil && (verifiedAt.After(snapshotAt) || !reviewAfter.After(snapshotAt)) {
		items = append(items, diagnostics.Error("YARA-CAT-054", "Manifest evidence is not current at the snapshot publication time.", path))
	}
	if metadata.Status == "supported" && provenance.Confidence == "low" {
		items = append(items, diagnostics.Error("YARA-CAT-056", "Supported manifests cannot rely only on low-confidence provenance.", path))
	}
	return items
}

func experimentalManifestDiagnostic(set manifestSet) []diagnostics.Diagnostic {
	ids := make(map[string]struct{})
	add := func(metadata ManifestMetadata) {
		if metadata.Status == "experimental" {
			ids[metadata.ID] = struct{}{}
		}
	}
	for _, item := range set.Capabilities {
		add(item.Metadata)
	}
	for _, item := range set.Components {
		add(item.Metadata)
	}
	for _, item := range set.Models {
		add(item.Metadata)
	}
	for _, item := range set.Hardware {
		add(item.Metadata)
	}
	for _, item := range set.Compatibility {
		add(item.Metadata)
	}
	for _, item := range set.Topologies {
		add(item.Metadata)
	}
	if len(ids) == 0 {
		return nil
	}
	paths := make([]string, 0, len(ids))
	for id := range ids {
		paths = append(paths, id)
	}
	sort.Strings(paths)
	return []diagnostics.Diagnostic{{
		Code: "YARA-CAT-055", Severity: diagnostics.SeverityWarning,
		Message: "The snapshot contains experimental manifests; generated plans require expert review.", Paths: paths,
	}}
}

func selectableStatus(status string) bool {
	return status == "experimental" || status == "supported"
}

func contractTestableStatus(status string) bool {
	return status == "known" || selectableStatus(status)
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
		if assertion.Spec.Compatibility == "supported" && !selectableStatus(assertion.Metadata.Status) {
			continue
		}
		if assertion.Spec.Compatibility == "unsupported" && assertion.Metadata.Status == "quarantined" {
			continue
		}
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
		if !componentOK || !modelOK || !profileOK || !selectableStatus(component.Metadata.Status) || !selectableStatus(model.Metadata.Status) || !selectableStatus(profile.Metadata.Status) {
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
			Conditions:      compatibilityConditions(assertion.Spec.Conditions),
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
