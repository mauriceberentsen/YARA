package resources

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// OfflineAcquisitionManifest is the immutable hand-off between rendering and
// an external acquisition/import workflow. It describes what must be copied;
// it does not authorize network access or target mutation.
type OfflineAcquisitionManifest struct {
	APIVersion string                             `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                             `json:"kind" yaml:"kind"`
	Metadata   OfflineAcquisitionManifestMetadata `json:"metadata" yaml:"metadata"`
	Spec       OfflineAcquisitionManifestSpec     `json:"spec" yaml:"spec"`
}

type OfflineAcquisitionManifestMetadata struct {
	Name       string `json:"name" yaml:"name"`
	ManifestID string `json:"manifestId" yaml:"manifestId"`
}

type OfflineAcquisitionManifestSpec struct {
	PlanID        string                       `json:"planId" yaml:"planId"`
	CatalogDigest string                       `json:"catalogDigest" yaml:"catalogDigest"`
	GeneratedBy   BundleRenderer               `json:"generatedBy" yaml:"generatedBy"`
	Artifacts     []OfflineAcquisitionArtifact `json:"artifacts" yaml:"artifacts"`
	Policy        OfflineAcquisitionPolicy     `json:"policy" yaml:"policy"`
}

type OfflineAcquisitionArtifact struct {
	Type          string               `json:"type" yaml:"type"`
	Ref           string               `json:"ref" yaml:"ref"`
	Method        string               `json:"method" yaml:"method"`
	Digest        string               `json:"digest,omitempty" yaml:"digest,omitempty"`
	Revision      string               `json:"revision,omitempty" yaml:"revision,omitempty"`
	Platforms     []string             `json:"platforms,omitempty" yaml:"platforms,omitempty"`
	Files         []BundleArtifactFile `json:"files,omitempty" yaml:"files,omitempty"`
	LicenseID     string               `json:"licenseId" yaml:"licenseId"`
	LicenseSource string               `json:"licenseSource" yaml:"licenseSource"`
}

type OfflineAcquisitionPolicy struct {
	NetworkRequiredDuringAcquisition bool `json:"networkRequiredDuringAcquisition" yaml:"networkRequiredDuringAcquisition"`
	NetworkAllowedDuringExecution    bool `json:"networkAllowedDuringExecution" yaml:"networkAllowedDuringExecution"`
	RequireDigestVerification        bool `json:"requireDigestVerification" yaml:"requireDigestVerification"`
	RequireCompleteSet               bool `json:"requireCompleteSet" yaml:"requireCompleteSet"`
}

func (m OfflineAcquisitionManifest) AssignManifestID() (OfflineAcquisitionManifest, error) {
	m.Metadata.ManifestID = ""
	digest, err := canonical.Digest(m)
	if err != nil {
		return OfflineAcquisitionManifest{}, fmt.Errorf("digest offline acquisition manifest: %w", err)
	}
	m.Metadata.ManifestID = digest
	return m, nil
}

func (m OfflineAcquisitionManifest) Validate() diagnostics.Report {
	items := validateEnvelope(m.APIVersion, m.Kind, "OfflineAcquisitionManifest", "ACQ", Metadata{Name: m.Metadata.Name})
	if !sha256DigestPattern.MatchString(m.Metadata.ManifestID) || !sha256DigestPattern.MatchString(m.Spec.PlanID) || !sha256DigestPattern.MatchString(m.Spec.CatalogDigest) {
		items = append(items, diagnostics.Error("YARA-ACQ-010", "Manifest, plan and catalog identities must be SHA-256 digests.", "metadata.manifestId"))
	}
	if m.Spec.GeneratedBy.Name == "" || m.Spec.GeneratedBy.Version == "" || m.Spec.GeneratedBy.Target == "" {
		items = append(items, diagnostics.Error("YARA-ACQ-011", "A complete versioned generator identity is required.", "spec.generatedBy"))
	}
	if len(m.Spec.Artifacts) == 0 {
		items = append(items, diagnostics.Error("YARA-ACQ-012", "At least one immutable acquisition artifact is required.", "spec.artifacts"))
	}
	previous := ""
	for index, artifact := range m.Spec.Artifacts {
		path := fmt.Sprintf("spec.artifacts[%d]", index)
		identityValid := false
		switch artifact.Type {
		case "oci-image":
			identityValid = artifact.Method == "mirror-oci-index" && sha256DigestPattern.MatchString(artifact.Digest) && len(artifact.Platforms) > 0 && slices.IsSorted(artifact.Platforms) && !hasDuplicateStrings(artifact.Platforms) && artifact.Revision == "" && len(artifact.Files) == 0
		case "huggingface-snapshot":
			identityValid = artifact.Method == "mirror-huggingface-snapshot" && artifact.Digest == "" && artifact.Revision != "" && len(artifact.Platforms) == 0 && validBundleArtifactFiles(artifact.Files)
		}
		if strings.TrimSpace(artifact.Ref) == "" || artifact.Ref <= previous || !identityValid || artifact.LicenseID == "" || artifact.LicenseSource == "" {
			items = append(items, diagnostics.Error("YARA-ACQ-013", "Acquisition artifacts require sorted immutable identities, an explicit method and license facts.", path))
		}
		previous = artifact.Ref
	}
	if !m.Spec.Policy.NetworkRequiredDuringAcquisition || m.Spec.Policy.NetworkAllowedDuringExecution || !m.Spec.Policy.RequireDigestVerification || !m.Spec.Policy.RequireCompleteSet {
		items = append(items, diagnostics.Error("YARA-ACQ-014", "The offline contract requires acquisition networking only, exact digest verification and a complete artifact set.", "spec.policy"))
	}
	if m.Metadata.ManifestID != "" {
		claimed := m.Metadata.ManifestID
		recomputed, err := m.AssignManifestID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-ACQ-500", "Could not recompute offline-acquisition-manifest identity."))
		} else if recomputed.Metadata.ManifestID != claimed {
			items = append(items, diagnostics.Error("YARA-ACQ-015", "Manifest contents do not match metadata.manifestId.", "metadata.manifestId"))
		}
	}
	return diagnostics.NewReport(items...)
}
