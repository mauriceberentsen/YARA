package resources

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// ArtifactImportReceipt binds imported model artifacts to exact internal
// non-secret locations before deployment mutation can start.
type ArtifactImportReceipt struct {
	APIVersion string                        `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                        `json:"kind" yaml:"kind"`
	Metadata   ArtifactImportReceiptMetadata `json:"metadata" yaml:"metadata"`
	Spec       ArtifactImportReceiptSpec     `json:"spec" yaml:"spec"`
}

type ArtifactImportReceiptMetadata struct {
	Name            string `json:"name" yaml:"name"`
	ImportReceiptID string `json:"importReceiptId" yaml:"importReceiptId"`
}

type ArtifactImportReceiptSpec struct {
	RecordedAt     string                   `json:"recordedAt" yaml:"recordedAt"`
	PlanID         string                   `json:"planId" yaml:"planId"`
	BundleID       string                   `json:"bundleId" yaml:"bundleId"`
	Target         TargetIdentity           `json:"target" yaml:"target"`
	Importer       ImporterIdentity         `json:"importer" yaml:"importer"`
	Verification   ImportVerificationStatus `json:"verification" yaml:"verification"`
	ModelArtifacts []ImportedModelArtifact  `json:"modelArtifacts" yaml:"modelArtifacts"`
	Limitations    []string                 `json:"limitations" yaml:"limitations"`
}

type ImporterIdentity struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}

type ImportVerificationStatus struct {
	DigestVerified bool `json:"digestVerified" yaml:"digestVerified"`
	SizeVerified   bool `json:"sizeVerified" yaml:"sizeVerified"`
	CompleteSet    bool `json:"completeSet" yaml:"completeSet"`
}

type ImportedModelArtifact struct {
	Ref      string                         `json:"ref" yaml:"ref"`
	Revision string                         `json:"revision" yaml:"revision"`
	Files    []ImportedModelArtifactBinding `json:"files" yaml:"files"`
}

type ImportedModelArtifactBinding struct {
	Path         string `json:"path" yaml:"path"`
	Digest       string `json:"digest" yaml:"digest"`
	SizeBytes    int64  `json:"sizeBytes" yaml:"sizeBytes"`
	InternalPath string `json:"internalPath" yaml:"internalPath"`
}

func (r ArtifactImportReceipt) AssignImportReceiptID() (ArtifactImportReceipt, error) {
	r.Metadata.ImportReceiptID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return ArtifactImportReceipt{}, fmt.Errorf("digest artifact import receipt: %w", err)
	}
	r.Metadata.ImportReceiptID = digest
	return r, nil
}

func (r ArtifactImportReceipt) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "ArtifactImportReceipt", "AIR", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.importReceiptId":    r.Metadata.ImportReceiptID,
		"spec.planId":                 r.Spec.PlanID,
		"spec.bundleId":               r.Spec.BundleID,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-AIR-010", "Import receipt bindings must be SHA-256 digests.", path))
		}
	}
	recordedAt, err := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt)
	if err != nil || recordedAt.IsZero() {
		items = append(items, diagnostics.Error("YARA-AIR-011", "RecordedAt must be a valid RFC3339 timestamp.", "spec.recordedAt"))
	}
	if r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" {
		items = append(items, diagnostics.Error("YARA-AIR-012", "A complete Kubernetes target identity is required.", "spec.target"))
	}
	if r.Spec.Importer.Name == "" || r.Spec.Importer.Version == "" {
		items = append(items, diagnostics.Error("YARA-AIR-013", "Importer name and version are required.", "spec.importer"))
	}
	if !r.Spec.Verification.DigestVerified || !r.Spec.Verification.SizeVerified || !r.Spec.Verification.CompleteSet {
		items = append(items, diagnostics.Error("YARA-AIR-014", "Import verification must confirm digest, size and complete-set checks.", "spec.verification"))
	}
	if len(r.Spec.ModelArtifacts) == 0 {
		items = append(items, diagnostics.Error("YARA-AIR-015", "At least one imported model artifact is required.", "spec.modelArtifacts"))
	}
	previousArtifactRef := ""
	for artifactIndex, artifact := range r.Spec.ModelArtifacts {
		artifactPath := fmt.Sprintf("spec.modelArtifacts[%d]", artifactIndex)
		if artifact.Ref == "" || artifact.Ref <= previousArtifactRef || artifact.Revision == "" || len(artifact.Files) == 0 {
			items = append(items, diagnostics.Error("YARA-AIR-016", "Model artifacts must be complete, unique and sorted.", artifactPath))
		}
		previousArtifactRef = artifact.Ref
		previousFilePath := ""
		seenInternal := map[string]struct{}{}
		for fileIndex, file := range artifact.Files {
			filePath := fmt.Sprintf("%s.files[%d]", artifactPath, fileIndex)
			if !validSafeRelativePath(file.Path) || file.Path <= previousFilePath || !sha256DigestPattern.MatchString(file.Digest) || file.SizeBytes <= 0 || !validSafeRelativePath(file.InternalPath) {
				items = append(items, diagnostics.Error("YARA-AIR-017", "Imported files require safe sorted paths, stable digests and positive sizes.", filePath))
			}
			if _, exists := seenInternal[file.InternalPath]; exists {
				items = append(items, diagnostics.Error("YARA-AIR-018", "Internal artifact paths must be unique per artifact.", filePath+".internalPath"))
			}
			seenInternal[file.InternalPath] = struct{}{}
			previousFilePath = file.Path
		}
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-AIR-019", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ImportReceiptID != "" {
		claimed := r.Metadata.ImportReceiptID
		recomputed, err := r.AssignImportReceiptID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-AIR-500", "Could not recompute artifact-import-receipt identity."))
		} else if recomputed.Metadata.ImportReceiptID != claimed {
			items = append(items, diagnostics.Error("YARA-AIR-020", "Import receipt contents do not match metadata.importReceiptId.", "metadata.importReceiptId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func validSafeRelativePath(value string) bool {
	clean := path.Clean(value)
	return value != "" && clean == value && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../") && !path.IsAbs(clean)
}
