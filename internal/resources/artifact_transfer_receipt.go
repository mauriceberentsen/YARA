package resources

import (
	"fmt"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// ArtifactTransferReceipt records one immutable non-secret transfer stage across
// offline boundaries for bundle artifacts.
type ArtifactTransferReceipt struct {
	APIVersion string                          `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                          `json:"kind" yaml:"kind"`
	Metadata   ArtifactTransferReceiptMetadata `json:"metadata" yaml:"metadata"`
	Spec       ArtifactTransferReceiptSpec     `json:"spec" yaml:"spec"`
}

type ArtifactTransferReceiptMetadata struct {
	Name              string `json:"name" yaml:"name"`
	TransferReceiptID string `json:"transferReceiptId" yaml:"transferReceiptId"`
}

type ArtifactTransferReceiptSpec struct {
	RecordedAt                string                  `json:"recordedAt" yaml:"recordedAt"`
	PlanID                    string                  `json:"planId" yaml:"planId"`
	BundleID                  string                  `json:"bundleId" yaml:"bundleId"`
	CatalogDigest             string                  `json:"catalogDigest" yaml:"catalogDigest"`
	Target                    TargetIdentity          `json:"target" yaml:"target"`
	Stage                     string                  `json:"stage" yaml:"stage"`
	SourceAttestationRef      string                  `json:"sourceAttestationRef" yaml:"sourceAttestationRef"`
	DestinationAttestationRef string                  `json:"destinationAttestationRef" yaml:"destinationAttestationRef"`
	PriorReceiptIDs           []string                `json:"priorReceiptIds" yaml:"priorReceiptIds"`
	ModelArtifacts            []ImportedModelArtifact `json:"modelArtifacts" yaml:"modelArtifacts"`
	Limitations               []string                `json:"limitations" yaml:"limitations"`
}

func (r ArtifactTransferReceipt) AssignTransferReceiptID() (ArtifactTransferReceipt, error) {
	r.Metadata.TransferReceiptID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return ArtifactTransferReceipt{}, fmt.Errorf("digest artifact transfer receipt: %w", err)
	}
	r.Metadata.TransferReceiptID = digest
	return r, nil
}

func (r ArtifactTransferReceipt) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "ArtifactTransferReceipt", "ATR", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.transferReceiptId":  r.Metadata.TransferReceiptID,
		"spec.planId":                 r.Spec.PlanID,
		"spec.bundleId":               r.Spec.BundleID,
		"spec.catalogDigest":          r.Spec.CatalogDigest,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-ATR-010", "Transfer receipt bindings must be SHA-256 digests.", path))
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-ATR-011", "RecordedAt must be a valid RFC3339 timestamp.", "spec.recordedAt"))
	}
	if r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" {
		items = append(items, diagnostics.Error("YARA-ATR-012", "A complete Kubernetes target identity is required.", "spec.target"))
	}
	if !slices.Contains([]string{"staging-to-vault", "vault-to-registry", "registry-to-runtime"}, r.Spec.Stage) {
		items = append(items, diagnostics.Error("YARA-ATR-013", "Transfer stage must be a supported bounded value.", "spec.stage"))
	}
	if r.Spec.SourceAttestationRef == "" || r.Spec.DestinationAttestationRef == "" {
		items = append(items, diagnostics.Error("YARA-ATR-014", "Source and destination attestation references are required.", "spec"))
	}
	if len(r.Spec.PriorReceiptIDs) == 0 || !slices.IsSorted(r.Spec.PriorReceiptIDs) || hasDuplicateStrings(r.Spec.PriorReceiptIDs) {
		items = append(items, diagnostics.Error("YARA-ATR-015", "Transfer receipts require unique sorted prior receipt IDs.", "spec.priorReceiptIds"))
	}
	for index, value := range r.Spec.PriorReceiptIDs {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-ATR-016", "Prior receipt IDs must be SHA-256 digests.", fmt.Sprintf("spec.priorReceiptIds[%d]", index)))
		}
	}
	if len(r.Spec.ModelArtifacts) == 0 {
		items = append(items, diagnostics.Error("YARA-ATR-017", "At least one transferred model artifact is required.", "spec.modelArtifacts"))
	}
	previousArtifactRef := ""
	for artifactIndex, artifact := range r.Spec.ModelArtifacts {
		artifactPath := fmt.Sprintf("spec.modelArtifacts[%d]", artifactIndex)
		if artifact.Ref == "" || artifact.Ref <= previousArtifactRef || artifact.Revision == "" || len(artifact.Files) == 0 {
			items = append(items, diagnostics.Error("YARA-ATR-018", "Model artifacts must be complete, unique and sorted.", artifactPath))
		}
		previousArtifactRef = artifact.Ref
		previousFilePath := ""
		for fileIndex, file := range artifact.Files {
			filePath := fmt.Sprintf("%s.files[%d]", artifactPath, fileIndex)
			if !validSafeRelativePath(file.Path) || file.Path <= previousFilePath || !sha256DigestPattern.MatchString(file.Digest) || file.SizeBytes <= 0 {
				items = append(items, diagnostics.Error("YARA-ATR-019", "Transferred files require safe sorted paths, stable digests and positive sizes.", filePath))
			}
			previousFilePath = file.Path
		}
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-ATR-020", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.TransferReceiptID != "" {
		claimed := r.Metadata.TransferReceiptID
		recomputed, err := r.AssignTransferReceiptID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-ATR-500", "Could not recompute artifact-transfer-receipt identity."))
		} else if recomputed.Metadata.TransferReceiptID != claimed {
			items = append(items, diagnostics.Error("YARA-ATR-021", "Transfer receipt contents do not match metadata.transferReceiptId.", "metadata.transferReceiptId"))
		}
	}
	return diagnostics.NewReport(items...)
}
