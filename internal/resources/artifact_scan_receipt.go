package resources

import (
	"fmt"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// ArtifactScanReceipt records immutable, non-secret scanner verdict evidence for
// exact transferred model artifacts.
type ArtifactScanReceipt struct {
	APIVersion string                      `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                      `json:"kind" yaml:"kind"`
	Metadata   ArtifactScanReceiptMetadata `json:"metadata" yaml:"metadata"`
	Spec       ArtifactScanReceiptSpec     `json:"spec" yaml:"spec"`
}

type ArtifactScanReceiptMetadata struct {
	Name          string `json:"name" yaml:"name"`
	ScanReceiptID string `json:"scanReceiptId" yaml:"scanReceiptId"`
}

type ArtifactScanReceiptSpec struct {
	RecordedAt      string                  `json:"recordedAt" yaml:"recordedAt"`
	PlanID          string                  `json:"planId" yaml:"planId"`
	BundleID        string                  `json:"bundleId" yaml:"bundleId"`
	CatalogDigest   string                  `json:"catalogDigest" yaml:"catalogDigest"`
	Target          TargetIdentity          `json:"target" yaml:"target"`
	Scanner         ScanToolIdentity        `json:"scanner" yaml:"scanner"`
	Verdict         string                  `json:"verdict" yaml:"verdict"`
	ReasonReference string                  `json:"reasonReference" yaml:"reasonReference"`
	PriorReceiptIDs []string                `json:"priorReceiptIds" yaml:"priorReceiptIds"`
	ModelArtifacts  []ImportedModelArtifact `json:"modelArtifacts" yaml:"modelArtifacts"`
	Limitations     []string                `json:"limitations" yaml:"limitations"`
}

type ScanToolIdentity struct {
	Name         string `json:"name" yaml:"name"`
	Version      string `json:"version" yaml:"version"`
	Profile      string `json:"profile" yaml:"profile"`
	PolicyDigest string `json:"policyDigest" yaml:"policyDigest"`
}

func (r ArtifactScanReceipt) AssignScanReceiptID() (ArtifactScanReceipt, error) {
	r.Metadata.ScanReceiptID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return ArtifactScanReceipt{}, fmt.Errorf("digest artifact scan receipt: %w", err)
	}
	r.Metadata.ScanReceiptID = digest
	return r, nil
}

func (r ArtifactScanReceipt) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "ArtifactScanReceipt", "ASC", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.scanReceiptId":      r.Metadata.ScanReceiptID,
		"spec.planId":                 r.Spec.PlanID,
		"spec.bundleId":               r.Spec.BundleID,
		"spec.catalogDigest":          r.Spec.CatalogDigest,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest,
		"spec.scanner.policyDigest":   r.Spec.Scanner.PolicyDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-ASC-010", "Scan receipt bindings must be SHA-256 digests.", path))
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-ASC-011", "RecordedAt must be a valid RFC3339 timestamp.", "spec.recordedAt"))
	}
	if r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" {
		items = append(items, diagnostics.Error("YARA-ASC-012", "A complete Kubernetes target identity is required.", "spec.target"))
	}
	if r.Spec.Scanner.Name == "" || r.Spec.Scanner.Version == "" || r.Spec.Scanner.Profile == "" {
		items = append(items, diagnostics.Error("YARA-ASC-013", "Scanner name, version and profile are required.", "spec.scanner"))
	}
	if !slices.Contains([]string{"passed", "failed", "blocked"}, r.Spec.Verdict) {
		items = append(items, diagnostics.Error("YARA-ASC-014", "Scan verdict must be passed, failed or blocked.", "spec.verdict"))
	}
	if r.Spec.ReasonReference == "" {
		items = append(items, diagnostics.Error("YARA-ASC-015", "A non-secret reason reference is required.", "spec.reasonReference"))
	}
	if len(r.Spec.PriorReceiptIDs) == 0 || !slices.IsSorted(r.Spec.PriorReceiptIDs) || hasDuplicateStrings(r.Spec.PriorReceiptIDs) {
		items = append(items, diagnostics.Error("YARA-ASC-016", "Scan receipts require unique sorted prior receipt IDs.", "spec.priorReceiptIds"))
	}
	for index, value := range r.Spec.PriorReceiptIDs {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-ASC-017", "Prior receipt IDs must be SHA-256 digests.", fmt.Sprintf("spec.priorReceiptIds[%d]", index)))
		}
	}
	if len(r.Spec.ModelArtifacts) == 0 {
		items = append(items, diagnostics.Error("YARA-ASC-018", "At least one scanned model artifact is required.", "spec.modelArtifacts"))
	}
	previousArtifactRef := ""
	for artifactIndex, artifact := range r.Spec.ModelArtifacts {
		artifactPath := fmt.Sprintf("spec.modelArtifacts[%d]", artifactIndex)
		if artifact.Ref == "" || artifact.Ref <= previousArtifactRef || artifact.Revision == "" || len(artifact.Files) == 0 {
			items = append(items, diagnostics.Error("YARA-ASC-019", "Model artifacts must be complete, unique and sorted.", artifactPath))
		}
		previousArtifactRef = artifact.Ref
		previousFilePath := ""
		for fileIndex, file := range artifact.Files {
			filePath := fmt.Sprintf("%s.files[%d]", artifactPath, fileIndex)
			if !validSafeRelativePath(file.Path) || file.Path <= previousFilePath || !sha256DigestPattern.MatchString(file.Digest) || file.SizeBytes <= 0 {
				items = append(items, diagnostics.Error("YARA-ASC-020", "Scanned files require safe sorted paths, stable digests and positive sizes.", filePath))
			}
			previousFilePath = file.Path
		}
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-ASC-021", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ScanReceiptID != "" {
		claimed := r.Metadata.ScanReceiptID
		recomputed, err := r.AssignScanReceiptID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-ASC-500", "Could not recompute artifact-scan-receipt identity."))
		} else if recomputed.Metadata.ScanReceiptID != claimed {
			items = append(items, diagnostics.Error("YARA-ASC-022", "Scan receipt contents do not match metadata.scanReceiptId.", "metadata.scanReceiptId"))
		}
	}
	return diagnostics.NewReport(items...)
}
