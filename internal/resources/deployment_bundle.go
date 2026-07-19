package resources

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type DeploymentBundle struct {
	APIVersion string                   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                   `json:"kind" yaml:"kind"`
	Metadata   DeploymentBundleMetadata `json:"metadata" yaml:"metadata"`
	Spec       DeploymentBundleSpec     `json:"spec" yaml:"spec"`
}

type DeploymentBundleMetadata struct {
	Name     string `json:"name" yaml:"name"`
	BundleID string `json:"bundleId" yaml:"bundleId"`
}

type DeploymentBundleSpec struct {
	PlanID         string                `json:"planId" yaml:"planId"`
	CatalogDigest  string                `json:"catalogDigest" yaml:"catalogDigest"`
	Renderer       BundleRenderer        `json:"renderer" yaml:"renderer"`
	Files          []BundleFile          `json:"files" yaml:"files"`
	Artifacts      []BundleArtifact      `json:"artifacts" yaml:"artifacts"`
	RequiredInputs []BundleRequiredInput `json:"requiredInputs" yaml:"requiredInputs"`
	Operations     []BundleOperation     `json:"operations" yaml:"operations"`
	Preflight      []string              `json:"preflight" yaml:"preflight"`
	Postflight     []string              `json:"postflight" yaml:"postflight"`
	Limitations    []string              `json:"limitations" yaml:"limitations"`
}

type BundleRenderer struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
	Target  string `json:"target" yaml:"target"`
}

type BundleFile struct {
	Path      string `json:"path" yaml:"path"`
	MediaType string `json:"mediaType" yaml:"mediaType"`
	Digest    string `json:"digest" yaml:"digest"`
	Content   string `json:"content" yaml:"content"`
}

type BundleArtifact struct {
	Type          string               `json:"type" yaml:"type"`
	Ref           string               `json:"ref" yaml:"ref"`
	Digest        string               `json:"digest,omitempty" yaml:"digest,omitempty"`
	Revision      string               `json:"revision,omitempty" yaml:"revision,omitempty"`
	Platforms     []string             `json:"platforms,omitempty" yaml:"platforms,omitempty"`
	Files         []BundleArtifactFile `json:"files,omitempty" yaml:"files,omitempty"`
	LicenseID     string               `json:"licenseId" yaml:"licenseId"`
	LicenseSource string               `json:"licenseSource" yaml:"licenseSource"`
}

type BundleArtifactFile struct {
	Path      string `json:"path" yaml:"path"`
	Digest    string `json:"digest" yaml:"digest"`
	SizeBytes int64  `json:"sizeBytes" yaml:"sizeBytes"`
}

type BundleRequiredInput struct {
	Name        string `json:"name" yaml:"name"`
	Secret      bool   `json:"secret" yaml:"secret"`
	Description string `json:"description" yaml:"description"`
}

type BundleOperation struct {
	Stage      int    `json:"stage" yaml:"stage"`
	Action     string `json:"action" yaml:"action"`
	InstanceID string `json:"instanceId" yaml:"instanceId"`
}

func (b DeploymentBundle) AssignBundleID() (DeploymentBundle, error) {
	b.Metadata.BundleID = ""
	digest, err := canonical.Digest(b)
	if err != nil {
		return DeploymentBundle{}, fmt.Errorf("digest deployment bundle: %w", err)
	}
	b.Metadata.BundleID = digest
	return b, nil
}

func BundleContentDigest(content string) string {
	sum := sha256.Sum256([]byte(content))
	return fmt.Sprintf("sha256:%x", sum)
}

func (b DeploymentBundle) Validate() diagnostics.Report {
	items := validateEnvelope(b.APIVersion, b.Kind, "DeploymentBundle", "BND", Metadata{Name: b.Metadata.Name})
	if !sha256DigestPattern.MatchString(b.Metadata.BundleID) || !sha256DigestPattern.MatchString(b.Spec.PlanID) || !sha256DigestPattern.MatchString(b.Spec.CatalogDigest) {
		items = append(items, diagnostics.Error("YARA-BND-010", "Bundle, plan and catalog identities must be SHA-256 digests.", "metadata.bundleId"))
	}
	if b.Spec.Renderer.Name == "" || b.Spec.Renderer.Version == "" || b.Spec.Renderer.Target == "" {
		items = append(items, diagnostics.Error("YARA-BND-011", "A complete versioned renderer identity is required.", "spec.renderer"))
	}
	if len(b.Spec.Files) == 0 {
		items = append(items, diagnostics.Error("YARA-BND-012", "At least one rendered file is required.", "spec.files"))
	}
	previous := ""
	for index, file := range b.Spec.Files {
		path := fmt.Sprintf("spec.files[%d]", index)
		if file.Path == "" || strings.HasPrefix(file.Path, "/") || strings.Contains(file.Path, "..") || file.Path <= previous || file.MediaType == "" || file.Content == "" || file.Digest != BundleContentDigest(file.Content) {
			items = append(items, diagnostics.Error("YARA-BND-013", "Rendered files require safe sorted paths, media types and matching content digests.", path))
		}
		previous = file.Path
	}
	if len(b.Spec.Artifacts) == 0 {
		items = append(items, diagnostics.Error("YARA-BND-014", "At least one immutable artifact is required.", "spec.artifacts"))
	}
	previous = ""
	for index, artifact := range b.Spec.Artifacts {
		path := fmt.Sprintf("spec.artifacts[%d]", index)
		identityValid := false
		switch artifact.Type {
		case "oci-image":
			identityValid = sha256DigestPattern.MatchString(artifact.Digest) && len(artifact.Platforms) > 0 && slices.IsSorted(artifact.Platforms) && !hasDuplicateStrings(artifact.Platforms) && artifact.Revision == "" && len(artifact.Files) == 0
		case "huggingface-snapshot":
			identityValid = artifact.Digest == "" && artifact.Revision != "" && len(artifact.Platforms) == 0 && validBundleArtifactFiles(artifact.Files)
		}
		if artifact.Ref == "" || artifact.Ref <= previous || !identityValid || artifact.LicenseID == "" || artifact.LicenseSource == "" {
			items = append(items, diagnostics.Error("YARA-BND-014", "Artifacts require sorted immutable identity, platforms and license facts.", path))
		}
		previous = artifact.Ref
	}
	previous = ""
	for index, input := range b.Spec.RequiredInputs {
		if input.Name == "" || input.Name <= previous || input.Description == "" {
			items = append(items, diagnostics.Error("YARA-BND-015", "Required inputs must be complete, unique and sorted.", fmt.Sprintf("spec.requiredInputs[%d]", index)))
		}
		previous = input.Name
	}
	if len(b.Spec.Operations) == 0 {
		items = append(items, diagnostics.Error("YARA-BND-016", "At least one ordered operation is required.", "spec.operations"))
	}
	previousOperation := ""
	for index, operation := range b.Spec.Operations {
		key := fmt.Sprintf("%08d\x00%s\x00%s", operation.Stage, operation.InstanceID, operation.Action)
		if operation.Stage < 0 || !slices.Contains([]string{"create", "remove", "update", "verify"}, operation.Action) || operation.InstanceID == "" || key <= previousOperation {
			items = append(items, diagnostics.Error("YARA-BND-016", "Operations must preserve deterministic deployment-stage order.", fmt.Sprintf("spec.operations[%d]", index)))
		}
		previousOperation = key
	}
	for path, values := range map[string][]string{
		"spec.preflight": b.Spec.Preflight, "spec.postflight": b.Spec.Postflight, "spec.limitations": b.Spec.Limitations,
	} {
		if len(values) == 0 || !slices.IsSorted(values) || hasDuplicateStrings(values) {
			items = append(items, diagnostics.Error("YARA-BND-017", "Checks and limitations must be non-empty, unique and sorted.", path))
		}
	}
	if b.Metadata.BundleID != "" {
		claimed := b.Metadata.BundleID
		recomputed, err := b.AssignBundleID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-BND-500", "Could not recompute deployment-bundle identity."))
		} else if recomputed.Metadata.BundleID != claimed {
			items = append(items, diagnostics.Error("YARA-BND-018", "Bundle contents do not match metadata.bundleId.", "metadata.bundleId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func validBundleArtifactFiles(files []BundleArtifactFile) bool {
	if len(files) == 0 {
		return false
	}
	previous := ""
	for _, file := range files {
		if file.Path == "" || file.Path <= previous || !sha256DigestPattern.MatchString(file.Digest) || file.SizeBytes <= 0 {
			return false
		}
		previous = file.Path
	}
	return true
}
