package resources

import (
	"fmt"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type AirgapGateTrustPolicyDiff struct {
	APIVersion string                            `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                            `json:"kind" yaml:"kind"`
	Metadata   AirgapGateTrustPolicyDiffMetadata `json:"metadata" yaml:"metadata"`
	Spec       AirgapGateTrustPolicyDiffSpec     `json:"spec" yaml:"spec"`
}

type AirgapGateTrustPolicyDiffMetadata struct {
	Name   string `json:"name" yaml:"name"`
	DiffID string `json:"diffId" yaml:"diffId"`
}

type AirgapGateTrustPolicyDiffSpec struct {
	RecordedAt            string                        `json:"recordedAt" yaml:"recordedAt"`
	FromPolicyID          string                        `json:"fromPolicyId" yaml:"fromPolicyId"`
	ToPolicyID            string                        `json:"toPolicyId" yaml:"toPolicyId"`
	TargetReferenceDigest string                        `json:"targetReferenceDigest" yaml:"targetReferenceDigest"`
	HighestImpact         string                        `json:"highestImpact" yaml:"highestImpact"`
	Changes               []AirgapGateTrustPolicyChange `json:"changes" yaml:"changes"`
	Limitations           []string                      `json:"limitations" yaml:"limitations"`
}

type AirgapGateTrustPolicyChange struct {
	ID       string `json:"id" yaml:"id"`
	KeyID    string `json:"keyId" yaml:"keyId"`
	Digest   string `json:"digest" yaml:"digest"`
	Category string `json:"category" yaml:"category"`
	Impact   string `json:"impact" yaml:"impact"`
	Summary  string `json:"summary" yaml:"summary"`
}

func (r AirgapGateTrustPolicyDiff) AssignDiffID() (AirgapGateTrustPolicyDiff, error) {
	r.Metadata.DiffID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return AirgapGateTrustPolicyDiff{}, fmt.Errorf("digest airgap gate trust policy diff: %w", err)
	}
	r.Metadata.DiffID = digest
	return r, nil
}

func (r AirgapGateTrustPolicyDiff) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "AirgapGateTrustPolicyDiff", "AGD", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.diffId":            r.Metadata.DiffID,
		"spec.fromPolicyId":          r.Spec.FromPolicyID,
		"spec.toPolicyId":            r.Spec.ToPolicyID,
		"spec.targetReferenceDigest": r.Spec.TargetReferenceDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-AGD-010", "Trust-policy diff identities must be SHA-256 digests.", path))
		}
	}
	if r.Spec.FromPolicyID == r.Spec.ToPolicyID {
		items = append(items, diagnostics.Error("YARA-AGD-011", "Trust-policy diff requires two distinct policy identities.", "spec.toPolicyId"))
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-AGD-012", "Trust-policy diff recordedAt must be RFC3339.", "spec.recordedAt"))
	}
	if len(r.Spec.Changes) == 0 {
		items = append(items, diagnostics.Error("YARA-AGD-013", "Trust-policy diff must include at least one signer change.", "spec.changes"))
	}
	previous := ""
	derivedImpact := "review"
	for index, change := range r.Spec.Changes {
		path := fmt.Sprintf("spec.changes[%d]", index)
		key := change.KeyID + "|" + change.Digest + "|" + change.Category
		if change.ID == "" || change.KeyID == "" || !sha256DigestPattern.MatchString(change.Digest) || key <= previous {
			items = append(items, diagnostics.Error("YARA-AGD-014", "Trust-policy changes must be complete, unique and sorted.", path))
		}
		if !slices.Contains([]string{"added", "revoked", "validity-window-updated", "removed"}, change.Category) {
			items = append(items, diagnostics.Error("YARA-AGD-015", "Trust-policy diff category is unsupported.", path+".category"))
		}
		if !slices.Contains([]string{"review", "destructive"}, change.Impact) {
			items = append(items, diagnostics.Error("YARA-AGD-016", "Trust-policy diff impact is unsupported.", path+".impact"))
		}
		if change.Summary == "" {
			items = append(items, diagnostics.Error("YARA-AGD-017", "Trust-policy change summary is required.", path+".summary"))
		}
		if change.Impact == "destructive" {
			derivedImpact = "destructive"
		}
		previous = key
	}
	if r.Spec.HighestImpact != derivedImpact {
		items = append(items, diagnostics.Error("YARA-AGD-018", "highestImpact must match change impacts.", "spec.highestImpact"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-AGD-019", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.DiffID != "" {
		claimed := r.Metadata.DiffID
		recomputed, err := r.AssignDiffID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-AGD-500", "Could not recompute trust-policy diff identity."))
		} else if recomputed.Metadata.DiffID != claimed {
			items = append(items, diagnostics.Error("YARA-AGD-020", "Trust-policy diff contents do not match metadata.diffId.", "metadata.diffId"))
		}
	}
	return diagnostics.NewReport(items...)
}
