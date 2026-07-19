package resources

import (
	"fmt"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type DeploymentApproval struct {
	APIVersion string                     `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                     `json:"kind" yaml:"kind"`
	Metadata   DeploymentApprovalMetadata `json:"metadata" yaml:"metadata"`
	Spec       DeploymentApprovalSpec     `json:"spec" yaml:"spec"`
}

type DeploymentApprovalMetadata struct {
	Name       string `json:"name" yaml:"name"`
	ApprovalID string `json:"approvalId" yaml:"approvalId"`
}

type DeploymentApprovalSpec struct {
	Decision          string         `json:"decision" yaml:"decision"`
	Effect            string         `json:"effect" yaml:"effect"`
	RecordedAt        string         `json:"recordedAt" yaml:"recordedAt"`
	ExpiresAt         string         `json:"expiresAt" yaml:"expiresAt"`
	PlanID            string         `json:"planId" yaml:"planId"`
	BundleID          string         `json:"bundleId" yaml:"bundleId"`
	PreflightResultID string         `json:"preflightResultId" yaml:"preflightResultId"`
	ChangeSetID       string         `json:"changeSetId" yaml:"changeSetId"`
	Target            TargetIdentity `json:"target" yaml:"target"`
	Actor             ApprovalActor  `json:"actor" yaml:"actor"`
	Reason            ApprovalReason `json:"reason" yaml:"reason"`
	Limitations       []string       `json:"limitations" yaml:"limitations"`
}

type ApprovalActor struct {
	ID        string `json:"id" yaml:"id"`
	Type      string `json:"type" yaml:"type"`
	Assurance string `json:"assurance" yaml:"assurance"`
}

type ApprovalReason struct {
	Type      string `json:"type" yaml:"type"`
	Reference string `json:"reference" yaml:"reference"`
}

func (r DeploymentApproval) AssignApprovalID() (DeploymentApproval, error) {
	r.Metadata.ApprovalID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return DeploymentApproval{}, fmt.Errorf("digest deployment approval: %w", err)
	}
	r.Metadata.ApprovalID = digest
	return r, nil
}

func (r DeploymentApproval) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "DeploymentApproval", "APR", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.approvalId": r.Metadata.ApprovalID, "spec.planId": r.Spec.PlanID, "spec.bundleId": r.Spec.BundleID,
		"spec.preflightResultId": r.Spec.PreflightResultID, "spec.changeSetId": r.Spec.ChangeSetID,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-APR-010", "Approval bindings must be SHA-256 digests.", path))
		}
	}
	recorded, recordedErr := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, r.Spec.ExpiresAt)
	if recordedErr != nil || expiresErr != nil || !expires.After(recorded) || expires.Sub(recorded) > 24*time.Hour {
		items = append(items, diagnostics.Error("YARA-APR-011", "Approval validity must be a positive RFC3339 interval of at most 24 hours.", "spec.expiresAt"))
	}
	if !slices.Contains([]string{"approved", "rejected"}, r.Spec.Decision) || r.Spec.Effect != "review-only" {
		items = append(items, diagnostics.Error("YARA-APR-012", "Unsupported approval decision or effect.", "spec.decision"))
	}
	if r.Spec.Actor.ID == "" || !slices.Contains([]string{"user", "service"}, r.Spec.Actor.Type) || r.Spec.Actor.Assurance == "" {
		items = append(items, diagnostics.Error("YARA-APR-013", "A typed actor with explicit assurance is required.", "spec.actor"))
	}
	if r.Spec.Effect == "execution-authorized" {
		items = append(items, diagnostics.Error("YARA-APR-014", "v1alpha1 cannot represent verifiable execution authorization; a future signed/authenticated approval contract is required.", "spec.effect"))
	}
	if r.Spec.Decision == "rejected" && r.Spec.Effect != "review-only" {
		items = append(items, diagnostics.Error("YARA-APR-015", "A rejected decision cannot authorize execution.", "spec.effect"))
	}
	if r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" || r.Spec.Reason.Type == "" || r.Spec.Reason.Reference == "" {
		items = append(items, diagnostics.Error("YARA-APR-016", "Target and non-secret reason reference are required.", "spec"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-APR-017", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ApprovalID != "" {
		claimed := r.Metadata.ApprovalID
		recomputed, err := r.AssignApprovalID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-APR-500", "Could not recompute approval identity."))
		} else if recomputed.Metadata.ApprovalID != claimed {
			items = append(items, diagnostics.Error("YARA-APR-018", "Approval contents do not match metadata.approvalId.", "metadata.approvalId"))
		}
	}
	return diagnostics.NewReport(items...)
}
