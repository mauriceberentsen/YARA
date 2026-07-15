package resources

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

var planDiffChangeIDPattern = regexp.MustCompile(`^change-[0-9]{3,}$`)

const (
	DiffClassificationPresentationOnly              = "presentation-only"
	DiffClassificationProvenanceChange              = "provenance-change"
	DiffClassificationConfigurationUpdate           = "configuration-update"
	DiffClassificationArtifactOrVersionUpgrade      = "artifact-or-version-upgrade"
	DiffClassificationScaleOrPlacementChange        = "scale-or-placement-change"
	DiffClassificationStatefulMigration             = "stateful-migration"
	DiffClassificationSecurityOrTrustBoundaryChange = "security-or-trust-boundary-change"
	DiffClassificationDestructiveReplacement        = "destructive-replacement"

	DiffImpactNone        = "none"
	DiffImpactReview      = "review"
	DiffImpactRedeploy    = "redeploy"
	DiffImpactDestructive = "destructive"
)

type PlatformPlanDiff struct {
	APIVersion string           `json:"apiVersion" yaml:"apiVersion"`
	Kind       string           `json:"kind" yaml:"kind"`
	Metadata   PlanDiffMetadata `json:"metadata" yaml:"metadata"`
	Spec       PlanDiffSpec     `json:"spec" yaml:"spec"`
}

type PlanDiffMetadata struct {
	DiffID     string `json:"diffId" yaml:"diffId"`
	FromPlanID string `json:"fromPlanId" yaml:"fromPlanId"`
	ToPlanID   string `json:"toPlanId" yaml:"toPlanId"`
}

type PlanDiffSpec struct {
	Changed       bool            `json:"changed" yaml:"changed"`
	HighestImpact string          `json:"highestImpact" yaml:"highestImpact"`
	Causes        []PlanDiffCause `json:"causes" yaml:"causes"`
	Changes       []PlanChange    `json:"changes" yaml:"changes"`
}

type PlanDiffCause struct {
	Kind         string `json:"kind" yaml:"kind"`
	BeforeDigest string `json:"beforeDigest" yaml:"beforeDigest"`
	AfterDigest  string `json:"afterDigest" yaml:"afterDigest"`
}

type PlanChange struct {
	ID             string   `json:"id" yaml:"id"`
	Path           string   `json:"path" yaml:"path"`
	Classification string   `json:"classification" yaml:"classification"`
	Impact         string   `json:"impact" yaml:"impact"`
	Summary        string   `json:"summary" yaml:"summary"`
	BeforeDigest   string   `json:"beforeDigest" yaml:"beforeDigest"`
	AfterDigest    string   `json:"afterDigest" yaml:"afterDigest"`
	DecisionRefs   []string `json:"decisionRefs" yaml:"decisionRefs"`
}

func (d PlatformPlanDiff) AssignDiffID() (PlatformPlanDiff, error) {
	d.Metadata.DiffID = ""
	type changeIdentity struct {
		ID             string   `json:"id"`
		Path           string   `json:"path"`
		Classification string   `json:"classification"`
		Impact         string   `json:"impact"`
		BeforeDigest   string   `json:"beforeDigest"`
		AfterDigest    string   `json:"afterDigest"`
		DecisionRefs   []string `json:"decisionRefs"`
	}
	changes := make([]changeIdentity, len(d.Spec.Changes))
	for index, change := range d.Spec.Changes {
		decisionRefs := append([]string{}, change.DecisionRefs...)
		sort.Strings(decisionRefs)
		changes[index] = changeIdentity{
			ID: change.ID, Path: change.Path, Classification: change.Classification,
			Impact: change.Impact, BeforeDigest: change.BeforeDigest, AfterDigest: change.AfterDigest,
			DecisionRefs: decisionRefs,
		}
	}
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].ID < changes[j].ID })
	causes := append([]PlanDiffCause{}, d.Spec.Causes...)
	sort.SliceStable(causes, func(i, j int) bool { return causes[i].Kind < causes[j].Kind })
	identity := struct {
		APIVersion string           `json:"apiVersion"`
		Kind       string           `json:"kind"`
		Metadata   PlanDiffMetadata `json:"metadata"`
		Changed    bool             `json:"changed"`
		Impact     string           `json:"highestImpact"`
		Causes     []PlanDiffCause  `json:"causes"`
		Changes    []changeIdentity `json:"changes"`
	}{d.APIVersion, d.Kind, d.Metadata, d.Spec.Changed, d.Spec.HighestImpact, causes, changes}
	digest, err := canonical.Digest(identity)
	if err != nil {
		return PlatformPlanDiff{}, err
	}
	d.Metadata.DiffID = digest
	return d, nil
}

func (d PlatformPlanDiff) Validate() diagnostics.Report {
	var items []diagnostics.Diagnostic
	if d.APIVersion != APIVersion {
		items = append(items, diagnostics.Error("YARA-DIFF-001", "Unsupported apiVersion; expected "+APIVersion+".", "apiVersion"))
	}
	if d.Kind != "PlatformPlanDiff" {
		items = append(items, diagnostics.Error("YARA-DIFF-002", "Unexpected resource kind; expected PlatformPlanDiff.", "kind"))
	}
	identities := []struct {
		path  string
		value string
	}{
		{"metadata.diffId", d.Metadata.DiffID},
		{"metadata.fromPlanId", d.Metadata.FromPlanID},
		{"metadata.toPlanId", d.Metadata.ToPlanID},
	}
	for _, identity := range identities {
		path, value := identity.path, identity.value
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-DIFF-010", "Diff and plan identities must be SHA-256 identities.", path))
		}
	}
	if d.Spec.Changed != (len(d.Spec.Changes) > 0) {
		items = append(items, diagnostics.Error("YARA-DIFF-011", "changed must match whether semantic changes are present.", "spec.changed"))
	}
	seen := make(map[string]struct{}, len(d.Spec.Changes))
	highest := DiffImpactNone
	for index, change := range d.Spec.Changes {
		path := fmt.Sprintf("spec.changes[%d]", index)
		if !planDiffChangeIDPattern.MatchString(change.ID) || change.Path == "" || change.Summary == "" {
			items = append(items, diagnostics.Error("YARA-DIFF-012", "Each change requires an ID, path and summary.", path))
		}
		if _, exists := seen[change.ID]; exists {
			items = append(items, diagnostics.Error("YARA-DIFF-013", "Change IDs must be unique.", path+".id"))
		}
		seen[change.ID] = struct{}{}
		if !validDiffClassification(change.Classification) {
			items = append(items, diagnostics.Error("YARA-DIFF-014", "Change classification is unsupported.", path+".classification"))
		}
		if !validDiffImpact(change.Impact) {
			items = append(items, diagnostics.Error("YARA-DIFF-015", "Change impact is unsupported.", path+".impact"))
		} else if diffImpactRank(change.Impact) > diffImpactRank(highest) {
			highest = change.Impact
		}
		if !validClassificationImpact(change.Classification, change.Impact) {
			items = append(items, diagnostics.Error("YARA-DIFF-020", "Change impact is inconsistent with its classification.", path+".impact"))
		}
		if !sha256DigestPattern.MatchString(change.BeforeDigest) || !sha256DigestPattern.MatchString(change.AfterDigest) {
			items = append(items, diagnostics.Error("YARA-DIFF-016", "Change values must be represented by SHA-256 digests.", path))
		} else if change.BeforeDigest == change.AfterDigest {
			items = append(items, diagnostics.Error("YARA-DIFF-021", "A change must identify different before and after values.", path))
		}
		decisionRefs := make(map[string]struct{}, len(change.DecisionRefs))
		for _, reference := range change.DecisionRefs {
			if reference == "" {
				items = append(items, diagnostics.Error("YARA-DIFF-022", "Decision references must not be empty.", path+".decisionRefs"))
			}
			if _, exists := decisionRefs[reference]; exists {
				items = append(items, diagnostics.Error("YARA-DIFF-023", "Decision references must be unique.", path+".decisionRefs"))
			}
			decisionRefs[reference] = struct{}{}
		}
	}
	for index, cause := range d.Spec.Causes {
		path := fmt.Sprintf("spec.causes[%d]", index)
		if !validDiffCause(cause.Kind) || !sha256DigestPattern.MatchString(cause.BeforeDigest) || !sha256DigestPattern.MatchString(cause.AfterDigest) {
			items = append(items, diagnostics.Error("YARA-DIFF-017", "Each cause requires a kind and two SHA-256 digests.", path))
		} else if cause.BeforeDigest == cause.AfterDigest {
			items = append(items, diagnostics.Error("YARA-DIFF-024", "A cause must identify different before and after values.", path))
		}
	}
	if d.Spec.HighestImpact != highest {
		items = append(items, diagnostics.Error("YARA-DIFF-018", "highestImpact does not match the classified changes.", "spec.highestImpact"))
	}
	if d.Metadata.DiffID != "" {
		claimed := d.Metadata.DiffID
		recomputed, err := d.AssignDiffID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-DIFF-500", "Could not recompute semantic diff identity."))
		} else if recomputed.Metadata.DiffID != claimed {
			items = append(items, diagnostics.Error("YARA-DIFF-019", "Diff contents do not match metadata.diffId.", "metadata.diffId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func validDiffClassification(value string) bool {
	switch value {
	case DiffClassificationPresentationOnly, DiffClassificationProvenanceChange,
		DiffClassificationConfigurationUpdate, DiffClassificationArtifactOrVersionUpgrade,
		DiffClassificationScaleOrPlacementChange, DiffClassificationStatefulMigration,
		DiffClassificationSecurityOrTrustBoundaryChange, DiffClassificationDestructiveReplacement:
		return true
	default:
		return false
	}
}

func validDiffImpact(value string) bool {
	return value == DiffImpactNone || value == DiffImpactReview || value == DiffImpactRedeploy || value == DiffImpactDestructive
}

func validClassificationImpact(classification, impact string) bool {
	switch classification {
	case DiffClassificationPresentationOnly:
		return impact == DiffImpactNone
	case DiffClassificationProvenanceChange:
		return impact == DiffImpactReview
	case DiffClassificationConfigurationUpdate, DiffClassificationArtifactOrVersionUpgrade, DiffClassificationScaleOrPlacementChange:
		return impact == DiffImpactRedeploy
	case DiffClassificationStatefulMigration, DiffClassificationSecurityOrTrustBoundaryChange, DiffClassificationDestructiveReplacement:
		return impact == DiffImpactDestructive
	default:
		return false
	}
}

func validDiffCause(value string) bool {
	return value == "request" || value == "inventory" || value == "catalog" || value == "planner"
}

func diffImpactRank(value string) int {
	switch value {
	case DiffImpactReview:
		return 1
	case DiffImpactRedeploy:
		return 2
	case DiffImpactDestructive:
		return 3
	default:
		return 0
	}
}
