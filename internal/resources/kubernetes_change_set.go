package resources

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// KubernetesChangeSet is a bounded read-only comparison of one exact bundle
// with one observed target. It is not approval and grants no mutation authority.
type KubernetesChangeSet struct {
	APIVersion string                      `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                      `json:"kind" yaml:"kind"`
	Metadata   KubernetesChangeSetMetadata `json:"metadata" yaml:"metadata"`
	Spec       KubernetesChangeSetSpec     `json:"spec" yaml:"spec"`
}

type KubernetesChangeSetMetadata struct {
	Name        string `json:"name" yaml:"name"`
	ChangeSetID string `json:"changeSetId" yaml:"changeSetId"`
}

type KubernetesChangeSetSpec struct {
	Outcome           string                      `json:"outcome" yaml:"outcome"`
	ObservedAt        string                      `json:"observedAt" yaml:"observedAt"`
	BundleID          string                      `json:"bundleId" yaml:"bundleId"`
	PlanID            string                      `json:"planId" yaml:"planId"`
	PreflightResultID string                      `json:"preflightResultId" yaml:"preflightResultId"`
	Observer          TargetPreflightObserver     `json:"observer" yaml:"observer"`
	Target            TargetIdentity              `json:"target" yaml:"target"`
	Summary           KubernetesChangeSummary     `json:"summary" yaml:"summary"`
	Operations        []KubernetesChangeOperation `json:"operations" yaml:"operations"`
	Limitations       []string                    `json:"limitations" yaml:"limitations"`
}

type KubernetesChangeSummary struct {
	Creates    int `json:"creates" yaml:"creates"`
	Updates    int `json:"updates" yaml:"updates"`
	NoOps      int `json:"noOps" yaml:"noOps"`
	Conflicts  int `json:"conflicts" yaml:"conflicts"`
	Unresolved int `json:"unresolved" yaml:"unresolved"`
	Deletes    int `json:"deletes" yaml:"deletes"`
}

type KubernetesObjectReference struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
	Namespace  string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Name       string `json:"name" yaml:"name"`
}

type KubernetesChangeOperation struct {
	Resource       KubernetesObjectReference `json:"resource" yaml:"resource"`
	Action         string                    `json:"action" yaml:"action"`
	Ownership      string                    `json:"ownership" yaml:"ownership"`
	DesiredDigest  string                    `json:"desiredDigest" yaml:"desiredDigest"`
	CurrentDigest  string                    `json:"currentDigest,omitempty" yaml:"currentDigest,omitempty"`
	RiskClasses    []string                  `json:"riskClasses" yaml:"riskClasses"`
	DiagnosticCode string                    `json:"diagnosticCode,omitempty" yaml:"diagnosticCode,omitempty"`
}

func (r KubernetesChangeSet) AssignChangeSetID() (KubernetesChangeSet, error) {
	r.Metadata.ChangeSetID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return KubernetesChangeSet{}, fmt.Errorf("digest Kubernetes change set: %w", err)
	}
	r.Metadata.ChangeSetID = digest
	return r, nil
}

func (r KubernetesChangeSet) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "KubernetesChangeSet", "CHG", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.changeSetId": r.Metadata.ChangeSetID, "spec.bundleId": r.Spec.BundleID,
		"spec.planId": r.Spec.PlanID, "spec.preflightResultId": r.Spec.PreflightResultID,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-CHG-010", "Change-set bindings must be SHA-256 digests.", path))
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.ObservedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-CHG-011", "observedAt must be an RFC3339 timestamp.", "spec.observedAt"))
	}
	if !slices.Contains([]string{"review-required", "blocked"}, r.Spec.Outcome) {
		items = append(items, diagnostics.Error("YARA-CHG-012", "Unsupported change-set outcome.", "spec.outcome"))
	}
	if r.Spec.Observer.Name == "" || r.Spec.Observer.Version == "" || r.Spec.Observer.Mode != "read-only" || r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" {
		items = append(items, diagnostics.Error("YARA-CHG-013", "A versioned read-only observer and Kubernetes target are required.", "spec.observer"))
	}
	if len(r.Spec.Operations) == 0 {
		items = append(items, diagnostics.Error("YARA-CHG-014", "At least one observed operation is required.", "spec.operations"))
	}
	derived := KubernetesChangeSummary{}
	previous, blocked := "", false
	for index, operation := range r.Spec.Operations {
		path := fmt.Sprintf("spec.operations[%d]", index)
		key := kubernetesObjectKey(operation.Resource)
		if operation.Resource.APIVersion == "" || operation.Resource.Kind == "" || operation.Resource.Name == "" || key <= previous {
			items = append(items, diagnostics.Error("YARA-CHG-015", "Operations require complete, unique, sorted resource identities.", path+".resource"))
		}
		if !sha256DigestPattern.MatchString(operation.DesiredDigest) || (operation.CurrentDigest != "" && !sha256DigestPattern.MatchString(operation.CurrentDigest)) {
			items = append(items, diagnostics.Error("YARA-CHG-016", "Observed desired/current identities must be SHA-256 digests.", path))
		}
		if !slices.Contains([]string{"create", "update", "no-op", "conflict", "unresolved"}, operation.Action) || !slices.Contains([]string{"absent", "owned", "foreign", "unknown"}, operation.Ownership) {
			items = append(items, diagnostics.Error("YARA-CHG-017", "Unsupported operation action or ownership classification.", path))
		}
		validCombination := false
		switch operation.Action {
		case "create":
			derived.Creates++
			validCombination = operation.Ownership == "absent" && operation.CurrentDigest == "" && operation.DiagnosticCode == ""
		case "update":
			derived.Updates++
			validCombination = operation.Ownership == "owned" && operation.CurrentDigest != "" && operation.CurrentDigest != operation.DesiredDigest && operation.DiagnosticCode == ""
		case "no-op":
			derived.NoOps++
			validCombination = operation.Ownership == "owned" && operation.CurrentDigest == operation.DesiredDigest && operation.DiagnosticCode == ""
		case "conflict":
			derived.Conflicts++
			blocked = true
			validCombination = operation.Ownership == "foreign" && operation.CurrentDigest != "" && diagnosticCodePattern.MatchString(operation.DiagnosticCode)
		case "unresolved":
			derived.Unresolved++
			blocked = true
			validCombination = operation.Ownership == "unknown" && operation.CurrentDigest == "" && diagnosticCodePattern.MatchString(operation.DiagnosticCode)
		}
		if !validCombination {
			items = append(items, diagnostics.Error("YARA-CHG-018", "Operation action, ownership, identities and diagnostic are inconsistent.", path))
		}
		if !slices.IsSorted(operation.RiskClasses) || hasDuplicateStrings(operation.RiskClasses) {
			items = append(items, diagnostics.Error("YARA-CHG-019", "Risk classes must be unique and sorted.", path+".riskClasses"))
		}
		previous = key
	}
	if r.Spec.Summary != derived || r.Spec.Summary.Deletes != 0 {
		items = append(items, diagnostics.Error("YARA-CHG-020", "Summary must exactly match operations and this observer cannot propose deletion.", "spec.summary"))
	}
	expectedOutcome := "review-required"
	if blocked {
		expectedOutcome = "blocked"
	}
	if r.Spec.Outcome != expectedOutcome {
		items = append(items, diagnostics.Error("YARA-CHG-021", "Outcome must be derived from observed conflicts.", "spec.outcome"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-CHG-022", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ChangeSetID != "" {
		claimed := r.Metadata.ChangeSetID
		recomputed, err := r.AssignChangeSetID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-CHG-500", "Could not recompute change-set identity."))
		} else if recomputed.Metadata.ChangeSetID != claimed {
			items = append(items, diagnostics.Error("YARA-CHG-023", "Change-set contents do not match metadata.changeSetId.", "metadata.changeSetId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func kubernetesObjectKey(reference KubernetesObjectReference) string {
	return strings.Join([]string{reference.APIVersion, reference.Kind, reference.Namespace, reference.Name}, "\x00")
}
