package resources

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// TargetPreflightResult records a bounded read-only observation. It is not an
// approval, change set, deployment receipt or compatibility claim.
type TargetPreflightResult struct {
	APIVersion string                        `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                        `json:"kind" yaml:"kind"`
	Metadata   TargetPreflightResultMetadata `json:"metadata" yaml:"metadata"`
	Spec       TargetPreflightResultSpec     `json:"spec" yaml:"spec"`
}

type TargetPreflightResultMetadata struct {
	Name     string `json:"name" yaml:"name"`
	ResultID string `json:"resultId" yaml:"resultId"`
}

type TargetPreflightResultSpec struct {
	Outcome     string                  `json:"outcome" yaml:"outcome"`
	ObservedAt  string                  `json:"observedAt" yaml:"observedAt"`
	BundleID    string                  `json:"bundleId" yaml:"bundleId"`
	PlanID      string                  `json:"planId" yaml:"planId"`
	Observer    TargetPreflightObserver `json:"observer" yaml:"observer"`
	Target      TargetIdentity          `json:"target" yaml:"target"`
	Checks      []TargetPreflightCheck  `json:"checks" yaml:"checks"`
	Limitations []string                `json:"limitations" yaml:"limitations"`
}

type TargetPreflightObserver struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
	Mode    string `json:"mode" yaml:"mode"`
}

type TargetIdentity struct {
	Type            string `json:"type" yaml:"type"`
	ReferenceDigest string `json:"referenceDigest" yaml:"referenceDigest"`
	ServerVersion   string `json:"serverVersion" yaml:"serverVersion"`
}

type TargetPreflightCheck struct {
	ID             string                `json:"id" yaml:"id"`
	Status         string                `json:"status" yaml:"status"`
	DiagnosticCode string                `json:"diagnosticCode,omitempty" yaml:"diagnosticCode,omitempty"`
	Summary        string                `json:"summary" yaml:"summary"`
	EvidenceDigest string                `json:"evidenceDigest" yaml:"evidenceDigest"`
	Facts          []TargetPreflightFact `json:"facts" yaml:"facts"`
}

type TargetPreflightFact struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
}

func (r TargetPreflightResult) AssignResultID() (TargetPreflightResult, error) {
	r.Metadata.ResultID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return TargetPreflightResult{}, fmt.Errorf("digest target preflight result: %w", err)
	}
	r.Metadata.ResultID = digest
	return r, nil
}

func (r TargetPreflightResult) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "TargetPreflightResult", "TPR", Metadata{Name: r.Metadata.Name})
	if !sha256DigestPattern.MatchString(r.Metadata.ResultID) || !sha256DigestPattern.MatchString(r.Spec.BundleID) || !sha256DigestPattern.MatchString(r.Spec.PlanID) || !sha256DigestPattern.MatchString(r.Spec.Target.ReferenceDigest) {
		items = append(items, diagnostics.Error("YARA-TPR-010", "Result, bundle, plan and target identities must be SHA-256 digests.", "metadata.resultId"))
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.ObservedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-TPR-011", "observedAt must be an RFC3339 timestamp.", "spec.observedAt"))
	}
	if !slices.Contains([]string{"passed", "failed", "blocked"}, r.Spec.Outcome) {
		items = append(items, diagnostics.Error("YARA-TPR-012", "Unsupported preflight outcome.", "spec.outcome"))
	}
	if r.Spec.Observer.Name == "" || r.Spec.Observer.Version == "" || r.Spec.Observer.Mode != "read-only" {
		items = append(items, diagnostics.Error("YARA-TPR-013", "A versioned read-only observer is required.", "spec.observer"))
	}
	if r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" {
		items = append(items, diagnostics.Error("YARA-TPR-014", "A pseudonymous Kubernetes target and observed server version are required.", "spec.target"))
	}
	if len(r.Spec.Checks) == 0 {
		items = append(items, diagnostics.Error("YARA-TPR-015", "At least one preflight check is required.", "spec.checks"))
	}
	previous, derived := "", "passed"
	for index, check := range r.Spec.Checks {
		path := fmt.Sprintf("spec.checks[%d]", index)
		if check.ID == "" || check.ID <= previous || !slices.Contains([]string{"passed", "failed", "blocked"}, check.Status) || check.Summary == "" || !sha256DigestPattern.MatchString(check.EvidenceDigest) {
			items = append(items, diagnostics.Error("YARA-TPR-016", "Checks must be complete, unique and sorted.", path))
		}
		if (check.Status == "passed" && check.DiagnosticCode != "") || (check.Status != "passed" && !diagnosticCodePattern.MatchString(check.DiagnosticCode)) {
			items = append(items, diagnostics.Error("YARA-TPR-017", "Only non-passing checks require a stable diagnostic code.", path+".diagnosticCode"))
		}
		factPrevious := ""
		for factIndex, fact := range check.Facts {
			if strings.TrimSpace(fact.Name) == "" || fact.Name <= factPrevious || strings.TrimSpace(fact.Value) == "" {
				items = append(items, diagnostics.Error("YARA-TPR-018", "Check facts must be complete, unique and sorted.", fmt.Sprintf("%s.facts[%d]", path, factIndex)))
			}
			factPrevious = fact.Name
		}
		expectedEvidence, err := canonical.Digest(struct {
			ID     string
			Status string
			Facts  []TargetPreflightFact
		}{ID: check.ID, Status: check.Status, Facts: check.Facts})
		if err != nil || check.EvidenceDigest != expectedEvidence {
			items = append(items, diagnostics.Error("YARA-TPR-022", "Check evidence digest does not match its allowlisted facts.", path+".evidenceDigest"))
		}
		if check.Status == "failed" {
			derived = "failed"
		} else if check.Status == "blocked" && derived == "passed" {
			derived = "blocked"
		}
		previous = check.ID
	}
	if r.Spec.Outcome != derived {
		items = append(items, diagnostics.Error("YARA-TPR-019", "Overall outcome must match the most severe check status.", "spec.outcome"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-TPR-020", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ResultID != "" {
		claimed := r.Metadata.ResultID
		recomputed, err := r.AssignResultID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-TPR-500", "Could not recompute target-preflight identity."))
		} else if recomputed.Metadata.ResultID != claimed {
			items = append(items, diagnostics.Error("YARA-TPR-021", "Result contents do not match metadata.resultId.", "metadata.resultId"))
		}
	}
	return diagnostics.NewReport(items...)
}
