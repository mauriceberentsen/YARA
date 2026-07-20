package resources

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// RuntimeDriftSignal records a bounded read-only runtime drift observation
// anchored to exact catalog, bundle and preflight identities.
type RuntimeDriftSignal struct {
	APIVersion string                     `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                     `json:"kind" yaml:"kind"`
	Metadata   RuntimeDriftSignalMetadata `json:"metadata" yaml:"metadata"`
	Spec       RuntimeDriftSignalSpec     `json:"spec" yaml:"spec"`
}

type RuntimeDriftSignalMetadata struct {
	Name     string `json:"name" yaml:"name"`
	SignalID string `json:"signalId" yaml:"signalId"`
}

type RuntimeDriftSignalSpec struct {
	RecordedAt          string                  `json:"recordedAt" yaml:"recordedAt"`
	CatalogDigest       string                  `json:"catalogDigest" yaml:"catalogDigest"`
	AssertionRef        string                  `json:"assertionRef" yaml:"assertionRef"`
	RuntimeRef          string                  `json:"runtimeRef" yaml:"runtimeRef"`
	BundleID            string                  `json:"bundleId" yaml:"bundleId"`
	PreflightResultID   string                  `json:"preflightResultId" yaml:"preflightResultId"`
	PreflightObservedAt string                  `json:"preflightObservedAt" yaml:"preflightObservedAt"`
	MaxPreflightAge     string                  `json:"maxPreflightAge" yaml:"maxPreflightAge"`
	Observer            TargetPreflightObserver `json:"observer" yaml:"observer"`
	Target              TargetIdentity          `json:"target" yaml:"target"`
	Status              string                  `json:"status" yaml:"status"`
	Checks              []RuntimeDriftCheck     `json:"checks" yaml:"checks"`
	Limitations         []string                `json:"limitations" yaml:"limitations"`
}

type RuntimeDriftCheck struct {
	ID             string `json:"id" yaml:"id"`
	Expected       string `json:"expected" yaml:"expected"`
	Observed       string `json:"observed" yaml:"observed"`
	Status         string `json:"status" yaml:"status"`
	ReasonCode     string `json:"reasonCode,omitempty" yaml:"reasonCode,omitempty"`
	EvidenceDigest string `json:"evidenceDigest" yaml:"evidenceDigest"`
}

func (s RuntimeDriftSignal) AssignSignalID() (RuntimeDriftSignal, error) {
	s.Metadata.SignalID = ""
	digest, err := canonical.Digest(s)
	if err != nil {
		return RuntimeDriftSignal{}, fmt.Errorf("digest runtime drift signal: %w", err)
	}
	s.Metadata.SignalID = digest
	return s, nil
}

func (s RuntimeDriftSignal) Validate() diagnostics.Report {
	items := validateEnvelope(s.APIVersion, s.Kind, "RuntimeDriftSignal", "RDS", Metadata{Name: s.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.signalId":           s.Metadata.SignalID,
		"spec.catalogDigest":          s.Spec.CatalogDigest,
		"spec.bundleId":               s.Spec.BundleID,
		"spec.preflightResultId":      s.Spec.PreflightResultID,
		"spec.target.referenceDigest": s.Spec.Target.ReferenceDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-RDS-010", "Signal identity bindings must be SHA-256 digests.", path))
		}
	}
	recordedAt, err := time.Parse(time.RFC3339Nano, s.Spec.RecordedAt)
	if err != nil || recordedAt.IsZero() {
		items = append(items, diagnostics.Error("YARA-RDS-011", "recordedAt must be a valid RFC3339 timestamp.", "spec.recordedAt"))
	}
	preflightObservedAt, err := time.Parse(time.RFC3339Nano, s.Spec.PreflightObservedAt)
	if err != nil || preflightObservedAt.IsZero() {
		items = append(items, diagnostics.Error("YARA-RDS-012", "preflightObservedAt must be a valid RFC3339 timestamp.", "spec.preflightObservedAt"))
	}
	maxAge, err := time.ParseDuration(s.Spec.MaxPreflightAge)
	if err != nil || maxAge <= 0 {
		items = append(items, diagnostics.Error("YARA-RDS-013", "maxPreflightAge must be a positive duration.", "spec.maxPreflightAge"))
	}
	if !recordedAt.IsZero() && !preflightObservedAt.IsZero() && !recordedAt.After(preflightObservedAt) {
		items = append(items, diagnostics.Error("YARA-RDS-014", "recordedAt must be after preflightObservedAt.", "spec.recordedAt"))
	}
	if s.Spec.AssertionRef == "" || s.Spec.RuntimeRef == "" {
		items = append(items, diagnostics.Error("YARA-RDS-015", "assertionRef and runtimeRef are required.", "spec"))
	}
	if s.Spec.Observer.Name == "" || s.Spec.Observer.Version == "" || s.Spec.Observer.Mode != "read-only" {
		items = append(items, diagnostics.Error("YARA-RDS-016", "A versioned read-only observer is required.", "spec.observer"))
	}
	if s.Spec.Target.Type != "kubernetes" || s.Spec.Target.ServerVersion == "" {
		items = append(items, diagnostics.Error("YARA-RDS-017", "A complete Kubernetes target identity is required.", "spec.target"))
	}
	if !slices.Contains([]string{"in-sync", "drifted"}, s.Spec.Status) {
		items = append(items, diagnostics.Error("YARA-RDS-018", "status must be in-sync or drifted.", "spec.status"))
	}
	if len(s.Spec.Checks) == 0 {
		items = append(items, diagnostics.Error("YARA-RDS-019", "At least one runtime drift check is required.", "spec.checks"))
	}
	previousCheck := ""
	derivedStatus := "in-sync"
	for index, check := range s.Spec.Checks {
		path := fmt.Sprintf("spec.checks[%d]", index)
		if check.ID == "" || check.ID <= previousCheck || strings.TrimSpace(check.Expected) == "" || strings.TrimSpace(check.Observed) == "" {
			items = append(items, diagnostics.Error("YARA-RDS-020", "Checks must be complete, unique and sorted.", path))
		}
		if !slices.Contains([]string{"matched", "drifted"}, check.Status) {
			items = append(items, diagnostics.Error("YARA-RDS-021", "Check status must be matched or drifted.", path+".status"))
		}
		if (check.Status == "matched" && check.ReasonCode != "") || (check.Status == "drifted" && !diagnosticCodePattern.MatchString(check.ReasonCode)) {
			items = append(items, diagnostics.Error("YARA-RDS-022", "Only drifted checks require a stable diagnostic reason code.", path+".reasonCode"))
		}
		expectedEvidence, err := canonical.Digest(struct {
			ID       string
			Expected string
			Observed string
			Status   string
		}{
			ID: check.ID, Expected: check.Expected, Observed: check.Observed, Status: check.Status,
		})
		if err != nil || check.EvidenceDigest != expectedEvidence {
			items = append(items, diagnostics.Error("YARA-RDS-023", "Check evidence digest does not match expected/observed drift facts.", path+".evidenceDigest"))
		}
		if check.Status == "drifted" {
			derivedStatus = "drifted"
		}
		previousCheck = check.ID
	}
	if derivedStatus != s.Spec.Status {
		items = append(items, diagnostics.Error("YARA-RDS-024", "Signal status must match the most severe check status.", "spec.status"))
	}
	if len(s.Spec.Limitations) == 0 || !slices.IsSorted(s.Spec.Limitations) || hasDuplicateStrings(s.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-RDS-025", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if s.Metadata.SignalID != "" {
		claimed := s.Metadata.SignalID
		recomputed, err := s.AssignSignalID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-RDS-500", "Could not recompute runtime-drift-signal identity."))
		} else if recomputed.Metadata.SignalID != claimed {
			items = append(items, diagnostics.Error("YARA-RDS-026", "Signal contents do not match metadata.signalId.", "metadata.signalId"))
		}
	}
	return diagnostics.NewReport(items...)
}
