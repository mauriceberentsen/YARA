package resources

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

var catalogVersionRefPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// IntegrationTestResult records bounded, observed integration evidence without
// turning that evidence into a general compatibility or performance claim.
type IntegrationTestResult struct {
	APIVersion string                        `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                        `json:"kind" yaml:"kind"`
	Metadata   IntegrationTestResultMetadata `json:"metadata" yaml:"metadata"`
	Spec       IntegrationTestResultSpec     `json:"spec" yaml:"spec"`
}

type IntegrationTestResultMetadata struct {
	Name     string `json:"name" yaml:"name"`
	ResultID string `json:"resultId" yaml:"resultId"`
}

type IntegrationTestResultSpec struct {
	Mode          string                  `json:"mode" yaml:"mode"`
	Outcome       string                  `json:"outcome" yaml:"outcome"`
	CatalogDigest string                  `json:"catalogDigest" yaml:"catalogDigest"`
	ComponentRefs []string                `json:"componentRefs" yaml:"componentRefs"`
	TopologyRef   string                  `json:"topologyRef,omitempty" yaml:"topologyRef,omitempty"`
	Runner        *ContractTestRunner     `json:"runner,omitempty" yaml:"runner,omitempty"`
	Environment   ContractTestEnvironment `json:"environment" yaml:"environment"`
	Checks        []ContractTestCheck     `json:"checks" yaml:"checks"`
	Limitations   []string                `json:"limitations" yaml:"limitations"`
}

func (r IntegrationTestResult) AssignResultID() (IntegrationTestResult, error) {
	r.Metadata.ResultID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return IntegrationTestResult{}, fmt.Errorf("digest integration test result: %w", err)
	}
	r.Metadata.ResultID = digest
	return r, nil
}

func (r IntegrationTestResult) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "IntegrationTestResult", "INT", Metadata{Name: r.Metadata.Name})
	if !sha256DigestPattern.MatchString(r.Metadata.ResultID) || !sha256DigestPattern.MatchString(r.Spec.CatalogDigest) || !sha256DigestPattern.MatchString(r.Spec.Environment.ReferenceDigest) {
		items = append(items, diagnostics.Error("YARA-INT-010", "Result, catalog and target identities must be SHA-256 digests.", "metadata.resultId"))
	}
	if !slices.Contains([]string{"component-smoke", "topology-end-to-end"}, r.Spec.Mode) || !slices.Contains([]string{"passed", "failed", "blocked"}, r.Spec.Outcome) {
		items = append(items, diagnostics.Error("YARA-INT-011", "Unsupported integration-test mode or outcome.", "spec"))
	}
	if len(r.Spec.ComponentRefs) == 0 || !slices.IsSorted(r.Spec.ComponentRefs) || hasDuplicateStrings(r.Spec.ComponentRefs) {
		items = append(items, diagnostics.Error("YARA-INT-012", "At least one unique, sorted component reference is required.", "spec.componentRefs"))
	}
	for index, reference := range r.Spec.ComponentRefs {
		if !catalogVersionRefPattern.MatchString(reference) {
			items = append(items, diagnostics.Error("YARA-INT-013", "Component references must use exact id@version form.", fmt.Sprintf("spec.componentRefs[%d]", index)))
		}
	}
	if r.Spec.Mode == "component-smoke" && r.Spec.TopologyRef != "" {
		items = append(items, diagnostics.Error("YARA-INT-014", "Component-smoke evidence must not claim a topology.", "spec.topologyRef"))
	}
	if r.Spec.Mode == "topology-end-to-end" && (!catalogVersionRefPattern.MatchString(r.Spec.TopologyRef) || len(r.Spec.ComponentRefs) < 2) {
		items = append(items, diagnostics.Error("YARA-INT-015", "Topology evidence requires an exact topology reference and at least two components.", "spec.topologyRef"))
	}
	if r.Spec.Runner != nil && (strings.TrimSpace(r.Spec.Runner.Version) == "" || !sha256DigestPattern.MatchString(r.Spec.Runner.BinaryDigest)) {
		items = append(items, diagnostics.Error("YARA-INT-016", "Runner evidence requires a version and executable SHA-256 digest.", "spec.runner"))
	}
	if !slices.Contains([]string{"local", "ssh"}, r.Spec.Environment.Transport) || r.Spec.Environment.OperatingSystem == "" || r.Spec.Environment.Architecture == "" {
		items = append(items, diagnostics.Error("YARA-INT-017", "Local or SSH transport and observed operating-system facts are required.", "spec.environment"))
	}
	if r.Spec.Environment.Docker.Available && (r.Spec.Environment.Docker.Version == "" || r.Spec.Environment.Docker.OperatingSystem == "" || r.Spec.Environment.Docker.Architecture == "") {
		items = append(items, diagnostics.Error("YARA-INT-018", "Available Docker requires version, OS and architecture facts.", "spec.environment.docker"))
	}
	previousAccelerator := ""
	for index, accelerator := range r.Spec.Environment.Accelerators {
		key := accelerator.Vendor + "\x00" + accelerator.Model + "\x00" + accelerator.DriverVersion + "\x00" + accelerator.ComputeCapability
		if accelerator.Vendor == "" || accelerator.Model == "" || accelerator.DriverVersion == "" || accelerator.ComputeCapability == "" || key <= previousAccelerator {
			items = append(items, diagnostics.Error("YARA-INT-019", "Accelerators must contain complete facts in unique sorted order.", fmt.Sprintf("spec.environment.accelerators[%d]", index)))
		}
		previousAccelerator = key
	}
	previousCheck, derivedOutcome := "", "passed"
	seenChecks := make(map[string]struct{}, len(r.Spec.Checks))
	if len(r.Spec.Checks) == 0 {
		items = append(items, diagnostics.Error("YARA-INT-020", "At least one integration check is required.", "spec.checks"))
	}
	for index, check := range r.Spec.Checks {
		path := fmt.Sprintf("spec.checks[%d]", index)
		if strings.TrimSpace(check.ID) == "" || check.ID < previousCheck || !slices.Contains([]string{"passed", "failed", "blocked"}, check.Status) || !sha256DigestPattern.MatchString(check.EvidenceDigest) {
			items = append(items, diagnostics.Error("YARA-INT-021", "Checks must be identified, sorted and carry valid status and evidence.", path))
		}
		if _, exists := seenChecks[check.ID]; exists {
			items = append(items, diagnostics.Error("YARA-INT-022", "Check IDs must be unique.", path+".id"))
		}
		seenChecks[check.ID] = struct{}{}
		if (check.Status == "passed" && check.DiagnosticCode != "") || (check.Status != "passed" && !diagnosticCodePattern.MatchString(check.DiagnosticCode)) {
			items = append(items, diagnostics.Error("YARA-INT-023", "Only non-passing checks require a stable diagnostic code.", path+".diagnosticCode"))
		}
		for key, value := range check.Measurements {
			if strings.TrimSpace(key) == "" || value < 0 {
				items = append(items, diagnostics.Error("YARA-INT-024", "Check measurements require non-empty names and non-negative integer values.", path+".measurements"))
				break
			}
		}
		if check.Status == "failed" {
			derivedOutcome = "failed"
		} else if check.Status == "blocked" && derivedOutcome == "passed" {
			derivedOutcome = "blocked"
		}
		previousCheck = check.ID
	}
	if r.Spec.Outcome != derivedOutcome {
		items = append(items, diagnostics.Error("YARA-INT-025", "Overall outcome must match the most severe check status.", "spec.outcome"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-INT-026", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ResultID != "" {
		claimed := r.Metadata.ResultID
		recomputed, err := r.AssignResultID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-INT-500", "Could not recompute integration-test result identity."))
		} else if recomputed.Metadata.ResultID != claimed {
			items = append(items, diagnostics.Error("YARA-INT-027", "Result contents do not match metadata.resultId.", "metadata.resultId"))
		}
	}
	return diagnostics.NewReport(items...)
}
