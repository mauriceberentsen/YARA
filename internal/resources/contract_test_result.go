package resources

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type ContractTestResult struct {
	APIVersion string                     `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                     `json:"kind" yaml:"kind"`
	Metadata   ContractTestResultMetadata `json:"metadata" yaml:"metadata"`
	Spec       ContractTestResultSpec     `json:"spec" yaml:"spec"`
}

type ContractTestResultMetadata struct {
	Name     string `json:"name" yaml:"name"`
	ResultID string `json:"resultId" yaml:"resultId"`
}

type ContractTestResultSpec struct {
	Mode          string                  `json:"mode" yaml:"mode"`
	Outcome       string                  `json:"outcome" yaml:"outcome"`
	CatalogDigest string                  `json:"catalogDigest" yaml:"catalogDigest"`
	AssertionRef  string                  `json:"assertionRef" yaml:"assertionRef"`
	Target        ContractTestTarget      `json:"target" yaml:"target"`
	Environment   ContractTestEnvironment `json:"environment" yaml:"environment"`
	Checks        []ContractTestCheck     `json:"checks" yaml:"checks"`
	Limitations   []string                `json:"limitations" yaml:"limitations"`
}

type ContractTestTarget struct {
	RuntimeRef         string `json:"runtimeRef" yaml:"runtimeRef"`
	ModelRef           string `json:"modelRef" yaml:"modelRef"`
	HardwareProfileRef string `json:"hardwareProfileRef" yaml:"hardwareProfileRef"`
}

type ContractTestEnvironment struct {
	Transport       string                    `json:"transport" yaml:"transport"`
	ReferenceDigest string                    `json:"referenceDigest" yaml:"referenceDigest"`
	OperatingSystem string                    `json:"operatingSystem" yaml:"operatingSystem"`
	Architecture    string                    `json:"architecture" yaml:"architecture"`
	Docker          ContractTestDocker        `json:"docker" yaml:"docker"`
	Accelerators    []ContractTestAccelerator `json:"accelerators" yaml:"accelerators"`
}

type ContractTestDocker struct {
	Available       bool   `json:"available" yaml:"available"`
	Version         string `json:"version,omitempty" yaml:"version,omitempty"`
	OperatingSystem string `json:"operatingSystem,omitempty" yaml:"operatingSystem,omitempty"`
	Architecture    string `json:"architecture,omitempty" yaml:"architecture,omitempty"`
	NVIDIARuntime   bool   `json:"nvidiaRuntime" yaml:"nvidiaRuntime"`
}

type ContractTestAccelerator struct {
	Vendor            string `json:"vendor" yaml:"vendor"`
	Model             string `json:"model" yaml:"model"`
	DriverVersion     string `json:"driverVersion" yaml:"driverVersion"`
	ComputeCapability string `json:"computeCapability" yaml:"computeCapability"`
}

type ContractTestCheck struct {
	ID             string `json:"id" yaml:"id"`
	Status         string `json:"status" yaml:"status"`
	DiagnosticCode string `json:"diagnosticCode,omitempty" yaml:"diagnosticCode,omitempty"`
	EvidenceDigest string `json:"evidenceDigest" yaml:"evidenceDigest"`
}

func (r ContractTestResult) AssignResultID() (ContractTestResult, error) {
	r.Metadata.ResultID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return ContractTestResult{}, fmt.Errorf("digest contract test result: %w", err)
	}
	r.Metadata.ResultID = digest
	return r, nil
}

func (r ContractTestResult) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "ContractTestResult", "CTR", Metadata{Name: r.Metadata.Name})
	if !sha256DigestPattern.MatchString(r.Metadata.ResultID) || !sha256DigestPattern.MatchString(r.Spec.CatalogDigest) || !sha256DigestPattern.MatchString(r.Spec.Environment.ReferenceDigest) {
		items = append(items, diagnostics.Error("YARA-CTR-010", "Result, catalog and target identities must be SHA-256 digests.", "metadata.resultId"))
	}
	if r.Spec.Mode != "preflight" || !slices.Contains([]string{"passed", "failed", "blocked"}, r.Spec.Outcome) {
		items = append(items, diagnostics.Error("YARA-CTR-011", "Unsupported contract-test mode or outcome.", "spec"))
	}
	if r.Spec.AssertionRef == "" || r.Spec.Target.RuntimeRef == "" || r.Spec.Target.ModelRef == "" || r.Spec.Target.HardwareProfileRef == "" {
		items = append(items, diagnostics.Error("YARA-CTR-012", "The exact assertion, runtime, model and hardware profile are required.", "spec.target"))
	}
	if r.Spec.Environment.Transport != "ssh" || r.Spec.Environment.OperatingSystem == "" || r.Spec.Environment.Architecture == "" {
		items = append(items, diagnostics.Error("YARA-CTR-013", "SSH transport and observed operating-system facts are required.", "spec.environment"))
	}
	if r.Spec.Environment.Docker.Available && (r.Spec.Environment.Docker.Version == "" || r.Spec.Environment.Docker.OperatingSystem == "" || r.Spec.Environment.Docker.Architecture == "") {
		items = append(items, diagnostics.Error("YARA-CTR-014", "Available Docker requires version, OS and architecture facts.", "spec.environment.docker"))
	}
	previousAccelerator := ""
	for index, accelerator := range r.Spec.Environment.Accelerators {
		key := accelerator.Vendor + "\x00" + accelerator.Model + "\x00" + accelerator.DriverVersion + "\x00" + accelerator.ComputeCapability
		path := fmt.Sprintf("spec.environment.accelerators[%d]", index)
		if accelerator.Vendor == "" || accelerator.Model == "" || accelerator.DriverVersion == "" || accelerator.ComputeCapability == "" || key <= previousAccelerator {
			items = append(items, diagnostics.Error("YARA-CTR-022", "Accelerators must contain complete facts in unique sorted order.", path))
		}
		previousAccelerator = key
	}
	previous, derivedOutcome := "", "passed"
	seen := make(map[string]struct{}, len(r.Spec.Checks))
	if len(r.Spec.Checks) == 0 {
		items = append(items, diagnostics.Error("YARA-CTR-015", "At least one contract check is required.", "spec.checks"))
	}
	for index, check := range r.Spec.Checks {
		path := fmt.Sprintf("spec.checks[%d]", index)
		if strings.TrimSpace(check.ID) == "" || check.ID < previous || !slices.Contains([]string{"passed", "failed", "blocked"}, check.Status) || !sha256DigestPattern.MatchString(check.EvidenceDigest) {
			items = append(items, diagnostics.Error("YARA-CTR-016", "Checks must be identified, sorted and carry valid status and evidence.", path))
		}
		if _, exists := seen[check.ID]; exists {
			items = append(items, diagnostics.Error("YARA-CTR-017", "Check IDs must be unique.", path+".id"))
		}
		seen[check.ID] = struct{}{}
		if (check.Status == "passed" && check.DiagnosticCode != "") || (check.Status != "passed" && !diagnosticCodePattern.MatchString(check.DiagnosticCode)) {
			items = append(items, diagnostics.Error("YARA-CTR-018", "Only non-passing checks require a stable diagnostic code.", path+".diagnosticCode"))
		}
		if check.Status == "failed" {
			derivedOutcome = "failed"
		} else if check.Status == "blocked" && derivedOutcome == "passed" {
			derivedOutcome = "blocked"
		}
		previous = check.ID
	}
	if r.Spec.Outcome != derivedOutcome {
		items = append(items, diagnostics.Error("YARA-CTR-019", "Overall outcome must match the most severe check status.", "spec.outcome"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-CTR-020", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.ResultID != "" {
		claimed := r.Metadata.ResultID
		recomputed, err := r.AssignResultID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-CTR-500", "Could not recompute contract-test result identity."))
		} else if recomputed.Metadata.ResultID != claimed {
			items = append(items, diagnostics.Error("YARA-CTR-021", "Result contents do not match metadata.resultId.", "metadata.resultId"))
		}
	}
	return diagnostics.NewReport(items...)
}

func hasDuplicateStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}
