package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
)

const (
	ExitSuccess      = 0
	ExitInvalidInput = 2
	ExitInfeasible   = 3
	ExitInternal     = 4
	ExitUnsupported  = 5
)

type validationResult struct {
	Valid      bool   `json:"valid"`
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
}

type auditVerificationResult struct {
	Valid      bool   `json:"valid"`
	Events     int    `json:"events"`
	HeadDigest string `json:"headDigest"`
}

type catalogValidationResult struct {
	Valid       bool                     `json:"valid"`
	APIVersion  string                   `json:"apiVersion"`
	Kind        string                   `json:"kind"`
	Name        string                   `json:"name"`
	Version     string                   `json:"version"`
	Digest      string                   `json:"digest"`
	Candidates  int                      `json:"candidates"`
	Diagnostics []diagnostics.Diagnostic `json:"diagnostics"`
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(stdout, version.Version)
		return ExitSuccess
	}
	if len(args) == 3 && args[0] == "audit" && args[1] == "verify" {
		return verifyAudit(args[2], stdout)
	}
	if len(args) >= 2 && args[0] == "plan" && args[1] == "create" {
		return createPlan(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "plan" && args[1] == "diff" {
		return diffPlan(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "plan" && args[1] == "explain" {
		return explainPlan(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "debug" && args[1] == "bundle" {
		return createDebugBundle(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "scenario" && args[1] == "validate" {
		return validateScenario(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "scenario" && args[1] == "validate-all" {
		return validateScenarioSuite(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "preflight" {
		return preflightContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "runtime-smoke" {
		return runtimeSmokeContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "model-inference" {
		return modelInferenceContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "capacity-boundary" {
		return capacityBoundaryContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "sustained-capacity" {
		return sustainedCapacityContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "policy" {
		return policyContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "lifecycle" {
		return lifecycleContract(args[2:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "catalog" && args[1] == "coverage" && args[2] == "create" {
		return catalogCoverage(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "catalog" && args[1] == "coverage" && args[2] == "validate" {
		return validateCatalogCoverage(args[3:], stdout, stderr)
	}
	if len(args) < 2 || args[1] != "validate" {
		writeUsage(stderr)
		return ExitInvalidInput
	}
	options, ok := parseValidationOptions(args[2:], stderr)
	if !ok {
		return ExitInvalidInput
	}

	switch args[0] {
	case "request":
		request, err := resources.LoadPlatformRequest(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "request.validate", "PlatformRequest", options.inputPath, "YARA-REQ-004", err, nil)
		}
		subject, err := canonicalSubject("PlatformRequest", request)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "request.validate", subject, request.APIVersion, request.Kind, request.Metadata.Name, request.Validate())
	case "inventory":
		inventory, err := resources.LoadInventory(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "inventory.validate", "Inventory", options.inputPath, "YARA-INV-004", err, nil)
		}
		subject, err := canonicalSubject("Inventory", inventory)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "inventory.validate", subject, inventory.APIVersion, inventory.Kind, inventory.Metadata.Name, inventory.Validate())
	case "catalog":
		snapshot, err := catalog.Load(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "catalog.validate", "CatalogSnapshot", options.inputPath, "YARA-CAT-004", err, nil)
		}
		digest, err := snapshot.Digest()
		if err != nil {
			return writeLoadError(stdout, "YARA-CAT-500", err)
		}
		if err := writeCatalogValidationAudit(options.auditPath, audit.Subject{Kind: "CatalogSnapshot", Digest: digest}, snapshot.Diagnostics()); err != nil {
			return writeLoadError(stdout, "YARA-AUD-005", err)
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(catalogValidationResult{
			Valid: true, APIVersion: snapshot.APIVersion, Kind: snapshot.Kind,
			Name: snapshot.Metadata.Name, Version: snapshot.Metadata.Version,
			Digest: digest, Candidates: len(snapshot.Candidates()), Diagnostics: snapshot.Diagnostics(),
		}); err != nil {
			return ExitInternal
		}
		return ExitSuccess
	case "plan":
		plan, err := resources.LoadPlatformPlan(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "plan.validate", "PlatformPlan", options.inputPath, "YARA-PLAN-004", err, nil)
		}
		subject, err := canonicalSubject("PlatformPlan", plan)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "plan.validate", subject, plan.APIVersion, plan.Kind, plan.Metadata.Name, plan.Validate())
	case "contract":
		result, err := resources.LoadContractTestResult(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "contract.validate", "ContractTestResult", options.inputPath, "YARA-CTR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("ContractTestResult", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "contract.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	default:
		writeUsage(stderr)
		return ExitUnsupported
	}
}

func verifyAudit(path string, output io.Writer) int {
	events, err := audit.LoadJSONL(path)
	if err != nil {
		return writeLoadError(output, "YARA-AUD-004", err)
	}
	head, err := audit.Verify(events)
	if err != nil {
		return writeLoadError(output, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(auditVerificationResult{Valid: true, Events: len(events), HeadDigest: head}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func writeValidation(output io.Writer, apiVersion, kind, name string, report diagnostics.Report) int {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if report.Valid {
		if err := encoder.Encode(validationResult{Valid: true, APIVersion: apiVersion, Kind: kind, Name: name}); err != nil {
			return ExitInternal
		}
		return ExitSuccess
	}
	if err := encoder.Encode(report); err != nil {
		return ExitInternal
	}
	return ExitInvalidInput
}

func writeLoadError(output io.Writer, code string, err error) int {
	report := diagnostics.NewReport(diagnostics.Error(code, err.Error()))
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if encodeErr := encoder.Encode(report); encodeErr != nil {
		return ExitInternal
	}
	return ExitInvalidInput
}

func writeUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  yara version")
	fmt.Fprintln(output, "  yara request validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara inventory validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara catalog validate <snapshot-file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara catalog coverage create --catalog <file> --evidence-dir <directory> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara catalog coverage validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara plan create --request <file> --inventory <file> --catalog <file> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara plan validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara plan explain <file> [--decision <id>] [--audit-output <file>]")
	fmt.Fprintln(output, "  yara plan diff <from-file> <to-file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara debug bundle --plan <file> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara scenario validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara scenario validate-all <directory> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara contract preflight --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract runtime-smoke --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract model-inference --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract capacity-boundary --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract sustained-capacity --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract policy --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract lifecycle --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara audit verify <file>")
}
