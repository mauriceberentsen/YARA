package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/contracttest"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
	"gopkg.in/yaml.v3"
)

var contractProbe contracttest.Probe = contracttest.SSHProbe{}
var runtimeSmokeArtifactVerifier contracttest.ArtifactVerifier = contracttest.RegistryArtifactVerifier{}
var runtimeSmokeRunner contracttest.RuntimeSmokeRunner = contracttest.SSHRuntimeSmokeRunner{}
var modelInferenceRunner contracttest.ModelInferenceRunner = contracttest.SSHModelInferenceRunner{}

type contractPreflightOptions struct {
	catalogPath string
	assertionID string
	target      string
	name        string
	outputPath  string
	auditPath   string
}

func preflightContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseContractOptions("contract preflight", args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeContractPreflightFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-CAT-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeContractPreflightFailure(stdout, options, nil, "YARA-CAT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	target, found := snapshot.ContractTarget(options.assertionID)
	if !found {
		return writeContractPreflightFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a testable positive compatibility assertion", options.assertionID), ExitInvalidInput)
	}
	environment, err := contractProbe.Observe(context.Background(), options.target)
	if err != nil {
		return writeContractPreflightFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-108", err, ExitInfeasible)
	}
	auditTarget := "ssh:" + environment.ReferenceDigest
	result, err := contracttest.Evaluate(options.name, catalogDigest, target, environment)
	if err != nil {
		return writeContractPreflightFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	result, err = bindContractRunner(result)
	if err != nil {
		return writeContractPreflightFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeContractPreflightReportFailure(stdout, options, auditTarget, []audit.Subject{catalogSubject}, report, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeContractPreflightFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", fmt.Errorf("encode contract test result: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeContractPreflightFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-005", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, "contract.preflight", suffix, auditOutcome, auditTarget, []audit.Subject{catalogSubject, resultSubject}, contractDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	response := map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return exitCode
}

func runtimeSmokeContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseContractOptions("contract runtime-smoke", args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeContractRuntimeFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-CAT-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeContractRuntimeFailure(stdout, options, nil, "YARA-CAT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	target, found := snapshot.ContractTarget(options.assertionID)
	if !found {
		return writeContractRuntimeFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a testable positive compatibility assertion", options.assertionID), ExitInvalidInput)
	}
	ctx := context.Background()
	artifactChecks, err := runtimeSmokeArtifactVerifier.Verify(ctx, target)
	if err != nil {
		return writeContractRuntimeFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-130", err, ExitInfeasible)
	}
	environment, err := contractProbe.Observe(ctx, options.target)
	if err != nil {
		return writeContractRuntimeFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-108", err, ExitInfeasible)
	}
	auditTarget := "ssh:" + environment.ReferenceDigest
	preflight, err := contracttest.Evaluate(options.name, catalogDigest, target, environment)
	if err != nil {
		return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	var runtimeChecks []resources.ContractTestCheck
	if preflight.Spec.Outcome == "passed" && checksPassed(artifactChecks) {
		runtimeChecks, err = runtimeSmokeRunner.Run(ctx, options.target, target)
		if err != nil {
			return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-131", err, ExitInfeasible)
		}
	}
	result, err := contracttest.EvaluateRuntimeSmoke(options.name, catalogDigest, target, environment, artifactChecks, runtimeChecks)
	if err != nil {
		return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	result, err = bindContractRunner(result)
	if err != nil {
		return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeContractRuntimeReportFailure(stdout, options, auditTarget, []audit.Subject{catalogSubject}, report, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", fmt.Errorf("encode contract test result: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-005", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, "contract.runtime-smoke", suffix, auditOutcome, auditTarget, []audit.Subject{catalogSubject, resultSubject}, contractDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	response := map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return exitCode
}

func modelInferenceContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseContractOptions("contract model-inference", args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeContractModelFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-CAT-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeContractModelFailure(stdout, options, nil, "YARA-CAT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	target, found := snapshot.ContractTarget(options.assertionID)
	if !found {
		return writeContractModelFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a testable positive compatibility assertion", options.assertionID), ExitInvalidInput)
	}
	ctx := context.Background()
	artifactChecks, err := runtimeSmokeArtifactVerifier.Verify(ctx, target)
	if err != nil {
		return writeContractModelFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-130", err, ExitInfeasible)
	}
	environment, err := contractProbe.Observe(ctx, options.target)
	if err != nil {
		return writeContractModelFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-108", err, ExitInfeasible)
	}
	auditTarget := "ssh:" + environment.ReferenceDigest
	preflight, err := contracttest.Evaluate(options.name, catalogDigest, target, environment)
	if err != nil {
		return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	var modelChecks []resources.ContractTestCheck
	if preflight.Spec.Outcome == "passed" && checksPassed(artifactChecks) {
		modelChecks, err = modelInferenceRunner.Run(ctx, options.target, target)
		if err != nil {
			return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-152", err, ExitInfeasible)
		}
	}
	result, err := contracttest.EvaluateModelInference(options.name, catalogDigest, target, environment, artifactChecks, modelChecks)
	if err != nil {
		return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	result, err = bindContractRunner(result)
	if err != nil {
		return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeContractModelReportFailure(stdout, options, auditTarget, []audit.Subject{catalogSubject}, report, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", fmt.Errorf("encode contract test result: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-005", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, "contract.model-inference", suffix, auditOutcome, auditTarget, []audit.Subject{catalogSubject, resultSubject}, contractDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	response := map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return exitCode
}

func checksPassed(checks []resources.ContractTestCheck) bool {
	for _, item := range checks {
		if item.Status != "passed" {
			return false
		}
	}
	return len(checks) > 0
}

func bindContractRunner(result resources.ContractTestResult) (resources.ContractTestResult, error) {
	executable, err := os.Executable()
	if err != nil {
		return resources.ContractTestResult{}, fmt.Errorf("locate contract runner executable: %w", err)
	}
	file, err := os.Open(executable)
	if err != nil {
		return resources.ContractTestResult{}, fmt.Errorf("open contract runner executable: %w", err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return resources.ContractTestResult{}, fmt.Errorf("digest contract runner executable: %w", err)
	}
	result.Metadata.ResultID = ""
	result.Spec.Runner = &resources.ContractTestRunner{Version: version.Version, BinaryDigest: fmt.Sprintf("sha256:%x", digest.Sum(nil))}
	return result.AssignResultID()
}

func parseContractOptions(command string, args []string, stderr io.Writer) (contractPreflightOptions, bool) {
	var options contractPreflightOptions
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.assertionID, "assertion", "", "CompatibilityAssertion identifier")
	flags.StringVar(&options.target, "target", "", "SSH target in user@host form")
	flags.StringVar(&options.name, "name", "", "DNS-style ContractTestResult name")
	flags.StringVar(&options.outputPath, "output", "", "Generated ContractTestResult YAML file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.assertionID == "" || options.target == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintf(stderr, "%s requires --catalog, --assertion, --target, --name, --output and --audit-output\n", command)
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}

func contractDiagnosticCodes(result resources.ContractTestResult) []string {
	codes := make([]string, 0)
	for _, check := range result.Spec.Checks {
		if check.DiagnosticCode != "" {
			codes = append(codes, check.DiagnosticCode)
		}
	}
	return uniqueSortedStrings(codes)
}

func writeContractPreflightFailure(output io.Writer, options contractPreflightOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	return writeContractPreflightFailureForTarget(output, options, "ssh:"+digestBytes([]byte(options.target)), subjects, code, err, exitCode)
}

func writeContractPreflightFailureForTarget(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.preflight", "failed", "failed", auditTarget, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}

func writeContractPreflightReportFailure(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.preflight", "failed", "failed", auditTarget, subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, report, exitCode)
}

func writeContractRuntimeFailure(output io.Writer, options contractPreflightOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	return writeContractRuntimeFailureForTarget(output, options, "ssh:"+digestBytes([]byte(options.target)), subjects, code, err, exitCode)
}

func writeContractRuntimeFailureForTarget(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.runtime-smoke", "failed", "failed", auditTarget, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}

func writeContractRuntimeReportFailure(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.runtime-smoke", "failed", "failed", auditTarget, subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, report, exitCode)
}

func writeContractModelFailure(output io.Writer, options contractPreflightOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	return writeContractModelFailureForTarget(output, options, "ssh:"+digestBytes([]byte(options.target)), subjects, code, err, exitCode)
}

func writeContractModelFailureForTarget(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.model-inference", "failed", "failed", auditTarget, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}

func writeContractModelReportFailure(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.model-inference", "failed", "failed", auditTarget, subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, report, exitCode)
}
