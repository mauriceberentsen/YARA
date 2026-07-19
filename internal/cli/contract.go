package cli

import (
	"context"
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
	"gopkg.in/yaml.v3"
)

var contractProbe contracttest.Probe = contracttest.SSHProbe{}

type contractPreflightOptions struct {
	catalogPath string
	assertionID string
	target      string
	name        string
	outputPath  string
	auditPath   string
}

func preflightContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseContractPreflightOptions(args, stderr)
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
		return writeContractPreflightFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a selectable supported compatibility assertion", options.assertionID), ExitInvalidInput)
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

func parseContractPreflightOptions(args []string, stderr io.Writer) (contractPreflightOptions, bool) {
	var options contractPreflightOptions
	flags := flag.NewFlagSet("contract preflight", flag.ContinueOnError)
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
		fmt.Fprintln(stderr, "contract preflight requires --catalog, --assertion, --target, --name, --output and --audit-output")
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
