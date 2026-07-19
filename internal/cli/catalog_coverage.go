package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
	"gopkg.in/yaml.v3"
)

type catalogCoverageOptions struct {
	catalogPath string
	evidenceDir string
	name        string
	outputPath  string
	auditPath   string
}

func catalogCoverage(args []string, stdout, stderr io.Writer) int {
	options, ok := parseCatalogCoverageOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-COV-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeCatalogCoverageFailure(stdout, options, nil, "YARA-COV-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	report, err := catalogcoverage.Build(options.name, snapshot, options.evidenceDir)
	if err != nil {
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-COV-005", err, ExitInvalidInput)
	}
	if err := report.Validate(); err != nil {
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-COV-500", err, ExitInternal)
	}
	data, err := yaml.Marshal(report)
	if err != nil {
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-COV-500", fmt.Errorf("encode catalog coverage report: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-COV-006", err, ExitInvalidInput)
	}
	reportSubject := audit.Subject{Kind: catalogcoverage.Kind, Digest: report.Metadata.ReportID}
	if err := persistOperationAudit(options.auditPath, "catalog.coverage", "completed", "success", []audit.Subject{catalogSubject, reportSubject}, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid": true, "complete": report.Spec.Complete, "reportId": report.Metadata.ReportID,
		"output": options.outputPath, "auditOutput": options.auditPath, "summary": report.Spec.Summary,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func validateCatalogCoverage(args []string, stdout, stderr io.Writer) int {
	options, ok := parseValidationOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	report, err := catalogcoverage.Load(options.inputPath)
	if err != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "catalog.coverage.validate", catalogcoverage.Kind, options.inputPath, "YARA-COV-004", err, nil)
	}
	subject := audit.Subject{Kind: catalogcoverage.Kind, Digest: report.Metadata.ReportID}
	if err := persistOperationAudit(options.auditPath, "catalog.coverage.validate", "completed", "success", []audit.Subject{subject}, nil); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid": true, "apiVersion": report.APIVersion, "kind": report.Kind, "name": report.Metadata.Name,
		"reportId": report.Metadata.ReportID, "complete": report.Spec.Complete,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseCatalogCoverageOptions(args []string, stderr io.Writer) (catalogCoverageOptions, bool) {
	var options catalogCoverageOptions
	flags := flag.NewFlagSet("catalog coverage create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.evidenceDir, "evidence-dir", "", "Directory containing ContractTestResult YAML and adjacent audit chains")
	flags.StringVar(&options.name, "name", "", "CatalogCoverageReport name")
	flags.StringVar(&options.outputPath, "output", "", "Generated CatalogCoverageReport YAML file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.evidenceDir == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "catalog coverage create requires --catalog, --evidence-dir, --name, --output and --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}

func writeCatalogCoverageFailure(output io.Writer, options catalogCoverageOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAudit(options.auditPath, "catalog.coverage", "failed", "failed", subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}

func writeLoadErrorWithExit(output io.Writer, code string, err error, exitCode int) int {
	_ = json.NewEncoder(output).Encode(map[string]any{
		"valid":       false,
		"diagnostics": []map[string]string{{"code": code, "severity": "error", "message": err.Error()}},
	})
	return exitCode
}
