package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/debugbundle"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type debugBundleOptions struct {
	planPath   string
	outputPath string
	auditPath  string
}

type debugBundleResult struct {
	Valid       bool                           `json:"valid"`
	BundleID    string                         `json:"bundleId"`
	Output      string                         `json:"output"`
	AuditOutput string                         `json:"auditOutput"`
	Contents    []resources.DebugBundleContent `json:"contents"`
}

func createDebugBundle(args []string, stdout, stderr io.Writer) int {
	options, ok := parseDebugBundleOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	plan, err := resources.LoadPlatformPlan(options.planPath)
	if err != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "debug.bundle", "PlatformPlan", options.planPath, "YARA-PLAN-004", err, nil)
	}
	inputSubject, err := canonicalSubject("PlatformPlan", plan)
	if err != nil {
		return writeLoadError(stdout, "YARA-AUD-500", err)
	}
	if report := plan.Validate(); !report.Valid {
		return writeDebugBundleFailure(stdout, options.auditPath, []audit.Subject{inputSubject}, report, ExitInvalidInput)
	}
	planSubject := audit.Subject{Kind: "PlatformPlan", Digest: plan.Metadata.PlanID}
	bundle, report := debugbundle.Build(plan)
	if !report.Valid {
		return writeDebugBundleFailure(stdout, options.auditPath, []audit.Subject{planSubject}, report, ExitInvalidInput)
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return writeDebugBundleInternalFailure(stdout, options.auditPath, []audit.Subject{planSubject}, "YARA-DBG-500", fmt.Errorf("encode debug bundle: %w", err), ExitInternal)
	}
	data = append(data, '\n')
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeDebugBundleInternalFailure(stdout, options.auditPath, []audit.Subject{planSubject}, "YARA-DBG-005", err, ExitInvalidInput)
	}
	bundleSubject := audit.Subject{Kind: "DebugBundle", Digest: bundle.Metadata.BundleID}
	if err := persistOperationAudit(options.auditPath, "debug.bundle", "completed", "success", []audit.Subject{planSubject, bundleSubject}, diagnosticCodes(plan.Spec.Diagnostics)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(debugBundleResult{
		Valid: true, BundleID: bundle.Metadata.BundleID, Output: options.outputPath,
		AuditOutput: options.auditPath, Contents: bundle.Spec.Contents,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseDebugBundleOptions(args []string, stderr io.Writer) (debugBundleOptions, bool) {
	var options debugBundleOptions
	flags := flag.NewFlagSet("debug bundle", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.planPath, "plan", "", "Validated PlatformPlan file")
	flags.StringVar(&options.outputPath, "output", "", "Generated redacted DebugBundle file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.planPath == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "debug bundle requires --plan, --output and --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}

func writeDebugBundleFailure(output io.Writer, auditPath string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if err := persistOperationAudit(auditPath, "debug.bundle", "failed", "failed", subjects, diagnosticCodes(report.Diagnostics)); err != nil {
		return writeLoadError(output, "YARA-AUD-005", err)
	}
	return writeReport(output, report, exitCode)
}

func writeDebugBundleInternalFailure(output io.Writer, auditPath string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAudit(auditPath, "debug.bundle", "failed", "failed", subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}
