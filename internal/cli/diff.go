package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/plandiff"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type planDiffOptions struct {
	fromPath  string
	toPath    string
	auditPath string
}

func diffPlan(args []string, stdout, stderr io.Writer) int {
	options, ok := parsePlanDiffOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	from, err := resources.LoadPlatformPlan(options.fromPath)
	if err != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "plan.diff", "PlatformPlanFrom", options.fromPath, "YARA-PLAN-004", err, nil)
	}
	fromSubject, err := validatedDiffInput("PlatformPlanFrom", from, options.auditPath, stdout)
	if err != nil {
		return ExitInvalidInput
	}
	to, loadErr := resources.LoadPlatformPlan(options.toPath)
	if loadErr != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "plan.diff", "PlatformPlanTo", options.toPath, "YARA-PLAN-004", loadErr, []audit.Subject{fromSubject})
	}
	toSubject, err := validatedDiffInput("PlatformPlanTo", to, options.auditPath, stdout, fromSubject)
	if err != nil {
		return ExitInvalidInput
	}

	diff, err := plandiff.Compare(from, to)
	if err != nil {
		return writeDiffFailure(stdout, options.auditPath, "YARA-DIFF-500", err, []audit.Subject{fromSubject, toSubject}, ExitInternal)
	}
	if report := diff.Validate(); !report.Valid {
		if auditErr := persistOperationAudit(options.auditPath, "plan.diff", "failed", "failed", []audit.Subject{fromSubject, toSubject}, diagnosticCodes(report.Diagnostics)); auditErr != nil {
			return writeLoadError(stdout, "YARA-AUD-005", auditErr)
		}
		return writeReport(stdout, report, ExitInternal)
	}
	diffSubject := audit.Subject{Kind: "PlatformPlanDiff", Digest: diff.Metadata.DiffID}
	planDiagnostics := append(append([]diagnostics.Diagnostic{}, from.Spec.Diagnostics...), to.Spec.Diagnostics...)
	if err := persistOperationAudit(options.auditPath, "plan.diff", "completed", "success", []audit.Subject{fromSubject, toSubject, diffSubject}, diagnosticCodes(planDiagnostics)); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(diff); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parsePlanDiffOptions(args []string, stderr io.Writer) (planDiffOptions, bool) {
	if len(args) == 2 && args[0] != "" && args[1] != "" {
		return planDiffOptions{fromPath: args[0], toPath: args[1]}, true
	}
	if len(args) == 4 && args[0] != "" && args[1] != "" && args[2] == "--audit-output" && args[3] != "" {
		return planDiffOptions{fromPath: args[0], toPath: args[1], auditPath: args[3]}, true
	}
	writeUsage(stderr)
	return planDiffOptions{}, false
}

func validatedDiffInput(kind string, plan resources.PlatformPlan, auditPath string, output io.Writer, available ...audit.Subject) (audit.Subject, error) {
	subject, err := canonicalSubject(kind, plan)
	if err != nil {
		writeLoadError(output, "YARA-AUD-500", err)
		return audit.Subject{}, err
	}
	if report := plan.Validate(); !report.Valid {
		subjects := append(append([]audit.Subject{}, available...), subject)
		if auditErr := persistOperationAudit(auditPath, "plan.diff", "failed", "failed", subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
			writeLoadError(output, "YARA-AUD-005", auditErr)
			return audit.Subject{}, auditErr
		}
		writeReport(output, report, ExitInvalidInput)
		return audit.Subject{}, fmt.Errorf("%s is invalid", kind)
	}
	return audit.Subject{Kind: kind, Digest: plan.Metadata.PlanID}, nil
}

func writeDiffFailure(output io.Writer, auditPath, code string, err error, subjects []audit.Subject, exitCode int) int {
	if auditErr := persistOperationAudit(auditPath, "plan.diff", "failed", "failed", subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	report := diagnostics.NewReport(diagnostics.Error(code, err.Error()))
	return writeReport(output, report, exitCode)
}
