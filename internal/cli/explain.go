package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type planExplainOptions struct {
	planPath   string
	decisionID string
	auditPath  string
}

func explainPlan(args []string, stdout, stderr io.Writer) int {
	options, ok := parsePlanExplainOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	plan, err := resources.LoadPlatformPlan(options.planPath)
	if err != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "plan.explain", "PlatformPlan", options.planPath, "YARA-PLAN-004", err, nil)
	}
	inputSubject, err := canonicalSubject("PlatformPlan", plan)
	if err != nil {
		return writeLoadError(stdout, "YARA-AUD-500", err)
	}
	if report := plan.Validate(); !report.Valid {
		if auditErr := persistOperationAudit(options.auditPath, "plan.explain", "failed", "failed", []audit.Subject{inputSubject}, diagnosticCodes(report.Diagnostics)); auditErr != nil {
			return writeLoadError(stdout, "YARA-AUD-005", auditErr)
		}
		return writeReport(stdout, report, ExitInvalidInput)
	}

	planSubject := audit.Subject{Kind: "PlatformPlan", Digest: plan.Metadata.PlanID}
	value, outputSubject, report := selectPlanExplanation(plan, options.decisionID)
	if !report.Valid {
		if auditErr := persistOperationAudit(options.auditPath, "plan.explain", "failed", "failed", []audit.Subject{planSubject}, diagnosticCodes(report.Diagnostics)); auditErr != nil {
			return writeLoadError(stdout, "YARA-AUD-005", auditErr)
		}
		return writeReport(stdout, report, ExitInvalidInput)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return writeLoadError(stdout, "YARA-PLAN-500", fmt.Errorf("encode plan explanation: %w", err))
	}
	if err := persistOperationAudit(options.auditPath, "plan.explain", "completed", "success", []audit.Subject{planSubject, outputSubject}, diagnosticCodes(plan.Spec.Diagnostics)); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	if _, err := fmt.Fprintln(stdout, string(data)); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parsePlanExplainOptions(args []string, stderr io.Writer) (planExplainOptions, bool) {
	var options planExplainOptions
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		writeUsage(stderr)
		return options, false
	}
	options.planPath = args[0]
	decisionSet, auditSet := false, false
	for index := 1; index < len(args); index += 2 {
		if index+1 >= len(args) || strings.TrimSpace(args[index+1]) == "" {
			writeUsage(stderr)
			return planExplainOptions{}, false
		}
		switch args[index] {
		case "--decision":
			if decisionSet {
				writeUsage(stderr)
				return planExplainOptions{}, false
			}
			decisionSet = true
			options.decisionID = args[index+1]
		case "--audit-output":
			if auditSet {
				writeUsage(stderr)
				return planExplainOptions{}, false
			}
			auditSet = true
			options.auditPath = args[index+1]
		default:
			writeUsage(stderr)
			return planExplainOptions{}, false
		}
	}
	return options, true
}

func selectPlanExplanation(plan resources.PlatformPlan, decisionID string) (any, audit.Subject, diagnostics.Report) {
	if decisionID == "" {
		subject, err := canonicalSubject("PlatformPlanDecisions", plan.Spec.Decisions)
		if err != nil {
			return nil, audit.Subject{}, diagnostics.NewReport(diagnostics.Error("YARA-AUD-500", err.Error()))
		}
		return plan.Spec.Decisions, subject, diagnostics.NewReport()
	}
	for _, decision := range plan.Spec.Decisions {
		if decision.ID != decisionID {
			continue
		}
		subject, err := canonicalSubject("PlanDecision", decision)
		if err != nil {
			return nil, audit.Subject{}, diagnostics.NewReport(diagnostics.Error("YARA-AUD-500", err.Error()))
		}
		return decision, subject, diagnostics.NewReport()
	}
	return nil, audit.Subject{}, diagnostics.NewReport(diagnostics.Error(
		"YARA-PLAN-040",
		"The requested plan decision does not exist.",
		"spec.decisions",
	))
}
