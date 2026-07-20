package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type lifecycleProofRecordOptions struct {
	applyReceiptPath, retirementReceiptPath, rollbackReceiptPath string
	reviewerRole, decision, reasonReference                      string
	name, outputPath, auditPath                                  string
	maxReceiptAge                                                time.Duration
}

func recordLifecycleProof(args []string, stdout, stderr io.Writer) int {
	options, ok := parseLifecycleProofRecordOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	applyReceipt, err := resources.LoadDeploymentReceipt(options.applyReceiptPath)
	if err != nil || !applyReceipt.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-LGR-101", errors.New("deployment apply receipt is invalid"), ExitInvalidInput)
	}
	retirementReceipt, err := resources.LoadRetirementReceipt(options.retirementReceiptPath)
	if err != nil || !retirementReceipt.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-LGR-102", errors.New("retirement receipt is invalid"), ExitInvalidInput)
	}
	rollbackReceipt, err := resources.LoadRollbackReceipt(options.rollbackReceiptPath)
	if err != nil || !rollbackReceipt.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-LGR-103", errors.New("rollback receipt is invalid"), ExitInvalidInput)
	}
	target := "kubernetes:" + applyReceipt.Spec.Target.ReferenceDigest
	if applyReceipt.Spec.PlanID != retirementReceipt.Spec.PlanID || applyReceipt.Spec.PlanID != rollbackReceipt.Spec.PlanID ||
		applyReceipt.Spec.BundleID != retirementReceipt.Spec.BundleID || applyReceipt.Spec.BundleID != rollbackReceipt.Spec.BundleID ||
		applyReceipt.Spec.Target.ReferenceDigest != retirementReceipt.Spec.Target.ReferenceDigest || applyReceipt.Spec.Target.ReferenceDigest != rollbackReceipt.Spec.Target.ReferenceDigest {
		return writeLifecycleProofFailure(stdout, options.auditPath, target, lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), "YARA-LGR-104", errors.New("receipt chain is foreign: plan, bundle or target mismatch"), ExitInfeasible)
	}
	completedApply, applyErr := time.Parse(time.RFC3339Nano, applyReceipt.Spec.CompletedAt)
	completedRetire, retireErr := time.Parse(time.RFC3339Nano, retirementReceipt.Spec.CompletedAt)
	completedRollback, rollbackErr := time.Parse(time.RFC3339Nano, rollbackReceipt.Spec.CompletedAt)
	if applyErr != nil || retireErr != nil || rollbackErr != nil {
		return writeLifecycleProofFailure(stdout, options.auditPath, target, lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), "YARA-LGR-105", errors.New("receipt timestamps must be RFC3339 for lifecycle linkage"), ExitInvalidInput)
	}
	if !(completedApply.Before(completedRetire) && completedRetire.Before(completedRollback)) {
		return writeLifecycleProofFailure(stdout, options.auditPath, target, lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), "YARA-LGR-106", errors.New("receipt chain is incomplete: apply->retire->rollback completion order is required"), ExitInfeasible)
	}
	if applyReceipt.Spec.Outcome != "succeeded" || retirementReceipt.Spec.Outcome != "succeeded" || rollbackReceipt.Spec.Outcome != "succeeded" {
		return writeLifecycleProofFailure(stdout, options.auditPath, target, lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), "YARA-LGR-106", errors.New("receipt chain is incomplete: all lifecycle receipts must be succeeded"), ExitInfeasible)
	}
	now := time.Now().UTC()
	for _, stage := range []struct {
		name      string
		completed time.Time
	}{
		{name: "apply", completed: completedApply},
		{name: "retire", completed: completedRetire},
		{name: "rollback", completed: completedRollback},
	} {
		if stage.completed.After(now) || now.Sub(stage.completed) > options.maxReceiptAge {
			return writeLifecycleProofFailure(stdout, options.auditPath, target, lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), "YARA-LGR-107", fmt.Errorf("%s receipt is stale for lifecycle proof recording", stage.name), ExitInfeasible)
		}
	}
	decision := strings.TrimSpace(options.decision)
	if decision == "approve" {
		decision = resources.PromotionDecisionApproved
	} else if decision == "reject" {
		decision = resources.PromotionDecisionChangesRequired
	}
	if !validPromotionDecisionCLI(decision) {
		return writeLifecycleProofFailure(stdout, options.auditPath, target, lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), "YARA-LGR-108", errors.New("decision must be approved, changes-required or abstained"), ExitInvalidInput)
	}
	actorID, assurance := localActor()
	ledger := resources.LifecycleProofLedger{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofLedger",
		Metadata: resources.LifecycleProofLedgerMeta{
			Name: options.name,
		},
		Spec: resources.LifecycleProofLedgerSpec{
			RecordedAt:            now.Format(time.RFC3339Nano),
			PlanID:                applyReceipt.Spec.PlanID,
			BundleID:              applyReceipt.Spec.BundleID,
			TargetReferenceDigest: applyReceipt.Spec.Target.ReferenceDigest,
			Reviewer: resources.ReviewerRecord{
				Identity:  actorID,
				Role:      options.reviewerRole,
				Assurance: assurance,
			},
			Decision:        decision,
			ReasonReference: options.reasonReference,
			Stages: []resources.LifecycleProofLedgerStage{
				{
					Stage:                  resources.LifecycleStageApply,
					ReceiptID:              applyReceipt.Metadata.ReceiptID,
					ExecutionCorrelationID: applyReceipt.Spec.ExecutionCorrelationID,
					Outcome:                applyReceipt.Spec.Outcome,
					CompletedAt:            applyReceipt.Spec.CompletedAt,
				},
				{
					Stage:                  resources.LifecycleStageRetire,
					ReceiptID:              retirementReceipt.Metadata.ReceiptID,
					ExecutionCorrelationID: retirementReceipt.Spec.ExecutionCorrelationID,
					Outcome:                retirementReceipt.Spec.Outcome,
					CompletedAt:            retirementReceipt.Spec.CompletedAt,
				},
				{
					Stage:                  resources.LifecycleStageRollback,
					ReceiptID:              rollbackReceipt.Metadata.ReceiptID,
					ExecutionCorrelationID: rollbackReceipt.Spec.ExecutionCorrelationID,
					Outcome:                rollbackReceipt.Spec.Outcome,
					CompletedAt:            rollbackReceipt.Spec.CompletedAt,
				},
			},
			Limitations: []string{
				"Lifecycle proof ledger links immutable lifecycle receipt identities only.",
				"Lifecycle proof ledger recording has no mutation authority.",
			},
		},
	}
	slices.Sort(ledger.Spec.Limitations)
	ledger, err = ledger.AssignLedgerID()
	if err != nil {
		return writeLifecycleProofFailure(stdout, options.auditPath, target, lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), "YARA-LGR-500", err, ExitInternal)
	}
	if report := ledger.Validate(); !report.Valid {
		return writeLifecycleProofFailure(stdout, options.auditPath, target, lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), "YARA-LGR-500", errors.New("constructed lifecycle proof ledger is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(ledger)
	if err != nil {
		return writeLifecycleProofFailure(stdout, options.auditPath, target, lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), "YARA-LGR-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeLifecycleProofFailure(stdout, options.auditPath, target, lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), "YARA-LGR-109", err, ExitInvalidInput)
	}
	subjects := append(lifecycleProofSubjects(applyReceipt, retirementReceipt, rollbackReceipt), audit.Subject{Kind: "LifecycleProofLedger", Digest: ledger.Metadata.LedgerID})
	if err := persistOperationAuditForTarget(options.auditPath, "lifecycle.proof.record", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":       true,
		"ledgerId":    ledger.Metadata.LedgerID,
		"planId":      ledger.Spec.PlanID,
		"bundleId":    ledger.Spec.BundleID,
		"output":      options.outputPath,
		"auditOutput": options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseLifecycleProofRecordOptions(args []string, stderr io.Writer) (lifecycleProofRecordOptions, bool) {
	var options lifecycleProofRecordOptions
	flags := flag.NewFlagSet("lifecycle proof record", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.applyReceiptPath, "apply-receipt", "", "Validated DeploymentReceipt from apply execution")
	flags.StringVar(&options.retirementReceiptPath, "retirement-receipt", "", "Validated RetirementReceipt from retire execution")
	flags.StringVar(&options.rollbackReceiptPath, "rollback-receipt", "", "Validated RollbackReceipt from rollback execution")
	flags.StringVar(&options.reviewerRole, "reviewer-role", "", "Independent reviewer role")
	flags.StringVar(&options.decision, "decision", "", "Review decision: approved|changes-required|abstained")
	flags.StringVar(&options.reasonReference, "reason-reference", "", "Non-secret review reason reference")
	flags.StringVar(&options.name, "name", "", "LifecycleProofLedger name")
	flags.StringVar(&options.outputPath, "output", "", "Generated LifecycleProofLedger YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated lifecycle proof audit JSONL output")
	flags.DurationVar(&options.maxReceiptAge, "max-receipt-age", 30*24*time.Hour, "Maximum age for linked lifecycle receipts")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.applyReceiptPath == "" || options.retirementReceiptPath == "" || options.rollbackReceiptPath == "" || options.reviewerRole == "" || options.decision == "" || options.reasonReference == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "lifecycle proof record requires --apply-receipt --retirement-receipt --rollback-receipt --reviewer-role --decision --reason-reference --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	if options.maxReceiptAge <= 0 {
		fmt.Fprintln(stderr, "--max-receipt-age must be greater than zero")
		return options, false
	}
	return options, true
}

func lifecycleProofSubjects(apply resources.DeploymentReceipt, retirement resources.RetirementReceipt, rollback resources.RollbackReceipt) []audit.Subject {
	return []audit.Subject{
		{Kind: "DeploymentReceipt", Digest: apply.Metadata.ReceiptID},
		{Kind: "RetirementReceipt", Digest: retirement.Metadata.ReceiptID},
		{Kind: "RollbackReceipt", Digest: rollback.Metadata.ReceiptID},
	}
}

func writeLifecycleProofFailure(output io.Writer, auditPath, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(auditPath, "lifecycle.proof.record", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}
