package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type approvalOptions struct {
	bundlePath, preflightPath, changeSetPath, name   string
	decision, reasonReference, outputPath, auditPath string
	validFor                                         time.Duration
}

func recordDeploymentApproval(args []string, stdout, stderr io.Writer) int {
	return recordDeploymentApprovalAt(args, stdout, stderr, time.Now)
}

func recordDeploymentApprovalAt(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	options, ok := parseApprovalOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil {
		return writeApprovalFailure(stdout, options, "local", []audit.Subject{attemptedInputSubject("DeploymentBundle", options.bundlePath)}, "YARA-APR-004", err, ExitInvalidInput)
	}
	bundleSubject := audit.Subject{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID}
	if report := bundle.Validate(); !report.Valid {
		return writeApprovalFailure(stdout, options, "local", []audit.Subject{bundleSubject}, "YARA-APR-005", fmt.Errorf("bundle is invalid"), ExitInvalidInput)
	}
	preflight, err := resources.LoadTargetPreflightResult(options.preflightPath)
	if err != nil {
		return writeApprovalFailure(stdout, options, "local", []audit.Subject{bundleSubject, attemptedInputSubject("TargetPreflightResult", options.preflightPath)}, "YARA-APR-006", err, ExitInvalidInput)
	}
	preflightSubject := audit.Subject{Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID}
	changeSet, err := resources.LoadKubernetesChangeSet(options.changeSetPath)
	if err != nil {
		return writeApprovalFailure(stdout, options, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, attemptedInputSubject("KubernetesChangeSet", options.changeSetPath)}, "YARA-APR-007", err, ExitInvalidInput)
	}
	changeSetSubject := audit.Subject{Kind: "KubernetesChangeSet", Digest: changeSet.Metadata.ChangeSetID}
	if report := preflight.Validate(); !report.Valid {
		return writeApprovalFailure(stdout, options, "local", []audit.Subject{bundleSubject, preflightSubject}, "YARA-APR-008", fmt.Errorf("preflight is invalid"), ExitInvalidInput)
	}
	if report := changeSet.Validate(); !report.Valid {
		return writeApprovalFailure(stdout, options, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject}, "YARA-APR-009", fmt.Errorf("change set is invalid"), ExitInvalidInput)
	}
	if preflight.Spec.BundleID != bundle.Metadata.BundleID || changeSet.Spec.BundleID != bundle.Metadata.BundleID || changeSet.Spec.PreflightResultID != preflight.Metadata.ResultID || changeSet.Spec.Target != preflight.Spec.Target {
		return writeApprovalFailure(stdout, options, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject}, "YARA-APR-010", fmt.Errorf("approval inputs do not bind the exact same deployment"), ExitInvalidInput)
	}
	recordedAt := now().UTC()
	decision := "approved"
	if options.decision == "reject" {
		decision = "rejected"
	}
	actorID, assurance := localActor()
	limitations := []string{
		"Local OS identity is self-asserted and cannot authorize execution.",
		"This record does not prove separation of duties, policy authorization or cryptographic signature.",
		"Target state can change after the bound preflight and change-set observations.",
	}
	slices.Sort(limitations)
	approval := resources.DeploymentApproval{
		APIVersion: resources.APIVersion, Kind: "DeploymentApproval", Metadata: resources.DeploymentApprovalMetadata{Name: options.name},
		Spec: resources.DeploymentApprovalSpec{
			Decision: decision, Effect: "review-only", RecordedAt: recordedAt.Format(time.RFC3339Nano), ExpiresAt: recordedAt.Add(options.validFor).Format(time.RFC3339Nano),
			PlanID: bundle.Spec.PlanID, BundleID: bundle.Metadata.BundleID, PreflightResultID: preflight.Metadata.ResultID, ChangeSetID: changeSet.Metadata.ChangeSetID,
			Target: preflight.Spec.Target, Actor: resources.ApprovalActor{ID: actorID, Type: "user", Assurance: assurance},
			Reason: resources.ApprovalReason{Type: "user-review", Reference: options.reasonReference}, Limitations: limitations,
		},
	}
	approval, err = approval.AssignApprovalID()
	if err != nil {
		return writeApprovalFailure(stdout, options, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject}, "YARA-APR-500", err, ExitInternal)
	}
	if report := approval.Validate(); !report.Valid {
		return writeApprovalFailure(stdout, options, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject}, "YARA-APR-500", fmt.Errorf("approval construction failed: %s", report.Diagnostics[0].Code), ExitInternal)
	}
	data, err := yaml.Marshal(approval)
	if err != nil {
		return writeApprovalFailure(stdout, options, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject}, "YARA-APR-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeApprovalFailure(stdout, options, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject}, "YARA-APR-018", err, ExitInvalidInput)
	}
	approvalSubject := audit.Subject{Kind: "DeploymentApproval", Digest: approval.Metadata.ApprovalID}
	if err := persistOperationAuditForTarget(options.auditPath, "approval.record", "completed", "success", "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{"valid": true, "approvalId": approval.Metadata.ApprovalID, "decision": approval.Spec.Decision, "effect": approval.Spec.Effect, "output": options.outputPath, "auditOutput": options.auditPath}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseApprovalOptions(args []string, stderr io.Writer) (approvalOptions, bool) {
	options := approvalOptions{validFor: time.Hour}
	flags := flag.NewFlagSet("approval record", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Exact DeploymentBundle")
	flags.StringVar(&options.preflightPath, "preflight", "", "Exact TargetPreflightResult")
	flags.StringVar(&options.changeSetPath, "change-set", "", "Exact KubernetesChangeSet")
	flags.StringVar(&options.name, "name", "", "DeploymentApproval name")
	flags.StringVar(&options.decision, "decision", "", "approve or reject")
	flags.StringVar(&options.reasonReference, "reason-reference", "", "Non-secret ticket or review reference")
	flags.StringVar(&options.outputPath, "output", "", "Generated DeploymentApproval YAML")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated mandatory audit JSONL")
	flags.DurationVar(&options.validFor, "valid-for", options.validFor, "Review record validity, maximum 24h")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.bundlePath == "" || options.preflightPath == "" || options.changeSetPath == "" || options.name == "" || options.reasonReference == "" || options.outputPath == "" || options.auditPath == "" || !slices.Contains([]string{"approve", "reject"}, options.decision) {
		fmt.Fprintln(stderr, "approval record requires exact inputs, --decision approve|reject, --reason-reference, --name, --output and --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath || options.validFor <= 0 || options.validFor > 24*time.Hour {
		fmt.Fprintln(stderr, "output paths must differ and --valid-for must be greater than zero and at most 24h")
		return options, false
	}
	return options, true
}

func writeApprovalFailure(output io.Writer, options approvalOptions, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "approval.record", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}
