package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	authkeys "github.com/mauriceberentsen/YARA/internal/authorization"
	"github.com/mauriceberentsen/YARA/internal/executor"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
	"gopkg.in/yaml.v3"
)

type deploymentRetireOptions struct {
	bundlePath, preflightPath, changeSetPath, approvalPath string
	authorizationPath, publicKeyPath, confirmAuthorization string
	name, receiptPath, auditPath, kubeconfig, contextName  string
	timeout                                                time.Duration
}

func retireKubernetesDeployment(args []string, stdout, stderr io.Writer) int {
	return retireKubernetesDeploymentAt(args, stdout, stderr, time.Now)
}

func retireKubernetesDeploymentAt(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	options, ok := parseDeploymentRetireOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	bundle, preflight, changeSet, approval, authorization, code, err := loadAndValidateRetirementInputs(options, now())
	if err != nil {
		return writeLoadErrorWithExit(stdout, code, err, ExitInfeasible)
	}
	correlationID := fmt.Sprintf("retirement-%d", now().UTC().UnixNano())
	subjects := retirementSubjects(bundle, preflight, changeSet, approval, authorization)
	auditWriter, err := newExecutionAudit(options.auditPath, correlationID, "deployment.retire", "kubernetes:"+authorization.Spec.Target.ReferenceDigest, subjects, now())
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AUD-005", err, ExitInvalidInput)
	}
	auditClosed := false
	defer func() {
		if !auditClosed {
			_ = auditWriter.file.Close()
		}
	}()
	fail := func(code string, cause error, exitCode int) int {
		if auditErr := auditWriter.finish("failed", subjects, []string{code}, now()); auditErr != nil {
			_ = auditWriter.file.Close()
			auditClosed = true
			return writeLoadErrorWithExit(stdout, "YARA-AUD-005", auditErr, ExitInternal)
		}
		auditClosed = true
		return writeLoadErrorWithExit(stdout, code, cause, exitCode)
	}
	publicKey, err := authkeys.LoadPublicKey(options.publicKeyPath)
	if err != nil {
		return fail("YARA-RET-108", err, ExitInvalidInput)
	}
	if err := authorization.Verify(publicKey, now()); err != nil {
		return fail("YARA-RET-109", err, ExitInfeasible)
	}
	if authorization.Metadata.AuthorizationID != options.confirmAuthorization {
		return fail("YARA-RET-110", errors.New("explicit confirmation does not match the signed authorization"), ExitInfeasible)
	}
	if err := validateRetirementConstraints(changeSet, authorization); err != nil {
		return fail("YARA-RET-111", err, ExitInfeasible)
	}
	binaryDigest, err := currentBinaryDigest()
	if err != nil {
		return fail("YARA-RET-113", err, ExitInternal)
	}
	receiptFile, err := reserveOutput(options.receiptPath)
	if err != nil {
		return fail("YARA-RET-112", err, ExitInvalidInput)
	}
	receiptWritten := false
	defer func() {
		_ = receiptFile.Close()
		if !receiptWritten {
			_ = os.Remove(options.receiptPath)
		}
	}()
	engine, err := newKubernetesExecutor(options.kubeconfig, options.contextName)
	if err != nil {
		return fail("YARA-RET-113", err, ExitUnsupported)
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	startedAt := now().UTC()
	result, retireErr := engine.Retire(ctx, bundle, changeSet, authorization, startedAt)
	if !result.MutationStarted {
		if retireErr == nil {
			retireErr = errors.New("retirement executor returned without starting or explaining execution")
		}
		return fail("YARA-RET-114", retireErr, ExitInfeasible)
	}
	receipt, err := buildRetirementReceipt(options.name, correlationID, binaryDigest, bundle, preflight, changeSet, approval, authorization, result)
	if err != nil {
		return fail("YARA-RET-500", err, ExitInternal)
	}
	data, err := yaml.Marshal(receipt)
	if err == nil {
		err = writeReserved(receiptFile, data)
	}
	if err != nil {
		return fail("YARA-RET-115", err, ExitInternal)
	}
	receiptWritten = true
	receiptSubject := audit.Subject{Kind: "RetirementReceipt", Digest: receipt.Metadata.ReceiptID}
	terminalSubjects := append(append([]audit.Subject(nil), subjects...), receiptSubject)
	terminalOutcome := "success"
	diagnosticCodes := retirementDiagnosticCodes(receipt)
	if receipt.Spec.Outcome != "succeeded" || retireErr != nil {
		terminalOutcome = "failed"
		if len(diagnosticCodes) == 0 {
			diagnosticCodes = []string{"YARA-RET-114"}
		}
	}
	if err := auditWriter.finish(terminalOutcome, terminalSubjects, diagnosticCodes, now()); err != nil {
		_ = auditWriter.file.Close()
		auditClosed = true
		return writeLoadErrorWithExit(stdout, "YARA-AUD-005", err, ExitInternal)
	}
	auditClosed = true
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{"valid": receipt.Spec.Outcome == "succeeded", "outcome": receipt.Spec.Outcome, "receiptId": receipt.Metadata.ReceiptID, "authorizationId": authorization.Metadata.AuthorizationID, "receiptOutput": options.receiptPath, "auditOutput": options.auditPath}); err != nil {
		return ExitInternal
	}
	if retireErr != nil || receipt.Spec.Outcome != "succeeded" {
		return ExitInfeasible
	}
	return ExitSuccess
}

func parseDeploymentRetireOptions(args []string, stderr io.Writer) (deploymentRetireOptions, bool) {
	options := deploymentRetireOptions{timeout: 30 * time.Minute}
	flags := flag.NewFlagSet("deployment retire kubernetes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Exact DeploymentBundle")
	flags.StringVar(&options.preflightPath, "preflight", "", "Exact TargetPreflightResult")
	flags.StringVar(&options.changeSetPath, "change-set", "", "Exact KubernetesChangeSet")
	flags.StringVar(&options.approvalPath, "approval", "", "Exact DeploymentApproval")
	flags.StringVar(&options.authorizationPath, "authorization", "", "Signed retirement ExecutionAuthorization")
	flags.StringVar(&options.publicKeyPath, "public-key", "", "Trusted PEM PKIX Ed25519 public key")
	flags.StringVar(&options.confirmAuthorization, "confirm-authorization", "", "Exact authorization ID operator confirmation")
	flags.StringVar(&options.name, "name", "", "RetirementReceipt name")
	flags.StringVar(&options.receiptPath, "receipt-output", "", "Exclusive RetirementReceipt output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Exclusive durable audit JSONL output")
	flags.StringVar(&options.kubeconfig, "kubeconfig", "", "Kubeconfig path passed only to kubectl")
	flags.StringVar(&options.contextName, "context", "", "Kubernetes context passed only to kubectl")
	flags.DurationVar(&options.timeout, "timeout", options.timeout, "Overall execution timeout")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return options, false
	}
	if options.bundlePath == "" || options.preflightPath == "" || options.changeSetPath == "" || options.approvalPath == "" || options.authorizationPath == "" || options.publicKeyPath == "" || options.confirmAuthorization == "" || options.name == "" || options.receiptPath == "" || options.auditPath == "" || options.timeout <= 0 {
		fmt.Fprintln(stderr, "deployment retire kubernetes requires all exact inputs, trusted key, confirmation, name, receipt output and audit output")
		return options, false
	}
	if options.receiptPath == options.auditPath {
		fmt.Fprintln(stderr, "receipt and audit output paths must differ")
		return options, false
	}
	return options, true
}

func loadAndValidateRetirementInputs(options deploymentRetireOptions, at time.Time) (resources.DeploymentBundle, resources.TargetPreflightResult, resources.KubernetesChangeSet, resources.DeploymentApproval, resources.ExecutionAuthorization, string, error) {
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil || !bundle.Validate().Valid {
		return bundle, resources.TargetPreflightResult{}, resources.KubernetesChangeSet{}, resources.DeploymentApproval{}, resources.ExecutionAuthorization{}, "YARA-RET-101", errors.New("deployment bundle is invalid")
	}
	preflight, err := resources.LoadTargetPreflightResult(options.preflightPath)
	if err != nil || !preflight.Validate().Valid {
		return bundle, preflight, resources.KubernetesChangeSet{}, resources.DeploymentApproval{}, resources.ExecutionAuthorization{}, "YARA-RET-102", errors.New("target preflight is invalid")
	}
	changeSet, err := resources.LoadKubernetesChangeSet(options.changeSetPath)
	if err != nil || !changeSet.Validate().Valid {
		return bundle, preflight, changeSet, resources.DeploymentApproval{}, resources.ExecutionAuthorization{}, "YARA-RET-103", errors.New("change set is invalid")
	}
	approval, err := resources.LoadDeploymentApproval(options.approvalPath)
	if err != nil || !approval.Validate().Valid {
		return bundle, preflight, changeSet, approval, resources.ExecutionAuthorization{}, "YARA-RET-104", errors.New("approval is invalid")
	}
	authorization, err := resources.LoadExecutionAuthorization(options.authorizationPath)
	if err != nil || !authorization.Validate().Valid {
		return bundle, preflight, changeSet, approval, authorization, "YARA-RET-105", errors.New("execution authorization is invalid")
	}
	if approval.Spec.Decision != "approved" || approval.Spec.Effect != "review-only" || changeSet.Spec.Outcome != "review-required" {
		return bundle, preflight, changeSet, approval, authorization, "YARA-RET-106", errors.New("approved conflict-free review inputs are required")
	}
	approvalExpiry, _ := time.Parse(time.RFC3339Nano, approval.Spec.ExpiresAt)
	if !at.UTC().Before(approvalExpiry) {
		return bundle, preflight, changeSet, approval, authorization, "YARA-RET-107", errors.New("approval has expired")
	}
	issuedAt, _ := time.Parse(time.RFC3339Nano, authorization.Spec.IssuedAt)
	authorizationExpiry, _ := time.Parse(time.RFC3339Nano, authorization.Spec.ExpiresAt)
	preflightAt, _ := time.Parse(time.RFC3339Nano, preflight.Spec.ObservedAt)
	changeSetAt, _ := time.Parse(time.RFC3339Nano, changeSet.Spec.ObservedAt)
	approvalAt, _ := time.Parse(time.RFC3339Nano, approval.Spec.RecordedAt)
	if issuedAt.Before(preflightAt) || issuedAt.Sub(preflightAt) > 15*time.Minute || issuedAt.Before(changeSetAt) || issuedAt.Sub(changeSetAt) > 5*time.Minute || issuedAt.Before(approvalAt) || authorizationExpiry.After(approvalExpiry) {
		return bundle, preflight, changeSet, approval, authorization, "YARA-RET-107", errors.New("authorization was not issued from fresh inputs within approval validity")
	}
	if bundle.Spec.PlanID != preflight.Spec.PlanID || bundle.Spec.PlanID != changeSet.Spec.PlanID || bundle.Spec.PlanID != approval.Spec.PlanID || bundle.Spec.PlanID != authorization.Spec.PlanID ||
		bundle.Metadata.BundleID != preflight.Spec.BundleID || bundle.Metadata.BundleID != changeSet.Spec.BundleID || bundle.Metadata.BundleID != approval.Spec.BundleID || bundle.Metadata.BundleID != authorization.Spec.BundleID ||
		preflight.Metadata.ResultID != changeSet.Spec.PreflightResultID || preflight.Metadata.ResultID != approval.Spec.PreflightResultID || preflight.Metadata.ResultID != authorization.Spec.PreflightResultID ||
		changeSet.Metadata.ChangeSetID != approval.Spec.ChangeSetID || changeSet.Metadata.ChangeSetID != authorization.Spec.ChangeSetID || approval.Metadata.ApprovalID != authorization.Spec.ApprovalID ||
		preflight.Spec.Target != changeSet.Spec.Target || preflight.Spec.Target != approval.Spec.Target || preflight.Spec.Target != authorization.Spec.Target {
		return bundle, preflight, changeSet, approval, authorization, "YARA-RET-106", errors.New("retirement inputs do not bind the same deployment")
	}
	return bundle, preflight, changeSet, approval, authorization, "", nil
}

func validateRetirementConstraints(changeSet resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization) error {
	if !authorization.Spec.Constraints.AllowDelete || authorization.Spec.Constraints.AllowActiveVerification || len(authorization.Spec.Constraints.AcceptedPreflightBlockers) != 0 {
		return errors.New("retirement authorization constraints must be delete-only without active verification blockers")
	}
	if len(authorization.Spec.Constraints.AllowedActions) != 1 || authorization.Spec.Constraints.AllowedActions[0] != "delete" {
		return errors.New("retirement authorization must allow exactly delete actions")
	}
	maxDeletes := 0
	for _, operation := range changeSet.Spec.Operations {
		if operation.Resource.Kind == "Namespace" {
			if operation.Action != "no-op" {
				return errors.New("namespace operation must remain no-op for retirement")
			}
			continue
		}
		if operation.Action != "no-op" || operation.Ownership != "owned" || operation.CurrentDigest != operation.DesiredDigest {
			return errors.New("retirement requires exact owned no-op operations in the reviewed change set")
		}
		maxDeletes++
	}
	if maxDeletes == 0 || maxDeletes != authorization.Spec.Constraints.MaxOperations {
		return errors.New("retirement authorization operation count does not match reviewed delete set")
	}
	return nil
}

func buildRetirementReceipt(name, correlationID, binaryDigest string, bundle resources.DeploymentBundle, preflight resources.TargetPreflightResult, changeSet resources.KubernetesChangeSet, approval resources.DeploymentApproval, authorization resources.ExecutionAuthorization, result executor.RetirementResult) (resources.RetirementReceipt, error) {
	outcome := "succeeded"
	for _, operation := range result.Operations {
		if operation.Outcome == "failed" {
			outcome = "failed"
			break
		}
		if operation.Outcome == "skipped" || operation.Outcome == "unchanged" {
			outcome = "partial"
		}
	}
	receipt := resources.RetirementReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "RetirementReceipt",
		Metadata: resources.RetirementReceiptMetadata{
			Name: name,
		},
		Spec: resources.RetirementReceiptSpec{
			Outcome:                outcome,
			StartedAt:              result.StartedAt.Format(time.RFC3339Nano),
			CompletedAt:            result.CompletedAt.Format(time.RFC3339Nano),
			ExecutionCorrelationID: correlationID,
			PlanID:                 bundle.Spec.PlanID,
			BundleID:               bundle.Metadata.BundleID,
			PreflightResultID:      preflight.Metadata.ResultID,
			ChangeSetID:            changeSet.Metadata.ChangeSetID,
			ApprovalID:             approval.Metadata.ApprovalID,
			AuthorizationID:        authorization.Metadata.AuthorizationID,
			Target:                 result.Target,
			Executor: resources.DeploymentExecutorIdentity{
				Name:         "yara-kubernetes-executor",
				Version:      version.Version,
				BinaryDigest: binaryDigest,
			},
			Operations:  result.Operations,
			Limitations: result.Limitations,
		},
	}
	receipt, err := receipt.AssignReceiptID()
	if err != nil {
		return resources.RetirementReceipt{}, err
	}
	if report := receipt.Validate(); !report.Valid {
		return resources.RetirementReceipt{}, fmt.Errorf("constructed retirement receipt is invalid: %s", report.Diagnostics[0].Code)
	}
	return receipt, nil
}

func retirementSubjects(bundle resources.DeploymentBundle, preflight resources.TargetPreflightResult, changeSet resources.KubernetesChangeSet, approval resources.DeploymentApproval, authorization resources.ExecutionAuthorization) []audit.Subject {
	return []audit.Subject{{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID}, {Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID}, {Kind: "KubernetesChangeSet", Digest: changeSet.Metadata.ChangeSetID}, {Kind: "DeploymentApproval", Digest: approval.Metadata.ApprovalID}, {Kind: "ExecutionAuthorization", Digest: authorization.Metadata.AuthorizationID}}
}

func retirementDiagnosticCodes(receipt resources.RetirementReceipt) []string {
	set := map[string]struct{}{}
	for _, operation := range receipt.Spec.Operations {
		if operation.DiagnosticCode != "" {
			set[operation.DiagnosticCode] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for code := range set {
		result = append(result, code)
	}
	slices.Sort(result)
	return result
}
