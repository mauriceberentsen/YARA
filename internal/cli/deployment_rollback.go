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

type deploymentRollbackOptions struct {
	bundlePath, preflightPath, changeSetPath, approvalPath string
	authorizationPath, publicKeyPath, confirmAuthorization string
	name, receiptPath, auditPath, kubeconfig, contextName  string
	timeout                                                time.Duration
}

func rollbackKubernetesDeployment(args []string, stdout, stderr io.Writer) int {
	return rollbackKubernetesDeploymentAt(args, stdout, stderr, time.Now)
}

func rollbackKubernetesDeploymentAt(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	options, ok := parseDeploymentRollbackOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	bundle, preflight, changeSet, approval, authorization, code, err := loadAndValidateRollbackInputs(options, now())
	if err != nil {
		return writeLoadErrorWithExit(stdout, code, err, ExitInfeasible)
	}
	correlationID := fmt.Sprintf("rollback-%d", now().UTC().UnixNano())
	subjects := rollbackSubjects(bundle, preflight, changeSet, approval, authorization)
	auditWriter, err := newExecutionAudit(options.auditPath, correlationID, "deployment.rollback", "kubernetes:"+authorization.Spec.Target.ReferenceDigest, subjects, now())
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
		return fail("YARA-RBK-108", err, ExitInvalidInput)
	}
	if err := authorization.Verify(publicKey, now()); err != nil {
		return fail("YARA-RBK-109", err, ExitInfeasible)
	}
	if authorization.Metadata.AuthorizationID != options.confirmAuthorization {
		return fail("YARA-RBK-110", errors.New("explicit confirmation does not match the signed authorization"), ExitInfeasible)
	}
	if err := validateRollbackConstraints(changeSet, authorization); err != nil {
		return fail("YARA-RBK-111", err, ExitInfeasible)
	}
	binaryDigest, err := currentBinaryDigest()
	if err != nil {
		return fail("YARA-RBK-113", err, ExitInternal)
	}
	receiptFile, err := reserveOutput(options.receiptPath)
	if err != nil {
		return fail("YARA-RBK-112", err, ExitInvalidInput)
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
		return fail("YARA-RBK-113", err, ExitUnsupported)
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	startedAt := now().UTC()
	result, rollbackErr := engine.Rollback(ctx, bundle, changeSet, authorization, startedAt)
	if !result.MutationStarted {
		if rollbackErr == nil {
			rollbackErr = errors.New("rollback executor returned without starting or explaining execution")
		}
		return fail("YARA-RBK-114", rollbackErr, ExitInfeasible)
	}
	receipt, err := buildRollbackReceipt(options.name, correlationID, binaryDigest, bundle, preflight, changeSet, approval, authorization, result)
	if err != nil {
		return fail("YARA-RBK-500", err, ExitInternal)
	}
	data, err := yaml.Marshal(receipt)
	if err == nil {
		err = writeReserved(receiptFile, data)
	}
	if err != nil {
		return fail("YARA-RBK-115", err, ExitInternal)
	}
	receiptWritten = true
	receiptSubject := audit.Subject{Kind: "RollbackReceipt", Digest: receipt.Metadata.ReceiptID}
	terminalSubjects := append(append([]audit.Subject(nil), subjects...), receiptSubject)
	terminalOutcome := "success"
	diagnosticCodes := rollbackDiagnosticCodes(receipt)
	if receipt.Spec.Outcome != "succeeded" || rollbackErr != nil {
		terminalOutcome = "failed"
		if len(diagnosticCodes) == 0 {
			diagnosticCodes = []string{"YARA-RBK-114"}
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
	if rollbackErr != nil || receipt.Spec.Outcome != "succeeded" {
		return ExitInfeasible
	}
	return ExitSuccess
}

func parseDeploymentRollbackOptions(args []string, stderr io.Writer) (deploymentRollbackOptions, bool) {
	options := deploymentRollbackOptions{timeout: 30 * time.Minute}
	flags := flag.NewFlagSet("deployment rollback kubernetes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Exact rollback DeploymentBundle")
	flags.StringVar(&options.preflightPath, "preflight", "", "Exact TargetPreflightResult")
	flags.StringVar(&options.changeSetPath, "change-set", "", "Exact rollback KubernetesChangeSet")
	flags.StringVar(&options.approvalPath, "approval", "", "Exact DeploymentApproval")
	flags.StringVar(&options.authorizationPath, "authorization", "", "Signed rollback ExecutionAuthorization")
	flags.StringVar(&options.publicKeyPath, "public-key", "", "Trusted PEM PKIX Ed25519 public key")
	flags.StringVar(&options.confirmAuthorization, "confirm-authorization", "", "Exact authorization ID operator confirmation")
	flags.StringVar(&options.name, "name", "", "RollbackReceipt name")
	flags.StringVar(&options.receiptPath, "receipt-output", "", "Exclusive RollbackReceipt output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Exclusive durable audit JSONL output")
	flags.StringVar(&options.kubeconfig, "kubeconfig", "", "Kubeconfig path passed only to kubectl")
	flags.StringVar(&options.contextName, "context", "", "Kubernetes context passed only to kubectl")
	flags.DurationVar(&options.timeout, "timeout", options.timeout, "Overall execution timeout")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return options, false
	}
	if options.bundlePath == "" || options.preflightPath == "" || options.changeSetPath == "" || options.approvalPath == "" || options.authorizationPath == "" || options.publicKeyPath == "" || options.confirmAuthorization == "" || options.name == "" || options.receiptPath == "" || options.auditPath == "" || options.timeout <= 0 {
		fmt.Fprintln(stderr, "deployment rollback kubernetes requires all exact inputs, trusted key, confirmation, name, receipt output and audit output")
		return options, false
	}
	if options.receiptPath == options.auditPath {
		fmt.Fprintln(stderr, "receipt and audit output paths must differ")
		return options, false
	}
	return options, true
}

func loadAndValidateRollbackInputs(options deploymentRollbackOptions, at time.Time) (resources.DeploymentBundle, resources.TargetPreflightResult, resources.KubernetesChangeSet, resources.DeploymentApproval, resources.ExecutionAuthorization, string, error) {
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil || !bundle.Validate().Valid {
		return bundle, resources.TargetPreflightResult{}, resources.KubernetesChangeSet{}, resources.DeploymentApproval{}, resources.ExecutionAuthorization{}, "YARA-RBK-101", errors.New("deployment bundle is invalid")
	}
	preflight, err := resources.LoadTargetPreflightResult(options.preflightPath)
	if err != nil || !preflight.Validate().Valid {
		return bundle, preflight, resources.KubernetesChangeSet{}, resources.DeploymentApproval{}, resources.ExecutionAuthorization{}, "YARA-RBK-102", errors.New("target preflight is invalid")
	}
	changeSet, err := resources.LoadKubernetesChangeSet(options.changeSetPath)
	if err != nil || !changeSet.Validate().Valid {
		return bundle, preflight, changeSet, resources.DeploymentApproval{}, resources.ExecutionAuthorization{}, "YARA-RBK-103", errors.New("change set is invalid")
	}
	approval, err := resources.LoadDeploymentApproval(options.approvalPath)
	if err != nil || !approval.Validate().Valid {
		return bundle, preflight, changeSet, approval, resources.ExecutionAuthorization{}, "YARA-RBK-104", errors.New("approval is invalid")
	}
	authorization, err := resources.LoadExecutionAuthorization(options.authorizationPath)
	if err != nil || !authorization.Validate().Valid {
		return bundle, preflight, changeSet, approval, authorization, "YARA-RBK-105", errors.New("execution authorization is invalid")
	}
	if approval.Spec.Decision != "approved" || approval.Spec.Effect != "review-only" || changeSet.Spec.Outcome != "review-required" {
		return bundle, preflight, changeSet, approval, authorization, "YARA-RBK-106", errors.New("approved conflict-free review inputs are required")
	}
	approvalExpiry, _ := time.Parse(time.RFC3339Nano, approval.Spec.ExpiresAt)
	if !at.UTC().Before(approvalExpiry) {
		return bundle, preflight, changeSet, approval, authorization, "YARA-RBK-107", errors.New("approval has expired")
	}
	issuedAt, _ := time.Parse(time.RFC3339Nano, authorization.Spec.IssuedAt)
	authorizationExpiry, _ := time.Parse(time.RFC3339Nano, authorization.Spec.ExpiresAt)
	preflightAt, _ := time.Parse(time.RFC3339Nano, preflight.Spec.ObservedAt)
	changeSetAt, _ := time.Parse(time.RFC3339Nano, changeSet.Spec.ObservedAt)
	approvalAt, _ := time.Parse(time.RFC3339Nano, approval.Spec.RecordedAt)
	if issuedAt.Before(preflightAt) || issuedAt.Sub(preflightAt) > 15*time.Minute || issuedAt.Before(changeSetAt) || issuedAt.Sub(changeSetAt) > 5*time.Minute || issuedAt.Before(approvalAt) || authorizationExpiry.After(approvalExpiry) {
		return bundle, preflight, changeSet, approval, authorization, "YARA-RBK-107", errors.New("authorization was not issued from fresh inputs within approval validity")
	}
	if bundle.Spec.PlanID != preflight.Spec.PlanID || bundle.Spec.PlanID != changeSet.Spec.PlanID || bundle.Spec.PlanID != approval.Spec.PlanID || bundle.Spec.PlanID != authorization.Spec.PlanID ||
		bundle.Metadata.BundleID != preflight.Spec.BundleID || bundle.Metadata.BundleID != changeSet.Spec.BundleID || bundle.Metadata.BundleID != approval.Spec.BundleID || bundle.Metadata.BundleID != authorization.Spec.BundleID ||
		preflight.Metadata.ResultID != changeSet.Spec.PreflightResultID || preflight.Metadata.ResultID != approval.Spec.PreflightResultID || preflight.Metadata.ResultID != authorization.Spec.PreflightResultID ||
		changeSet.Metadata.ChangeSetID != approval.Spec.ChangeSetID || changeSet.Metadata.ChangeSetID != authorization.Spec.ChangeSetID || approval.Metadata.ApprovalID != authorization.Spec.ApprovalID ||
		preflight.Spec.Target != changeSet.Spec.Target || preflight.Spec.Target != approval.Spec.Target || preflight.Spec.Target != authorization.Spec.Target {
		return bundle, preflight, changeSet, approval, authorization, "YARA-RBK-106", errors.New("rollback inputs do not bind the same deployment")
	}
	return bundle, preflight, changeSet, approval, authorization, "", nil
}

func validateRollbackConstraints(changeSet resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization) error {
	if authorization.Spec.Constraints.AllowDelete || authorization.Spec.Constraints.AllowActiveVerification || len(authorization.Spec.Constraints.AcceptedPreflightBlockers) != 0 {
		return errors.New("rollback authorization constraints must be non-delete and must not accept active verification blockers")
	}
	actions := []string{}
	seen := map[string]struct{}{}
	for _, operation := range changeSet.Spec.Operations {
		if operation.Action == "conflict" || operation.Action == "unresolved" {
			return errors.New("rollback cannot authorize conflict or unresolved actions")
		}
		if operation.Resource.Kind == "Namespace" && operation.Action != "no-op" {
			return errors.New("namespace operation must remain no-op for rollback")
		}
		if _, ok := seen[operation.Action]; !ok {
			seen[operation.Action] = struct{}{}
			actions = append(actions, operation.Action)
		}
	}
	slices.Sort(actions)
	if len(actions) == 0 || !slices.Equal(actions, authorization.Spec.Constraints.AllowedActions) || authorization.Spec.Constraints.MaxOperations != len(changeSet.Spec.Operations) {
		return errors.New("rollback authorization constraints do not match reviewed rollback actions")
	}
	return nil
}

func buildRollbackReceipt(name, correlationID, binaryDigest string, bundle resources.DeploymentBundle, preflight resources.TargetPreflightResult, changeSet resources.KubernetesChangeSet, approval resources.DeploymentApproval, authorization resources.ExecutionAuthorization, result executor.RollbackResult) (resources.RollbackReceipt, error) {
	outcome := "succeeded"
	for _, operation := range result.Operations {
		if operation.Outcome == "failed" {
			outcome = "failed"
			break
		}
		if operation.Outcome == "skipped" {
			outcome = "partial"
		}
	}
	receipt := resources.RollbackReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "RollbackReceipt",
		Metadata: resources.RollbackReceiptMetadata{
			Name: name,
		},
		Spec: resources.RollbackReceiptSpec{
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
		return resources.RollbackReceipt{}, err
	}
	if report := receipt.Validate(); !report.Valid {
		return resources.RollbackReceipt{}, fmt.Errorf("constructed rollback receipt is invalid: %s", report.Diagnostics[0].Code)
	}
	return receipt, nil
}

func rollbackSubjects(bundle resources.DeploymentBundle, preflight resources.TargetPreflightResult, changeSet resources.KubernetesChangeSet, approval resources.DeploymentApproval, authorization resources.ExecutionAuthorization) []audit.Subject {
	return []audit.Subject{{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID}, {Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID}, {Kind: "KubernetesChangeSet", Digest: changeSet.Metadata.ChangeSetID}, {Kind: "DeploymentApproval", Digest: approval.Metadata.ApprovalID}, {Kind: "ExecutionAuthorization", Digest: authorization.Metadata.AuthorizationID}}
}

func rollbackDiagnosticCodes(receipt resources.RollbackReceipt) []string {
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
