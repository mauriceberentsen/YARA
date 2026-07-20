package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	authkeys "github.com/mauriceberentsen/YARA/internal/authorization"
	"github.com/mauriceberentsen/YARA/internal/executor"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
	"gopkg.in/yaml.v3"
)

type deploymentApplyOptions struct {
	bundlePath, preflightPath, changeSetPath, approvalPath string
	importReceiptPath                                      string
	transferReceiptPaths                                   csvFlag
	authorizationPath, publicKeyPath, confirmAuthorization string
	name, receiptPath, auditPath, kubeconfig, contextName  string
	timeout                                                time.Duration
}

type kubernetesExecutor interface {
	Execute(context.Context, resources.DeploymentBundle, resources.KubernetesChangeSet, resources.ExecutionAuthorization, resources.ArtifactImportReceipt, time.Time) (executor.ExecutionResult, error)
	Retire(context.Context, resources.DeploymentBundle, resources.KubernetesChangeSet, resources.ExecutionAuthorization, time.Time) (executor.RetirementResult, error)
	Rollback(context.Context, resources.DeploymentBundle, resources.KubernetesChangeSet, resources.ExecutionAuthorization, time.Time) (executor.RollbackResult, error)
}

var newKubernetesExecutor = func(kubeconfig, contextName string) (kubernetesExecutor, error) {
	return executor.NewKubernetes(kubeconfig, contextName)
}

func applyKubernetesDeployment(args []string, stdout, stderr io.Writer) int {
	return applyKubernetesDeploymentAt(args, stdout, stderr, time.Now)
}

func applyKubernetesDeploymentAt(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	options, ok := parseDeploymentApplyOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	bundle, preflight, changeSet, approval, authorization, importReceipt, transferReceipts, code, err := loadAndValidateExecutionInputs(options, now())
	if err != nil {
		return writeLoadErrorWithExit(stdout, code, err, ExitInfeasible)
	}
	correlationID := fmt.Sprintf("deployment-%d", now().UTC().UnixNano())
	subjects := executionSubjects(bundle, preflight, changeSet, approval, authorization, importReceipt, transferReceipts)
	auditWriter, err := newExecutionAudit(options.auditPath, correlationID, "deployment.apply", "kubernetes:"+authorization.Spec.Target.ReferenceDigest, subjects, now())
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
		return fail("YARA-EXE-108", err, ExitInvalidInput)
	}
	if err := authorization.Verify(publicKey, now()); err != nil {
		return fail("YARA-EXE-109", err, ExitInfeasible)
	}
	if authorization.Metadata.AuthorizationID != options.confirmAuthorization {
		return fail("YARA-EXE-110", errors.New("explicit confirmation does not match the signed authorization"), ExitInfeasible)
	}
	if err := validateExecutionConstraints(preflight, changeSet, authorization); err != nil {
		return fail("YARA-EXE-111", err, ExitInfeasible)
	}
	binaryDigest, err := currentBinaryDigest()
	if err != nil {
		return fail("YARA-EXE-113", err, ExitInternal)
	}

	receiptFile, err := reserveOutput(options.receiptPath)
	if err != nil {
		return fail("YARA-EXE-112", err, ExitInvalidInput)
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
		return fail("YARA-EXE-113", err, ExitUnsupported)
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	startedAt := now().UTC()
	result, executeErr := engine.Execute(ctx, bundle, changeSet, authorization, importReceipt, startedAt)
	if !result.MutationStarted {
		if executeErr == nil {
			executeErr = errors.New("executor returned without starting or explaining execution")
		}
		return fail("YARA-EXE-114", executeErr, ExitInfeasible)
	}
	receipt, err := buildDeploymentReceipt(options.name, correlationID, binaryDigest, bundle, preflight, changeSet, approval, authorization, importReceipt, transferReceipts, result)
	if err != nil {
		return fail("YARA-EXE-500", err, ExitInternal)
	}
	data, err := yaml.Marshal(receipt)
	if err == nil {
		err = writeReserved(receiptFile, data)
	}
	if err != nil {
		return fail("YARA-EXE-115", err, ExitInternal)
	}
	receiptWritten = true
	receiptSubject := audit.Subject{Kind: "DeploymentReceipt", Digest: receipt.Metadata.ReceiptID}
	terminalSubjects := append(append([]audit.Subject(nil), subjects...), receiptSubject)
	terminalOutcome := "success"
	diagnosticCodes := receiptDiagnosticCodes(receipt)
	if receipt.Spec.Outcome != "succeeded" || executeErr != nil {
		terminalOutcome = "failed"
		if len(diagnosticCodes) == 0 {
			diagnosticCodes = []string{"YARA-EXE-114"}
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
	if executeErr != nil || receipt.Spec.Outcome != "succeeded" {
		return ExitInfeasible
	}
	return ExitSuccess
}

func parseDeploymentApplyOptions(args []string, stderr io.Writer) (deploymentApplyOptions, bool) {
	options := deploymentApplyOptions{timeout: 30 * time.Minute}
	flags := flag.NewFlagSet("deployment apply kubernetes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Exact DeploymentBundle")
	flags.StringVar(&options.preflightPath, "preflight", "", "Exact TargetPreflightResult")
	flags.StringVar(&options.changeSetPath, "change-set", "", "Exact KubernetesChangeSet")
	flags.StringVar(&options.approvalPath, "approval", "", "Exact DeploymentApproval")
	flags.StringVar(&options.importReceiptPath, "import-receipt", "", "Exact ArtifactImportReceipt")
	flags.Var(&options.transferReceiptPaths, "transfer-receipt", "ArtifactTransferReceipt path (repeatable)")
	flags.StringVar(&options.authorizationPath, "authorization", "", "Signed ExecutionAuthorization")
	flags.StringVar(&options.publicKeyPath, "public-key", "", "Trusted PEM PKIX Ed25519 public key")
	flags.StringVar(&options.confirmAuthorization, "confirm-authorization", "", "Exact authorization ID operator confirmation")
	flags.StringVar(&options.name, "name", "", "DeploymentReceipt name")
	flags.StringVar(&options.receiptPath, "receipt-output", "", "Exclusive DeploymentReceipt output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Exclusive durable audit JSONL output")
	flags.StringVar(&options.kubeconfig, "kubeconfig", "", "Kubeconfig path passed only to kubectl")
	flags.StringVar(&options.contextName, "context", "", "Kubernetes context passed only to kubectl")
	flags.DurationVar(&options.timeout, "timeout", options.timeout, "Overall execution timeout")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return options, false
	}
	if options.bundlePath == "" || options.preflightPath == "" || options.changeSetPath == "" || options.approvalPath == "" || options.importReceiptPath == "" || options.authorizationPath == "" || options.publicKeyPath == "" || options.confirmAuthorization == "" || options.name == "" || options.receiptPath == "" || options.auditPath == "" || options.timeout <= 0 {
		fmt.Fprintln(stderr, "deployment apply kubernetes requires all exact inputs including import receipt, trusted key, confirmation, name, receipt output and audit output")
		return options, false
	}
	if options.receiptPath == options.auditPath {
		fmt.Fprintln(stderr, "receipt and audit output paths must differ")
		return options, false
	}
	return options, true
}

func loadAndValidateExecutionInputs(options deploymentApplyOptions, at time.Time) (resources.DeploymentBundle, resources.TargetPreflightResult, resources.KubernetesChangeSet, resources.DeploymentApproval, resources.ExecutionAuthorization, resources.ArtifactImportReceipt, []resources.ArtifactTransferReceipt, string, error) {
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil || !bundle.Validate().Valid {
		return bundle, resources.TargetPreflightResult{}, resources.KubernetesChangeSet{}, resources.DeploymentApproval{}, resources.ExecutionAuthorization{}, resources.ArtifactImportReceipt{}, nil, "YARA-EXE-101", errors.New("deployment bundle is invalid")
	}
	preflight, err := resources.LoadTargetPreflightResult(options.preflightPath)
	if err != nil || !preflight.Validate().Valid {
		return bundle, preflight, resources.KubernetesChangeSet{}, resources.DeploymentApproval{}, resources.ExecutionAuthorization{}, resources.ArtifactImportReceipt{}, nil, "YARA-EXE-102", errors.New("target preflight is invalid")
	}
	changeSet, err := resources.LoadKubernetesChangeSet(options.changeSetPath)
	if err != nil || !changeSet.Validate().Valid {
		return bundle, preflight, changeSet, resources.DeploymentApproval{}, resources.ExecutionAuthorization{}, resources.ArtifactImportReceipt{}, nil, "YARA-EXE-103", errors.New("change set is invalid")
	}
	approval, err := resources.LoadDeploymentApproval(options.approvalPath)
	if err != nil || !approval.Validate().Valid {
		return bundle, preflight, changeSet, approval, resources.ExecutionAuthorization{}, resources.ArtifactImportReceipt{}, nil, "YARA-EXE-104", errors.New("approval is invalid")
	}
	importReceipt, err := resources.LoadArtifactImportReceipt(options.importReceiptPath)
	if err != nil || !importReceipt.Validate().Valid {
		return bundle, preflight, changeSet, approval, resources.ExecutionAuthorization{}, importReceipt, nil, "YARA-EXE-116", errors.New("artifact import receipt is invalid")
	}
	authorization, err := resources.LoadExecutionAuthorization(options.authorizationPath)
	if err != nil || !authorization.Validate().Valid {
		return bundle, preflight, changeSet, approval, authorization, importReceipt, nil, "YARA-EXE-105", errors.New("execution authorization is invalid")
	}
	if approval.Spec.Decision != "approved" || approval.Spec.Effect != "review-only" || changeSet.Spec.Outcome != "review-required" {
		return bundle, preflight, changeSet, approval, authorization, importReceipt, nil, "YARA-EXE-106", errors.New("approved conflict-free review inputs are required")
	}
	approvalExpiry, _ := time.Parse(time.RFC3339Nano, approval.Spec.ExpiresAt)
	if !at.UTC().Before(approvalExpiry) {
		return bundle, preflight, changeSet, approval, authorization, importReceipt, nil, "YARA-EXE-107", errors.New("approval has expired")
	}
	issuedAt, _ := time.Parse(time.RFC3339Nano, authorization.Spec.IssuedAt)
	authorizationExpiry, _ := time.Parse(time.RFC3339Nano, authorization.Spec.ExpiresAt)
	preflightAt, _ := time.Parse(time.RFC3339Nano, preflight.Spec.ObservedAt)
	changeSetAt, _ := time.Parse(time.RFC3339Nano, changeSet.Spec.ObservedAt)
	approvalAt, _ := time.Parse(time.RFC3339Nano, approval.Spec.RecordedAt)
	if issuedAt.Before(preflightAt) || issuedAt.Sub(preflightAt) > 15*time.Minute || issuedAt.Before(changeSetAt) || issuedAt.Sub(changeSetAt) > 5*time.Minute || issuedAt.Before(approvalAt) || authorizationExpiry.After(approvalExpiry) {
		return bundle, preflight, changeSet, approval, authorization, importReceipt, nil, "YARA-EXE-107", errors.New("authorization was not issued from fresh inputs within approval validity")
	}
	if bundle.Spec.PlanID != preflight.Spec.PlanID || bundle.Spec.PlanID != changeSet.Spec.PlanID || bundle.Spec.PlanID != approval.Spec.PlanID || bundle.Spec.PlanID != authorization.Spec.PlanID ||
		bundle.Metadata.BundleID != preflight.Spec.BundleID || bundle.Metadata.BundleID != changeSet.Spec.BundleID || bundle.Metadata.BundleID != approval.Spec.BundleID || bundle.Metadata.BundleID != authorization.Spec.BundleID ||
		preflight.Metadata.ResultID != changeSet.Spec.PreflightResultID || preflight.Metadata.ResultID != approval.Spec.PreflightResultID || preflight.Metadata.ResultID != authorization.Spec.PreflightResultID ||
		changeSet.Metadata.ChangeSetID != approval.Spec.ChangeSetID || changeSet.Metadata.ChangeSetID != authorization.Spec.ChangeSetID || approval.Metadata.ApprovalID != authorization.Spec.ApprovalID ||
		preflight.Spec.Target != changeSet.Spec.Target || preflight.Spec.Target != approval.Spec.Target || preflight.Spec.Target != authorization.Spec.Target {
		return bundle, preflight, changeSet, approval, authorization, importReceipt, nil, "YARA-EXE-106", errors.New("execution inputs do not bind the same deployment")
	}
	if importReceipt.Spec.PlanID != bundle.Spec.PlanID || importReceipt.Spec.BundleID != bundle.Metadata.BundleID || importReceipt.Spec.Target != preflight.Spec.Target {
		return bundle, preflight, changeSet, approval, authorization, importReceipt, nil, "YARA-EXE-116", errors.New("import receipt does not bind the same plan, bundle and target")
	}
	if err := validateImportReceiptCoverage(bundle, importReceipt); err != nil {
		return bundle, preflight, changeSet, approval, authorization, importReceipt, nil, "YARA-EXE-116", err
	}
	transferReceipts := make([]resources.ArtifactTransferReceipt, 0, len(options.transferReceiptPaths))
	for _, path := range uniqueSortedStrings(options.transferReceiptPaths) {
		receipt, err := resources.LoadArtifactTransferReceipt(path)
		if err != nil || !receipt.Validate().Valid {
			return bundle, preflight, changeSet, approval, authorization, importReceipt, nil, "YARA-EXE-117", errors.New("artifact transfer receipt is invalid")
		}
		transferReceipts = append(transferReceipts, receipt)
	}
	requiresTransferChain, err := bundleRequiresTransferChain(bundle)
	if err != nil {
		return bundle, preflight, changeSet, approval, authorization, importReceipt, nil, "YARA-EXE-117", err
	}
	if requiresTransferChain {
		if err := validateTransferReceiptChain(bundle, preflight, importReceipt, transferReceipts); err != nil {
			return bundle, preflight, changeSet, approval, authorization, importReceipt, nil, "YARA-EXE-117", err
		}
	}
	return bundle, preflight, changeSet, approval, authorization, importReceipt, transferReceipts, "", nil
}

func validateExecutionConstraints(preflight resources.TargetPreflightResult, changeSet resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization) error {
	actions := []string{}
	seen := map[string]struct{}{}
	for _, operation := range changeSet.Spec.Operations {
		if operation.Action == "conflict" || operation.Action == "unresolved" {
			return errors.New("change set contains a non-executable action")
		}
		if _, ok := seen[operation.Action]; !ok {
			seen[operation.Action] = struct{}{}
			actions = append(actions, operation.Action)
		}
	}
	slices.Sort(actions)
	blockers, err := acceptedActiveVerificationBlockers(preflight)
	if err != nil {
		return err
	}
	if !slices.Equal(actions, authorization.Spec.Constraints.AllowedActions) || len(changeSet.Spec.Operations) != authorization.Spec.Constraints.MaxOperations || authorization.Spec.Constraints.AllowDelete || !slices.Equal(blockers, authorization.Spec.Constraints.AcceptedPreflightBlockers) || authorization.Spec.Constraints.AllowActiveVerification != (len(blockers) > 0) {
		return errors.New("signed constraints do not exactly match reviewed operations and preflight blockers")
	}
	return nil
}

func buildDeploymentReceipt(name, correlationID, binaryDigest string, bundle resources.DeploymentBundle, preflight resources.TargetPreflightResult, changeSet resources.KubernetesChangeSet, approval resources.DeploymentApproval, authorization resources.ExecutionAuthorization, importReceipt resources.ArtifactImportReceipt, transferReceipts []resources.ArtifactTransferReceipt, result executor.ExecutionResult) (resources.DeploymentReceipt, error) {
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
	if outcome != "failed" {
		for _, check := range result.Postflight {
			if check.Status != "passed" {
				outcome = "partial"
				break
			}
		}
	}
	receipt := resources.DeploymentReceipt{APIVersion: resources.APIVersion, Kind: "DeploymentReceipt", Metadata: resources.DeploymentReceiptMetadata{Name: name}, Spec: resources.DeploymentReceiptSpec{
		Outcome: outcome, StartedAt: result.StartedAt.Format(time.RFC3339Nano), CompletedAt: result.CompletedAt.Format(time.RFC3339Nano), ExecutionCorrelationID: correlationID,
		PlanID: bundle.Spec.PlanID, BundleID: bundle.Metadata.BundleID, PreflightResultID: preflight.Metadata.ResultID, ChangeSetID: changeSet.Metadata.ChangeSetID, ApprovalID: approval.Metadata.ApprovalID, AuthorizationID: authorization.Metadata.AuthorizationID, ImportReceiptID: importReceipt.Metadata.ImportReceiptID,
		Target: result.Target, Executor: resources.DeploymentExecutorIdentity{Name: "yara-kubernetes-executor", Version: version.Version, BinaryDigest: binaryDigest}, Operations: result.Operations, Postflight: result.Postflight, Limitations: result.Limitations,
	}}
	for _, transferReceipt := range transferReceipts {
		receipt.Spec.TransferReceiptIDs = append(receipt.Spec.TransferReceiptIDs, transferReceipt.Metadata.TransferReceiptID)
	}
	slices.Sort(receipt.Spec.TransferReceiptIDs)
	receipt, err := receipt.AssignReceiptID()
	if err != nil {
		return resources.DeploymentReceipt{}, err
	}
	if report := receipt.Validate(); !report.Valid {
		return resources.DeploymentReceipt{}, fmt.Errorf("constructed receipt is invalid: %s", report.Diagnostics[0].Code)
	}
	return receipt, nil
}

func currentBinaryDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", errors.New("executor binary identity is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("executor binary identity is unavailable")
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", errors.New("executor binary identity is unavailable")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func executionSubjects(bundle resources.DeploymentBundle, preflight resources.TargetPreflightResult, changeSet resources.KubernetesChangeSet, approval resources.DeploymentApproval, authorization resources.ExecutionAuthorization, importReceipt resources.ArtifactImportReceipt, transferReceipts []resources.ArtifactTransferReceipt) []audit.Subject {
	subjects := []audit.Subject{
		{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID},
		{Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID},
		{Kind: "KubernetesChangeSet", Digest: changeSet.Metadata.ChangeSetID},
		{Kind: "DeploymentApproval", Digest: approval.Metadata.ApprovalID},
		{Kind: "ExecutionAuthorization", Digest: authorization.Metadata.AuthorizationID},
		{Kind: "ArtifactImportReceipt", Digest: importReceipt.Metadata.ImportReceiptID},
	}
	for _, receipt := range transferReceipts {
		subjects = append(subjects, audit.Subject{Kind: "ArtifactTransferReceipt", Digest: receipt.Metadata.TransferReceiptID})
	}
	return subjects
}

func validateImportReceiptCoverage(bundle resources.DeploymentBundle, receipt resources.ArtifactImportReceipt) error {
	expected, err := expectedModelArtifacts(bundle)
	if err != nil {
		return err
	}
	if len(expected) != len(receipt.Spec.ModelArtifacts) {
		return errors.New("import receipt does not cover the exact set of required model artifacts")
	}
	for _, observed := range receipt.Spec.ModelArtifacts {
		artifact, ok := expected[observed.Ref]
		if !ok || observed.Revision != artifact.Revision || len(observed.Files) != len(artifact.Files) {
			return errors.New("import receipt model artifact identity does not match bundle")
		}
		bundleFiles := map[string]resources.BundleArtifactFile{}
		for _, file := range artifact.Files {
			bundleFiles[file.Path] = file
		}
		for _, file := range observed.Files {
			match, exists := bundleFiles[file.Path]
			if !exists || file.Digest != match.Digest || file.SizeBytes != match.SizeBytes {
				return errors.New("import receipt model file bindings do not match bundle artifact files")
			}
		}
	}
	return nil
}

func bundleRequiresTransferChain(bundle resources.DeploymentBundle) (bool, error) {
	manifest, err := bundle.OfflineAcquisitionManifest()
	if err != nil {
		return false, err
	}
	return manifest.Spec.Policy.NetworkRequiredDuringAcquisition && !manifest.Spec.Policy.NetworkAllowedDuringExecution, nil
}

func validateTransferReceiptChain(bundle resources.DeploymentBundle, preflight resources.TargetPreflightResult, importReceipt resources.ArtifactImportReceipt, transferReceipts []resources.ArtifactTransferReceipt) error {
	if len(transferReceipts) == 0 {
		return errors.New("air-gapped deployment requires at least one artifact transfer receipt")
	}
	expected, err := expectedModelArtifacts(bundle)
	if err != nil {
		return err
	}
	known := map[string]struct{}{importReceipt.Metadata.ImportReceiptID: {}}
	linkedImport := false
	for _, receipt := range transferReceipts {
		if receipt.Spec.PlanID != bundle.Spec.PlanID || receipt.Spec.BundleID != bundle.Metadata.BundleID || receipt.Spec.CatalogDigest != bundle.Spec.CatalogDigest || receipt.Spec.Target != preflight.Spec.Target {
			return errors.New("transfer receipt does not bind the same plan, bundle, catalog and target")
		}
		if len(receipt.Spec.ModelArtifacts) != len(expected) {
			return errors.New("transfer receipt does not cover the exact set of required model artifacts")
		}
		for _, observed := range receipt.Spec.ModelArtifacts {
			artifact, ok := expected[observed.Ref]
			if !ok || observed.Revision != artifact.Revision || len(observed.Files) != len(artifact.Files) {
				return errors.New("transfer receipt model artifact identity does not match bundle")
			}
			bundleFiles := map[string]resources.BundleArtifactFile{}
			for _, file := range artifact.Files {
				bundleFiles[file.Path] = file
			}
			for _, file := range observed.Files {
				match, exists := bundleFiles[file.Path]
				if !exists || file.Digest != match.Digest || file.SizeBytes != match.SizeBytes {
					return errors.New("transfer receipt model file bindings do not match bundle artifact files")
				}
			}
		}
		linked := false
		for _, prior := range receipt.Spec.PriorReceiptIDs {
			if prior == importReceipt.Metadata.ImportReceiptID {
				linkedImport = true
			}
			if _, ok := known[prior]; ok {
				linked = true
			}
		}
		if !linked {
			return errors.New("transfer receipt chain is incomplete or references unknown prior receipts")
		}
		known[receipt.Metadata.TransferReceiptID] = struct{}{}
	}
	if !linkedImport {
		return errors.New("transfer receipt chain does not reference the artifact import receipt")
	}
	return nil
}

func expectedModelArtifacts(bundle resources.DeploymentBundle) (map[string]resources.BundleArtifact, error) {
	expected := map[string]resources.BundleArtifact{}
	for _, artifact := range bundle.Spec.Artifacts {
		if artifact.Type == "huggingface-snapshot" {
			expected[artifact.Ref] = artifact
		}
	}
	if len(expected) == 0 {
		return nil, errors.New("deployment bundle does not contain transfer-tracked model artifacts")
	}
	return expected, nil
}

func receiptDiagnosticCodes(receipt resources.DeploymentReceipt) []string {
	set := map[string]struct{}{}
	for _, operation := range receipt.Spec.Operations {
		if operation.DiagnosticCode != "" {
			set[operation.DiagnosticCode] = struct{}{}
		}
	}
	for _, check := range receipt.Spec.Postflight {
		if check.DiagnosticCode != "" {
			set[check.DiagnosticCode] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for code := range set {
		result = append(result, code)
	}
	slices.Sort(result)
	return result
}

func reserveOutput(path string) (*os.File, error) {
	if parent := filepath.Dir(path); parent != "." {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return nil, err
		}
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func writeReserved(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

type executionAudit struct {
	file                                     *os.File
	chain                                    *audit.Chain
	correlationID, action, target, startedID string
}

func newExecutionAudit(path, correlationID, action, target string, subjects []audit.Subject, at time.Time) (*executionAudit, error) {
	file, err := reserveOutput(path)
	if err != nil {
		return nil, err
	}
	actorID, assurance := localActor()
	writer := &executionAudit{file: file, chain: audit.NewChain(), correlationID: correlationID, action: action, target: target, startedID: correlationID + "-started"}
	event, err := writer.chain.Append(audit.Event{Metadata: audit.Metadata{ID: writer.startedID, OccurredAt: at.UTC().Format(time.RFC3339Nano)}, Spec: audit.Spec{CorrelationID: correlationID, Actor: audit.Actor{ID: actorID, Type: "user", Assurance: assurance}, Action: action + ".started", Subjects: subjects, Reason: audit.Reason{Type: "user-request", Reference: "cli"}, Target: target, Outcome: "started", DiagnosticCodes: []string{}}})
	if err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := audit.EncodeJSONL(file, []audit.Event{event}); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return writer, nil
}

func (w *executionAudit) finish(outcome string, subjects []audit.Subject, codes []string, at time.Time) error {
	actorID, assurance := localActor()
	event, err := w.chain.Append(audit.Event{Metadata: audit.Metadata{ID: w.correlationID + "-terminal", OccurredAt: at.UTC().Format(time.RFC3339Nano)}, Spec: audit.Spec{CorrelationID: w.correlationID, CausationID: w.startedID, Actor: audit.Actor{ID: actorID, Type: "user", Assurance: assurance}, Action: w.action + ".completed", Subjects: subjects, Reason: audit.Reason{Type: "user-request", Reference: "cli"}, Target: w.target, Outcome: outcome, DiagnosticCodes: codes}})
	if err != nil {
		return err
	}
	if err := audit.EncodeJSONL(w.file, []audit.Event{event}); err != nil {
		return err
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	return w.file.Close()
}
