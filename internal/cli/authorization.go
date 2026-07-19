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
	authkeys "github.com/mauriceberentsen/YARA/internal/authorization"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type authorizationIssueOptions struct {
	bundlePath, preflightPath, changeSetPath, approvalPath string
	privateKeyPath, keyID, name, outputPath, auditPath     string
	validFor                                               time.Duration
}

func issueExecutionAuthorization(args []string, stdout, stderr io.Writer) int {
	return issueExecutionAuthorizationAt(args, stdout, stderr, time.Now)
}

func issueExecutionAuthorizationAt(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	options, ok := parseAuthorizationIssueOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:unresolved", []audit.Subject{attemptedInputSubject("DeploymentBundle", options.bundlePath)}, "YARA-AUT-004", err, ExitInvalidInput)
	}
	bundleSubject := audit.Subject{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID}
	preflight, err := resources.LoadTargetPreflightResult(options.preflightPath)
	if err != nil {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:unresolved", []audit.Subject{bundleSubject, attemptedInputSubject("TargetPreflightResult", options.preflightPath)}, "YARA-AUT-005", err, ExitInvalidInput)
	}
	preflightSubject := audit.Subject{Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID}
	changeSet, err := resources.LoadKubernetesChangeSet(options.changeSetPath)
	if err != nil {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, attemptedInputSubject("KubernetesChangeSet", options.changeSetPath)}, "YARA-AUT-006", err, ExitInvalidInput)
	}
	changeSetSubject := audit.Subject{Kind: "KubernetesChangeSet", Digest: changeSet.Metadata.ChangeSetID}
	approval, err := resources.LoadDeploymentApproval(options.approvalPath)
	if err != nil {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, attemptedInputSubject("DeploymentApproval", options.approvalPath)}, "YARA-AUT-007", err, ExitInvalidInput)
	}
	approvalSubject := audit.Subject{Kind: "DeploymentApproval", Digest: approval.Metadata.ApprovalID}
	if report := bundle.Validate(); !report.Valid {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:unresolved", []audit.Subject{bundleSubject}, "YARA-AUT-008", fmt.Errorf("bundle is invalid"), ExitInvalidInput)
	}
	if report := preflight.Validate(); !report.Valid {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:unresolved", []audit.Subject{bundleSubject, preflightSubject}, "YARA-AUT-009", fmt.Errorf("preflight is invalid"), ExitInvalidInput)
	}
	if report := changeSet.Validate(); !report.Valid {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject}, "YARA-AUT-010", fmt.Errorf("change set is invalid"), ExitInvalidInput)
	}
	if report := approval.Validate(); !report.Valid {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-011", fmt.Errorf("approval is invalid"), ExitInvalidInput)
	}
	if approval.Spec.Decision != "approved" || approval.Spec.Effect != "review-only" || changeSet.Spec.Outcome != "review-required" {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-101", fmt.Errorf("approved conflict-free review inputs are required"), ExitInfeasible)
	}
	if bundle.Metadata.BundleID != preflight.Spec.BundleID || bundle.Metadata.BundleID != changeSet.Spec.BundleID || bundle.Metadata.BundleID != approval.Spec.BundleID ||
		preflight.Metadata.ResultID != changeSet.Spec.PreflightResultID || preflight.Metadata.ResultID != approval.Spec.PreflightResultID ||
		changeSet.Metadata.ChangeSetID != approval.Spec.ChangeSetID || preflight.Spec.Target != changeSet.Spec.Target || preflight.Spec.Target != approval.Spec.Target {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-102", fmt.Errorf("authorization inputs do not bind the same deployment"), ExitInfeasible)
	}
	issuedAt := now().UTC()
	preflightObservedAt, preflightTimeErr := time.Parse(time.RFC3339Nano, preflight.Spec.ObservedAt)
	changeSetObservedAt, changeSetTimeErr := time.Parse(time.RFC3339Nano, changeSet.Spec.ObservedAt)
	approvalRecordedAt, approvalRecordedErr := time.Parse(time.RFC3339Nano, approval.Spec.RecordedAt)
	approvalExpires, _ := time.Parse(time.RFC3339Nano, approval.Spec.ExpiresAt)
	if preflightTimeErr != nil || changeSetTimeErr != nil || approvalRecordedErr != nil || issuedAt.Before(preflightObservedAt) || issuedAt.Sub(preflightObservedAt) > 15*time.Minute || issuedAt.Before(changeSetObservedAt) || issuedAt.Sub(changeSetObservedAt) > 5*time.Minute || issuedAt.Before(approvalRecordedAt) {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-103", fmt.Errorf("authorization inputs are stale or not yet valid"), ExitInfeasible)
	}
	expiresAt := issuedAt.Add(options.validFor)
	if !issuedAt.Before(approvalExpires) || expiresAt.After(approvalExpires) {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-103", fmt.Errorf("authorization validity exceeds the approval validity"), ExitInfeasible)
	}
	privateKey, err := authkeys.LoadPrivateKey(options.privateKeyPath)
	if err != nil {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-104", err, ExitInvalidInput)
	}
	actions := []string{}
	seenActions := map[string]struct{}{}
	for _, operation := range changeSet.Spec.Operations {
		if _, exists := seenActions[operation.Action]; !exists {
			seenActions[operation.Action] = struct{}{}
			actions = append(actions, operation.Action)
		}
	}
	slices.Sort(actions)
	blockers, err := acceptedActiveVerificationBlockers(preflight)
	if err != nil {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-105", err, ExitInfeasible)
	}
	authorization := resources.ExecutionAuthorization{
		APIVersion: resources.APIVersion, Kind: "ExecutionAuthorization", Metadata: resources.ExecutionAuthorizationMetadata{Name: options.name},
		Spec: resources.ExecutionAuthorizationSpec{
			IssuedAt: issuedAt.Format(time.RFC3339Nano), ExpiresAt: expiresAt.Format(time.RFC3339Nano),
			PlanID: bundle.Spec.PlanID, BundleID: bundle.Metadata.BundleID, PreflightResultID: preflight.Metadata.ResultID, ChangeSetID: changeSet.Metadata.ChangeSetID, ApprovalID: approval.Metadata.ApprovalID,
			Target: preflight.Spec.Target, Issuer: resources.ExecutionAuthorizationIssuer{KeyID: options.keyID},
			Constraints: resources.ExecutionAuthorizationConstraints{AllowedActions: actions, MaxOperations: len(changeSet.Spec.Operations), AllowDelete: false, AllowActiveVerification: len(blockers) > 0, AcceptedPreflightBlockers: blockers},
		},
	}
	authorization, err = authorization.Sign(privateKey)
	if err != nil {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-500", err, ExitInternal)
	}
	if report := authorization.Validate(); !report.Valid {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-500", fmt.Errorf("authorization construction failed: %s", report.Diagnostics[0].Code), ExitInternal)
	}
	data, err := yaml.Marshal(authorization)
	if err != nil {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeAuthorizationFailure(stdout, options.auditPath, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject}, "YARA-AUT-018", err, ExitInvalidInput)
	}
	authorizationSubject := audit.Subject{Kind: "ExecutionAuthorization", Digest: authorization.Metadata.AuthorizationID}
	if err := persistOperationAuditForTarget(options.auditPath, "authorization.issue", "completed", "success", "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, changeSetSubject, approvalSubject, authorizationSubject}, blockers); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{"valid": true, "authorizationId": authorization.Metadata.AuthorizationID, "publicKeyDigest": authorization.Spec.Issuer.PublicKeyDigest, "expiresAt": authorization.Spec.ExpiresAt, "output": options.outputPath, "auditOutput": options.auditPath}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func acceptedActiveVerificationBlockers(preflight resources.TargetPreflightResult) ([]string, error) {
	allowed := map[string]struct{}{"YARA-TPR-114": {}, "YARA-TPR-115": {}, "YARA-TPR-116": {}, "YARA-TPR-117": {}}
	blockers := []string{}
	for _, check := range preflight.Spec.Checks {
		if check.Status == "passed" {
			continue
		}
		if check.Status != "blocked" {
			return nil, fmt.Errorf("failed preflight check %s cannot be accepted for active verification", check.ID)
		}
		if _, ok := allowed[check.DiagnosticCode]; !ok {
			return nil, fmt.Errorf("preflight blocker %s is not an active-verification prerequisite", check.DiagnosticCode)
		}
		blockers = append(blockers, check.DiagnosticCode)
	}
	slices.Sort(blockers)
	return blockers, nil
}

func parseAuthorizationIssueOptions(args []string, stderr io.Writer) (authorizationIssueOptions, bool) {
	options := authorizationIssueOptions{validFor: 10 * time.Minute}
	flags := flag.NewFlagSet("authorization issue", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Exact DeploymentBundle")
	flags.StringVar(&options.preflightPath, "preflight", "", "Exact TargetPreflightResult")
	flags.StringVar(&options.changeSetPath, "change-set", "", "Exact KubernetesChangeSet")
	flags.StringVar(&options.approvalPath, "approval", "", "Approved review-only DeploymentApproval")
	flags.StringVar(&options.privateKeyPath, "private-key", "", "PEM PKCS#8 Ed25519 signing key (never persisted)")
	flags.StringVar(&options.keyID, "key-id", "", "Organization trust-policy key identifier")
	flags.StringVar(&options.name, "name", "", "ExecutionAuthorization name")
	flags.StringVar(&options.outputPath, "output", "", "Generated ExecutionAuthorization YAML")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated mandatory audit JSONL")
	flags.DurationVar(&options.validFor, "valid-for", options.validFor, "Authorization validity, maximum 15m and within approval")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.bundlePath == "" || options.preflightPath == "" || options.changeSetPath == "" || options.approvalPath == "" || options.privateKeyPath == "" || options.keyID == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "authorization issue requires exact deployment inputs, signing key, key ID, name, output and audit output")
		return options, false
	}
	if options.outputPath == options.auditPath || options.validFor <= 0 || options.validFor > 15*time.Minute {
		fmt.Fprintln(stderr, "output paths must differ and --valid-for must be greater than zero and at most 15m")
		return options, false
	}
	return options, true
}

type authorizationVerifyOptions struct{ authorizationPath, publicKeyPath, auditPath string }

func verifyExecutionAuthorization(args []string, stdout, stderr io.Writer) int {
	return verifyExecutionAuthorizationAt(args, stdout, stderr, time.Now)
}

func verifyExecutionAuthorizationAt(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	var options authorizationVerifyOptions
	flags := flag.NewFlagSet("authorization verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.authorizationPath, "authorization", "", "ExecutionAuthorization YAML")
	flags.StringVar(&options.publicKeyPath, "public-key", "", "Trusted PEM PKIX Ed25519 public key")
	flags.StringVar(&options.auditPath, "audit-output", "", "Optional verification audit JSONL")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || options.authorizationPath == "" || options.publicKeyPath == "" {
		fmt.Fprintln(stderr, "authorization verify requires --authorization and --public-key")
		return ExitInvalidInput
	}
	authorization, err := resources.LoadExecutionAuthorization(options.authorizationPath)
	if err != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "authorization.verify", "ExecutionAuthorization", options.authorizationPath, "YARA-AUT-004", err, nil)
	}
	subject := audit.Subject{Kind: "ExecutionAuthorization", Digest: authorization.Metadata.AuthorizationID}
	publicKey, err := authkeys.LoadPublicKey(options.publicKeyPath)
	if err != nil {
		if auditErr := persistOperationAuditForTarget(options.auditPath, "authorization.verify", "failed", "failed", "kubernetes:"+authorization.Spec.Target.ReferenceDigest, []audit.Subject{subject}, []string{"YARA-AUT-106"}); auditErr != nil {
			return writeLoadError(stdout, "YARA-AUD-005", auditErr)
		}
		return writeLoadErrorWithExit(stdout, "YARA-AUT-106", err, ExitInvalidInput)
	}
	if err := authorization.Verify(publicKey, now()); err != nil {
		if auditErr := persistOperationAuditForTarget(options.auditPath, "authorization.verify", "failed", "failed", "kubernetes:"+authorization.Spec.Target.ReferenceDigest, []audit.Subject{subject}, []string{"YARA-AUT-107"}); auditErr != nil {
			return writeLoadError(stdout, "YARA-AUD-005", auditErr)
		}
		return writeLoadErrorWithExit(stdout, "YARA-AUT-107", err, ExitInfeasible)
	}
	if err := persistOperationAuditForTarget(options.auditPath, "authorization.verify", "completed", "success", "kubernetes:"+authorization.Spec.Target.ReferenceDigest, []audit.Subject{subject}, nil); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{"valid": true, "authorizationId": authorization.Metadata.AuthorizationID, "keyId": authorization.Spec.Issuer.KeyID, "expiresAt": authorization.Spec.ExpiresAt}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func writeAuthorizationFailure(output io.Writer, auditPath, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(auditPath, "authorization.issue", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}
