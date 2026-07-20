package cli

import (
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
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type airgapGateOptions struct {
	bundlePath, importReceiptPath, reasonReference string
	privateKeyPath, keyID                          string
	name, outputPath, auditPath                    string
	validFor                                       time.Duration
	transferReceiptPaths, scanReceiptPaths         csvFlag
}

type airgapGateVerifyOptions struct {
	gateResultPath, trustPolicyPath, auditPath string
}

func evaluateAirgapProvenanceGate(args []string, stdout, stderr io.Writer) int {
	options, ok := parseAirgapGateOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil || !bundle.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AGP-101", errors.New("deployment bundle is invalid"), ExitInvalidInput)
	}
	importReceipt, err := resources.LoadArtifactImportReceipt(options.importReceiptPath)
	if err != nil || !importReceipt.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AGP-102", errors.New("artifact import receipt is invalid"), ExitInvalidInput)
	}
	if importReceipt.Spec.PlanID != bundle.Spec.PlanID || importReceipt.Spec.BundleID != bundle.Metadata.BundleID || importReceipt.Spec.Target.ReferenceDigest == "" {
		return writeLoadErrorWithExit(stdout, "YARA-AGP-103", errors.New("import receipt does not bind the supplied bundle"), ExitInvalidInput)
	}
	transferReceipts := make([]resources.ArtifactTransferReceipt, 0, len(options.transferReceiptPaths))
	for _, path := range uniqueSortedStrings(options.transferReceiptPaths) {
		receipt, err := resources.LoadArtifactTransferReceipt(path)
		if err != nil || !receipt.Validate().Valid {
			return writeLoadErrorWithExit(stdout, "YARA-AGP-104", errors.New("artifact transfer receipt is invalid"), ExitInvalidInput)
		}
		transferReceipts = append(transferReceipts, receipt)
	}
	scanReceipts := make([]resources.ArtifactScanReceipt, 0, len(options.scanReceiptPaths))
	for _, path := range uniqueSortedStrings(options.scanReceiptPaths) {
		receipt, err := resources.LoadArtifactScanReceipt(path)
		if err != nil || !receipt.Validate().Valid {
			return writeLoadErrorWithExit(stdout, "YARA-AGP-105", errors.New("artifact scan receipt is invalid"), ExitInvalidInput)
		}
		scanReceipts = append(scanReceipts, receipt)
	}
	target := importReceipt.Spec.Target
	gates := []resources.ProvenanceGateEvaluation{}
	transferErr := validateTransferReceiptChain(bundle, resources.TargetPreflightResult{Spec: resources.TargetPreflightResultSpec{Target: target}}, importReceipt, transferReceipts)
	if transferErr != nil {
		gates = append(gates, resources.ProvenanceGateEvaluation{ID: "transfer-chain", Status: "failed", Blocker: transferErr.Error()})
	} else {
		gates = append(gates, resources.ProvenanceGateEvaluation{ID: "transfer-chain", Status: "passed"})
	}
	scanErr := validateScanReceiptChain(bundle, resources.TargetPreflightResult{Spec: resources.TargetPreflightResultSpec{Target: target}}, transferReceipts, scanReceipts)
	if transferErr != nil {
		gates = append(gates, resources.ProvenanceGateEvaluation{ID: "scan-chain", Status: "blocked", Blocker: "transfer-chain-not-passed"})
	} else if scanErr != nil {
		gates = append(gates, resources.ProvenanceGateEvaluation{ID: "scan-chain", Status: "failed", Blocker: scanErr.Error()})
	} else {
		gates = append(gates, resources.ProvenanceGateEvaluation{ID: "scan-chain", Status: "passed"})
	}
	slices.SortFunc(gates, func(left, right resources.ProvenanceGateEvaluation) int {
		return compareStrings(left.ID, right.ID)
	})
	outcome := "passed"
	for _, gate := range gates {
		if gate.Status != "passed" {
			outcome = gate.Status
			break
		}
	}
	transferIDs := make([]string, 0, len(transferReceipts))
	for _, receipt := range transferReceipts {
		transferIDs = append(transferIDs, receipt.Metadata.TransferReceiptID)
	}
	slices.Sort(transferIDs)
	scanIDs := make([]string, 0, len(scanReceipts))
	for _, receipt := range scanReceipts {
		scanIDs = append(scanIDs, receipt.Metadata.ScanReceiptID)
	}
	slices.Sort(scanIDs)
	result := resources.AirgapProvenanceGateResult{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapProvenanceGateResult",
		Metadata: resources.AirgapProvenanceGateResultMetadata{
			Name: options.name,
		},
		Spec: resources.AirgapProvenanceGateResultSpec{
			RecordedAt:         time.Now().UTC().Format(time.RFC3339Nano),
			PlanID:             bundle.Spec.PlanID,
			BundleID:           bundle.Metadata.BundleID,
			CatalogDigest:      bundle.Spec.CatalogDigest,
			Target:             target,
			ImportReceiptID:    importReceipt.Metadata.ImportReceiptID,
			TransferReceiptIDs: transferIDs,
			ScanReceiptIDs:     scanIDs,
			Gates:              gates,
			Outcome:            outcome,
			ReasonReference:    options.reasonReference,
			Limitations: []string{
				"Gate result evaluates only immutable receipt bindings and declared offline policy constraints.",
				"Gate result excludes raw scanner output, findings payloads and secret-bearing metadata.",
			},
		},
	}
	slices.Sort(result.Spec.Limitations)
	privateKey, err := authkeys.LoadPrivateKey(options.privateKeyPath)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGP-107", err, ExitInvalidInput)
	}
	result.Spec.ExpiresAt = time.Now().UTC().Add(options.validFor).Format(time.RFC3339Nano)
	result.Spec.Signer = resources.AirgapGateResultSignerIdentity{KeyID: options.keyID}
	result, err = result.Sign(privateKey)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGP-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AGP-500", errors.New("signed gate result is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGP-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGP-106", err, ExitInvalidInput)
	}
	subjects := []audit.Subject{
		{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID},
		{Kind: "ArtifactImportReceipt", Digest: importReceipt.Metadata.ImportReceiptID},
		{Kind: "AirgapProvenanceGateResult", Digest: result.Metadata.GateResultID},
	}
	for _, id := range transferIDs {
		subjects = append(subjects, audit.Subject{Kind: "ArtifactTransferReceipt", Digest: id})
	}
	for _, id := range scanIDs {
		subjects = append(subjects, audit.Subject{Kind: "ArtifactScanReceipt", Digest: id})
	}
	if err := persistOperationAuditForTarget(options.auditPath, "airgap.provenance-gate.evaluate", "completed", "success", "kubernetes:"+target.ReferenceDigest, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":           true,
		"outcome":         result.Spec.Outcome,
		"gateResultId":    result.Metadata.GateResultID,
		"publicKeyDigest": result.Spec.Signer.PublicKeyDigest,
		"expiresAt":       result.Spec.ExpiresAt,
		"output":          options.outputPath,
		"auditOutput":     options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	if result.Spec.Outcome != "passed" {
		return ExitInfeasible
	}
	return ExitSuccess
}

func parseAirgapGateOptions(args []string, stderr io.Writer) (airgapGateOptions, bool) {
	options := airgapGateOptions{validFor: 10 * time.Minute}
	flags := flag.NewFlagSet("airgap provenance-gate evaluate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Exact DeploymentBundle")
	flags.StringVar(&options.importReceiptPath, "import-receipt", "", "Exact ArtifactImportReceipt")
	flags.Var(&options.transferReceiptPaths, "transfer-receipt", "ArtifactTransferReceipt path (repeatable)")
	flags.Var(&options.scanReceiptPaths, "scan-receipt", "ArtifactScanReceipt path (repeatable)")
	flags.StringVar(&options.privateKeyPath, "private-key", "", "PEM PKCS#8 Ed25519 signing key")
	flags.StringVar(&options.keyID, "key-id", "", "Organization trust-policy key identifier")
	flags.StringVar(&options.reasonReference, "reason-reference", "", "Non-secret gate evaluation reason reference")
	flags.StringVar(&options.name, "name", "", "AirgapProvenanceGateResult name")
	flags.StringVar(&options.outputPath, "output", "", "Generated AirgapProvenanceGateResult YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated gate evaluation audit JSONL output")
	flags.DurationVar(&options.validFor, "valid-for", options.validFor, "Gate result validity, maximum 15m")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.bundlePath == "" || options.importReceiptPath == "" || options.privateKeyPath == "" || options.keyID == "" || options.reasonReference == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "airgap provenance-gate evaluate requires --bundle --import-receipt --transfer-receipt --scan-receipt --private-key --key-id --reason-reference --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath || options.validFor <= 0 || options.validFor > 15*time.Minute {
		fmt.Fprintln(stderr, "--output and --audit-output must differ; --valid-for must be greater than zero and at most 15m")
		return options, false
	}
	if len(options.transferReceiptPaths) == 0 || len(options.scanReceiptPaths) == 0 {
		fmt.Fprintln(stderr, "at least one --transfer-receipt and one --scan-receipt are required")
		return options, false
	}
	return options, true
}

func verifyAirgapProvenanceGateResult(args []string, stdout, stderr io.Writer) int {
	return verifyAirgapProvenanceGateResultAt(args, stdout, stderr, time.Now)
}

func verifyAirgapProvenanceGateResultAt(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	var options airgapGateVerifyOptions
	flags := flag.NewFlagSet("airgap provenance-gate verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.gateResultPath, "gate-result", "", "AirgapProvenanceGateResult YAML")
	flags.StringVar(&options.trustPolicyPath, "trust-policy", "", "AirgapGateTrustPolicy YAML")
	flags.StringVar(&options.auditPath, "audit-output", "", "Optional verification audit JSONL")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || options.gateResultPath == "" || options.trustPolicyPath == "" {
		fmt.Fprintln(stderr, "airgap provenance-gate verify requires --gate-result and --trust-policy")
		return ExitInvalidInput
	}
	result, err := resources.LoadAirgapProvenanceGateResult(options.gateResultPath)
	if err != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "airgap.provenance-gate.verify", "AirgapProvenanceGateResult", options.gateResultPath, "YARA-AGP-004", err, nil)
	}
	policy, err := resources.LoadAirgapGateTrustPolicy(options.trustPolicyPath)
	if err != nil || !policy.Validate().Valid {
		if auditErr := persistOperationAuditForTarget(options.auditPath, "airgap.provenance-gate.verify", "failed", "failed", "kubernetes:"+result.Spec.Target.ReferenceDigest, []audit.Subject{{Kind: "AirgapProvenanceGateResult", Digest: result.Metadata.GateResultID}}, []string{"YARA-AGP-108"}); auditErr != nil {
			return writeLoadError(stdout, "YARA-AUD-005", auditErr)
		}
		return writeLoadErrorWithExit(stdout, "YARA-AGP-108", errors.New("air-gap gate trust policy is invalid"), ExitInvalidInput)
	}
	subjects := []audit.Subject{
		{Kind: "AirgapProvenanceGateResult", Digest: result.Metadata.GateResultID},
		{Kind: "AirgapGateTrustPolicy", Digest: policy.Metadata.PolicyID},
	}
	if err := policy.VerifyGateResult(result, now()); err != nil {
		if auditErr := persistOperationAuditForTarget(options.auditPath, "airgap.provenance-gate.verify", "failed", "failed", "kubernetes:"+result.Spec.Target.ReferenceDigest, subjects, []string{"YARA-AGP-109"}); auditErr != nil {
			return writeLoadError(stdout, "YARA-AUD-005", auditErr)
		}
		return writeLoadErrorWithExit(stdout, "YARA-AGP-109", err, ExitInfeasible)
	}
	if err := persistOperationAuditForTarget(options.auditPath, "airgap.provenance-gate.verify", "completed", "success", "kubernetes:"+result.Spec.Target.ReferenceDigest, subjects, nil); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":           true,
		"gateResultId":    result.Metadata.GateResultID,
		"policyId":        policy.Metadata.PolicyID,
		"keyId":           result.Spec.Signer.KeyID,
		"publicKeyDigest": result.Spec.Signer.PublicKeyDigest,
		"expiresAt":       result.Spec.ExpiresAt,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func compareStrings(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
