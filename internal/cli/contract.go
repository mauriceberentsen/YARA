package cli

import (
	"context"
	"crypto/sha256"
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
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/contracttest"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
	"gopkg.in/yaml.v3"
)

var contractProbe contracttest.Probe = contracttest.SSHProbe{}
var runtimeSmokeArtifactVerifier contracttest.ArtifactVerifier = contracttest.RegistryArtifactVerifier{}
var runtimeSmokeRunner contracttest.RuntimeSmokeRunner = contracttest.SSHRuntimeSmokeRunner{}
var modelInferenceRunner contracttest.ModelInferenceRunner = contracttest.SSHModelInferenceRunner{}
var capacityBoundaryRunner contracttest.CapacityBoundaryRunner = contracttest.SSHCapacityBoundaryRunner{}
var sustainedCapacityRunner contracttest.SustainedCapacityRunner = contracttest.SSHSustainedCapacityRunner{}
var policyContractRunner contracttest.PolicyContractRunner = contracttest.SSHPolicyContractRunner{}
var lifecycleContractRunner contracttest.LifecycleContractRunner = contracttest.SSHLifecycleContractRunner{}

type contractPreflightOptions struct {
	catalogPath string
	assertionID string
	target      string
	name        string
	outputPath  string
	auditPath   string
}

type lifecycleContractOptions struct {
	contractPreflightOptions
	lifecycleProofLedgerPath        string
	confirmLifecycleProofLedgerID   string
	lifecycleApplyReceiptPath       string
	lifecycleRetirementReceiptPath  string
	lifecycleRollbackReceiptPath    string
	lifecycleProofMaxAge            time.Duration
	confirmLifecycleReasonReference string
}

func preflightContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseContractOptions("contract preflight", args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeContractPreflightFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-CAT-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeContractPreflightFailure(stdout, options, nil, "YARA-CAT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	target, found := snapshot.ContractTarget(options.assertionID)
	if !found {
		return writeContractPreflightFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a testable positive compatibility assertion", options.assertionID), ExitInvalidInput)
	}
	environment, err := contractProbe.Observe(context.Background(), options.target)
	if err != nil {
		return writeContractPreflightFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-108", err, ExitInfeasible)
	}
	auditTarget := "ssh:" + environment.ReferenceDigest
	result, err := contracttest.Evaluate(options.name, catalogDigest, target, environment)
	if err != nil {
		return writeContractPreflightFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	result, err = bindContractRunner(result)
	if err != nil {
		return writeContractPreflightFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeContractPreflightReportFailure(stdout, options, auditTarget, []audit.Subject{catalogSubject}, report, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeContractPreflightFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", fmt.Errorf("encode contract test result: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeContractPreflightFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-005", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, "contract.preflight", suffix, auditOutcome, auditTarget, []audit.Subject{catalogSubject, resultSubject}, contractDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	response := map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return exitCode
}

func runtimeSmokeContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseContractOptions("contract runtime-smoke", args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeContractRuntimeFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-CAT-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeContractRuntimeFailure(stdout, options, nil, "YARA-CAT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	target, found := snapshot.ContractTarget(options.assertionID)
	if !found {
		return writeContractRuntimeFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a testable positive compatibility assertion", options.assertionID), ExitInvalidInput)
	}
	ctx := context.Background()
	artifactChecks, err := runtimeSmokeArtifactVerifier.Verify(ctx, target)
	if err != nil {
		return writeContractRuntimeFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-130", err, ExitInfeasible)
	}
	environment, err := contractProbe.Observe(ctx, options.target)
	if err != nil {
		return writeContractRuntimeFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-108", err, ExitInfeasible)
	}
	auditTarget := "ssh:" + environment.ReferenceDigest
	preflight, err := contracttest.Evaluate(options.name, catalogDigest, target, environment)
	if err != nil {
		return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	var runtimeChecks []resources.ContractTestCheck
	if preflight.Spec.Outcome == "passed" && checksPassed(artifactChecks) {
		runtimeChecks, err = runtimeSmokeRunner.Run(ctx, options.target, target)
		if err != nil {
			return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-131", err, ExitInfeasible)
		}
	}
	result, err := contracttest.EvaluateRuntimeSmoke(options.name, catalogDigest, target, environment, artifactChecks, runtimeChecks)
	if err != nil {
		return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	result, err = bindContractRunner(result)
	if err != nil {
		return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeContractRuntimeReportFailure(stdout, options, auditTarget, []audit.Subject{catalogSubject}, report, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", fmt.Errorf("encode contract test result: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeContractRuntimeFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-005", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, "contract.runtime-smoke", suffix, auditOutcome, auditTarget, []audit.Subject{catalogSubject, resultSubject}, contractDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	response := map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return exitCode
}

func modelInferenceContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseContractOptions("contract model-inference", args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeContractModelFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-CAT-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeContractModelFailure(stdout, options, nil, "YARA-CAT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	target, found := snapshot.ContractTarget(options.assertionID)
	if !found {
		return writeContractModelFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a testable positive compatibility assertion", options.assertionID), ExitInvalidInput)
	}
	ctx := context.Background()
	artifactChecks, err := runtimeSmokeArtifactVerifier.Verify(ctx, target)
	if err != nil {
		return writeContractModelFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-130", err, ExitInfeasible)
	}
	environment, err := contractProbe.Observe(ctx, options.target)
	if err != nil {
		return writeContractModelFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-108", err, ExitInfeasible)
	}
	auditTarget := "ssh:" + environment.ReferenceDigest
	preflight, err := contracttest.Evaluate(options.name, catalogDigest, target, environment)
	if err != nil {
		return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	var modelChecks []resources.ContractTestCheck
	if preflight.Spec.Outcome == "passed" && checksPassed(artifactChecks) {
		modelChecks, err = modelInferenceRunner.Run(ctx, options.target, target)
		if err != nil {
			return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-152", err, ExitInfeasible)
		}
	}
	result, err := contracttest.EvaluateModelInference(options.name, catalogDigest, target, environment, artifactChecks, modelChecks)
	if err != nil {
		return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	result, err = bindContractRunner(result)
	if err != nil {
		return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeContractModelReportFailure(stdout, options, auditTarget, []audit.Subject{catalogSubject}, report, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", fmt.Errorf("encode contract test result: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeContractModelFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-005", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, "contract.model-inference", suffix, auditOutcome, auditTarget, []audit.Subject{catalogSubject, resultSubject}, contractDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	response := map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return exitCode
}

func capacityBoundaryContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseContractOptions("contract capacity-boundary", args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeContractCapacityFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-CAT-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeContractCapacityFailure(stdout, options, nil, "YARA-CAT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	target, found := snapshot.ContractTarget(options.assertionID)
	if !found {
		return writeContractCapacityFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a testable positive compatibility assertion", options.assertionID), ExitInvalidInput)
	}
	ctx := context.Background()
	artifactChecks, err := runtimeSmokeArtifactVerifier.Verify(ctx, target)
	if err != nil {
		return writeContractCapacityFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-130", err, ExitInfeasible)
	}
	environment, err := contractProbe.Observe(ctx, options.target)
	if err != nil {
		return writeContractCapacityFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-108", err, ExitInfeasible)
	}
	auditTarget := "ssh:" + environment.ReferenceDigest
	preflight, err := contracttest.Evaluate(options.name, catalogDigest, target, environment)
	if err != nil {
		return writeContractCapacityFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	var capacityChecks []resources.ContractTestCheck
	if preflight.Spec.Outcome == "passed" && checksPassed(artifactChecks) {
		capacityChecks, err = capacityBoundaryRunner.Run(ctx, options.target, target)
		if err != nil {
			return writeContractCapacityFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-158", err, ExitInfeasible)
		}
	}
	result, err := contracttest.EvaluateCapacityBoundary(options.name, catalogDigest, target, environment, artifactChecks, capacityChecks)
	if err != nil {
		return writeContractCapacityFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	result, err = bindContractRunner(result)
	if err != nil {
		return writeContractCapacityFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeContractCapacityReportFailure(stdout, options, auditTarget, []audit.Subject{catalogSubject}, report, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeContractCapacityFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", fmt.Errorf("encode contract test result: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeContractCapacityFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-005", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, "contract.capacity-boundary", suffix, auditOutcome, auditTarget, []audit.Subject{catalogSubject, resultSubject}, contractDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	response := map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return exitCode
}

func sustainedCapacityContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseContractOptions("contract sustained-capacity", args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeContractSustainedFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-CAT-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeContractSustainedFailure(stdout, options, nil, "YARA-CAT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	target, found := snapshot.ContractTarget(options.assertionID)
	if !found {
		return writeContractSustainedFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a testable positive compatibility assertion", options.assertionID), ExitInvalidInput)
	}
	ctx := context.Background()
	artifactChecks, err := runtimeSmokeArtifactVerifier.Verify(ctx, target)
	if err != nil {
		return writeContractSustainedFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-130", err, ExitInfeasible)
	}
	environment, err := contractProbe.Observe(ctx, options.target)
	if err != nil {
		return writeContractSustainedFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-108", err, ExitInfeasible)
	}
	auditTarget := "ssh:" + environment.ReferenceDigest
	preflight, err := contracttest.Evaluate(options.name, catalogDigest, target, environment)
	if err != nil {
		return writeContractSustainedFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	var capacityChecks []resources.ContractTestCheck
	if preflight.Spec.Outcome == "passed" && checksPassed(artifactChecks) {
		capacityChecks, err = sustainedCapacityRunner.Run(ctx, options.target, target)
		if err != nil {
			return writeContractSustainedFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-182", err, ExitInfeasible)
		}
	}
	result, err := contracttest.EvaluateSustainedCapacity(options.name, catalogDigest, target, environment, artifactChecks, capacityChecks)
	if err != nil {
		return writeContractSustainedFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	result, err = bindContractRunner(result)
	if err != nil {
		return writeContractSustainedFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeContractSustainedReportFailure(stdout, options, auditTarget, []audit.Subject{catalogSubject}, report, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeContractSustainedFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", fmt.Errorf("encode contract test result: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeContractSustainedFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-005", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, "contract.sustained-capacity", suffix, auditOutcome, auditTarget, []audit.Subject{catalogSubject, resultSubject}, contractDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	response := map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return exitCode
}

func policyContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseContractOptions("contract policy", args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeContractPolicyFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-CAT-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeContractPolicyFailure(stdout, options, nil, "YARA-CAT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	target, found := snapshot.ContractTarget(options.assertionID)
	if !found {
		return writeContractPolicyFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a testable positive compatibility assertion", options.assertionID), ExitInvalidInput)
	}
	ctx := context.Background()
	artifactChecks, err := runtimeSmokeArtifactVerifier.Verify(ctx, target)
	if err != nil {
		return writeContractPolicyFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-130", err, ExitInfeasible)
	}
	environment, err := contractProbe.Observe(ctx, options.target)
	if err != nil {
		return writeContractPolicyFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-CTR-108", err, ExitInfeasible)
	}
	auditTarget := "ssh:" + environment.ReferenceDigest
	preflight, err := contracttest.Evaluate(options.name, catalogDigest, target, environment)
	if err != nil {
		return writeContractPolicyFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	var policyChecks []resources.ContractTestCheck
	if preflight.Spec.Outcome == "passed" && checksPassed(artifactChecks) {
		policyChecks, err = policyContractRunner.Run(ctx, options.target, target)
		if err != nil {
			return writeContractPolicyFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-168", err, ExitInfeasible)
		}
	}
	result, err := contracttest.EvaluatePolicyContract(options.name, catalogDigest, target, environment, artifactChecks, policyChecks)
	if err != nil {
		return writeContractPolicyFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	result, err = bindContractRunner(result)
	if err != nil {
		return writeContractPolicyFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeContractPolicyReportFailure(stdout, options, auditTarget, []audit.Subject{catalogSubject}, report, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeContractPolicyFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-500", fmt.Errorf("encode contract test result: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeContractPolicyFailureForTarget(stdout, options, auditTarget, []audit.Subject{catalogSubject}, "YARA-CTR-005", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, "contract.policy", suffix, auditOutcome, auditTarget, []audit.Subject{catalogSubject, resultSubject}, contractDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	response := map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return exitCode
}

func lifecycleContract(args []string, stdout, stderr io.Writer) int {
	options, ok := parseLifecycleContractOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-CAT-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, nil, "YARA-CAT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	target, found := snapshot.ContractTarget(options.assertionID)
	if !found {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, []audit.Subject{catalogSubject}, "YARA-CTR-107", fmt.Errorf("assertion %q is not a testable positive compatibility assertion", options.assertionID), ExitInvalidInput)
	}
	ledger, err := resources.LoadLifecycleProofLedger(options.lifecycleProofLedgerPath)
	if err != nil || !ledger.Validate().Valid {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, []audit.Subject{catalogSubject}, "YARA-CTR-183", errors.New("lifecycle proof ledger is invalid"), ExitInvalidInput)
	}
	subjects := []audit.Subject{catalogSubject, {Kind: "LifecycleProofLedger", Digest: ledger.Metadata.LedgerID}}
	if ledger.Metadata.LedgerID != options.confirmLifecycleProofLedgerID {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, subjects, "YARA-CTR-184", errors.New("explicit lifecycle proof ledger confirmation mismatch"), ExitInfeasible)
	}
	if ledger.Spec.ReasonReference != options.confirmLifecycleReasonReference {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, subjects, "YARA-CTR-185", errors.New("lifecycle proof reason reference confirmation mismatch"), ExitInfeasible)
	}
	applyReceipt, err := resources.LoadDeploymentReceipt(options.lifecycleApplyReceiptPath)
	if err != nil || !applyReceipt.Validate().Valid {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, subjects, "YARA-CTR-186", errors.New("lifecycle apply receipt is invalid"), ExitInvalidInput)
	}
	retirementReceipt, err := resources.LoadRetirementReceipt(options.lifecycleRetirementReceiptPath)
	if err != nil || !retirementReceipt.Validate().Valid {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, subjects, "YARA-CTR-186", errors.New("lifecycle retirement receipt is invalid"), ExitInvalidInput)
	}
	rollbackReceipt, err := resources.LoadRollbackReceipt(options.lifecycleRollbackReceiptPath)
	if err != nil || !rollbackReceipt.Validate().Valid {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, subjects, "YARA-CTR-186", errors.New("lifecycle rollback receipt is invalid"), ExitInvalidInput)
	}
	subjects = append(subjects,
		audit.Subject{Kind: "DeploymentReceipt", Digest: applyReceipt.Metadata.ReceiptID},
		audit.Subject{Kind: "RetirementReceipt", Digest: retirementReceipt.Metadata.ReceiptID},
		audit.Subject{Kind: "RollbackReceipt", Digest: rollbackReceipt.Metadata.ReceiptID},
	)
	if ledger.Spec.PlanID != applyReceipt.Spec.PlanID || ledger.Spec.PlanID != retirementReceipt.Spec.PlanID || ledger.Spec.PlanID != rollbackReceipt.Spec.PlanID ||
		ledger.Spec.BundleID != applyReceipt.Spec.BundleID || ledger.Spec.BundleID != retirementReceipt.Spec.BundleID || ledger.Spec.BundleID != rollbackReceipt.Spec.BundleID ||
		ledger.Spec.TargetReferenceDigest != applyReceipt.Spec.Target.ReferenceDigest || ledger.Spec.TargetReferenceDigest != retirementReceipt.Spec.Target.ReferenceDigest || ledger.Spec.TargetReferenceDigest != rollbackReceipt.Spec.Target.ReferenceDigest {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, subjects, "YARA-CTR-187", errors.New("lifecycle proof receipt bindings drift from ledger plan, bundle or target"), ExitInfeasible)
	}
	stageByName := map[string]resources.LifecycleProofLedgerStage{}
	for _, stage := range ledger.Spec.Stages {
		stageByName[stage.Stage] = stage
	}
	expected := []struct {
		stage                string
		receiptID            string
		executionCorrelation string
		completedAt          string
	}{
		{stage: resources.LifecycleStageApply, receiptID: applyReceipt.Metadata.ReceiptID, executionCorrelation: applyReceipt.Spec.ExecutionCorrelationID, completedAt: applyReceipt.Spec.CompletedAt},
		{stage: resources.LifecycleStageRetire, receiptID: retirementReceipt.Metadata.ReceiptID, executionCorrelation: retirementReceipt.Spec.ExecutionCorrelationID, completedAt: retirementReceipt.Spec.CompletedAt},
		{stage: resources.LifecycleStageRollback, receiptID: rollbackReceipt.Metadata.ReceiptID, executionCorrelation: rollbackReceipt.Spec.ExecutionCorrelationID, completedAt: rollbackReceipt.Spec.CompletedAt},
	}
	now := time.Now().UTC()
	for _, item := range expected {
		stage, ok := stageByName[item.stage]
		if !ok || stage.ReceiptID != item.receiptID || stage.ExecutionCorrelationID != item.executionCorrelation || stage.CompletedAt != item.completedAt || stage.Outcome != "succeeded" {
			return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, subjects, "YARA-CTR-188", errors.New("lifecycle proof stage ordering or receipt binding drift detected"), ExitInfeasible)
		}
		completedAt, parseErr := time.Parse(time.RFC3339Nano, stage.CompletedAt)
		if parseErr != nil || completedAt.After(now) || now.Sub(completedAt) > options.lifecycleProofMaxAge {
			return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, subjects, "YARA-CTR-189", errors.New("lifecycle proof ledger freshness policy violated"), ExitInfeasible)
		}
	}
	ctx := context.Background()
	artifactChecks, err := runtimeSmokeArtifactVerifier.Verify(ctx, target)
	if err != nil {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, subjects, "YARA-CTR-130", err, ExitInfeasible)
	}
	environment, err := contractProbe.Observe(ctx, options.target)
	if err != nil {
		return writeContractLifecycleFailure(stdout, options.contractPreflightOptions, subjects, "YARA-CTR-108", err, ExitInfeasible)
	}
	auditTarget := "ssh:" + environment.ReferenceDigest
	preflight, err := contracttest.Evaluate(options.name, catalogDigest, target, environment)
	if err != nil {
		return writeContractLifecycleFailureForTarget(stdout, options.contractPreflightOptions, auditTarget, subjects, "YARA-CTR-500", err, ExitInternal)
	}
	proofBindingEvidence := digestBytes([]byte(strings.Join([]string{
		ledger.Metadata.LedgerID,
		applyReceipt.Metadata.ReceiptID,
		retirementReceipt.Metadata.ReceiptID,
		rollbackReceipt.Metadata.ReceiptID,
		options.confirmLifecycleReasonReference,
		options.lifecycleProofMaxAge.String(),
	}, "|")))
	lifecycleChecks := []resources.ContractTestCheck{
		{
			ID:             "lifecycle.proof-ledger.binding",
			Status:         "passed",
			EvidenceDigest: proofBindingEvidence,
		},
		{
			ID:             "lifecycle.proof-ledger.freshness-policy",
			Status:         "passed",
			EvidenceDigest: proofBindingEvidence,
			Measurements: map[string]int{
				"maxAgeSeconds": int(options.lifecycleProofMaxAge.Seconds()),
			},
		},
	}
	if preflight.Spec.Outcome == "passed" && checksPassed(artifactChecks) {
		runnerChecks, runErr := lifecycleContractRunner.Run(ctx, options.target, target)
		err = runErr
		if err != nil {
			return writeContractLifecycleFailureForTarget(stdout, options.contractPreflightOptions, auditTarget, subjects, "YARA-CTR-178", err, ExitInfeasible)
		}
		lifecycleChecks = append(lifecycleChecks, runnerChecks...)
	}
	result, err := contracttest.EvaluateLifecycleContract(options.name, catalogDigest, target, environment, artifactChecks, lifecycleChecks)
	if err != nil {
		return writeContractLifecycleFailureForTarget(stdout, options.contractPreflightOptions, auditTarget, subjects, "YARA-CTR-500", err, ExitInternal)
	}
	result.Spec.Limitations = append(result.Spec.Limitations,
		fmt.Sprintf("Lifecycle proof freshness policy requires linked receipt completion within %s.", options.lifecycleProofMaxAge),
		fmt.Sprintf("Lifecycle proof reviewed reason reference is %s.", options.confirmLifecycleReasonReference),
	)
	slices.Sort(result.Spec.Limitations)
	result, err = result.AssignResultID()
	if err != nil {
		return writeContractLifecycleFailureForTarget(stdout, options.contractPreflightOptions, auditTarget, subjects, "YARA-CTR-500", err, ExitInternal)
	}
	result, err = bindContractRunner(result)
	if err != nil {
		return writeContractLifecycleFailureForTarget(stdout, options.contractPreflightOptions, auditTarget, subjects, "YARA-CTR-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		return writeContractLifecycleReportFailure(stdout, options.contractPreflightOptions, auditTarget, subjects, report, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeContractLifecycleFailureForTarget(stdout, options.contractPreflightOptions, auditTarget, subjects, "YARA-CTR-500", fmt.Errorf("encode contract test result: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeContractLifecycleFailureForTarget(stdout, options.contractPreflightOptions, auditTarget, subjects, "YARA-CTR-005", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, "contract.lifecycle", suffix, auditOutcome, auditTarget, append(subjects, resultSubject), contractDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	response := map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return exitCode
}

func parseLifecycleContractOptions(args []string, stderr io.Writer) (lifecycleContractOptions, bool) {
	var options lifecycleContractOptions
	flags := flag.NewFlagSet("contract lifecycle", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.assertionID, "assertion", "", "CompatibilityAssertion identifier")
	flags.StringVar(&options.target, "target", "", "SSH target in user@host form")
	flags.StringVar(&options.name, "name", "", "DNS-style ContractTestResult name")
	flags.StringVar(&options.outputPath, "output", "", "Generated ContractTestResult YAML file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated audit JSONL file")
	flags.StringVar(&options.lifecycleProofLedgerPath, "lifecycle-proof-ledger", "", "Validated LifecycleProofLedger file")
	flags.StringVar(&options.confirmLifecycleProofLedgerID, "confirm-lifecycle-proof-ledger", "", "Exact lifecycle proof ledger ID")
	flags.StringVar(&options.lifecycleApplyReceiptPath, "lifecycle-apply-receipt", "", "DeploymentReceipt linked in lifecycle proof")
	flags.StringVar(&options.lifecycleRetirementReceiptPath, "lifecycle-retirement-receipt", "", "RetirementReceipt linked in lifecycle proof")
	flags.StringVar(&options.lifecycleRollbackReceiptPath, "lifecycle-rollback-receipt", "", "RollbackReceipt linked in lifecycle proof")
	flags.DurationVar(&options.lifecycleProofMaxAge, "lifecycle-proof-max-age", 30*24*time.Hour, "Maximum allowed age for linked lifecycle receipts")
	flags.StringVar(&options.confirmLifecycleReasonReference, "confirm-lifecycle-reason-reference", "", "Exact reviewed lifecycle proof reason reference")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.assertionID == "" || options.target == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" ||
		options.lifecycleProofLedgerPath == "" || options.confirmLifecycleProofLedgerID == "" || options.lifecycleApplyReceiptPath == "" || options.lifecycleRetirementReceiptPath == "" ||
		options.lifecycleRollbackReceiptPath == "" || options.confirmLifecycleReasonReference == "" {
		fmt.Fprintln(stderr, "contract lifecycle requires --catalog --assertion --target --name --output --audit-output --lifecycle-proof-ledger --confirm-lifecycle-proof-ledger --lifecycle-apply-receipt --lifecycle-retirement-receipt --lifecycle-rollback-receipt --confirm-lifecycle-reason-reference")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	if options.lifecycleProofMaxAge <= 0 {
		fmt.Fprintln(stderr, "--lifecycle-proof-max-age must be greater than zero")
		return options, false
	}
	return options, true
}

func checksPassed(checks []resources.ContractTestCheck) bool {
	for _, item := range checks {
		if item.Status != "passed" {
			return false
		}
	}
	return len(checks) > 0
}

func bindContractRunner(result resources.ContractTestResult) (resources.ContractTestResult, error) {
	executable, err := os.Executable()
	if err != nil {
		return resources.ContractTestResult{}, fmt.Errorf("locate contract runner executable: %w", err)
	}
	file, err := os.Open(executable)
	if err != nil {
		return resources.ContractTestResult{}, fmt.Errorf("open contract runner executable: %w", err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return resources.ContractTestResult{}, fmt.Errorf("digest contract runner executable: %w", err)
	}
	result.Metadata.ResultID = ""
	result.Spec.Runner = &resources.ContractTestRunner{Version: version.Version, BinaryDigest: fmt.Sprintf("sha256:%x", digest.Sum(nil))}
	return result.AssignResultID()
}

func parseContractOptions(command string, args []string, stderr io.Writer) (contractPreflightOptions, bool) {
	var options contractPreflightOptions
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.assertionID, "assertion", "", "CompatibilityAssertion identifier")
	flags.StringVar(&options.target, "target", "", "SSH target in user@host form")
	flags.StringVar(&options.name, "name", "", "DNS-style ContractTestResult name")
	flags.StringVar(&options.outputPath, "output", "", "Generated ContractTestResult YAML file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.assertionID == "" || options.target == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintf(stderr, "%s requires --catalog, --assertion, --target, --name, --output and --audit-output\n", command)
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}

func contractDiagnosticCodes(result resources.ContractTestResult) []string {
	codes := make([]string, 0)
	for _, check := range result.Spec.Checks {
		if check.DiagnosticCode != "" {
			codes = append(codes, check.DiagnosticCode)
		}
	}
	return uniqueSortedStrings(codes)
}

func writeContractPreflightFailure(output io.Writer, options contractPreflightOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	return writeContractPreflightFailureForTarget(output, options, "ssh:"+digestBytes([]byte(options.target)), subjects, code, err, exitCode)
}

func writeContractPreflightFailureForTarget(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.preflight", "failed", "failed", auditTarget, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}

func writeContractPreflightReportFailure(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.preflight", "failed", "failed", auditTarget, subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, report, exitCode)
}

func writeContractRuntimeFailure(output io.Writer, options contractPreflightOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	return writeContractRuntimeFailureForTarget(output, options, "ssh:"+digestBytes([]byte(options.target)), subjects, code, err, exitCode)
}

func writeContractRuntimeFailureForTarget(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.runtime-smoke", "failed", "failed", auditTarget, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}

func writeContractRuntimeReportFailure(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.runtime-smoke", "failed", "failed", auditTarget, subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, report, exitCode)
}

func writeContractModelFailure(output io.Writer, options contractPreflightOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	return writeContractModelFailureForTarget(output, options, "ssh:"+digestBytes([]byte(options.target)), subjects, code, err, exitCode)
}

func writeContractModelFailureForTarget(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.model-inference", "failed", "failed", auditTarget, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}

func writeContractModelReportFailure(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.model-inference", "failed", "failed", auditTarget, subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, report, exitCode)
}

func writeContractCapacityFailure(output io.Writer, options contractPreflightOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	return writeContractCapacityFailureForTarget(output, options, "ssh:"+digestBytes([]byte(options.target)), subjects, code, err, exitCode)
}

func writeContractCapacityFailureForTarget(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.capacity-boundary", "failed", "failed", auditTarget, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}

func writeContractCapacityReportFailure(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.capacity-boundary", "failed", "failed", auditTarget, subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, report, exitCode)
}

func writeContractSustainedFailure(output io.Writer, options contractPreflightOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	return writeContractSustainedFailureForTarget(output, options, "ssh:"+digestBytes([]byte(options.target)), subjects, code, err, exitCode)
}

func writeContractSustainedFailureForTarget(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.sustained-capacity", "failed", "failed", auditTarget, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}

func writeContractSustainedReportFailure(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.sustained-capacity", "failed", "failed", auditTarget, subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, report, exitCode)
}

func writeContractPolicyFailure(output io.Writer, options contractPreflightOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	return writeContractPolicyFailureForTarget(output, options, "ssh:"+digestBytes([]byte(options.target)), subjects, code, err, exitCode)
}

func writeContractPolicyFailureForTarget(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.policy", "failed", "failed", auditTarget, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}

func writeContractPolicyReportFailure(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.policy", "failed", "failed", auditTarget, subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, report, exitCode)
}

func writeContractLifecycleFailure(output io.Writer, options contractPreflightOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	return writeContractLifecycleFailureForTarget(output, options, "ssh:"+digestBytes([]byte(options.target)), subjects, code, err, exitCode)
}

func writeContractLifecycleFailureForTarget(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.lifecycle", "failed", "failed", auditTarget, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, diagnostics.NewReport(diagnostics.Error(code, err.Error())), exitCode)
}

func writeContractLifecycleReportFailure(output io.Writer, options contractPreflightOptions, auditTarget string, subjects []audit.Subject, report diagnostics.Report, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "contract.lifecycle", "failed", "failed", auditTarget, subjects, diagnosticCodes(report.Diagnostics)); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeReport(output, report, exitCode)
}
