package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
)

const (
	ExitSuccess      = 0
	ExitInvalidInput = 2
	ExitInfeasible   = 3
	ExitInternal     = 4
	ExitUnsupported  = 5
)

type validationResult struct {
	Valid      bool   `json:"valid"`
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
}

type auditVerificationResult struct {
	Valid      bool   `json:"valid"`
	Events     int    `json:"events"`
	HeadDigest string `json:"headDigest"`
}

type catalogValidationResult struct {
	Valid       bool                     `json:"valid"`
	APIVersion  string                   `json:"apiVersion"`
	Kind        string                   `json:"kind"`
	Name        string                   `json:"name"`
	Version     string                   `json:"version"`
	Digest      string                   `json:"digest"`
	Candidates  int                      `json:"candidates"`
	Diagnostics []diagnostics.Diagnostic `json:"diagnostics"`
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(stdout, version.Version)
		return ExitSuccess
	}
	if len(args) >= 1 && args[0] == "serve" {
		return serveAPI(args[1:], stdout, stderr)
	}
	if len(args) == 3 && args[0] == "audit" && args[1] == "verify" {
		return verifyAudit(args[2], stdout)
	}
	if len(args) >= 2 && args[0] == "plan" && args[1] == "create" {
		return createPlan(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "plan" && args[1] == "diff" {
		return diffPlan(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "plan" && args[1] == "explain" {
		return explainPlan(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "debug" && args[1] == "bundle" {
		return createDebugBundle(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "render" && args[1] == "docker-compose" {
		return renderDockerCompose(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "render" && args[1] == "kubernetes-gitops" {
		return renderKubernetesGitOps(args[2:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "target" && args[1] == "preflight" && args[2] == "kubernetes" {
		return kubernetesTargetPreflight(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "target" && args[1] == "changeset" && args[2] == "kubernetes" {
		return kubernetesChangeSet(args[3:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "approval" && args[1] == "record" {
		return recordDeploymentApproval(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "authorization" && args[1] == "issue" {
		return issueExecutionAuthorization(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "authorization" && args[1] == "issue-retirement" {
		return issueRetirementAuthorization(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "authorization" && args[1] == "issue-rollback" {
		return issueRollbackAuthorization(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "authorization" && args[1] == "verify" {
		return verifyExecutionAuthorization(args[2:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "deployment" && args[1] == "apply" && args[2] == "kubernetes" {
		return applyKubernetesDeployment(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "deployment" && args[1] == "bootstrap" && args[2] == "kubernetes" {
		return bootstrapKubernetesDeployment(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "deployment" && args[1] == "import" && args[2] == "kubernetes" {
		return importKubernetesDeployment(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "deployment" && args[1] == "retire" && args[2] == "kubernetes" {
		return retireKubernetesDeployment(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "deployment" && args[1] == "rollback" && args[2] == "kubernetes" {
		return rollbackKubernetesDeployment(args[3:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "scenario" && args[1] == "validate" {
		return validateScenario(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "scenario" && args[1] == "validate-all" {
		return validateScenarioSuite(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "preflight" {
		return preflightContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "runtime-smoke" {
		return runtimeSmokeContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "model-inference" {
		return modelInferenceContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "capacity-boundary" {
		return capacityBoundaryContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "sustained-capacity" {
		return sustainedCapacityContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "policy" {
		return policyContract(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "contract" && args[1] == "lifecycle" {
		return lifecycleContract(args[2:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "promotion" && args[1] == "review" && args[2] == "record" {
		return recordPromotionReview(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "artifact" && args[1] == "import" && args[2] == "record" {
		return recordArtifactImport(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "artifact" && args[1] == "transfer" && args[2] == "record" {
		return recordArtifactTransfer(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "artifact" && args[1] == "scan" && args[2] == "record" {
		return recordArtifactScan(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "airgap" && args[1] == "provenance-gate" && args[2] == "evaluate" {
		return evaluateAirgapProvenanceGate(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "airgap" && args[1] == "provenance-gate" && args[2] == "verify" {
		return verifyAirgapProvenanceGateResult(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "airgap" && args[1] == "gate-trust-policy" && args[2] == "record" {
		return recordAirgapGateTrustPolicy(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "airgap" && args[1] == "gate-trust-policy" && args[2] == "diff" {
		return diffAirgapGateTrustPolicy(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "airgap" && args[1] == "gate-trust-policy" && args[2] == "review-transition" {
		return reviewAirgapGateTrustPolicyTransition(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "lifecycle" && args[1] == "proof" && args[2] == "record" {
		return recordLifecycleProof(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "lifecycle" && args[1] == "proof" && args[2] == "approve-publication" {
		return approveLifecycleProofPublication(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "publication" && args[1] == "chain" && args[2] == "rehearse" {
		return rehearsePublicationChain(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "publication" && args[1] == "chain" && args[2] == "retention-diagnostics" {
		return publicationChainRetentionDiagnostics(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "publication" && args[1] == "chain" && args[2] == "renewal-review" {
		return reviewPublicationChainRenewal(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "runtime" && args[1] == "drift-signal" && args[2] == "record" {
		return recordRuntimeDriftSignal(args[3:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "integration" && args[1] == "component-smoke" {
		return runIntegrationComponentSmoke(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "integration" && args[1] == "topology-end-to-end" {
		return runIntegrationTopologyEndToEnd(args[2:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "integration" && args[1] == "execute" {
		return runIntegrationExecute(args[2:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "integration" && args[1] == "publish" && args[2] == "attest" {
		return attestIntegrationPublication(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "catalog" && args[1] == "coverage" && args[2] == "create" {
		return catalogCoverage(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "catalog" && args[1] == "coverage" && args[2] == "validate" {
		return validateCatalogCoverage(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "catalog" && args[1] == "coverage" && args[2] == "lifecycle-publication-policy" {
		return explainLifecyclePublicationPolicy(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "catalog" && args[1] == "coverage" && args[2] == "runtime-drift-policy" {
		return explainRuntimeDriftPolicy(args[3:], stdout, stderr)
	}
	if len(args) >= 3 && args[0] == "catalog" && args[1] == "coverage" && args[2] == "signing-authority-boundary" {
		return explainSigningAuthorityBoundaryPolicy(args[3:], stdout, stderr)
	}
	if len(args) < 2 || args[1] != "validate" {
		writeUsage(stderr)
		return ExitInvalidInput
	}
	options, ok := parseValidationOptions(args[2:], stderr)
	if !ok {
		return ExitInvalidInput
	}

	switch args[0] {
	case "request":
		request, err := resources.LoadPlatformRequest(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "request.validate", "PlatformRequest", options.inputPath, "YARA-REQ-004", err, nil)
		}
		subject, err := canonicalSubject("PlatformRequest", request)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "request.validate", subject, request.APIVersion, request.Kind, request.Metadata.Name, request.Validate())
	case "inventory":
		inventory, err := resources.LoadInventory(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "inventory.validate", "Inventory", options.inputPath, "YARA-INV-004", err, nil)
		}
		subject, err := canonicalSubject("Inventory", inventory)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "inventory.validate", subject, inventory.APIVersion, inventory.Kind, inventory.Metadata.Name, inventory.Validate())
	case "catalog":
		snapshot, err := catalog.Load(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "catalog.validate", "CatalogSnapshot", options.inputPath, "YARA-CAT-004", err, nil)
		}
		digest, err := snapshot.Digest()
		if err != nil {
			return writeLoadError(stdout, "YARA-CAT-500", err)
		}
		if err := writeCatalogValidationAudit(options.auditPath, audit.Subject{Kind: "CatalogSnapshot", Digest: digest}, snapshot.Diagnostics()); err != nil {
			return writeLoadError(stdout, "YARA-AUD-005", err)
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(catalogValidationResult{
			Valid: true, APIVersion: snapshot.APIVersion, Kind: snapshot.Kind,
			Name: snapshot.Metadata.Name, Version: snapshot.Metadata.Version,
			Digest: digest, Candidates: len(snapshot.Candidates()), Diagnostics: snapshot.Diagnostics(),
		}); err != nil {
			return ExitInternal
		}
		return ExitSuccess
	case "plan":
		plan, err := resources.LoadPlatformPlan(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "plan.validate", "PlatformPlan", options.inputPath, "YARA-PLAN-004", err, nil)
		}
		subject, err := canonicalSubject("PlatformPlan", plan)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "plan.validate", subject, plan.APIVersion, plan.Kind, plan.Metadata.Name, plan.Validate())
	case "contract":
		result, err := resources.LoadContractTestResult(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "contract.validate", "ContractTestResult", options.inputPath, "YARA-CTR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("ContractTestResult", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "ContractTestResult", Digest: result.Metadata.ResultID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "contract.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "integration":
		result, err := resources.LoadIntegrationTestResult(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "integration.validate", "IntegrationTestResult", options.inputPath, "YARA-INT-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("IntegrationTestResult", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "IntegrationTestResult", Digest: result.Metadata.ResultID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "integration.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "integration-publication-attestation":
		result, err := resources.LoadIntegrationPublicationAttestation(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "integration.publish.attestation.validate", "IntegrationPublicationAttestation", options.inputPath, "YARA-IPA-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("IntegrationPublicationAttestation", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "IntegrationPublicationAttestation", Digest: result.Metadata.AttestationID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "integration.publish.attestation.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "bundle":
		bundle, err := resources.LoadDeploymentBundle(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "bundle.validate", "DeploymentBundle", options.inputPath, "YARA-BND-004", err, nil)
		}
		report := bundle.Validate()
		subject, err := canonicalSubject("DeploymentBundle", bundle)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "bundle.validate", subject, bundle.APIVersion, bundle.Kind, bundle.Metadata.Name, report)
	case "target-preflight":
		result, err := resources.LoadTargetPreflightResult(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "target.preflight.validate", "TargetPreflightResult", options.inputPath, "YARA-TPR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("TargetPreflightResult", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "TargetPreflightResult", Digest: result.Metadata.ResultID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "target.preflight.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "change-set":
		result, err := resources.LoadKubernetesChangeSet(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "target.changeset.validate", "KubernetesChangeSet", options.inputPath, "YARA-CHG-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("KubernetesChangeSet", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "KubernetesChangeSet", Digest: result.Metadata.ChangeSetID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "target.changeset.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "approval":
		result, err := resources.LoadDeploymentApproval(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "approval.validate", "DeploymentApproval", options.inputPath, "YARA-APR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("DeploymentApproval", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "DeploymentApproval", Digest: result.Metadata.ApprovalID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "approval.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "import-receipt":
		result, err := resources.LoadArtifactImportReceipt(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "artifact.import-receipt.validate", "ArtifactImportReceipt", options.inputPath, "YARA-AIR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("ArtifactImportReceipt", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "ArtifactImportReceipt", Digest: result.Metadata.ImportReceiptID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "artifact.import-receipt.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "receipt":
		result, err := resources.LoadDeploymentReceipt(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "deployment.receipt.validate", "DeploymentReceipt", options.inputPath, "YARA-RCP-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("DeploymentReceipt", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "DeploymentReceipt", Digest: result.Metadata.ReceiptID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "deployment.receipt.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "bootstrap-receipt":
		result, err := resources.LoadBootstrapReceipt(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "deployment.bootstrap-receipt.validate", "BootstrapReceipt", options.inputPath, "YARA-BST-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("BootstrapReceipt", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "BootstrapReceipt", Digest: result.Metadata.ReceiptID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "deployment.bootstrap-receipt.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "retirement-receipt":
		result, err := resources.LoadRetirementReceipt(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "deployment.retirement-receipt.validate", "RetirementReceipt", options.inputPath, "YARA-RTR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("RetirementReceipt", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "RetirementReceipt", Digest: result.Metadata.ReceiptID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "deployment.retirement-receipt.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "rollback-receipt":
		result, err := resources.LoadRollbackReceipt(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "deployment.rollback-receipt.validate", "RollbackReceipt", options.inputPath, "YARA-RBK-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("RollbackReceipt", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "RollbackReceipt", Digest: result.Metadata.ReceiptID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "deployment.rollback-receipt.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "promotion-review":
		result, err := resources.LoadPromotionReview(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "promotion.review.validate", "PromotionReview", options.inputPath, "YARA-PRM-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("PromotionReview", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "PromotionReview", Digest: result.Metadata.ReviewID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "promotion.review.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "artifact-transfer-receipt":
		result, err := resources.LoadArtifactTransferReceipt(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "artifact.transfer-receipt.validate", "ArtifactTransferReceipt", options.inputPath, "YARA-ATR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("ArtifactTransferReceipt", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "ArtifactTransferReceipt", Digest: result.Metadata.TransferReceiptID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "artifact.transfer-receipt.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "artifact-scan-receipt":
		result, err := resources.LoadArtifactScanReceipt(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "artifact.scan-receipt.validate", "ArtifactScanReceipt", options.inputPath, "YARA-ASC-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("ArtifactScanReceipt", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "ArtifactScanReceipt", Digest: result.Metadata.ScanReceiptID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "artifact.scan-receipt.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "airgap-provenance-gate-result":
		result, err := resources.LoadAirgapProvenanceGateResult(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "airgap.provenance-gate-result.validate", "AirgapProvenanceGateResult", options.inputPath, "YARA-AGP-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("AirgapProvenanceGateResult", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "AirgapProvenanceGateResult", Digest: result.Metadata.GateResultID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "airgap.provenance-gate-result.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "airgap-gate-trust-policy":
		result, err := resources.LoadAirgapGateTrustPolicy(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "airgap.gate-trust-policy.validate", "AirgapGateTrustPolicy", options.inputPath, "YARA-AGT-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("AirgapGateTrustPolicy", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "AirgapGateTrustPolicy", Digest: result.Metadata.PolicyID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "airgap.gate-trust-policy.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "airgap-gate-trust-policy-diff":
		result, err := resources.LoadAirgapGateTrustPolicyDiff(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "airgap.gate-trust-policy-diff.validate", "AirgapGateTrustPolicyDiff", options.inputPath, "YARA-AGD-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("AirgapGateTrustPolicyDiff", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "AirgapGateTrustPolicyDiff", Digest: result.Metadata.DiffID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "airgap.gate-trust-policy-diff.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "airgap-gate-transition-review":
		result, err := resources.LoadAirgapGateTransitionReview(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "airgap.gate-transition-review.validate", "AirgapGateTransitionReview", options.inputPath, "YARA-AGR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("AirgapGateTransitionReview", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "AirgapGateTransitionReview", Digest: result.Metadata.ReviewID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "airgap.gate-transition-review.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "lifecycle-proof-ledger":
		result, err := resources.LoadLifecycleProofLedger(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "lifecycle.proof-ledger.validate", "LifecycleProofLedger", options.inputPath, "YARA-LGR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("LifecycleProofLedger", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "LifecycleProofLedger", Digest: result.Metadata.LedgerID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "lifecycle.proof-ledger.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "lifecycle-proof-approval":
		result, err := resources.LoadLifecycleProofApproval(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "lifecycle.proof-approval.validate", "LifecycleProofApproval", options.inputPath, "YARA-LPA-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("LifecycleProofApproval", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "LifecycleProofApproval", Digest: result.Metadata.ApprovalID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "lifecycle.proof-approval.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "publication-chain-rehearsal":
		result, err := resources.LoadPublicationChainRehearsal(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "publication.chain.rehearsal.validate", "PublicationChainRehearsal", options.inputPath, "YARA-PCR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("PublicationChainRehearsal", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "PublicationChainRehearsal", Digest: result.Metadata.RehearsalID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "publication.chain.rehearsal.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "publication-chain-renewal-review":
		result, err := resources.LoadPublicationChainRenewalReview(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "publication.chain.renewal-review.validate", "PublicationChainRenewalReview", options.inputPath, "YARA-PCRR-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("PublicationChainRenewalReview", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "PublicationChainRenewalReview", Digest: result.Metadata.ReviewID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "publication.chain.renewal-review.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	case "runtime-drift-signal":
		result, err := resources.LoadRuntimeDriftSignal(options.inputPath)
		if err != nil {
			return writeAuditedLoadError(stdout, options.auditPath, "runtime.drift-signal.validate", "RuntimeDriftSignal", options.inputPath, "YARA-RDS-004", err, nil)
		}
		report := result.Validate()
		subject, err := canonicalSubject("RuntimeDriftSignal", result)
		if err != nil {
			return writeLoadError(stdout, "YARA-AUD-500", err)
		}
		if report.Valid {
			subject = audit.Subject{Kind: "RuntimeDriftSignal", Digest: result.Metadata.SignalID}
		}
		return writeValidationResultWithAudit(stdout, options.auditPath, "runtime.drift-signal.validate", subject, result.APIVersion, result.Kind, result.Metadata.Name, report)
	default:
		writeUsage(stderr)
		return ExitUnsupported
	}
}

func verifyAudit(path string, output io.Writer) int {
	events, err := audit.LoadJSONL(path)
	if err != nil {
		return writeLoadError(output, "YARA-AUD-004", err)
	}
	head, err := audit.Verify(events)
	if err != nil {
		return writeLoadError(output, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(auditVerificationResult{Valid: true, Events: len(events), HeadDigest: head}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func writeValidation(output io.Writer, apiVersion, kind, name string, report diagnostics.Report) int {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if report.Valid {
		if err := encoder.Encode(validationResult{Valid: true, APIVersion: apiVersion, Kind: kind, Name: name}); err != nil {
			return ExitInternal
		}
		return ExitSuccess
	}
	if err := encoder.Encode(report); err != nil {
		return ExitInternal
	}
	return ExitInvalidInput
}

func writeLoadError(output io.Writer, code string, err error) int {
	report := diagnostics.NewReport(diagnostics.Error(code, err.Error()))
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if encodeErr := encoder.Encode(report); encodeErr != nil {
		return ExitInternal
	}
	return ExitInvalidInput
}

func writeUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  yara version")
	fmt.Fprintln(output, "  yara serve --catalog <file> --coverage-report <file> [--port <port>]")
	fmt.Fprintln(output, "  yara request validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara inventory validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara catalog validate <snapshot-file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara catalog coverage create --catalog <file> --evidence-dir <directory> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara catalog coverage validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara catalog coverage lifecycle-publication-policy --report <file> [--assertion <id>] --audit-output <file>")
	fmt.Fprintln(output, "  yara catalog coverage runtime-drift-policy --report <file> [--assertion <id>] --audit-output <file>")
	fmt.Fprintln(output, "  yara catalog coverage signing-authority-boundary --report <file> --trust-policy <file> --authorization <file> [--authorization <file> ...] --audit-output <file>")
	fmt.Fprintln(output, "  yara plan create --request <file> --inventory <file> --catalog <file> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara plan validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara plan explain <file> [--decision <id>] [--audit-output <file>]")
	fmt.Fprintln(output, "  yara plan diff <from-file> <to-file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara debug bundle --plan <file> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara render docker-compose --plan <file> --catalog <file> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara render kubernetes-gitops --plan <file> --catalog <file> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara bundle validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara target preflight kubernetes --bundle <file> --name <name> --output <file> --audit-output <file> [--kubeconfig <file>] [--context <name>] [--timeout <duration>]")
	fmt.Fprintln(output, "  yara target-preflight validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara target changeset kubernetes --bundle <file> --preflight <file> --name <name> --output <file> --audit-output <file> [--kubeconfig <file>] [--context <name>] [--timeout <duration>]")
	fmt.Fprintln(output, "  yara change-set validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara approval record --bundle <file> --preflight <file> --change-set <file> --name <name> --decision <approve|reject> --reason-reference <reference> --output <file> --audit-output <file> [--valid-for <duration>]")
	fmt.Fprintln(output, "  yara approval validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara import-receipt validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara authorization issue --bundle <file> --preflight <file> --change-set <file> --approval <file> --private-key <file> --key-id <id> --name <name> --output <file> --audit-output <file> [--valid-for <duration>]")
	fmt.Fprintln(output, "  yara authorization issue-retirement --bundle <file> --preflight <file> --change-set <file> --approval <file> --private-key <file> --key-id <id> --name <name> --output <file> --audit-output <file> [--valid-for <duration>]")
	fmt.Fprintln(output, "  yara authorization issue-rollback --bundle <file> --preflight <file> --change-set <file> --approval <file> --private-key <file> --key-id <id> --name <name> --output <file> --audit-output <file> [--valid-for <duration>]")
	fmt.Fprintln(output, "  yara authorization verify --authorization <file> --public-key <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara deployment apply kubernetes --bundle <file> --preflight <file> --change-set <file> --approval <file> --import-receipt <file> --authorization <file> --public-key <file> --confirm-authorization <sha256:id> --name <name> --receipt-output <file> --audit-output <file> [--airgap-gate-result <file> --airgap-gate-trust-policy <file> --confirm-airgap-gate-trust-policy <sha256:id> --airgap-gate-policy-diff <file> --confirm-airgap-gate-policy-diff <sha256:id> --airgap-gate-transition-review <file> --confirm-airgap-gate-transition-review <sha256:id>] [--kubeconfig <file>] [--context <name>] [--timeout <duration>]")
	fmt.Fprintln(output, "  yara deployment bootstrap kubernetes --name <name> --namespace <name> --model-pvc <name> --storage-class <name> --size <value> --target <sha256:id> --receipt-output <file> --audit-output <file> [--kubeconfig <file>] [--context <name>] [--timeout <duration>]")
	fmt.Fprintln(output, "  yara deployment import kubernetes --bundle <file> --confirm-bundle <sha256:id> --preflight <file> --target <sha256:id> --artifact-ref <ref> --source-dir <directory> [--internal-root <path>] --namespace <name> --model-pvc <name> --name <name> --output <file> --audit-output <file> [--kubeconfig <file>] [--context <name>] [--timeout <duration>]")
	fmt.Fprintln(output, "  yara deployment retire kubernetes --bundle <file> --preflight <file> --change-set <file> --approval <file> --authorization <file> --public-key <file> --confirm-authorization <sha256:id> --name <name> --receipt-output <file> --audit-output <file> [--kubeconfig <file>] [--context <name>] [--timeout <duration>]")
	fmt.Fprintln(output, "  yara deployment rollback kubernetes --bundle <file> --preflight <file> --change-set <file> --approval <file> --authorization <file> --public-key <file> --confirm-authorization <sha256:id> --name <name> --receipt-output <file> --audit-output <file> [--kubeconfig <file>] [--context <name>] [--timeout <duration>]")
	fmt.Fprintln(output, "  yara receipt validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara bootstrap-receipt validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara retirement-receipt validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara rollback-receipt validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara scenario validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara scenario validate-all <directory> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara contract preflight --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract runtime-smoke --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract model-inference --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract capacity-boundary --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract sustained-capacity --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract policy --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara contract lifecycle --catalog <file> --assertion <id> --target <user@host> --name <name> --output <file> --audit-output <file> --lifecycle-proof-ledger <file> --confirm-lifecycle-proof-ledger <sha256:id> --lifecycle-apply-receipt <file> --lifecycle-retirement-receipt <file> --lifecycle-rollback-receipt <file> --confirm-lifecycle-reason-reference <ref> [--lifecycle-proof-max-age <duration>]")
	fmt.Fprintln(output, "  yara contract validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara promotion review record --catalog <file> --assertion <id> --evidence <sha256:id> [--evidence <sha256:id> ...] [--publication-chain-rehearsal <file> --confirm-publication-chain-rehearsal <sha256:id> --max-rehearsal-age <duration> --publication-chain-retention-audit <file> --confirm-publication-chain-retention-audit <sha256:id> --max-retention-audit-age <duration> --publication-chain-renewal-review <file> --confirm-publication-chain-renewal-review <sha256:id> --max-renewal-review-age <duration>] --reviewer-role <role> --decision <approved|changes-required|abstained> --reason-reference <ref> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara promotion-review validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara artifact import record --bundle <file> --preflight <file> --importer-name <name> --importer-version <version> [--internal-root <path>] --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara artifact transfer record --bundle <file> --import-receipt <file> --stage <staging-to-vault|vault-to-registry|registry-to-runtime> --source-attestation-ref <ref> --destination-attestation-ref <ref> [--prior-receipt <sha256:id> ...] --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara artifact-transfer-receipt validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara artifact scan record --bundle <file> --transfer-receipt <file> --scanner-name <name> --scanner-version <version> --scanner-profile <profile> --policy-digest <sha256:id> --verdict <passed|failed|blocked> --reason-reference <ref> [--prior-receipt <sha256:id> ...] --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara artifact-scan-receipt validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara airgap provenance-gate evaluate --bundle <file> --import-receipt <file> --transfer-receipt <file> --scan-receipt <file> --private-key <file> --key-id <id> --reason-reference <ref> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara airgap provenance-gate verify --gate-result <file> --trust-policy <file> --confirm-policy <sha256:id> [--policy-diff <file> --confirm-policy-diff <sha256:id> --transition-review <file> --confirm-transition-review <sha256:id>] [--audit-output <file>]")
	fmt.Fprintln(output, "  yara airgap gate-trust-policy record --target-reference-digest <sha256:id> --signer key-id=<id>,public-key=<pem>,status=<active|revoked>[,valid-from=<RFC3339>][,valid-until=<RFC3339>] --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara airgap gate-trust-policy diff --from-policy <file> --to-policy <file> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara airgap gate-trust-policy review-transition --policy-diff <file> --decision <approved|changes-required|abstained> --reviewer-role <role> --reason-reference <ref> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara lifecycle proof record --apply-receipt <file> --retirement-receipt <file> --rollback-receipt <file> --reviewer-role <role> --decision <approved|changes-required|abstained> --reason-reference <ref> --name <name> --output <file> --audit-output <file> [--max-receipt-age <duration>]")
	fmt.Fprintln(output, "  yara lifecycle proof approve-publication --catalog <file> --assertion <id> --lifecycle-proof-ledger <file> --confirm-lifecycle-proof-ledger <sha256:id> --evidence <sha256:id> [--evidence <sha256:id> ...] --reviewer-role <role> --decision <approved|changes-required|abstained> --reason-reference <ref> --max-ledger-age <duration> [--valid-for <duration>] --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara publication chain rehearse --catalog <file> --assertion <id> --lifecycle-proof-approval <file> --confirm-lifecycle-proof-approval <sha256:id> --integration-publication-attestation <file> --confirm-integration-publication-attestation <sha256:id> --coverage-report <file> --confirm-coverage-report <sha256:id> --trust-policy <file> --confirm-trust-policy <sha256:id> --signing-boundary-audit <file> --authorization <file> [--authorization <file> ...] --reviewer-role <role> --decision <approved|changes-required|abstained> --reason-reference <ref> --max-evidence-age <duration> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara publication chain retention-diagnostics --catalog <file> --assertion <id> --current-rehearsal <file> [--current-rehearsal <file> ...] [--candidate-rehearsal <file>] --audit-output <file>")
	fmt.Fprintln(output, "  yara publication chain renewal-review --catalog <file> --assertion <id> --publication-chain-rehearsal <file> --confirm-publication-chain-rehearsal <sha256:id> --publication-chain-retention-audit <file> --confirm-publication-chain-retention-audit <sha256:id> --promotion-review <file> --confirm-promotion-review <sha256:id> --lifecycle-proof-approval <file> --confirm-lifecycle-proof-approval <sha256:id> --integration-publication-attestation <file> --confirm-integration-publication-attestation <sha256:id> --evidence <sha256:id> [--evidence <sha256:id> ...] --reviewer-role <role> --decision <approved|changes-required|abstained> --reason-reference <ref> --max-evidence-age <duration> [--valid-for <duration>] --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara runtime drift-signal record --catalog <file> --assertion <id> --bundle <file> --preflight <file> --confirm-target <sha256:id> --observer-name <name> --observer-version <version> --status <in-sync|drifted> --check id=<id>,expected=<value>,observed=<value>,status=<matched|drifted>[,reason-code=<YARA-...>] [--check ...] --name <name> --output <file> --audit-output <file> [--max-preflight-age <duration>]")
	fmt.Fprintln(output, "  yara airgap-provenance-gate-result validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara airgap-gate-trust-policy validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara airgap-gate-trust-policy-diff validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara airgap-gate-transition-review validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara lifecycle-proof-ledger validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara lifecycle-proof-approval validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara publication-chain-rehearsal validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara publication-chain-renewal-review validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara runtime-drift-signal validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara integration component-smoke --catalog <file> --target <local|user@host> --component <id@version> [--component <id@version> ...] --confirm-catalog-digest <sha256:id> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara integration topology-end-to-end --catalog <file> --target <local|user@host> --topology <id@version> --component <id@version> --component <id@version> [--component <id@version> ...] --confirm-catalog-digest <sha256:id> --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara integration execute <component-smoke|topology-end-to-end> [mode-flags]")
	fmt.Fprintln(output, "  yara integration publish attest --catalog <file> --evidence-dir <directory> --assertion <id> --evidence <sha256:id> [--evidence <sha256:id> ...] --reviewer-role <role> --decision <approved|changes-required|abstained> --reason-reference <ref> --max-evidence-age <duration> [--valid-for <duration>] --name <name> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara integration-publication-attestation validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara integration validate <file> [--audit-output <file>]")
	fmt.Fprintln(output, "  yara audit verify <file>")
}
