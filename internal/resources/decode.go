package resources

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

const maxResourceBytes = 4 << 20

var ErrResourceTooLarge = errors.New("resource exceeds the 4 MiB input limit")

func LoadPlatformRequest(path string) (PlatformRequest, error) {
	return loadResource[PlatformRequest](path)
}

func LoadInventory(path string) (Inventory, error) {
	return loadResource[Inventory](path)
}

func LoadPlatformPlan(path string) (PlatformPlan, error) {
	return loadResource[PlatformPlan](path)
}

func LoadPlatformPlanDiff(path string) (PlatformPlanDiff, error) {
	return loadResource[PlatformPlanDiff](path)
}

func LoadDebugBundle(path string) (DebugBundle, error) {
	return loadResource[DebugBundle](path)
}

func LoadGoldenScenario(path string) (GoldenScenario, error) {
	return loadResource[GoldenScenario](path)
}

func LoadScenarioReview(path string) (ScenarioReview, error) {
	return loadResource[ScenarioReview](path)
}

func LoadAcceptanceGateReview(path string) (AcceptanceGateReview, error) {
	return loadResource[AcceptanceGateReview](path)
}

func LoadContractTestResult(path string) (ContractTestResult, error) {
	return loadResource[ContractTestResult](path)
}

func LoadIntegrationTestResult(path string) (IntegrationTestResult, error) {
	return loadResource[IntegrationTestResult](path)
}

func LoadDeploymentBundle(path string) (DeploymentBundle, error) {
	return loadResource[DeploymentBundle](path)
}

func LoadOfflineAcquisitionManifest(path string) (OfflineAcquisitionManifest, error) {
	return loadResource[OfflineAcquisitionManifest](path)
}

func LoadTargetPreflightResult(path string) (TargetPreflightResult, error) {
	return loadResource[TargetPreflightResult](path)
}

func LoadKubernetesChangeSet(path string) (KubernetesChangeSet, error) {
	return loadResource[KubernetesChangeSet](path)
}

func LoadDeploymentApproval(path string) (DeploymentApproval, error) {
	return loadResource[DeploymentApproval](path)
}

func LoadDeploymentReceipt(path string) (DeploymentReceipt, error) {
	return loadResource[DeploymentReceipt](path)
}

func LoadArtifactImportReceipt(path string) (ArtifactImportReceipt, error) {
	return loadResource[ArtifactImportReceipt](path)
}

func LoadExecutionAuthorization(path string) (ExecutionAuthorization, error) {
	return loadResource[ExecutionAuthorization](path)
}

func LoadRetirementReceipt(path string) (RetirementReceipt, error) {
	return loadResource[RetirementReceipt](path)
}

func LoadRollbackReceipt(path string) (RollbackReceipt, error) {
	return loadResource[RollbackReceipt](path)
}

func LoadPromotionReview(path string) (PromotionReview, error) {
	return loadResource[PromotionReview](path)
}

func LoadArtifactTransferReceipt(path string) (ArtifactTransferReceipt, error) {
	return loadResource[ArtifactTransferReceipt](path)
}

func LoadArtifactScanReceipt(path string) (ArtifactScanReceipt, error) {
	return loadResource[ArtifactScanReceipt](path)
}

func LoadAirgapProvenanceGateResult(path string) (AirgapProvenanceGateResult, error) {
	return loadResource[AirgapProvenanceGateResult](path)
}

func LoadAirgapGateTrustPolicy(path string) (AirgapGateTrustPolicy, error) {
	return loadResource[AirgapGateTrustPolicy](path)
}

func LoadAirgapGateTrustPolicyDiff(path string) (AirgapGateTrustPolicyDiff, error) {
	return loadResource[AirgapGateTrustPolicyDiff](path)
}

func LoadAirgapGateTransitionReview(path string) (AirgapGateTransitionReview, error) {
	return loadResource[AirgapGateTransitionReview](path)
}

func LoadLifecycleProofLedger(path string) (LifecycleProofLedger, error) {
	return loadResource[LifecycleProofLedger](path)
}

func LoadLifecycleProofApproval(path string) (LifecycleProofApproval, error) {
	return loadResource[LifecycleProofApproval](path)
}

func loadResource[T any](path string) (T, error) {
	var resource T
	data, err := readBounded(path)
	if err != nil {
		return resource, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return resource, errors.New("resource is empty")
	}
	if trimmed[0] == '{' {
		err = decodeJSON(trimmed, &resource)
	} else {
		err = decodeYAML(trimmed, &resource)
	}
	if err != nil {
		return resource, fmt.Errorf("decode resource: %w", err)
	}
	return resource, nil
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open resource: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxResourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read resource: %w", err)
	}
	if len(data) > maxResourceBytes {
		return nil, ErrResourceTooLarge
	}
	return data, nil
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values are not allowed")
}

func decodeYAML(data []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple YAML documents are not allowed")
}
