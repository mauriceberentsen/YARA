package contracttest

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type PolicyContractRunner interface {
	Run(context.Context, string, catalog.ContractTarget) ([]resources.ContractTestCheck, error)
}

type SSHPolicyContractRunner struct {
	Timeout time.Duration
}

func (r SSHPolicyContractRunner) Run(parent context.Context, sshTarget string, target catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	observation, err := runModelServingContract(parent, sshTarget, target, r.Timeout, modelServingProfile{
		ContextTokens:  modelInferenceContext,
		Concurrency:    modelInferenceConcurrency,
		MaxTokens:      modelInferenceMaxTokens,
		RequestProgram: boundedInferenceProgram(modelInferenceMaxTokens),
		InspectPolicy:  true,
	})
	if err != nil {
		return nil, err
	}
	return policyContractChecks(observation, modelArtifactBytes(target.ModelArtifact))
}

func policyContractChecks(observation modelInferenceObservation, modelBytes int64) ([]resources.ContractTestCheck, error) {
	checks, err := modelServingChecks(observation, modelBytes, modelInferenceContext, modelInferenceConcurrency, modelInferenceMaxTokens)
	if err != nil {
		return nil, err
	}
	appendPolicyCheck := func(id string, passed bool, code string, evidence any) error {
		status, diagnostic := "passed", ""
		if !passed {
			status, diagnostic = "failed", code
			if !observation.PolicyInspected && id != "policy.inspect-state" {
				status, diagnostic = "blocked", "YARA-CTR-149"
			}
		}
		item, checkErr := check(id, status, diagnostic, evidence)
		if checkErr == nil {
			checks = append(checks, item)
		}
		return checkErr
	}
	if err := appendPolicyCheck("policy.inspect-state", observation.PolicyInspected, "YARA-CTR-160", observation.PolicyInspected); err != nil {
		return nil, err
	}
	if err := appendPolicyCheck("policy.egress-blocked", observation.EgressBlocked && observation.NetworkMode == "none", "YARA-CTR-161", map[string]any{"activeProbeBlocked": observation.EgressBlocked, "networkMode": observation.NetworkMode}); err != nil {
		return nil, err
	}
	if err := appendPolicyCheck("policy.ports-unpublished", observation.PortsUnpublished, "YARA-CTR-162", observation.PortsUnpublished); err != nil {
		return nil, err
	}
	if err := appendPolicyCheck("policy.telemetry-disabled", observation.TelemetryDisabled, "YARA-CTR-163", observation.TelemetryDisabled); err != nil {
		return nil, err
	}
	if err := appendPolicyCheck("policy.root-filesystem-readonly", observation.RootFilesystemReadOnly, "YARA-CTR-164", observation.RootFilesystemReadOnly); err != nil {
		return nil, err
	}
	if err := appendPolicyCheck("policy.tmpfs-restricted", observation.TmpfsRestricted, "YARA-CTR-164", observation.TmpfsRestricted); err != nil {
		return nil, err
	}
	if err := appendPolicyCheck("policy.mounts-restricted", observation.MountsRestricted && observation.DockerSocketAbsent, "YARA-CTR-165", map[string]bool{"dockerSocketAbsent": observation.DockerSocketAbsent, "mountsRestricted": observation.MountsRestricted}); err != nil {
		return nil, err
	}
	if err := appendPolicyCheck("policy.sensitive-env-absent", observation.SensitiveEnvAbsent, "YARA-CTR-165", observation.SensitiveEnvAbsent); err != nil {
		return nil, err
	}
	if err := appendPolicyCheck("policy.privileges-restricted", observation.PrivilegesRestricted, "YARA-CTR-166", observation.PrivilegesRestricted); err != nil {
		return nil, err
	}
	if err := appendPolicyCheck("policy.cleanup-completed", observation.CleanupCompleted, "YARA-CTR-167", observation.CleanupCompleted); err != nil {
		return nil, err
	}
	slices.SortFunc(checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	return checks, nil
}

func EvaluatePolicyContract(name, catalogDigest string, target catalog.ContractTarget, environment resources.ContractTestEnvironment, artifactChecks, policyChecks []resources.ContractTestCheck) (resources.ContractTestResult, error) {
	result, err := Evaluate(name, catalogDigest, target, environment)
	if err != nil {
		return resources.ContractTestResult{}, err
	}
	result.Metadata.ResultID = ""
	result.Spec.Mode = "policy-contract"
	result.Spec.Checks = append(result.Spec.Checks, artifactChecks...)
	result.Spec.Checks = append(result.Spec.Checks, policyChecks...)
	slices.SortFunc(result.Spec.Checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	result.Spec.Outcome = deriveOutcome(result.Spec.Checks)
	result.Spec.Limitations = []string{
		"The active egress probe and Docker network-none state cover only this serving container and test duration.",
		"Telemetry opt-out environment controls do not prove the absence of every upstream or dependency behavior.",
		"The container runs as image-default root with all Linux capabilities dropped and no-new-privileges; non-root execution remains unproven.",
		"Executable private tmpfs paths are required for generated CUDA/Triton objects and remain an explicit exception.",
		"Model acquisition used external network access before the isolated serving phase; this is not air-gap evidence.",
		"The contract does not establish host hardening, Docker daemon security, supply-chain integrity beyond pinned artifacts or regulatory compliance.",
	}
	if len(policyChecks) == 0 {
		result.Spec.Limitations = append(result.Spec.Limitations, "Policy workload was not started because an earlier gate failed.")
	}
	slices.Sort(result.Spec.Limitations)
	return result.AssignResultID()
}
