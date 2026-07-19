package contracttest

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type LifecycleContractRunner interface {
	Run(context.Context, string, catalog.ContractTarget) ([]resources.ContractTestCheck, error)
}

type SSHLifecycleContractRunner struct {
	Timeout time.Duration
}

func (r SSHLifecycleContractRunner) Run(parent context.Context, sshTarget string, target catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	observation, err := runModelServingContract(parent, sshTarget, target, timeout, modelServingProfile{
		ContextTokens:  modelInferenceContext,
		Concurrency:    modelInferenceConcurrency,
		MaxTokens:      modelInferenceMaxTokens,
		RequestProgram: boundedInferenceProgram(modelInferenceMaxTokens),
		TestLifecycle:  true,
	})
	if err != nil {
		return nil, err
	}
	return lifecycleContractChecks(observation, modelArtifactBytes(target.ModelArtifact))
}

func lifecycleContractChecks(observation modelInferenceObservation, modelBytes int64) ([]resources.ContractTestCheck, error) {
	checks, err := modelServingChecks(observation, modelBytes, modelInferenceContext, modelInferenceConcurrency, modelInferenceMaxTokens, modelInferenceGPUPercent)
	if err != nil {
		return nil, err
	}
	appendLifecycleCheck := func(id string, passed bool, code string, evidence any) error {
		status, diagnostic := "passed", ""
		if !passed {
			status, diagnostic = "failed", code
			if !observation.LifecycleInspected && id != "lifecycle.inspect-state" && !(id == "lifecycle.restart-completed" && observation.FailureStage == "restart") {
				status, diagnostic = "blocked", "YARA-CTR-149"
			}
		}
		item, checkErr := check(id, status, diagnostic, evidence)
		if checkErr == nil {
			checks = append(checks, item)
		}
		return checkErr
	}
	preInferencePassed := observation.PreRestartInference == 200 &&
		observation.PreRestartModel == "yara-contract" &&
		strings.HasPrefix(observation.PreRestartContent, "sha256:") && len(observation.PreRestartContent) == 71 &&
		observation.PreRestartCompletion > 0 && observation.PreRestartCompletion <= modelInferenceMaxTokens
	postInferencePassed := observation.InferenceStatus == 200 &&
		observation.Model == "yara-contract" &&
		strings.HasPrefix(observation.ContentDigest, "sha256:") && len(observation.ContentDigest) == 71 &&
		observation.CompletionTokens > 0 && observation.CompletionTokens <= modelInferenceMaxTokens

	if err := appendLifecycleCheck("lifecycle.inspect-state", observation.LifecycleInspected, "YARA-CTR-169", observation.LifecycleInspected); err != nil {
		return nil, err
	}
	if err := appendLifecycleCheck("lifecycle.pre-restart-health", observation.PreRestartHealthStatus == 200, "YARA-CTR-170", observation.PreRestartHealthStatus); err != nil {
		return nil, err
	}
	if err := appendLifecycleCheck("lifecycle.pre-restart-inference", preInferencePassed, "YARA-CTR-170", map[string]any{
		"completionTokens": observation.PreRestartCompletion,
		"contentDigest":    observation.PreRestartContent,
		"model":            observation.PreRestartModel,
		"status":           observation.PreRestartInference,
	}); err != nil {
		return nil, err
	}
	if err := appendLifecycleCheck("lifecycle.restart-completed", observation.RestartCompleted, "YARA-CTR-171", observation.RestartCompleted); err != nil {
		return nil, err
	}
	if err := appendLifecycleCheck("lifecycle.started-at-advanced", observation.StartedAtAdvanced, "YARA-CTR-172", observation.StartedAtAdvanced); err != nil {
		return nil, err
	}
	if err := appendLifecycleCheck("lifecycle.container-identity-stable", observation.ContainerIdentityStable, "YARA-CTR-173", observation.ContainerIdentityStable); err != nil {
		return nil, err
	}
	if err := appendLifecycleCheck("lifecycle.configuration-stable", observation.ConfigurationStable, "YARA-CTR-174", observation.ConfigurationStable); err != nil {
		return nil, err
	}
	if err := appendLifecycleCheck("lifecycle.post-restart-health", observation.PostRestartHealthStatus == 200, "YARA-CTR-175", observation.PostRestartHealthStatus); err != nil {
		return nil, err
	}
	if err := appendLifecycleCheck("lifecycle.post-restart-inference", postInferencePassed, "YARA-CTR-176", map[string]any{
		"completionTokens": observation.CompletionTokens,
		"contentDigest":    observation.ContentDigest,
		"model":            observation.Model,
		"status":           observation.InferenceStatus,
	}); err != nil {
		return nil, err
	}
	if err := appendLifecycleCheck("lifecycle.cleanup-completed", observation.CleanupCompleted, "YARA-CTR-177", observation.CleanupCompleted); err != nil {
		return nil, err
	}
	slices.SortFunc(checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	return checks, nil
}

func EvaluateLifecycleContract(name, catalogDigest string, target catalog.ContractTarget, environment resources.ContractTestEnvironment, artifactChecks, lifecycleChecks []resources.ContractTestCheck) (resources.ContractTestResult, error) {
	result, err := Evaluate(name, catalogDigest, target, environment)
	if err != nil {
		return resources.ContractTestResult{}, err
	}
	result.Metadata.ResultID = ""
	result.Spec.Mode = "lifecycle-contract"
	result.Spec.Checks = append(result.Spec.Checks, artifactChecks...)
	result.Spec.Checks = append(result.Spec.Checks, lifecycleChecks...)
	slices.SortFunc(result.Spec.Checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	result.Spec.Outcome = deriveOutcome(result.Spec.Checks)
	result.Spec.Limitations = []string{
		"The contract proves one operator-requested restart of the same container and same pinned artifacts, not crash-loop or host-failure recovery.",
		"The serving process is stateless; this result does not establish backup, restore or persistent-data recovery.",
		"The contract does not establish version upgrade, rollback, high availability, traffic draining or zero-downtime behavior.",
		"One bounded request before and after restart does not establish sustained availability, capacity, latency or output equivalence.",
		"Model acquisition used external network access before the isolated serving phase; this is not air-gap evidence.",
	}
	if len(lifecycleChecks) == 0 {
		result.Spec.Limitations = append(result.Spec.Limitations, "Lifecycle workload was not started because an earlier gate failed.")
	}
	slices.Sort(result.Spec.Limitations)
	return result.AssignResultID()
}
