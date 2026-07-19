package contracttest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

const (
	capacityBoundaryMaxContext  = 32768
	capacityBoundaryConcurrency = 1
	capacityBoundaryMaxTokens   = 8
)

type CapacityBoundaryRunner interface {
	Run(context.Context, string, catalog.ContractTarget) ([]resources.ContractTestCheck, error)
}

type SSHCapacityBoundaryRunner struct {
	Timeout time.Duration
}

func (r SSHCapacityBoundaryRunner) Run(parent context.Context, sshTarget string, target catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	contextTokens := target.Conditions.MaximumContextTokens
	if contextTokens <= capacityBoundaryMaxTokens || contextTokens > capacityBoundaryMaxContext {
		return nil, fmt.Errorf("cataloged maximum context %d is outside the bounded capacity contract", contextTokens)
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 40 * time.Minute
	}
	observation, err := runModelServingContract(parent, sshTarget, target, timeout, modelServingProfile{
		ContextTokens:  contextTokens,
		Concurrency:    capacityBoundaryConcurrency,
		MaxTokens:      capacityBoundaryMaxTokens,
		RequestProgram: capacityBoundaryProgram(contextTokens, capacityBoundaryMaxTokens),
	})
	if err != nil {
		return nil, err
	}
	return capacityBoundaryChecks(observation, modelArtifactBytes(target.ModelArtifact), contextTokens)
}

func capacityBoundaryChecks(observation modelInferenceObservation, modelBytes int64, contextTokens int) ([]resources.ContractTestCheck, error) {
	checks, err := modelServingChecks(observation, modelBytes, contextTokens, capacityBoundaryConcurrency, capacityBoundaryMaxTokens)
	if err != nil {
		return nil, err
	}
	targetPromptTokens := contextTokens - capacityBoundaryMaxTokens
	boundaryPassed := observation.InferenceStatus == 200 &&
		observation.PromptTokens == targetPromptTokens &&
		observation.CompletionTokens > 0 &&
		observation.CompletionTokens <= capacityBoundaryMaxTokens &&
		observation.TotalTokens == observation.PromptTokens+observation.CompletionTokens &&
		observation.TotalTokens <= contextTokens
	status, code := "passed", ""
	if !boundaryPassed {
		if observation.InferenceStatus != 200 {
			status, code = "blocked", "YARA-CTR-149"
		} else {
			status, code = "failed", "YARA-CTR-157"
		}
	}
	measurements := map[string]int{
		"advertisedContextTokens":  contextTokens,
		"requestedPromptTokens":    targetPromptTokens,
		"observedPromptTokens":     observation.PromptTokens,
		"completionTokenLimit":     capacityBoundaryMaxTokens,
		"observedCompletionTokens": observation.CompletionTokens,
		"observedTotalTokens":      observation.TotalTokens,
	}
	boundary, err := check("capacity.context-boundary", status, code, measurements)
	if err != nil {
		return nil, errors.New("digest context-boundary evidence")
	}
	boundary.Measurements = measurements
	checks = append(checks, boundary)
	slices.SortFunc(checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	return checks, nil
}

func capacityBoundaryProgram(contextTokens, maxTokens int) string {
	targetPromptTokens := contextTokens - maxTokens
	return fmt.Sprintf(`import hashlib,json,urllib.request
target=%d
payload={"model":"yara-contract","messages":[{"role":"user","content":"YARA capacity boundary "*(target*2)}],"temperature":0,"seed":0,"max_tokens":%d,"truncate_prompt_tokens":target}
request=urllib.request.Request("http://127.0.0.1:8000/v1/chat/completions",data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"})
try:
 response=urllib.request.urlopen(request,timeout=600); status=response.status; body=response.read(); data=json.loads(body); choice=data["choices"][0]; content=choice["message"]["content"] or ""; usage=data.get("usage",{}); print(json.dumps({"inferenceStatus":status,"model":data.get("model",""),"finishReason":choice.get("finish_reason",""),"promptTokens":usage.get("prompt_tokens",0),"completionTokens":usage.get("completion_tokens",0),"totalTokens":usage.get("total_tokens",0),"contentDigest":"sha256:"+hashlib.sha256(content.encode()).hexdigest()}))
except Exception as error:
 body=getattr(error,"read",lambda:b"")(); print(json.dumps({"failureStage":"inference","inferenceStatus":getattr(error,"code",0),"contentDigest":"sha256:"+hashlib.sha256(body).hexdigest()}))`, targetPromptTokens, maxTokens)
}

func EvaluateCapacityBoundary(name, catalogDigest string, target catalog.ContractTarget, environment resources.ContractTestEnvironment, artifactChecks, capacityChecks []resources.ContractTestCheck) (resources.ContractTestResult, error) {
	result, err := Evaluate(name, catalogDigest, target, environment)
	if err != nil {
		return resources.ContractTestResult{}, err
	}
	result.Metadata.ResultID = ""
	result.Spec.Mode = "capacity-boundary"
	result.Spec.Checks = append(result.Spec.Checks, artifactChecks...)
	result.Spec.Checks = append(result.Spec.Checks, capacityChecks...)
	slices.SortFunc(result.Spec.Checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	result.Spec.Outcome = deriveOutcome(result.Spec.Checks)
	result.Spec.Limitations = []string{
		"The contract tests one request at concurrency 1 and makes no sustained-load, throughput or latency claim.",
		"Prompt truncation constructs the exact advertised context boundary; it does not establish quality across long inputs.",
		"Model acquisition used external network access; this is not air-gap evidence.",
		"The contract does not establish restart, lifecycle, upgrade or recovery compatibility.",
		"The server had no network, ports or persistent volumes, but broader policy and telemetry behavior remains unproven.",
	}
	if len(capacityChecks) == 0 {
		result.Spec.Limitations = append(result.Spec.Limitations, "Capacity workload was not started because an earlier gate failed.")
	}
	slices.Sort(result.Spec.Limitations)
	return result.AssignResultID()
}
