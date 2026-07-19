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
	sustainedCapacityRequests    = 32
	sustainedCapacityContext     = modelInferenceContext
	sustainedCapacityConcurrency = 1
	sustainedCapacityMaxTokens   = modelInferenceMaxTokens
	sustainedCapacityGPUPercent  = modelInferenceGPUPercent
)

type SustainedCapacityRunner interface {
	Run(context.Context, string, catalog.ContractTarget) ([]resources.ContractTestCheck, error)
}

type SSHSustainedCapacityRunner struct {
	Timeout time.Duration
}

func (r SSHSustainedCapacityRunner) Run(parent context.Context, sshTarget string, target catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 45 * time.Minute
	}
	observation, err := runModelServingContract(parent, sshTarget, target, timeout, modelServingProfile{
		ContextTokens:         sustainedCapacityContext,
		Concurrency:           sustainedCapacityConcurrency,
		MaxTokens:             sustainedCapacityMaxTokens,
		RequestProgram:        sustainedCapacityProgram(sustainedCapacityRequests, sustainedCapacityMaxTokens),
		GPUUtilizationPercent: sustainedCapacityGPUPercent,
	})
	if err != nil {
		return nil, err
	}
	return sustainedCapacityChecks(observation, modelArtifactBytes(target.ModelArtifact))
}

func sustainedCapacityChecks(observation modelInferenceObservation, modelBytes int64) ([]resources.ContractTestCheck, error) {
	checks, err := modelServingChecks(observation, modelBytes, sustainedCapacityContext, sustainedCapacityConcurrency, sustainedCapacityMaxTokens, sustainedCapacityGPUPercent)
	if err != nil {
		return nil, err
	}
	passed := observation.InferenceStatus == 200 &&
		observation.SustainedAttempted == sustainedCapacityRequests &&
		observation.SustainedCompleted == sustainedCapacityRequests &&
		observation.SustainedPromptTokens > 0 &&
		observation.SustainedCompletionTokens >= sustainedCapacityRequests &&
		observation.SustainedCompletionTokens <= sustainedCapacityRequests*sustainedCapacityMaxTokens &&
		observation.SustainedTotalTokens == observation.SustainedPromptTokens+observation.SustainedCompletionTokens
	status, code := "passed", ""
	if !passed {
		if observation.InferenceStatus != 200 {
			status, code = "blocked", "YARA-CTR-149"
		} else {
			status, code = "failed", "YARA-CTR-181"
		}
	}
	measurements := map[string]int{
		"concurrency":              sustainedCapacityConcurrency,
		"expectedRequests":         sustainedCapacityRequests,
		"observedAttempted":        observation.SustainedAttempted,
		"observedCompleted":        observation.SustainedCompleted,
		"observedCompletionTokens": observation.SustainedCompletionTokens,
		"observedPromptTokens":     observation.SustainedPromptTokens,
		"observedTotalTokens":      observation.SustainedTotalTokens,
	}
	item, err := check("capacity.sustained-requests", status, code, measurements)
	if err != nil {
		return nil, errors.New("digest sustained-capacity evidence")
	}
	item.Measurements = measurements
	checks = append(checks, item)
	slices.SortFunc(checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	return checks, nil
}

func sustainedCapacityProgram(requests, maxTokens int) string {
	return fmt.Sprintf(`import hashlib,json,urllib.request
attempted=0
completed=0
prompt_tokens=0
completion_tokens=0
total_tokens=0
last={"inferenceStatus":0,"model":"","finishReason":"","promptTokens":0,"completionTokens":0,"totalTokens":0,"contentDigest":"sha256:"+hashlib.sha256(b"").hexdigest()}
try:
 for index in range(%d):
  attempted+=1
  payload={"model":"yara-contract","messages":[{"role":"user","content":"Reply with exactly YARA_OK"}],"temperature":0,"seed":index,"max_tokens":%d}
  request=urllib.request.Request("http://127.0.0.1:8000/v1/chat/completions",data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"})
  response=urllib.request.urlopen(request,timeout=120); body=response.read(); data=json.loads(body); choice=data["choices"][0]; content=choice["message"]["content"] or ""; usage=data.get("usage",{})
  last={"inferenceStatus":response.status,"model":data.get("model",""),"finishReason":choice.get("finish_reason",""),"promptTokens":usage.get("prompt_tokens",0),"completionTokens":usage.get("completion_tokens",0),"totalTokens":usage.get("total_tokens",0),"contentDigest":"sha256:"+hashlib.sha256(content.encode()).hexdigest()}
  if response.status!=200 or last["model"]!="yara-contract" or last["completionTokens"]<1 or last["completionTokens"]>%d: raise RuntimeError("bounded response contract failed")
  completed+=1; prompt_tokens+=last["promptTokens"]; completion_tokens+=last["completionTokens"]; total_tokens+=last["totalTokens"]
 last.update({"sustainedRequestsAttempted":attempted,"sustainedRequestsCompleted":completed,"sustainedPromptTokens":prompt_tokens,"sustainedCompletionTokens":completion_tokens,"sustainedTotalTokens":total_tokens}); print(json.dumps(last))
except Exception as error:
 body=getattr(error,"read",lambda:b"")(); print(json.dumps({"failureStage":"inference","inferenceStatus":getattr(error,"code",0),"contentDigest":"sha256:"+hashlib.sha256(body).hexdigest(),"sustainedRequestsAttempted":attempted,"sustainedRequestsCompleted":completed,"sustainedPromptTokens":prompt_tokens,"sustainedCompletionTokens":completion_tokens,"sustainedTotalTokens":total_tokens}))`, requests, maxTokens, maxTokens)
}

func EvaluateSustainedCapacity(name, catalogDigest string, target catalog.ContractTarget, environment resources.ContractTestEnvironment, artifactChecks, capacityChecks []resources.ContractTestCheck) (resources.ContractTestResult, error) {
	result, err := Evaluate(name, catalogDigest, target, environment)
	if err != nil {
		return resources.ContractTestResult{}, err
	}
	result.Metadata.ResultID = ""
	result.Spec.Mode = "sustained-capacity"
	result.Spec.Checks = append(result.Spec.Checks, artifactChecks...)
	result.Spec.Checks = append(result.Spec.Checks, capacityChecks...)
	slices.SortFunc(result.Spec.Checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	result.Spec.Outcome = deriveOutcome(result.Spec.Checks)
	result.Spec.Limitations = []string{
		"Model acquisition used external network access; this is not air-gap evidence.",
		"The contract runs 32 sequential bounded requests at concurrency 1; it establishes no higher-concurrency capacity.",
		"The contract records no latency, throughput, quality or service-level objective and makes no performance claim.",
		"The contract is a bounded repeated-request observation, not a long-duration soak, production-headroom or availability test.",
		"The contract does not establish restart, lifecycle, upgrade or recovery compatibility.",
	}
	if len(capacityChecks) == 0 {
		result.Spec.Limitations = append(result.Spec.Limitations, "Sustained workload was not started because an earlier gate failed.")
	}
	slices.Sort(result.Spec.Limitations)
	return result.AssignResultID()
}
