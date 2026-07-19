package contracttest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

const (
	modelInferenceMemoryBytes = int64(16 << 30)
	modelInferenceContext     = 1024
	modelInferenceConcurrency = 1
	modelInferenceMaxTokens   = 8
)

type ModelInferenceRunner interface {
	Run(context.Context, string, catalog.ContractTarget) ([]resources.ContractTestCheck, error)
}

type SSHModelInferenceRunner struct {
	Timeout time.Duration
}

type modelInferenceObservation struct {
	FailureStage         string `json:"failureStage"`
	FailureReason        string `json:"failureReason"`
	MemoryAvailableBytes int64  `json:"memoryAvailableBytes"`
	DiskAvailableBytes   int64  `json:"diskAvailableBytes"`
	AcquisitionCompleted bool   `json:"acquisitionCompleted"`
	ArtifactVerified     bool   `json:"artifactVerified"`
	ServerStarted        bool   `json:"serverStarted"`
	NetworkMode          string `json:"networkMode"`
	HealthStatus         int    `json:"healthStatus"`
	InferenceStatus      int    `json:"inferenceStatus"`
	Model                string `json:"model"`
	FinishReason         string `json:"finishReason"`
	PromptTokens         int    `json:"promptTokens"`
	CompletionTokens     int    `json:"completionTokens"`
	TotalTokens          int    `json:"totalTokens"`
	ContentDigest        string `json:"contentDigest"`
	ServerLogDigest      string `json:"serverLogDigest"`
}

type modelServingProfile struct {
	ContextTokens  int
	Concurrency    int
	MaxTokens      int
	RequestProgram string
}

func (r SSHModelInferenceRunner) Run(parent context.Context, sshTarget string, target catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	observation, err := runModelServingContract(parent, sshTarget, target, r.Timeout, modelServingProfile{
		ContextTokens:  modelInferenceContext,
		Concurrency:    modelInferenceConcurrency,
		MaxTokens:      modelInferenceMaxTokens,
		RequestProgram: boundedInferenceProgram(modelInferenceMaxTokens),
	})
	if err != nil {
		return nil, err
	}
	return modelInferenceChecks(observation, modelArtifactBytes(target.ModelArtifact))
}

func runModelServingContract(parent context.Context, sshTarget string, target catalog.ContractTarget, timeout time.Duration, profile modelServingProfile) (modelInferenceObservation, error) {
	if !sshTargetPattern.MatchString(sshTarget) {
		return modelInferenceObservation{}, errors.New("SSH target must use the form user@host")
	}
	image, ok := runtimeImage(target.RuntimeArtifacts)
	if !ok {
		return modelInferenceObservation{}, errors.New("contract target has no digest-pinned OCI runtime image")
	}
	if target.ModelArtifact.Type != "huggingface-snapshot" || target.ModelArtifact.Ref == "" || target.ModelArtifact.Revision == "" || len(target.ModelArtifact.Files) == 0 {
		return modelInferenceObservation{}, errors.New("contract target has no verifiable Hugging Face model snapshot")
	}
	if profile.ContextTokens <= 0 || profile.Concurrency != 1 || profile.MaxTokens <= 0 || profile.ContextTokens <= profile.MaxTokens || strings.TrimSpace(profile.RequestProgram) == "" {
		return modelInferenceObservation{}, errors.New("model serving profile is invalid or exceeds the supported single-sequence safety boundary")
	}
	files, err := json.Marshal(target.ModelArtifact.Files)
	if err != nil {
		return modelInferenceObservation{}, fmt.Errorf("encode model artifact contract: %w", err)
	}
	if timeout <= 0 {
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	runID := fmt.Sprintf("%d", time.Now().UnixNano())
	script := modelServingScript(
		base64.StdEncoding.EncodeToString([]byte(image)),
		base64.StdEncoding.EncodeToString([]byte(target.ModelArtifact.Ref)),
		base64.StdEncoding.EncodeToString([]byte(target.ModelArtifact.Revision)),
		base64.StdEncoding.EncodeToString(files),
		base64.StdEncoding.EncodeToString([]byte(runID)),
		modelArtifactBytes(target.ModelArtifact),
		profile,
	)
	command := exec.CommandContext(ctx, "ssh", "-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10", sshTarget, script)
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return modelInferenceObservation{}, fmt.Errorf("model serving contract timed out: %w", ctx.Err())
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return modelInferenceObservation{}, fmt.Errorf("model serving transport exited with status %d", exitErr.ExitCode())
		}
		return modelInferenceObservation{}, fmt.Errorf("start model serving contract: %w", err)
	}
	var observation modelInferenceObservation
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || json.Unmarshal([]byte(lines[len(lines)-1]), &observation) != nil {
		return modelInferenceObservation{}, errors.New("model serving contract returned no valid observation")
	}
	return observation, nil
}

func modelArtifactBytes(artifact catalog.ArtifactReference) int64 {
	var total int64
	for _, file := range artifact.Files {
		total += file.SizeBytes
	}
	return total
}

func modelInferenceChecks(observation modelInferenceObservation, modelBytes int64) ([]resources.ContractTestCheck, error) {
	return modelServingChecks(observation, modelBytes, modelInferenceContext, modelInferenceConcurrency, modelInferenceMaxTokens)
}

func modelServingChecks(observation modelInferenceObservation, modelBytes int64, contextTokens, concurrency, maxTokens int) ([]resources.ContractTestCheck, error) {
	minimumDisk := modelBytes*2 + (2 << 30)
	checks := make([]resources.ContractTestCheck, 0, 12)
	appendCheck := func(id, status, code string, evidence any) error {
		item, err := check(id, status, code, evidence)
		if err == nil {
			checks = append(checks, item)
		}
		return err
	}
	status := func(passed bool, failedStage string, prerequisitesPassed bool) (string, string) {
		if passed {
			return "passed", ""
		}
		if !prerequisitesPassed || (observation.FailureStage != "" && observation.FailureStage != failedStage) {
			return "blocked", "YARA-CTR-149"
		}
		return "failed", ""
	}
	memoryPassed := observation.MemoryAvailableBytes >= modelInferenceMemoryBytes
	diskPassed := observation.DiskAvailableBytes >= minimumDisk
	memoryStatus, memoryCode := "passed", ""
	if !memoryPassed {
		memoryStatus, memoryCode = "blocked", "YARA-CTR-140"
	}
	if appendCheck("capacity.memory-available", memoryStatus, memoryCode, map[string]int64{"minimum": modelInferenceMemoryBytes, "observed": observation.MemoryAvailableBytes}) != nil {
		return nil, errors.New("digest memory-capacity evidence")
	}
	diskStatus, diskCode := "passed", ""
	if !diskPassed {
		diskStatus, diskCode = "blocked", "YARA-CTR-141"
	}
	if appendCheck("capacity.disk-available", diskStatus, diskCode, map[string]int64{"minimum": minimumDisk, "observed": observation.DiskAvailableBytes}) != nil {
		return nil, errors.New("digest disk-capacity evidence")
	}
	capacityPassed := memoryPassed && diskPassed
	acquisitionPassed := observation.AcquisitionCompleted || slices.Contains([]string{"artifact", "server", "health", "inference"}, observation.FailureStage)
	acquisitionStatus, acquisitionCode := status(acquisitionPassed, "acquisition", capacityPassed)
	if observation.FailureStage == "collision" {
		acquisitionStatus, acquisitionCode = "failed", "YARA-CTR-150"
	}
	if err := appendCheck("model.acquisition", acquisitionStatus, chooseCode(acquisitionStatus, acquisitionCode, "YARA-CTR-151"), acquisitionPassed); err != nil {
		return nil, err
	}
	artifactPassed := observation.ArtifactVerified || slices.Contains([]string{"server", "health", "inference"}, observation.FailureStage)
	artifactStatus, artifactCode := status(artifactPassed, "artifact", acquisitionPassed)
	if err := appendCheck("model.artifact-local", artifactStatus, chooseCode(artifactStatus, artifactCode, "YARA-CTR-142"), artifactPassed); err != nil {
		return nil, err
	}
	serverPassed := observation.ServerStarted || slices.Contains([]string{"health", "inference"}, observation.FailureStage)
	serverStatus, serverCode := status(serverPassed, "server", artifactPassed)
	if err := appendCheck("model.server-started", serverStatus, chooseCode(serverStatus, serverCode, "YARA-CTR-143"), map[string]any{"started": serverPassed, "logDigest": observation.ServerLogDigest}); err != nil {
		return nil, err
	}
	networkStatus, networkCode := status(observation.NetworkMode == "none", "server", serverPassed)
	if err := appendCheck("model.network-isolation", networkStatus, chooseCode(networkStatus, networkCode, "YARA-CTR-144"), observation.NetworkMode); err != nil {
		return nil, err
	}
	healthPassed := observation.HealthStatus == 200 || observation.FailureStage == "inference"
	healthStatus, healthCode := status(healthPassed, "health", serverPassed)
	if healthStatus == "failed" {
		healthCode = modelHealthDiagnostic(observation.FailureReason)
	}
	if err := appendCheck("model.health", healthStatus, chooseCode(healthStatus, healthCode, "YARA-CTR-145"), map[string]any{"passed": healthPassed, "observedStatus": observation.HealthStatus, "reason": observation.FailureReason}); err != nil {
		return nil, err
	}
	inferenceHTTPPassed := observation.InferenceStatus == 200
	httpStatus, httpCode := status(inferenceHTTPPassed, "inference", healthPassed)
	if err := appendCheck("model.inference-http", httpStatus, chooseCode(httpStatus, httpCode, "YARA-CTR-146"), observation.InferenceStatus); err != nil {
		return nil, err
	}
	schemaPassed := inferenceHTTPPassed && observation.Model == "yara-contract" && len(observation.ContentDigest) == 71 && strings.HasPrefix(observation.ContentDigest, "sha256:")
	schemaStatus, schemaCode := status(schemaPassed, "inference", inferenceHTTPPassed)
	if err := appendCheck("model.inference-schema", schemaStatus, chooseCode(schemaStatus, schemaCode, "YARA-CTR-147"), map[string]any{"model": observation.Model, "finishReason": observation.FinishReason, "contentDigest": observation.ContentDigest}); err != nil {
		return nil, err
	}
	boundedPassed := schemaPassed && observation.CompletionTokens > 0 && observation.CompletionTokens <= maxTokens
	boundedStatus, boundedCode := status(boundedPassed, "inference", schemaPassed)
	if err := appendCheck("model.inference-bounded", boundedStatus, chooseCode(boundedStatus, boundedCode, "YARA-CTR-148"), map[string]int{"completionTokens": observation.CompletionTokens, "maximum": maxTokens}); err != nil {
		return nil, err
	}
	configStatus, configCode := "passed", ""
	if !serverPassed {
		configStatus, configCode = "blocked", "YARA-CTR-149"
	}
	if err := appendCheck("model.context-limit", configStatus, configCode, contextTokens); err != nil {
		return nil, err
	}
	if err := appendCheck("model.concurrency-limit", configStatus, configCode, concurrency); err != nil {
		return nil, err
	}
	if err := appendCheck("model.async-scheduling-disabled", configStatus, configCode, serverPassed); err != nil {
		return nil, err
	}
	if err := appendCheck("model.prefix-caching-disabled", configStatus, configCode, serverPassed); err != nil {
		return nil, err
	}
	cacheStatus, cacheCode := configStatus, configCode
	if observation.FailureStage == "health" && observation.FailureReason == "filesystem-policy" {
		cacheStatus, cacheCode = "failed", "YARA-CTR-156"
	}
	if err := appendCheck("model.ephemeral-runtime-cache", cacheStatus, cacheCode, healthPassed); err != nil {
		return nil, err
	}
	slices.SortFunc(checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	return checks, nil
}

func chooseCode(status, current, failed string) string {
	if status == "passed" {
		return ""
	}
	if current != "" {
		return current
	}
	return failed
}

func modelHealthDiagnostic(reason string) string {
	switch reason {
	case "memory-limit":
		return "YARA-CTR-153"
	case "unsupported-runtime":
		return "YARA-CTR-154"
	case "offline-artifact":
		return "YARA-CTR-155"
	case "filesystem-policy":
		return "YARA-CTR-156"
	default:
		return "YARA-CTR-145"
	}
}

func modelInferenceScript(imageB64, repoB64, revisionB64, filesB64, runIDB64 string, modelBytes int64) string {
	return modelServingScript(imageB64, repoB64, revisionB64, filesB64, runIDB64, modelBytes, modelServingProfile{
		ContextTokens:  modelInferenceContext,
		Concurrency:    modelInferenceConcurrency,
		MaxTokens:      modelInferenceMaxTokens,
		RequestProgram: boundedInferenceProgram(modelInferenceMaxTokens),
	})
}

func modelServingScript(imageB64, repoB64, revisionB64, filesB64, runIDB64 string, modelBytes int64, profile modelServingProfile) string {
	minimumDisk := modelBytes*2 + (2 << 30)
	requestB64 := base64.StdEncoding.EncodeToString([]byte(profile.RequestProgram))
	return fmt.Sprintf(`set -u
image="$(printf '%%s' '%s' | base64 -d)"
repo="$(printf '%%s' '%s' | base64 -d)"
revision="$(printf '%%s' '%s' | base64 -d)"
files_b64='%s'
run_id="$(printf '%%s' '%s' | base64 -d)"
request_b64='%s'
download="yara-contract-download-$run_id"
server="yara-contract-model-$run_id"
volume="yara-contract-model-$run_id"
memory_available="$(awk '/MemAvailable:/ {print $2 * 1024}' /proc/meminfo)"
disk_available="$(df -B1 --output=avail / | tail -1 | tr -d ' ')"
network_mode=""
emit_failure() {
  stage="$1"
  log_digest="${2:-}"
  reason="${3:-}"
  printf '{"failureStage":"%%s","failureReason":"%%s","memoryAvailableBytes":%%s,"diskAvailableBytes":%%s,"networkMode":"%%s","serverLogDigest":"%%s"}\n' "$stage" "$reason" "$memory_available" "$disk_available" "$network_mode" "$log_digest"
}
if [ "$memory_available" -lt %d ] || [ "$disk_available" -lt %d ]; then
  emit_failure capacity
  exit 0
fi
if docker ps -a --format '{{.Names}}' | grep -Eq "^($download|$server)$" || docker volume inspect "$volume" >/dev/null 2>&1; then
  emit_failure collision
  exit 0
fi
cleanup() {
  docker rm -f "$server" "$download" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT
if ! docker volume create --label yara.contract=model-inference "$volume" >/dev/null; then
  emit_failure acquisition
  exit 0
fi
if ! docker image inspect "$image" >/dev/null; then
  emit_failure acquisition
  exit 0
fi
if ! docker run --rm --name "$download" --network bridge --pids-limit 256 --memory 4294967296 \
  --mount "type=volume,src=$volume,dst=/model" --entrypoint /usr/bin/python3 "$image" \
  -c 'from huggingface_hub import snapshot_download; import sys; snapshot_download(repo_id=sys.argv[1], revision=sys.argv[2], local_dir="/model")' "$repo" "$revision"; then
  emit_failure acquisition
  exit 0
fi
if ! docker run --rm --network none --pids-limit 256 --memory 2147483648 \
  -e "YARA_FILES_B64=$files_b64" --mount "type=volume,src=$volume,dst=/model,readonly" \
  --entrypoint /usr/bin/python3 "$image" -c 'import base64,hashlib,json,os,pathlib,sys; items=json.loads(base64.b64decode(os.environ["YARA_FILES_B64"])); ok=True
for item in items:
 p=pathlib.Path("/model")/item["path"]
 if not p.is_file() or p.stat().st_size != item["sizeBytes"]: ok=False; continue
 h=hashlib.sha256()
 with p.open("rb") as f:
  for chunk in iter(lambda:f.read(8*1024*1024),b""): h.update(chunk)
 if "sha256:"+h.hexdigest() != item["digest"]: ok=False
sys.exit(0 if ok else 1)'; then
  emit_failure artifact
  exit 0
fi
if ! docker run -d --name "$server" --network none --read-only --pids-limit 1024 \
  --memory %d --memory-swap %d --shm-size 1073741824 --gpus all \
  --mount "type=volume,src=$volume,dst=/model,readonly" \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=1073741824 --tmpfs /root/.cache:rw,exec,nosuid,nodev,size=1073741824 \
  --tmpfs /root/.config:rw,noexec,nosuid,nodev,size=67108864 --tmpfs /root/.triton:rw,exec,nosuid,nodev,size=1073741824 \
  -e HF_HUB_OFFLINE=1 -e TRANSFORMERS_OFFLINE=1 -e VLLM_NO_USAGE_STATS=1 "$image" \
  /model --served-model-name yara-contract --host 127.0.0.1 --max-model-len %d --max-num-seqs %d \
  --gpu-memory-utilization 0.08 --enforce-eager --no-async-scheduling --no-enable-prefix-caching >/dev/null; then
  emit_failure server
  exit 0
fi
network_mode="$(docker inspect "$server" --format '{{.HostConfig.NetworkMode}}')"
health_status=0
attempt=0
while [ "$attempt" -lt 180 ]; do
  if docker exec "$server" /usr/bin/python3 -c 'import urllib.request; r=urllib.request.urlopen("http://127.0.0.1:8000/health",timeout=2); raise SystemExit(0 if r.status==200 else 1)' >/dev/null 2>&1; then
    health_status=200
    break
  fi
  if [ "$(docker inspect "$server" --format '{{.State.Running}}' 2>/dev/null || true)" != "true" ]; then
    break
  fi
  attempt=$((attempt+1))
  sleep 2
done
if [ "$health_status" -ne 200 ]; then
  logs="$(docker logs "$server" 2>&1 | tail -80 || true)"
  log_digest="sha256:$(printf '%%s' "$logs" | sha256sum | awk '{print $1}')"
  reason="server-unhealthy"
  if [ "$(docker inspect "$server" --format '{{.State.OOMKilled}}' 2>/dev/null || true)" = "true" ] || printf '%%s' "$logs" | grep -Eqi 'out of memory|oom|killed process'; then
    reason="memory-limit"
  elif printf '%%s' "$logs" | grep -Eqi 'read-only file system|permission denied'; then
    reason="filesystem-policy"
  elif printf '%%s' "$logs" | grep -Eqi 'offline mode|local files only|cannot find.*config|no such file.*model'; then
    reason="offline-artifact"
  elif printf '%%s' "$logs" | grep -Eqi 'no kernel image|not supported for the current gpu|unsupported.*compute capability|sm_121.*not compatible'; then
    reason="unsupported-runtime"
  fi
  emit_failure health "$log_digest" "$reason"
  exit 0
fi
inference="$(docker exec -e "YARA_REQUEST_B64=$request_b64" "$server" /usr/bin/python3 -c 'import base64,os; exec(compile(base64.b64decode(os.environ["YARA_REQUEST_B64"]),"<yara-contract>","exec"))' 2>/dev/null)"
if [ -z "$inference" ]; then
  emit_failure inference
  exit 0
fi
printf '%%s' "$inference" | /usr/bin/python3 -c 'import json,sys; data=json.load(sys.stdin); data.update({"memoryAvailableBytes":int(sys.argv[1]),"diskAvailableBytes":int(sys.argv[2]),"acquisitionCompleted":True,"artifactVerified":True,"serverStarted":True,"networkMode":sys.argv[3],"healthStatus":200}); print(json.dumps(data,separators=(",",":")))' "$memory_available" "$disk_available" "$network_mode"
`, imageB64, repoB64, revisionB64, filesB64, runIDB64, requestB64, modelInferenceMemoryBytes, minimumDisk, modelInferenceMemoryBytes, modelInferenceMemoryBytes, profile.ContextTokens, profile.Concurrency)
}

func boundedInferenceProgram(maxTokens int) string {
	return fmt.Sprintf(`import hashlib,json,urllib.request
payload={"model":"yara-contract","messages":[{"role":"user","content":"Reply with exactly YARA_OK"}],"temperature":0,"max_tokens":%d}
request=urllib.request.Request("http://127.0.0.1:8000/v1/chat/completions",data=json.dumps(payload).encode(),headers={"Content-Type":"application/json"})
try:
 response=urllib.request.urlopen(request,timeout=120); status=response.status; body=response.read(); data=json.loads(body); choice=data["choices"][0]; content=choice["message"]["content"] or ""; usage=data.get("usage",{}); print(json.dumps({"inferenceStatus":status,"model":data.get("model",""),"finishReason":choice.get("finish_reason",""),"promptTokens":usage.get("prompt_tokens",0),"completionTokens":usage.get("completion_tokens",0),"totalTokens":usage.get("total_tokens",0),"contentDigest":"sha256:"+hashlib.sha256(content.encode()).hexdigest()}))
except Exception as error:
 body=getattr(error,"read",lambda:b"")(); print(json.dumps({"failureStage":"inference","inferenceStatus":getattr(error,"code",0),"contentDigest":"sha256:"+hashlib.sha256(body).hexdigest()}))`, maxTokens)
}

func EvaluateModelInference(name, catalogDigest string, target catalog.ContractTarget, environment resources.ContractTestEnvironment, artifactChecks, modelChecks []resources.ContractTestCheck) (resources.ContractTestResult, error) {
	result, err := Evaluate(name, catalogDigest, target, environment)
	if err != nil {
		return resources.ContractTestResult{}, err
	}
	result.Metadata.ResultID = ""
	result.Spec.Mode = "model-inference"
	result.Spec.Checks = append(result.Spec.Checks, artifactChecks...)
	result.Spec.Checks = append(result.Spec.Checks, modelChecks...)
	slices.SortFunc(result.Spec.Checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	result.Spec.Outcome = deriveOutcome(result.Spec.Checks)
	result.Spec.Limitations = []string{
		"Model acquisition used external network access; this is not air-gap evidence.",
		"One context-1024, concurrency-1 request does not establish advertised context, capacity or performance.",
		"The contract does not establish restart, lifecycle, upgrade or recovery compatibility.",
		"The server had no network, ports or persistent volumes, but broader policy and telemetry behavior remains unproven.",
	}
	if len(modelChecks) == 0 {
		result.Spec.Limitations = append(result.Spec.Limitations, "Model workload was not started because an earlier gate failed.")
	}
	slices.Sort(result.Spec.Limitations)
	return result.AssignResultID()
}
