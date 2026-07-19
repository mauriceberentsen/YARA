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

type RuntimeSmokeRunner interface {
	Run(context.Context, string, catalog.ContractTarget) ([]resources.ContractTestCheck, error)
}

type SSHRuntimeSmokeRunner struct {
	Timeout time.Duration
}

type runtimeSmokeObservation struct {
	VLLM       string  `json:"vllm"`
	Torch      string  `json:"torch"`
	CUDA       string  `json:"cuda"`
	Device     string  `json:"device"`
	Capability []int   `json:"capability"`
	Value      float64 `json:"value"`
}

func (r SSHRuntimeSmokeRunner) Run(parent context.Context, sshTarget string, target catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	if !sshTargetPattern.MatchString(sshTarget) {
		return nil, errors.New("SSH target must use the form user@host")
	}
	image, ok := runtimeImage(target.RuntimeArtifacts)
	if !ok {
		return nil, errors.New("contract target has no digest-pinned OCI runtime image")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	name := fmt.Sprintf("yara-contract-smoke-%d", time.Now().UnixNano())
	script := runtimeSmokeScript(base64.StdEncoding.EncodeToString([]byte(image)), base64.StdEncoding.EncodeToString([]byte(name)))
	command := exec.CommandContext(ctx, "ssh", "-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10", sshTarget, script)
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("runtime smoke timed out: %w", ctx.Err())
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			item, checkErr := check("runtime.container", "failed", "YARA-CTR-124", exitErr.ExitCode())
			if checkErr != nil {
				return nil, checkErr
			}
			return []resources.ContractTestCheck{item}, nil
		}
		return nil, fmt.Errorf("start runtime smoke: %w", err)
	}
	var observation runtimeSmokeObservation
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || json.Unmarshal([]byte(lines[len(lines)-1]), &observation) != nil {
		return nil, errors.New("runtime smoke returned no valid observation")
	}
	expectedCUDA := strings.TrimPrefix(target.Conditions.ComputePlatform, "cuda-")
	expectedCapability := target.HardwareComputeCapability
	observedCapability := ""
	if len(observation.Capability) == 2 {
		observedCapability = fmt.Sprintf("%d.%d", observation.Capability[0], observation.Capability[1])
	}
	checks := []resources.ContractTestCheck{
		contractCheck("runtime.container", true, "", true),
		contractCheck("runtime.vllm-version", observation.VLLM == target.Conditions.RuntimeVersion, "YARA-CTR-125", map[string]string{"expected": target.Conditions.RuntimeVersion, "observed": observation.VLLM}),
		contractCheck("runtime.cuda-version", observation.CUDA == expectedCUDA, "YARA-CTR-126", map[string]string{"expected": expectedCUDA, "observed": observation.CUDA}),
		contractCheck("runtime.accelerator-identity", slices.Contains(target.HardwareModels, observation.Device), "YARA-CTR-127", observation.Device),
		contractCheck("runtime.compute-capability", observedCapability == expectedCapability, "YARA-CTR-128", map[string]string{"expected": expectedCapability, "observed": observedCapability}),
		contractCheck("runtime.cuda-tensor", observation.Value == 1, "YARA-CTR-129", observation.Value),
	}
	slices.SortFunc(checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	return checks, nil
}

func runtimeImage(artifacts []catalog.ArtifactReference) (string, bool) {
	for _, artifact := range artifacts {
		if artifact.Type != "oci-image" || artifact.Digest == "" {
			continue
		}
		ref := artifact.Ref
		if slash, colon := strings.LastIndex(ref, "/"), strings.LastIndex(ref, ":"); colon > slash {
			ref = ref[:colon]
		}
		return ref + "@" + artifact.Digest, true
	}
	return "", false
}

func runtimeSmokeScript(imageBase64, nameBase64 string) string {
	return fmt.Sprintf(`set -eu
image="$(printf '%%s' '%s' | base64 -d)"
name="$(printf '%%s' '%s' | base64 -d)"
if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then exit 41; fi
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker image inspect "$image" >/dev/null
docker run --rm --name "$name" --network none --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=268435456 --pids-limit 256 \
  --memory 4294967296 --gpus all --entrypoint /usr/bin/python3 "$image" \
  -c 'import json,torch,vllm; x=torch.ones(1,device="cuda"); torch.cuda.synchronize(); print(json.dumps({"vllm":vllm.__version__,"torch":torch.__version__,"cuda":torch.version.cuda,"device":torch.cuda.get_device_name(0),"capability":list(torch.cuda.get_device_capability(0)),"value":x.item()}))'
`, imageBase64, nameBase64)
}

func EvaluateRuntimeSmoke(name, catalogDigest string, target catalog.ContractTarget, environment resources.ContractTestEnvironment, artifactChecks, runtimeChecks []resources.ContractTestCheck) (resources.ContractTestResult, error) {
	result, err := Evaluate(name, catalogDigest, target, environment)
	if err != nil {
		return resources.ContractTestResult{}, err
	}
	result.Metadata.ResultID = ""
	result.Spec.Mode = "runtime-smoke"
	result.Spec.Checks = append(result.Spec.Checks, artifactChecks...)
	result.Spec.Checks = append(result.Spec.Checks, runtimeChecks...)
	slices.SortFunc(result.Spec.Checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	result.Spec.Outcome = deriveOutcome(result.Spec.Checks)
	result.Spec.Limitations = []string{
		"No model weights were downloaded or loaded by runtime smoke.",
		"Runtime smoke does not establish inference, context, concurrency, policy, restart or air-gap compatibility.",
	}
	if len(runtimeChecks) == 0 {
		result.Spec.Limitations = append(result.Spec.Limitations, "Runtime container was not started because an earlier gate failed.")
	}
	slices.Sort(result.Spec.Limitations)
	return result.AssignResultID()
}
