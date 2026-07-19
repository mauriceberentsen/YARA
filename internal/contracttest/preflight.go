// Package contracttest evaluates catalog compatibility assertions against
// observed execution environments without mutating the target.
package contracttest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

var sshTargetPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9][A-Za-z0-9.:-]*$`)

const remoteProbeScript = `set -eu
printf 'os\t%s\n' "$(uname -s | tr '[:upper:]' '[:lower:]')"
printf 'arch\t%s\n' "$(uname -m)"
if command -v docker >/dev/null 2>&1 && docker version >/dev/null 2>&1; then
  printf 'docker.available\ttrue\n'
  printf 'docker.version\t%s\n' "$(docker version --format '{{.Server.Version}}')"
  printf 'docker.os\t%s\n' "$(docker info --format '{{.OSType}}')"
  printf 'docker.arch\t%s\n' "$(docker info --format '{{.Architecture}}')"
  if docker info --format '{{json .Runtimes}}' | grep -q '"nvidia"'; then
    printf 'docker.nvidia\ttrue\n'
  else
    printf 'docker.nvidia\tfalse\n'
  fi
else
  printf 'docker.available\tfalse\n'
  printf 'docker.nvidia\tfalse\n'
fi
if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi --query-gpu=name,driver_version,compute_cap --format=csv,noheader,nounits | sed 's/^/gpu\t/'
fi
`

type Probe interface {
	Observe(context.Context, string) (resources.ContractTestEnvironment, error)
}

type SSHProbe struct {
	Timeout time.Duration
}

func (p SSHProbe) Observe(parent context.Context, target string) (resources.ContractTestEnvironment, error) {
	if !sshTargetPattern.MatchString(target) {
		return resources.ContractTestEnvironment{}, errors.New("SSH target must use the form user@host")
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, "ssh", "-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10", target, remoteProbeScript)
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return resources.ContractTestEnvironment{}, fmt.Errorf("SSH preflight timed out: %w", ctx.Err())
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return resources.ContractTestEnvironment{}, fmt.Errorf("SSH preflight failed with exit status %d", exitErr.ExitCode())
		}
		return resources.ContractTestEnvironment{}, fmt.Errorf("start SSH preflight: %w", err)
	}
	return parseObservation(target, output)
}

func parseObservation(target string, output []byte) (resources.ContractTestEnvironment, error) {
	referenceDigest, err := canonical.Digest(target)
	if err != nil {
		return resources.ContractTestEnvironment{}, fmt.Errorf("digest SSH target: %w", err)
	}
	environment := resources.ContractTestEnvironment{Transport: "ssh", ReferenceDigest: referenceDigest}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "\t")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "os":
			environment.OperatingSystem = strings.ToLower(value)
		case "arch":
			environment.Architecture = normalizeArchitecture(value)
		case "docker.available":
			environment.Docker.Available = value == "true"
		case "docker.version":
			environment.Docker.Version = value
		case "docker.os":
			environment.Docker.OperatingSystem = strings.ToLower(value)
		case "docker.arch":
			environment.Docker.Architecture = normalizeArchitecture(value)
		case "docker.nvidia":
			environment.Docker.NVIDIARuntime = value == "true"
		case "gpu":
			parts := strings.Split(value, ",")
			if len(parts) != 3 {
				return resources.ContractTestEnvironment{}, errors.New("nvidia-smi returned an unexpected accelerator record")
			}
			environment.Accelerators = append(environment.Accelerators, resources.ContractTestAccelerator{
				Vendor: "nvidia", Model: strings.TrimSpace(parts[0]), DriverVersion: strings.TrimSpace(parts[1]), ComputeCapability: strings.TrimSpace(parts[2]),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return resources.ContractTestEnvironment{}, fmt.Errorf("read SSH preflight output: %w", err)
	}
	if environment.OperatingSystem == "" || environment.Architecture == "" {
		return resources.ContractTestEnvironment{}, errors.New("SSH preflight did not return operating-system facts")
	}
	sort.Slice(environment.Accelerators, func(i, j int) bool {
		left, right := environment.Accelerators[i], environment.Accelerators[j]
		return left.Vendor+"\x00"+left.Model+"\x00"+left.DriverVersion+"\x00"+left.ComputeCapability <
			right.Vendor+"\x00"+right.Model+"\x00"+right.DriverVersion+"\x00"+right.ComputeCapability
	})
	return environment, nil
}

func Evaluate(name, catalogDigest string, target catalog.ContractTarget, environment resources.ContractTestEnvironment) (resources.ContractTestResult, error) {
	environment.Accelerators = slices.Clone(environment.Accelerators)
	sort.Slice(environment.Accelerators, func(i, j int) bool {
		left, right := environment.Accelerators[i], environment.Accelerators[j]
		return left.Vendor+"\x00"+left.Model+"\x00"+left.DriverVersion+"\x00"+left.ComputeCapability <
			right.Vendor+"\x00"+right.Model+"\x00"+right.DriverVersion+"\x00"+right.ComputeCapability
	})
	checks := make([]resources.ContractTestCheck, 0, 8)
	var evidenceErr error
	appendCheck := func(id, status, code string, evidence any) {
		if evidenceErr != nil {
			return
		}
		item, err := check(id, status, code, evidence)
		if err != nil {
			evidenceErr = err
			return
		}
		checks = append(checks, item)
	}
	appendCheck("catalog.assertion", "passed", "", target.AssertionID)
	if environment.Docker.Available {
		appendCheck("docker.available", "passed", "", environment.Docker.Version)
	} else {
		appendCheck("docker.available", "blocked", "YARA-CTR-100", false)
	}
	if environment.Docker.Available && environment.Docker.OperatingSystem == "linux" {
		appendCheck("docker.linux", "passed", "", environment.Docker.OperatingSystem)
	} else if environment.Docker.Available {
		appendCheck("docker.linux", "failed", "YARA-CTR-101", environment.Docker.OperatingSystem)
	} else {
		appendCheck("docker.linux", "blocked", "YARA-CTR-100", "docker-unavailable")
	}
	if environment.Docker.NVIDIARuntime {
		appendCheck("docker.nvidia-runtime", "passed", "", true)
	} else {
		appendCheck("docker.nvidia-runtime", "blocked", "YARA-CTR-102", false)
	}
	if environment.OperatingSystem == "linux" {
		appendCheck("host.linux", "passed", "", environment.OperatingSystem)
	} else {
		appendCheck("host.linux", "failed", "YARA-CTR-110", environment.OperatingSystem)
	}
	platform := "linux/" + environment.Docker.Architecture
	if environment.Docker.Available && runtimeSupportsPlatform(target.RuntimeArtifacts, platform) {
		appendCheck("runtime.platform", "passed", "", platform)
	} else if environment.Docker.Available {
		appendCheck("runtime.platform", "failed", "YARA-CTR-103", platform)
	} else {
		appendCheck("runtime.platform", "blocked", "YARA-CTR-100", platform)
	}
	if len(environment.Accelerators) == 0 {
		appendCheck("accelerator.detected", "blocked", "YARA-CTR-104", "none")
		appendCheck("accelerator.compute-capability", "blocked", "YARA-CTR-104", "none")
		appendCheck("accelerator.driver", "blocked", "YARA-CTR-104", "none")
		appendCheck("accelerator.identity", "blocked", "YARA-CTR-104", "none")
	} else {
		appendCheck("accelerator.detected", "passed", "", len(environment.Accelerators))
		accelerator, identityMatches := matchingAccelerator(environment.Accelerators, target)
		if driverMeetsMinimum(accelerator.DriverVersion, target.Conditions.MinimumDriverVersion) {
			appendCheck("accelerator.driver", "passed", "", accelerator.DriverVersion)
		} else {
			appendCheck("accelerator.driver", "blocked", "YARA-CTR-105", accelerator.DriverVersion)
		}
		if identityMatches {
			appendCheck("accelerator.identity", "passed", "", accelerator.Model)
		} else {
			appendCheck("accelerator.identity", "blocked", "YARA-CTR-106", accelerator.Model)
		}
		if identityMatches && accelerator.ComputeCapability == target.HardwareComputeCapability {
			appendCheck("accelerator.compute-capability", "passed", "", accelerator.ComputeCapability)
		} else {
			appendCheck("accelerator.compute-capability", "blocked", "YARA-CTR-109", accelerator.ComputeCapability)
		}
	}
	if evidenceErr != nil {
		return resources.ContractTestResult{}, evidenceErr
	}
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].ID < checks[j].ID })
	outcome := deriveOutcome(checks)
	result := resources.ContractTestResult{
		APIVersion: resources.APIVersion, Kind: "ContractTestResult",
		Metadata: resources.ContractTestResultMetadata{Name: name},
		Spec: resources.ContractTestResultSpec{
			Mode: "preflight", Outcome: outcome, CatalogDigest: catalogDigest, AssertionRef: target.AssertionID,
			Target:      resources.ContractTestTarget{RuntimeRef: target.RuntimeRef, ModelRef: target.ModelRef, HardwareProfileRef: target.HardwareProfileID},
			Environment: environment, Checks: checks,
			Limitations: []string{"No containers or model workloads were started by preflight.", "Preflight does not establish runtime, inference, restart or air-gap compatibility."},
		},
	}
	sort.Strings(result.Spec.Limitations)
	return result.AssignResultID()
}

func matchingAccelerator(accelerators []resources.ContractTestAccelerator, target catalog.ContractTarget) (resources.ContractTestAccelerator, bool) {
	for _, accelerator := range accelerators {
		if strings.EqualFold(accelerator.Vendor, target.HardwareVendor) && slices.Contains(target.HardwareModels, accelerator.Model) {
			return accelerator, true
		}
	}
	return accelerators[0], false
}

func check(id, status, code string, evidence any) (resources.ContractTestCheck, error) {
	digest, err := canonical.Digest(evidence)
	if err != nil {
		return resources.ContractTestCheck{}, fmt.Errorf("digest evidence for %s: %w", id, err)
	}
	return resources.ContractTestCheck{ID: id, Status: status, DiagnosticCode: code, EvidenceDigest: digest}, nil
}

func deriveOutcome(checks []resources.ContractTestCheck) string {
	outcome := "passed"
	for _, item := range checks {
		if item.Status == "failed" {
			return "failed"
		}
		if item.Status == "blocked" {
			outcome = "blocked"
		}
	}
	return outcome
}

func runtimeSupportsPlatform(artifacts []catalog.ArtifactReference, platform string) bool {
	for _, artifact := range artifacts {
		if artifact.Type == "oci-image" && slices.Contains(artifact.Platforms, platform) {
			return true
		}
	}
	return false
}

func driverMeetsMinimum(actual, minimum string) bool {
	if minimum == "" {
		return true
	}
	actualMajor, actualErr := strconv.Atoi(strings.SplitN(actual, ".", 2)[0])
	minimumMajor, minimumErr := strconv.Atoi(strings.SplitN(minimum, ".", 2)[0])
	return actualErr == nil && minimumErr == nil && actualMajor >= minimumMajor
}

func normalizeArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "aarch64", "arm64":
		return "arm64"
	case "x86_64", "amd64":
		return "amd64"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}
