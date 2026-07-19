// Package targetpreflight performs bounded read-only target observation and
// pure evaluation. It has no apply, create, patch, delete or exec capability.
package targetpreflight

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

const ObserverVersion = "0.2.0"

var kubernetesVersionPattern = regexp.MustCompile(`^v?1\.([0-9]+)(?:\.|$)`)

type Observation struct {
	ReferenceDigest    string
	ServerVersion      string
	CoreV1             bool
	AppsV1             bool
	NetworkingV1       bool
	NodesReadable      bool
	GPUCount           int
	NodePlatforms      []string
	DNSReadable        bool
	DNSPodCount        int
	NamespaceReadable  bool
	NamespaceExists    bool
	NamespaceManaged   bool
	NamespacePlanMatch bool
	PVCReadable        bool
	PVCExists          bool
	PVCPhase           string
}

func Evaluate(name string, bundle resources.DeploymentBundle, observation Observation, observedAt time.Time) (resources.TargetPreflightResult, error) {
	if report := bundle.Validate(); !report.Valid {
		return resources.TargetPreflightResult{}, fmt.Errorf("bundle is invalid: %s", report.Diagnostics[0].Code)
	}
	if bundle.Spec.Renderer.Target != "kubernetes-gitops" {
		return resources.TargetPreflightResult{}, fmt.Errorf("target preflight requires a kubernetes-gitops bundle")
	}
	checks := []resources.TargetPreflightCheck{
		availabilityCheck("api.apps-v1", observation.AppsV1, "YARA-TPR-101", "apps/v1 discovery is available.", "apps/v1 discovery is unavailable or could not be observed.", fact("available", observation.AppsV1)),
		availabilityCheck("api.core-v1", observation.CoreV1, "YARA-TPR-102", "core/v1 discovery is available.", "core/v1 discovery is unavailable or could not be observed.", fact("available", observation.CoreV1)),
		availabilityCheck("api.networking-v1", observation.NetworkingV1, "YARA-TPR-103", "networking.k8s.io/v1 discovery is available.", "networking.k8s.io/v1 discovery is unavailable or could not be observed.", fact("available", observation.NetworkingV1)),
		dnsCheck(observation),
		gpuCheck(observation),
		modelDigestCheck(),
		namespaceCheck(observation),
		networkPolicyEnforcementCheck(),
		platformCheck(bundle, observation),
		pvcCheck(observation),
		tmpExecCheck(),
		verifierGovernanceCheck(),
		versionCheck(observation.ServerVersion),
	}
	slices.SortFunc(checks, func(left, right resources.TargetPreflightCheck) int {
		if left.ID < right.ID {
			return -1
		}
		if left.ID > right.ID {
			return 1
		}
		return 0
	})
	outcome := "passed"
	for _, check := range checks {
		if check.Status == "failed" {
			outcome = "failed"
		} else if check.Status == "blocked" && outcome == "passed" {
			outcome = "blocked"
		}
	}
	limitations := []string{
		"API discovery proves resource availability, not admission or successful apply.",
		"Aggregated GPU, platform and DNS facts intentionally omit node, pod, endpoint and context identities.",
		"No object is created, patched, deleted, executed or server-side dry-run by this observer.",
		"PVC phase does not prove model file presence, digest, permissions, mount behavior or runtime compatibility.",
		"Target identity is pseudonymous and does not authenticate the cluster to a third party.",
	}
	slices.Sort(limitations)
	result := resources.TargetPreflightResult{
		APIVersion: resources.APIVersion, Kind: "TargetPreflightResult",
		Metadata: resources.TargetPreflightResultMetadata{Name: name},
		Spec: resources.TargetPreflightResultSpec{
			Outcome: outcome, ObservedAt: observedAt.UTC().Format(time.RFC3339Nano), BundleID: bundle.Metadata.BundleID, PlanID: bundle.Spec.PlanID,
			Observer: resources.TargetPreflightObserver{Name: "yara.kubernetes-readonly", Version: ObserverVersion, Mode: "read-only"},
			Target:   resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: observation.ReferenceDigest, ServerVersion: observation.ServerVersion},
			Checks:   checks, Limitations: limitations,
		},
	}
	result, err := result.AssignResultID()
	if err != nil {
		return resources.TargetPreflightResult{}, err
	}
	if report := result.Validate(); !report.Valid {
		return resources.TargetPreflightResult{}, fmt.Errorf("preflight evaluator produced invalid result: %s", report.Diagnostics[0].Code)
	}
	return result, nil
}

func availabilityCheck(id string, passed bool, code, passSummary, blockedSummary string, facts ...resources.TargetPreflightFact) resources.TargetPreflightCheck {
	status, summary, diagnostic := "passed", passSummary, ""
	if !passed {
		status, summary, diagnostic = "blocked", blockedSummary, code
	}
	return makeCheck(id, status, diagnostic, summary, facts...)
}

func versionCheck(version string) resources.TargetPreflightCheck {
	minor, valid := kubernetesMinor(version)
	status, diagnostic, summary := "passed", "", "Kubernetes server minor is within the renderer-tested range."
	if !valid || minor < 34 || minor > 36 {
		status, diagnostic, summary = "failed", "YARA-TPR-104", "Kubernetes server minor is outside the renderer-tested 1.34 through 1.36 range."
	}
	minorValue := "unknown"
	if valid {
		minorValue = strconv.Itoa(minor)
	}
	return makeCheck("kubernetes.version", status, diagnostic, summary, factString("observedMinor", minorValue), factString("testedRange", "1.34-1.36"))
}

func dnsCheck(observation Observation) resources.TargetPreflightCheck {
	if !observation.DNSReadable {
		return makeCheck("dns.selector", "blocked", "YARA-TPR-105", "DNS pods could not be observed with the available read-only permissions.", fact("readable", false))
	}
	if observation.DNSPodCount < 1 {
		return makeCheck("dns.selector", "failed", "YARA-TPR-106", "No kube-system pod matched k8s-app=kube-dns.", factInt("matchingPods", observation.DNSPodCount), fact("readable", true))
	}
	return makeCheck("dns.selector", "passed", "", "At least one DNS pod matches the renderer selector.", factInt("matchingPods", observation.DNSPodCount), fact("readable", true))
}

func gpuCheck(observation Observation) resources.TargetPreflightCheck {
	if !observation.NodesReadable {
		return makeCheck("gpu.allocatable", "blocked", "YARA-TPR-107", "Aggregated node GPU capacity could not be observed with the available read-only permissions.", fact("readable", false))
	}
	if observation.GPUCount < 1 {
		return makeCheck("gpu.allocatable", "failed", "YARA-TPR-108", "No allocatable nvidia.com/gpu capacity was observed.", factInt("nvidiaGpuCount", observation.GPUCount), fact("readable", true))
	}
	return makeCheck("gpu.allocatable", "passed", "", "Allocatable nvidia.com/gpu capacity is present.", factInt("nvidiaGpuCount", observation.GPUCount), fact("readable", true))
}

func platformCheck(bundle resources.DeploymentBundle, observation Observation) resources.TargetPreflightCheck {
	var supportedSet map[string]struct{}
	for _, artifact := range bundle.Spec.Artifacts {
		if artifact.Type != "oci-image" {
			continue
		}
		artifactSet := map[string]struct{}{}
		for _, platform := range artifact.Platforms {
			artifactSet[platform] = struct{}{}
		}
		if supportedSet == nil {
			supportedSet = artifactSet
			continue
		}
		for platform := range supportedSet {
			if _, ok := artifactSet[platform]; !ok {
				delete(supportedSet, platform)
			}
		}
	}
	supported := make([]string, 0, len(supportedSet))
	for platform := range supportedSet {
		supported = append(supported, platform)
	}
	slices.Sort(supported)
	observed := append([]string(nil), observation.NodePlatforms...)
	slices.Sort(observed)
	observed = slices.Compact(observed)
	if !observation.NodesReadable || len(observed) == 0 {
		return makeCheck("nodes.platform", "blocked", "YARA-TPR-118", "Node platforms could not be observed with the available read-only permissions.", fact("readable", observation.NodesReadable), factString("supportedPlatforms", strings.Join(supported, ",")))
	}
	unsupported := []string{}
	for _, platform := range observed {
		if _, ok := supportedSet[platform]; !ok {
			unsupported = append(unsupported, platform)
		}
	}
	if len(supported) == 0 || len(unsupported) > 0 {
		return makeCheck("nodes.platform", "failed", "YARA-TPR-119", "One or more observed node platforms are incompatible with the bundle OCI artifacts.", factString("observedPlatforms", strings.Join(observed, ",")), factString("supportedPlatforms", strings.Join(supported, ",")))
	}
	return makeCheck("nodes.platform", "passed", "", "Observed node platforms are compatible with every bundle OCI artifact.", factString("observedPlatforms", strings.Join(observed, ",")), factString("supportedPlatforms", strings.Join(supported, ",")))
}

func namespaceCheck(observation Observation) resources.TargetPreflightCheck {
	if !observation.NamespaceReadable {
		return makeCheck("namespace.ownership", "blocked", "YARA-TPR-109", "Target namespace ownership could not be observed.", fact("readable", false))
	}
	if !observation.NamespaceExists {
		return makeCheck("namespace.ownership", "passed", "", "Target namespace is absent; no ownership collision was observed.", fact("exists", false), fact("readable", true))
	}
	if !observation.NamespaceManaged || !observation.NamespacePlanMatch {
		return makeCheck("namespace.ownership", "failed", "YARA-TPR-110", "Existing target namespace is not owned by YARA for the exact plan.", fact("exists", true), fact("managedByYara", observation.NamespaceManaged), fact("planMatches", observation.NamespacePlanMatch), fact("readable", true))
	}
	return makeCheck("namespace.ownership", "passed", "", "Existing target namespace is labelled for YARA and the exact plan.", fact("exists", true), fact("managedByYara", true), fact("planMatches", true), fact("readable", true))
}

func pvcCheck(observation Observation) resources.TargetPreflightCheck {
	if !observation.PVCReadable {
		return makeCheck("storage.model-pvc", "blocked", "YARA-TPR-111", "Model PVC state could not be observed.", fact("readable", false))
	}
	if !observation.PVCExists {
		return makeCheck("storage.model-pvc", "blocked", "YARA-TPR-112", "Required yara-model PVC is absent.", fact("exists", false), fact("readable", true))
	}
	if observation.PVCPhase != "Bound" {
		return makeCheck("storage.model-pvc", "blocked", "YARA-TPR-113", "Required yara-model PVC is not Bound.", fact("exists", true), factString("phase", observation.PVCPhase), fact("readable", true))
	}
	return makeCheck("storage.model-pvc", "passed", "", "Required yara-model PVC is Bound.", fact("exists", true), factString("phase", "Bound"), fact("readable", true))
}

func modelDigestCheck() resources.TargetPreflightCheck {
	return makeCheck("storage.model-digests", "blocked", "YARA-TPR-114", "Read-only API observation cannot verify files inside the model PVC.", factString("verification", "not-observed"))
}

func networkPolicyEnforcementCheck() resources.TargetPreflightCheck {
	return makeCheck("network-policy.enforcement", "blocked", "YARA-TPR-115", "NetworkPolicy API discovery does not prove CNI enforcement.", factString("verification", "not-observed"))
}

func tmpExecCheck() resources.TargetPreflightCheck {
	return makeCheck("runtime.tmp-exec", "blocked", "YARA-TPR-116", "Read-only API observation cannot prove executable emptyDir behavior.", factString("verification", "not-observed"))
}

func verifierGovernanceCheck() resources.TargetPreflightCheck {
	return makeCheck("security.verifier-label-governance", "blocked", "YARA-TPR-117", "Read-only discovery cannot prove admission/RBAC control of verifier labels.", factString("verification", "not-observed"))
}

func makeCheck(id, status, diagnostic, summary string, facts ...resources.TargetPreflightFact) resources.TargetPreflightCheck {
	slices.SortFunc(facts, func(left, right resources.TargetPreflightFact) int {
		if left.Name < right.Name {
			return -1
		}
		if left.Name > right.Name {
			return 1
		}
		return 0
	})
	evidence, err := canonical.Digest(struct {
		ID     string
		Status string
		Facts  []resources.TargetPreflightFact
	}{ID: id, Status: status, Facts: facts})
	if err != nil {
		panic(fmt.Sprintf("digest allowlisted preflight evidence: %v", err))
	}
	return resources.TargetPreflightCheck{ID: id, Status: status, DiagnosticCode: diagnostic, Summary: summary, EvidenceDigest: evidence, Facts: facts}
}

func fact(name string, value bool) resources.TargetPreflightFact {
	return factString(name, strconv.FormatBool(value))
}

func factInt(name string, value int) resources.TargetPreflightFact {
	return factString(name, strconv.Itoa(value))
}

func factString(name, value string) resources.TargetPreflightFact {
	return resources.TargetPreflightFact{Name: name, Value: value}
}

func kubernetesMinor(version string) (int, bool) {
	matches := kubernetesVersionPattern.FindStringSubmatch(version)
	if len(matches) != 2 {
		return 0, false
	}
	minor, err := strconv.Atoi(matches[1])
	return minor, err == nil
}
