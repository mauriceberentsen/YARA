// Package changeset creates a bounded, read-only comparison between an exact
// Kubernetes bundle and an observed target. It contains no mutation capability.
package changeset

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

const ObserverVersion = "0.1.0"

type DesiredObject struct {
	Reference resources.KubernetesObjectReference
	Digest    string
	Object    map[string]any
}

type ObjectObservation struct {
	Reference resources.KubernetesObjectReference
	Readable  bool
	Exists    bool
	Owned     bool
	PlanMatch bool
	Digest    string
}

type Observation struct {
	Target  resources.TargetIdentity
	Objects []ObjectObservation
}

func DesiredObjects(bundle resources.DeploymentBundle) ([]DesiredObject, error) {
	if report := bundle.Validate(); !report.Valid {
		return nil, fmt.Errorf("bundle is invalid: %s", report.Diagnostics[0].Code)
	}
	if bundle.Spec.Renderer.Target != "kubernetes-gitops" {
		return nil, fmt.Errorf("change set requires a kubernetes-gitops bundle")
	}
	objects := make([]DesiredObject, 0)
	for _, file := range bundle.Spec.Files {
		if file.MediaType != "application/yaml" || file.Path == bundle.Spec.SupplyChain.OfflineAcquisitionPath {
			continue
		}
		object, err := decodeSingleObject(file.Content)
		if err != nil {
			return nil, fmt.Errorf("decode rendered object %s: %w", file.Path, err)
		}
		reference, err := objectReference(object)
		if err != nil {
			return nil, fmt.Errorf("identify rendered object %s: %w", file.Path, err)
		}
		normalized := normalizeObject(object, reference.Kind, false)
		digest, err := canonical.Digest(normalized)
		if err != nil {
			return nil, fmt.Errorf("digest rendered object %s: %w", file.Path, err)
		}
		objects = append(objects, DesiredObject{Reference: reference, Digest: digest, Object: normalized})
	}
	slices.SortFunc(objects, func(left, right DesiredObject) int {
		return strings.Compare(objectKey(left.Reference), objectKey(right.Reference))
	})
	if len(objects) == 0 {
		return nil, fmt.Errorf("bundle contains no supported Kubernetes objects")
	}
	for index := 1; index < len(objects); index++ {
		if objectKey(objects[index-1].Reference) == objectKey(objects[index].Reference) {
			return nil, fmt.Errorf("bundle contains duplicate Kubernetes object identity")
		}
	}
	return objects, nil
}

func Evaluate(name string, bundle resources.DeploymentBundle, preflight resources.TargetPreflightResult, observation Observation, observedAt time.Time) (resources.KubernetesChangeSet, error) {
	desired, err := DesiredObjects(bundle)
	if err != nil {
		return resources.KubernetesChangeSet{}, err
	}
	if report := preflight.Validate(); !report.Valid {
		return resources.KubernetesChangeSet{}, fmt.Errorf("preflight result is invalid: %s", report.Diagnostics[0].Code)
	}
	if preflight.Spec.BundleID != bundle.Metadata.BundleID || preflight.Spec.PlanID != bundle.Spec.PlanID {
		return resources.KubernetesChangeSet{}, fmt.Errorf("preflight does not bind the exact bundle and plan")
	}
	if observation.Target != preflight.Spec.Target {
		return resources.KubernetesChangeSet{}, fmt.Errorf("observed target changed since preflight")
	}
	observedByKey := make(map[string]ObjectObservation, len(observation.Objects))
	for _, item := range observation.Objects {
		key := objectKey(item.Reference)
		if _, exists := observedByKey[key]; exists {
			return resources.KubernetesChangeSet{}, fmt.Errorf("duplicate object observation")
		}
		observedByKey[key] = item
	}
	operations := make([]resources.KubernetesChangeOperation, 0, len(desired))
	summary := resources.KubernetesChangeSummary{}
	blocked := false
	for _, wanted := range desired {
		observed, exists := observedByKey[objectKey(wanted.Reference)]
		operation := resources.KubernetesChangeOperation{Resource: wanted.Reference, DesiredDigest: wanted.Digest, RiskClasses: riskClasses(wanted.Reference.Kind)}
		switch {
		case !exists || !observed.Readable:
			operation.Action, operation.Ownership, operation.DiagnosticCode = "unresolved", "unknown", "YARA-CHG-101"
			summary.Unresolved++
			blocked = true
		case !observed.Exists:
			operation.Action, operation.Ownership = "create", "absent"
			summary.Creates++
		case !observed.Owned || !observed.PlanMatch:
			operation.Action, operation.Ownership, operation.CurrentDigest, operation.DiagnosticCode = "conflict", "foreign", observed.Digest, "YARA-CHG-102"
			summary.Conflicts++
			blocked = true
		case observed.Digest == wanted.Digest:
			operation.Action, operation.Ownership, operation.CurrentDigest = "no-op", "owned", observed.Digest
			summary.NoOps++
		default:
			operation.Action, operation.Ownership, operation.CurrentDigest = "update", "owned", observed.Digest
			summary.Updates++
		}
		operations = append(operations, operation)
	}
	outcome := "review-required"
	if blocked {
		outcome = "blocked"
	}
	limitations := []string{
		"Change classification compares a versioned projection of supported resource kinds and does not invoke admission or server-side dry-run.",
		"No deletion or pruning is discovered or proposed by this observer.",
		"Read-only observation cannot predict admission, controller reconciliation or target state changes after observedAt.",
		"Resource ownership uses YARA labels and the exact plan annotation; it is not cryptographic ownership proof.",
	}
	slices.Sort(limitations)
	result := resources.KubernetesChangeSet{
		APIVersion: resources.APIVersion, Kind: "KubernetesChangeSet", Metadata: resources.KubernetesChangeSetMetadata{Name: name},
		Spec: resources.KubernetesChangeSetSpec{
			Outcome: outcome, ObservedAt: observedAt.UTC().Format(time.RFC3339Nano), BundleID: bundle.Metadata.BundleID,
			PlanID: bundle.Spec.PlanID, PreflightResultID: preflight.Metadata.ResultID,
			Observer: resources.TargetPreflightObserver{Name: "yara.kubernetes-change-set-readonly", Version: ObserverVersion, Mode: "read-only"},
			Target:   observation.Target, Summary: summary, Operations: operations, Limitations: limitations,
		},
	}
	result, err = result.AssignChangeSetID()
	if err != nil {
		return resources.KubernetesChangeSet{}, err
	}
	if report := result.Validate(); !report.Valid {
		return resources.KubernetesChangeSet{}, fmt.Errorf("change-set evaluator produced invalid result: %s", report.Diagnostics[0].Code)
	}
	return result, nil
}

func DecodeCurrentObject(data []byte, expected resources.KubernetesObjectReference, planID string) (ObjectObservation, error) {
	observation := ObjectObservation{Reference: expected, Readable: true}
	if len(bytes.TrimSpace(data)) == 0 {
		return observation, nil
	}
	object, err := decodeSingleObject(string(data))
	if err != nil {
		return ObjectObservation{}, err
	}
	reference, err := objectReference(object)
	if err != nil || reference != expected {
		return ObjectObservation{}, fmt.Errorf("observed object identity does not match requested object")
	}
	metadata, _ := object["metadata"].(map[string]any)
	labels, _ := metadata["labels"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	observation.Exists = true
	observation.Owned = stringValue(labels["app.kubernetes.io/managed-by"]) == "yara"
	observation.PlanMatch = stringValue(annotations["yara.dev/plan-id"]) == planID
	normalized := normalizeObject(object, reference.Kind, true)
	observation.Digest, err = canonical.Digest(normalized)
	if err != nil {
		return ObjectObservation{}, err
	}
	return observation, nil
}

func decodeSingleObject(content string) (map[string]any, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected exactly one YAML document")
	}
	if len(object) == 0 {
		return nil, fmt.Errorf("empty Kubernetes object")
	}
	return object, nil
}

func objectReference(object map[string]any) (resources.KubernetesObjectReference, error) {
	metadata, _ := object["metadata"].(map[string]any)
	reference := resources.KubernetesObjectReference{
		APIVersion: stringValue(object["apiVersion"]), Kind: stringValue(object["kind"]),
		Namespace: stringValue(metadata["namespace"]), Name: stringValue(metadata["name"]),
	}
	if reference.APIVersion == "" || reference.Kind == "" || reference.Name == "" {
		return resources.KubernetesObjectReference{}, fmt.Errorf("incomplete Kubernetes identity")
	}
	if !slices.Contains([]string{"Namespace", "ConfigMap", "Deployment", "Service", "NetworkPolicy"}, reference.Kind) {
		return resources.KubernetesObjectReference{}, fmt.Errorf("unsupported Kubernetes kind %s", reference.Kind)
	}
	if reference.Kind == "Namespace" && reference.Namespace != "" {
		return resources.KubernetesObjectReference{}, fmt.Errorf("Namespace must be cluster scoped")
	}
	return reference, nil
}

func normalizeObject(input map[string]any, kind string, current bool) map[string]any {
	object := deepCopyMap(input)
	delete(object, "status")
	metadata, _ := object["metadata"].(map[string]any)
	for _, key := range []string{"creationTimestamp", "deletionGracePeriodSeconds", "deletionTimestamp", "generation", "managedFields", "resourceVersion", "selfLink", "uid"} {
		delete(metadata, key)
	}
	if annotations, ok := metadata["annotations"].(map[string]any); ok {
		delete(annotations, "kubectl.kubernetes.io/last-applied-configuration")
		delete(annotations, "deployment.kubernetes.io/revision")
		if len(annotations) == 0 {
			delete(metadata, "annotations")
		}
	}
	if current && kind == "Namespace" {
		delete(object, "spec")
		if labels, ok := metadata["labels"].(map[string]any); ok {
			delete(labels, "kubernetes.io/metadata.name")
		}
	}
	if current && kind == "Service" {
		spec, _ := object["spec"].(map[string]any)
		for _, key := range []string{"clusterIP", "clusterIPs", "healthCheckNodePort", "internalTrafficPolicy", "ipFamilies", "ipFamilyPolicy", "sessionAffinity"} {
			delete(spec, key)
		}
		if ports, ok := spec["ports"].([]any); ok {
			for _, raw := range ports {
				if port, ok := raw.(map[string]any); ok {
					delete(port, "nodePort")
				}
			}
		}
	}
	if current && kind == "Deployment" {
		spec, _ := object["spec"].(map[string]any)
		template, _ := spec["template"].(map[string]any)
		pod, _ := template["spec"].(map[string]any)
		for _, key := range []string{"dnsPolicy", "enableServiceLinks", "preemptionPolicy", "priority", "restartPolicy", "schedulerName", "terminationGracePeriodSeconds"} {
			delete(pod, key)
		}
		if containers, ok := pod["containers"].([]any); ok {
			for _, raw := range containers {
				if container, ok := raw.(map[string]any); ok {
					delete(container, "terminationMessagePath")
					delete(container, "terminationMessagePolicy")
					for _, key := range []string{"startupProbe", "readinessProbe", "livenessProbe"} {
						probe, _ := container[key].(map[string]any)
						if probe["successThreshold"] == 1 {
							delete(probe, "successThreshold")
						}
						httpGet, _ := probe["httpGet"].(map[string]any)
						if httpGet["scheme"] == "HTTP" {
							delete(httpGet, "scheme")
						}
					}
				}
			}
		}
		if volumes, ok := pod["volumes"].([]any); ok {
			for _, raw := range volumes {
				volume, _ := raw.(map[string]any)
				configMap, _ := volume["configMap"].(map[string]any)
				if configMap["defaultMode"] == 420 {
					delete(configMap, "defaultMode")
				}
			}
		}
	}
	return object
}

func deepCopyMap(input map[string]any) map[string]any {
	data, _ := yaml.Marshal(input)
	var output map[string]any
	_ = yaml.Unmarshal(data, &output)
	return output
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func riskClasses(kind string) []string {
	switch kind {
	case "Namespace":
		return []string{"namespace"}
	case "ConfigMap":
		return []string{"configuration"}
	case "Deployment":
		return []string{"workload-restart"}
	case "Service":
		return []string{"network"}
	case "NetworkPolicy":
		return []string{"security-policy"}
	default:
		return []string{}
	}
}

func objectKey(reference resources.KubernetesObjectReference) string {
	return strings.Join([]string{reference.APIVersion, reference.Kind, reference.Namespace, reference.Name}, "\x00")
}
