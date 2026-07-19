package changeset_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/changeset"
	"github.com/mauriceberentsen/YARA/internal/planner"
	"github.com/mauriceberentsen/YARA/internal/renderer"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/targetpreflight"
	"gopkg.in/yaml.v3"
)

func TestDesiredObjectsAndNoOpEvaluationAreDeterministic(t *testing.T) {
	bundle := changeSetBundle(t)
	desired, err := changeset.DesiredObjects(bundle)
	if err != nil {
		t.Fatalf("desired objects: %v", err)
	}
	if len(desired) != 12 {
		t.Fatalf("expected 12 Kubernetes resources, found %d", len(desired))
	}
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: digest('c'), ServerVersion: "v1.35.2"}
	preflight := changeSetPreflight(t, bundle, target)
	observed := changeset.Observation{Target: target}
	for _, object := range desired {
		data, err := yaml.Marshal(object.Object)
		if err != nil {
			t.Fatal(err)
		}
		current, err := changeset.DecodeCurrentObject(data, object.Reference, bundle.Spec.PlanID)
		if err != nil {
			t.Fatalf("decode current %s: %v", object.Reference.Name, err)
		}
		observed.Objects = append(observed.Objects, current)
	}
	result, err := changeset.Evaluate("reference-change-set", bundle, preflight, observed, time.Date(2026, 7, 19, 12, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Spec.Outcome != "review-required" || result.Spec.Summary.NoOps != 12 || result.Spec.Summary.Creates != 0 {
		t.Fatalf("unexpected no-op result: %#v", result.Spec.Summary)
	}
	if report := result.Validate(); !report.Valid {
		t.Fatalf("invalid result: %#v", report.Diagnostics)
	}
}

func TestForeignAndUnreadableObjectsBlockChangeSet(t *testing.T) {
	bundle := changeSetBundle(t)
	desired, _ := changeset.DesiredObjects(bundle)
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: digest('c'), ServerVersion: "v1.35.2"}
	preflight := changeSetPreflight(t, bundle, target)
	observed := changeset.Observation{Target: target}
	for index, object := range desired {
		item := changeset.ObjectObservation{Reference: object.Reference, Readable: true}
		if index == 0 {
			item.Exists, item.Digest = true, digest('d')
		} else if index == 1 {
			item.Readable = false
		} else if index > 1 {
			item.Exists, item.Owned, item.PlanMatch, item.Digest = true, true, true, object.Digest
		}
		observed.Objects = append(observed.Objects, item)
	}
	result, err := changeset.Evaluate("reference-change-set", bundle, preflight, observed, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.Spec.Outcome != "blocked" || result.Spec.Summary.Conflicts != 1 || result.Spec.Summary.Unresolved != 1 {
		t.Fatalf("unsafe observations not blocked: %#v", result.Spec.Summary)
	}
}

func TestServiceProjectionIgnoresOnlyKnownServerAssignedFields(t *testing.T) {
	content := `apiVersion: v1
kind: Service
metadata:
  name: gateway
  namespace: reference-stack
  labels:
    app.kubernetes.io/managed-by: yara
  annotations:
    yara.dev/plan-id: ` + digest('a') + `
spec:
  type: ClusterIP
  selector: {app: gateway}
  clusterIP: 10.0.0.1
  clusterIPs: [10.0.0.1]
  ipFamilies: [IPv4]
  ipFamilyPolicy: SingleStack
  sessionAffinity: None
  internalTrafficPolicy: Cluster
  ports:
    - name: http
      port: 4000
      protocol: TCP
      targetPort: http
`
	reference := resources.KubernetesObjectReference{APIVersion: "v1", Kind: "Service", Namespace: "reference-stack", Name: "gateway"}
	first, err := changeset.DecodeCurrentObject([]byte(content), reference, digest('a'))
	if err != nil {
		t.Fatal(err)
	}
	content += "  externalTrafficPolicy: Local\n"
	second, err := changeset.DecodeCurrentObject([]byte(content), reference, digest('a'))
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest {
		t.Fatal("non-allowlisted service drift was hidden")
	}
}

func TestDeploymentProjectionIgnoresKnownServerDefaults(t *testing.T) {
	bundle := changeSetBundle(t)
	desired, err := changeset.DesiredObjects(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var gateway changeset.DesiredObject
	for _, object := range desired {
		if object.Reference.Kind == "Deployment" && object.Reference.Name == "gateway" {
			gateway = object
			break
		}
	}
	if gateway.Digest == "" {
		t.Fatal("gateway Deployment missing")
	}
	data, err := yaml.Marshal(gateway.Object)
	if err != nil {
		t.Fatal(err)
	}
	var current map[string]any
	if err := yaml.Unmarshal(data, &current); err != nil {
		t.Fatal(err)
	}
	spec := current["spec"].(map[string]any)
	pod := spec["template"].(map[string]any)["spec"].(map[string]any)
	container := pod["containers"].([]any)[0].(map[string]any)
	for _, key := range []string{"startupProbe", "readinessProbe", "livenessProbe"} {
		probe := container[key].(map[string]any)
		probe["successThreshold"] = 1
		probe["httpGet"].(map[string]any)["scheme"] = "HTTP"
	}
	for _, raw := range pod["volumes"].([]any) {
		volume := raw.(map[string]any)
		if configMap, ok := volume["configMap"].(map[string]any); ok {
			configMap["defaultMode"] = 420
		}
	}
	data, err = yaml.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := changeset.DecodeCurrentObject(data, gateway.Reference, bundle.Spec.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Digest != gateway.Digest {
		t.Fatalf("known Kubernetes defaults changed the desired digest: got %s want %s", observed.Digest, gateway.Digest)
	}
}

func changeSetBundle(t *testing.T) resources.DeploymentBundle {
	t.Helper()
	root := filepath.Join("..", "..")
	request, err := resources.LoadPlatformRequest(filepath.Join(root, "docs", "examples", "v0.2-platform-request.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := resources.LoadInventory(filepath.Join(root, "docs", "examples", "v0.2-inventory.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := catalog.Load(filepath.Join(root, "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	created := planner.Create(request, inventory, snapshot)
	if !created.Report.Valid {
		t.Fatalf("plan: %#v", created.Report.Diagnostics)
	}
	bundle, err := (renderer.KubernetesGitOps{}).Render("reference-stack", created.Plan, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func changeSetPreflight(t *testing.T, bundle resources.DeploymentBundle, target resources.TargetIdentity) resources.TargetPreflightResult {
	t.Helper()
	observation := targetpreflight.Observation{
		ReferenceDigest: target.ReferenceDigest, ServerVersion: target.ServerVersion,
		CoreV1: true, AppsV1: true, NetworkingV1: true, NodesReadable: true, GPUCount: 1, NodePlatforms: []string{"linux/amd64"},
		DNSReadable: true, DNSPodCount: 1, NamespaceReadable: true, PVCReadable: true, PVCExists: true, PVCPhase: "Bound",
	}
	result, err := targetpreflight.Evaluate("reference-preflight", bundle, observation, time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func digest(character byte) string {
	return "sha256:" + repeat(character, 64)
}

func repeat(character byte, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = character
	}
	return string(result)
}
