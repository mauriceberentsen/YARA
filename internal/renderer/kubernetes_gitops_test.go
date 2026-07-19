package renderer

import (
	"reflect"
	"strings"
	"testing"
)

func TestKubernetesGitOpsRenderIsDeterministicPinnedAndNonMutating(t *testing.T) {
	plan, snapshot := v02Plan(t)
	renderer := KubernetesGitOps{}
	first, err := renderer.Render("reference-stack", plan, snapshot)
	if err != nil {
		t.Fatalf("render first bundle: %v", err)
	}
	second, err := renderer.Render("reference-stack", plan, snapshot)
	if err != nil {
		t.Fatalf("render second bundle: %v", err)
	}
	if !reflect.DeepEqual(first, second) || first.Metadata.BundleID != second.Metadata.BundleID {
		t.Fatal("identical plan and catalog did not produce an identical Kubernetes bundle")
	}
	if report := first.Validate(); !report.Valid {
		t.Fatalf("bundle is invalid: %#v", report.Diagnostics)
	}
	if first.Spec.Renderer.Target != "kubernetes-gitops" || len(first.Spec.Files) != 14 || len(first.Spec.Artifacts) != 3 {
		t.Fatalf("Kubernetes bundle inventory is incomplete: renderer=%#v files=%d artifacts=%d", first.Spec.Renderer, len(first.Spec.Files), len(first.Spec.Artifacts))
	}
	assertSupplyChainInventory(t, first)

	files := map[string]string{}
	for _, file := range first.Spec.Files {
		files[file.Path] = file.Content
	}
	all := strings.Join([]string{
		files["20-inference-deployment.yaml"], files["21-inference-service.yaml"],
		files["30-gateway-deployment.yaml"], files["31-gateway-service.yaml"],
		files["40-default-deny.yaml"], files["41-gateway-egress-inference.yaml"],
		files["42-inference-ingress-gateway.yaml"], files["43-gateway-dns-egress.yaml"],
		files["44-gateway-verifier-ingress.yaml"],
		files["45-verifier-egress.yaml"],
	}, "\n")
	for _, expected := range []string{
		"ghcr.io/berriai/litellm:v1.93.0@sha256:a1745e629abfb17d434426ff48b115f54f4f4c4a0f5af241de569e93c63c411e",
		"vllm/vllm-openai:v0.25.1@sha256:e4f88a835143cd22aee2397a26ec6bb80b3a4a6fe0c882bcbc63822904766089",
		"automountServiceAccountToken: false", "allowPrivilegeEscalation: false", "readOnlyRootFilesystem: true",
		"type: RuntimeDefault", "nvidia.com/gpu: \"1\"", "claimName: yara-model", "type: ClusterIP",
		"name: FLASHINFER_WORKSPACE_BASE", "name: XDG_CACHE_HOME", "value: /tmp",
		"containerPort: 8000", "port: 4000", "port: 8000",
		"kind: NetworkPolicy", "kubernetes.io/metadata.name: kube-system", "k8s-app: kube-dns",
	} {
		if !strings.Contains(all, expected) {
			t.Fatalf("Kubernetes output lacks %q:\n%s", expected, all)
		}
	}
	for _, forbidden := range []string{"kind: Ingress", "kind: Gateway", "type: LoadBalancer", "type: NodePort", "hostNetwork: true", "privileged: true"} {
		if strings.Contains(all, forbidden) {
			t.Fatalf("Kubernetes output contains forbidden access/privilege setting %q", forbidden)
		}
	}
	if strings.Contains(all, "port: 0") || strings.Contains(all, "containerPort: 0") || strings.Contains(all, "name: \"\"") {
		t.Fatalf("Kubernetes output contains an unresolved adapter value:\n%s", all)
	}
	if !strings.Contains(files["10-litellm-configmap.yaml"], "immutable: true") || !strings.Contains(files["10-litellm-configmap.yaml"], "http://inference:8000/v1") || !strings.Contains(files["30-gateway-deployment.yaml"], "reference-stack-litellm-") {
		t.Fatalf("immutable gateway configuration is incomplete:\n%s", files["10-litellm-configmap.yaml"])
	}
}

func TestKubernetesGitOpsRejectsInvalidNamespaceAndUnknownAdapter(t *testing.T) {
	plan, snapshot := v02Plan(t)
	if _, err := (KubernetesGitOps{}).Render("Invalid_Name", plan, snapshot); err == nil {
		t.Fatal("renderer accepted an invalid Kubernetes namespace")
	}
	plan.Spec.Topology.Instances[0].ComponentRef = "core.unknown@1.0.0"
	assigned, err := plan.AssignPlanID()
	if err != nil {
		t.Fatalf("reassign plan identity: %v", err)
	}
	if _, err := (KubernetesGitOps{}).Render("reference-stack", assigned, snapshot); err == nil {
		t.Fatal("renderer silently replaced an unsupported component")
	}
}

func TestRendererPrototypesPreserveTheSamePlanAndArtifactInventory(t *testing.T) {
	plan, snapshot := v02Plan(t)
	compose, err := (DockerCompose{}).Render("reference-stack", plan, snapshot)
	if err != nil {
		t.Fatalf("render Compose comparison bundle: %v", err)
	}
	kubernetes, err := (KubernetesGitOps{}).Render("reference-stack", plan, snapshot)
	if err != nil {
		t.Fatalf("render Kubernetes comparison bundle: %v", err)
	}
	if compose.Spec.PlanID != kubernetes.Spec.PlanID || compose.Spec.CatalogDigest != kubernetes.Spec.CatalogDigest || !reflect.DeepEqual(compose.Spec.Artifacts, kubernetes.Spec.Artifacts) || !reflect.DeepEqual(compose.Spec.Operations, kubernetes.Spec.Operations) {
		t.Fatalf("renderer comparison changed architecture or immutable inventory:\ncompose=%#v\nkubernetes=%#v", compose.Spec, kubernetes.Spec)
	}
	if compose.Metadata.BundleID == kubernetes.Metadata.BundleID {
		t.Fatal("different target artifacts unexpectedly produced the same bundle identity")
	}
}
