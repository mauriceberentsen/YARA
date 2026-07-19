package targetpreflight_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/planner"
	"github.com/mauriceberentsen/YARA/internal/renderer"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/targetpreflight"
)

func TestEvaluateProducesContentAddressedBlockedResult(t *testing.T) {
	bundle := kubernetesBundle(t)
	observation := targetpreflight.Observation{
		ReferenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ServerVersion:   "v1.35.2", CoreV1: true, AppsV1: true, NetworkingV1: true,
		NodesReadable: true, GPUCount: 1, DNSReadable: true, DNSPodCount: 2,
		NamespaceReadable: true, PVCReadable: true, PVCExists: true, PVCPhase: "Bound",
	}
	result, err := targetpreflight.Evaluate("reference-target", bundle, observation, time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Spec.Outcome != "blocked" || result.Metadata.ResultID == "" || result.Spec.Target.ReferenceDigest != observation.ReferenceDigest {
		t.Fatalf("unexpected result identity/outcome: %#v", result)
	}
	if report := result.Validate(); !report.Valid {
		t.Fatalf("result is invalid: %#v", report.Diagnostics)
	}
	text := result.Spec.Target.ReferenceDigest + strings.Join(result.Spec.Limitations, "\n")
	for _, secret := range []string{"https://cluster.internal:6443", "production-admin", "worker-01", "coredns-abc"} {
		if strings.Contains(text, secret) {
			t.Fatalf("durable result leaked target identity %q", secret)
		}
	}
}

func TestEvaluateFailsUnsupportedVersionAndNamespaceCollision(t *testing.T) {
	bundle := kubernetesBundle(t)
	observation := targetpreflight.Observation{
		ReferenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ServerVersion:   "v1.33.9", CoreV1: true, AppsV1: true, NetworkingV1: true,
		NodesReadable: true, GPUCount: 1, DNSReadable: true, DNSPodCount: 1,
		NamespaceReadable: true, NamespaceExists: true, NamespaceManaged: false,
		PVCReadable: true, PVCExists: true, PVCPhase: "Bound",
	}
	result, err := targetpreflight.Evaluate("reference-target", bundle, observation, time.Now())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Spec.Outcome != "failed" {
		t.Fatalf("unsupported target did not fail: %#v", result.Spec.Checks)
	}
}

func TestEvaluateRejectsNonKubernetesBundle(t *testing.T) {
	bundle := kubernetesBundle(t)
	bundle.Spec.Renderer.Target = "docker-compose"
	bundle, err := bundle.AssignBundleID()
	if err != nil {
		t.Fatalf("assign bundle ID: %v", err)
	}
	_, err = targetpreflight.Evaluate("reference-target", bundle, targetpreflight.Observation{}, time.Now())
	if err == nil {
		t.Fatal("non-Kubernetes bundle was accepted")
	}
}

func kubernetesBundle(t *testing.T) resources.DeploymentBundle {
	t.Helper()
	root := filepath.Join("..", "..")
	request, err := resources.LoadPlatformRequest(filepath.Join(root, "docs", "examples", "v0.2-platform-request.yaml"))
	if err != nil {
		t.Fatalf("load request: %v", err)
	}
	inventory, err := resources.LoadInventory(filepath.Join(root, "docs", "examples", "v0.2-inventory.yaml"))
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	snapshot, err := catalog.Load(filepath.Join(root, "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	created := planner.Create(request, inventory, snapshot)
	if !created.Report.Valid {
		t.Fatalf("create plan: %#v", created.Report.Diagnostics)
	}
	bundle, err := (renderer.KubernetesGitOps{}).Render("reference-stack", created.Plan, snapshot)
	if err != nil {
		t.Fatalf("render bundle: %v", err)
	}
	return bundle
}
