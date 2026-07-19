package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/targetpreflight"
)

type fixedTargetObserver struct {
	observation targetpreflight.Observation
	err         error
}

func (o fixedTargetObserver) Observe(_ context.Context, _, _ string) (targetpreflight.Observation, error) {
	return o.observation, o.err
}

func TestKubernetesTargetPreflightWritesBlockedResultAndPseudonymousAudit(t *testing.T) {
	directory := t.TempDir()
	bundlePath := writeKubernetesBundle(t, directory)
	outputPath := filepath.Join(directory, "preflight.yaml")
	auditPath := filepath.Join(directory, "preflight.audit.jsonl")
	reference := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	observation := targetpreflight.Observation{
		ReferenceDigest: reference, ServerVersion: "v1.35.2", CoreV1: true, AppsV1: true, NetworkingV1: true,
		NodesReadable: true, GPUCount: 2, DNSReadable: true, DNSPodCount: 2,
		NamespaceReadable: true, PVCReadable: true, PVCExists: true, PVCPhase: "Bound",
	}
	factory := func(kubeconfig, contextName string) (targetpreflight.Observer, error) {
		if kubeconfig != "/private/admin.conf" || contextName != "production-admin" {
			t.Fatalf("CLI did not forward ephemeral observer settings")
		}
		return fixedTargetObserver{observation: observation}, nil
	}
	args := []string{"--bundle", bundlePath, "--name", "reference-preflight", "--output", outputPath, "--audit-output", auditPath, "--kubeconfig", "/private/admin.conf", "--context", "production-admin"}
	var stdout, stderr bytes.Buffer
	exit := runKubernetesTargetPreflight(args, &stdout, &stderr, factory, func() time.Time { return time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC) })
	if exit != ExitInfeasible {
		t.Fatalf("expected blocked exit, got %d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	result, err := resources.LoadTargetPreflightResult(outputPath)
	if err != nil {
		t.Fatalf("load result: %v", err)
	}
	if result.Spec.Outcome != "blocked" || result.Spec.Target.ReferenceDigest != reference {
		t.Fatalf("unexpected result: %#v", result)
	}
	validationAudit := filepath.Join(directory, "preflight-validation.audit.jsonl")
	stdout.Reset()
	stderr.Reset()
	if exit := Run([]string{"target-preflight", "validate", outputPath, "--audit-output", validationAudit}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("validate result: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "target.kubernetes-preflight.blocked" || terminal.Spec.Target != "kubernetes:"+reference || len(terminal.Spec.Subjects) != 3 || terminal.Spec.Subjects[2].Digest != result.Metadata.ResultID {
		t.Fatalf("unexpected terminal audit event: %#v", terminal.Spec)
	}
	durable := string(mustReadFile(t, outputPath)) + string(mustReadFile(t, auditPath))
	for _, forbidden := range []string{"/private/admin.conf", "production-admin", "cluster.internal", "worker-01", "pod-01"} {
		if strings.Contains(durable, forbidden) {
			t.Fatalf("durable evidence leaked %q", forbidden)
		}
	}
}

func TestKubernetesTargetPreflightRollsBackResultWhenAuditFails(t *testing.T) {
	directory := t.TempDir()
	bundlePath := writeKubernetesBundle(t, directory)
	outputPath := filepath.Join(directory, "preflight.yaml")
	auditPath := filepath.Join(directory, "audit-collision")
	if err := os.Mkdir(auditPath, 0o700); err != nil {
		t.Fatal(err)
	}
	observation := targetpreflight.Observation{ReferenceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", ServerVersion: "v1.35.2"}
	factory := func(_, _ string) (targetpreflight.Observer, error) {
		return fixedTargetObserver{observation: observation}, nil
	}
	args := []string{"--bundle", bundlePath, "--name", "reference-preflight", "--output", outputPath, "--audit-output", auditPath}
	var stdout, stderr bytes.Buffer
	if exit := runKubernetesTargetPreflight(args, &stdout, &stderr, factory, time.Now); exit == ExitSuccess {
		t.Fatal("preflight unexpectedly succeeded")
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("result survived mandatory audit failure: %v", err)
	}
}

func TestKubernetesTargetPreflightDoesNotPersistObserverError(t *testing.T) {
	directory := t.TempDir()
	bundlePath := writeKubernetesBundle(t, directory)
	outputPath, auditPath := filepath.Join(directory, "preflight.yaml"), filepath.Join(directory, "preflight.audit.jsonl")
	factory := func(_, _ string) (targetpreflight.Observer, error) {
		return fixedTargetObserver{err: errors.New("https://secret-api.internal:6443 production-admin")}, nil
	}
	args := []string{"--bundle", bundlePath, "--name", "reference-preflight", "--output", outputPath, "--audit-output", auditPath}
	var stdout, stderr bytes.Buffer
	if exit := runKubernetesTargetPreflight(args, &stdout, &stderr, factory, time.Now); exit != ExitInfeasible {
		t.Fatalf("unexpected exit: %d", exit)
	}
	durable := stdout.String() + string(mustReadFile(t, auditPath))
	if strings.Contains(durable, "secret-api") || strings.Contains(durable, "production-admin") {
		t.Fatalf("observer error leaked into durable/user output: %s", durable)
	}
}

func writeKubernetesBundle(t *testing.T, directory string) string {
	t.Helper()
	planPath, catalogPath := writeV02Plan(t, directory)
	bundlePath := filepath.Join(directory, "kubernetes-bundle.yaml")
	auditPath := filepath.Join(directory, "render.audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exit := renderKubernetesGitOps([]string{"--plan", planPath, "--catalog", catalogPath, "--name", "reference-stack", "--output", bundlePath, "--audit-output", auditPath}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("render fixture: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	return bundlePath
}
