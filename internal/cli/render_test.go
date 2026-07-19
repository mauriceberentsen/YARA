package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/planner"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

func TestRenderDockerComposeWritesValidBundleAndAudit(t *testing.T) {
	directory := t.TempDir()
	planPath, catalogPath := writeV02Plan(t, directory)
	outputPath := filepath.Join(directory, "bundle.yaml")
	auditPath := filepath.Join(directory, "bundle.audit.jsonl")
	args := []string{
		"render", "docker-compose", "--plan", planPath, "--catalog", catalogPath,
		"--name", "reference-stack", "--output", outputPath, "--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(args, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("render failed: exit=%d stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	bundle, err := resources.LoadDeploymentBundle(outputPath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	if report := bundle.Validate(); !report.Valid {
		t.Fatalf("validate bundle: %#v", report.Diagnostics)
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "render.docker-compose.completed" || len(terminal.Spec.Subjects) != 3 || terminal.Spec.Subjects[2].Kind != "DeploymentBundle" || terminal.Spec.Subjects[2].Digest != bundle.Metadata.BundleID {
		t.Fatalf("render audit does not bind plan, catalog and bundle: %#v", terminal.Spec)
	}
}

func TestRenderDockerComposeRollsBackBundleWhenAuditFails(t *testing.T) {
	directory := t.TempDir()
	planPath, catalogPath := writeV02Plan(t, directory)
	outputPath := filepath.Join(directory, "bundle.yaml")
	auditPath := filepath.Join(directory, "audit-is-a-directory")
	if err := os.Mkdir(auditPath, 0o700); err != nil {
		t.Fatalf("create audit collision: %v", err)
	}
	args := []string{
		"render", "docker-compose", "--plan", planPath, "--catalog", catalogPath,
		"--name", "reference-stack", "--output", outputPath, "--audit-output", auditPath,
	}
	var stdout, stderr bytes.Buffer
	if exitCode := Run(args, &stdout, &stderr); exitCode == ExitSuccess {
		t.Fatalf("render unexpectedly succeeded: %s", stdout.String())
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("bundle survived mandatory audit failure: %v", err)
	}
}

func writeV02Plan(t *testing.T, directory string) (string, string) {
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
	catalogPath := filepath.Join(root, "catalog", "v0.2", "snapshot.yaml")
	snapshot, err := catalog.Load(catalogPath)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	result := planner.Create(request, inventory, snapshot)
	if !result.Report.Valid {
		t.Fatalf("create plan: %#v", result.Report.Diagnostics)
	}
	data, err := yaml.Marshal(result.Plan)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	planPath := filepath.Join(directory, "plan.yaml")
	if err := os.WriteFile(planPath, data, 0o600); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	return planPath, catalogPath
}
