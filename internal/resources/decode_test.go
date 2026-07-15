package resources

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadExamplePlatformRequest(t *testing.T) {
	request, err := LoadPlatformRequest(filepath.Join("..", "..", "docs", "examples", "platform-request.yaml"))
	if err != nil {
		t.Fatalf("load request: %v", err)
	}
	if report := request.Validate(); !report.Valid {
		t.Fatalf("expected request to be valid, got %#v", report.Diagnostics)
	}
}

func TestLoadExampleInventory(t *testing.T) {
	inventory, err := LoadInventory(filepath.Join("..", "..", "docs", "examples", "inventory.yaml"))
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	if report := inventory.Validate(); !report.Valid {
		t.Fatalf("expected inventory to be valid, got %#v", report.Diagnostics)
	}
}

func TestLoadExamplePlatformPlan(t *testing.T) {
	plan, err := LoadPlatformPlan(filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml"))
	if err != nil {
		t.Fatalf("load plan: %v", err)
	}
	if report := plan.Validate(); !report.Valid {
		t.Fatalf("expected plan to be valid, got %#v", report.Diagnostics)
	}
}

func TestLoadExampleDebugBundle(t *testing.T) {
	bundle, err := LoadDebugBundle(filepath.Join("..", "..", "docs", "examples", "debug-bundle.json"))
	if err != nil {
		t.Fatalf("load debug bundle: %v", err)
	}
	if report := bundle.Validate(); !report.Valid {
		t.Fatalf("expected debug bundle to be valid, got %#v", report.Diagnostics)
	}
}

func TestLoadGoldenScenario(t *testing.T) {
	golden, err := LoadGoldenScenario(filepath.Join("..", "..", "scenarios", "v0.1", "private-chat-coding", "scenario.yaml"))
	if err != nil {
		t.Fatalf("load golden scenario: %v", err)
	}
	if report := golden.Validate(); !report.Valid {
		t.Fatalf("expected golden scenario to be valid, got %#v", report.Diagnostics)
	}
}

func TestLoadRejectsUnknownYAMLField(t *testing.T) {
	path := writeTempResource(t, `
apiVersion: yara.dev/v1alpha1
kind: PlatformRequest
metadata:
  name: test
unexpected: true
spec: {}
`)
	_, err := LoadPlatformRequest(path)
	if err == nil || !strings.Contains(err.Error(), "field unexpected not found") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestLoadRejectsUnknownJSONField(t *testing.T) {
	path := writeTempResource(t, `{"apiVersion":"yara.dev/v1alpha1","kind":"Inventory","metadata":{"name":"test"},"spec":{},"unexpected":true}`)
	_, err := LoadInventory(path)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestLoadRejectsMultipleYAMLDocuments(t *testing.T) {
	path := writeTempResource(t, "apiVersion: yara.dev/v1alpha1\nkind: Inventory\nmetadata: {name: test}\nspec: {}\n---\n{}\n")
	_, err := LoadInventory(path)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected multiple document error, got %v", err)
	}
}

func TestLoadRejectsOversizedResource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.yaml")
	data := make([]byte, maxResourceBytes+1)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write oversized resource: %v", err)
	}
	_, err := LoadInventory(path)
	if !errors.Is(err, ErrResourceTooLarge) {
		t.Fatalf("expected ErrResourceTooLarge, got %v", err)
	}
}

func writeTempResource(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resource.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write resource: %v", err)
	}
	return path
}
