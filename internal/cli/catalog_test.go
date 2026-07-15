package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

func TestCatalogValidateReportsCompiledSnapshot(t *testing.T) {
	path := filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"catalog", "validate", path}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("catalog validate failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	var result catalogValidationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.Valid || result.Candidates != 2 || result.Digest == "" {
		t.Fatalf("unexpected validation result: %#v", result)
	}
	if !hasCode(result.Diagnostics, "YARA-CAT-040") || !hasCode(result.Diagnostics, "YARA-CAT-055") {
		t.Fatalf("expected catalog quarantine warning: %#v", result.Diagnostics)
	}
}

func TestCatalogValidateWritesAuditWithGovernanceDiagnostics(t *testing.T) {
	path := filepath.Join("..", "..", "catalog", "v0.1", "snapshot.yaml")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	var stdout, stderr bytes.Buffer
	if exitCode := Run([]string{"catalog", "validate", path, "--audit-output", auditPath}, &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("catalog validate failed with %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "catalog.validate.completed" || terminal.Spec.Outcome != "success" {
		t.Fatalf("unexpected terminal event: %#v", terminal.Spec)
	}
	if !containsString(terminal.Spec.DiagnosticCodes, "YARA-CAT-040") || !containsString(terminal.Spec.DiagnosticCodes, "YARA-CAT-055") {
		t.Fatalf("audit omits governance diagnostics: %#v", terminal.Spec.DiagnosticCodes)
	}
}

func hasCode(items []diagnostics.Diagnostic, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
