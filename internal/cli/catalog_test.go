package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

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

func hasCode(items []diagnostics.Diagnostic, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}
