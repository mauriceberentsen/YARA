package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
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
}
