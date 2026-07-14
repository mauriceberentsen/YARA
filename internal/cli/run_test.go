package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/audit"
)

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"version"}, &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("expected success, got %d: %s", exitCode, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "0.1.0-dev" {
		t.Fatalf("unexpected version output: %q", stdout.String())
	}
}

func TestValidateExampleRequest(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "examples", "platform-request.yaml")
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"request", "validate", path}, &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("expected success, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"valid": true`) || !strings.Contains(stdout.String(), `"name": "private-coding-assistant"`) {
		t.Fatalf("unexpected validation output: %s", stdout.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"model", "validate", "model.yaml"}, &stdout, &stderr)
	if exitCode != ExitUnsupported {
		t.Fatalf("expected unsupported exit code, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("expected usage on stderr, got %q", stderr.String())
	}
}

func TestVerifyAudit(t *testing.T) {
	chain := audit.NewChain()
	event, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: "event-1", OccurredAt: "2026-07-14T10:00:00Z"},
		Spec: audit.Spec{
			CorrelationID:   "run-1",
			Actor:           audit.Actor{ID: "local:test", Type: "user", Assurance: "self-asserted-local"},
			Action:          "plan.create.completed",
			Subjects:        []audit.Subject{{Kind: "PlatformRequest", Digest: "sha256:test"}},
			Reason:          audit.Reason{Type: "test", Reference: "unit"},
			Target:          "local",
			Outcome:         "success",
			DiagnosticCodes: []string{},
		},
	})
	if err != nil {
		t.Fatalf("append event: %v", err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create audit file: %v", err)
	}
	if err := audit.EncodeJSONL(file, []audit.Event{event}); err != nil {
		t.Fatalf("encode audit file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close audit file: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"audit", "verify", path}, &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("expected success, got %d: %s", exitCode, stdout.String())
	}
	var result auditVerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.Valid || result.Events != 1 || result.HeadDigest == "" {
		t.Fatalf("unexpected result: %#v", result)
	}
}
