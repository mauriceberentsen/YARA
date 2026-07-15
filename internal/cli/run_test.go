package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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

func TestValidateRequestWritesFailureAudit(t *testing.T) {
	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "docs", "examples", "platform-request.yaml"))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	data = bytes.Replace(data, []byte("expectedUsers: 25"), []byte("expectedUsers: 0"), 1)
	temp := t.TempDir()
	requestPath := filepath.Join(temp, "request.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	if err := os.WriteFile(requestPath, data, 0o600); err != nil {
		t.Fatalf("write request: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"request", "validate", requestPath, "--audit-output", auditPath}, &stdout, &stderr)
	if exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: stdout=%s stderr=%s", exitCode, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load validation audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify validation audit: %v", err)
	}
	if len(events) != 2 || events[0].Spec.Action != "request.validate.started" || events[1].Spec.Action != "request.validate.failed" {
		t.Fatalf("unexpected validation events: %#v", events)
	}
	if events[1].Spec.Outcome != "failed" || !slices.Contains(events[1].Spec.DiagnosticCodes, "YARA-REQ-020") {
		t.Fatalf("failure audit omits validation diagnostic: %#v", events[1].Spec)
	}
	if len(events[1].Spec.Subjects) != 1 || events[1].Spec.Subjects[0].Kind != "PlatformRequest" {
		t.Fatalf("failure audit omits request identity: %#v", events[1].Spec.Subjects)
	}
}

func TestValidateMissingRequestWritesAttemptAudit(t *testing.T) {
	temp := t.TempDir()
	requestPath := filepath.Join(temp, "missing.yaml")
	auditPath := filepath.Join(temp, "audit.jsonl")
	var stdout, stderr bytes.Buffer
	exitCode := Run([]string{"request", "validate", requestPath, "--audit-output", auditPath}, &stdout, &stderr)
	if exitCode != ExitInvalidInput {
		t.Fatalf("expected invalid input, got %d: %s", exitCode, stdout.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatalf("load failure audit: %v", err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatalf("verify failure audit: %v", err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "request.validate.failed" || !slices.Contains(terminal.Spec.DiagnosticCodes, "YARA-REQ-004") {
		t.Fatalf("unexpected terminal event: %#v", terminal.Spec)
	}
	if len(terminal.Spec.Subjects) != 1 || terminal.Spec.Subjects[0].Kind != "PlatformRequestInputReference" {
		t.Fatalf("missing input reference subject: %#v", terminal.Spec.Subjects)
	}
	if strings.Contains(string(mustReadFile(t, auditPath)), requestPath) {
		t.Fatal("audit output must not expose the local input path")
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

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
