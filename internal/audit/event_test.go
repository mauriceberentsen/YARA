package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestChainDetectsTampering(t *testing.T) {
	chain := NewChain()
	first, err := chain.Append(testEvent("plan.create.started", "started"))
	if err != nil {
		t.Fatalf("append first event: %v", err)
	}
	second, err := chain.Append(testEvent("plan.create.completed", "success"))
	if err != nil {
		t.Fatalf("append second event: %v", err)
	}
	events := []Event{first, second}
	head, err := Verify(events)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if head != second.Spec.Integrity.EventDigest {
		t.Fatalf("unexpected head digest: %s", head)
	}

	events[0].Spec.Action = "plan.create.failed"
	if _, err := Verify(events); err == nil {
		t.Fatal("expected tampered chain verification to fail")
	}
}

func TestJSONLRoundTrip(t *testing.T) {
	chain := NewChain()
	event, err := chain.Append(testEvent("plan.create.completed", "success"))
	if err != nil {
		t.Fatalf("append event: %v", err)
	}
	var buffer bytes.Buffer
	if err := EncodeJSONL(&buffer, []Event{event}); err != nil {
		t.Fatalf("encode JSONL: %v", err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("write JSONL: %v", err)
	}
	loaded, err := LoadJSONL(path)
	if err != nil {
		t.Fatalf("load JSONL: %v", err)
	}
	if _, err := Verify(loaded); err != nil {
		t.Fatalf("verify loaded chain: %v", err)
	}
}

func testEvent(action, outcome string) Event {
	return Event{
		Metadata: Metadata{ID: action, OccurredAt: "2026-07-14T10:00:00Z"},
		Spec: Spec{
			CorrelationID:   "planning-run",
			Actor:           Actor{ID: "local:operator", Type: "user", Assurance: "self-asserted-local"},
			Action:          action,
			Subjects:        []Subject{{Kind: "PlatformRequest", Digest: "sha256:request"}},
			Reason:          Reason{Type: "user-request", Reference: "cli"},
			Target:          "local",
			Outcome:         outcome,
			DiagnosticCodes: []string{},
		},
	}
}
