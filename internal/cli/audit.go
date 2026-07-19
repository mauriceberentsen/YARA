package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
)

const maxAuditedInputBytes = 4 << 20

func operationAudit(baseAction, terminalSuffix, outcome string, subjects []audit.Subject, diagnosticCodes []string) ([]byte, error) {
	return operationAuditForTarget(baseAction, terminalSuffix, outcome, "local", subjects, diagnosticCodes)
}

func operationAuditForTarget(baseAction, terminalSuffix, outcome, target string, subjects []audit.Subject, diagnosticCodes []string) ([]byte, error) {
	now := time.Now().UTC()
	correlationID := fmt.Sprintf("operation-%d", now.UnixNano())
	actorID, assurance := localActor()
	baseSpec := audit.Spec{
		CorrelationID:   correlationID,
		Actor:           audit.Actor{ID: actorID, Type: "user", Assurance: assurance},
		Reason:          audit.Reason{Type: "user-request", Reference: "cli"},
		Target:          target,
		DiagnosticCodes: []string{},
	}
	chain := audit.NewChain()
	started, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: correlationID + "-started", OccurredAt: now.Format(time.RFC3339Nano)},
		Spec:     mergeAuditSpec(baseSpec, baseAction+".started", "started", subjects),
	})
	if err != nil {
		return nil, fmt.Errorf("create %s start audit event: %w", baseAction, err)
	}
	terminalSpec := mergeAuditSpec(baseSpec, baseAction+"."+terminalSuffix, outcome, subjects)
	terminalSpec.CausationID = started.Metadata.ID
	terminalSpec.DiagnosticCodes = diagnosticCodes
	terminal, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: correlationID + "-terminal", OccurredAt: now.Format(time.RFC3339Nano)},
		Spec:     terminalSpec,
	})
	if err != nil {
		return nil, fmt.Errorf("create %s terminal audit event: %w", baseAction, err)
	}
	var buffer bytes.Buffer
	if err := audit.EncodeJSONL(&buffer, []audit.Event{started, terminal}); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func persistOperationAudit(path, baseAction, terminalSuffix, outcome string, subjects []audit.Subject, diagnosticCodes []string) error {
	return persistOperationAuditForTarget(path, baseAction, terminalSuffix, outcome, "local", subjects, diagnosticCodes)
}

func persistOperationAuditForTarget(path, baseAction, terminalSuffix, outcome, target string, subjects []audit.Subject, diagnosticCodes []string) error {
	if path == "" {
		return nil
	}
	data, err := operationAuditForTarget(baseAction, terminalSuffix, outcome, target, subjects, diagnosticCodes)
	if err != nil {
		return err
	}
	return writeExclusive(path, data)
}

// attemptedInputSubject identifies the exact bounded input bytes when they can
// be read. If they cannot, it identifies the attempted local reference without
// exposing that reference in the audit record.
func attemptedInputSubject(kind, path string) audit.Subject {
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		data, readErr := io.ReadAll(io.LimitReader(file, maxAuditedInputBytes+1))
		if readErr == nil && len(data) <= maxAuditedInputBytes {
			return audit.Subject{Kind: kind + "Input", Digest: digestBytes(data)}
		}
	}
	reference := []byte(kind + "\x00" + filepath.Clean(path))
	return audit.Subject{Kind: kind + "InputReference", Digest: digestBytes(reference)}
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func localActor() (string, string) {
	current, err := user.Current()
	if err != nil || current.Username == "" {
		return "local:unknown", "unknown-local"
	}
	return "local:" + current.Username, "self-asserted-local"
}
