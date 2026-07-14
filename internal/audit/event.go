// Package audit implements the local append-only evidence primitives used by
// YARA commands. Audit records contain resource identities, never resource
// bodies or secret values.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mauriceberentsen/YARA/internal/canonical"
)

const (
	APIVersion = "yara.dev/v1alpha1"
	Kind       = "AuditEvent"
)

type Event struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}

type Metadata struct {
	ID         string `json:"id" yaml:"id"`
	OccurredAt string `json:"occurredAt" yaml:"occurredAt"`
}

type Spec struct {
	Sequence        uint64    `json:"sequence" yaml:"sequence"`
	CorrelationID   string    `json:"correlationId" yaml:"correlationId"`
	CausationID     string    `json:"causationId,omitempty" yaml:"causationId,omitempty"`
	Actor           Actor     `json:"actor" yaml:"actor"`
	Action          string    `json:"action" yaml:"action"`
	Subjects        []Subject `json:"subjects" yaml:"subjects"`
	Reason          Reason    `json:"reason" yaml:"reason"`
	PolicyDigest    string    `json:"policyDigest,omitempty" yaml:"policyDigest,omitempty"`
	Target          string    `json:"target" yaml:"target"`
	Outcome         string    `json:"outcome" yaml:"outcome"`
	DiagnosticCodes []string  `json:"diagnosticCodes" yaml:"diagnosticCodes"`
	Integrity       Integrity `json:"integrity" yaml:"integrity"`
}

type Actor struct {
	ID        string `json:"id" yaml:"id"`
	Type      string `json:"type" yaml:"type"`
	Assurance string `json:"assurance" yaml:"assurance"`
}

type Subject struct {
	Kind   string `json:"kind" yaml:"kind"`
	Digest string `json:"digest" yaml:"digest"`
}

type Reason struct {
	Type      string `json:"type" yaml:"type"`
	Reference string `json:"reference" yaml:"reference"`
}

type Integrity struct {
	PreviousEventDigest string `json:"previousEventDigest,omitempty" yaml:"previousEventDigest,omitempty"`
	EventDigest         string `json:"eventDigest" yaml:"eventDigest"`
}

type Chain struct {
	nextSequence uint64
	headDigest   string
}

func NewChain() *Chain {
	return &Chain{nextSequence: 1}
}

func (c *Chain) Append(event Event) (Event, error) {
	if event.APIVersion == "" {
		event.APIVersion = APIVersion
	}
	if event.Kind == "" {
		event.Kind = Kind
	}
	event.Spec.Sequence = c.nextSequence
	event.Spec.Integrity.PreviousEventDigest = c.headDigest
	event.Spec.Integrity.EventDigest = ""
	digest, err := digestEvent(event)
	if err != nil {
		return Event{}, err
	}
	event.Spec.Integrity.EventDigest = digest
	c.nextSequence++
	c.headDigest = digest
	return event, nil
}

func Verify(events []Event) (string, error) {
	previous := ""
	for index, event := range events {
		expectedSequence := uint64(index + 1)
		if event.APIVersion != APIVersion || event.Kind != Kind {
			return "", fmt.Errorf("event %d has unsupported resource envelope", index)
		}
		if event.Spec.Sequence != expectedSequence {
			return "", fmt.Errorf("event %d has sequence %d; expected %d", index, event.Spec.Sequence, expectedSequence)
		}
		if event.Spec.Integrity.PreviousEventDigest != previous {
			return "", fmt.Errorf("event %d does not reference the previous event digest", index)
		}
		claimed := event.Spec.Integrity.EventDigest
		event.Spec.Integrity.EventDigest = ""
		actual, err := digestEvent(event)
		if err != nil {
			return "", err
		}
		if claimed != actual {
			return "", fmt.Errorf("event %d digest mismatch", index)
		}
		previous = claimed
	}
	return previous, nil
}

func EncodeJSONL(writer io.Writer, events []Event) error {
	encoder := json.NewEncoder(writer)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("encode audit event: %w", err)
		}
	}
	return nil
}

func LoadJSONL(path string) ([]Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(bufio.NewReader(file))
	decoder.DisallowUnknownFields()
	events := make([]Event, 0)
	for {
		var event Event
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode audit event %d: %w", len(events), err)
		}
		events = append(events, event)
		if len(events) > 100_000 {
			return nil, errors.New("audit file exceeds the 100000 event verification limit")
		}
	}
	if len(events) == 0 {
		return nil, errors.New("audit file contains no events")
	}
	return events, nil
}

func digestEvent(event Event) (string, error) {
	digest, err := canonical.Digest(event)
	if err != nil {
		return "", fmt.Errorf("digest audit event: %w", err)
	}
	return digest, nil
}
