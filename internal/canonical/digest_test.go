package canonical

import "testing"

func TestDigestIsIndependentOfMapInsertionOrder(t *testing.T) {
	first := map[string]any{"b": 2, "a": 1}
	second := map[string]any{"a": 1, "b": 2}
	firstDigest, err := Digest(first)
	if err != nil {
		t.Fatalf("digest first value: %v", err)
	}
	secondDigest, err := Digest(second)
	if err != nil {
		t.Fatalf("digest second value: %v", err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("expected identical digests, got %s and %s", firstDigest, secondDigest)
	}
}
