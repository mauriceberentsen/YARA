// Package canonical provides deterministic serialization primitives used for
// content identities. Its behavior is intentionally small until public test
// vectors define the complete cross-language canonicalization contract.
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Digest returns a SHA-256 content identity for JSON-compatible typed data.
// encoding/json provides stable struct field order and sorted string map keys.
func Digest(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonical JSON: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
