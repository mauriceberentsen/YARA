package resources

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type AirgapGateTrustPolicy struct {
	APIVersion string                        `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                        `json:"kind" yaml:"kind"`
	Metadata   AirgapGateTrustPolicyMetadata `json:"metadata" yaml:"metadata"`
	Spec       AirgapGateTrustPolicySpec     `json:"spec" yaml:"spec"`
}

type AirgapGateTrustPolicyMetadata struct {
	Name     string `json:"name" yaml:"name"`
	PolicyID string `json:"policyId" yaml:"policyId"`
}

type AirgapGateTrustPolicySpec struct {
	RecordedAt              string                        `json:"recordedAt" yaml:"recordedAt"`
	TargetReferenceDigest   string                        `json:"targetReferenceDigest" yaml:"targetReferenceDigest"`
	TrustedSignerIdentities []AirgapTrustedSignerIdentity `json:"trustedSignerIdentities" yaml:"trustedSignerIdentities"`
	Limitations             []string                      `json:"limitations" yaml:"limitations"`
}

type AirgapTrustedSignerIdentity struct {
	KeyID           string `json:"keyId" yaml:"keyId"`
	Algorithm       string `json:"algorithm" yaml:"algorithm"`
	PublicKey       string `json:"publicKey" yaml:"publicKey"`
	PublicKeyDigest string `json:"publicKeyDigest" yaml:"publicKeyDigest"`
	ValidFrom       string `json:"validFrom,omitempty" yaml:"validFrom,omitempty"`
	ValidUntil      string `json:"validUntil,omitempty" yaml:"validUntil,omitempty"`
	Status          string `json:"status" yaml:"status"`
}

func (r AirgapGateTrustPolicy) AssignPolicyID() (AirgapGateTrustPolicy, error) {
	r.Metadata.PolicyID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return AirgapGateTrustPolicy{}, fmt.Errorf("digest airgap gate trust policy: %w", err)
	}
	r.Metadata.PolicyID = digest
	return r, nil
}

func (r AirgapGateTrustPolicy) VerifyGateResult(result AirgapProvenanceGateResult, at time.Time) error {
	if report := r.Validate(); !report.Valid {
		return fmt.Errorf("air-gap gate trust policy is invalid: %s", report.Diagnostics[0].Code)
	}
	if result.Spec.Target.ReferenceDigest != r.Spec.TargetReferenceDigest {
		return fmt.Errorf("gate result target does not match trust policy target")
	}
	if report := result.Validate(); !report.Valid {
		return fmt.Errorf("air-gap gate result is invalid: %s", report.Diagnostics[0].Code)
	}
	signerIndex := slices.IndexFunc(r.Spec.TrustedSignerIdentities, func(identity AirgapTrustedSignerIdentity) bool {
		return identity.KeyID == result.Spec.Signer.KeyID && identity.PublicKeyDigest == result.Spec.Signer.PublicKeyDigest
	})
	if signerIndex < 0 {
		return fmt.Errorf("gate signer identity is not trusted by policy")
	}
	signer := r.Spec.TrustedSignerIdentities[signerIndex]
	if signer.Status != "active" {
		return fmt.Errorf("gate signer identity is not active")
	}
	checkTime := at.UTC()
	if signer.ValidFrom != "" {
		validFrom, _ := time.Parse(time.RFC3339Nano, signer.ValidFrom)
		if checkTime.Before(validFrom) {
			return fmt.Errorf("gate signer identity is not yet valid")
		}
	}
	if signer.ValidUntil != "" {
		validUntil, _ := time.Parse(time.RFC3339Nano, signer.ValidUntil)
		if !checkTime.Before(validUntil) {
			return fmt.Errorf("gate signer identity validity has expired")
		}
	}
	decodedKey, err := base64.StdEncoding.DecodeString(signer.PublicKey)
	if err != nil || len(decodedKey) != ed25519.PublicKeySize {
		return fmt.Errorf("gate signer public key is malformed")
	}
	return result.Verify(ed25519.PublicKey(decodedKey), checkTime)
}

func (r AirgapGateTrustPolicy) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "AirgapGateTrustPolicy", "AGT", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.policyId":          r.Metadata.PolicyID,
		"spec.targetReferenceDigest": r.Spec.TargetReferenceDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-AGT-010", "Trust-policy digests must be SHA-256 identities.", path))
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-AGT-011", "Trust policy recordedAt must be a valid RFC3339 timestamp.", "spec.recordedAt"))
	}
	if len(r.Spec.TrustedSignerIdentities) == 0 {
		items = append(items, diagnostics.Error("YARA-AGT-012", "At least one trusted signer identity is required.", "spec.trustedSignerIdentities"))
	}
	previousSigner := ""
	activeCount := 0
	for index, signer := range r.Spec.TrustedSignerIdentities {
		path := fmt.Sprintf("spec.trustedSignerIdentities[%d]", index)
		identityKey := signer.KeyID + "|" + signer.PublicKeyDigest
		if signer.KeyID == "" || signer.Algorithm != "Ed25519" || !sha256DigestPattern.MatchString(signer.PublicKeyDigest) || identityKey <= previousSigner {
			items = append(items, diagnostics.Error("YARA-AGT-013", "Trusted signer identities must be complete, unique and sorted.", path))
		}
		if signer.Status != "active" && signer.Status != "revoked" {
			items = append(items, diagnostics.Error("YARA-AGT-014", "Trusted signer status must be active or revoked.", path+".status"))
		}
		if signer.Status == "active" {
			activeCount++
		}
		decodedKey, err := base64.StdEncoding.DecodeString(signer.PublicKey)
		if err != nil || len(decodedKey) != ed25519.PublicKeySize {
			items = append(items, diagnostics.Error("YARA-AGT-015", "Trusted signer public key must be base64-encoded Ed25519 bytes.", path+".publicKey"))
		} else if gateResultPublicKeyDigest(ed25519.PublicKey(decodedKey)) != signer.PublicKeyDigest {
			items = append(items, diagnostics.Error("YARA-AGT-016", "Trusted signer public key digest does not match publicKeyDigest.", path+".publicKeyDigest"))
		}
		validFrom := time.Time{}
		validUntil := time.Time{}
		if signer.ValidFrom != "" {
			parsed, err := time.Parse(time.RFC3339Nano, signer.ValidFrom)
			if err != nil {
				items = append(items, diagnostics.Error("YARA-AGT-017", "Trusted signer validFrom must be RFC3339 when present.", path+".validFrom"))
			}
			validFrom = parsed
		}
		if signer.ValidUntil != "" {
			parsed, err := time.Parse(time.RFC3339Nano, signer.ValidUntil)
			if err != nil {
				items = append(items, diagnostics.Error("YARA-AGT-018", "Trusted signer validUntil must be RFC3339 when present.", path+".validUntil"))
			}
			validUntil = parsed
		}
		if !validFrom.IsZero() && !validUntil.IsZero() && !validUntil.After(validFrom) {
			items = append(items, diagnostics.Error("YARA-AGT-019", "Trusted signer validity bounds must be a positive interval.", path+".validUntil"))
		}
		previousSigner = identityKey
	}
	if activeCount == 0 {
		items = append(items, diagnostics.Error("YARA-AGT-020", "Trust policy must contain at least one active signer identity.", "spec.trustedSignerIdentities"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-AGT-021", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.PolicyID != "" {
		claimed := r.Metadata.PolicyID
		recomputed, err := r.AssignPolicyID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-AGT-500", "Could not recompute air-gap gate trust-policy identity."))
		} else if recomputed.Metadata.PolicyID != claimed {
			items = append(items, diagnostics.Error("YARA-AGT-022", "Trust policy contents do not match metadata.policyId.", "metadata.policyId"))
		}
	}
	return diagnostics.NewReport(items...)
}
