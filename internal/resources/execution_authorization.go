package resources

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

// ExecutionAuthorization is a short-lived Ed25519-signed capability over one
// exact reviewed target operation set. Structural validity is never sufficient;
// consumers must also call Verify with an explicitly trusted public key.
type ExecutionAuthorization struct {
	APIVersion string                         `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                         `json:"kind" yaml:"kind"`
	Metadata   ExecutionAuthorizationMetadata `json:"metadata" yaml:"metadata"`
	Spec       ExecutionAuthorizationSpec     `json:"spec" yaml:"spec"`
}

type ExecutionAuthorizationMetadata struct {
	Name            string `json:"name" yaml:"name"`
	AuthorizationID string `json:"authorizationId" yaml:"authorizationId"`
}

type ExecutionAuthorizationSpec struct {
	IssuedAt          string                            `json:"issuedAt" yaml:"issuedAt"`
	ExpiresAt         string                            `json:"expiresAt" yaml:"expiresAt"`
	PlanID            string                            `json:"planId" yaml:"planId"`
	BundleID          string                            `json:"bundleId" yaml:"bundleId"`
	PreflightResultID string                            `json:"preflightResultId" yaml:"preflightResultId"`
	ChangeSetID       string                            `json:"changeSetId" yaml:"changeSetId"`
	ApprovalID        string                            `json:"approvalId" yaml:"approvalId"`
	Target            TargetIdentity                    `json:"target" yaml:"target"`
	Issuer            ExecutionAuthorizationIssuer      `json:"issuer" yaml:"issuer"`
	Constraints       ExecutionAuthorizationConstraints `json:"constraints" yaml:"constraints"`
	Signature         string                            `json:"signature" yaml:"signature"`
}

type ExecutionAuthorizationIssuer struct {
	KeyID           string `json:"keyId" yaml:"keyId"`
	Algorithm       string `json:"algorithm" yaml:"algorithm"`
	PublicKeyDigest string `json:"publicKeyDigest" yaml:"publicKeyDigest"`
}

type ExecutionAuthorizationConstraints struct {
	AllowedActions            []string `json:"allowedActions" yaml:"allowedActions"`
	MaxOperations             int      `json:"maxOperations" yaml:"maxOperations"`
	AllowDelete               bool     `json:"allowDelete" yaml:"allowDelete"`
	AllowActiveVerification   bool     `json:"allowActiveVerification" yaml:"allowActiveVerification"`
	AcceptedPreflightBlockers []string `json:"acceptedPreflightBlockers" yaml:"acceptedPreflightBlockers"`
}

func (r ExecutionAuthorization) signingPayload() ([]byte, error) {
	r.Metadata.AuthorizationID = ""
	r.Spec.Signature = ""
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("canonical authorization payload: %w", err)
	}
	return data, nil
}

func (r ExecutionAuthorization) Sign(privateKey ed25519.PrivateKey) (ExecutionAuthorization, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return ExecutionAuthorization{}, fmt.Errorf("Ed25519 private key has invalid size")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	r.Spec.Issuer.Algorithm = "Ed25519"
	r.Spec.Issuer.PublicKeyDigest = PublicKeyDigest(publicKey)
	payload, err := r.signingPayload()
	if err != nil {
		return ExecutionAuthorization{}, err
	}
	r.Spec.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	r.Metadata.AuthorizationID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return ExecutionAuthorization{}, fmt.Errorf("digest execution authorization: %w", err)
	}
	r.Metadata.AuthorizationID = digest
	return r, nil
}

func (r ExecutionAuthorization) Verify(publicKey ed25519.PublicKey, at time.Time) error {
	if report := r.Validate(); !report.Valid {
		return fmt.Errorf("authorization is invalid: %s", report.Diagnostics[0].Code)
	}
	if PublicKeyDigest(publicKey) != r.Spec.Issuer.PublicKeyDigest {
		return fmt.Errorf("trusted public key does not match authorization issuer")
	}
	issued, _ := time.Parse(time.RFC3339Nano, r.Spec.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, r.Spec.ExpiresAt)
	checkTime := at.UTC()
	if checkTime.Before(issued) || !checkTime.Before(expires) {
		return fmt.Errorf("authorization is not valid at the requested time")
	}
	signature, err := base64.StdEncoding.DecodeString(r.Spec.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("authorization signature is malformed")
	}
	payload, err := r.signingPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("authorization signature verification failed")
	}
	return nil
}

func PublicKeyDigest(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r ExecutionAuthorization) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "ExecutionAuthorization", "AUT", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.authorizationId": r.Metadata.AuthorizationID, "spec.planId": r.Spec.PlanID, "spec.bundleId": r.Spec.BundleID,
		"spec.preflightResultId": r.Spec.PreflightResultID, "spec.changeSetId": r.Spec.ChangeSetID, "spec.approvalId": r.Spec.ApprovalID,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest, "spec.issuer.publicKeyDigest": r.Spec.Issuer.PublicKeyDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-AUT-010", "Authorization bindings must be SHA-256 digests.", path))
		}
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, r.Spec.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, r.Spec.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || !expires.After(issued) || expires.Sub(issued) > 15*time.Minute {
		items = append(items, diagnostics.Error("YARA-AUT-011", "Authorization validity must be a positive RFC3339 interval of at most 15 minutes.", "spec.expiresAt"))
	}
	if r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" || r.Spec.Issuer.KeyID == "" || r.Spec.Issuer.Algorithm != "Ed25519" {
		items = append(items, diagnostics.Error("YARA-AUT-012", "A Kubernetes target and named Ed25519 issuer are required.", "spec"))
	}
	if len(r.Spec.Constraints.AllowedActions) == 0 || !slices.IsSorted(r.Spec.Constraints.AllowedActions) || hasDuplicateStrings(r.Spec.Constraints.AllowedActions) {
		items = append(items, diagnostics.Error("YARA-AUT-013", "Allowed actions must be non-empty, unique and sorted.", "spec.constraints.allowedActions"))
	}
	for _, action := range r.Spec.Constraints.AllowedActions {
		if !slices.Contains([]string{"create", "no-op", "update", "delete"}, action) {
			items = append(items, diagnostics.Error("YARA-AUT-014", "Authorization action is unsupported.", "spec.constraints.allowedActions"))
		}
	}
	if r.Spec.Constraints.MaxOperations < 1 || r.Spec.Constraints.MaxOperations > 100 {
		items = append(items, diagnostics.Error("YARA-AUT-015", "Authorization requires 1-100 operations.", "spec.constraints.maxOperations"))
	}
	if r.Spec.Constraints.AllowDelete {
		if len(r.Spec.Constraints.AllowedActions) != 1 || r.Spec.Constraints.AllowedActions[0] != "delete" || r.Spec.Constraints.AllowActiveVerification || len(r.Spec.Constraints.AcceptedPreflightBlockers) != 0 {
			items = append(items, diagnostics.Error("YARA-AUT-015", "Delete authorization must be delete-only and cannot accept active verification blockers.", "spec.constraints"))
		}
	} else if slices.Contains(r.Spec.Constraints.AllowedActions, "delete") {
		items = append(items, diagnostics.Error("YARA-AUT-015", "Delete action requires allowDelete=true.", "spec.constraints"))
	}
	if !slices.IsSorted(r.Spec.Constraints.AcceptedPreflightBlockers) || hasDuplicateStrings(r.Spec.Constraints.AcceptedPreflightBlockers) {
		items = append(items, diagnostics.Error("YARA-AUT-016", "Accepted preflight blockers must be unique and sorted.", "spec.constraints.acceptedPreflightBlockers"))
	}
	for _, code := range r.Spec.Constraints.AcceptedPreflightBlockers {
		if !diagnosticCodePattern.MatchString(code) {
			items = append(items, diagnostics.Error("YARA-AUT-016", "Accepted preflight blockers require stable diagnostic codes.", "spec.constraints.acceptedPreflightBlockers"))
		}
	}
	signature, signatureErr := base64.StdEncoding.DecodeString(r.Spec.Signature)
	if signatureErr != nil || len(signature) != ed25519.SignatureSize {
		items = append(items, diagnostics.Error("YARA-AUT-017", "A base64-encoded Ed25519 signature is required.", "spec.signature"))
	}
	if r.Metadata.AuthorizationID != "" {
		claimed := r.Metadata.AuthorizationID
		copy := r
		copy.Metadata.AuthorizationID = ""
		recomputed, err := canonical.Digest(copy)
		if err != nil {
			items = append(items, diagnostics.Error("YARA-AUT-500", "Could not recompute authorization identity."))
		} else if recomputed != claimed {
			items = append(items, diagnostics.Error("YARA-AUT-018", "Authorization contents do not match metadata.authorizationId.", "metadata.authorizationId"))
		}
	}
	return diagnostics.NewReport(items...)
}
