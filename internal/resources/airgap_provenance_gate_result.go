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

type AirgapProvenanceGateResult struct {
	APIVersion string                             `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                             `json:"kind" yaml:"kind"`
	Metadata   AirgapProvenanceGateResultMetadata `json:"metadata" yaml:"metadata"`
	Spec       AirgapProvenanceGateResultSpec     `json:"spec" yaml:"spec"`
}

type AirgapProvenanceGateResultMetadata struct {
	Name         string `json:"name" yaml:"name"`
	GateResultID string `json:"gateResultId" yaml:"gateResultId"`
}

type AirgapProvenanceGateResultSpec struct {
	RecordedAt         string                         `json:"recordedAt" yaml:"recordedAt"`
	ExpiresAt          string                         `json:"expiresAt" yaml:"expiresAt"`
	PlanID             string                         `json:"planId" yaml:"planId"`
	BundleID           string                         `json:"bundleId" yaml:"bundleId"`
	CatalogDigest      string                         `json:"catalogDigest" yaml:"catalogDigest"`
	Target             TargetIdentity                 `json:"target" yaml:"target"`
	ImportReceiptID    string                         `json:"importReceiptId" yaml:"importReceiptId"`
	TransferReceiptIDs []string                       `json:"transferReceiptIds" yaml:"transferReceiptIds"`
	ScanReceiptIDs     []string                       `json:"scanReceiptIds" yaml:"scanReceiptIds"`
	Gates              []ProvenanceGateEvaluation     `json:"gates" yaml:"gates"`
	Outcome            string                         `json:"outcome" yaml:"outcome"`
	ReasonReference    string                         `json:"reasonReference" yaml:"reasonReference"`
	Signer             AirgapGateResultSignerIdentity `json:"signer" yaml:"signer"`
	Signature          string                         `json:"signature" yaml:"signature"`
	Limitations        []string                       `json:"limitations" yaml:"limitations"`
}

type AirgapGateResultSignerIdentity struct {
	KeyID           string `json:"keyId" yaml:"keyId"`
	Algorithm       string `json:"algorithm" yaml:"algorithm"`
	PublicKeyDigest string `json:"publicKeyDigest" yaml:"publicKeyDigest"`
}

type ProvenanceGateEvaluation struct {
	ID      string `json:"id" yaml:"id"`
	Status  string `json:"status" yaml:"status"`
	Blocker string `json:"blocker,omitempty" yaml:"blocker,omitempty"`
}

func (r AirgapProvenanceGateResult) AssignGateResultID() (AirgapProvenanceGateResult, error) {
	r.Metadata.GateResultID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return AirgapProvenanceGateResult{}, fmt.Errorf("digest airgap provenance gate result: %w", err)
	}
	r.Metadata.GateResultID = digest
	return r, nil
}

func (r AirgapProvenanceGateResult) signingPayload() ([]byte, error) {
	r.Metadata.GateResultID = ""
	r.Spec.Signature = ""
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("canonical airgap gate payload: %w", err)
	}
	return data, nil
}

func (r AirgapProvenanceGateResult) Sign(privateKey ed25519.PrivateKey) (AirgapProvenanceGateResult, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return AirgapProvenanceGateResult{}, fmt.Errorf("Ed25519 private key has invalid size")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	r.Spec.Signer.Algorithm = "Ed25519"
	r.Spec.Signer.PublicKeyDigest = gateResultPublicKeyDigest(publicKey)
	payload, err := r.signingPayload()
	if err != nil {
		return AirgapProvenanceGateResult{}, err
	}
	r.Spec.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	r.Metadata.GateResultID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return AirgapProvenanceGateResult{}, fmt.Errorf("digest airgap provenance gate result: %w", err)
	}
	r.Metadata.GateResultID = digest
	return r, nil
}

func (r AirgapProvenanceGateResult) Verify(publicKey ed25519.PublicKey, at time.Time) error {
	if report := r.Validate(); !report.Valid {
		return fmt.Errorf("air-gap gate result is invalid: %s", report.Diagnostics[0].Code)
	}
	if gateResultPublicKeyDigest(publicKey) != r.Spec.Signer.PublicKeyDigest {
		return fmt.Errorf("trusted public key does not match gate-result signer")
	}
	recorded, _ := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt)
	expires, _ := time.Parse(time.RFC3339Nano, r.Spec.ExpiresAt)
	checkTime := at.UTC()
	if checkTime.Before(recorded) || !checkTime.Before(expires) {
		return fmt.Errorf("air-gap gate result is not valid at the requested time")
	}
	signature, err := base64.StdEncoding.DecodeString(r.Spec.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("air-gap gate result signature is malformed")
	}
	payload, err := r.signingPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("air-gap gate result signature verification failed")
	}
	return nil
}

func gateResultPublicKeyDigest(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r AirgapProvenanceGateResult) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "AirgapProvenanceGateResult", "AGP", Metadata{Name: r.Metadata.Name})
	for path, value := range map[string]string{
		"metadata.gateResultId":       r.Metadata.GateResultID,
		"spec.planId":                 r.Spec.PlanID,
		"spec.bundleId":               r.Spec.BundleID,
		"spec.catalogDigest":          r.Spec.CatalogDigest,
		"spec.target.referenceDigest": r.Spec.Target.ReferenceDigest,
		"spec.importReceiptId":        r.Spec.ImportReceiptID,
		"spec.signer.publicKeyDigest": r.Spec.Signer.PublicKeyDigest,
	} {
		if !sha256DigestPattern.MatchString(value) {
			items = append(items, diagnostics.Error("YARA-AGP-010", "Gate-result bindings must be SHA-256 digests.", path))
		}
	}
	recorded, recordedErr := time.Parse(time.RFC3339Nano, r.Spec.RecordedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, r.Spec.ExpiresAt)
	if recordedErr != nil || expiresErr != nil || !expires.After(recorded) || expires.Sub(recorded) > 15*time.Minute {
		items = append(items, diagnostics.Error("YARA-AGP-011", "Gate-result validity must be a positive RFC3339 interval of at most 15 minutes.", "spec.expiresAt"))
	}
	if r.Spec.Target.Type != "kubernetes" || r.Spec.Target.ServerVersion == "" {
		items = append(items, diagnostics.Error("YARA-AGP-012", "A complete Kubernetes target identity is required.", "spec.target"))
	}
	for index, path := range [][]string{r.Spec.TransferReceiptIDs, r.Spec.ScanReceiptIDs} {
		field := "spec.transferReceiptIds"
		code := "YARA-AGP-013"
		if index == 1 {
			field = "spec.scanReceiptIds"
			code = "YARA-AGP-014"
		}
		if len(path) == 0 || !slices.IsSorted(path) || hasDuplicateStrings(path) {
			items = append(items, diagnostics.Error(code, "Gate result receipt IDs must be non-empty, unique and sorted.", field))
		}
		for receiptIndex, value := range path {
			if !sha256DigestPattern.MatchString(value) {
				items = append(items, diagnostics.Error(code, "Gate result receipt IDs must be SHA-256 digests.", fmt.Sprintf("%s[%d]", field, receiptIndex)))
			}
		}
	}
	if len(r.Spec.Gates) == 0 {
		items = append(items, diagnostics.Error("YARA-AGP-015", "At least one provenance gate evaluation is required.", "spec.gates"))
	}
	previousGateID := ""
	derived := "passed"
	for index, gate := range r.Spec.Gates {
		path := fmt.Sprintf("spec.gates[%d]", index)
		if gate.ID == "" || gate.ID <= previousGateID || !slices.Contains([]string{"passed", "failed", "blocked"}, gate.Status) {
			items = append(items, diagnostics.Error("YARA-AGP-016", "Gate evaluations must be complete, unique and sorted.", path))
		}
		if gate.Status != "passed" {
			if gate.Blocker == "" {
				items = append(items, diagnostics.Error("YARA-AGP-017", "Non-passing gates require a blocker reference.", path+".blocker"))
			}
			if derived == "passed" {
				derived = gate.Status
			}
		}
		previousGateID = gate.ID
	}
	if !slices.Contains([]string{"passed", "failed", "blocked"}, r.Spec.Outcome) || r.Spec.Outcome != derived {
		items = append(items, diagnostics.Error("YARA-AGP-018", "Outcome must match derived gate statuses.", "spec.outcome"))
	}
	if r.Spec.ReasonReference == "" {
		items = append(items, diagnostics.Error("YARA-AGP-019", "A non-secret reason reference is required.", "spec.reasonReference"))
	}
	if r.Spec.Signer.KeyID == "" || r.Spec.Signer.Algorithm != "Ed25519" {
		items = append(items, diagnostics.Error("YARA-AGP-022", "A named Ed25519 signer is required.", "spec.signer"))
	}
	signature, signatureErr := base64.StdEncoding.DecodeString(r.Spec.Signature)
	if signatureErr != nil || len(signature) != ed25519.SignatureSize {
		items = append(items, diagnostics.Error("YARA-AGP-023", "A base64-encoded Ed25519 signature is required.", "spec.signature"))
	}
	if len(r.Spec.Limitations) == 0 || !slices.IsSorted(r.Spec.Limitations) || hasDuplicateStrings(r.Spec.Limitations) {
		items = append(items, diagnostics.Error("YARA-AGP-020", "At least one unique, sorted limitation is required.", "spec.limitations"))
	}
	if r.Metadata.GateResultID != "" {
		claimed := r.Metadata.GateResultID
		recomputed, err := r.AssignGateResultID()
		if err != nil {
			items = append(items, diagnostics.Error("YARA-AGP-500", "Could not recompute airgap-provenance-gate-result identity."))
		} else if recomputed.Metadata.GateResultID != claimed {
			items = append(items, diagnostics.Error("YARA-AGP-021", "Gate result contents do not match metadata.gateResultId.", "metadata.gateResultId"))
		}
	}
	return diagnostics.NewReport(items...)
}
