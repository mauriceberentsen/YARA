package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	authkeys "github.com/mauriceberentsen/YARA/internal/authorization"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type airgapTrustPolicyRecordOptions struct {
	targetReferenceDigest string
	name, outputPath      string
	auditPath             string
	signerInputs          csvFlag
}

func recordAirgapGateTrustPolicy(args []string, stdout, stderr io.Writer) int {
	options, ok := parseAirgapTrustPolicyRecordOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	signers := make([]resources.AirgapTrustedSignerIdentity, 0, len(options.signerInputs))
	for _, input := range options.signerInputs {
		signer, err := parseAirgapTrustedSignerInput(input)
		if err != nil {
			return writeLoadErrorWithExit(stdout, "YARA-AGT-101", err, ExitInvalidInput)
		}
		signers = append(signers, signer)
	}
	slices.SortFunc(signers, func(left, right resources.AirgapTrustedSignerIdentity) int {
		if left.KeyID < right.KeyID {
			return -1
		}
		if left.KeyID > right.KeyID {
			return 1
		}
		return compareStrings(left.PublicKeyDigest, right.PublicKeyDigest)
	})
	policy := resources.AirgapGateTrustPolicy{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicy",
		Metadata: resources.AirgapGateTrustPolicyMetadata{
			Name: options.name,
		},
		Spec: resources.AirgapGateTrustPolicySpec{
			RecordedAt:              time.Now().UTC().Format(time.RFC3339Nano),
			TargetReferenceDigest:   options.targetReferenceDigest,
			TrustedSignerIdentities: signers,
			Limitations: []string{
				"Trust policy records only non-secret signer identity and key digest metadata.",
				"Trust policy does not mutate deployment, approval or authorization resources.",
			},
		},
	}
	slices.Sort(policy.Spec.Limitations)
	policy, err := policy.AssignPolicyID()
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGT-500", err, ExitInternal)
	}
	if report := policy.Validate(); !report.Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AGT-500", errors.New("constructed air-gap gate trust policy is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(policy)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGT-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGT-102", err, ExitInvalidInput)
	}
	subjects := []audit.Subject{{Kind: "AirgapGateTrustPolicy", Digest: policy.Metadata.PolicyID}}
	target := "kubernetes:" + policy.Spec.TargetReferenceDigest
	if err := persistOperationAuditForTarget(options.auditPath, "airgap.gate-trust-policy.record", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":                 true,
		"policyId":              policy.Metadata.PolicyID,
		"trustedSignerCount":    len(policy.Spec.TrustedSignerIdentities),
		"targetReferenceDigest": policy.Spec.TargetReferenceDigest,
		"output":                options.outputPath,
		"auditOutput":           options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseAirgapTrustPolicyRecordOptions(args []string, stderr io.Writer) (airgapTrustPolicyRecordOptions, bool) {
	var options airgapTrustPolicyRecordOptions
	flags := flag.NewFlagSet("airgap gate-trust-policy record", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.targetReferenceDigest, "target-reference-digest", "", "Pseudonymized target reference digest (sha256:...)")
	flags.Var(&options.signerInputs, "signer", "Signer input key-id=<id>,public-key=<pem>,status=<active|revoked>[,valid-from=<RFC3339>][,valid-until=<RFC3339>]")
	flags.StringVar(&options.name, "name", "", "AirgapGateTrustPolicy name")
	flags.StringVar(&options.outputPath, "output", "", "Generated AirgapGateTrustPolicy YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated trust-policy audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.targetReferenceDigest == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" || len(options.signerInputs) == 0 {
		fmt.Fprintln(stderr, "airgap gate-trust-policy record requires --target-reference-digest --signer --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	if !strings.HasPrefix(options.targetReferenceDigest, "sha256:") || len(options.targetReferenceDigest) != 71 {
		fmt.Fprintln(stderr, "--target-reference-digest must be a SHA-256 digest")
		return options, false
	}
	return options, true
}

func parseAirgapTrustedSignerInput(value string) (resources.AirgapTrustedSignerIdentity, error) {
	parts := strings.Split(value, ",")
	fields := map[string]string{}
	for _, raw := range parts {
		item := strings.TrimSpace(raw)
		key, fieldValue, ok := strings.Cut(item, "=")
		if !ok || key == "" || fieldValue == "" {
			return resources.AirgapTrustedSignerIdentity{}, errors.New("signer values must use key=value fields")
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(fieldValue)
	}
	keyID := fields["key-id"]
	publicKeyPath := fields["public-key"]
	status := fields["status"]
	if keyID == "" || publicKeyPath == "" || status == "" {
		return resources.AirgapTrustedSignerIdentity{}, errors.New("signer requires key-id, public-key and status fields")
	}
	if status != "active" && status != "revoked" {
		return resources.AirgapTrustedSignerIdentity{}, errors.New("signer status must be active or revoked")
	}
	publicKey, err := authkeys.LoadPublicKey(publicKeyPath)
	if err != nil {
		return resources.AirgapTrustedSignerIdentity{}, fmt.Errorf("load signer public key: %w", err)
	}
	signer := resources.AirgapTrustedSignerIdentity{
		KeyID:           keyID,
		Algorithm:       "Ed25519",
		PublicKey:       base64.StdEncoding.EncodeToString(publicKey),
		PublicKeyDigest: resources.PublicKeyDigest(publicKey),
		Status:          status,
	}
	if validFrom := fields["valid-from"]; validFrom != "" {
		if _, err := time.Parse(time.RFC3339Nano, validFrom); err != nil {
			return resources.AirgapTrustedSignerIdentity{}, errors.New("signer valid-from must be RFC3339")
		}
		signer.ValidFrom = validFrom
	}
	if validUntil := fields["valid-until"]; validUntil != "" {
		if _, err := time.Parse(time.RFC3339Nano, validUntil); err != nil {
			return resources.AirgapTrustedSignerIdentity{}, errors.New("signer valid-until must be RFC3339")
		}
		signer.ValidUntil = validUntil
	}
	return signer, nil
}
