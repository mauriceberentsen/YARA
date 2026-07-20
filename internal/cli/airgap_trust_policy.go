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

type airgapTrustPolicyDiffOptions struct {
	fromPolicyPath string
	toPolicyPath   string
	name           string
	outputPath     string
	auditPath      string
}

type airgapTransitionReviewOptions struct {
	policyDiffPath  string
	decision        string
	reviewerRole    string
	reasonReference string
	name            string
	outputPath      string
	auditPath       string
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

func diffAirgapGateTrustPolicy(args []string, stdout, stderr io.Writer) int {
	options, ok := parseAirgapTrustPolicyDiffOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	fromPolicy, err := resources.LoadAirgapGateTrustPolicy(options.fromPolicyPath)
	if err != nil || !fromPolicy.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AGD-101", errors.New("from trust policy is invalid"), ExitInvalidInput)
	}
	toPolicy, err := resources.LoadAirgapGateTrustPolicy(options.toPolicyPath)
	if err != nil || !toPolicy.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AGD-102", errors.New("to trust policy is invalid"), ExitInvalidInput)
	}
	if fromPolicy.Spec.TargetReferenceDigest != toPolicy.Spec.TargetReferenceDigest {
		return writeLoadErrorWithExit(stdout, "YARA-AGD-103", errors.New("trust-policy diff requires matching targetReferenceDigest"), ExitInvalidInput)
	}
	changes, highestImpact := computeTrustPolicyDiffChanges(fromPolicy, toPolicy)
	if len(changes) == 0 {
		return writeLoadErrorWithExit(stdout, "YARA-AGD-104", errors.New("trust-policy diff requires at least one signer change"), ExitInvalidInput)
	}
	if err := enforceTrustPolicyTransitionSafety(fromPolicy, toPolicy); err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGD-105", err, ExitInfeasible)
	}
	diff := resources.AirgapGateTrustPolicyDiff{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTrustPolicyDiff",
		Metadata: resources.AirgapGateTrustPolicyDiffMetadata{
			Name: options.name,
		},
		Spec: resources.AirgapGateTrustPolicyDiffSpec{
			RecordedAt:            time.Now().UTC().Format(time.RFC3339Nano),
			FromPolicyID:          fromPolicy.Metadata.PolicyID,
			ToPolicyID:            toPolicy.Metadata.PolicyID,
			TargetReferenceDigest: toPolicy.Spec.TargetReferenceDigest,
			HighestImpact:         highestImpact,
			Changes:               changes,
			Limitations: []string{
				"Trust-policy diff includes signer identity and digest metadata only.",
				"Trust-policy diff excludes private keys and secret-bearing payloads.",
			},
		},
	}
	slices.Sort(diff.Spec.Limitations)
	diff, err = diff.AssignDiffID()
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGD-500", err, ExitInternal)
	}
	if report := diff.Validate(); !report.Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AGD-500", errors.New("constructed trust-policy diff is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(diff)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGD-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGD-106", err, ExitInvalidInput)
	}
	subjects := []audit.Subject{
		{Kind: "AirgapGateTrustPolicy", Digest: fromPolicy.Metadata.PolicyID},
		{Kind: "AirgapGateTrustPolicy", Digest: toPolicy.Metadata.PolicyID},
		{Kind: "AirgapGateTrustPolicyDiff", Digest: diff.Metadata.DiffID},
	}
	target := "kubernetes:" + toPolicy.Spec.TargetReferenceDigest
	if err := persistOperationAuditForTarget(options.auditPath, "airgap.gate-trust-policy.diff", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":         true,
		"diffId":        diff.Metadata.DiffID,
		"fromPolicyId":  diff.Spec.FromPolicyID,
		"toPolicyId":    diff.Spec.ToPolicyID,
		"highestImpact": diff.Spec.HighestImpact,
		"output":        options.outputPath,
		"auditOutput":   options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseAirgapTrustPolicyDiffOptions(args []string, stderr io.Writer) (airgapTrustPolicyDiffOptions, bool) {
	var options airgapTrustPolicyDiffOptions
	flags := flag.NewFlagSet("airgap gate-trust-policy diff", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.fromPolicyPath, "from-policy", "", "From AirgapGateTrustPolicy YAML")
	flags.StringVar(&options.toPolicyPath, "to-policy", "", "To AirgapGateTrustPolicy YAML")
	flags.StringVar(&options.name, "name", "", "AirgapGateTrustPolicyDiff name")
	flags.StringVar(&options.outputPath, "output", "", "Generated AirgapGateTrustPolicyDiff YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated trust-policy diff audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.fromPolicyPath == "" || options.toPolicyPath == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "airgap gate-trust-policy diff requires --from-policy --to-policy --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}

func computeTrustPolicyDiffChanges(fromPolicy, toPolicy resources.AirgapGateTrustPolicy) ([]resources.AirgapGateTrustPolicyChange, string) {
	type signerKey struct {
		keyID  string
		digest string
	}
	fromSigners := map[signerKey]resources.AirgapTrustedSignerIdentity{}
	toSigners := map[signerKey]resources.AirgapTrustedSignerIdentity{}
	for _, signer := range fromPolicy.Spec.TrustedSignerIdentities {
		fromSigners[signerKey{keyID: signer.KeyID, digest: signer.PublicKeyDigest}] = signer
	}
	for _, signer := range toPolicy.Spec.TrustedSignerIdentities {
		toSigners[signerKey{keyID: signer.KeyID, digest: signer.PublicKeyDigest}] = signer
	}
	changes := []resources.AirgapGateTrustPolicyChange{}
	highestImpact := "review"
	changeID := 1
	for key, signer := range toSigners {
		before, exists := fromSigners[key]
		if !exists {
			changes = append(changes, resources.AirgapGateTrustPolicyChange{
				ID:       fmt.Sprintf("change-%03d", changeID),
				KeyID:    key.keyID,
				Digest:   key.digest,
				Category: "added",
				Impact:   "review",
				Summary:  "Signer identity added to trust policy.",
			})
			changeID++
			continue
		}
		if before.Status != signer.Status {
			impact := "review"
			category := "revoked"
			summary := "Signer status changed."
			if signer.Status == "active" {
				category = "added"
				summary = "Signer status changed from revoked to active."
			}
			if before.Status == "active" && signer.Status == "revoked" {
				impact = "destructive"
				highestImpact = "destructive"
				summary = "Signer status changed from active to revoked."
			}
			changes = append(changes, resources.AirgapGateTrustPolicyChange{
				ID:       fmt.Sprintf("change-%03d", changeID),
				KeyID:    key.keyID,
				Digest:   key.digest,
				Category: category,
				Impact:   impact,
				Summary:  summary,
			})
			changeID++
		}
		if before.ValidFrom != signer.ValidFrom || before.ValidUntil != signer.ValidUntil {
			changes = append(changes, resources.AirgapGateTrustPolicyChange{
				ID:       fmt.Sprintf("change-%03d", changeID),
				KeyID:    key.keyID,
				Digest:   key.digest,
				Category: "validity-window-updated",
				Impact:   "review",
				Summary:  "Signer validity window updated.",
			})
			changeID++
		}
	}
	for key := range fromSigners {
		if _, exists := toSigners[key]; exists {
			continue
		}
		changes = append(changes, resources.AirgapGateTrustPolicyChange{
			ID:       fmt.Sprintf("change-%03d", changeID),
			KeyID:    key.keyID,
			Digest:   key.digest,
			Category: "removed",
			Impact:   "destructive",
			Summary:  "Signer identity removed from trust policy.",
		})
		highestImpact = "destructive"
		changeID++
	}
	slices.SortFunc(changes, func(left, right resources.AirgapGateTrustPolicyChange) int {
		leftKey := left.KeyID + "|" + left.Digest + "|" + left.Category
		rightKey := right.KeyID + "|" + right.Digest + "|" + right.Category
		return compareStrings(leftKey, rightKey)
	})
	for index := range changes {
		changes[index].ID = fmt.Sprintf("change-%03d", index+1)
	}
	return changes, highestImpact
}

func enforceTrustPolicyTransitionSafety(fromPolicy, toPolicy resources.AirgapGateTrustPolicy) error {
	activeBefore := map[string]struct{}{}
	activeAfter := map[string]struct{}{}
	for _, signer := range fromPolicy.Spec.TrustedSignerIdentities {
		if signer.Status == "active" {
			activeBefore[signer.KeyID+"|"+signer.PublicKeyDigest] = struct{}{}
		}
	}
	for _, signer := range toPolicy.Spec.TrustedSignerIdentities {
		if signer.Status == "active" {
			activeAfter[signer.KeyID+"|"+signer.PublicKeyDigest] = struct{}{}
		}
	}
	preserved := 0
	for key := range activeBefore {
		if _, ok := activeAfter[key]; ok {
			preserved++
		}
	}
	if len(activeBefore) > 0 && len(activeAfter) > 0 && preserved == 0 {
		return errors.New("trust-policy transition cannot replace all active signers in one change")
	}
	return nil
}

func reviewAirgapGateTrustPolicyTransition(args []string, stdout, stderr io.Writer) int {
	options, ok := parseAirgapTransitionReviewOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	diff, err := resources.LoadAirgapGateTrustPolicyDiff(options.policyDiffPath)
	if err != nil || !diff.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AGR-101", errors.New("trust-policy diff is invalid"), ExitInvalidInput)
	}
	if diff.Spec.HighestImpact != "destructive" {
		return writeLoadErrorWithExit(stdout, "YARA-AGR-102", errors.New("transition review is required only for destructive trust-policy diffs"), ExitInvalidInput)
	}
	decision := strings.TrimSpace(options.decision)
	if decision == "approve" {
		decision = resources.PromotionDecisionApproved
	} else if decision == "reject" {
		decision = resources.PromotionDecisionChangesRequired
	}
	if !slices.Contains([]string{resources.PromotionDecisionApproved, resources.PromotionDecisionChangesRequired, resources.PromotionDecisionAbstained}, decision) {
		return writeLoadErrorWithExit(stdout, "YARA-AGR-103", errors.New("decision must be approved, changes-required or abstained"), ExitInvalidInput)
	}
	actorID, assurance := localActor()
	review := resources.AirgapGateTransitionReview{
		APIVersion: resources.APIVersion,
		Kind:       "AirgapGateTransitionReview",
		Metadata: resources.AirgapGateTransitionReviewMetadata{
			Name: options.name,
		},
		Spec: resources.AirgapGateTransitionReviewSpec{
			RecordedAt:            time.Now().UTC().Format(time.RFC3339Nano),
			PolicyDiffID:          diff.Metadata.DiffID,
			FromPolicyID:          diff.Spec.FromPolicyID,
			ToPolicyID:            diff.Spec.ToPolicyID,
			TargetReferenceDigest: diff.Spec.TargetReferenceDigest,
			Reviewer: resources.ReviewerRecord{
				Identity:  actorID,
				Role:      options.reviewerRole,
				Assurance: assurance,
			},
			Decision:        decision,
			ReasonReference: options.reasonReference,
			Limitations: []string{
				"Transition review is scoped to one destructive trust-policy diff identity.",
				"Transition review records non-secret reviewer metadata only.",
			},
		},
	}
	slices.Sort(review.Spec.Limitations)
	review, err = review.AssignReviewID()
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGR-500", err, ExitInternal)
	}
	if report := review.Validate(); !report.Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AGR-500", errors.New("constructed transition review is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(review)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGR-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AGR-104", err, ExitInvalidInput)
	}
	subjects := []audit.Subject{
		{Kind: "AirgapGateTrustPolicyDiff", Digest: diff.Metadata.DiffID},
		{Kind: "AirgapGateTransitionReview", Digest: review.Metadata.ReviewID},
	}
	if err := persistOperationAuditForTarget(options.auditPath, "airgap.gate-trust-policy.review-transition", "completed", "success", "kubernetes:"+diff.Spec.TargetReferenceDigest, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":        true,
		"reviewId":     review.Metadata.ReviewID,
		"policyDiffId": diff.Metadata.DiffID,
		"decision":     review.Spec.Decision,
		"output":       options.outputPath,
		"auditOutput":  options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseAirgapTransitionReviewOptions(args []string, stderr io.Writer) (airgapTransitionReviewOptions, bool) {
	var options airgapTransitionReviewOptions
	flags := flag.NewFlagSet("airgap gate-trust-policy review-transition", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.policyDiffPath, "policy-diff", "", "AirgapGateTrustPolicyDiff YAML")
	flags.StringVar(&options.decision, "decision", "", "Review decision: approved|changes-required|abstained")
	flags.StringVar(&options.reviewerRole, "reviewer-role", "", "Independent reviewer role")
	flags.StringVar(&options.reasonReference, "reason-reference", "", "Non-secret review reason reference")
	flags.StringVar(&options.name, "name", "", "AirgapGateTransitionReview name")
	flags.StringVar(&options.outputPath, "output", "", "Generated AirgapGateTransitionReview YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated transition review audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.policyDiffPath == "" || options.decision == "" || options.reviewerRole == "" || options.reasonReference == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "airgap gate-trust-policy review-transition requires --policy-diff --decision --reviewer-role --reason-reference --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}
