package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type integrationPublicationAttestationOptions struct {
	catalogPath, evidenceDir, assertionRef, reviewerRole, decision, reasonReference string
	name, outputPath, auditPath, maxEvidenceAge                                     string
	selectedEvidence                                                                csvFlag
	validFor                                                                        time.Duration
}

func attestIntegrationPublication(args []string, stdout, stderr io.Writer) int {
	options, ok := parseIntegrationPublicationAttestationOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, "catalog:unresolved", []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-IPA-101", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, "catalog:unresolved", nil, "YARA-IPA-500", err, ExitInternal)
	}
	target := "catalog:" + catalogDigest
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	assertion, assertionKnown := findCatalogAssertion(snapshot, options.assertionRef)
	if !assertionKnown {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-102", errors.New("assertion reference is not present in the catalog"), ExitInvalidInput)
	}
	if !requiresIntegrationPublicationAttestation(assertion) {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-103", errors.New("assertion does not require integration publication attestation"), ExitInfeasible)
	}
	selected := uniqueSortedStrings(options.selectedEvidence)
	if len(selected) == 0 {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-104", errors.New("at least one selected evidence ID is required"), ExitInvalidInput)
	}
	for _, digest := range selected {
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
			return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-105", errors.New("selected evidence IDs must be SHA-256 digests"), ExitInvalidInput)
		}
	}
	maxEvidenceAge, err := time.ParseDuration(options.maxEvidenceAge)
	if err != nil || maxEvidenceAge <= 0 {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-106", errors.New("max-evidence-age must be a positive duration"), ExitInvalidInput)
	}
	acceptedEvidence, err := loadBoundIntegrationEvidence(options.evidenceDir, catalogDigest, assertion)
	if err != nil {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-107", err, ExitInvalidInput)
	}
	if len(acceptedEvidence) == 0 {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-108", errors.New("no accepted integration execution evidence found for assertion runtime"), ExitInfeasible)
	}
	now := time.Now().UTC()
	selectedBound := map[string]integrationPublicationEvidence{}
	latestOccurredAt := time.Time{}
	for _, digest := range selected {
		evidence, exists := acceptedEvidence[digest]
		if !exists {
			return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-109", errors.New("selected evidence is not accepted integration execution evidence for the assertion"), ExitInfeasible)
		}
		occurredAt, parseErr := time.Parse(time.RFC3339Nano, evidence.OccurredAt)
		if parseErr != nil {
			return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-500", errors.New("integration evidence audit timestamp is invalid"), ExitInternal)
		}
		if occurredAt.After(now) || now.Sub(occurredAt) > maxEvidenceAge {
			return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-110", errors.New("selected evidence is stale for integration publication attestation"), ExitInfeasible)
		}
		if occurredAt.After(latestOccurredAt) {
			latestOccurredAt = occurredAt
		}
		selectedBound[digest] = evidence
	}
	decision := strings.TrimSpace(options.decision)
	if decision == "approve" {
		decision = resources.PromotionDecisionApproved
	} else if decision == "reject" {
		decision = resources.PromotionDecisionChangesRequired
	}
	if !validPromotionDecisionCLI(decision) {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-111", errors.New("decision must be approved, changes-required or abstained"), ExitInvalidInput)
	}
	actorID, assurance := localActor()
	attestation := resources.IntegrationPublicationAttestation{
		APIVersion: resources.APIVersion,
		Kind:       "IntegrationPublicationAttestation",
		Metadata: resources.IntegrationPublicationAttestationMeta{
			Name: options.name,
		},
		Spec: resources.IntegrationPublicationAttestationSpec{
			ReviewedAt:       now.Format(time.RFC3339Nano),
			ExpiresAt:        now.Add(options.validFor).Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     options.assertionRef,
			SelectedEvidence: selected,
			Reviewer: resources.ReviewerRecord{
				Identity:  actorID,
				Role:      options.reviewerRole,
				Assurance: assurance,
			},
			Decision:        decision,
			ReasonReference: options.reasonReference,
			MaxEvidenceAge:  options.maxEvidenceAge,
			Limitations: []string{
				"Integration publication attestation binds one assertion to immutable integration evidence identities only.",
				"Integration publication attestation records reviewer intent without mutating catalog manifests.",
			},
		},
	}
	slices.Sort(attestation.Spec.Limitations)
	attestation, err = attestation.AssignAttestationID()
	if err != nil {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-500", err, ExitInternal)
	}
	if report := attestation.Validate(); !report.Valid {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-500", errors.New("constructed integration publication attestation is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(attestation)
	if err != nil {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeIntegrationPublicationAttestationFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-IPA-112", err, ExitInvalidInput)
	}
	subjects := []audit.Subject{catalogSubject, {Kind: "IntegrationPublicationAttestation", Digest: attestation.Metadata.AttestationID}}
	for _, digest := range selected {
		subjects = append(subjects, audit.Subject{Kind: "IntegrationTestResult", Digest: digest})
	}
	slices.SortFunc(subjects, func(left, right audit.Subject) int {
		if cmp := strings.Compare(left.Kind, right.Kind); cmp != 0 {
			return cmp
		}
		return strings.Compare(left.Digest, right.Digest)
	})
	if err := persistOperationAuditForTarget(options.auditPath, "integration.publish.attestation", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":         true,
		"attestationId": attestation.Metadata.AttestationID,
		"decision":      attestation.Spec.Decision,
		"output":        options.outputPath,
		"auditOutput":   options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	_ = latestOccurredAt
	return ExitSuccess
}

type integrationPublicationEvidence struct {
	ResultID      string
	AuditHead     string
	OccurredAt    string
	RuntimeRef    string
	CatalogDigest string
}

func loadBoundIntegrationEvidence(directory, catalogDigest string, assertion catalog.AssertionDescriptor) (map[string]integrationPublicationEvidence, error) {
	result := map[string]integrationPublicationEvidence{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			return nil
		}
		kind, err := evidenceKind(path)
		if err != nil {
			return fmt.Errorf("load integration evidence %s: %w", filepath.Base(path), err)
		}
		if kind != "IntegrationTestResult" {
			return nil
		}
		integrationResult, err := resources.LoadIntegrationTestResult(path)
		if err != nil {
			return fmt.Errorf("load integration evidence %s: %w", filepath.Base(path), err)
		}
		if report := integrationResult.Validate(); !report.Valid {
			return fmt.Errorf("integration evidence %s is invalid", filepath.Base(path))
		}
		if integrationResult.Spec.CatalogDigest != catalogDigest {
			return fmt.Errorf("integration evidence %s is not bound to this catalog", filepath.Base(path))
		}
		bindsAssertionRuntime := false
		for _, componentRef := range integrationResult.Spec.ComponentRefs {
			if componentRef == assertion.RuntimeRef || strings.HasPrefix(componentRef, assertion.RuntimeRef+"@") {
				bindsAssertionRuntime = true
				break
			}
		}
		if !bindsAssertionRuntime {
			return nil
		}
		auditPath := strings.TrimSuffix(path, ".yaml") + ".audit.jsonl"
		events, err := audit.LoadJSONL(auditPath)
		if err != nil {
			return fmt.Errorf("load integration evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		head, err := audit.Verify(events)
		if err != nil {
			return fmt.Errorf("verify integration evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		if len(events) != 2 {
			return fmt.Errorf("verify integration evidence audit %s: expected two events, found %d", filepath.Base(auditPath), len(events))
		}
		terminal := events[len(events)-1]
		if !strings.HasPrefix(terminal.Spec.Action, "integration.") || !strings.HasSuffix(terminal.Spec.Action, ".completed") {
			return fmt.Errorf("bind integration evidence audit %s: terminal action is not integration execution evidence", filepath.Base(auditPath))
		}
		if !hasSubject(terminal.Spec.Subjects, "CatalogSnapshot", catalogDigest) || !hasSubject(terminal.Spec.Subjects, "IntegrationTestResult", integrationResult.Metadata.ResultID) {
			return fmt.Errorf("bind integration evidence audit %s: terminal subjects do not bind catalog and integration result identities", filepath.Base(auditPath))
		}
		if existing, exists := result[integrationResult.Metadata.ResultID]; exists && existing.AuditHead != head {
			return fmt.Errorf("integration evidence %s reuses result identity with mismatched audit binding", filepath.Base(path))
		}
		result[integrationResult.Metadata.ResultID] = integrationPublicationEvidence{
			ResultID:      integrationResult.Metadata.ResultID,
			AuditHead:     head,
			OccurredAt:    terminal.Metadata.OccurredAt,
			RuntimeRef:    assertion.RuntimeRef,
			CatalogDigest: integrationResult.Spec.CatalogDigest,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func parseIntegrationPublicationAttestationOptions(args []string, stderr io.Writer) (integrationPublicationAttestationOptions, bool) {
	var options integrationPublicationAttestationOptions
	flags := flag.NewFlagSet("integration publish attest", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.evidenceDir, "evidence-dir", "", "Directory containing integration result YAML and adjacent audit chains")
	flags.StringVar(&options.assertionRef, "assertion", "", "Exact assertion ID to attest for integration publication")
	flags.Var(&options.selectedEvidence, "evidence", "Selected integration evidence digest (repeatable)")
	flags.StringVar(&options.reviewerRole, "reviewer-role", "", "Independent reviewer role")
	flags.StringVar(&options.decision, "decision", "", "Review decision: approved|changes-required|abstained")
	flags.StringVar(&options.reasonReference, "reason-reference", "", "Non-secret review reason reference")
	flags.StringVar(&options.maxEvidenceAge, "max-evidence-age", "", "Maximum allowed selected-evidence age")
	flags.DurationVar(&options.validFor, "valid-for", 7*24*time.Hour, "Integration publication attestation validity duration")
	flags.StringVar(&options.name, "name", "", "IntegrationPublicationAttestation name")
	flags.StringVar(&options.outputPath, "output", "", "Generated IntegrationPublicationAttestation YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated integration publication attestation audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.evidenceDir == "" || options.assertionRef == "" || len(options.selectedEvidence) == 0 || options.reviewerRole == "" || options.decision == "" || options.reasonReference == "" || options.maxEvidenceAge == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "integration publish attest requires --catalog --evidence-dir --assertion --evidence --reviewer-role --decision --reason-reference --max-evidence-age --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	if options.validFor <= 0 {
		fmt.Fprintln(stderr, "--valid-for must be greater than zero")
		return options, false
	}
	return options, true
}

func writeIntegrationPublicationAttestationFailure(output io.Writer, auditPath, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(auditPath, "integration.publish.attestation", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}

func findCatalogAssertion(snapshot catalog.Snapshot, assertionRef string) (catalog.AssertionDescriptor, bool) {
	for _, assertion := range snapshot.ManifestInventory().Compatibility {
		if assertion.ID == assertionRef {
			return assertion, true
		}
	}
	return catalog.AssertionDescriptor{}, false
}

func requiresIntegrationPublicationAttestation(assertion catalog.AssertionDescriptor) bool {
	return assertion.Compatibility == "supported" && slices.Contains([]string{"known", "experimental", "supported"}, assertion.Status)
}

func hasSubject(subjects []audit.Subject, kind, digest string) bool {
	for _, subject := range subjects {
		if subject.Kind == kind && subject.Digest == digest {
			return true
		}
	}
	return false
}

func evidenceKind(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil {
		return "", err
	}
	if len(data) > 4<<20 {
		return "", errors.New("evidence resource exceeds the 4 MiB input limit")
	}
	var envelope struct {
		Kind string `yaml:"kind"`
	}
	if err := yaml.Unmarshal(data, &envelope); err != nil {
		return "", err
	}
	return envelope.Kind, nil
}
