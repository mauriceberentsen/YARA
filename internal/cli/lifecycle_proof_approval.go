package cli

import (
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
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type lifecycleProofApprovalOptions struct {
	catalogPath, assertionRef, lifecycleProofLedgerPath, confirmLifecycleProofLedgerID string
	reviewerRole, decision, reasonReference, name, outputPath, auditPath, maxLedgerAge string
	selectedEvidence                                                                   csvFlag
	validFor                                                                           time.Duration
}

func approveLifecycleProofPublication(args []string, stdout, stderr io.Writer) int {
	options, ok := parseLifecycleProofApprovalOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, "catalog:unresolved", []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-LPA-101", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, "catalog:unresolved", nil, "YARA-LPA-500", err, ExitInternal)
	}
	target := "catalog:" + catalogDigest
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	assertionKnown := false
	for _, assertion := range snapshot.ManifestInventory().Compatibility {
		if assertion.ID == options.assertionRef {
			assertionKnown = true
			break
		}
	}
	if !assertionKnown {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-LPA-102", errors.New("assertion reference is not present in the catalog"), ExitInvalidInput)
	}
	ledger, err := resources.LoadLifecycleProofLedger(options.lifecycleProofLedgerPath)
	if err != nil || !ledger.Validate().Valid {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-LPA-103", errors.New("lifecycle proof ledger is invalid"), ExitInvalidInput)
	}
	subjects := []audit.Subject{
		catalogSubject,
		{Kind: "LifecycleProofLedger", Digest: ledger.Metadata.LedgerID},
	}
	if ledger.Metadata.LedgerID != options.confirmLifecycleProofLedgerID {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-104", errors.New("explicit lifecycle proof ledger confirmation mismatch"), ExitInfeasible)
	}
	selected := uniqueSortedStrings(options.selectedEvidence)
	if len(selected) == 0 {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-105", errors.New("at least one selected evidence ID is required"), ExitInvalidInput)
	}
	for _, digest := range selected {
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
			return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-105", errors.New("selected evidence IDs must be SHA-256 digests"), ExitInvalidInput)
		}
	}
	maxLedgerAge, err := time.ParseDuration(options.maxLedgerAge)
	if err != nil || maxLedgerAge <= 0 {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-106", errors.New("max-ledger-age must be a positive duration"), ExitInvalidInput)
	}
	recordedAt, parseErr := time.Parse(time.RFC3339Nano, ledger.Spec.RecordedAt)
	if parseErr != nil {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-103", errors.New("lifecycle proof ledger recordedAt is invalid"), ExitInvalidInput)
	}
	now := time.Now().UTC()
	if recordedAt.After(now) || now.Sub(recordedAt) > maxLedgerAge {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-107", errors.New("lifecycle proof ledger is stale for publication approval"), ExitInfeasible)
	}
	decision := strings.TrimSpace(options.decision)
	if decision == "approve" {
		decision = resources.PromotionDecisionApproved
	} else if decision == "reject" {
		decision = resources.PromotionDecisionChangesRequired
	}
	if !validPromotionDecisionCLI(decision) {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-108", errors.New("decision must be approved, changes-required or abstained"), ExitInvalidInput)
	}
	actorID, assurance := localActor()
	approval := resources.LifecycleProofApproval{
		APIVersion: resources.APIVersion,
		Kind:       "LifecycleProofApproval",
		Metadata: resources.LifecycleProofApprovalMeta{
			Name: options.name,
		},
		Spec: resources.LifecycleProofApprovalSpec{
			ReviewedAt:       now.Format(time.RFC3339Nano),
			ExpiresAt:        now.Add(options.validFor).Format(time.RFC3339Nano),
			CatalogDigest:    catalogDigest,
			AssertionRef:     options.assertionRef,
			LedgerID:         ledger.Metadata.LedgerID,
			SelectedEvidence: selected,
			Reviewer: resources.ReviewerRecord{
				Identity:  actorID,
				Role:      options.reviewerRole,
				Assurance: assurance,
			},
			Decision:        decision,
			ReasonReference: options.reasonReference,
			MaxLedgerAge:    options.maxLedgerAge,
			Limitations: []string{
				"Lifecycle-proof approval is bounded to one catalog assertion and one immutable lifecycle ledger identity.",
				"Lifecycle-proof approval records publication review intent without mutating catalog manifests.",
			},
		},
	}
	slices.Sort(approval.Spec.Limitations)
	approval, err = approval.AssignApprovalID()
	if err != nil {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-500", err, ExitInternal)
	}
	if report := approval.Validate(); !report.Valid {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-500", errors.New("constructed lifecycle proof approval is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(approval)
	if err != nil {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeLifecycleProofApprovalFailure(stdout, options.auditPath, target, subjects, "YARA-LPA-109", err, ExitInvalidInput)
	}
	subjects = append(subjects, audit.Subject{Kind: "LifecycleProofApproval", Digest: approval.Metadata.ApprovalID})
	if err := persistOperationAuditForTarget(options.auditPath, "lifecycle.proof.approve-publication", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":       true,
		"approvalId":  approval.Metadata.ApprovalID,
		"decision":    approval.Spec.Decision,
		"output":      options.outputPath,
		"auditOutput": options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseLifecycleProofApprovalOptions(args []string, stderr io.Writer) (lifecycleProofApprovalOptions, bool) {
	var options lifecycleProofApprovalOptions
	flags := flag.NewFlagSet("lifecycle proof approve-publication", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.assertionRef, "assertion", "", "Exact assertion ID to approve for lifecycle publication")
	flags.StringVar(&options.lifecycleProofLedgerPath, "lifecycle-proof-ledger", "", "Validated LifecycleProofLedger file")
	flags.StringVar(&options.confirmLifecycleProofLedgerID, "confirm-lifecycle-proof-ledger", "", "Exact lifecycle proof ledger ID confirmation")
	flags.Var(&options.selectedEvidence, "evidence", "Selected lifecycle evidence digest (repeatable)")
	flags.StringVar(&options.reviewerRole, "reviewer-role", "", "Independent reviewer role")
	flags.StringVar(&options.decision, "decision", "", "Review decision: approved|changes-required|abstained")
	flags.StringVar(&options.reasonReference, "reason-reference", "", "Non-secret review reason reference")
	flags.StringVar(&options.maxLedgerAge, "max-ledger-age", "", "Maximum allowed ledger age for publication review")
	flags.DurationVar(&options.validFor, "valid-for", 7*24*time.Hour, "Lifecycle-proof approval validity duration")
	flags.StringVar(&options.name, "name", "", "LifecycleProofApproval name")
	flags.StringVar(&options.outputPath, "output", "", "Generated LifecycleProofApproval YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated lifecycle proof approval audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.assertionRef == "" || options.lifecycleProofLedgerPath == "" || options.confirmLifecycleProofLedgerID == "" || len(options.selectedEvidence) == 0 || options.reviewerRole == "" || options.decision == "" || options.reasonReference == "" || options.maxLedgerAge == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "lifecycle proof approve-publication requires --catalog --assertion --lifecycle-proof-ledger --confirm-lifecycle-proof-ledger --evidence --reviewer-role --decision --reason-reference --max-ledger-age --name --output --audit-output")
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

func writeLifecycleProofApprovalFailure(output io.Writer, auditPath, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(auditPath, "lifecycle.proof.approve-publication", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}
