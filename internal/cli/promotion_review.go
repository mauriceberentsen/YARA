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

type promotionReviewOptions struct {
	catalogPath, assertionRef, reviewerRole, reasonReference string
	name, outputPath, auditPath, decision                    string
	selectedEvidence                                         csvFlag
}

func recordPromotionReview(args []string, stdout, stderr io.Writer) int {
	options, ok := parsePromotionReviewOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writePromotionFailure(stdout, options.auditPath, "catalog:unresolved", []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-PRM-101", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writePromotionFailure(stdout, options.auditPath, "catalog:unresolved", nil, "YARA-PRM-500", err, ExitInternal)
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
		return writePromotionFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PRM-102", errors.New("assertion reference is not present in the catalog"), ExitInvalidInput)
	}
	decision := strings.TrimSpace(options.decision)
	if decision == "approve" {
		decision = resources.PromotionDecisionApproved
	} else if decision == "reject" {
		decision = resources.PromotionDecisionChangesRequired
	}
	if !validPromotionDecisionCLI(decision) {
		return writePromotionFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PRM-103", errors.New("decision must be approved, changes-required or abstained"), ExitInvalidInput)
	}
	if len(options.selectedEvidence) == 0 {
		return writePromotionFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PRM-104", errors.New("at least one selected evidence ID is required"), ExitInvalidInput)
	}
	selected := uniqueSortedStrings(options.selectedEvidence)
	for _, digest := range selected {
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
			return writePromotionFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PRM-104", errors.New("selected evidence IDs must be SHA-256 digests"), ExitInvalidInput)
		}
	}
	actorID, assurance := localActor()
	review := resources.PromotionReview{
		APIVersion: resources.APIVersion,
		Kind:       "PromotionReview",
		Metadata: resources.PromotionReviewMetadata{
			Name: options.name,
		},
		Spec: resources.PromotionReviewSpec{
			CatalogDigest:    catalogDigest,
			AssertionRef:     options.assertionRef,
			SelectedEvidence: selected,
			Reviewer: resources.ReviewerRecord{
				Identity:  actorID,
				Role:      options.reviewerRole,
				Assurance: assurance,
			},
			ReviewedAt:      time.Now().UTC().Format(time.RFC3339Nano),
			Decision:        decision,
			ReasonReference: options.reasonReference,
			Limitations: []string{
				"Promotion review is bounded to explicit catalog and selected evidence identities.",
				"Promotion review does not mutate catalog manifests or execute workloads.",
			},
		},
	}
	slices.Sort(review.Spec.Limitations)
	review, err = review.AssignReviewID()
	if err != nil {
		return writePromotionFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PRM-500", err, ExitInternal)
	}
	if report := review.Validate(); !report.Valid {
		return writePromotionFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PRM-500", errors.New("constructed promotion review is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(review)
	if err != nil {
		return writePromotionFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PRM-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writePromotionFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PRM-105", err, ExitInvalidInput)
	}
	subjects := []audit.Subject{
		catalogSubject,
		{Kind: "PromotionReview", Digest: review.Metadata.ReviewID},
	}
	if err := persistOperationAuditForTarget(options.auditPath, "promotion.review", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":         true,
		"reviewId":      review.Metadata.ReviewID,
		"decision":      review.Spec.Decision,
		"catalogDigest": catalogDigest,
		"output":        options.outputPath,
		"auditOutput":   options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parsePromotionReviewOptions(args []string, stderr io.Writer) (promotionReviewOptions, bool) {
	var options promotionReviewOptions
	flags := flag.NewFlagSet("promotion review record", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.assertionRef, "assertion", "", "Exact assertion ID to review")
	flags.Var(&options.selectedEvidence, "evidence", "Selected accepted evidence result digest (repeatable)")
	flags.StringVar(&options.reviewerRole, "reviewer-role", "", "Independent reviewer role")
	flags.StringVar(&options.decision, "decision", "", "Review decision: approved|changes-required|abstained")
	flags.StringVar(&options.reasonReference, "reason-reference", "", "Non-secret review reason reference")
	flags.StringVar(&options.name, "name", "", "PromotionReview name")
	flags.StringVar(&options.outputPath, "output", "", "Generated PromotionReview YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated promotion review audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.assertionRef == "" || options.reviewerRole == "" || options.decision == "" || options.reasonReference == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "promotion review record requires --catalog --assertion --evidence --reviewer-role --decision --reason-reference --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}

func writePromotionFailure(output io.Writer, auditPath, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(auditPath, "promotion.review", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}

func validPromotionDecisionCLI(value string) bool {
	return value == resources.PromotionDecisionApproved || value == resources.PromotionDecisionChangesRequired || value == resources.PromotionDecisionAbstained
}
