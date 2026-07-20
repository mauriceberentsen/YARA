package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type publicationChainRenewalReviewOptions struct {
	catalogPath, assertionRef, publicationChainRehearsalPath, confirmPublicationChainRehearsalID string
	publicationChainRetentionAuditPath, confirmPublicationChainRetentionAuditHead                string
	promotionReviewPath, confirmPromotionReviewID                                                string
	lifecycleProofApprovalPath, confirmLifecycleProofApprovalID                                  string
	integrationPublicationAttestationPath, confirmIntegrationPublicationAttestationID            string
	reviewerRole, decision, reasonReference, maxEvidenceAge                                      string
	name, outputPath, auditPath                                                                  string
	selectedEvidence                                                                             csvFlag
	validFor                                                                                     time.Duration
}

func reviewPublicationChainRenewal(args []string, stdout, stderr io.Writer) int {
	options, ok := parsePublicationChainRenewalReviewOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, "catalog:unresolved", []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-PCRR-101", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, "catalog:unresolved", nil, "YARA-PCRR-500", err, ExitInternal)
	}
	target := "catalog:" + catalogDigest
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	assertion, found := findCatalogAssertion(snapshot, options.assertionRef)
	if !found {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCRR-102", errors.New("assertion reference is not present in the catalog"), ExitInvalidInput)
	}
	if !requiresIntegrationPublicationAttestation(assertion) {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCRR-103", errors.New("assertion does not require publication-chain renewal review"), ExitInfeasible)
	}
	maxEvidenceAge, err := time.ParseDuration(options.maxEvidenceAge)
	if err != nil || maxEvidenceAge <= 0 {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCRR-104", errors.New("max-evidence-age must be a positive duration"), ExitInvalidInput)
	}
	rehearsal, err := resources.LoadPublicationChainRehearsal(options.publicationChainRehearsalPath)
	if err != nil || !rehearsal.Validate().Valid {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCRR-105", errors.New("publication-chain rehearsal evidence is invalid"), ExitInvalidInput)
	}
	promotionReview, err := resources.LoadPromotionReview(options.promotionReviewPath)
	if err != nil || !promotionReview.Validate().Valid {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCRR-106", errors.New("promotion review evidence is invalid"), ExitInvalidInput)
	}
	lifecycleApproval, err := resources.LoadLifecycleProofApproval(options.lifecycleProofApprovalPath)
	if err != nil || !lifecycleApproval.Validate().Valid {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCRR-107", errors.New("lifecycle proof approval evidence is invalid"), ExitInvalidInput)
	}
	integrationAttestation, err := resources.LoadIntegrationPublicationAttestation(options.integrationPublicationAttestationPath)
	if err != nil || !integrationAttestation.Validate().Valid {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCRR-108", errors.New("integration publication attestation evidence is invalid"), ExitInvalidInput)
	}
	retentionEvents, retentionHead, err := loadVerifiedBoundaryAudit(options.publicationChainRetentionAuditPath)
	if err != nil {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCRR-109", errors.New("publication-chain retention diagnostics audit is invalid"), ExitInvalidInput)
	}
	subjects := []audit.Subject{
		catalogSubject,
		{Kind: "PublicationChainRehearsal", Digest: rehearsal.Metadata.RehearsalID},
		{Kind: "AuditChain", Digest: retentionHead},
		{Kind: "PromotionReview", Digest: promotionReview.Metadata.ReviewID},
		{Kind: "LifecycleProofApproval", Digest: lifecycleApproval.Metadata.ApprovalID},
		{Kind: "IntegrationPublicationAttestation", Digest: integrationAttestation.Metadata.AttestationID},
	}
	if rehearsal.Metadata.RehearsalID != options.confirmPublicationChainRehearsalID {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-110", errors.New("explicit publication-chain rehearsal confirmation mismatch"), ExitInfeasible)
	}
	if retentionHead != options.confirmPublicationChainRetentionAuditHead {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-111", errors.New("explicit publication-chain retention diagnostics audit confirmation mismatch"), ExitInfeasible)
	}
	if promotionReview.Metadata.ReviewID != options.confirmPromotionReviewID {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-112", errors.New("explicit promotion review confirmation mismatch"), ExitInfeasible)
	}
	if lifecycleApproval.Metadata.ApprovalID != options.confirmLifecycleProofApprovalID {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-113", errors.New("explicit lifecycle proof approval confirmation mismatch"), ExitInfeasible)
	}
	if integrationAttestation.Metadata.AttestationID != options.confirmIntegrationPublicationAttestationID {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-114", errors.New("explicit integration publication attestation confirmation mismatch"), ExitInfeasible)
	}
	if rehearsal.Spec.CatalogDigest != catalogDigest || rehearsal.Spec.AssertionRef != options.assertionRef {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-115", errors.New("publication-chain rehearsal evidence is foreign to selected assertion scope"), ExitInfeasible)
	}
	if promotionReview.Spec.CatalogDigest != catalogDigest || promotionReview.Spec.AssertionRef != options.assertionRef {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-116", errors.New("promotion review evidence is foreign to selected assertion scope"), ExitInfeasible)
	}
	if lifecycleApproval.Spec.CatalogDigest != catalogDigest || lifecycleApproval.Spec.AssertionRef != options.assertionRef {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-117", errors.New("lifecycle proof approval evidence is foreign to selected assertion scope"), ExitInfeasible)
	}
	if integrationAttestation.Spec.CatalogDigest != catalogDigest || integrationAttestation.Spec.AssertionRef != options.assertionRef {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-118", errors.New("integration publication attestation evidence is foreign to selected assertion scope"), ExitInfeasible)
	}
	if rehearsal.Spec.Decision != resources.PromotionDecisionApproved || promotionReview.Spec.Decision != resources.PromotionDecisionApproved || lifecycleApproval.Spec.Decision != resources.PromotionDecisionApproved || integrationAttestation.Spec.Decision != resources.PromotionDecisionApproved {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-119", errors.New("renewal review requires approved prerequisite publication evidence"), ExitInfeasible)
	}
	if len(retentionEvents) != 2 {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-120", errors.New("publication-chain retention diagnostics audit must contain exactly two events"), ExitInfeasible)
	}
	terminalRetention := retentionEvents[len(retentionEvents)-1]
	if terminalRetention.Spec.Action != "publication.chain.retention-diagnostics.completed" || terminalRetention.Spec.Outcome != "success" || terminalRetention.Spec.Target != target {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-120", errors.New("publication-chain retention diagnostics audit terminal event is invalid"), ExitInfeasible)
	}
	if !hasSubject(terminalRetention.Spec.Subjects, "CatalogSnapshot", catalogDigest) || !hasSubject(terminalRetention.Spec.Subjects, "PublicationChainRehearsal", rehearsal.Metadata.RehearsalID) {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-121", errors.New("publication-chain retention diagnostics audit is unbound to selected rehearsal scope"), ExitInfeasible)
	}
	selected := uniqueSortedStrings(options.selectedEvidence)
	for _, digest := range selected {
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
			return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-122", errors.New("selected evidence IDs must be SHA-256 digests"), ExitInvalidInput)
		}
	}
	requiredSelected := []string{
		rehearsal.Metadata.RehearsalID,
		retentionHead,
		promotionReview.Metadata.ReviewID,
		lifecycleApproval.Metadata.ApprovalID,
		integrationAttestation.Metadata.AttestationID,
	}
	for _, requiredDigest := range requiredSelected {
		if !slices.Contains(selected, requiredDigest) {
			return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-123", errors.New("selected evidence must include all bound publication-chain renewal identities"), ExitInfeasible)
		}
	}
	now := time.Now().UTC()
	if stalePublicationChainRenewalEvidence(now, maxEvidenceAge, rehearsal.Spec.RehearsedAt, promotionReview.Spec.ReviewedAt, promotionReview.Spec.Decision, lifecycleApproval.Spec.ReviewedAt, lifecycleApproval.Spec.ExpiresAt, integrationAttestation.Spec.ReviewedAt, integrationAttestation.Spec.ExpiresAt, terminalRetention.Metadata.OccurredAt) {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-124", errors.New("publication-chain renewal evidence is stale"), ExitInfeasible)
	}
	decision := strings.TrimSpace(options.decision)
	if decision == "approve" {
		decision = resources.PromotionDecisionApproved
	} else if decision == "reject" {
		decision = resources.PromotionDecisionChangesRequired
	}
	if !validPromotionDecisionCLI(decision) {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-125", errors.New("decision must be approved, changes-required or abstained"), ExitInvalidInput)
	}
	actorID, assurance := localActor()
	review := resources.PublicationChainRenewalReview{
		APIVersion: resources.APIVersion,
		Kind:       "PublicationChainRenewalReview",
		Metadata: resources.PublicationChainRenewalReviewMeta{
			Name: options.name,
		},
		Spec: resources.PublicationChainRenewalReviewSpec{
			ReviewedAt:                          now.Format(time.RFC3339Nano),
			ExpiresAt:                           now.Add(options.validFor).Format(time.RFC3339Nano),
			CatalogDigest:                       catalogDigest,
			AssertionRef:                        options.assertionRef,
			PublicationChainRehearsalID:         rehearsal.Metadata.RehearsalID,
			PublicationChainRetentionAuditHead:  retentionHead,
			PromotionReviewID:                   promotionReview.Metadata.ReviewID,
			LifecycleProofApprovalID:            lifecycleApproval.Metadata.ApprovalID,
			IntegrationPublicationAttestationID: integrationAttestation.Metadata.AttestationID,
			SelectedEvidence:                    selected,
			Reviewer: resources.ReviewerRecord{
				Identity:  actorID,
				Role:      options.reviewerRole,
				Assurance: assurance,
			},
			Decision:        decision,
			ReasonReference: options.reasonReference,
			MaxEvidenceAge:  options.maxEvidenceAge,
			Limitations: []string{
				"Publication-chain renewal review references immutable publication history identities only.",
				"Publication-chain renewal review is non-mutating and does not replace historical evidence resources.",
			},
		},
	}
	slices.Sort(review.Spec.Limitations)
	review, err = review.AssignReviewID()
	if err != nil {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-500", err, ExitInternal)
	}
	if report := review.Validate(); !report.Valid {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-500", errors.New("constructed publication-chain renewal review is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(review)
	if err != nil {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writePublicationChainRenewalReviewFailure(stdout, options.auditPath, target, subjects, "YARA-PCRR-126", err, ExitInvalidInput)
	}
	subjects = append(subjects, audit.Subject{Kind: "PublicationChainRenewalReview", Digest: review.Metadata.ReviewID})
	sort.Slice(subjects, func(i, j int) bool {
		if subjects[i].Kind != subjects[j].Kind {
			return subjects[i].Kind < subjects[j].Kind
		}
		return subjects[i].Digest < subjects[j].Digest
	})
	if err := persistOperationAuditForTarget(options.auditPath, "publication.chain.renewal-review", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":       true,
		"reviewId":    review.Metadata.ReviewID,
		"assertion":   review.Spec.AssertionRef,
		"decision":    review.Spec.Decision,
		"output":      options.outputPath,
		"auditOutput": options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parsePublicationChainRenewalReviewOptions(args []string, stderr io.Writer) (publicationChainRenewalReviewOptions, bool) {
	var options publicationChainRenewalReviewOptions
	flags := flag.NewFlagSet("publication chain renewal-review", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.assertionRef, "assertion", "", "Exact assertion ID to review for renewal")
	flags.StringVar(&options.publicationChainRehearsalPath, "publication-chain-rehearsal", "", "Validated PublicationChainRehearsal file")
	flags.StringVar(&options.confirmPublicationChainRehearsalID, "confirm-publication-chain-rehearsal", "", "Exact publication-chain rehearsal ID confirmation")
	flags.StringVar(&options.publicationChainRetentionAuditPath, "publication-chain-retention-audit", "", "Validated publication-chain retention diagnostics audit JSONL file")
	flags.StringVar(&options.confirmPublicationChainRetentionAuditHead, "confirm-publication-chain-retention-audit", "", "Exact publication-chain retention diagnostics audit head confirmation")
	flags.StringVar(&options.promotionReviewPath, "promotion-review", "", "Validated PromotionReview file")
	flags.StringVar(&options.confirmPromotionReviewID, "confirm-promotion-review", "", "Exact promotion review ID confirmation")
	flags.StringVar(&options.lifecycleProofApprovalPath, "lifecycle-proof-approval", "", "Validated LifecycleProofApproval file")
	flags.StringVar(&options.confirmLifecycleProofApprovalID, "confirm-lifecycle-proof-approval", "", "Exact lifecycle proof approval ID confirmation")
	flags.StringVar(&options.integrationPublicationAttestationPath, "integration-publication-attestation", "", "Validated IntegrationPublicationAttestation file")
	flags.StringVar(&options.confirmIntegrationPublicationAttestationID, "confirm-integration-publication-attestation", "", "Exact integration publication attestation ID confirmation")
	flags.Var(&options.selectedEvidence, "evidence", "Selected publication-chain renewal evidence digest (repeatable)")
	flags.StringVar(&options.reviewerRole, "reviewer-role", "", "Independent reviewer role")
	flags.StringVar(&options.decision, "decision", "", "Review decision: approved|changes-required|abstained")
	flags.StringVar(&options.reasonReference, "reason-reference", "", "Non-secret review reason reference")
	flags.StringVar(&options.maxEvidenceAge, "max-evidence-age", "", "Maximum age allowed for bound publication-chain evidence")
	flags.DurationVar(&options.validFor, "valid-for", 7*24*time.Hour, "Publication-chain renewal review validity duration")
	flags.StringVar(&options.name, "name", "", "PublicationChainRenewalReview name")
	flags.StringVar(&options.outputPath, "output", "", "Generated PublicationChainRenewalReview YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated publication-chain renewal review audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.assertionRef == "" || options.publicationChainRehearsalPath == "" || options.confirmPublicationChainRehearsalID == "" || options.publicationChainRetentionAuditPath == "" || options.confirmPublicationChainRetentionAuditHead == "" || options.promotionReviewPath == "" || options.confirmPromotionReviewID == "" || options.lifecycleProofApprovalPath == "" || options.confirmLifecycleProofApprovalID == "" || options.integrationPublicationAttestationPath == "" || options.confirmIntegrationPublicationAttestationID == "" || len(options.selectedEvidence) == 0 || options.reviewerRole == "" || options.decision == "" || options.reasonReference == "" || options.maxEvidenceAge == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "publication chain renewal-review requires --catalog --assertion --publication-chain-rehearsal --confirm-publication-chain-rehearsal --publication-chain-retention-audit --confirm-publication-chain-retention-audit --promotion-review --confirm-promotion-review --lifecycle-proof-approval --confirm-lifecycle-proof-approval --integration-publication-attestation --confirm-integration-publication-attestation --evidence --reviewer-role --decision --reason-reference --max-evidence-age --name --output --audit-output")
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

func stalePublicationChainRenewalEvidence(now time.Time, maxEvidenceAge time.Duration, rehearsedAt, promotionReviewedAt, promotionDecision, lifecycleReviewedAt, lifecycleExpiresAt, integrationReviewedAt, integrationExpiresAt, retentionOccurredAt string) bool {
	parseTime := func(value string) (time.Time, error) {
		return time.Parse(time.RFC3339Nano, value)
	}
	rehearsed, err := parseTime(rehearsedAt)
	if err != nil || rehearsed.After(now) || now.Sub(rehearsed) > maxEvidenceAge {
		return true
	}
	promotionReviewed, err := parseTime(promotionReviewedAt)
	if err != nil || promotionReviewed.After(now) || now.Sub(promotionReviewed) > maxEvidenceAge {
		return true
	}
	if promotionDecision != resources.PromotionDecisionApproved {
		return true
	}
	lifecycleReviewed, err := parseTime(lifecycleReviewedAt)
	if err != nil || lifecycleReviewed.After(now) || now.Sub(lifecycleReviewed) > maxEvidenceAge {
		return true
	}
	lifecycleExpires, err := parseTime(lifecycleExpiresAt)
	if err != nil || !lifecycleExpires.After(now) {
		return true
	}
	integrationReviewed, err := parseTime(integrationReviewedAt)
	if err != nil || integrationReviewed.After(now) || now.Sub(integrationReviewed) > maxEvidenceAge {
		return true
	}
	integrationExpires, err := parseTime(integrationExpiresAt)
	if err != nil || !integrationExpires.After(now) {
		return true
	}
	retentionOccurred, err := parseTime(retentionOccurredAt)
	if err != nil || retentionOccurred.After(now) || now.Sub(retentionOccurred) > maxEvidenceAge {
		return true
	}
	return false
}

func writePublicationChainRenewalReviewFailure(output io.Writer, auditPath, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(auditPath, "publication.chain.renewal-review", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}
