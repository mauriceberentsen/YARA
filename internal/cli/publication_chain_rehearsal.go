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
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type publicationChainRehearsalOptions struct {
	catalogPath, assertionRef, lifecycleApprovalPath, confirmLifecycleApprovalID string
	integrationAttestationPath, confirmIntegrationAttestationID                  string
	coverageReportPath, confirmCoverageReportID                                  string
	trustPolicyPath, confirmTrustPolicyID, boundaryAuditPath                     string
	reviewerRole, decision, reasonReference, maxEvidenceAge                      string
	name, outputPath, auditPath                                                  string
	authorizationPaths                                                           csvFlag
}

func rehearsePublicationChain(args []string, stdout, stderr io.Writer) int {
	options, ok := parsePublicationChainRehearsalOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, "catalog:unresolved", []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-PCR-101", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, "catalog:unresolved", nil, "YARA-PCR-500", err, ExitInternal)
	}
	target := "catalog:" + catalogDigest
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	assertion, assertionKnown := findCatalogAssertion(snapshot, options.assertionRef)
	if !assertionKnown {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCR-102", errors.New("assertion reference is not present in the catalog"), ExitInvalidInput)
	}
	maxEvidenceAge, err := time.ParseDuration(options.maxEvidenceAge)
	if err != nil || maxEvidenceAge <= 0 {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCR-103", errors.New("max-evidence-age must be a positive duration"), ExitInvalidInput)
	}
	lifecycleApproval, err := resources.LoadLifecycleProofApproval(options.lifecycleApprovalPath)
	if err != nil || !lifecycleApproval.Validate().Valid {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCR-104", errors.New("lifecycle proof approval is invalid"), ExitInvalidInput)
	}
	integrationAttestation, err := resources.LoadIntegrationPublicationAttestation(options.integrationAttestationPath)
	if err != nil || !integrationAttestation.Validate().Valid {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCR-105", errors.New("integration publication attestation is invalid"), ExitInvalidInput)
	}
	coverageReport, err := catalogcoverage.Load(options.coverageReportPath)
	if err != nil {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCR-106", errors.New("catalog coverage report is invalid"), ExitInvalidInput)
	}
	trustPolicy, err := resources.LoadAirgapGateTrustPolicy(options.trustPolicyPath)
	if err != nil || !trustPolicy.Validate().Valid {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCR-107", errors.New("air-gap gate trust policy is invalid"), ExitInvalidInput)
	}
	subjects := []audit.Subject{
		catalogSubject,
		{Kind: "LifecycleProofApproval", Digest: lifecycleApproval.Metadata.ApprovalID},
		{Kind: "IntegrationPublicationAttestation", Digest: integrationAttestation.Metadata.AttestationID},
		{Kind: catalogcoverage.Kind, Digest: coverageReport.Metadata.ReportID},
		{Kind: "AirgapGateTrustPolicy", Digest: trustPolicy.Metadata.PolicyID},
	}
	if lifecycleApproval.Metadata.ApprovalID != options.confirmLifecycleApprovalID {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-108", errors.New("explicit lifecycle proof approval confirmation mismatch"), ExitInfeasible)
	}
	if integrationAttestation.Metadata.AttestationID != options.confirmIntegrationAttestationID {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-109", errors.New("explicit integration publication attestation confirmation mismatch"), ExitInfeasible)
	}
	if coverageReport.Metadata.ReportID != options.confirmCoverageReportID {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-110", errors.New("explicit coverage report confirmation mismatch"), ExitInfeasible)
	}
	if trustPolicy.Metadata.PolicyID != options.confirmTrustPolicyID {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-111", errors.New("explicit trust policy confirmation mismatch"), ExitInfeasible)
	}
	if lifecycleApproval.Spec.CatalogDigest != catalogDigest || lifecycleApproval.Spec.AssertionRef != assertion.ID {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-112", errors.New("lifecycle proof approval is foreign to catalog assertion scope"), ExitInfeasible)
	}
	if integrationAttestation.Spec.CatalogDigest != catalogDigest || integrationAttestation.Spec.AssertionRef != assertion.ID {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-113", errors.New("integration publication attestation is foreign to catalog assertion scope"), ExitInfeasible)
	}
	if lifecycleApproval.Spec.Decision != resources.PromotionDecisionApproved || integrationAttestation.Spec.Decision != resources.PromotionDecisionApproved {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-114", errors.New("publication chain requires approved lifecycle and integration publication decisions"), ExitInfeasible)
	}
	if _, found := findCoverageAssertion(coverageReport, assertion.ID); !found {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-115", errors.New("coverage report does not include assertion scope"), ExitInfeasible)
	}
	authorizationFiles := uniqueSortedStrings(options.authorizationPaths)
	authorizations := make([]resources.ExecutionAuthorization, 0, len(authorizationFiles))
	authorizationIDs := make([]string, 0, len(authorizationFiles))
	for _, path := range authorizationFiles {
		authorization, loadErr := resources.LoadExecutionAuthorization(path)
		if loadErr != nil || !authorization.Validate().Valid {
			return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-117", errors.New("deployment authorization evidence is invalid"), ExitInvalidInput)
		}
		authorizations = append(authorizations, authorization)
		authorizationIDs = append(authorizationIDs, authorization.Metadata.AuthorizationID)
		subjects = append(subjects, audit.Subject{Kind: "ExecutionAuthorization", Digest: authorization.Metadata.AuthorizationID})
	}
	slices.Sort(authorizationIDs)
	events, boundaryHead, err := loadVerifiedBoundaryAudit(options.boundaryAuditPath)
	if err != nil {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-118", errors.New("signing-authority boundary audit is invalid"), ExitInvalidInput)
	}
	if err := verifySigningBoundaryAudit(events, coverageReport.Metadata.ReportID, trustPolicy.Metadata.PolicyID, authorizationIDs); err != nil {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-119", err, ExitInfeasible)
	}
	boundaryStatus := evaluateSigningAuthorityBoundary(trustPolicy, authorizations)
	if boundaryStatus.Status != "independent" {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-120", errors.New("signing-authority boundary is not independent"), ExitInfeasible)
	}
	now := time.Now().UTC()
	if stalePublicationChainEvidence(now, maxEvidenceAge, lifecycleApproval.Spec.ReviewedAt, lifecycleApproval.Spec.ExpiresAt, integrationAttestation.Spec.ReviewedAt, integrationAttestation.Spec.ExpiresAt, events[len(events)-1].Metadata.OccurredAt) {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-121", errors.New("publication chain evidence is stale for rehearsal"), ExitInfeasible)
	}
	decision := strings.TrimSpace(options.decision)
	if decision == "approve" {
		decision = resources.PromotionDecisionApproved
	} else if decision == "reject" {
		decision = resources.PromotionDecisionChangesRequired
	}
	if !validPromotionDecisionCLI(decision) {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-122", errors.New("decision must be approved, changes-required or abstained"), ExitInvalidInput)
	}
	actorID, assurance := localActor()
	rehearsal := resources.PublicationChainRehearsal{
		APIVersion: resources.APIVersion,
		Kind:       "PublicationChainRehearsal",
		Metadata: resources.PublicationChainRehearsalMeta{
			Name: options.name,
		},
		Spec: resources.PublicationChainRehearsalSpec{
			RehearsedAt:                         now.Format(time.RFC3339Nano),
			CatalogDigest:                       catalogDigest,
			AssertionRef:                        assertion.ID,
			LifecycleProofApprovalID:            lifecycleApproval.Metadata.ApprovalID,
			IntegrationPublicationAttestationID: integrationAttestation.Metadata.AttestationID,
			CoverageReportID:                    coverageReport.Metadata.ReportID,
			TrustPolicyID:                       trustPolicy.Metadata.PolicyID,
			BoundaryAuditHead:                   boundaryHead,
			AuthorizationIDs:                    authorizationIDs,
			Reviewer: resources.ReviewerRecord{
				Identity:  actorID,
				Role:      options.reviewerRole,
				Assurance: assurance,
			},
			Decision:        decision,
			ReasonReference: options.reasonReference,
			MaxEvidenceAge:  options.maxEvidenceAge,
			Limitations: []string{
				"Publication-chain rehearsal records immutable publication evidence checks only.",
				"Publication-chain rehearsal is non-mutating and does not grant deployment authority.",
			},
		},
	}
	slices.Sort(rehearsal.Spec.AuthorizationIDs)
	slices.Sort(rehearsal.Spec.Limitations)
	rehearsal, err = rehearsal.AssignRehearsalID()
	if err != nil {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-500", err, ExitInternal)
	}
	if report := rehearsal.Validate(); !report.Valid {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-500", errors.New("constructed publication chain rehearsal is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(rehearsal)
	if err != nil {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writePublicationChainRehearsalFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-123", err, ExitInvalidInput)
	}
	subjects = append(subjects, audit.Subject{Kind: "PublicationChainRehearsal", Digest: rehearsal.Metadata.RehearsalID})
	sort.Slice(subjects, func(i, j int) bool {
		if subjects[i].Kind != subjects[j].Kind {
			return subjects[i].Kind < subjects[j].Kind
		}
		return subjects[i].Digest < subjects[j].Digest
	})
	if err := persistOperationAuditForTarget(options.auditPath, "publication.chain.rehearse", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":       true,
		"rehearsalId": rehearsal.Metadata.RehearsalID,
		"assertion":   rehearsal.Spec.AssertionRef,
		"output":      options.outputPath,
		"auditOutput": options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parsePublicationChainRehearsalOptions(args []string, stderr io.Writer) (publicationChainRehearsalOptions, bool) {
	var options publicationChainRehearsalOptions
	flags := flag.NewFlagSet("publication chain rehearse", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.assertionRef, "assertion", "", "Exact assertion ID to rehearse")
	flags.StringVar(&options.lifecycleApprovalPath, "lifecycle-proof-approval", "", "Validated LifecycleProofApproval file")
	flags.StringVar(&options.confirmLifecycleApprovalID, "confirm-lifecycle-proof-approval", "", "Exact lifecycle-proof approval ID confirmation")
	flags.StringVar(&options.integrationAttestationPath, "integration-publication-attestation", "", "Validated IntegrationPublicationAttestation file")
	flags.StringVar(&options.confirmIntegrationAttestationID, "confirm-integration-publication-attestation", "", "Exact integration publication attestation ID confirmation")
	flags.StringVar(&options.coverageReportPath, "coverage-report", "", "Validated CatalogCoverageReport file")
	flags.StringVar(&options.confirmCoverageReportID, "confirm-coverage-report", "", "Exact coverage report ID confirmation")
	flags.StringVar(&options.trustPolicyPath, "trust-policy", "", "Validated AirgapGateTrustPolicy file")
	flags.StringVar(&options.confirmTrustPolicyID, "confirm-trust-policy", "", "Exact trust policy ID confirmation")
	flags.StringVar(&options.boundaryAuditPath, "signing-boundary-audit", "", "Audit JSONL from catalog coverage signing-authority-boundary")
	flags.Var(&options.authorizationPaths, "authorization", "ExecutionAuthorization YAML file (repeatable)")
	flags.StringVar(&options.reviewerRole, "reviewer-role", "", "Independent reviewer role")
	flags.StringVar(&options.decision, "decision", "", "Review decision: approved|changes-required|abstained")
	flags.StringVar(&options.reasonReference, "reason-reference", "", "Non-secret review reason reference")
	flags.StringVar(&options.maxEvidenceAge, "max-evidence-age", "", "Maximum age allowed for publication-chain evidence")
	flags.StringVar(&options.name, "name", "", "PublicationChainRehearsal name")
	flags.StringVar(&options.outputPath, "output", "", "Generated PublicationChainRehearsal YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated publication-chain rehearsal audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.assertionRef == "" || options.lifecycleApprovalPath == "" || options.confirmLifecycleApprovalID == "" || options.integrationAttestationPath == "" || options.confirmIntegrationAttestationID == "" || options.coverageReportPath == "" || options.confirmCoverageReportID == "" || options.trustPolicyPath == "" || options.confirmTrustPolicyID == "" || options.boundaryAuditPath == "" || len(options.authorizationPaths) == 0 || options.reviewerRole == "" || options.decision == "" || options.reasonReference == "" || options.maxEvidenceAge == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "publication chain rehearse requires --catalog --assertion --lifecycle-proof-approval --confirm-lifecycle-proof-approval --integration-publication-attestation --confirm-integration-publication-attestation --coverage-report --confirm-coverage-report --trust-policy --confirm-trust-policy --signing-boundary-audit --authorization --reviewer-role --decision --reason-reference --max-evidence-age --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}

func verifySigningBoundaryAudit(events []audit.Event, reportID, trustPolicyID string, authorizationIDs []string) error {
	if len(events) != 2 {
		return fmt.Errorf("expected two signing-boundary audit events, found %d", len(events))
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "catalog.coverage.signing-authority-boundary.completed" || terminal.Spec.Outcome != "success" {
		return errors.New("signing-boundary audit terminal action or outcome is invalid")
	}
	if !hasSubject(terminal.Spec.Subjects, catalogcoverage.Kind, reportID) || !hasSubject(terminal.Spec.Subjects, "AirgapGateTrustPolicy", trustPolicyID) {
		return errors.New("signing-boundary audit does not bind report and trust policy identities")
	}
	for _, authorizationID := range authorizationIDs {
		if !hasSubject(terminal.Spec.Subjects, "ExecutionAuthorization", authorizationID) {
			return errors.New("signing-boundary audit does not bind authorization identities")
		}
	}
	return nil
}

func loadVerifiedBoundaryAudit(path string) ([]audit.Event, string, error) {
	events, err := audit.LoadJSONL(path)
	if err != nil {
		return nil, "", err
	}
	head, err := audit.Verify(events)
	if err != nil {
		return nil, "", err
	}
	return events, head, nil
}

func stalePublicationChainEvidence(now time.Time, maxEvidenceAge time.Duration, lifecycleReviewedAt, lifecycleExpiresAt, integrationReviewedAt, integrationExpiresAt, boundaryOccurredAt string) bool {
	parseTime := func(value string) (time.Time, error) {
		return time.Parse(time.RFC3339Nano, value)
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
	boundaryOccurred, err := parseTime(boundaryOccurredAt)
	if err != nil || boundaryOccurred.After(now) || now.Sub(boundaryOccurred) > maxEvidenceAge {
		return true
	}
	return false
}

func findCoverageAssertion(report catalogcoverage.Report, assertionID string) (catalogcoverage.AssertionCoverage, bool) {
	for _, assertion := range report.Spec.Assertions {
		if assertion.ID == assertionID {
			return assertion, true
		}
	}
	return catalogcoverage.AssertionCoverage{}, false
}

func writePublicationChainRehearsalFailure(output io.Writer, auditPath, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(auditPath, "publication.chain.rehearse", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}
