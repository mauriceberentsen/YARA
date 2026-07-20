package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"sort"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type publicationChainRetentionOptions struct {
	catalogPath, assertionRef string
	currentRehearsals         csvFlag
	candidateRehearsalPath    string
	auditPath                 string
}

type publicationChainRetentionState struct {
	RehearsalID string `json:"rehearsalId"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
}

func publicationChainRetentionDiagnostics(args []string, stdout, stderr io.Writer) int {
	options, ok := parsePublicationChainRetentionOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writePublicationChainRetentionFailure(stdout, options.auditPath, "catalog:unresolved", []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-PCR-201", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writePublicationChainRetentionFailure(stdout, options.auditPath, "catalog:unresolved", nil, "YARA-PCR-500", err, ExitInternal)
	}
	target := "catalog:" + catalogDigest
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	if _, found := findCatalogAssertion(snapshot, options.assertionRef); !found {
		return writePublicationChainRetentionFailure(stdout, options.auditPath, target, []audit.Subject{catalogSubject}, "YARA-PCR-202", errors.New("assertion reference is not present in the catalog"), ExitInvalidInput)
	}
	rehearsalPaths := uniqueSortedStrings(options.currentRehearsals)
	now := time.Now().UTC()
	subjects := []audit.Subject{catalogSubject}
	states := make([]publicationChainRetentionState, 0, len(rehearsalPaths))
	seenRehearsalIDs := map[string]struct{}{}
	latestRehearsedAt := time.Time{}
	for _, path := range rehearsalPaths {
		rehearsal, err := resources.LoadPublicationChainRehearsal(path)
		if err != nil || !rehearsal.Validate().Valid {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-203", errors.New("publication-chain rehearsal evidence is invalid"), ExitInvalidInput)
		}
		subjects = append(subjects, audit.Subject{Kind: "PublicationChainRehearsal", Digest: rehearsal.Metadata.RehearsalID})
		if rehearsal.Spec.CatalogDigest != catalogDigest || rehearsal.Spec.AssertionRef != options.assertionRef {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-204", errors.New("publication-chain rehearsal evidence is foreign to selected assertion scope"), ExitInfeasible)
		}
		if _, exists := seenRehearsalIDs[rehearsal.Metadata.RehearsalID]; exists {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-205", errors.New("duplicate publication-chain rehearsal identities are not allowed in retention diagnostics"), ExitInfeasible)
		}
		seenRehearsalIDs[rehearsal.Metadata.RehearsalID] = struct{}{}
		rehearsedAt, err := time.Parse(time.RFC3339Nano, rehearsal.Spec.RehearsedAt)
		if err != nil {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-206", errors.New("publication-chain rehearsal timestamp is invalid"), ExitInvalidInput)
		}
		maxEvidenceAge, err := time.ParseDuration(rehearsal.Spec.MaxEvidenceAge)
		if err != nil || maxEvidenceAge <= 0 {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-207", errors.New("publication-chain rehearsal max evidence age is invalid"), ExitInvalidInput)
		}
		if rehearsedAt.After(now) {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-208", errors.New("publication-chain rehearsal timestamp is in the future"), ExitInfeasible)
		}
		if rehearsedAt.After(latestRehearsedAt) {
			latestRehearsedAt = rehearsedAt
		}
		status := "renewable"
		reason := "within-retention-window"
		if rehearsal.Spec.Decision != resources.PromotionDecisionApproved {
			status = "non-renewable"
			reason = "decision-not-approved"
		} else if now.Sub(rehearsedAt) > maxEvidenceAge {
			status = "non-renewable"
			reason = "retention-window-expired"
		}
		states = append(states, publicationChainRetentionState{
			RehearsalID: rehearsal.Metadata.RehearsalID,
			Status:      status,
			Reason:      reason,
		})
	}
	var candidateID string
	if options.candidateRehearsalPath != "" {
		candidate, err := resources.LoadPublicationChainRehearsal(options.candidateRehearsalPath)
		if err != nil || !candidate.Validate().Valid {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-209", errors.New("candidate publication-chain rehearsal evidence is invalid"), ExitInvalidInput)
		}
		candidateID = candidate.Metadata.RehearsalID
		subjects = append(subjects, audit.Subject{Kind: "PublicationChainRehearsal", Digest: candidate.Metadata.RehearsalID})
		if candidate.Spec.CatalogDigest != catalogDigest || candidate.Spec.AssertionRef != options.assertionRef {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-210", errors.New("candidate publication-chain rehearsal is foreign to selected assertion scope"), ExitInfeasible)
		}
		if _, exists := seenRehearsalIDs[candidate.Metadata.RehearsalID]; exists {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-211", errors.New("candidate publication-chain rehearsal identity reuses historical reviewed identity"), ExitInfeasible)
		}
		candidateRehearsedAt, err := time.Parse(time.RFC3339Nano, candidate.Spec.RehearsedAt)
		if err != nil {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-206", errors.New("candidate publication-chain rehearsal timestamp is invalid"), ExitInvalidInput)
		}
		candidateMaxEvidenceAge, err := time.ParseDuration(candidate.Spec.MaxEvidenceAge)
		if err != nil || candidateMaxEvidenceAge <= 0 {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-207", errors.New("candidate publication-chain rehearsal max evidence age is invalid"), ExitInvalidInput)
		}
		if candidateRehearsedAt.After(now) || now.Sub(candidateRehearsedAt) > candidateMaxEvidenceAge {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-212", errors.New("candidate publication-chain rehearsal is stale for renewal"), ExitInfeasible)
		}
		if !latestRehearsedAt.IsZero() && (candidateRehearsedAt.Before(latestRehearsedAt) || candidateRehearsedAt.Equal(latestRehearsedAt)) {
			return writePublicationChainRetentionFailure(stdout, options.auditPath, target, subjects, "YARA-PCR-213", errors.New("candidate publication-chain rehearsal cannot overwrite or predate historical reviewed evidence"), ExitInfeasible)
		}
	}
	sort.Slice(subjects, func(i, j int) bool {
		if subjects[i].Kind != subjects[j].Kind {
			return subjects[i].Kind < subjects[j].Kind
		}
		return subjects[i].Digest < subjects[j].Digest
	})
	slices.SortFunc(states, func(left, right publicationChainRetentionState) int {
		switch {
		case left.RehearsalID < right.RehearsalID:
			return -1
		case left.RehearsalID > right.RehearsalID:
			return 1
		default:
			return 0
		}
	})
	if err := persistOperationAuditForTarget(options.auditPath, "publication.chain.retention-diagnostics", "completed", "success", target, subjects, nil); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":             true,
		"catalogDigest":     catalogDigest,
		"assertion":         options.assertionRef,
		"currentRehearsals": states,
		"candidateRehearsal": map[string]string{
			"rehearsalId": candidateID,
		},
		"auditOutput": options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parsePublicationChainRetentionOptions(args []string, stderr io.Writer) (publicationChainRetentionOptions, bool) {
	var options publicationChainRetentionOptions
	flags := flag.NewFlagSet("publication chain retention-diagnostics", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.assertionRef, "assertion", "", "Exact assertion ID to classify for retention diagnostics")
	flags.Var(&options.currentRehearsals, "current-rehearsal", "Current PublicationChainRehearsal YAML file (repeatable)")
	flags.StringVar(&options.candidateRehearsalPath, "candidate-rehearsal", "", "Optional candidate PublicationChainRehearsal YAML file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated publication-chain retention diagnostics audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.assertionRef == "" || len(options.currentRehearsals) == 0 || options.auditPath == "" {
		fmt.Fprintln(stderr, "publication chain retention-diagnostics requires --catalog --assertion --current-rehearsal --audit-output")
		return options, false
	}
	return options, true
}

func writePublicationChainRetentionFailure(output io.Writer, auditPath, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(auditPath, "publication.chain.retention-diagnostics", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}
