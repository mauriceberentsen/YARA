package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type catalogCoverageOptions struct {
	catalogPath string
	evidenceDir string
	name        string
	outputPath  string
	auditPath   string
}

type lifecyclePublicationPolicyOptions struct {
	reportPath string
	assertion  string
	auditPath  string
}

type runtimeDriftPolicyOptions struct {
	reportPath string
	assertion  string
	auditPath  string
}

type signingAuthorityBoundaryOptions struct {
	reportPath       string
	trustPolicyPath  string
	authorizationSet csvFlag
	auditPath        string
}

type integrationEvidenceConvergence struct {
	IdentityCount        int  `json:"identityCount"`
	DeduplicatedCount    int  `json:"deduplicatedCount"`
	DeduplicationApplied bool `json:"deduplicationApplied"`
}

type signingAuthorityBoundaryConvergence struct {
	Status         string `json:"status"`
	OverlapCount   int    `json:"overlapCount"`
	AmbiguityCount int    `json:"ambiguityCount"`
	Evaluated      bool   `json:"evaluated"`
}

type signingAuthorityBoundary struct {
	Status                   string   `json:"status"`
	GateSignerCount          int      `json:"gateSignerCount"`
	AuthorizationIssuerCount int      `json:"authorizationIssuerCount"`
	OverlapIdentities        []string `json:"overlapIdentities,omitempty"`
	AmbiguityDiagnostics     []string `json:"ambiguityDiagnostics,omitempty"`
}

type publicationChainRehearsalDiagnostics struct {
	Assertion         string `json:"assertion"`
	Status            string `json:"status"`
	Blocker           string `json:"blocker,omitempty"`
	SelectedRehearsal string `json:"selectedRehearsal,omitempty"`
}

type publicationChainRetentionPosture struct {
	Assertion         string `json:"assertion"`
	Status            string `json:"status"`
	Blocker           string `json:"blocker,omitempty"`
	SelectedRehearsal string `json:"selectedRehearsal,omitempty"`
}

type publicationChainRenewalReviewPosture struct {
	Assertion             string `json:"assertion"`
	Status                string `json:"status"`
	Blocker               string `json:"blocker,omitempty"`
	SelectedRenewalReview string `json:"selectedRenewalReview,omitempty"`
}

type artifactImportChainPosture struct {
	Assertion       string `json:"assertion"`
	Status          string `json:"status"`
	Blocker         string `json:"blocker,omitempty"`
	SelectedReceipt string `json:"selectedReceipt,omitempty"`
}

type runtimeDriftPosture struct {
	Assertion      string `json:"assertion"`
	Status         string `json:"status"`
	Blocker        string `json:"blocker,omitempty"`
	SelectedSignal string `json:"selectedSignal,omitempty"`
}

type runtimeDriftBlockedAssertion struct {
	Assertion   string `json:"assertion"`
	Status      string `json:"status"`
	Blocker     string `json:"blocker"`
	Remediation string `json:"remediation"`
}

func catalogCoverage(args []string, stdout, stderr io.Writer) int {
	options, ok := parseCatalogCoverageOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-COV-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeCatalogCoverageFailure(stdout, options, nil, "YARA-COV-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	report, err := catalogcoverage.Build(options.name, snapshot, options.evidenceDir)
	if err != nil {
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-COV-005", err, ExitInvalidInput)
	}
	if err := report.Validate(); err != nil {
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-COV-500", err, ExitInternal)
	}
	data, err := yaml.Marshal(report)
	if err != nil {
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-COV-500", fmt.Errorf("encode catalog coverage report: %w", err), ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject}, "YARA-COV-006", err, ExitInvalidInput)
	}
	reportSubject := audit.Subject{Kind: catalogcoverage.Kind, Digest: report.Metadata.ReportID}
	if err := persistOperationAudit(options.auditPath, "catalog.coverage", "completed", "success", []audit.Subject{catalogSubject, reportSubject}, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	convergence, err := integrationEvidenceConvergenceFromReport(report)
	if err != nil {
		_ = os.Remove(options.outputPath)
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject, reportSubject}, "YARA-COV-500", err, ExitInternal)
	}
	signingBoundary, err := signingAuthorityBoundaryFromReport(report)
	if err != nil {
		_ = os.Remove(options.outputPath)
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject, reportSubject}, "YARA-COV-500", err, ExitInternal)
	}
	retentionDiagnostics, err := publicationChainRetentionFromReport(report)
	if err != nil {
		_ = os.Remove(options.outputPath)
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject, reportSubject}, "YARA-COV-500", err, ExitInternal)
	}
	renewalDiagnostics, err := publicationChainRenewalReviewFromReport(report)
	if err != nil {
		_ = os.Remove(options.outputPath)
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject, reportSubject}, "YARA-COV-500", err, ExitInternal)
	}
	importChainDiagnostics, err := artifactImportChainFromReport(report)
	if err != nil {
		_ = os.Remove(options.outputPath)
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject, reportSubject}, "YARA-COV-500", err, ExitInternal)
	}
	runtimeDriftDiagnostics, err := runtimeDriftPostureFromReport(report)
	if err != nil {
		_ = os.Remove(options.outputPath)
		return writeCatalogCoverageFailure(stdout, options, []audit.Subject{catalogSubject, reportSubject}, "YARA-COV-500", err, ExitInternal)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid": true, "complete": report.Spec.Complete, "reportId": report.Metadata.ReportID,
		"output": options.outputPath, "auditOutput": options.auditPath, "summary": report.Spec.Summary,
		"lifecyclePublicationReadyAssertions":   report.Spec.Summary.LifecyclePublicationReadyAssertions,
		"lifecyclePublicationBlockedAssertions": report.Spec.Summary.LifecyclePublicationBlockedAssertions,
		"integrationEvidenceConvergence":        convergence,
		"signingAuthorityBoundary":              signingBoundary,
		"publicationChainRetention":             retentionDiagnostics,
		"publicationChainRenewalReview":         renewalDiagnostics,
		"artifactImportChain":                   importChainDiagnostics,
		"runtimeDriftPosture":                   runtimeDriftDiagnostics,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func explainLifecyclePublicationPolicy(args []string, stdout, stderr io.Writer) int {
	options, ok := parseLifecyclePublicationPolicyOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	report, err := catalogcoverage.Load(options.reportPath)
	if err != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "catalog.coverage.lifecycle-publication-policy", catalogcoverage.Kind, options.reportPath, "YARA-COV-004", err, nil)
	}
	subject := audit.Subject{Kind: catalogcoverage.Kind, Digest: report.Metadata.ReportID}
	filtered := make([]catalogcoverage.AssertionCoverage, 0, len(report.Spec.Assertions))
	for _, assertion := range report.Spec.Assertions {
		if options.assertion == "" || assertion.ID == options.assertion {
			filtered = append(filtered, assertion)
		}
	}
	if options.assertion != "" && len(filtered) == 0 {
		return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-007", errors.New("assertion is not present in catalog coverage report"), ExitInvalidInput)
	}
	convergence, err := integrationEvidenceConvergenceFromReport(report)
	if err != nil {
		return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", err, ExitInternal)
	}
	signingBoundary, err := signingAuthorityBoundaryFromReport(report)
	if err != nil {
		return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", err, ExitInternal)
	}
	retentionDiagnostics, err := publicationChainRetentionFromReport(report)
	if err != nil {
		return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", err, ExitInternal)
	}
	renewalDiagnostics, err := publicationChainRenewalReviewFromReport(report)
	if err != nil {
		return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", err, ExitInternal)
	}
	importChainDiagnostics, err := artifactImportChainFromReport(report)
	if err != nil {
		return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", err, ExitInternal)
	}
	runtimeDriftDiagnostics, err := runtimeDriftPostureFromReport(report)
	if err != nil {
		return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", err, ExitInternal)
	}
	blocked := []map[string]string{}
	rehearsalDiagnostics := []publicationChainRehearsalDiagnostics{}
	filteredRetentionDiagnostics := []publicationChainRetentionPosture{}
	filteredRenewalDiagnostics := []publicationChainRenewalReviewPosture{}
	filteredImportChainDiagnostics := []artifactImportChainPosture{}
	filteredRuntimeDriftDiagnostics := []runtimeDriftPosture{}
	for _, assertion := range filtered {
		rehearsalGate, found := findAssertionGate(assertion, "publication-chain-rehearsal")
		if !found {
			return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", fmt.Errorf("assertion %s does not include publication-chain rehearsal diagnostics gate", assertion.ID), ExitInternal)
		}
		rehearsalDiagnostics = append(rehearsalDiagnostics, publicationChainRehearsalDiagnostics{
			Assertion:         assertion.ID,
			Status:            rehearsalGate.Status,
			Blocker:           rehearsalGate.Blocker,
			SelectedRehearsal: rehearsalGate.SelectedResult,
		})
		retentionDiagnostic, found := findPublicationChainRetentionDiagnostic(retentionDiagnostics, assertion.ID)
		if !found {
			return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", fmt.Errorf("assertion %s does not include publication-chain retention diagnostics", assertion.ID), ExitInternal)
		}
		filteredRetentionDiagnostics = append(filteredRetentionDiagnostics, retentionDiagnostic)
		renewalDiagnostic, found := findPublicationChainRenewalReviewDiagnostic(renewalDiagnostics, assertion.ID)
		if !found {
			return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", fmt.Errorf("assertion %s does not include publication-chain renewal-review diagnostics", assertion.ID), ExitInternal)
		}
		filteredRenewalDiagnostics = append(filteredRenewalDiagnostics, renewalDiagnostic)
		importChainDiagnostic, found := findArtifactImportChainDiagnostic(importChainDiagnostics, assertion.ID)
		if found {
			filteredImportChainDiagnostics = append(filteredImportChainDiagnostics, importChainDiagnostic)
			if options.assertion != "" && importChainDiagnostic.Status != "passed" {
				return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-013", fmt.Errorf("assertion %s artifact import chain is not ready: %s", assertion.ID, importChainDiagnostic.Blocker), ExitInfeasible)
			}
		}
		runtimeDriftDiagnostic, found := findRuntimeDriftDiagnostic(runtimeDriftDiagnostics, assertion.ID)
		if !found {
			return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", fmt.Errorf("assertion %s does not include runtime drift posture diagnostics", assertion.ID), ExitInternal)
		}
		filteredRuntimeDriftDiagnostics = append(filteredRuntimeDriftDiagnostics, runtimeDriftDiagnostic)
		if options.assertion != "" && rehearsalGate.Status != "passed" {
			return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-012", fmt.Errorf("assertion %s publication-chain rehearsal is not ready: %s", assertion.ID, rehearsalGate.Blocker), ExitInfeasible)
		}
		if assertion.LifecyclePublicationReady {
			continue
		}
		parsedBlocker, parseErr := catalogcoverage.ParseLifecyclePublicationBlocker(assertion.LifecyclePublicationBlocker)
		if parseErr != nil {
			return writeCatalogCoveragePolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", fmt.Errorf("assertion %s has invalid lifecycle publication blocker: %w", assertion.ID, parseErr), ExitInternal)
		}
		blocked = append(blocked, map[string]string{
			"assertion":   assertion.ID,
			"blocker":     assertion.LifecyclePublicationBlocker,
			"code":        parsedBlocker.Code,
			"remediation": parsedBlocker.Remediation,
		})
	}
	sort.Slice(blocked, func(i, j int) bool { return blocked[i]["assertion"] < blocked[j]["assertion"] })
	sort.Slice(rehearsalDiagnostics, func(i, j int) bool { return rehearsalDiagnostics[i].Assertion < rehearsalDiagnostics[j].Assertion })
	sort.Slice(filteredRetentionDiagnostics, func(i, j int) bool {
		return filteredRetentionDiagnostics[i].Assertion < filteredRetentionDiagnostics[j].Assertion
	})
	sort.Slice(filteredRenewalDiagnostics, func(i, j int) bool {
		return filteredRenewalDiagnostics[i].Assertion < filteredRenewalDiagnostics[j].Assertion
	})
	sort.Slice(filteredImportChainDiagnostics, func(i, j int) bool {
		return filteredImportChainDiagnostics[i].Assertion < filteredImportChainDiagnostics[j].Assertion
	})
	sort.Slice(filteredRuntimeDriftDiagnostics, func(i, j int) bool {
		return filteredRuntimeDriftDiagnostics[i].Assertion < filteredRuntimeDriftDiagnostics[j].Assertion
	})
	if err := persistOperationAudit(options.auditPath, "catalog.coverage.lifecycle-publication-policy", "completed", "success", []audit.Subject{subject}, nil); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":                                 true,
		"reportId":                              report.Metadata.ReportID,
		"reportSubject":                         map[string]string{"kind": catalogcoverage.Kind, "digest": report.Metadata.ReportID},
		"assertionScope":                        lifecyclePublicationAssertionScope(options.assertion),
		"lifecyclePublicationReadyAssertions":   report.Spec.Summary.LifecyclePublicationReadyAssertions,
		"lifecyclePublicationBlockedAssertions": report.Spec.Summary.LifecyclePublicationBlockedAssertions,
		"integrationEvidenceConvergence":        convergence,
		"signingAuthorityBoundary":              signingBoundary,
		"publicationChainRehearsal":             rehearsalDiagnostics,
		"publicationChainRetention":             filteredRetentionDiagnostics,
		"publicationChainRenewalReview":         filteredRenewalDiagnostics,
		"artifactImportChain":                   filteredImportChainDiagnostics,
		"runtimeDriftPosture":                   filteredRuntimeDriftDiagnostics,
		"blockedAssertions":                     blocked,
		"taxonomy":                              catalogcoverage.LifecyclePublicationBlockerTaxonomy(),
		"auditOutput":                           options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func explainRuntimeDriftPolicy(args []string, stdout, stderr io.Writer) int {
	options, ok := parseRuntimeDriftPolicyOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	report, err := catalogcoverage.Load(options.reportPath)
	if err != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "catalog.coverage.runtime-drift-policy", catalogcoverage.Kind, options.reportPath, "YARA-COV-004", err, nil)
	}
	subject := audit.Subject{Kind: catalogcoverage.Kind, Digest: report.Metadata.ReportID}
	filtered := make([]catalogcoverage.AssertionCoverage, 0, len(report.Spec.Assertions))
	for _, assertion := range report.Spec.Assertions {
		if options.assertion == "" || assertion.ID == options.assertion {
			filtered = append(filtered, assertion)
		}
	}
	if options.assertion != "" && len(filtered) == 0 {
		return writeCatalogCoverageRuntimeDriftPolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-007", errors.New("assertion is not present in catalog coverage report"), ExitInvalidInput)
	}
	diagnostics, err := runtimeDriftPostureFromReport(report)
	if err != nil {
		return writeCatalogCoverageRuntimeDriftPolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", err, ExitInternal)
	}
	filteredDiagnostics := make([]runtimeDriftPosture, 0, len(filtered))
	blocked := make([]runtimeDriftBlockedAssertion, 0, len(filtered))
	for _, assertion := range filtered {
		diagnostic, found := findRuntimeDriftDiagnostic(diagnostics, assertion.ID)
		if !found {
			return writeCatalogCoverageRuntimeDriftPolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-500", fmt.Errorf("assertion %s does not include runtime drift posture diagnostics", assertion.ID), ExitInternal)
		}
		filteredDiagnostics = append(filteredDiagnostics, diagnostic)
		if diagnostic.Status == "in-sync" {
			continue
		}
		blocker := diagnostic.Blocker
		if blocker == "" {
			blocker = "runtime-drift-posture-" + diagnostic.Status
		}
		blocked = append(blocked, runtimeDriftBlockedAssertion{
			Assertion: assertion.ID, Status: diagnostic.Status, Blocker: blocker, Remediation: runtimeDriftRemediation(diagnostic.Status),
		})
	}
	sort.Slice(filteredDiagnostics, func(i, j int) bool { return filteredDiagnostics[i].Assertion < filteredDiagnostics[j].Assertion })
	sort.Slice(blocked, func(i, j int) bool { return blocked[i].Assertion < blocked[j].Assertion })
	if options.assertion != "" && len(blocked) > 0 {
		return writeCatalogCoverageRuntimeDriftPolicyFailure(stdout, options.auditPath, []audit.Subject{subject}, "YARA-COV-014", fmt.Errorf("assertion %s runtime drift posture is not in-sync: %s", blocked[0].Assertion, blocked[0].Blocker), ExitInfeasible)
	}
	if err := persistOperationAudit(options.auditPath, "catalog.coverage.runtime-drift-policy", "completed", "success", []audit.Subject{subject}, nil); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":               true,
		"policyPassed":        len(blocked) == 0,
		"reportId":            report.Metadata.ReportID,
		"reportSubject":       map[string]string{"kind": catalogcoverage.Kind, "digest": report.Metadata.ReportID},
		"assertionScope":      lifecyclePublicationAssertionScope(options.assertion),
		"runtimeDriftPosture": filteredDiagnostics,
		"blockedAssertions":   blocked,
		"auditOutput":         options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func findAssertionGate(assertion catalogcoverage.AssertionCoverage, gateID string) (catalogcoverage.GateCoverage, bool) {
	for _, gate := range assertion.Gates {
		if gate.ID == gateID {
			return gate, true
		}
	}
	return catalogcoverage.GateCoverage{}, false
}

func explainSigningAuthorityBoundaryPolicy(args []string, stdout, stderr io.Writer) int {
	options, ok := parseSigningAuthorityBoundaryOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	report, err := catalogcoverage.Load(options.reportPath)
	if err != nil {
		return writeCatalogCoverageBoundaryFailure(stdout, options.auditPath, nil, "YARA-COV-004", err, ExitInvalidInput)
	}
	reportSubject := audit.Subject{Kind: catalogcoverage.Kind, Digest: report.Metadata.ReportID}
	trustPolicy, err := resources.LoadAirgapGateTrustPolicy(options.trustPolicyPath)
	if err != nil || !trustPolicy.Validate().Valid {
		return writeCatalogCoverageBoundaryFailure(stdout, options.auditPath, []audit.Subject{reportSubject}, "YARA-COV-008", errors.New("air-gap gate trust policy is invalid"), ExitInvalidInput)
	}
	authorizationPaths := uniqueSortedStrings(options.authorizationSet)
	authorizations := make([]resources.ExecutionAuthorization, 0, len(authorizationPaths))
	authorizationSubjects := make([]audit.Subject, 0, len(authorizationPaths))
	for _, path := range authorizationPaths {
		authorization, loadErr := resources.LoadExecutionAuthorization(path)
		if loadErr != nil || !authorization.Validate().Valid {
			return writeCatalogCoverageBoundaryFailure(stdout, options.auditPath, []audit.Subject{reportSubject, {Kind: "AirgapGateTrustPolicy", Digest: trustPolicy.Metadata.PolicyID}}, "YARA-COV-009", errors.New("deployment authorization evidence is invalid"), ExitInvalidInput)
		}
		authorizations = append(authorizations, authorization)
		authorizationSubjects = append(authorizationSubjects, audit.Subject{Kind: "ExecutionAuthorization", Digest: authorization.Metadata.AuthorizationID})
	}
	boundary := evaluateSigningAuthorityBoundary(trustPolicy, authorizations)
	subjects := []audit.Subject{reportSubject, {Kind: "AirgapGateTrustPolicy", Digest: trustPolicy.Metadata.PolicyID}}
	subjects = append(subjects, authorizationSubjects...)
	sort.Slice(subjects, func(i, j int) bool {
		if subjects[i].Kind != subjects[j].Kind {
			return subjects[i].Kind < subjects[j].Kind
		}
		return subjects[i].Digest < subjects[j].Digest
	})
	if boundary.Status != "independent" {
		code := "YARA-COV-010"
		err := errors.New("signing-authority boundary is not independent")
		if len(boundary.AmbiguityDiagnostics) > 0 {
			code = "YARA-COV-011"
			err = errors.New("signing-authority boundary is ambiguous")
		}
		return writeCatalogCoverageBoundaryFailure(stdout, options.auditPath, subjects, code, err, ExitInfeasible)
	}
	if err := persistOperationAudit(options.auditPath, "catalog.coverage.signing-authority-boundary", "completed", "success", subjects, nil); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	authorizationIDs := make([]string, 0, len(authorizations))
	for _, authorization := range authorizations {
		authorizationIDs = append(authorizationIDs, authorization.Metadata.AuthorizationID)
	}
	sort.Strings(authorizationIDs)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":                    true,
		"reportId":                 report.Metadata.ReportID,
		"reportSubject":            map[string]string{"kind": catalogcoverage.Kind, "digest": report.Metadata.ReportID},
		"trustPolicyId":            trustPolicy.Metadata.PolicyID,
		"authorizationIds":         authorizationIDs,
		"signingAuthorityBoundary": boundary,
		"auditOutput":              options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseLifecyclePublicationPolicyOptions(args []string, stderr io.Writer) (lifecyclePublicationPolicyOptions, bool) {
	var options lifecyclePublicationPolicyOptions
	flags := flag.NewFlagSet("catalog coverage lifecycle-publication-policy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.reportPath, "report", "", "CatalogCoverageReport YAML file")
	flags.StringVar(&options.assertion, "assertion", "", "Optional exact assertion ID to inspect")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated lifecycle publication policy audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.reportPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "catalog coverage lifecycle-publication-policy requires --report and --audit-output")
		return options, false
	}
	return options, true
}

func parseRuntimeDriftPolicyOptions(args []string, stderr io.Writer) (runtimeDriftPolicyOptions, bool) {
	var options runtimeDriftPolicyOptions
	flags := flag.NewFlagSet("catalog coverage runtime-drift-policy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.reportPath, "report", "", "CatalogCoverageReport YAML file")
	flags.StringVar(&options.assertion, "assertion", "", "Optional exact assertion ID to inspect")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated runtime drift policy audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.reportPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "catalog coverage runtime-drift-policy requires --report and --audit-output")
		return options, false
	}
	return options, true
}

func parseSigningAuthorityBoundaryOptions(args []string, stderr io.Writer) (signingAuthorityBoundaryOptions, bool) {
	var options signingAuthorityBoundaryOptions
	flags := flag.NewFlagSet("catalog coverage signing-authority-boundary", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.reportPath, "report", "", "CatalogCoverageReport YAML file")
	flags.StringVar(&options.trustPolicyPath, "trust-policy", "", "AirgapGateTrustPolicy YAML file")
	flags.Var(&options.authorizationSet, "authorization", "ExecutionAuthorization YAML file (repeatable)")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated signing-authority boundary audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.reportPath == "" || options.trustPolicyPath == "" || len(options.authorizationSet) == 0 || options.auditPath == "" {
		fmt.Fprintln(stderr, "catalog coverage signing-authority-boundary requires --report --trust-policy --authorization --audit-output")
		return options, false
	}
	return options, true
}

func lifecyclePublicationAssertionScope(assertion string) map[string]string {
	if assertion == "" {
		return map[string]string{"mode": "all"}
	}
	return map[string]string{"mode": "single-assertion", "assertion": assertion}
}

func integrationEvidenceConvergenceFromReport(report catalogcoverage.Report) (integrationEvidenceConvergence, error) {
	const prefix = "integration-evidence-convergence:"
	found := ""
	for _, limitation := range report.Spec.Limitations {
		if strings.HasPrefix(limitation, prefix) {
			if found != "" {
				return integrationEvidenceConvergence{}, errors.New("catalog coverage report contains multiple integration convergence limitation records")
			}
			found = limitation
		}
	}
	if found == "" {
		return integrationEvidenceConvergence{}, errors.New("catalog coverage report does not include integration convergence limitation record")
	}
	body := strings.TrimPrefix(found, prefix)
	parts := strings.Split(body, ",")
	if len(parts) != 2 {
		return integrationEvidenceConvergence{}, errors.New("integration convergence limitation record is malformed")
	}
	values := map[string]int{}
	for _, part := range parts {
		keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(keyValue) != 2 {
			return integrationEvidenceConvergence{}, errors.New("integration convergence limitation record contains invalid key-value pairs")
		}
		value, err := strconv.Atoi(strings.TrimSpace(keyValue[1]))
		if err != nil || value < 0 {
			return integrationEvidenceConvergence{}, errors.New("integration convergence limitation record contains invalid count values")
		}
		values[strings.TrimSpace(keyValue[0])] = value
	}
	identityCount, ok := values["identity-count"]
	if !ok {
		return integrationEvidenceConvergence{}, errors.New("integration convergence limitation record omits identity-count")
	}
	deduplicatedCount, ok := values["deduplicated-count"]
	if !ok {
		return integrationEvidenceConvergence{}, errors.New("integration convergence limitation record omits deduplicated-count")
	}
	return integrationEvidenceConvergence{
		IdentityCount:        identityCount,
		DeduplicatedCount:    deduplicatedCount,
		DeduplicationApplied: deduplicatedCount > 0,
	}, nil
}

func signingAuthorityBoundaryFromReport(report catalogcoverage.Report) (signingAuthorityBoundaryConvergence, error) {
	const prefix = "signing-authority-boundary:"
	found := ""
	for _, limitation := range report.Spec.Limitations {
		if strings.HasPrefix(limitation, prefix) {
			if found != "" {
				return signingAuthorityBoundaryConvergence{}, errors.New("catalog coverage report contains multiple signing-authority boundary limitation records")
			}
			found = limitation
		}
	}
	if found == "" {
		return signingAuthorityBoundaryConvergence{}, errors.New("catalog coverage report does not include signing-authority boundary limitation record")
	}
	body := strings.TrimPrefix(found, prefix)
	parts := strings.Split(body, ",")
	if len(parts) != 3 {
		return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record is malformed")
	}
	values := map[string]string{}
	for _, part := range parts {
		keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(keyValue) != 2 {
			return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record contains invalid key-value pairs")
		}
		key := strings.TrimSpace(keyValue[0])
		if _, exists := values[key]; exists {
			return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record contains duplicate keys")
		}
		values[key] = strings.TrimSpace(keyValue[1])
	}
	status, ok := values["status"]
	if !ok {
		return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record omits status")
	}
	if status != "not-evaluated" && status != "independent" && status != "overlap" && status != "ambiguous" {
		return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record has unsupported status")
	}
	overlapValue, ok := values["overlap-count"]
	if !ok {
		return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record omits overlap-count")
	}
	overlapCount, err := strconv.Atoi(overlapValue)
	if err != nil || overlapCount < 0 {
		return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record has invalid overlap-count")
	}
	ambiguityValue, ok := values["ambiguity-count"]
	if !ok {
		return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record omits ambiguity-count")
	}
	ambiguityCount, err := strconv.Atoi(ambiguityValue)
	if err != nil || ambiguityCount < 0 {
		return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record has invalid ambiguity-count")
	}
	switch status {
	case "not-evaluated", "independent":
		if overlapCount != 0 || ambiguityCount != 0 {
			return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record has inconsistent counts for status")
		}
	case "overlap":
		if overlapCount == 0 || ambiguityCount != 0 {
			return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record has inconsistent overlap status counts")
		}
	case "ambiguous":
		if ambiguityCount == 0 {
			return signingAuthorityBoundaryConvergence{}, errors.New("signing-authority boundary limitation record has inconsistent ambiguity status counts")
		}
	}
	return signingAuthorityBoundaryConvergence{
		Status:         status,
		OverlapCount:   overlapCount,
		AmbiguityCount: ambiguityCount,
		Evaluated:      status != "not-evaluated",
	}, nil
}

func publicationChainRetentionFromReport(report catalogcoverage.Report) ([]publicationChainRetentionPosture, error) {
	const prefix = "publication-chain-retention:"
	byAssertion := map[string]publicationChainRetentionPosture{}
	for _, limitation := range report.Spec.Limitations {
		if !strings.HasPrefix(limitation, prefix) {
			continue
		}
		body := strings.TrimPrefix(limitation, prefix)
		parts := strings.Split(body, ",")
		if len(parts) != 4 {
			return nil, errors.New("publication-chain retention limitation record is malformed")
		}
		values := map[string]string{}
		for _, part := range parts {
			keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(keyValue) != 2 {
				return nil, errors.New("publication-chain retention limitation record contains invalid key-value pairs")
			}
			key := strings.TrimSpace(keyValue[0])
			if _, exists := values[key]; exists {
				return nil, errors.New("publication-chain retention limitation record contains duplicate keys")
			}
			values[key] = strings.TrimSpace(keyValue[1])
		}
		assertionID, ok := values["assertion"]
		if !ok || assertionID == "" {
			return nil, errors.New("publication-chain retention limitation record omits assertion")
		}
		status, ok := values["status"]
		if !ok || (status != "renewable" && status != "non-renewable") {
			return nil, errors.New("publication-chain retention limitation record has unsupported status")
		}
		selectedRehearsal, ok := values["selected-rehearsal"]
		if !ok || selectedRehearsal == "" {
			return nil, errors.New("publication-chain retention limitation record omits selected-rehearsal")
		}
		if selectedRehearsal != "none" && (!strings.HasPrefix(selectedRehearsal, "sha256:") || len(selectedRehearsal) != 71) {
			return nil, errors.New("publication-chain retention limitation record contains invalid selected-rehearsal identity")
		}
		blocker, ok := values["blocker"]
		if !ok || blocker == "" {
			return nil, errors.New("publication-chain retention limitation record omits blocker")
		}
		if _, exists := byAssertion[assertionID]; exists {
			return nil, errors.New("catalog coverage report contains duplicate publication-chain retention limitation records for one assertion")
		}
		diagnostic := publicationChainRetentionPosture{
			Assertion: assertionID,
			Status:    status,
		}
		if blocker != "none" {
			diagnostic.Blocker = blocker
		}
		if selectedRehearsal != "none" {
			diagnostic.SelectedRehearsal = selectedRehearsal
		}
		byAssertion[assertionID] = diagnostic
	}
	if len(byAssertion) != len(report.Spec.Assertions) {
		return nil, errors.New("catalog coverage report does not include publication-chain retention limitation records for each assertion")
	}
	result := make([]publicationChainRetentionPosture, 0, len(report.Spec.Assertions))
	for _, assertion := range report.Spec.Assertions {
		retentionDiagnostic, ok := byAssertion[assertion.ID]
		if !ok {
			return nil, errors.New("catalog coverage report is missing publication-chain retention limitation for assertion")
		}
		rehearsalGate, found := findAssertionGate(assertion, "publication-chain-rehearsal")
		if !found {
			return nil, errors.New("catalog coverage assertion is missing publication-chain rehearsal gate")
		}
		expectedStatus := "non-renewable"
		if rehearsalGate.Status == "passed" {
			expectedStatus = "renewable"
		}
		if retentionDiagnostic.Status != expectedStatus {
			return nil, errors.New("publication-chain retention limitation status is inconsistent with rehearsal gate status")
		}
		expectedSelectedRehearsal := rehearsalGate.SelectedResult
		if expectedSelectedRehearsal == "" {
			expectedSelectedRehearsal = "none"
		}
		actualSelectedRehearsal := retentionDiagnostic.SelectedRehearsal
		if actualSelectedRehearsal == "" {
			actualSelectedRehearsal = "none"
		}
		if actualSelectedRehearsal != expectedSelectedRehearsal {
			return nil, errors.New("publication-chain retention limitation selected-rehearsal is inconsistent with rehearsal gate selection")
		}
		expectedBlocker := rehearsalGate.Blocker
		if expectedBlocker == "" {
			expectedBlocker = "none"
		}
		actualBlocker := retentionDiagnostic.Blocker
		if actualBlocker == "" {
			actualBlocker = "none"
		}
		if actualBlocker != expectedBlocker {
			return nil, errors.New("publication-chain retention limitation blocker is inconsistent with rehearsal gate blocker")
		}
		result = append(result, retentionDiagnostic)
	}
	return result, nil
}

func findPublicationChainRetentionDiagnostic(diagnostics []publicationChainRetentionPosture, assertionID string) (publicationChainRetentionPosture, bool) {
	for _, diagnostic := range diagnostics {
		if diagnostic.Assertion == assertionID {
			return diagnostic, true
		}
	}
	return publicationChainRetentionPosture{}, false
}

func publicationChainRenewalReviewFromReport(report catalogcoverage.Report) ([]publicationChainRenewalReviewPosture, error) {
	const prefix = "publication-chain-renewal-review:"
	byAssertion := map[string]publicationChainRenewalReviewPosture{}
	for _, limitation := range report.Spec.Limitations {
		if !strings.HasPrefix(limitation, prefix) {
			continue
		}
		body := strings.TrimPrefix(limitation, prefix)
		parts := strings.Split(body, ",")
		if len(parts) != 4 {
			return nil, errors.New("publication-chain renewal-review limitation record is malformed")
		}
		values := map[string]string{}
		for _, part := range parts {
			keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(keyValue) != 2 {
				return nil, errors.New("publication-chain renewal-review limitation record contains invalid key-value pairs")
			}
			key := strings.TrimSpace(keyValue[0])
			if _, exists := values[key]; exists {
				return nil, errors.New("publication-chain renewal-review limitation record contains duplicate keys")
			}
			values[key] = strings.TrimSpace(keyValue[1])
		}
		assertionID, ok := values["assertion"]
		if !ok || assertionID == "" {
			return nil, errors.New("publication-chain renewal-review limitation record omits assertion")
		}
		status, ok := values["status"]
		if !ok || (status != "missing" && status != "failed" && status != "blocked" && status != "passed") {
			return nil, errors.New("publication-chain renewal-review limitation record has unsupported status")
		}
		selectedRenewalReview, ok := values["selected-renewal-review"]
		if !ok || selectedRenewalReview == "" {
			return nil, errors.New("publication-chain renewal-review limitation record omits selected-renewal-review")
		}
		if selectedRenewalReview != "none" && (!strings.HasPrefix(selectedRenewalReview, "sha256:") || len(selectedRenewalReview) != 71) {
			return nil, errors.New("publication-chain renewal-review limitation record contains invalid selected-renewal-review identity")
		}
		blocker, ok := values["blocker"]
		if !ok || blocker == "" {
			return nil, errors.New("publication-chain renewal-review limitation record omits blocker")
		}
		if _, exists := byAssertion[assertionID]; exists {
			return nil, errors.New("catalog coverage report contains duplicate publication-chain renewal-review limitation records for one assertion")
		}
		diagnostic := publicationChainRenewalReviewPosture{
			Assertion: assertionID,
			Status:    status,
		}
		if blocker != "none" {
			diagnostic.Blocker = blocker
		}
		if selectedRenewalReview != "none" {
			diagnostic.SelectedRenewalReview = selectedRenewalReview
		}
		byAssertion[assertionID] = diagnostic
	}
	if len(byAssertion) != len(report.Spec.Assertions) {
		return nil, errors.New("catalog coverage report does not include publication-chain renewal-review limitation records for each assertion")
	}
	result := make([]publicationChainRenewalReviewPosture, 0, len(report.Spec.Assertions))
	for _, assertion := range report.Spec.Assertions {
		renewalDiagnostic, ok := byAssertion[assertion.ID]
		if !ok {
			return nil, errors.New("catalog coverage report is missing publication-chain renewal-review limitation for assertion")
		}
		renewalGate, found := findAssertionGate(assertion, "publication-chain-renewal-review")
		if !found {
			return nil, errors.New("catalog coverage assertion is missing publication-chain renewal-review gate")
		}
		if renewalDiagnostic.Status != renewalGate.Status {
			return nil, errors.New("publication-chain renewal-review limitation status is inconsistent with renewal-review gate status")
		}
		expectedSelectedRenewalReview := renewalGate.SelectedResult
		if expectedSelectedRenewalReview == "" {
			expectedSelectedRenewalReview = "none"
		}
		actualSelectedRenewalReview := renewalDiagnostic.SelectedRenewalReview
		if actualSelectedRenewalReview == "" {
			actualSelectedRenewalReview = "none"
		}
		if actualSelectedRenewalReview != expectedSelectedRenewalReview {
			return nil, errors.New("publication-chain renewal-review limitation selected-renewal-review is inconsistent with renewal-review gate selection")
		}
		expectedBlocker := renewalGate.Blocker
		if expectedBlocker == "" {
			expectedBlocker = "none"
		}
		actualBlocker := renewalDiagnostic.Blocker
		if actualBlocker == "" {
			actualBlocker = "none"
		}
		if actualBlocker != expectedBlocker {
			return nil, errors.New("publication-chain renewal-review limitation blocker is inconsistent with renewal-review gate blocker")
		}
		lifecycleGate, found := findAssertionGate(assertion, "lifecycle-proof-publication-approval")
		if !found {
			return nil, errors.New("catalog coverage assertion is missing lifecycle publication gate")
		}
		integrationGate, found := findAssertionGate(assertion, "integration-publication-attestation")
		if !found {
			return nil, errors.New("catalog coverage assertion is missing integration publication gate")
		}
		rehearsalGate, found := findAssertionGate(assertion, "publication-chain-rehearsal")
		if !found {
			return nil, errors.New("catalog coverage assertion is missing publication-chain rehearsal gate")
		}
		if renewalDiagnostic.Status == "passed" {
			if lifecycleGate.SelectedResult == "" || integrationGate.SelectedResult == "" || rehearsalGate.SelectedResult == "" {
				return nil, errors.New("publication-chain renewal-review diagnostics passed without selected lifecycle/integration/rehearsal evidence identities")
			}
		}
		result = append(result, renewalDiagnostic)
	}
	return result, nil
}

func findPublicationChainRenewalReviewDiagnostic(diagnostics []publicationChainRenewalReviewPosture, assertionID string) (publicationChainRenewalReviewPosture, bool) {
	for _, diagnostic := range diagnostics {
		if diagnostic.Assertion == assertionID {
			return diagnostic, true
		}
	}
	return publicationChainRenewalReviewPosture{}, false
}

func artifactImportChainFromReport(report catalogcoverage.Report) ([]artifactImportChainPosture, error) {
	const prefix = "artifact-import-chain:"
	byAssertion := map[string]artifactImportChainPosture{}
	for _, limitation := range report.Spec.Limitations {
		if !strings.HasPrefix(limitation, prefix) {
			continue
		}
		body := strings.TrimPrefix(limitation, prefix)
		parts := strings.Split(body, ",")
		if len(parts) != 4 {
			return nil, errors.New("artifact import-chain limitation record is malformed")
		}
		values := map[string]string{}
		for _, part := range parts {
			keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(keyValue) != 2 {
				return nil, errors.New("artifact import-chain limitation record contains invalid key-value pairs")
			}
			key := strings.TrimSpace(keyValue[0])
			if _, exists := values[key]; exists {
				return nil, errors.New("artifact import-chain limitation record contains duplicate keys")
			}
			values[key] = strings.TrimSpace(keyValue[1])
		}
		assertionID, ok := values["assertion"]
		if !ok || assertionID == "" {
			return nil, errors.New("artifact import-chain limitation record omits assertion")
		}
		status, ok := values["status"]
		if !ok || (status != "missing" && status != "failed" && status != "blocked" && status != "passed") {
			return nil, errors.New("artifact import-chain limitation record has unsupported status")
		}
		selectedReceipt, ok := values["selected-receipt"]
		if !ok || selectedReceipt == "" {
			return nil, errors.New("artifact import-chain limitation record omits selected-receipt")
		}
		if selectedReceipt != "none" && (!strings.HasPrefix(selectedReceipt, "sha256:") || len(selectedReceipt) != 71) {
			return nil, errors.New("artifact import-chain limitation record contains invalid selected-receipt identity")
		}
		blocker, ok := values["blocker"]
		if !ok || blocker == "" {
			return nil, errors.New("artifact import-chain limitation record omits blocker")
		}
		if _, exists := byAssertion[assertionID]; exists {
			return nil, errors.New("catalog coverage report contains duplicate artifact import-chain limitation records for one assertion")
		}
		diagnostic := artifactImportChainPosture{
			Assertion: assertionID,
			Status:    status,
		}
		if blocker != "none" {
			diagnostic.Blocker = blocker
		}
		if selectedReceipt != "none" {
			diagnostic.SelectedReceipt = selectedReceipt
		}
		byAssertion[assertionID] = diagnostic
	}
	result := []artifactImportChainPosture{}
	for _, assertion := range report.Spec.Assertions {
		importGate, found := findAssertionGate(assertion, "artifact-import-chain")
		if !found {
			continue
		}
		importDiagnostic, ok := byAssertion[assertion.ID]
		if !ok {
			return nil, errors.New("catalog coverage report is missing artifact import-chain limitation for assertion")
		}
		if importDiagnostic.Status != importGate.Status {
			return nil, errors.New("artifact import-chain limitation status is inconsistent with import-chain gate status")
		}
		expectedSelected := importGate.SelectedResult
		if expectedSelected == "" {
			expectedSelected = "none"
		}
		actualSelected := importDiagnostic.SelectedReceipt
		if actualSelected == "" {
			actualSelected = "none"
		}
		if actualSelected != expectedSelected {
			return nil, errors.New("artifact import-chain limitation selected-receipt is inconsistent with import-chain gate selection")
		}
		expectedBlocker := importGate.Blocker
		if expectedBlocker == "" {
			expectedBlocker = "none"
		}
		actualBlocker := importDiagnostic.Blocker
		if actualBlocker == "" {
			actualBlocker = "none"
		}
		if actualBlocker != expectedBlocker {
			return nil, errors.New("artifact import-chain limitation blocker is inconsistent with import-chain gate blocker")
		}
		result = append(result, importDiagnostic)
	}
	return result, nil
}

func findArtifactImportChainDiagnostic(diagnostics []artifactImportChainPosture, assertionID string) (artifactImportChainPosture, bool) {
	for _, diagnostic := range diagnostics {
		if diagnostic.Assertion == assertionID {
			return diagnostic, true
		}
	}
	return artifactImportChainPosture{}, false
}

func runtimeDriftPostureFromReport(report catalogcoverage.Report) ([]runtimeDriftPosture, error) {
	const prefix = "runtime-drift-posture:"
	byAssertion := map[string]runtimeDriftPosture{}
	for _, limitation := range report.Spec.Limitations {
		if !strings.HasPrefix(limitation, prefix) {
			continue
		}
		body := strings.TrimPrefix(limitation, prefix)
		parts := strings.Split(body, ",")
		if len(parts) != 4 {
			return nil, errors.New("runtime drift posture limitation record is malformed")
		}
		values := map[string]string{}
		for _, part := range parts {
			keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(keyValue) != 2 {
				return nil, errors.New("runtime drift posture limitation record contains invalid key-value pairs")
			}
			key := strings.TrimSpace(keyValue[0])
			if _, exists := values[key]; exists {
				return nil, errors.New("runtime drift posture limitation record contains duplicate keys")
			}
			values[key] = strings.TrimSpace(keyValue[1])
		}
		assertionID, ok := values["assertion"]
		if !ok || assertionID == "" {
			return nil, errors.New("runtime drift posture limitation record omits assertion")
		}
		status, ok := values["status"]
		if !ok || (status != "missing" && status != "in-sync" && status != "drifted") {
			return nil, errors.New("runtime drift posture limitation record has unsupported status")
		}
		selectedSignal, ok := values["selected-signal"]
		if !ok || selectedSignal == "" {
			return nil, errors.New("runtime drift posture limitation record omits selected-signal")
		}
		if selectedSignal != "none" && (!strings.HasPrefix(selectedSignal, "sha256:") || len(selectedSignal) != 71) {
			return nil, errors.New("runtime drift posture limitation record contains invalid selected-signal identity")
		}
		blocker, ok := values["blocker"]
		if !ok || blocker == "" {
			return nil, errors.New("runtime drift posture limitation record omits blocker")
		}
		if _, exists := byAssertion[assertionID]; exists {
			return nil, errors.New("catalog coverage report contains duplicate runtime drift posture limitation records for one assertion")
		}
		diagnostic := runtimeDriftPosture{Assertion: assertionID, Status: status}
		if blocker != "none" {
			diagnostic.Blocker = blocker
		}
		if selectedSignal != "none" {
			diagnostic.SelectedSignal = selectedSignal
		}
		byAssertion[assertionID] = diagnostic
	}
	if len(byAssertion) != len(report.Spec.Assertions) {
		return nil, errors.New("catalog coverage report does not include runtime drift posture limitation records for each assertion")
	}
	result := make([]runtimeDriftPosture, 0, len(report.Spec.Assertions))
	for _, assertion := range report.Spec.Assertions {
		diagnostic, ok := byAssertion[assertion.ID]
		if !ok {
			return nil, errors.New("catalog coverage report is missing runtime drift posture limitation for assertion")
		}
		result = append(result, diagnostic)
	}
	return result, nil
}

func findRuntimeDriftDiagnostic(diagnostics []runtimeDriftPosture, assertionID string) (runtimeDriftPosture, bool) {
	for _, diagnostic := range diagnostics {
		if diagnostic.Assertion == assertionID {
			return diagnostic, true
		}
	}
	return runtimeDriftPosture{}, false
}

func writeCatalogCoveragePolicyFailure(output io.Writer, auditPath string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAudit(auditPath, "catalog.coverage.lifecycle-publication-policy", "failed", "failed", subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}

func writeCatalogCoverageRuntimeDriftPolicyFailure(output io.Writer, auditPath string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAudit(auditPath, "catalog.coverage.runtime-drift-policy", "failed", "failed", subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}

func runtimeDriftRemediation(status string) string {
	switch status {
	case "missing":
		return "record-runtime-drift-signal"
	case "drifted":
		return "resolve-runtime-drift-and-rerecord-signal"
	default:
		return "none"
	}
}

func writeCatalogCoverageBoundaryFailure(output io.Writer, auditPath string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAudit(auditPath, "catalog.coverage.signing-authority-boundary", "failed", "failed", subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}

func evaluateSigningAuthorityBoundary(trustPolicy resources.AirgapGateTrustPolicy, authorizations []resources.ExecutionAuthorization) signingAuthorityBoundary {
	type signerIdentity struct {
		keyID  string
		digest string
	}
	formatIdentity := func(identity signerIdentity) string {
		return identity.keyID + "|" + identity.digest
	}
	gateIdentities := []signerIdentity{}
	for _, signer := range trustPolicy.Spec.TrustedSignerIdentities {
		if signer.Status == "active" {
			gateIdentities = append(gateIdentities, signerIdentity{keyID: signer.KeyID, digest: signer.PublicKeyDigest})
		}
	}
	authIdentities := []signerIdentity{}
	for _, authorization := range authorizations {
		authIdentities = append(authIdentities, signerIdentity{keyID: authorization.Spec.Issuer.KeyID, digest: authorization.Spec.Issuer.PublicKeyDigest})
	}
	ambiguities := []string{}
	keyRoleGate := map[string]string{}
	keyRoleAuth := map[string]string{}
	digestRoleGate := map[string]string{}
	digestRoleAuth := map[string]string{}
	for _, identity := range gateIdentities {
		if existing, ok := keyRoleGate[identity.keyID]; ok && existing != identity.digest {
			ambiguities = append(ambiguities, "gate-signer-key-id-reused-with-different-digest:"+identity.keyID)
		}
		keyRoleGate[identity.keyID] = identity.digest
		if existing, ok := digestRoleGate[identity.digest]; ok && existing != identity.keyID {
			ambiguities = append(ambiguities, "gate-signer-digest-reused-with-different-key-id:"+identity.digest)
		}
		digestRoleGate[identity.digest] = identity.keyID
	}
	for _, identity := range authIdentities {
		if existing, ok := keyRoleAuth[identity.keyID]; ok && existing != identity.digest {
			ambiguities = append(ambiguities, "authorization-key-id-reused-with-different-digest:"+identity.keyID)
		}
		keyRoleAuth[identity.keyID] = identity.digest
		if existing, ok := digestRoleAuth[identity.digest]; ok && existing != identity.keyID {
			ambiguities = append(ambiguities, "authorization-digest-reused-with-different-key-id:"+identity.digest)
		}
		digestRoleAuth[identity.digest] = identity.keyID
	}
	for keyID, digest := range keyRoleGate {
		if authDigest, ok := keyRoleAuth[keyID]; ok && authDigest != digest {
			ambiguities = append(ambiguities, "cross-role-key-id-reused-with-different-digest:"+keyID)
		}
	}
	for digest, keyID := range digestRoleGate {
		if authKeyID, ok := digestRoleAuth[digest]; ok && authKeyID != keyID {
			ambiguities = append(ambiguities, "cross-role-digest-reused-with-different-key-id:"+digest)
		}
	}
	sort.Strings(ambiguities)
	ambiguities = uniqueSortedStrings(ambiguities)
	overlaps := []string{}
	for _, gateIdentity := range gateIdentities {
		for _, authorizationIdentity := range authIdentities {
			if gateIdentity.digest == authorizationIdentity.digest {
				overlaps = append(overlaps, formatIdentity(gateIdentity))
				break
			}
		}
	}
	sort.Strings(overlaps)
	overlaps = uniqueSortedStrings(overlaps)
	status := "independent"
	if len(ambiguities) > 0 {
		status = "ambiguous"
	} else if len(overlaps) > 0 {
		status = "overlap"
	}
	return signingAuthorityBoundary{
		Status:                   status,
		GateSignerCount:          len(gateIdentities),
		AuthorizationIssuerCount: len(authIdentities),
		OverlapIdentities:        overlaps,
		AmbiguityDiagnostics:     ambiguities,
	}
}

func validateCatalogCoverage(args []string, stdout, stderr io.Writer) int {
	options, ok := parseValidationOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	report, err := catalogcoverage.Load(options.inputPath)
	if err != nil {
		return writeAuditedLoadError(stdout, options.auditPath, "catalog.coverage.validate", catalogcoverage.Kind, options.inputPath, "YARA-COV-004", err, nil)
	}
	subject := audit.Subject{Kind: catalogcoverage.Kind, Digest: report.Metadata.ReportID}
	if err := persistOperationAudit(options.auditPath, "catalog.coverage.validate", "completed", "success", []audit.Subject{subject}, nil); err != nil {
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid": true, "apiVersion": report.APIVersion, "kind": report.Kind, "name": report.Metadata.Name,
		"reportId": report.Metadata.ReportID, "complete": report.Spec.Complete,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseCatalogCoverageOptions(args []string, stderr io.Writer) (catalogCoverageOptions, bool) {
	var options catalogCoverageOptions
	flags := flag.NewFlagSet("catalog coverage create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.evidenceDir, "evidence-dir", "", "Directory containing contract or integration result YAML and adjacent audit chains")
	flags.StringVar(&options.name, "name", "", "CatalogCoverageReport name")
	flags.StringVar(&options.outputPath, "output", "", "Generated CatalogCoverageReport YAML file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.evidenceDir == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "catalog coverage create requires --catalog, --evidence-dir, --name, --output and --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}

func writeCatalogCoverageFailure(output io.Writer, options catalogCoverageOptions, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAudit(options.auditPath, "catalog.coverage", "failed", "failed", subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}

func writeLoadErrorWithExit(output io.Writer, code string, err error, exitCode int) int {
	_ = json.NewEncoder(output).Encode(map[string]any{
		"valid":       false,
		"diagnostics": []map[string]string{{"code": code, "severity": "error", "message": err.Error()}},
	})
	return exitCode
}
