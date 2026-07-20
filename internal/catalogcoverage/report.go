package catalogcoverage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

const (
	APIVersion = "yara.dev/v1alpha1"
	Kind       = "CatalogCoverageReport"
)

var requiredContractModes = []string{
	"capacity-boundary",
	"lifecycle-contract",
	"model-inference",
	"policy-contract",
	"runtime-smoke",
	"sustained-capacity",
}

var (
	sha256Pattern                      = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	namePattern                        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)
	lifecyclePublicationBlockerPattern = regexp.MustCompile(`^[a-z0-9-]+\|remediation:[a-z0-9-]+$`)
)

var lifecyclePublicationBlockerRemediations = map[string]string{
	"lifecycle-proof-approval-not-recorded":                               "record-lifecycle-proof-approval",
	"no-accepted-lifecycle-contract-evidence":                             "run-lifecycle-contract",
	"selected-approval-catalog-mismatch":                                  "reissue-approval-for-catalog",
	"selected-approval-decision-abstained":                                "collect-explicit-approval-decision",
	"selected-approval-decision-changes-required":                         "address-review-feedback-and-reapprove",
	"selected-approval-does-not-bind-lifecycle-evidence":                  "reissue-approval-with-lifecycle-evidence",
	"selected-approval-expiry-invalid":                                    "reissue-approval-with-valid-expiry",
	"selected-approval-expired-for-lifecycle-evidence":                    "renew-lifecycle-proof-approval",
	"integration-publication-attestation-not-recorded":                    "record-integration-publication-attestation",
	"no-accepted-integration-evidence":                                    "run-integration-execute",
	"selected-integration-attestation-catalog-mismatch":                   "reissue-integration-attestation-for-catalog",
	"selected-integration-attestation-decision-abstained":                 "collect-explicit-integration-attestation-decision",
	"selected-integration-attestation-decision-changes-required":          "address-integration-review-feedback-and-reattest",
	"selected-integration-attestation-does-not-bind-integration-evidence": "reissue-integration-attestation-with-bound-evidence",
	"selected-integration-attestation-expiry-invalid":                     "reissue-integration-attestation-with-valid-expiry",
	"selected-integration-attestation-expired-for-integration-evidence":   "renew-integration-publication-attestation",
}

type LifecyclePublicationBlockerDefinition struct {
	Code        string `json:"code" yaml:"code"`
	Remediation string `json:"remediation" yaml:"remediation"`
}

type Report struct {
	APIVersion string         `json:"apiVersion" yaml:"apiVersion"`
	Kind       string         `json:"kind" yaml:"kind"`
	Metadata   ReportMetadata `json:"metadata" yaml:"metadata"`
	Spec       ReportSpec     `json:"spec" yaml:"spec"`
}

type ReportMetadata struct {
	Name     string `json:"name" yaml:"name"`
	ReportID string `json:"reportId" yaml:"reportId"`
}

type ReportSpec struct {
	CatalogDigest string              `json:"catalogDigest" yaml:"catalogDigest"`
	Complete      bool                `json:"complete" yaml:"complete"`
	Summary       CoverageSummary     `json:"summary" yaml:"summary"`
	Capabilities  []ManifestCoverage  `json:"capabilities" yaml:"capabilities"`
	Components    []ManifestCoverage  `json:"components" yaml:"components"`
	Models        []ManifestCoverage  `json:"models" yaml:"models"`
	Hardware      []ManifestCoverage  `json:"hardware" yaml:"hardware"`
	Topologies    []ManifestCoverage  `json:"topologies" yaml:"topologies"`
	Assertions    []AssertionCoverage `json:"assertions" yaml:"assertions"`
	Limitations   []string            `json:"limitations" yaml:"limitations"`
}

type CoverageSummary struct {
	ManifestCount                         int `json:"manifestCount" yaml:"manifestCount"`
	CapabilityCount                       int `json:"capabilityCount" yaml:"capabilityCount"`
	ComponentCount                        int `json:"componentCount" yaml:"componentCount"`
	ModelCount                            int `json:"modelCount" yaml:"modelCount"`
	HardwareProfileCount                  int `json:"hardwareProfileCount" yaml:"hardwareProfileCount"`
	AssertionCount                        int `json:"assertionCount" yaml:"assertionCount"`
	TopologyCount                         int `json:"topologyCount" yaml:"topologyCount"`
	AcceptedEvidenceCount                 int `json:"acceptedEvidenceCount" yaml:"acceptedEvidenceCount"`
	VerifiedAuditChainCount               int `json:"verifiedAuditChainCount" yaml:"verifiedAuditChainCount"`
	PromotionEligibleAssertions           int `json:"promotionEligibleAssertions" yaml:"promotionEligibleAssertions"`
	LifecyclePublicationReadyAssertions   int `json:"lifecyclePublicationReadyAssertions" yaml:"lifecyclePublicationReadyAssertions"`
	LifecyclePublicationBlockedAssertions int `json:"lifecyclePublicationBlockedAssertions" yaml:"lifecyclePublicationBlockedAssertions"`
}

type ManifestCoverage struct {
	ID                string   `json:"id" yaml:"id"`
	Version           string   `json:"version" yaml:"version"`
	Status            string   `json:"status" yaml:"status"`
	Coverage          string   `json:"coverage" yaml:"coverage"`
	RelatedAssertions []string `json:"relatedAssertions" yaml:"relatedAssertions"`
	PassedModes       []string `json:"passedModes" yaml:"passedModes"`
	Blockers          []string `json:"blockers" yaml:"blockers"`
}

type AssertionCoverage struct {
	ID                          string         `json:"id" yaml:"id"`
	Status                      string         `json:"status" yaml:"status"`
	RuntimeRef                  string         `json:"runtimeRef" yaml:"runtimeRef"`
	ModelRef                    string         `json:"modelRef" yaml:"modelRef"`
	HardwareProfileRef          string         `json:"hardwareProfileRef" yaml:"hardwareProfileRef"`
	PromotionEligible           bool           `json:"promotionEligible" yaml:"promotionEligible"`
	LifecyclePublicationReady   bool           `json:"lifecyclePublicationReady" yaml:"lifecyclePublicationReady"`
	LifecyclePublicationBlocker string         `json:"lifecyclePublicationBlocker,omitempty" yaml:"lifecyclePublicationBlocker,omitempty"`
	Gates                       []GateCoverage `json:"gates" yaml:"gates"`
	Blockers                    []string       `json:"blockers" yaml:"blockers"`
}

type GateCoverage struct {
	ID                string            `json:"id" yaml:"id"`
	Status            string            `json:"status" yaml:"status"`
	SelectedResult    string            `json:"selectedResultId,omitempty" yaml:"selectedResultId,omitempty"`
	SelectedAuditHead string            `json:"selectedAuditHead,omitempty" yaml:"selectedAuditHead,omitempty"`
	ObservedEvidence  []EvidenceBinding `json:"observedEvidence" yaml:"observedEvidence"`
	Blocker           string            `json:"blocker,omitempty" yaml:"blocker,omitempty"`
}

type EvidenceBinding struct {
	ResultID  string `json:"resultId" yaml:"resultId"`
	Outcome   string `json:"outcome" yaml:"outcome"`
	AuditHead string `json:"auditHead" yaml:"auditHead"`
}

type acceptedEvidence struct {
	Result     resources.ContractTestResult
	AuditHead  string
	OccurredAt string
}

type acceptedIntegrationEvidence struct {
	Result     resources.IntegrationTestResult
	AuditHead  string
	OccurredAt string
}

type acceptedPromotionReview struct {
	Review     resources.PromotionReview
	AuditHead  string
	OccurredAt string
}

type acceptedLifecycleProofApproval struct {
	Approval   resources.LifecycleProofApproval
	AuditHead  string
	OccurredAt string
}

type acceptedIntegrationPublicationAttestation struct {
	Attestation resources.IntegrationPublicationAttestation
	AuditHead   string
	OccurredAt  string
}

type acceptedPublicationChainRehearsal struct {
	Rehearsal  resources.PublicationChainRehearsal
	AuditHead  string
	OccurredAt string
}

type acceptedPublicationChainRenewalReview struct {
	Review     resources.PublicationChainRenewalReview
	AuditHead  string
	OccurredAt string
}

type evidenceIndex struct {
	Contracts                      map[string][]acceptedEvidence
	ComponentEvidence              map[string][]acceptedIntegrationEvidence
	TopologyEvidence               map[string][]acceptedIntegrationEvidence
	PromotionReviews               map[string][]acceptedPromotionReview
	LifecycleProofApprovals        map[string][]acceptedLifecycleProofApproval
	IntegrationAttestations        map[string][]acceptedIntegrationPublicationAttestation
	PublicationChainRehearsals     map[string][]acceptedPublicationChainRehearsal
	PublicationChainRenewalReviews map[string][]acceptedPublicationChainRenewalReview
	AcceptedCount                  int
	VerifiedAuditCount             int
	IntegrationIdentityCount       int
	IntegrationDeduplicatedCount   int
}

func Build(name string, snapshot catalog.Snapshot, evidenceDirectory string) (Report, error) {
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return Report{}, fmt.Errorf("digest catalog: %w", err)
	}
	evidence, err := loadEvidence(evidenceDirectory, snapshot, catalogDigest)
	if err != nil {
		return Report{}, err
	}
	inventory := snapshot.ManifestInventory()
	report := Report{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata:   ReportMetadata{Name: name},
		Spec: ReportSpec{
			CatalogDigest: catalogDigest,
			Limitations: []string{
				"A missing gate means no accepted evidence was found in the supplied directory; it does not prove incompatibility.",
				"Audit verification proves local chain integrity, not target or actor attestation.",
				"Component, model and hardware coverage is derived from exact compatibility assertions and does not replace dedicated integration review.",
				"Independent promotion review is represented but remains an external review step.",
				"Integration validation alone is not execution evidence; component and topology coverage requires a matching execution audit chain.",
				fmt.Sprintf("integration-evidence-convergence:identity-count=%d,deduplicated-count=%d", evidence.IntegrationIdentityCount, evidence.IntegrationDeduplicatedCount),
				"signing-authority-boundary:status=not-evaluated,overlap-count=0,ambiguity-count=0",
			},
		},
	}
	slices.Sort(report.Spec.Limitations)
	for _, assertion := range inventory.Compatibility {
		coverage := assertionCoverage(
			assertion,
			evidence.Contracts[assertion.ID],
			integrationEvidenceForAssertion(assertion, evidence.ComponentEvidence),
			evidence.PromotionReviews[assertion.ID],
			evidence.LifecycleProofApprovals[assertion.ID],
			evidence.IntegrationAttestations[assertion.ID],
			evidence.PublicationChainRehearsals[assertion.ID],
			evidence.PublicationChainRenewalReviews[assertion.ID],
			catalogDigest,
		)
		report.Spec.Assertions = append(report.Spec.Assertions, coverage)
		if coverage.PromotionEligible {
			report.Spec.Summary.PromotionEligibleAssertions++
		}
		if coverage.LifecyclePublicationReady {
			report.Spec.Summary.LifecyclePublicationReadyAssertions++
		} else {
			report.Spec.Summary.LifecyclePublicationBlockedAssertions++
		}
	}
	report.Spec.Limitations = append(report.Spec.Limitations, publicationChainRetentionLimitations(report.Spec.Assertions)...)
	report.Spec.Limitations = append(report.Spec.Limitations, publicationChainRenewalReviewLimitations(report.Spec.Assertions)...)
	slices.Sort(report.Spec.Limitations)
	report.Spec.Components = componentCoverage(inventory.Components, report.Spec.Assertions, evidence, func(assertion AssertionCoverage, id string) bool { return assertion.RuntimeRef == id })
	report.Spec.Models = manifestCoverage(inventory.Models, report.Spec.Assertions, evidence.Contracts, func(assertion AssertionCoverage, id string) bool { return assertion.ModelRef == id })
	report.Spec.Hardware = manifestCoverage(inventory.Hardware, report.Spec.Assertions, evidence.Contracts, func(assertion AssertionCoverage, id string) bool { return assertion.HardwareProfileRef == id })
	report.Spec.Capabilities = structuralCoverage(inventory.Capabilities)
	report.Spec.Topologies = topologyCoverage(inventory.Topologies, evidence.TopologyEvidence)
	report.Spec.Summary.ManifestCount = len(inventory.Capabilities) + len(inventory.Components) + len(inventory.Models) + len(inventory.Hardware) + len(inventory.Compatibility) + len(inventory.Topologies)
	report.Spec.Summary.CapabilityCount = len(inventory.Capabilities)
	report.Spec.Summary.ComponentCount = len(inventory.Components)
	report.Spec.Summary.ModelCount = len(inventory.Models)
	report.Spec.Summary.HardwareProfileCount = len(inventory.Hardware)
	report.Spec.Summary.AssertionCount = len(inventory.Compatibility)
	report.Spec.Summary.TopologyCount = len(inventory.Topologies)
	report.Spec.Summary.AcceptedEvidenceCount = evidence.AcceptedCount
	report.Spec.Summary.VerifiedAuditChainCount = evidence.VerifiedAuditCount
	report.Spec.Complete = report.Spec.Summary.AssertionCount > 0 && report.Spec.Summary.PromotionEligibleAssertions == report.Spec.Summary.AssertionCount && allManifestCoverageComplete(report)
	return report.AssignReportID()
}

func publicationChainRetentionLimitations(assertions []AssertionCoverage) []string {
	records := make([]string, 0, len(assertions))
	for _, assertion := range assertions {
		rehearsalGate := GateCoverage{}
		found := false
		for _, gate := range assertion.Gates {
			if gate.ID == "publication-chain-rehearsal" {
				rehearsalGate = gate
				found = true
				break
			}
		}
		if !found {
			continue
		}
		status := "non-renewable"
		if rehearsalGate.Status == "passed" {
			status = "renewable"
		}
		selected := rehearsalGate.SelectedResult
		if selected == "" {
			selected = "none"
		}
		blocker := rehearsalGate.Blocker
		if blocker == "" {
			blocker = "none"
		}
		records = append(records, fmt.Sprintf("publication-chain-retention:assertion=%s,status=%s,selected-rehearsal=%s,blocker=%s", assertion.ID, status, selected, blocker))
	}
	return records
}

func publicationChainRenewalReviewLimitations(assertions []AssertionCoverage) []string {
	records := make([]string, 0, len(assertions))
	for _, assertion := range assertions {
		renewalGate := GateCoverage{}
		found := false
		for _, gate := range assertion.Gates {
			if gate.ID == "publication-chain-renewal-review" {
				renewalGate = gate
				found = true
				break
			}
		}
		if !found {
			continue
		}
		selected := renewalGate.SelectedResult
		if selected == "" {
			selected = "none"
		}
		blocker := renewalGate.Blocker
		if blocker == "" {
			blocker = "none"
		}
		records = append(records, fmt.Sprintf("publication-chain-renewal-review:assertion=%s,status=%s,selected-renewal-review=%s,blocker=%s", assertion.ID, renewalGate.Status, selected, blocker))
	}
	return records
}

func assertionCoverage(
	assertion catalog.AssertionDescriptor,
	evidence []acceptedEvidence,
	integrationEvidence []acceptedIntegrationEvidence,
	reviews []acceptedPromotionReview,
	approvals []acceptedLifecycleProofApproval,
	attestations []acceptedIntegrationPublicationAttestation,
	rehearsals []acceptedPublicationChainRehearsal,
	renewalReviews []acceptedPublicationChainRenewalReview,
	catalogDigest string,
) AssertionCoverage {
	coverage := AssertionCoverage{
		ID: assertion.ID, Status: assertion.Status, RuntimeRef: assertion.RuntimeRef, ModelRef: assertion.ModelRef,
		HardwareProfileRef: assertion.HardwareProfileRef,
		Gates:              []GateCoverage{},
		Blockers:           []string{},
	}
	artifactStatus, artifactBlocker := "passed", ""
	if !assertion.ArtifactVerified {
		artifactStatus, artifactBlocker = "failed", "catalog-artifact-identity-unverified"
	}
	coverage.Gates = append(coverage.Gates, GateCoverage{ID: "artifact-identity", Status: artifactStatus, ObservedEvidence: []EvidenceBinding{}, Blocker: artifactBlocker})
	for _, mode := range requiredContractModes {
		coverage.Gates = append(coverage.Gates, contractGate(mode, evidence))
	}
	coverage.Gates = append(coverage.Gates, promotionReviewGate(reviews))
	lifecycleGate := lifecycleProofApprovalGate(evidence, approvals, catalogDigest)
	coverage.Gates = append(coverage.Gates, lifecycleGate)
	integrationGate := integrationPublicationAttestationGate(integrationEvidence, attestations, catalogDigest)
	coverage.Gates = append(coverage.Gates, integrationGate)
	rehearsalGate := publicationChainRehearsalGate(approvals, attestations, rehearsals, catalogDigest)
	coverage.Gates = append(coverage.Gates, rehearsalGate)
	renewalReviewGate := publicationChainRenewalReviewGate(reviews, approvals, attestations, rehearsals, renewalReviews, catalogDigest)
	coverage.Gates = append(coverage.Gates, renewalReviewGate)
	slices.SortFunc(coverage.Gates, func(left, right GateCoverage) int { return strings.Compare(left.ID, right.ID) })
	for _, gate := range coverage.Gates {
		if gate.Status != "passed" && gate.ID != "publication-chain-rehearsal" && gate.ID != "publication-chain-renewal-review" {
			coverage.Blockers = append(coverage.Blockers, gate.ID+":"+gate.Blocker)
		}
	}
	if len(evidence) == 0 {
		coverage.Blockers = append(coverage.Blockers, "external-target:no-observed-target-evidence")
	}
	slices.Sort(coverage.Blockers)
	coverage.PromotionEligible = slices.Contains([]string{"known", "experimental", "supported"}, assertion.Status) && assertion.Compatibility == "supported" && len(coverage.Blockers) == 0
	coverage.LifecyclePublicationReady = lifecycleGate.Status == "passed" && integrationGate.Status == "passed"
	if lifecycleGate.Status != "passed" {
		coverage.LifecyclePublicationBlocker = lifecycleGate.Blocker
	} else if integrationGate.Status != "passed" {
		coverage.LifecyclePublicationBlocker = lifecyclePublicationBlocker(integrationGate.Blocker)
	}
	return coverage
}

func integrationEvidenceForAssertion(assertion catalog.AssertionDescriptor, evidenceByComponent map[string][]acceptedIntegrationEvidence) []acceptedIntegrationEvidence {
	byID := map[string]acceptedIntegrationEvidence{}
	prefix := assertion.RuntimeRef + "@"
	for componentRef, evidence := range evidenceByComponent {
		if !strings.HasPrefix(componentRef, prefix) {
			continue
		}
		for _, item := range evidence {
			byID[item.Result.Metadata.ResultID] = item
		}
	}
	result := make([]acceptedIntegrationEvidence, 0, len(byID))
	for _, item := range byID {
		result = append(result, item)
	}
	slices.SortFunc(result, func(left, right acceptedIntegrationEvidence) int {
		if comparison := strings.Compare(left.OccurredAt, right.OccurredAt); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Result.Metadata.ResultID, right.Result.Metadata.ResultID)
	})
	return result
}

func promotionReviewGate(reviews []acceptedPromotionReview) GateCoverage {
	gate := GateCoverage{
		ID:               "independent-promotion-review",
		Status:           "missing",
		ObservedEvidence: []EvidenceBinding{},
		Blocker:          "promotion-review-not-recorded",
	}
	if len(reviews) == 0 {
		return gate
	}
	sorted := slices.Clone(reviews)
	slices.SortFunc(sorted, func(left, right acceptedPromotionReview) int {
		if comparison := strings.Compare(left.OccurredAt, right.OccurredAt); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Review.Metadata.ReviewID, right.Review.Metadata.ReviewID)
	})
	for _, item := range sorted {
		outcome := "failed"
		if item.Review.Spec.Decision == resources.PromotionDecisionApproved {
			outcome = "passed"
		} else if item.Review.Spec.Decision == resources.PromotionDecisionAbstained {
			outcome = "blocked"
		}
		gate.ObservedEvidence = append(gate.ObservedEvidence, EvidenceBinding{
			ResultID:  item.Review.Metadata.ReviewID,
			Outcome:   outcome,
			AuditHead: item.AuditHead,
		})
	}
	selected := sorted[len(sorted)-1]
	gate.SelectedResult = selected.Review.Metadata.ReviewID
	gate.SelectedAuditHead = selected.AuditHead
	switch selected.Review.Spec.Decision {
	case resources.PromotionDecisionApproved:
		gate.Status = "passed"
		gate.Blocker = ""
	case resources.PromotionDecisionAbstained:
		gate.Status = "blocked"
		gate.Blocker = "selected-review-decision-abstained"
	default:
		gate.Status = "failed"
		gate.Blocker = "selected-review-decision-changes-required"
	}
	return gate
}

func lifecycleProofApprovalGate(lifecycleEvidence []acceptedEvidence, approvals []acceptedLifecycleProofApproval, catalogDigest string) GateCoverage {
	gate := GateCoverage{
		ID:               "lifecycle-proof-publication-approval",
		Status:           "missing",
		ObservedEvidence: []EvidenceBinding{},
		Blocker:          lifecyclePublicationBlocker("lifecycle-proof-approval-not-recorded"),
	}
	filteredEvidence := make([]acceptedEvidence, 0)
	for _, item := range lifecycleEvidence {
		if item.Result.Spec.Mode == "lifecycle-contract" && item.Result.Spec.Outcome == "passed" {
			filteredEvidence = append(filteredEvidence, item)
		}
	}
	if len(filteredEvidence) == 0 {
		gate.Blocker = lifecyclePublicationBlocker("no-accepted-lifecycle-contract-evidence")
		return gate
	}
	if len(approvals) == 0 {
		return gate
	}
	sorted := slices.Clone(approvals)
	slices.SortFunc(sorted, func(left, right acceptedLifecycleProofApproval) int {
		if comparison := strings.Compare(left.OccurredAt, right.OccurredAt); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Approval.Metadata.ApprovalID, right.Approval.Metadata.ApprovalID)
	})
	lifecycleEvidenceByID := map[string]acceptedEvidence{}
	latestLifecycleOccurredAt := ""
	for _, item := range filteredEvidence {
		lifecycleEvidenceByID[item.Result.Metadata.ResultID] = item
		if strings.Compare(item.OccurredAt, latestLifecycleOccurredAt) > 0 {
			latestLifecycleOccurredAt = item.OccurredAt
		}
	}
	for _, item := range sorted {
		outcome := "failed"
		if item.Approval.Spec.Decision == resources.PromotionDecisionApproved {
			outcome = "passed"
		} else if item.Approval.Spec.Decision == resources.PromotionDecisionAbstained {
			outcome = "blocked"
		}
		gate.ObservedEvidence = append(gate.ObservedEvidence, EvidenceBinding{
			ResultID:  item.Approval.Metadata.ApprovalID,
			Outcome:   outcome,
			AuditHead: item.AuditHead,
		})
	}
	selected := sorted[len(sorted)-1]
	gate.SelectedResult = selected.Approval.Metadata.ApprovalID
	gate.SelectedAuditHead = selected.AuditHead
	if selected.Approval.Spec.CatalogDigest != catalogDigest {
		gate.Status = "failed"
		gate.Blocker = lifecyclePublicationBlocker("selected-approval-catalog-mismatch")
		return gate
	}
	if selected.Approval.Spec.Decision != resources.PromotionDecisionApproved {
		if selected.Approval.Spec.Decision == resources.PromotionDecisionAbstained {
			gate.Status = "blocked"
			gate.Blocker = lifecyclePublicationBlocker("selected-approval-decision-abstained")
		} else {
			gate.Status = "failed"
			gate.Blocker = lifecyclePublicationBlocker("selected-approval-decision-changes-required")
		}
		return gate
	}
	bindsLifecycleEvidence := false
	for _, digest := range selected.Approval.Spec.SelectedEvidence {
		if _, ok := lifecycleEvidenceByID[digest]; ok {
			bindsLifecycleEvidence = true
			break
		}
	}
	if !bindsLifecycleEvidence {
		gate.Status = "failed"
		gate.Blocker = lifecyclePublicationBlocker("selected-approval-does-not-bind-lifecycle-evidence")
		return gate
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, selected.Approval.Spec.ExpiresAt)
	if err != nil {
		gate.Status = "failed"
		gate.Blocker = lifecyclePublicationBlocker("selected-approval-expiry-invalid")
		return gate
	}
	latestLifecycleTime, err := time.Parse(time.RFC3339Nano, latestLifecycleOccurredAt)
	if err != nil || !expiresAt.After(latestLifecycleTime) {
		gate.Status = "failed"
		gate.Blocker = lifecyclePublicationBlocker("selected-approval-expired-for-lifecycle-evidence")
		return gate
	}
	gate.Status = "passed"
	gate.Blocker = ""
	return gate
}

func integrationPublicationAttestationGate(integrationEvidence []acceptedIntegrationEvidence, attestations []acceptedIntegrationPublicationAttestation, catalogDigest string) GateCoverage {
	gate := GateCoverage{
		ID:               "integration-publication-attestation",
		Status:           "missing",
		ObservedEvidence: []EvidenceBinding{},
		Blocker:          "integration-publication-attestation-not-recorded",
	}
	if len(integrationEvidence) == 0 {
		gate.Blocker = "no-accepted-integration-evidence"
		return gate
	}
	if len(attestations) == 0 {
		return gate
	}
	sorted := slices.Clone(attestations)
	slices.SortFunc(sorted, func(left, right acceptedIntegrationPublicationAttestation) int {
		if comparison := strings.Compare(left.OccurredAt, right.OccurredAt); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Attestation.Metadata.AttestationID, right.Attestation.Metadata.AttestationID)
	})
	integrationEvidenceByID := map[string]acceptedIntegrationEvidence{}
	latestIntegrationOccurredAt := ""
	for _, item := range integrationEvidence {
		integrationEvidenceByID[item.Result.Metadata.ResultID] = item
		if strings.Compare(item.OccurredAt, latestIntegrationOccurredAt) > 0 {
			latestIntegrationOccurredAt = item.OccurredAt
		}
	}
	for _, item := range sorted {
		outcome := "failed"
		if item.Attestation.Spec.Decision == resources.PromotionDecisionApproved {
			outcome = "passed"
		} else if item.Attestation.Spec.Decision == resources.PromotionDecisionAbstained {
			outcome = "blocked"
		}
		gate.ObservedEvidence = append(gate.ObservedEvidence, EvidenceBinding{
			ResultID:  item.Attestation.Metadata.AttestationID,
			Outcome:   outcome,
			AuditHead: item.AuditHead,
		})
	}
	selected := sorted[len(sorted)-1]
	gate.SelectedResult = selected.Attestation.Metadata.AttestationID
	gate.SelectedAuditHead = selected.AuditHead
	if selected.Attestation.Spec.CatalogDigest != catalogDigest {
		gate.Status = "failed"
		gate.Blocker = "selected-integration-attestation-catalog-mismatch"
		return gate
	}
	if selected.Attestation.Spec.Decision != resources.PromotionDecisionApproved {
		if selected.Attestation.Spec.Decision == resources.PromotionDecisionAbstained {
			gate.Status = "blocked"
			gate.Blocker = "selected-integration-attestation-decision-abstained"
		} else {
			gate.Status = "failed"
			gate.Blocker = "selected-integration-attestation-decision-changes-required"
		}
		return gate
	}
	bindsIntegrationEvidence := false
	for _, digest := range selected.Attestation.Spec.SelectedEvidence {
		if _, ok := integrationEvidenceByID[digest]; ok {
			bindsIntegrationEvidence = true
			break
		}
	}
	if !bindsIntegrationEvidence {
		gate.Status = "failed"
		gate.Blocker = "selected-integration-attestation-does-not-bind-integration-evidence"
		return gate
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, selected.Attestation.Spec.ExpiresAt)
	if err != nil {
		gate.Status = "failed"
		gate.Blocker = "selected-integration-attestation-expiry-invalid"
		return gate
	}
	latestIntegrationTime, err := time.Parse(time.RFC3339Nano, latestIntegrationOccurredAt)
	if err != nil || !expiresAt.After(latestIntegrationTime) {
		gate.Status = "failed"
		gate.Blocker = "selected-integration-attestation-expired-for-integration-evidence"
		return gate
	}
	gate.Status = "passed"
	gate.Blocker = ""
	return gate
}

func publicationChainRehearsalGate(approvals []acceptedLifecycleProofApproval, attestations []acceptedIntegrationPublicationAttestation, rehearsals []acceptedPublicationChainRehearsal, catalogDigest string) GateCoverage {
	gate := GateCoverage{
		ID:               "publication-chain-rehearsal",
		Status:           "missing",
		ObservedEvidence: []EvidenceBinding{},
		Blocker:          "publication-chain-rehearsal-not-recorded",
	}
	if len(rehearsals) == 0 {
		return gate
	}
	approvalByID := map[string]acceptedLifecycleProofApproval{}
	for _, item := range approvals {
		approvalByID[item.Approval.Metadata.ApprovalID] = item
	}
	attestationByID := map[string]acceptedIntegrationPublicationAttestation{}
	for _, item := range attestations {
		attestationByID[item.Attestation.Metadata.AttestationID] = item
	}
	sorted := slices.Clone(rehearsals)
	slices.SortFunc(sorted, func(left, right acceptedPublicationChainRehearsal) int {
		if comparison := strings.Compare(left.OccurredAt, right.OccurredAt); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Rehearsal.Metadata.RehearsalID, right.Rehearsal.Metadata.RehearsalID)
	})
	for _, item := range sorted {
		outcome := "failed"
		if item.Rehearsal.Spec.Decision == resources.PromotionDecisionApproved {
			outcome = "passed"
		} else if item.Rehearsal.Spec.Decision == resources.PromotionDecisionAbstained {
			outcome = "blocked"
		}
		gate.ObservedEvidence = append(gate.ObservedEvidence, EvidenceBinding{
			ResultID:  item.Rehearsal.Metadata.RehearsalID,
			Outcome:   outcome,
			AuditHead: item.AuditHead,
		})
	}
	selected := sorted[len(sorted)-1]
	gate.SelectedResult = selected.Rehearsal.Metadata.RehearsalID
	gate.SelectedAuditHead = selected.AuditHead
	if selected.Rehearsal.Spec.CatalogDigest != catalogDigest {
		gate.Status = "failed"
		gate.Blocker = "selected-rehearsal-catalog-mismatch"
		return gate
	}
	if selected.Rehearsal.Spec.Decision != resources.PromotionDecisionApproved {
		if selected.Rehearsal.Spec.Decision == resources.PromotionDecisionAbstained {
			gate.Status = "blocked"
			gate.Blocker = "selected-rehearsal-decision-abstained"
		} else {
			gate.Status = "failed"
			gate.Blocker = "selected-rehearsal-decision-changes-required"
		}
		return gate
	}
	approval, hasApproval := approvalByID[selected.Rehearsal.Spec.LifecycleProofApprovalID]
	if !hasApproval {
		gate.Status = "failed"
		gate.Blocker = "selected-rehearsal-does-not-bind-lifecycle-proof-approval"
		return gate
	}
	attestation, hasAttestation := attestationByID[selected.Rehearsal.Spec.IntegrationPublicationAttestationID]
	if !hasAttestation {
		gate.Status = "failed"
		gate.Blocker = "selected-rehearsal-does-not-bind-integration-publication-attestation"
		return gate
	}
	maxEvidenceAge, err := time.ParseDuration(selected.Rehearsal.Spec.MaxEvidenceAge)
	if err != nil || maxEvidenceAge <= 0 {
		gate.Status = "failed"
		gate.Blocker = "selected-rehearsal-max-evidence-age-invalid"
		return gate
	}
	rehearsedAt, err := time.Parse(time.RFC3339Nano, selected.Rehearsal.Spec.RehearsedAt)
	if err != nil {
		gate.Status = "failed"
		gate.Blocker = "selected-rehearsal-recorded-at-invalid"
		return gate
	}
	approvalObservedAt, err := time.Parse(time.RFC3339Nano, approval.OccurredAt)
	if err != nil {
		gate.Status = "failed"
		gate.Blocker = "selected-rehearsal-approval-observed-at-invalid"
		return gate
	}
	attestationObservedAt, err := time.Parse(time.RFC3339Nano, attestation.OccurredAt)
	if err != nil {
		gate.Status = "failed"
		gate.Blocker = "selected-rehearsal-attestation-observed-at-invalid"
		return gate
	}
	latestPrerequisite := approvalObservedAt
	if attestationObservedAt.After(latestPrerequisite) {
		latestPrerequisite = attestationObservedAt
	}
	if rehearsedAt.Before(latestPrerequisite) || rehearsedAt.Sub(latestPrerequisite) > maxEvidenceAge {
		gate.Status = "failed"
		gate.Blocker = "selected-rehearsal-stale-for-prerequisite-evidence"
		return gate
	}
	gate.Status = "passed"
	gate.Blocker = ""
	return gate
}

func publicationChainRenewalReviewGate(reviews []acceptedPromotionReview, approvals []acceptedLifecycleProofApproval, attestations []acceptedIntegrationPublicationAttestation, rehearsals []acceptedPublicationChainRehearsal, renewalReviews []acceptedPublicationChainRenewalReview, catalogDigest string) GateCoverage {
	gate := GateCoverage{
		ID:               "publication-chain-renewal-review",
		Status:           "missing",
		ObservedEvidence: []EvidenceBinding{},
		Blocker:          "publication-chain-renewal-review-not-recorded",
	}
	if len(renewalReviews) == 0 {
		return gate
	}
	reviewByID := map[string]acceptedPromotionReview{}
	for _, item := range reviews {
		reviewByID[item.Review.Metadata.ReviewID] = item
	}
	approvalByID := map[string]acceptedLifecycleProofApproval{}
	for _, item := range approvals {
		approvalByID[item.Approval.Metadata.ApprovalID] = item
	}
	attestationByID := map[string]acceptedIntegrationPublicationAttestation{}
	for _, item := range attestations {
		attestationByID[item.Attestation.Metadata.AttestationID] = item
	}
	rehearsalByID := map[string]acceptedPublicationChainRehearsal{}
	for _, item := range rehearsals {
		rehearsalByID[item.Rehearsal.Metadata.RehearsalID] = item
	}
	sorted := slices.Clone(renewalReviews)
	slices.SortFunc(sorted, func(left, right acceptedPublicationChainRenewalReview) int {
		if comparison := strings.Compare(left.OccurredAt, right.OccurredAt); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Review.Metadata.ReviewID, right.Review.Metadata.ReviewID)
	})
	for _, item := range sorted {
		outcome := "failed"
		if item.Review.Spec.Decision == resources.PromotionDecisionApproved {
			outcome = "passed"
		} else if item.Review.Spec.Decision == resources.PromotionDecisionAbstained {
			outcome = "blocked"
		}
		gate.ObservedEvidence = append(gate.ObservedEvidence, EvidenceBinding{
			ResultID:  item.Review.Metadata.ReviewID,
			Outcome:   outcome,
			AuditHead: item.AuditHead,
		})
	}
	selected := sorted[len(sorted)-1]
	gate.SelectedResult = selected.Review.Metadata.ReviewID
	gate.SelectedAuditHead = selected.AuditHead
	if selected.Review.Spec.CatalogDigest != catalogDigest {
		gate.Status = "failed"
		gate.Blocker = "selected-renewal-review-catalog-mismatch"
		return gate
	}
	if selected.Review.Spec.Decision != resources.PromotionDecisionApproved {
		if selected.Review.Spec.Decision == resources.PromotionDecisionAbstained {
			gate.Status = "blocked"
			gate.Blocker = "selected-renewal-review-decision-abstained"
		} else {
			gate.Status = "failed"
			gate.Blocker = "selected-renewal-review-decision-changes-required"
		}
		return gate
	}
	if _, ok := rehearsalByID[selected.Review.Spec.PublicationChainRehearsalID]; !ok {
		gate.Status = "failed"
		gate.Blocker = "selected-renewal-review-does-not-bind-publication-chain-rehearsal"
		return gate
	}
	if _, ok := reviewByID[selected.Review.Spec.PromotionReviewID]; !ok {
		gate.Status = "failed"
		gate.Blocker = "selected-renewal-review-does-not-bind-promotion-review"
		return gate
	}
	if _, ok := approvalByID[selected.Review.Spec.LifecycleProofApprovalID]; !ok {
		gate.Status = "failed"
		gate.Blocker = "selected-renewal-review-does-not-bind-lifecycle-proof-approval"
		return gate
	}
	if _, ok := attestationByID[selected.Review.Spec.IntegrationPublicationAttestationID]; !ok {
		gate.Status = "failed"
		gate.Blocker = "selected-renewal-review-does-not-bind-integration-publication-attestation"
		return gate
	}
	maxEvidenceAge, err := time.ParseDuration(selected.Review.Spec.MaxEvidenceAge)
	if err != nil || maxEvidenceAge <= 0 {
		gate.Status = "failed"
		gate.Blocker = "selected-renewal-review-max-evidence-age-invalid"
		return gate
	}
	reviewedAt, err := time.Parse(time.RFC3339Nano, selected.Review.Spec.ReviewedAt)
	if err != nil {
		gate.Status = "failed"
		gate.Blocker = "selected-renewal-review-reviewed-at-invalid"
		return gate
	}
	if strings.Compare(selected.OccurredAt, "") <= 0 {
		gate.Status = "failed"
		gate.Blocker = "selected-renewal-review-observed-at-invalid"
		return gate
	}
	observedAt, err := time.Parse(time.RFC3339Nano, selected.OccurredAt)
	if err != nil || reviewedAt.Before(observedAt) || reviewedAt.Sub(observedAt) > maxEvidenceAge {
		gate.Status = "failed"
		gate.Blocker = "selected-renewal-review-stale-for-bound-evidence"
		return gate
	}
	gate.Status = "passed"
	gate.Blocker = ""
	return gate
}

func lifecyclePublicationBlocker(code string) string {
	step, ok := lifecyclePublicationBlockerRemediations[code]
	if !ok {
		return code
	}
	return code + "|remediation:" + step
}

func LifecyclePublicationBlockerTaxonomy() []LifecyclePublicationBlockerDefinition {
	keys := make([]string, 0, len(lifecyclePublicationBlockerRemediations))
	for code := range lifecyclePublicationBlockerRemediations {
		keys = append(keys, code)
	}
	sort.Strings(keys)
	definitions := make([]LifecyclePublicationBlockerDefinition, 0, len(keys))
	for _, code := range keys {
		definitions = append(definitions, LifecyclePublicationBlockerDefinition{
			Code:        code,
			Remediation: lifecyclePublicationBlockerRemediations[code],
		})
	}
	return definitions
}

func ParseLifecyclePublicationBlocker(blocker string) (LifecyclePublicationBlockerDefinition, error) {
	if strings.Count(blocker, "|remediation:") != 1 {
		return LifecyclePublicationBlockerDefinition{}, errors.New("lifecycle publication blocker must include exactly one remediation delimiter")
	}
	parts := strings.SplitN(blocker, "|remediation:", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return LifecyclePublicationBlockerDefinition{}, errors.New("lifecycle publication blocker is malformed")
	}
	if !lifecyclePublicationBlockerPattern.MatchString(blocker) {
		return LifecyclePublicationBlockerDefinition{}, errors.New("lifecycle publication blocker encoding is invalid")
	}
	expected, ok := lifecyclePublicationBlockerRemediations[parts[0]]
	if !ok {
		return LifecyclePublicationBlockerDefinition{}, errors.New("lifecycle publication blocker code is not in taxonomy")
	}
	if parts[1] != expected {
		return LifecyclePublicationBlockerDefinition{}, errors.New("lifecycle publication blocker remediation does not match taxonomy")
	}
	return LifecyclePublicationBlockerDefinition{Code: parts[0], Remediation: parts[1]}, nil
}

func contractGate(mode string, evidence []acceptedEvidence) GateCoverage {
	matching := make([]acceptedEvidence, 0)
	for _, item := range evidence {
		if item.Result.Spec.Mode == mode {
			matching = append(matching, item)
		}
	}
	gate := GateCoverage{ID: mode, Status: "missing", ObservedEvidence: []EvidenceBinding{}, Blocker: "no-accepted-" + mode + "-evidence"}
	if len(matching) == 0 {
		return gate
	}
	slices.SortFunc(matching, func(left, right acceptedEvidence) int {
		if comparison := strings.Compare(left.OccurredAt, right.OccurredAt); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Result.Metadata.ResultID, right.Result.Metadata.ResultID)
	})
	for _, item := range matching {
		gate.ObservedEvidence = append(gate.ObservedEvidence, EvidenceBinding{
			ResultID: item.Result.Metadata.ResultID, Outcome: item.Result.Spec.Outcome, AuditHead: item.AuditHead,
		})
	}
	selected := matching[len(matching)-1]
	gate.Status = selected.Result.Spec.Outcome
	gate.SelectedResult = selected.Result.Metadata.ResultID
	gate.SelectedAuditHead = selected.AuditHead
	gate.Blocker = ""
	if gate.Status != "passed" {
		gate.Blocker = "selected-evidence-outcome-" + gate.Status
	}
	return gate
}

func manifestCoverage(manifests []catalog.ManifestDescriptor, assertions []AssertionCoverage, evidence map[string][]acceptedEvidence, related func(AssertionCoverage, string) bool) []ManifestCoverage {
	result := make([]ManifestCoverage, 0, len(manifests))
	for _, manifest := range manifests {
		item := ManifestCoverage{
			ID: manifest.ID, Version: manifest.Version, Status: manifest.Status, Coverage: "none",
			RelatedAssertions: []string{}, PassedModes: []string{}, Blockers: []string{},
		}
		modeSet := map[string]struct{}{}
		allComplete := true
		for _, assertion := range assertions {
			if !related(assertion, manifest.ID) {
				continue
			}
			item.RelatedAssertions = append(item.RelatedAssertions, assertion.ID)
			if !assertion.PromotionEligible {
				allComplete = false
			}
			for _, accepted := range evidence[assertion.ID] {
				if accepted.Result.Spec.Outcome == "passed" {
					modeSet[accepted.Result.Spec.Mode] = struct{}{}
				}
			}
		}
		for mode := range modeSet {
			item.PassedModes = append(item.PassedModes, mode)
		}
		slices.Sort(item.RelatedAssertions)
		slices.Sort(item.PassedModes)
		if len(item.PassedModes) > 0 {
			item.Coverage = "partial"
		}
		if len(item.RelatedAssertions) > 0 && allComplete {
			item.Coverage = "complete"
		}
		if len(item.RelatedAssertions) == 0 {
			item.Blockers = append(item.Blockers, "no-component-integration-evidence-model")
		} else if item.Coverage == "none" {
			item.Blockers = append(item.Blockers, "no-accepted-contract-evidence")
		} else if item.Coverage == "partial" {
			item.Blockers = append(item.Blockers, "related-assertions-not-promotion-eligible")
		}
		result = append(result, item)
	}
	return result
}

func componentCoverage(manifests []catalog.ManifestDescriptor, assertions []AssertionCoverage, evidence evidenceIndex, related func(AssertionCoverage, string) bool) []ManifestCoverage {
	result := manifestCoverage(manifests, assertions, evidence.Contracts, related)
	for index := range result {
		item := &result[index]
		integration := evidence.ComponentEvidence[item.ID+"@"+item.Version]
		latest := latestIntegrationByMode(integration)
		for _, mode := range []string{"component-smoke", "topology-end-to-end"} {
			selected, exists := latest[mode]
			if exists && selected.Result.Spec.Outcome == "passed" && !slices.Contains(item.PassedModes, mode) {
				item.PassedModes = append(item.PassedModes, mode)
			}
		}
		slices.Sort(item.PassedModes)

		componentPassed := integrationModePassed(latest, "component-smoke")
		topologyPassed := integrationModePassed(latest, "topology-end-to-end")
		if len(integration) > 0 && item.Coverage == "none" {
			item.Coverage = "partial"
		}
		if componentPassed && topologyPassed && relatedAssertionsComplete(*item, assertions) {
			item.Coverage = "complete"
		}
		item.Blockers = removeBlockers(item.Blockers, "no-component-integration-evidence-model")
		item.Blockers = appendIntegrationBlocker(item.Blockers, latest, "component-smoke", "no-component-smoke-evidence")
		item.Blockers = appendIntegrationBlocker(item.Blockers, latest, "topology-end-to-end", "no-topology-integration-evidence")
		slices.Sort(item.Blockers)
	}
	return result
}

func topologyCoverage(manifests []catalog.ManifestDescriptor, evidence map[string][]acceptedIntegrationEvidence) []ManifestCoverage {
	result := make([]ManifestCoverage, 0, len(manifests))
	for _, manifest := range manifests {
		item := ManifestCoverage{
			ID: manifest.ID, Version: manifest.Version, Status: manifest.Status, Coverage: "none",
			RelatedAssertions: []string{}, PassedModes: []string{}, Blockers: []string{},
		}
		latest := latestIntegrationByMode(evidence[manifest.ID+"@"+manifest.Version])
		selected, exists := latest["topology-end-to-end"]
		if exists {
			item.Coverage = "partial"
			if selected.Result.Spec.Outcome == "passed" {
				item.Coverage = "complete"
				item.PassedModes = append(item.PassedModes, "topology-end-to-end")
			}
		}
		item.Blockers = appendIntegrationBlocker(item.Blockers, latest, "topology-end-to-end", "no-topology-integration-evidence")
		result = append(result, item)
	}
	return result
}

func latestIntegrationByMode(evidence []acceptedIntegrationEvidence) map[string]acceptedIntegrationEvidence {
	sorted := slices.Clone(evidence)
	slices.SortFunc(sorted, func(left, right acceptedIntegrationEvidence) int {
		if comparison := strings.Compare(left.OccurredAt, right.OccurredAt); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Result.Metadata.ResultID, right.Result.Metadata.ResultID)
	})
	result := make(map[string]acceptedIntegrationEvidence)
	for _, item := range sorted {
		result[item.Result.Spec.Mode] = item
	}
	return result
}

func integrationModePassed(latest map[string]acceptedIntegrationEvidence, mode string) bool {
	item, exists := latest[mode]
	return exists && item.Result.Spec.Outcome == "passed"
}

func appendIntegrationBlocker(blockers []string, latest map[string]acceptedIntegrationEvidence, mode, missing string) []string {
	item, exists := latest[mode]
	if !exists {
		return append(blockers, missing)
	}
	if item.Result.Spec.Outcome != "passed" {
		return append(blockers, mode+":selected-evidence-outcome-"+item.Result.Spec.Outcome)
	}
	return blockers
}

func relatedAssertionsComplete(item ManifestCoverage, assertions []AssertionCoverage) bool {
	for _, assertionID := range item.RelatedAssertions {
		for _, assertion := range assertions {
			if assertion.ID == assertionID && !assertion.PromotionEligible {
				return false
			}
		}
	}
	return true
}

func removeBlockers(blockers []string, blocker string) []string {
	result := make([]string, 0, len(blockers))
	for _, item := range blockers {
		if item != blocker {
			result = append(result, item)
		}
	}
	return result
}

func allManifestCoverageComplete(report Report) bool {
	for _, collection := range [][]ManifestCoverage{report.Spec.Capabilities, report.Spec.Components, report.Spec.Models, report.Spec.Hardware, report.Spec.Topologies} {
		for _, item := range collection {
			if item.Coverage != "complete" {
				return false
			}
		}
	}
	return true
}

func structuralCoverage(manifests []catalog.ManifestDescriptor) []ManifestCoverage {
	result := make([]ManifestCoverage, 0, len(manifests))
	for _, manifest := range manifests {
		result = append(result, ManifestCoverage{
			ID: manifest.ID, Version: manifest.Version, Status: manifest.Status, Coverage: "complete",
			RelatedAssertions: []string{}, PassedModes: []string{"catalog-validation"}, Blockers: []string{},
		})
	}
	return result
}

func loadEvidence(directory string, snapshot catalog.Snapshot, catalogDigest string) (evidenceIndex, error) {
	result := evidenceIndex{
		Contracts:                      make(map[string][]acceptedEvidence),
		ComponentEvidence:              make(map[string][]acceptedIntegrationEvidence),
		TopologyEvidence:               make(map[string][]acceptedIntegrationEvidence),
		PromotionReviews:               make(map[string][]acceptedPromotionReview),
		LifecycleProofApprovals:        make(map[string][]acceptedLifecycleProofApproval),
		IntegrationAttestations:        make(map[string][]acceptedIntegrationPublicationAttestation),
		PublicationChainRehearsals:     make(map[string][]acceptedPublicationChainRehearsal),
		PublicationChainRenewalReviews: make(map[string][]acceptedPublicationChainRenewalReview),
	}
	assertions := make(map[string]catalog.AssertionDescriptor)
	inventory := snapshot.ManifestInventory()
	for _, assertion := range inventory.Compatibility {
		assertions[assertion.ID] = assertion
	}
	components := make(map[string]struct{}, len(inventory.Components))
	for _, component := range inventory.Components {
		components[component.ID+"@"+component.Version] = struct{}{}
	}
	topologies := make(map[string]struct{}, len(inventory.Topologies))
	for _, topology := range inventory.Topologies {
		topologies[topology.ID+"@"+topology.Version] = struct{}{}
	}
	pendingPromotionReviewPaths := []string{}
	pendingLifecycleProofApprovalPaths := []string{}
	pendingIntegrationAttestationPaths := []string{}
	pendingPublicationChainRehearsalPaths := []string{}
	pendingPublicationChainRenewalReviewPaths := []string{}
	acceptedIntegrationByID := map[string]acceptedIntegrationEvidence{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			return nil
		}
		kind, err := evidenceKind(path)
		if err != nil {
			return fmt.Errorf("load evidence %s: %w", filepath.Base(path), err)
		}
		if kind == "IntegrationTestResult" {
			integrationResult, err := resources.LoadIntegrationTestResult(path)
			if err != nil {
				return fmt.Errorf("load evidence %s: %w", filepath.Base(path), err)
			}
			if report := integrationResult.Validate(); !report.Valid || integrationResult.Spec.CatalogDigest != catalogDigest {
				return fmt.Errorf("evidence %s is invalid or not bound to this catalog", filepath.Base(path))
			}
			for _, reference := range integrationResult.Spec.ComponentRefs {
				if _, ok := components[reference]; !ok {
					return fmt.Errorf("evidence %s references an unknown component version", filepath.Base(path))
				}
			}
			if integrationResult.Spec.TopologyRef != "" {
				if _, ok := topologies[integrationResult.Spec.TopologyRef]; !ok {
					return fmt.Errorf("evidence %s references an unknown topology version", filepath.Base(path))
				}
			}
			auditPath := strings.TrimSuffix(path, ".yaml") + ".audit.jsonl"
			events, head, err := loadVerifiedAudit(auditPath)
			if err != nil {
				return err
			}
			if err := verifyIntegrationEvidenceAudit(events, integrationResult, catalogDigest); err != nil {
				return fmt.Errorf("bind evidence audit %s: %w", filepath.Base(auditPath), err)
			}
			terminal := events[len(events)-1]
			accepted := acceptedIntegrationEvidence{Result: integrationResult, AuditHead: head, OccurredAt: terminal.Metadata.OccurredAt}
			if existing, exists := acceptedIntegrationByID[integrationResult.Metadata.ResultID]; exists {
				if existing.AuditHead != accepted.AuditHead {
					return fmt.Errorf("integration evidence %s reuses result identity with mismatched audit binding", filepath.Base(path))
				}
				result.IntegrationDeduplicatedCount++
				return nil
			}
			acceptedIntegrationByID[integrationResult.Metadata.ResultID] = accepted
			for _, reference := range integrationResult.Spec.ComponentRefs {
				result.ComponentEvidence[reference] = append(result.ComponentEvidence[reference], accepted)
			}
			if integrationResult.Spec.TopologyRef != "" {
				result.TopologyEvidence[integrationResult.Spec.TopologyRef] = append(result.TopologyEvidence[integrationResult.Spec.TopologyRef], accepted)
			}
			result.AcceptedCount++
			result.VerifiedAuditCount++
			return nil
		}
		if kind == "PromotionReview" {
			pendingPromotionReviewPaths = append(pendingPromotionReviewPaths, path)
			return nil
		}
		if kind == "LifecycleProofApproval" {
			pendingLifecycleProofApprovalPaths = append(pendingLifecycleProofApprovalPaths, path)
			return nil
		}
		if kind == "IntegrationPublicationAttestation" {
			pendingIntegrationAttestationPaths = append(pendingIntegrationAttestationPaths, path)
			return nil
		}
		if kind == "PublicationChainRehearsal" {
			pendingPublicationChainRehearsalPaths = append(pendingPublicationChainRehearsalPaths, path)
			return nil
		}
		if kind == "PublicationChainRenewalReview" {
			pendingPublicationChainRenewalReviewPaths = append(pendingPublicationChainRenewalReviewPaths, path)
			return nil
		}
		if kind != "ContractTestResult" {
			return fmt.Errorf("evidence %s has unsupported kind %q", filepath.Base(path), kind)
		}
		contractResult, err := resources.LoadContractTestResult(path)
		if err != nil {
			return fmt.Errorf("load evidence %s: %w", filepath.Base(path), err)
		}
		if report := contractResult.Validate(); !report.Valid {
			return fmt.Errorf("evidence %s is invalid", filepath.Base(path))
		}
		assertion, ok := assertions[contractResult.Spec.AssertionRef]
		if !ok || contractResult.Spec.CatalogDigest != catalogDigest {
			return fmt.Errorf("evidence %s is not bound to this catalog", filepath.Base(path))
		}
		target, ok := snapshot.ContractTarget(assertion.ID)
		if !ok || contractResult.Spec.Target.RuntimeRef != target.RuntimeRef || contractResult.Spec.Target.ModelRef != target.ModelRef || contractResult.Spec.Target.HardwareProfileRef != target.HardwareProfileID {
			return fmt.Errorf("evidence %s target does not match the catalog assertion", filepath.Base(path))
		}
		auditPath := strings.TrimSuffix(path, ".yaml") + ".audit.jsonl"
		events, head, err := loadVerifiedAudit(auditPath)
		if err != nil {
			return err
		}
		if err := verifyEvidenceAudit(events, contractResult, catalogDigest); err != nil {
			return fmt.Errorf("bind evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		terminal := events[len(events)-1]
		result.Contracts[assertion.ID] = append(result.Contracts[assertion.ID], acceptedEvidence{Result: contractResult, AuditHead: head, OccurredAt: terminal.Metadata.OccurredAt})
		result.AcceptedCount++
		result.VerifiedAuditCount++
		return nil
	})
	if err != nil {
		return evidenceIndex{}, fmt.Errorf("discover catalog evidence: %w", err)
	}
	for _, path := range pendingPromotionReviewPaths {
		review, err := resources.LoadPromotionReview(path)
		if err != nil {
			return evidenceIndex{}, fmt.Errorf("load evidence %s: %w", filepath.Base(path), err)
		}
		if report := review.Validate(); !report.Valid || review.Spec.CatalogDigest != catalogDigest {
			return evidenceIndex{}, fmt.Errorf("evidence %s is invalid or not bound to this catalog", filepath.Base(path))
		}
		assertion, ok := assertions[review.Spec.AssertionRef]
		if !ok {
			return evidenceIndex{}, fmt.Errorf("evidence %s references an unknown assertion", filepath.Base(path))
		}
		acceptedEvidenceIDs := map[string]struct{}{}
		for _, item := range result.Contracts[assertion.ID] {
			acceptedEvidenceIDs[item.Result.Metadata.ResultID] = struct{}{}
		}
		for _, item := range result.ComponentEvidence {
			for _, integrationResult := range item {
				for _, componentRef := range integrationResult.Result.Spec.ComponentRefs {
					if componentRef == assertion.RuntimeRef {
						acceptedEvidenceIDs[integrationResult.Result.Metadata.ResultID] = struct{}{}
						break
					}
				}
			}
		}
		for _, selected := range review.Spec.SelectedEvidence {
			if _, ok := acceptedEvidenceIDs[selected]; !ok {
				return evidenceIndex{}, fmt.Errorf("evidence %s selects unknown or unbound evidence %s", filepath.Base(path), selected)
			}
		}
		auditPath := strings.TrimSuffix(path, ".yaml") + ".audit.jsonl"
		events, head, err := loadVerifiedAudit(auditPath)
		if err != nil {
			return evidenceIndex{}, err
		}
		if err := verifyPromotionReviewAudit(events, review, catalogDigest); err != nil {
			return evidenceIndex{}, fmt.Errorf("bind evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		terminal := events[len(events)-1]
		result.PromotionReviews[assertion.ID] = append(result.PromotionReviews[assertion.ID], acceptedPromotionReview{
			Review:     review,
			AuditHead:  head,
			OccurredAt: terminal.Metadata.OccurredAt,
		})
		result.AcceptedCount++
		result.VerifiedAuditCount++
	}
	for _, path := range pendingLifecycleProofApprovalPaths {
		approval, err := resources.LoadLifecycleProofApproval(path)
		if err != nil {
			return evidenceIndex{}, fmt.Errorf("load evidence %s: %w", filepath.Base(path), err)
		}
		if report := approval.Validate(); !report.Valid || approval.Spec.CatalogDigest != catalogDigest {
			return evidenceIndex{}, fmt.Errorf("evidence %s is invalid or not bound to this catalog", filepath.Base(path))
		}
		if _, ok := assertions[approval.Spec.AssertionRef]; !ok {
			return evidenceIndex{}, fmt.Errorf("evidence %s references an unknown assertion", filepath.Base(path))
		}
		acceptedEvidenceIDs := map[string]struct{}{}
		for _, item := range result.Contracts[approval.Spec.AssertionRef] {
			acceptedEvidenceIDs[item.Result.Metadata.ResultID] = struct{}{}
		}
		for _, selected := range approval.Spec.SelectedEvidence {
			if _, ok := acceptedEvidenceIDs[selected]; !ok {
				return evidenceIndex{}, fmt.Errorf("evidence %s selects unknown or unbound evidence %s", filepath.Base(path), selected)
			}
		}
		auditPath := strings.TrimSuffix(path, ".yaml") + ".audit.jsonl"
		events, head, err := loadVerifiedAudit(auditPath)
		if err != nil {
			return evidenceIndex{}, err
		}
		if err := verifyLifecycleProofApprovalAudit(events, approval, catalogDigest); err != nil {
			return evidenceIndex{}, fmt.Errorf("bind evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		terminal := events[len(events)-1]
		result.LifecycleProofApprovals[approval.Spec.AssertionRef] = append(result.LifecycleProofApprovals[approval.Spec.AssertionRef], acceptedLifecycleProofApproval{
			Approval:   approval,
			AuditHead:  head,
			OccurredAt: terminal.Metadata.OccurredAt,
		})
		result.AcceptedCount++
		result.VerifiedAuditCount++
	}
	for _, path := range pendingIntegrationAttestationPaths {
		attestation, err := resources.LoadIntegrationPublicationAttestation(path)
		if err != nil {
			return evidenceIndex{}, fmt.Errorf("load evidence %s: %w", filepath.Base(path), err)
		}
		if report := attestation.Validate(); !report.Valid || attestation.Spec.CatalogDigest != catalogDigest {
			return evidenceIndex{}, fmt.Errorf("evidence %s is invalid or not bound to this catalog", filepath.Base(path))
		}
		assertion, ok := assertions[attestation.Spec.AssertionRef]
		if !ok {
			return evidenceIndex{}, fmt.Errorf("evidence %s references an unknown assertion", filepath.Base(path))
		}
		acceptedEvidenceIDs := map[string]struct{}{}
		for _, item := range integrationEvidenceForAssertion(assertion, result.ComponentEvidence) {
			acceptedEvidenceIDs[item.Result.Metadata.ResultID] = struct{}{}
		}
		for _, selected := range attestation.Spec.SelectedEvidence {
			if _, ok := acceptedEvidenceIDs[selected]; !ok {
				return evidenceIndex{}, fmt.Errorf("evidence %s selects unknown or unbound evidence %s", filepath.Base(path), selected)
			}
		}
		auditPath := strings.TrimSuffix(path, ".yaml") + ".audit.jsonl"
		events, head, err := loadVerifiedAudit(auditPath)
		if err != nil {
			return evidenceIndex{}, err
		}
		if err := verifyIntegrationPublicationAttestationAudit(events, attestation, catalogDigest); err != nil {
			return evidenceIndex{}, fmt.Errorf("bind evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		terminal := events[len(events)-1]
		result.IntegrationAttestations[attestation.Spec.AssertionRef] = append(result.IntegrationAttestations[attestation.Spec.AssertionRef], acceptedIntegrationPublicationAttestation{
			Attestation: attestation,
			AuditHead:   head,
			OccurredAt:  terminal.Metadata.OccurredAt,
		})
		result.AcceptedCount++
		result.VerifiedAuditCount++
	}
	for _, path := range pendingPublicationChainRehearsalPaths {
		rehearsal, err := resources.LoadPublicationChainRehearsal(path)
		if err != nil {
			return evidenceIndex{}, fmt.Errorf("load evidence %s: %w", filepath.Base(path), err)
		}
		if report := rehearsal.Validate(); !report.Valid || rehearsal.Spec.CatalogDigest != catalogDigest {
			return evidenceIndex{}, fmt.Errorf("evidence %s is invalid or not bound to this catalog", filepath.Base(path))
		}
		if _, ok := assertions[rehearsal.Spec.AssertionRef]; !ok {
			return evidenceIndex{}, fmt.Errorf("evidence %s references an unknown assertion", filepath.Base(path))
		}
		approvalBound := false
		for _, item := range result.LifecycleProofApprovals[rehearsal.Spec.AssertionRef] {
			if item.Approval.Metadata.ApprovalID == rehearsal.Spec.LifecycleProofApprovalID {
				approvalBound = true
				break
			}
		}
		if !approvalBound {
			return evidenceIndex{}, fmt.Errorf("evidence %s references unknown lifecycle-proof approval %s", filepath.Base(path), rehearsal.Spec.LifecycleProofApprovalID)
		}
		attestationBound := false
		for _, item := range result.IntegrationAttestations[rehearsal.Spec.AssertionRef] {
			if item.Attestation.Metadata.AttestationID == rehearsal.Spec.IntegrationPublicationAttestationID {
				attestationBound = true
				break
			}
		}
		if !attestationBound {
			return evidenceIndex{}, fmt.Errorf("evidence %s references unknown integration publication attestation %s", filepath.Base(path), rehearsal.Spec.IntegrationPublicationAttestationID)
		}
		for _, authorizationID := range rehearsal.Spec.AuthorizationIDs {
			if !sha256Pattern.MatchString(authorizationID) {
				return evidenceIndex{}, fmt.Errorf("evidence %s contains invalid authorization identity %s", filepath.Base(path), authorizationID)
			}
		}
		auditPath := strings.TrimSuffix(path, ".yaml") + ".audit.jsonl"
		events, head, err := loadVerifiedAudit(auditPath)
		if err != nil {
			return evidenceIndex{}, err
		}
		if err := verifyPublicationChainRehearsalAudit(events, rehearsal, catalogDigest); err != nil {
			return evidenceIndex{}, fmt.Errorf("bind evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		terminal := events[len(events)-1]
		result.PublicationChainRehearsals[rehearsal.Spec.AssertionRef] = append(result.PublicationChainRehearsals[rehearsal.Spec.AssertionRef], acceptedPublicationChainRehearsal{
			Rehearsal:  rehearsal,
			AuditHead:  head,
			OccurredAt: terminal.Metadata.OccurredAt,
		})
		result.AcceptedCount++
		result.VerifiedAuditCount++
	}
	for _, path := range pendingPublicationChainRenewalReviewPaths {
		review, err := resources.LoadPublicationChainRenewalReview(path)
		if err != nil {
			return evidenceIndex{}, fmt.Errorf("load evidence %s: %w", filepath.Base(path), err)
		}
		if report := review.Validate(); !report.Valid || review.Spec.CatalogDigest != catalogDigest {
			return evidenceIndex{}, fmt.Errorf("evidence %s is invalid or not bound to this catalog", filepath.Base(path))
		}
		if _, ok := assertions[review.Spec.AssertionRef]; !ok {
			return evidenceIndex{}, fmt.Errorf("evidence %s references an unknown assertion", filepath.Base(path))
		}
		rehearsalBound := false
		for _, item := range result.PublicationChainRehearsals[review.Spec.AssertionRef] {
			if item.Rehearsal.Metadata.RehearsalID == review.Spec.PublicationChainRehearsalID {
				rehearsalBound = true
				break
			}
		}
		if !rehearsalBound {
			return evidenceIndex{}, fmt.Errorf("evidence %s references unknown publication-chain rehearsal %s", filepath.Base(path), review.Spec.PublicationChainRehearsalID)
		}
		promotionReviewBound := false
		for _, item := range result.PromotionReviews[review.Spec.AssertionRef] {
			if item.Review.Metadata.ReviewID == review.Spec.PromotionReviewID {
				promotionReviewBound = true
				break
			}
		}
		if !promotionReviewBound {
			return evidenceIndex{}, fmt.Errorf("evidence %s references unknown promotion review %s", filepath.Base(path), review.Spec.PromotionReviewID)
		}
		lifecycleApprovalBound := false
		for _, item := range result.LifecycleProofApprovals[review.Spec.AssertionRef] {
			if item.Approval.Metadata.ApprovalID == review.Spec.LifecycleProofApprovalID {
				lifecycleApprovalBound = true
				break
			}
		}
		if !lifecycleApprovalBound {
			return evidenceIndex{}, fmt.Errorf("evidence %s references unknown lifecycle-proof approval %s", filepath.Base(path), review.Spec.LifecycleProofApprovalID)
		}
		attestationBound := false
		for _, item := range result.IntegrationAttestations[review.Spec.AssertionRef] {
			if item.Attestation.Metadata.AttestationID == review.Spec.IntegrationPublicationAttestationID {
				attestationBound = true
				break
			}
		}
		if !attestationBound {
			return evidenceIndex{}, fmt.Errorf("evidence %s references unknown integration publication attestation %s", filepath.Base(path), review.Spec.IntegrationPublicationAttestationID)
		}
		auditPath := strings.TrimSuffix(path, ".yaml") + ".audit.jsonl"
		events, head, err := loadVerifiedAudit(auditPath)
		if err != nil {
			return evidenceIndex{}, err
		}
		if err := verifyPublicationChainRenewalReviewAudit(events, review, catalogDigest); err != nil {
			return evidenceIndex{}, fmt.Errorf("bind evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		terminal := events[len(events)-1]
		result.PublicationChainRenewalReviews[review.Spec.AssertionRef] = append(result.PublicationChainRenewalReviews[review.Spec.AssertionRef], acceptedPublicationChainRenewalReview{
			Review:     review,
			AuditHead:  head,
			OccurredAt: terminal.Metadata.OccurredAt,
		})
		result.AcceptedCount++
		result.VerifiedAuditCount++
	}
	result.IntegrationIdentityCount = len(acceptedIntegrationByID)
	return result, nil
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

func loadVerifiedAudit(path string) ([]audit.Event, string, error) {
	events, err := audit.LoadJSONL(path)
	if err != nil {
		return nil, "", fmt.Errorf("load evidence audit %s: %w", filepath.Base(path), err)
	}
	head, err := audit.Verify(events)
	if err != nil {
		return nil, "", fmt.Errorf("verify evidence audit %s: %w", filepath.Base(path), err)
	}
	return events, head, nil
}

func verifyEvidenceAudit(events []audit.Event, result resources.ContractTestResult, catalogDigest string) error {
	if len(events) != 2 {
		return fmt.Errorf("expected two events, found %d", len(events))
	}
	prefix, ok := map[string]string{
		"runtime-smoke": "contract.runtime-smoke", "model-inference": "contract.model-inference",
		"capacity-boundary": "contract.capacity-boundary", "sustained-capacity": "contract.sustained-capacity", "policy-contract": "contract.policy", "lifecycle-contract": "contract.lifecycle",
	}[result.Spec.Mode]
	if !ok {
		return errors.New("unsupported evidence mode")
	}
	suffix, outcome := "completed", "success"
	if result.Spec.Outcome == "blocked" {
		suffix, outcome = "blocked", "infeasible"
	} else if result.Spec.Outcome == "failed" {
		suffix, outcome = "failed", "failed"
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != prefix+"."+suffix || terminal.Spec.Outcome != outcome || terminal.Spec.Target != "ssh:"+result.Spec.Environment.ReferenceDigest {
		return errors.New("terminal action, outcome or target does not match result")
	}
	if !hasSubject(terminal.Spec.Subjects, "CatalogSnapshot", catalogDigest) || !hasSubject(terminal.Spec.Subjects, "ContractTestResult", result.Metadata.ResultID) {
		return errors.New("terminal event does not bind catalog and result identities")
	}
	return nil
}

func verifyIntegrationEvidenceAudit(events []audit.Event, result resources.IntegrationTestResult, catalogDigest string) error {
	if len(events) != 2 {
		return fmt.Errorf("expected two events, found %d", len(events))
	}
	prefix, ok := map[string]string{
		"component-smoke":     "integration.component-smoke",
		"topology-end-to-end": "integration.topology-end-to-end",
	}[result.Spec.Mode]
	if !ok {
		return errors.New("unsupported integration evidence mode")
	}
	suffix, outcome := "completed", "success"
	if result.Spec.Outcome == "blocked" {
		suffix, outcome = "blocked", "infeasible"
	} else if result.Spec.Outcome == "failed" {
		suffix, outcome = "failed", "failed"
	}
	terminal := events[len(events)-1]
	expectedTarget := result.Spec.Environment.Transport + ":" + result.Spec.Environment.ReferenceDigest
	if terminal.Spec.Action != prefix+"."+suffix || terminal.Spec.Outcome != outcome || terminal.Spec.Target != expectedTarget {
		return errors.New("terminal action, outcome or target does not match integration result")
	}
	if !hasSubject(terminal.Spec.Subjects, "CatalogSnapshot", catalogDigest) || !hasSubject(terminal.Spec.Subjects, "IntegrationTestResult", result.Metadata.ResultID) {
		return errors.New("terminal event does not bind catalog and integration-result identities")
	}
	return nil
}

func verifyPromotionReviewAudit(events []audit.Event, review resources.PromotionReview, catalogDigest string) error {
	if len(events) != 2 {
		return fmt.Errorf("expected two events, found %d", len(events))
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "promotion.review.completed" || terminal.Spec.Outcome != "success" || terminal.Spec.Target != "catalog:"+catalogDigest {
		return errors.New("terminal action, outcome or target does not match promotion review")
	}
	if !hasSubject(terminal.Spec.Subjects, "CatalogSnapshot", catalogDigest) || !hasSubject(terminal.Spec.Subjects, "PromotionReview", review.Metadata.ReviewID) {
		return errors.New("terminal event does not bind catalog and promotion-review identities")
	}
	return nil
}

func verifyLifecycleProofApprovalAudit(events []audit.Event, approval resources.LifecycleProofApproval, catalogDigest string) error {
	if len(events) != 2 {
		return fmt.Errorf("expected two events, found %d", len(events))
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "lifecycle.proof.approve-publication.completed" || terminal.Spec.Outcome != "success" || terminal.Spec.Target != "catalog:"+catalogDigest {
		return errors.New("terminal action, outcome or target does not match lifecycle-proof approval")
	}
	if !hasSubject(terminal.Spec.Subjects, "CatalogSnapshot", catalogDigest) || !hasSubject(terminal.Spec.Subjects, "LifecycleProofApproval", approval.Metadata.ApprovalID) || !hasSubject(terminal.Spec.Subjects, "LifecycleProofLedger", approval.Spec.LedgerID) {
		return errors.New("terminal event does not bind catalog, lifecycle-proof ledger and lifecycle-proof approval identities")
	}
	return nil
}

func verifyIntegrationPublicationAttestationAudit(events []audit.Event, attestation resources.IntegrationPublicationAttestation, catalogDigest string) error {
	if len(events) != 2 {
		return fmt.Errorf("expected two events, found %d", len(events))
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "integration.publish.attestation.completed" || terminal.Spec.Outcome != "success" || terminal.Spec.Target != "catalog:"+catalogDigest {
		return errors.New("terminal action, outcome or target does not match integration publication attestation")
	}
	if !hasSubject(terminal.Spec.Subjects, "CatalogSnapshot", catalogDigest) || !hasSubject(terminal.Spec.Subjects, "IntegrationPublicationAttestation", attestation.Metadata.AttestationID) {
		return errors.New("terminal event does not bind catalog and integration publication attestation identities")
	}
	for _, selected := range attestation.Spec.SelectedEvidence {
		if !hasSubject(terminal.Spec.Subjects, "IntegrationTestResult", selected) {
			return errors.New("terminal event does not bind selected integration evidence identities")
		}
	}
	return nil
}

func verifyPublicationChainRehearsalAudit(events []audit.Event, rehearsal resources.PublicationChainRehearsal, catalogDigest string) error {
	if len(events) != 2 {
		return fmt.Errorf("expected two events, found %d", len(events))
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "publication.chain.rehearse.completed" || terminal.Spec.Outcome != "success" || terminal.Spec.Target != "catalog:"+catalogDigest {
		return errors.New("terminal action, outcome or target does not match publication-chain rehearsal")
	}
	if !hasSubject(terminal.Spec.Subjects, "CatalogSnapshot", catalogDigest) || !hasSubject(terminal.Spec.Subjects, "PublicationChainRehearsal", rehearsal.Metadata.RehearsalID) || !hasSubject(terminal.Spec.Subjects, "LifecycleProofApproval", rehearsal.Spec.LifecycleProofApprovalID) || !hasSubject(terminal.Spec.Subjects, "IntegrationPublicationAttestation", rehearsal.Spec.IntegrationPublicationAttestationID) || !hasSubject(terminal.Spec.Subjects, Kind, rehearsal.Spec.CoverageReportID) || !hasSubject(terminal.Spec.Subjects, "AirgapGateTrustPolicy", rehearsal.Spec.TrustPolicyID) {
		return errors.New("terminal event does not bind publication-chain rehearsal evidence identities")
	}
	for _, authorizationID := range rehearsal.Spec.AuthorizationIDs {
		if !hasSubject(terminal.Spec.Subjects, "ExecutionAuthorization", authorizationID) {
			return errors.New("terminal event does not bind publication-chain rehearsal authorization identities")
		}
	}
	return nil
}

func verifyPublicationChainRenewalReviewAudit(events []audit.Event, review resources.PublicationChainRenewalReview, catalogDigest string) error {
	if len(events) != 2 {
		return fmt.Errorf("expected two events, found %d", len(events))
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "publication.chain.renewal-review.completed" || terminal.Spec.Outcome != "success" || terminal.Spec.Target != "catalog:"+catalogDigest {
		return errors.New("terminal action, outcome or target does not match publication-chain renewal review")
	}
	if !hasSubject(terminal.Spec.Subjects, "CatalogSnapshot", catalogDigest) ||
		!hasSubject(terminal.Spec.Subjects, "PublicationChainRenewalReview", review.Metadata.ReviewID) ||
		!hasSubject(terminal.Spec.Subjects, "PublicationChainRehearsal", review.Spec.PublicationChainRehearsalID) ||
		!hasSubject(terminal.Spec.Subjects, "PublicationChainRetentionDiagnosticsAudit", review.Spec.PublicationChainRetentionAuditHead) ||
		!hasSubject(terminal.Spec.Subjects, "PromotionReview", review.Spec.PromotionReviewID) ||
		!hasSubject(terminal.Spec.Subjects, "LifecycleProofApproval", review.Spec.LifecycleProofApprovalID) ||
		!hasSubject(terminal.Spec.Subjects, "IntegrationPublicationAttestation", review.Spec.IntegrationPublicationAttestationID) {
		return errors.New("terminal event does not bind publication-chain renewal review evidence identities")
	}
	return nil
}

func hasSubject(subjects []audit.Subject, kind, digest string) bool {
	for _, subject := range subjects {
		if subject.Kind == kind && subject.Digest == digest {
			return true
		}
	}
	return false
}

func (r Report) AssignReportID() (Report, error) {
	r.Metadata.ReportID = ""
	digest, err := canonical.Digest(r)
	if err != nil {
		return Report{}, fmt.Errorf("digest catalog coverage report: %w", err)
	}
	r.Metadata.ReportID = digest
	return r, nil
}

func (r Report) Validate() error {
	if r.APIVersion != APIVersion || r.Kind != Kind || !namePattern.MatchString(r.Metadata.Name) || !sha256Pattern.MatchString(r.Metadata.ReportID) {
		return errors.New("invalid catalog coverage report envelope")
	}
	if !sha256Pattern.MatchString(r.Spec.CatalogDigest) || len(r.Spec.Assertions) == 0 {
		return errors.New("catalog coverage report lacks catalog identity or assertions")
	}
	previousAssertion := ""
	eligible := 0
	for _, item := range r.Spec.Assertions {
		if item.ID <= previousAssertion || len(item.Gates) == 0 || !slices.IsSorted(item.Blockers) {
			return errors.New("catalog coverage assertions must be sorted and complete")
		}
		if item.LifecyclePublicationReady && item.LifecyclePublicationBlocker != "" {
			return errors.New("lifecycle publication blocker must be empty when lifecycle publication is ready")
		}
		if !item.LifecyclePublicationReady && strings.TrimSpace(item.LifecyclePublicationBlocker) == "" {
			return errors.New("lifecycle publication blocker is required when lifecycle publication is not ready")
		}
		if !item.LifecyclePublicationReady {
			if _, err := ParseLifecyclePublicationBlocker(item.LifecyclePublicationBlocker); err != nil {
				return errors.New("lifecycle publication blocker is required when lifecycle publication is not ready")
			}
		}
		previousGate := ""
		for _, gate := range item.Gates {
			if gate.ID <= previousGate || !slices.Contains([]string{"passed", "failed", "blocked", "missing", "not-implemented"}, gate.Status) {
				return errors.New("catalog coverage gates must be sorted and use known states")
			}
			if gate.SelectedResult != "" && !sha256Pattern.MatchString(gate.SelectedResult) || gate.SelectedAuditHead != "" && !sha256Pattern.MatchString(gate.SelectedAuditHead) {
				return errors.New("catalog coverage evidence identities must be SHA-256 digests")
			}
			selectedBound := gate.SelectedResult == ""
			seenEvidence := make(map[string]struct{}, len(gate.ObservedEvidence))
			for _, evidence := range gate.ObservedEvidence {
				if !sha256Pattern.MatchString(evidence.ResultID) || !sha256Pattern.MatchString(evidence.AuditHead) || !slices.Contains([]string{"passed", "failed", "blocked"}, evidence.Outcome) {
					return errors.New("catalog coverage observed evidence binding is invalid")
				}
				if _, exists := seenEvidence[evidence.ResultID]; exists {
					return errors.New("catalog coverage observed evidence contains a duplicate result")
				}
				seenEvidence[evidence.ResultID] = struct{}{}
				if evidence.ResultID == gate.SelectedResult && evidence.AuditHead == gate.SelectedAuditHead && evidence.Outcome == gate.Status {
					selectedBound = true
				}
			}
			if !selectedBound {
				return errors.New("selected catalog coverage evidence is not present in observed bindings")
			}
			if gate.Status == "passed" && gate.ID != "artifact-identity" && (gate.SelectedResult == "" || gate.SelectedAuditHead == "" || gate.Blocker != "") {
				return errors.New("passing contract gates require selected audited evidence")
			}
			previousGate = gate.ID
		}
		if item.PromotionEligible {
			eligible++
		}
		previousAssertion = item.ID
	}
	for _, collection := range [][]ManifestCoverage{r.Spec.Capabilities, r.Spec.Components, r.Spec.Models, r.Spec.Hardware, r.Spec.Topologies} {
		previous := ""
		for _, item := range collection {
			if item.ID <= previous || !slices.Contains([]string{"none", "partial", "complete"}, item.Coverage) || !slices.IsSorted(item.RelatedAssertions) || !slices.IsSorted(item.PassedModes) || !slices.IsSorted(item.Blockers) {
				return errors.New("manifest coverage must be sorted and use known states")
			}
			previous = item.ID
		}
	}
	lifecycleReady, lifecycleBlocked := 0, 0
	for _, assertion := range r.Spec.Assertions {
		if assertion.LifecyclePublicationReady {
			lifecycleReady++
		} else {
			lifecycleBlocked++
		}
	}
	if r.Spec.Summary.CapabilityCount != len(r.Spec.Capabilities) || r.Spec.Summary.ComponentCount != len(r.Spec.Components) || r.Spec.Summary.ModelCount != len(r.Spec.Models) || r.Spec.Summary.HardwareProfileCount != len(r.Spec.Hardware) || r.Spec.Summary.AssertionCount != len(r.Spec.Assertions) || r.Spec.Summary.TopologyCount != len(r.Spec.Topologies) || r.Spec.Summary.PromotionEligibleAssertions != eligible || r.Spec.Summary.LifecyclePublicationReadyAssertions != lifecycleReady || r.Spec.Summary.LifecyclePublicationBlockedAssertions != lifecycleBlocked || !slices.IsSorted(r.Spec.Limitations) {
		return errors.New("catalog coverage summary or limitations do not match report contents")
	}
	claimed := r.Metadata.ReportID
	recomputed, err := r.AssignReportID()
	if err != nil || recomputed.Metadata.ReportID != claimed {
		return errors.New("catalog coverage report identity mismatch")
	}
	return nil
}

func Load(path string) (Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Report{}, fmt.Errorf("read catalog coverage report: %w", err)
	}
	if len(data) > 4<<20 {
		return Report{}, errors.New("catalog coverage report exceeds the 4 MiB limit")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, fmt.Errorf("decode catalog coverage report: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return Report{}, errors.New("catalog coverage report contains multiple documents")
	} else if !errors.Is(err, io.EOF) {
		return Report{}, fmt.Errorf("decode trailing catalog coverage data: %w", err)
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}
