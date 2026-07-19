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
	"strings"

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
}

var (
	sha256Pattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)
)

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
	ManifestCount               int `json:"manifestCount" yaml:"manifestCount"`
	CapabilityCount             int `json:"capabilityCount" yaml:"capabilityCount"`
	ComponentCount              int `json:"componentCount" yaml:"componentCount"`
	ModelCount                  int `json:"modelCount" yaml:"modelCount"`
	HardwareProfileCount        int `json:"hardwareProfileCount" yaml:"hardwareProfileCount"`
	AssertionCount              int `json:"assertionCount" yaml:"assertionCount"`
	TopologyCount               int `json:"topologyCount" yaml:"topologyCount"`
	AcceptedEvidenceCount       int `json:"acceptedEvidenceCount" yaml:"acceptedEvidenceCount"`
	VerifiedAuditChainCount     int `json:"verifiedAuditChainCount" yaml:"verifiedAuditChainCount"`
	PromotionEligibleAssertions int `json:"promotionEligibleAssertions" yaml:"promotionEligibleAssertions"`
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
	ID                 string         `json:"id" yaml:"id"`
	Status             string         `json:"status" yaml:"status"`
	RuntimeRef         string         `json:"runtimeRef" yaml:"runtimeRef"`
	ModelRef           string         `json:"modelRef" yaml:"modelRef"`
	HardwareProfileRef string         `json:"hardwareProfileRef" yaml:"hardwareProfileRef"`
	PromotionEligible  bool           `json:"promotionEligible" yaml:"promotionEligible"`
	Gates              []GateCoverage `json:"gates" yaml:"gates"`
	Blockers           []string       `json:"blockers" yaml:"blockers"`
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
				"Sustained-capacity and independent-promotion gates are represented but are not yet executable YARA contract modes.",
			},
		},
	}
	slices.Sort(report.Spec.Limitations)
	for _, assertion := range inventory.Compatibility {
		coverage := assertionCoverage(assertion, evidence[assertion.ID])
		report.Spec.Assertions = append(report.Spec.Assertions, coverage)
		if coverage.PromotionEligible {
			report.Spec.Summary.PromotionEligibleAssertions++
		}
	}
	report.Spec.Components = manifestCoverage(inventory.Components, report.Spec.Assertions, evidence, func(assertion AssertionCoverage, id string) bool { return assertion.RuntimeRef == id })
	report.Spec.Models = manifestCoverage(inventory.Models, report.Spec.Assertions, evidence, func(assertion AssertionCoverage, id string) bool { return assertion.ModelRef == id })
	report.Spec.Hardware = manifestCoverage(inventory.Hardware, report.Spec.Assertions, evidence, func(assertion AssertionCoverage, id string) bool { return assertion.HardwareProfileRef == id })
	report.Spec.Capabilities = structuralCoverage(inventory.Capabilities)
	report.Spec.Topologies = untestedTopologyCoverage(inventory.Topologies)
	report.Spec.Summary.ManifestCount = len(inventory.Capabilities) + len(inventory.Components) + len(inventory.Models) + len(inventory.Hardware) + len(inventory.Compatibility) + len(inventory.Topologies)
	report.Spec.Summary.CapabilityCount = len(inventory.Capabilities)
	report.Spec.Summary.ComponentCount = len(inventory.Components)
	report.Spec.Summary.ModelCount = len(inventory.Models)
	report.Spec.Summary.HardwareProfileCount = len(inventory.Hardware)
	report.Spec.Summary.AssertionCount = len(inventory.Compatibility)
	report.Spec.Summary.TopologyCount = len(inventory.Topologies)
	for _, byAssertion := range evidence {
		report.Spec.Summary.AcceptedEvidenceCount += len(byAssertion)
		report.Spec.Summary.VerifiedAuditChainCount += len(byAssertion)
	}
	report.Spec.Complete = report.Spec.Summary.AssertionCount > 0 && report.Spec.Summary.PromotionEligibleAssertions == report.Spec.Summary.AssertionCount && allManifestCoverageComplete(report)
	return report.AssignReportID()
}

func assertionCoverage(assertion catalog.AssertionDescriptor, evidence []acceptedEvidence) AssertionCoverage {
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
	coverage.Gates = append(coverage.Gates,
		GateCoverage{ID: "independent-promotion-review", Status: "missing", ObservedEvidence: []EvidenceBinding{}, Blocker: "promotion-review-not-recorded"},
		GateCoverage{ID: "sustained-capacity", Status: "not-implemented", ObservedEvidence: []EvidenceBinding{}, Blocker: "sustained-capacity-contract-not-implemented"},
	)
	slices.SortFunc(coverage.Gates, func(left, right GateCoverage) int { return strings.Compare(left.ID, right.ID) })
	for _, gate := range coverage.Gates {
		if gate.Status != "passed" {
			coverage.Blockers = append(coverage.Blockers, gate.ID+":"+gate.Blocker)
		}
	}
	if len(evidence) == 0 {
		coverage.Blockers = append(coverage.Blockers, "external-target:no-observed-target-evidence")
	}
	slices.Sort(coverage.Blockers)
	coverage.PromotionEligible = slices.Contains([]string{"known", "experimental", "supported"}, assertion.Status) && assertion.Compatibility == "supported" && len(coverage.Blockers) == 0
	return coverage
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

func untestedTopologyCoverage(manifests []catalog.ManifestDescriptor) []ManifestCoverage {
	result := make([]ManifestCoverage, 0, len(manifests))
	for _, manifest := range manifests {
		result = append(result, ManifestCoverage{
			ID: manifest.ID, Version: manifest.Version, Status: manifest.Status, Coverage: "none",
			RelatedAssertions: []string{}, PassedModes: []string{}, Blockers: []string{"no-topology-integration-evidence"},
		})
	}
	return result
}

func loadEvidence(directory string, snapshot catalog.Snapshot, catalogDigest string) (map[string][]acceptedEvidence, error) {
	result := make(map[string][]acceptedEvidence)
	assertions := make(map[string]catalog.AssertionDescriptor)
	for _, assertion := range snapshot.ManifestInventory().Compatibility {
		assertions[assertion.ID] = assertion
	}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			return nil
		}
		contractResult, err := resources.LoadContractTestResult(path)
		if err != nil {
			return fmt.Errorf("load evidence %s: %w", filepath.Base(path), err)
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
		events, err := audit.LoadJSONL(auditPath)
		if err != nil {
			return fmt.Errorf("load evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		head, err := audit.Verify(events)
		if err != nil {
			return fmt.Errorf("verify evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		if err := verifyEvidenceAudit(events, contractResult, catalogDigest); err != nil {
			return fmt.Errorf("bind evidence audit %s: %w", filepath.Base(auditPath), err)
		}
		terminal := events[len(events)-1]
		result[assertion.ID] = append(result[assertion.ID], acceptedEvidence{Result: contractResult, AuditHead: head, OccurredAt: terminal.Metadata.OccurredAt})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("discover catalog evidence: %w", err)
	}
	return result, nil
}

func verifyEvidenceAudit(events []audit.Event, result resources.ContractTestResult, catalogDigest string) error {
	if len(events) != 2 {
		return fmt.Errorf("expected two events, found %d", len(events))
	}
	prefix, ok := map[string]string{
		"runtime-smoke": "contract.runtime-smoke", "model-inference": "contract.model-inference",
		"capacity-boundary": "contract.capacity-boundary", "policy-contract": "contract.policy", "lifecycle-contract": "contract.lifecycle",
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
	if r.Spec.Summary.CapabilityCount != len(r.Spec.Capabilities) || r.Spec.Summary.ComponentCount != len(r.Spec.Components) || r.Spec.Summary.ModelCount != len(r.Spec.Models) || r.Spec.Summary.HardwareProfileCount != len(r.Spec.Hardware) || r.Spec.Summary.AssertionCount != len(r.Spec.Assertions) || r.Spec.Summary.TopologyCount != len(r.Spec.Topologies) || r.Spec.Summary.PromotionEligibleAssertions != eligible || !slices.IsSorted(r.Spec.Limitations) {
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
