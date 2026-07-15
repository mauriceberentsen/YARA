// Package planner compiles validated intent, inventory and an immutable catalog
// snapshot into an explainable PlatformPlan. It performs no I/O or mutation.
package planner

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
)

type Result struct {
	Plan   resources.PlatformPlan
	Report diagnostics.Report
}

type evaluatedCandidate struct {
	Candidate    catalog.ServingCandidate
	EstimatedGiB float64
	AvailableGiB float64
	Rejection    *diagnostics.Diagnostic
}

func Create(request resources.PlatformRequest, inventory resources.Inventory, snapshot catalog.Snapshot) Result {
	if report := request.Validate(); !report.Valid {
		return Result{Report: report}
	}
	if report := inventory.Validate(); !report.Valid {
		return Result{Report: report}
	}
	if report := snapshot.Validate(); !report.Valid {
		return Result{Report: report}
	}
	requiredUseCases := make([]string, 0, len(request.Spec.UseCases))
	for _, useCase := range request.Spec.UseCases {
		if useCase.Required {
			requiredUseCases = append(requiredUseCases, useCase.ID)
		}
	}
	sort.Strings(requiredUseCases)
	topologyTemplate, ok := snapshot.SelectTopology(requiredUseCases)
	if !ok {
		return Result{Report: diagnostics.NewReport(diagnostics.Error("YARA-PLAN-002", "No topology template satisfies the required use cases.", "spec.useCases"))}
	}

	host := inventory.Spec.Hosts[0]
	accelerator := host.Accelerators[0]
	candidates := snapshot.Candidates()
	evaluated := make([]evaluatedCandidate, 0, len(candidates))
	feasible := make([]evaluatedCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		item := evaluate(request, accelerator, candidate)
		evaluated = append(evaluated, item)
		if item.Rejection == nil {
			feasible = append(feasible, item)
		}
	}
	if len(feasible) == 0 {
		diagnostic := diagnostics.Error(
			"YARA-PLAN-001",
			"No catalog candidate satisfies all hard constraints.",
			"spec.candidates",
		)
		return Result{Report: diagnostics.NewReport(diagnostic)}
	}

	sort.SliceStable(feasible, func(i, j int) bool {
		if feasible[i].Candidate.PreferenceScore == feasible[j].Candidate.PreferenceScore {
			return feasible[i].Candidate.ID < feasible[j].Candidate.ID
		}
		return feasible[i].Candidate.PreferenceScore > feasible[j].Candidate.PreferenceScore
	})
	selected := feasible[0]
	acceleratorInstanceID := ""
	for _, role := range topologyTemplate.Roles {
		if role.RequiresAccelerator {
			acceleratorInstanceID = role.ID
			break
		}
	}
	resolvedTopology, topologyDecisions, topologyReport := resolveTopology(request, inventory.Spec.Hosts[0], accelerator, topologyTemplate, selected, snapshot)
	if !topologyReport.Valid {
		return Result{Report: topologyReport}
	}

	requestDigest, err := canonical.Digest(request)
	if err != nil {
		return internalFailure("request", err)
	}
	inventoryDigest, err := canonical.Digest(inventory)
	if err != nil {
		return internalFailure("inventory", err)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return internalFailure("catalog", err)
	}

	planDiagnostics := snapshot.Diagnostics()
	if strings.Contains(strings.ToLower(accelerator.DriverVersion), "unverified") {
		planDiagnostics = append(planDiagnostics, diagnostics.Diagnostic{
			Code: "YARA-INV-002", Severity: diagnostics.SeverityWarning,
			Message: "Accelerator driver compatibility must be verified before apply.",
			Paths:   []string{"spec.hosts[0].accelerators[0].driverVersion"},
		})
	}

	plan := resources.PlatformPlan{
		APIVersion: resources.APIVersion,
		Kind:       "PlatformPlan",
		Metadata:   resources.PlanMetadata{Name: request.Metadata.Name},
		Provenance: resources.PlanProvenance{
			RequestDigest: requestDigest, InventoryDigest: inventoryDigest,
			CatalogDigest: catalogDigest, PlannerVersion: version.Version,
		},
		Spec: resources.PlatformPlanSpec{
			Status:     "review-required",
			Search:     buildSearchSummary(evaluated, feasible),
			Confidence: buildConfidenceSummary(selected, planDiagnostics, accelerator, catalogDigest),
			Topology:   resolvedTopology,
			Allocations: []resources.PlanAllocation{{
				InstanceID: acceleratorInstanceID, AcceleratorID: accelerator.ID,
				EstimatedMemoryGiB:   selected.EstimatedGiB,
				AllocatableMemoryGiB: selected.AvailableGiB,
			}},
			Decisions:   append([]resources.PlanDecision{buildDecision(acceleratorInstanceID, selected, evaluated)}, topologyDecisions...),
			Diagnostics: planDiagnostics,
		},
	}
	plan, err = plan.AssignPlanID()
	if err != nil {
		return internalFailure("plan", err)
	}
	if report := plan.Validate(); !report.Valid {
		return Result{Report: report}
	}
	return Result{Plan: plan, Report: diagnostics.NewReport()}
}

func buildSearchSummary(evaluated, feasible []evaluatedCandidate) resources.PlanSearchSummary {
	boundaries := []string{
		"catalog-snapshot-only",
		"chat-and-coding-use-cases-only",
		"first-matching-topology-template",
		"no-live-benchmark-evaluation",
		"single-host-homogeneous-nvidia",
	}
	return resources.PlanSearchSummary{
		Strategy: "bounded-catalog-enumeration-v1", CompleteWithinBounds: true,
		Truncated: false, GlobalOptimalityClaimed: false,
		EvaluatedServingCandidates: len(evaluated), FeasibleServingCandidates: len(feasible),
		RejectedServingCandidates: len(evaluated) - len(feasible), Boundaries: boundaries,
	}
}

func buildConfidenceSummary(selected evaluatedCandidate, planDiagnostics []diagnostics.Diagnostic, accelerator resources.Accelerator, catalogDigest string) resources.PlanConfidenceSummary {
	evidenceLevel := minimumEvidenceConfidence(selected.Candidate.Evidence)
	evidenceRefs := make([]string, 0, len(selected.Candidate.Evidence)+1)
	evidenceRefs = append(evidenceRefs, selected.Candidate.ID)
	for _, evidence := range selected.Candidate.Evidence {
		evidenceRefs = append(evidenceRefs, evidence.ID)
	}
	sort.Strings(evidenceRefs)
	catalogLevel := "medium"
	inventoryLevel := "medium"
	for _, diagnostic := range planDiagnostics {
		switch diagnostic.Code {
		case "YARA-CAT-055":
			catalogLevel = "low"
		case "YARA-INV-002":
			inventoryLevel = "low"
		}
	}
	factors := []resources.PlanConfidenceFactor{
		{ID: "capacity-method", Level: "low", ReasonCode: "YARA-CONF-004", SubjectRefs: []string{selected.Candidate.ID}},
		{ID: "catalog-maturity", Level: catalogLevel, ReasonCode: "YARA-CONF-002", SubjectRefs: []string{catalogDigest}},
		{ID: "inventory-assurance", Level: inventoryLevel, ReasonCode: "YARA-CONF-003", SubjectRefs: []string{accelerator.ID}},
		{ID: "serving-evidence", Level: evidenceLevel, ReasonCode: "YARA-CONF-001", SubjectRefs: evidenceRefs},
	}
	level := "high"
	for _, factor := range factors {
		if confidenceRank(factor.Level) < confidenceRank(level) {
			level = factor.Level
		}
	}
	return resources.PlanConfidenceSummary{Level: level, Method: "minimum-factor-v1", Factors: factors}
}

func minimumEvidenceConfidence(evidence []catalog.EvidenceReference) string {
	if len(evidence) == 0 {
		return "low"
	}
	minimum := "high"
	for _, item := range evidence {
		if confidenceRank(item.Confidence) < confidenceRank(minimum) {
			minimum = item.Confidence
		}
	}
	return minimum
}

func confidenceRank(value string) int {
	switch value {
	case "medium":
		return 1
	case "high":
		return 2
	default:
		return 0
	}
}

func resolveTopology(request resources.PlatformRequest, host resources.Host, accelerator resources.Accelerator, template catalog.TopologyTemplate, selected evaluatedCandidate, snapshot catalog.Snapshot) (resources.PlanTopology, []resources.PlanDecision, diagnostics.Report) {
	topology := resources.PlanTopology{DeploymentStages: template.DeploymentStages}
	decisions := []resources.PlanDecision{{
		ID: "decision.topology", Selected: template.ID,
		Reasons:  []string{"Template satisfies all required use cases and defines an acyclic abstract role graph."},
		Evidence: []string{template.ID}, Alternatives: []resources.PlanAlternative{},
	}}
	for _, role := range template.Roles {
		requiredContracts := topologyContracts(role.ID, template.Connections)
		instance := resources.PlanInstance{ID: role.ID, Role: role.Role, APIContracts: requiredContracts}
		if role.RequiresAccelerator {
			if !isSubset(requiredContracts, selected.Candidate.APIContracts) {
				return resources.PlanTopology{}, nil, diagnostics.NewReport(diagnostics.Error("YARA-PLAN-024", "Selected accelerator component does not implement every topology contract.", role.ID))
			}
			instance.ComponentRef = selected.Candidate.RuntimeRef
			instance.ModelRef = selected.Candidate.ModelRef
			instance.Placement = host.ID + "/" + accelerator.ID
		} else {
			components := snapshot.ComponentsForRole(role.Role)
			var chosen *catalog.ComponentCandidate
			for index := range components {
				if componentAllowed(request, components[index]) && isSubset(requiredContracts, components[index].APIContracts) {
					chosen = &components[index]
					break
				}
			}
			if chosen == nil {
				return resources.PlanTopology{}, nil, diagnostics.NewReport(diagnostics.Error("YARA-PLAN-023", "No policy-compliant component implements the required topology role and contracts.", role.ID))
			}
			instance.ComponentRef = chosen.ComponentRef
			instance.Placement = host.ID
			decisions = append(decisions, resources.PlanDecision{
				ID: "decision." + role.ID, Selected: chosen.ID,
				Reasons:  []string{"Component implements the abstract role, required interfaces and effective policies."},
				Evidence: []string{chosen.ID}, Alternatives: []resources.PlanAlternative{},
			})
		}
		topology.Instances = append(topology.Instances, instance)
	}
	for _, connection := range template.Connections {
		topology.Connections = append(topology.Connections, resources.PlanConnection{From: connection.From, To: connection.To, Contract: connection.Contract})
	}
	sort.SliceStable(topology.Instances, func(i, j int) bool { return topology.Instances[i].ID < topology.Instances[j].ID })
	sort.SliceStable(topology.Connections, func(i, j int) bool {
		left := topology.Connections[i].From + "\x00" + topology.Connections[i].To + "\x00" + topology.Connections[i].Contract
		right := topology.Connections[j].From + "\x00" + topology.Connections[j].To + "\x00" + topology.Connections[j].Contract
		return left < right
	})
	return topology, decisions, diagnostics.NewReport()
}

func topologyContracts(roleID string, connections []catalog.TopologyConnection) []string {
	var contracts []string
	for _, connection := range connections {
		if (connection.From == roleID || connection.To == roleID) && !slices.Contains(contracts, connection.Contract) {
			contracts = append(contracts, connection.Contract)
		}
	}
	sort.Strings(contracts)
	return contracts
}

func componentAllowed(request resources.PlatformRequest, component catalog.ComponentCandidate) bool {
	if request.Spec.Policies.OpenSourceOnly != nil && *request.Spec.Policies.OpenSourceOnly && !component.Policy.OpenSource {
		return false
	}
	if request.Spec.Policies.ExternalEgress == "forbidden" && component.Policy.ExternalEgress {
		return false
	}
	if request.Spec.Policies.Telemetry == "forbidden" && component.Policy.Telemetry {
		return false
	}
	return request.Spec.Policies.ArtifactVerification != "required" || component.Policy.ArtifactVerified
}

func isSubset(required, available []string) bool {
	for _, value := range required {
		if !slices.Contains(available, value) {
			return false
		}
	}
	return true
}

func evaluate(request resources.PlatformRequest, accelerator resources.Accelerator, candidate catalog.ServingCandidate) evaluatedCandidate {
	estimated := estimateMemory(request.Spec.Workload.PeakConcurrentRequests, candidate.Memory)
	item := evaluatedCandidate{Candidate: candidate, EstimatedGiB: estimated, AvailableGiB: float64(accelerator.AllocatableMemoryGiB)}
	if !strings.EqualFold(accelerator.Vendor, candidate.HardwareVendor) || !slices.Contains(candidate.HardwareModels, accelerator.Model) {
		item.Rejection = rejection("YARA-HW-002", "Candidate is not asserted compatible with the inventoried accelerator.")
		return item
	}

	for _, useCase := range request.Spec.UseCases {
		if useCase.Required && !slices.Contains(candidate.Capabilities, useCase.ID) {
			item.Rejection = rejection("YARA-CAP-001", "Candidate does not supply required capability "+useCase.ID+".")
			return item
		}
	}
	if request.Spec.Policies.OpenSourceOnly != nil && *request.Spec.Policies.OpenSourceOnly && !candidate.Policy.OpenSource {
		item.Rejection = rejection("YARA-POL-010", "Candidate conflicts with the open-source-only policy.")
		return item
	}
	if request.Spec.Policies.ExternalEgress == "forbidden" && candidate.Policy.ExternalEgress {
		item.Rejection = rejection("YARA-POL-011", "Candidate requires forbidden external egress.")
		return item
	}
	if request.Spec.Policies.Telemetry == "forbidden" && candidate.Policy.Telemetry {
		item.Rejection = rejection("YARA-POL-012", "Candidate requires forbidden telemetry.")
		return item
	}
	if request.Spec.Policies.ArtifactVerification == "required" && !candidate.Policy.ArtifactVerified {
		item.Rejection = rejection("YARA-POL-013", "Candidate has no verified artifact.")
		return item
	}
	if estimated > item.AvailableGiB {
		item.Rejection = rejection(
			"YARA-HW-004",
			fmt.Sprintf("Estimated accelerator memory %.2f GiB exceeds %.2f GiB allocatable memory.", estimated, item.AvailableGiB),
		)
	}
	return item
}

func estimateMemory(concurrency int, memory catalog.MemoryModel) float64 {
	base := memory.WeightsGiB + memory.RuntimeOverheadGiB + float64(concurrency)*memory.KVCachePerConcurrentRequestGiB
	return base * (1 + memory.HeadroomPercent/100)
}

func rejection(code, message string) *diagnostics.Diagnostic {
	diagnostic := diagnostics.Error(code, message, "spec.candidates")
	return &diagnostic
}

func buildDecision(instanceID string, selected evaluatedCandidate, evaluated []evaluatedCandidate) resources.PlanDecision {
	alternatives := make([]resources.PlanAlternative, 0, len(evaluated)-1)
	for _, item := range evaluated {
		if item.Candidate.ID == selected.Candidate.ID {
			continue
		}
		alternative := resources.PlanAlternative{
			ID: item.Candidate.ID, EstimatedGiB: item.EstimatedGiB,
			AvailableGiB: item.AvailableGiB, PreferenceScore: item.Candidate.PreferenceScore,
		}
		if item.Rejection != nil {
			alternative.Outcome = "rejected"
			alternative.Code = item.Rejection.Code
			alternative.Reason = item.Rejection.Message
		} else {
			alternative.Outcome = "not-selected"
			alternative.Reason = "Candidate has a lower soft preference score."
		}
		alternatives = append(alternatives, alternative)
	}
	sort.SliceStable(alternatives, func(i, j int) bool { return alternatives[i].ID < alternatives[j].ID })
	evidence := make([]string, 0, len(selected.Candidate.Evidence))
	for _, reference := range selected.Candidate.Evidence {
		evidence = append(evidence, reference.ID)
	}
	sort.Strings(evidence)
	return resources.PlanDecision{
		ID: "decision." + instanceID, Selected: selected.Candidate.ID,
		Reasons: []string{
			fmt.Sprintf("Fits accelerator memory with cataloged headroom: %.2f GiB required of %.2f GiB allocatable.", selected.EstimatedGiB, selected.AvailableGiB),
			"Satisfies all required capabilities and effective policies.",
			"Has the highest soft preference score among feasible candidates.",
		},
		Evidence: evidence, Alternatives: alternatives,
	}
}

func internalFailure(subject string, err error) Result {
	diagnostic := diagnostics.Error("YARA-PLAN-500", "Failed to calculate "+subject+" identity: "+err.Error())
	return Result{Report: diagnostics.NewReport(diagnostic)}
}
