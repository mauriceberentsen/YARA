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
			Status: "review-required",
			Topology: resources.PlanTopology{
				Instances: []resources.PlanInstance{{
					ID: "inference", Role: "inference.text-generation",
					RuntimeRef: selected.Candidate.RuntimeRef, ModelRef: selected.Candidate.ModelRef,
					Placement:   host.ID + "/" + accelerator.ID,
					APIContract: selected.Candidate.APIContracts[0],
				}},
				Connections:      []resources.PlanConnection{},
				DeploymentStages: [][]string{{"inference"}},
			},
			Allocations: []resources.PlanAllocation{{
				InstanceID: "inference", AcceleratorID: accelerator.ID,
				EstimatedMemoryGiB:   selected.EstimatedGiB,
				AllocatableMemoryGiB: selected.AvailableGiB,
			}},
			Decisions:   []resources.PlanDecision{buildDecision(selected, evaluated)},
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

func buildDecision(selected evaluatedCandidate, evaluated []evaluatedCandidate) resources.PlanDecision {
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
		ID: "decision.inference", Selected: selected.Candidate.ID,
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
