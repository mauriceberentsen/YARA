// Package plandiff compares two valid immutable plans without interpreting
// renderer-specific state. Classifications are conservative and limited to
// facts represented by the v1alpha1 PlatformPlan contract.
package plandiff

import (
	"fmt"
	"sort"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type collector struct {
	changes      []resources.PlanChange
	decisionRefs []string
}

func Compare(from, to resources.PlatformPlan) (resources.PlatformPlanDiff, error) {
	if report := from.Validate(); !report.Valid {
		return resources.PlatformPlanDiff{}, fmt.Errorf("from plan is invalid: %s", report.Diagnostics[0].Code)
	}
	if report := to.Validate(); !report.Valid {
		return resources.PlatformPlanDiff{}, fmt.Errorf("to plan is invalid: %s", report.Diagnostics[0].Code)
	}

	c := collector{changes: []resources.PlanChange{}, decisionRefs: changedDecisionIDs(from.Spec.Decisions, to.Spec.Decisions)}
	causes, err := compareProvenance(from.Provenance, to.Provenance)
	if err != nil {
		return resources.PlatformPlanDiff{}, err
	}
	provenanceChanges := []struct {
		path    string
		summary string
		before  string
		after   string
	}{
		{"provenance.requestDigest", "Request input identity changed.", from.Provenance.RequestDigest, to.Provenance.RequestDigest},
		{"provenance.inventoryDigest", "Inventory input identity changed.", from.Provenance.InventoryDigest, to.Provenance.InventoryDigest},
		{"provenance.catalogDigest", "Catalog snapshot identity changed.", from.Provenance.CatalogDigest, to.Provenance.CatalogDigest},
		{"provenance.plannerVersion", "Planner version changed.", from.Provenance.PlannerVersion, to.Provenance.PlannerVersion},
	}
	for _, change := range provenanceChanges {
		if err := c.compareValue(change.path, resources.DiffClassificationProvenanceChange, resources.DiffImpactReview, change.summary, change.before, change.after, false); err != nil {
			return resources.PlatformPlanDiff{}, err
		}
	}
	if err := c.compareValue("metadata.name", resources.DiffClassificationPresentationOnly, resources.DiffImpactNone, "Plan display name changed.", from.Metadata.Name, to.Metadata.Name, false); err != nil {
		return resources.PlatformPlanDiff{}, err
	}
	if err := c.compareValue("spec.search", resources.DiffClassificationProvenanceChange, resources.DiffImpactReview, "Planner search bounds or coverage changed.", from.Spec.Search, to.Spec.Search, false); err != nil {
		return resources.PlatformPlanDiff{}, err
	}
	if err := c.compareValue("spec.confidence", resources.DiffClassificationProvenanceChange, resources.DiffImpactReview, "Recommendation confidence or its evidence factors changed.", from.Spec.Confidence, to.Spec.Confidence, false); err != nil {
		return resources.PlatformPlanDiff{}, err
	}
	if err := c.compareInstances(from.Spec.Topology.Instances, to.Spec.Topology.Instances); err != nil {
		return resources.PlatformPlanDiff{}, err
	}
	if err := c.compareValue("spec.topology.connections", resources.DiffClassificationConfigurationUpdate, resources.DiffImpactRedeploy, "Topology connections changed.", normalizedConnections(from.Spec.Topology.Connections), normalizedConnections(to.Spec.Topology.Connections), true); err != nil {
		return resources.PlatformPlanDiff{}, err
	}
	if err := c.compareValue("spec.topology.deploymentStages", resources.DiffClassificationConfigurationUpdate, resources.DiffImpactRedeploy, "Dependency-safe deployment order changed.", from.Spec.Topology.DeploymentStages, to.Spec.Topology.DeploymentStages, true); err != nil {
		return resources.PlatformPlanDiff{}, err
	}
	if err := c.compareAllocations(from.Spec.Allocations, to.Spec.Allocations); err != nil {
		return resources.PlatformPlanDiff{}, err
	}
	if err := c.compareDecisions(from.Spec.Decisions, to.Spec.Decisions); err != nil {
		return resources.PlatformPlanDiff{}, err
	}
	if err := c.compareDiagnostics(from.Spec.Diagnostics, to.Spec.Diagnostics); err != nil {
		return resources.PlatformPlanDiff{}, err
	}

	sort.SliceStable(c.changes, func(i, j int) bool {
		if c.changes[i].Path == c.changes[j].Path {
			return c.changes[i].Classification < c.changes[j].Classification
		}
		return c.changes[i].Path < c.changes[j].Path
	})
	highest := resources.DiffImpactNone
	for index := range c.changes {
		c.changes[index].ID = fmt.Sprintf("change-%03d", index+1)
		if impactRank(c.changes[index].Impact) > impactRank(highest) {
			highest = c.changes[index].Impact
		}
	}
	diff := resources.PlatformPlanDiff{
		APIVersion: resources.APIVersion,
		Kind:       "PlatformPlanDiff",
		Metadata: resources.PlanDiffMetadata{
			FromPlanID: from.Metadata.PlanID,
			ToPlanID:   to.Metadata.PlanID,
		},
		Spec: resources.PlanDiffSpec{
			Changed:       len(c.changes) > 0,
			HighestImpact: highest,
			Causes:        causes,
			Changes:       c.changes,
		},
	}
	assigned, err := diff.AssignDiffID()
	if err != nil {
		return resources.PlatformPlanDiff{}, fmt.Errorf("assign plan diff identity: %w", err)
	}
	return assigned, nil
}

func compareProvenance(from, to resources.PlanProvenance) ([]resources.PlanDiffCause, error) {
	values := []struct {
		kind   string
		before string
		after  string
	}{
		{"request", from.RequestDigest, to.RequestDigest},
		{"inventory", from.InventoryDigest, to.InventoryDigest},
		{"catalog", from.CatalogDigest, to.CatalogDigest},
		{"planner", from.PlannerVersion, to.PlannerVersion},
	}
	causes := make([]resources.PlanDiffCause, 0, len(values))
	for _, value := range values {
		if value.before == value.after {
			continue
		}
		beforeDigest, err := canonical.Digest(value.before)
		if err != nil {
			return nil, err
		}
		afterDigest, err := canonical.Digest(value.after)
		if err != nil {
			return nil, err
		}
		causes = append(causes, resources.PlanDiffCause{Kind: value.kind, BeforeDigest: beforeDigest, AfterDigest: afterDigest})
	}
	return causes, nil
}

func (c *collector) compareInstances(from, to []resources.PlanInstance) error {
	fromByID := make(map[string]resources.PlanInstance, len(from))
	toByID := make(map[string]resources.PlanInstance, len(to))
	ids := make(map[string]struct{}, len(from)+len(to))
	for _, instance := range from {
		fromByID[instance.ID], ids[instance.ID] = instance, struct{}{}
	}
	for _, instance := range to {
		toByID[instance.ID], ids[instance.ID] = instance, struct{}{}
	}
	for _, id := range sortedKeys(ids) {
		before, beforeExists := fromByID[id]
		after, afterExists := toByID[id]
		path := fmt.Sprintf("spec.topology.instances[%s]", id)
		if !beforeExists || !afterExists {
			if err := c.add(path, resources.DiffClassificationDestructiveReplacement, resources.DiffImpactDestructive, "Plan instance was added or removed.", optionalValue(before, beforeExists), optionalValue(after, afterExists), true); err != nil {
				return err
			}
			continue
		}
		if err := c.compareValue(path+".role", resources.DiffClassificationDestructiveReplacement, resources.DiffImpactDestructive, "Plan instance role changed.", before.Role, after.Role, true); err != nil {
			return err
		}
		if err := c.compareValue(path+".componentRef", resources.DiffClassificationArtifactOrVersionUpgrade, resources.DiffImpactRedeploy, "Selected component artifact or version changed.", before.ComponentRef, after.ComponentRef, true); err != nil {
			return err
		}
		if err := c.compareValue(path+".modelRef", resources.DiffClassificationArtifactOrVersionUpgrade, resources.DiffImpactRedeploy, "Selected model artifact or version changed.", before.ModelRef, after.ModelRef, true); err != nil {
			return err
		}
		if err := c.compareValue(path+".placement", resources.DiffClassificationScaleOrPlacementChange, resources.DiffImpactRedeploy, "Instance placement changed.", before.Placement, after.Placement, true); err != nil {
			return err
		}
		if err := c.compareValue(path+".apiContracts", resources.DiffClassificationConfigurationUpdate, resources.DiffImpactRedeploy, "Implemented API contracts changed.", sortedStrings(before.APIContracts), sortedStrings(after.APIContracts), true); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) compareAllocations(from, to []resources.PlanAllocation) error {
	fromByID := make(map[string]resources.PlanAllocation, len(from))
	toByID := make(map[string]resources.PlanAllocation, len(to))
	ids := make(map[string]struct{}, len(from)+len(to))
	for _, allocation := range from {
		fromByID[allocation.InstanceID], ids[allocation.InstanceID] = allocation, struct{}{}
	}
	for _, allocation := range to {
		toByID[allocation.InstanceID], ids[allocation.InstanceID] = allocation, struct{}{}
	}
	for _, id := range sortedKeys(ids) {
		before, beforeExists := fromByID[id]
		after, afterExists := toByID[id]
		if err := c.compareValue(fmt.Sprintf("spec.allocations[%s]", id), resources.DiffClassificationScaleOrPlacementChange, resources.DiffImpactRedeploy, "Instance accelerator allocation or capacity changed.", optionalValue(before, beforeExists), optionalValue(after, afterExists), true); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) compareDecisions(from, to []resources.PlanDecision) error {
	fromByID := make(map[string]resources.PlanDecision, len(from))
	toByID := make(map[string]resources.PlanDecision, len(to))
	ids := make(map[string]struct{}, len(from)+len(to))
	for _, decision := range from {
		fromByID[decision.ID], ids[decision.ID] = decision, struct{}{}
	}
	for _, decision := range to {
		toByID[decision.ID], ids[decision.ID] = decision, struct{}{}
	}
	for _, id := range sortedKeys(ids) {
		before, beforeExists := fromByID[id]
		after, afterExists := toByID[id]
		path := fmt.Sprintf("spec.decisions[%s]", id)
		if !beforeExists || !afterExists {
			if err := c.add(path, resources.DiffClassificationProvenanceChange, resources.DiffImpactReview, "Material decision evidence was added or removed.", optionalValue(before, beforeExists), optionalValue(after, afterExists), false); err != nil {
				return err
			}
			continue
		}
		if err := c.compareValue(path+".selected", resources.DiffClassificationConfigurationUpdate, resources.DiffImpactRedeploy, "Selected decision outcome changed.", before.Selected, after.Selected, true); err != nil {
			return err
		}
		beforeEvidence := decisionEvidenceIdentity(before)
		afterEvidence := decisionEvidenceIdentity(after)
		if err := c.compareValue(path+".evidence", resources.DiffClassificationProvenanceChange, resources.DiffImpactReview, "Decision evidence or alternatives changed.", beforeEvidence, afterEvidence, false); err != nil {
			return err
		}
		if err := c.compareValue(path+".presentation", resources.DiffClassificationPresentationOnly, resources.DiffImpactNone, "Decision explanation text changed.", decisionPresentation(before), decisionPresentation(after), false); err != nil {
			return err
		}
	}
	return nil
}

type diagnosticSemantics struct {
	Code     string               `json:"code"`
	Severity diagnostics.Severity `json:"severity"`
	Paths    []string             `json:"paths"`
}

func (c *collector) compareDiagnostics(from, to []diagnostics.Diagnostic) error {
	fromSemantics := make([]diagnosticSemantics, len(from))
	toSemantics := make([]diagnosticSemantics, len(to))
	for index, item := range from {
		fromSemantics[index] = diagnosticSemantics{item.Code, item.Severity, item.Paths}
	}
	for index, item := range to {
		toSemantics[index] = diagnosticSemantics{item.Code, item.Severity, item.Paths}
	}
	different, _, _, err := valueDigests(fromSemantics, toSemantics)
	if err != nil {
		return err
	}
	if different {
		return c.compareValue("spec.diagnostics", resources.DiffClassificationProvenanceChange, resources.DiffImpactReview, "Diagnostic codes, severity or affected paths changed.", from, to, false)
	}
	return c.compareValue("spec.diagnostics.presentation", resources.DiffClassificationPresentationOnly, resources.DiffImpactNone, "Diagnostic presentation text changed.", from, to, false)
}

func (c *collector) compareValue(path, classification, impact, summary string, before, after any, linkDecisions bool) error {
	different, beforeDigest, afterDigest, err := valueDigests(before, after)
	if err != nil || !different {
		return err
	}
	refs := []string{}
	if linkDecisions {
		refs = append(refs, c.decisionRefs...)
	}
	c.changes = append(c.changes, resources.PlanChange{
		Path: path, Classification: classification, Impact: impact, Summary: summary,
		BeforeDigest: beforeDigest, AfterDigest: afterDigest, DecisionRefs: refs,
	})
	return nil
}

func (c *collector) add(path, classification, impact, summary string, before, after any, linkDecisions bool) error {
	return c.compareValue(path, classification, impact, summary, before, after, linkDecisions)
}

func valueDigests(before, after any) (bool, string, string, error) {
	beforeDigest, err := canonical.Digest(before)
	if err != nil {
		return false, "", "", err
	}
	afterDigest, err := canonical.Digest(after)
	if err != nil {
		return false, "", "", err
	}
	return beforeDigest != afterDigest, beforeDigest, afterDigest, nil
}

func changedDecisionIDs(from, to []resources.PlanDecision) []string {
	fromByID := make(map[string]resources.PlanDecision, len(from))
	toByID := make(map[string]resources.PlanDecision, len(to))
	ids := make(map[string]struct{}, len(from)+len(to))
	for _, decision := range from {
		fromByID[decision.ID], ids[decision.ID] = decision, struct{}{}
	}
	for _, decision := range to {
		toByID[decision.ID], ids[decision.ID] = decision, struct{}{}
	}
	changed := make([]string, 0, len(ids))
	for _, id := range sortedKeys(ids) {
		different, _, _, err := valueDigests(decisionEvidenceIdentity(fromByID[id]), decisionEvidenceIdentity(toByID[id]))
		if err == nil && different {
			changed = append(changed, id)
		}
	}
	return changed
}

type alternativeIdentity struct {
	ID              string  `json:"id"`
	Outcome         string  `json:"outcome"`
	Code            string  `json:"code"`
	EstimatedGiB    float64 `json:"estimatedGiB"`
	AvailableGiB    float64 `json:"availableGiB"`
	PreferenceScore float64 `json:"preferenceScore"`
}

type decisionEvidence struct {
	ID           string                `json:"id"`
	Selected     string                `json:"selected"`
	Evidence     []string              `json:"evidence"`
	Alternatives []alternativeIdentity `json:"alternatives"`
}

func decisionEvidenceIdentity(value resources.PlanDecision) decisionEvidence {
	alternatives := make([]alternativeIdentity, len(value.Alternatives))
	for index, alternative := range value.Alternatives {
		alternatives[index] = alternativeIdentity{
			ID: alternative.ID, Outcome: alternative.Outcome, Code: alternative.Code,
			EstimatedGiB: alternative.EstimatedGiB, AvailableGiB: alternative.AvailableGiB,
			PreferenceScore: alternative.PreferenceScore,
		}
	}
	sort.SliceStable(alternatives, func(i, j int) bool { return alternatives[i].ID < alternatives[j].ID })
	return decisionEvidence{ID: value.ID, Selected: value.Selected, Evidence: sortedStrings(value.Evidence), Alternatives: alternatives}
}

func decisionPresentation(value resources.PlanDecision) any {
	reasons := append([]string{}, value.Reasons...)
	alternativeReasons := make([]string, len(value.Alternatives))
	for index, alternative := range value.Alternatives {
		alternativeReasons[index] = alternative.Reason
	}
	return struct {
		Reasons            []string `json:"reasons"`
		AlternativeReasons []string `json:"alternativeReasons"`
	}{reasons, alternativeReasons}
}

func sortedStrings(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	return result
}

func normalizedConnections(values []resources.PlanConnection) []resources.PlanConnection {
	result := append([]resources.PlanConnection{}, values...)
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].From != result[j].From {
			return result[i].From < result[j].From
		}
		if result[i].To != result[j].To {
			return result[i].To < result[j].To
		}
		return result[i].Contract < result[j].Contract
	})
	return result
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func optionalValue[T any](value T, exists bool) any {
	if !exists {
		return nil
	}
	return value
}

func impactRank(value string) int {
	switch value {
	case resources.DiffImpactReview:
		return 1
	case resources.DiffImpactRedeploy:
		return 2
	case resources.DiffImpactDestructive:
		return 3
	default:
		return 0
	}
}
