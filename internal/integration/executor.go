// Package integration evaluates bounded catalog-backed integration checks
// without mutating targets.
package integration

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type Executor interface {
	ComponentSmoke(context.Context, catalog.Snapshot, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error)
	TopologyEndToEnd(context.Context, catalog.Snapshot, string, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error)
}

type CatalogExecutor struct{}

func (CatalogExecutor) ComponentSmoke(_ context.Context, snapshot catalog.Snapshot, componentRefs []string, environment resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
	checks := []resources.ContractTestCheck{}
	base, err := integrationCheck("environment.transport", "passed", "", environment.Transport)
	if err != nil {
		return nil, nil, err
	}
	checks = append(checks, base)
	for _, reference := range componentRefs {
		component, ok := snapshot.DeploymentComponent(reference)
		if !ok {
			return nil, nil, fmt.Errorf("component %q is not present in the catalog", reference)
		}
		safeID := strings.ReplaceAll(strings.SplitN(reference, "@", 2)[0], ".", "-")
		artifactCheck, err := integrationCheck("component."+safeID+".artifact-bound", boolStatus(len(component.Artifacts) > 0), "YARA-INT-101", map[string]any{"componentRef": reference, "artifactCount": len(component.Artifacts)})
		if err != nil {
			return nil, nil, err
		}
		healthValid := slices.Contains([]string{"http", "tcp", "exec"}, component.Health.Protocol)
		healthCheck, err := integrationCheck("component."+safeID+".health-contract", boolStatus(healthValid), "YARA-INT-102", map[string]string{"componentRef": reference, "protocol": component.Health.Protocol})
		if err != nil {
			return nil, nil, err
		}
		checks = append(checks, artifactCheck, healthCheck)
	}
	slices.SortFunc(checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	limitations := []string{
		"Integration component-smoke checks manifest-bound contracts and observed target facts only.",
		"No container startup, prompt execution or performance claim is made by this bounded executor.",
	}
	slices.Sort(limitations)
	return checks, limitations, nil
}

func (CatalogExecutor) TopologyEndToEnd(ctx context.Context, snapshot catalog.Snapshot, topologyRef string, componentRefs []string, environment resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error) {
	checks, limitations, err := CatalogExecutor{}.ComponentSmoke(ctx, snapshot, componentRefs, environment)
	if err != nil {
		return nil, nil, err
	}
	topology, ok := snapshot.DeploymentTopology(topologyRef)
	if !ok {
		return nil, nil, fmt.Errorf("topology %q is not present in the catalog", topologyRef)
	}
	topologyKnown, err := integrationCheck("topology.reference-bound", "passed", "", topology.Ref)
	if err != nil {
		return nil, nil, err
	}
	checks = append(checks, topologyKnown)
	missingRole := ""
	for _, role := range topology.Roles {
		matched := false
		for _, candidate := range snapshot.ComponentsForRole(role.Role) {
			if slices.Contains(componentRefs, candidate.ComponentRef) {
				matched = true
				break
			}
		}
		if !matched {
			missingRole = role.Role
			break
		}
	}
	roleCoverage, err := integrationCheck("topology.role-coverage", boolStatus(missingRole == ""), "YARA-INT-103", map[string]any{"topologyRef": topologyRef, "missingRole": missingRole})
	if err != nil {
		return nil, nil, err
	}
	checks = append(checks, roleCoverage)
	connectionBound := len(topology.Connections) > 0
	connectionCheck, err := integrationCheck("topology.connection-contracts", boolStatus(connectionBound), "YARA-INT-104", map[string]any{"topologyRef": topologyRef, "connectionCount": len(topology.Connections)})
	if err != nil {
		return nil, nil, err
	}
	checks = append(checks, connectionCheck)
	slices.SortFunc(checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	limitations = append(limitations,
		"Topology-end-to-end checks bounded role and connection coverage against exact catalog topology metadata.",
		"This executor does not prove throughput, latency, availability or production readiness.",
	)
	slices.Sort(limitations)
	return checks, limitations, nil
}

func boolStatus(passed bool) string {
	if passed {
		return "passed"
	}
	return "failed"
}

func integrationCheck(id, status, diagnosticCode string, evidence any) (resources.ContractTestCheck, error) {
	if status == "passed" {
		diagnosticCode = ""
	}
	digest, err := canonical.Digest(evidence)
	if err != nil {
		return resources.ContractTestCheck{}, fmt.Errorf("digest integration evidence for %s: %w", id, err)
	}
	return resources.ContractTestCheck{
		ID:             id,
		Status:         status,
		DiagnosticCode: diagnosticCode,
		EvidenceDigest: digest,
	}, nil
}
