package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/integration"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
	"gopkg.in/yaml.v3"
)

type integrationExecutor interface {
	ComponentSmoke(context.Context, catalog.Snapshot, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error)
	TopologyEndToEnd(context.Context, catalog.Snapshot, string, []string, resources.ContractTestEnvironment) ([]resources.ContractTestCheck, []string, error)
}

var integrationRun integrationExecutor = integration.CatalogExecutor{}

type integrationExecuteOptions struct {
	catalogPath, target, name, outputPath, auditPath, confirmCatalogDigest string
	topologyRef                                                            string
	componentRefs                                                          csvFlag
}

func runIntegrationComponentSmoke(args []string, stdout, stderr io.Writer) int {
	return runIntegrationAt("component-smoke", args, stdout, stderr, time.Now, "")
}

func runIntegrationTopologyEndToEnd(args []string, stdout, stderr io.Writer) int {
	return runIntegrationAt("topology-end-to-end", args, stdout, stderr, time.Now, "")
}

func runIntegrationExecute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "integration execute requires a mode: component-smoke or topology-end-to-end")
		return ExitInvalidInput
	}
	mode := strings.TrimSpace(args[0])
	if mode != "component-smoke" && mode != "topology-end-to-end" {
		return writeLoadErrorWithExit(stdout, "YARA-INT-111", errors.New(integrationDiagnosticMessage("YARA-INT-111", "integration execute supports only component-smoke or topology-end-to-end")), ExitInvalidInput)
	}
	return runIntegrationAt(mode, args[1:], stdout, stderr, time.Now, "integration.execute."+mode)
}

func runIntegrationAt(mode string, args []string, stdout, stderr io.Writer, now func() time.Time, explainabilityPath string) int {
	options, ok := parseIntegrationExecuteOptions(mode, args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeIntegrationFailure(stdout, options.auditPath, mode, "local", []audit.Subject{attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-INT-101", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeIntegrationFailure(stdout, options.auditPath, mode, "local", nil, "YARA-INT-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	if options.confirmCatalogDigest != catalogDigest {
		return writeIntegrationFailure(stdout, options.auditPath, mode, "local", []audit.Subject{catalogSubject}, "YARA-INT-102", errors.New("explicit catalog confirmation does not match digest"), ExitInfeasible)
	}
	componentRefs, topologyRef, target, code, err := resolveIntegrationInputs(snapshot, mode, options)
	auditTarget := "local"
	if target.ReferenceDigest != "" {
		auditTarget = target.Transport + ":" + target.ReferenceDigest
	}
	if err != nil {
		return writeIntegrationFailure(stdout, options.auditPath, mode, auditTarget, []audit.Subject{catalogSubject}, code, err, ExitInfeasible)
	}
	inputDigest, err := canonical.Digest(struct {
		Mode          string   `json:"mode"`
		CatalogDigest string   `json:"catalogDigest"`
		ComponentRefs []string `json:"componentRefs"`
		TopologyRef   string   `json:"topologyRef,omitempty"`
		TargetDigest  string   `json:"targetDigest"`
	}{
		Mode:          mode,
		CatalogDigest: catalogDigest,
		ComponentRefs: componentRefs,
		TopologyRef:   topologyRef,
		TargetDigest:  target.ReferenceDigest,
	})
	if err != nil {
		return writeIntegrationFailure(stdout, options.auditPath, mode, auditTarget, []audit.Subject{catalogSubject}, "YARA-INT-500", err, ExitInternal)
	}
	subjects := []audit.Subject{
		catalogSubject,
		{Kind: "IntegrationInput", Digest: inputDigest},
	}
	auditWriter, err := newIntegrationExecutionAudit(options.auditPath, mode, auditTarget, subjects, now())
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AUD-005", err, ExitInvalidInput)
	}
	result, err := buildIntegrationResult(mode, options.name, catalogDigest, componentRefs, topologyRef, target, snapshot)
	if err != nil {
		_ = auditWriter.file.Close()
		return writeLoadErrorWithExit(stdout, "YARA-INT-500", err, ExitInternal)
	}
	var checks []resources.ContractTestCheck
	var limitations []string
	if mode == "component-smoke" {
		checks, limitations, err = integrationRun.ComponentSmoke(context.Background(), snapshot, componentRefs, target)
	} else {
		checks, limitations, err = integrationRun.TopologyEndToEnd(context.Background(), snapshot, topologyRef, componentRefs, target)
	}
	if err != nil {
		_ = auditWriter.finish("failed", subjects, []string{"YARA-INT-120"}, now())
		return writeLoadErrorWithExit(stdout, "YARA-INT-120", err, ExitInfeasible)
	}
	result.Spec.Checks = checks
	result.Spec.Limitations = limitations
	result.Spec.Outcome = deriveIntegrationOutcome(checks)
	result, err = bindIntegrationRunner(result)
	if err != nil {
		_ = auditWriter.finish("failed", subjects, []string{"YARA-INT-500"}, now())
		return writeLoadErrorWithExit(stdout, "YARA-INT-500", err, ExitInternal)
	}
	if report := result.Validate(); !report.Valid {
		_ = auditWriter.finish("failed", subjects, []string{"YARA-INT-500"}, now())
		return writeLoadErrorWithExit(stdout, "YARA-INT-500", errors.New("constructed integration result is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		_ = auditWriter.finish("failed", subjects, []string{"YARA-INT-500"}, now())
		return writeLoadErrorWithExit(stdout, "YARA-INT-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		_ = auditWriter.finish("failed", subjects, []string{"YARA-INT-103"}, now())
		return writeLoadErrorWithExit(stdout, "YARA-INT-103", err, ExitInvalidInput)
	}
	terminalSubjects := append(slices.Clone(subjects), audit.Subject{Kind: "IntegrationTestResult", Digest: result.Metadata.ResultID})
	terminalOutcome := "success"
	exitCode := ExitSuccess
	switch result.Spec.Outcome {
	case "blocked":
		terminalOutcome = "infeasible"
		exitCode = ExitInfeasible
	case "failed":
		terminalOutcome = "failed"
		exitCode = ExitInfeasible
	}
	if err := auditWriter.finish(terminalOutcome, terminalSubjects, integrationDiagnosticCodes(result), now()); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadErrorWithExit(stdout, "YARA-AUD-005", err, ExitInternal)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":         true,
		"mode":          mode,
		"outcome":       result.Spec.Outcome,
		"resultId":      result.Metadata.ResultID,
		"output":        options.outputPath,
		"auditOutput":   options.auditPath,
		"catalogDigest": catalogDigest,
		"modePath":      explainabilityPath,
	}); err != nil {
		return ExitInternal
	}
	return exitCode
}

func parseIntegrationExecuteOptions(mode string, args []string, stderr io.Writer) (integrationExecuteOptions, bool) {
	var options integrationExecuteOptions
	flags := flag.NewFlagSet("integration "+mode, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.target, "target", "", "Execution target: local or user@host")
	flags.Var(&options.componentRefs, "component", "Exact component reference id@version (repeatable)")
	flags.StringVar(&options.topologyRef, "topology", "", "Exact topology reference id@version (required for topology mode)")
	flags.StringVar(&options.confirmCatalogDigest, "confirm-catalog-digest", "", "Exact catalog digest operator confirmation")
	flags.StringVar(&options.name, "name", "", "IntegrationTestResult name")
	flags.StringVar(&options.outputPath, "output", "", "Generated IntegrationTestResult YAML file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated mandatory audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.target == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" || options.confirmCatalogDigest == "" {
		fmt.Fprintf(stderr, "integration %s requires --catalog, --target, --component, --confirm-catalog-digest, --name, --output and --audit-output\n", mode)
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	slices.Sort(options.componentRefs)
	options.componentRefs = uniqueSortedStrings(options.componentRefs)
	if mode == "component-smoke" {
		if options.topologyRef != "" || len(options.componentRefs) < 1 {
			fmt.Fprintln(stderr, "component-smoke requires at least one --component and forbids --topology")
			return options, false
		}
	} else {
		if options.topologyRef == "" || len(options.componentRefs) < 2 {
			fmt.Fprintln(stderr, "topology-end-to-end requires --topology and at least two --component references")
			return options, false
		}
	}
	return options, true
}

func resolveIntegrationInputs(snapshot catalog.Snapshot, mode string, options integrationExecuteOptions) ([]string, string, resources.ContractTestEnvironment, string, error) {
	inventory := snapshot.ManifestInventory()
	componentStatus := map[string]string{}
	for _, component := range inventory.Components {
		componentStatus[component.ID+"@"+component.Version] = component.Status
	}
	assertionBoundRuntimeRefs := map[string]struct{}{}
	for _, assertion := range inventory.Compatibility {
		if assertion.Compatibility == "supported" && slices.Contains([]string{"known", "experimental", "supported"}, assertion.Status) {
			assertionBoundRuntimeRefs[assertion.RuntimeRef] = struct{}{}
		}
	}
	selectedAssertionBoundRuntime := false
	for _, reference := range options.componentRefs {
		status, ok := componentStatus[reference]
		if !ok {
			return nil, "", resources.ContractTestEnvironment{}, "YARA-INT-104", fmt.Errorf("component reference %q is not present in the catalog", reference)
		}
		if status == "deprecated" || status == "quarantined" {
			return nil, "", resources.ContractTestEnvironment{}, "YARA-INT-105", fmt.Errorf("component reference %q is not selectable for integration execution", reference)
		}
		componentID := strings.SplitN(reference, "@", 2)[0]
		if _, ok := assertionBoundRuntimeRefs[componentID]; ok {
			selectedAssertionBoundRuntime = true
		}
	}
	if mode == "topology-end-to-end" {
		topology, ok := snapshot.DeploymentTopology(options.topologyRef)
		if !ok {
			return nil, "", resources.ContractTestEnvironment{}, "YARA-INT-106", fmt.Errorf("topology reference %q is not present in the catalog", options.topologyRef)
		}
		if topology.Status == "deprecated" || topology.Status == "quarantined" {
			return nil, "", resources.ContractTestEnvironment{}, "YARA-INT-107", fmt.Errorf("topology reference %q is not selectable for integration execution", options.topologyRef)
		}
		if !selectedAssertionBoundRuntime {
			return nil, "", resources.ContractTestEnvironment{}, "YARA-INT-109", errors.New("selected topology components are not bound to a supported compatibility runtime assertion")
		}
		for _, role := range topology.Roles {
			roleCandidates := snapshot.ComponentsForRole(role.Role)
			matched := false
			for _, candidate := range roleCandidates {
				if slices.Contains(options.componentRefs, candidate.ComponentRef) {
					matched = true
					break
				}
			}
			if !matched {
				return nil, "", resources.ContractTestEnvironment{}, "YARA-INT-110", fmt.Errorf("selected topology components do not satisfy role %q", role.Role)
			}
		}
	}
	target, err := observeIntegrationTarget(options.target)
	if err != nil {
		return nil, "", resources.ContractTestEnvironment{}, "YARA-INT-108", err
	}
	return slices.Clone(options.componentRefs), options.topologyRef, target, "", nil
}

func observeIntegrationTarget(target string) (resources.ContractTestEnvironment, error) {
	if target == "local" {
		return observeLocalIntegrationTarget(), nil
	}
	return contractProbe.Observe(context.Background(), target)
}

func observeLocalIntegrationTarget() resources.ContractTestEnvironment {
	host := "unknown-local"
	if name, err := os.Hostname(); err == nil && strings.TrimSpace(name) != "" {
		host = strings.TrimSpace(name)
	}
	sum := sha256.Sum256([]byte("local:" + host))
	environment := resources.ContractTestEnvironment{
		Transport:       "local",
		ReferenceDigest: "sha256:" + hex.EncodeToString(sum[:]),
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		Docker:          observeLocalDocker(),
		Accelerators:    []resources.ContractTestAccelerator{},
	}
	return environment
}

func observeLocalDocker() resources.ContractTestDocker {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	versionOut, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").Output()
	if err != nil {
		return resources.ContractTestDocker{Available: false}
	}
	infoOut, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.OSType}}|{{.Architecture}}|{{json .Runtimes}}").Output()
	if err != nil {
		return resources.ContractTestDocker{
			Available: true,
			Version:   strings.TrimSpace(string(versionOut)),
		}
	}
	parts := strings.SplitN(strings.TrimSpace(string(infoOut)), "|", 3)
	docker := resources.ContractTestDocker{
		Available:       true,
		Version:         strings.TrimSpace(string(versionOut)),
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
	}
	if len(parts) == 3 {
		if strings.TrimSpace(parts[0]) != "" {
			docker.OperatingSystem = strings.TrimSpace(parts[0])
		}
		if strings.TrimSpace(parts[1]) != "" {
			docker.Architecture = strings.TrimSpace(parts[1])
		}
		docker.NVIDIARuntime = strings.Contains(parts[2], "\"nvidia\"")
	}
	return docker
}

func buildIntegrationResult(mode, name, catalogDigest string, componentRefs []string, topologyRef string, environment resources.ContractTestEnvironment, snapshot catalog.Snapshot) (resources.IntegrationTestResult, error) {
	result := resources.IntegrationTestResult{
		APIVersion: resources.APIVersion,
		Kind:       "IntegrationTestResult",
		Metadata: resources.IntegrationTestResultMetadata{
			Name: name,
		},
		Spec: resources.IntegrationTestResultSpec{
			Mode:          mode,
			Outcome:       "passed",
			CatalogDigest: catalogDigest,
			ComponentRefs: slices.Clone(componentRefs),
			TopologyRef:   topologyRef,
			Environment:   environment,
			Checks:        []resources.ContractTestCheck{},
			Limitations:   []string{"Integration execution result was constructed from bounded catalog and target observations."},
		},
	}
	slices.Sort(result.Spec.ComponentRefs)
	slices.Sort(result.Spec.Limitations)
	_ = snapshot
	return result, nil
}

func deriveIntegrationOutcome(checks []resources.ContractTestCheck) string {
	outcome := "passed"
	for _, check := range checks {
		if check.Status == "failed" {
			return "failed"
		}
		if check.Status == "blocked" {
			outcome = "blocked"
		}
	}
	return outcome
}

func integrationDiagnosticCodes(result resources.IntegrationTestResult) []string {
	codes := []string{}
	for _, check := range result.Spec.Checks {
		if check.DiagnosticCode != "" {
			codes = append(codes, check.DiagnosticCode)
		}
	}
	return uniqueSortedStrings(codes)
}

func bindIntegrationRunner(result resources.IntegrationTestResult) (resources.IntegrationTestResult, error) {
	executable, err := os.Executable()
	if err != nil {
		return resources.IntegrationTestResult{}, fmt.Errorf("locate integration runner executable: %w", err)
	}
	file, err := os.Open(executable)
	if err != nil {
		return resources.IntegrationTestResult{}, fmt.Errorf("open integration runner executable: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return resources.IntegrationTestResult{}, fmt.Errorf("digest integration runner executable: %w", err)
	}
	result.Metadata.ResultID = ""
	result.Spec.Runner = &resources.ContractTestRunner{
		Version:      version.Version,
		BinaryDigest: "sha256:" + hex.EncodeToString(hash.Sum(nil)),
	}
	return result.AssignResultID()
}

type csvFlag []string

func (c *csvFlag) String() string { return strings.Join(*c, ",") }
func (c *csvFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("component reference cannot be empty")
	}
	*c = append(*c, value)
	return nil
}

type integrationExecutionAudit struct {
	file                                     *os.File
	chain                                    *audit.Chain
	correlationID, actionBase, target, start string
}

func newIntegrationExecutionAudit(path, mode, target string, subjects []audit.Subject, at time.Time) (*integrationExecutionAudit, error) {
	file, err := reserveOutput(path)
	if err != nil {
		return nil, err
	}
	correlationID := fmt.Sprintf("integration-%d", at.UTC().UnixNano())
	actionBase := "integration." + mode
	actorID, assurance := localActor()
	writer := &integrationExecutionAudit{
		file:          file,
		chain:         audit.NewChain(),
		correlationID: correlationID,
		actionBase:    actionBase,
		target:        target,
		start:         correlationID + "-started",
	}
	event, err := writer.chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: writer.start, OccurredAt: at.UTC().Format(time.RFC3339Nano)},
		Spec: audit.Spec{
			CorrelationID:   correlationID,
			Actor:           audit.Actor{ID: actorID, Type: "user", Assurance: assurance},
			Action:          actionBase + ".started",
			Subjects:        subjects,
			Reason:          audit.Reason{Type: "user-request", Reference: "cli"},
			Target:          target,
			Outcome:         "started",
			DiagnosticCodes: []string{},
		},
	})
	if err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := audit.EncodeJSONL(file, []audit.Event{event}); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return writer, nil
}

func (w *integrationExecutionAudit) finish(outcome string, subjects []audit.Subject, codes []string, at time.Time) error {
	suffix := "completed"
	if outcome == "failed" {
		suffix = "failed"
	} else if outcome == "infeasible" {
		suffix = "blocked"
	}
	actorID, assurance := localActor()
	event, err := w.chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: w.correlationID + "-terminal", OccurredAt: at.UTC().Format(time.RFC3339Nano)},
		Spec: audit.Spec{
			CorrelationID:   w.correlationID,
			CausationID:     w.start,
			Actor:           audit.Actor{ID: actorID, Type: "user", Assurance: assurance},
			Action:          w.actionBase + "." + suffix,
			Subjects:        subjects,
			Reason:          audit.Reason{Type: "user-request", Reference: "cli"},
			Target:          w.target,
			Outcome:         outcome,
			DiagnosticCodes: codes,
		},
	})
	if err != nil {
		return err
	}
	if err := audit.EncodeJSONL(w.file, []audit.Event{event}); err != nil {
		return err
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	return w.file.Close()
}

func writeIntegrationFailure(output io.Writer, auditPath, mode, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	baseAction := "integration." + mode
	if auditErr := persistOperationAuditForTarget(auditPath, baseAction, "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, errors.New(integrationDiagnosticMessage(code, err.Error())), exitCode)
}

func integrationDiagnosticMessage(code, message string) string {
	remediation := map[string]string{
		"YARA-INT-109": "include a component bound to a supported compatibility runtime assertion",
		"YARA-INT-110": "select components that satisfy every topology role from the catalog topology reference",
		"YARA-INT-111": "choose integration execute component-smoke or topology-end-to-end",
	}
	step, ok := remediation[code]
	if !ok {
		return message
	}
	return message + " (remediation: " + step + ")"
}
