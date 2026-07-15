package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"sort"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/planner"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type planCreateOptions struct {
	requestPath   string
	inventoryPath string
	catalogPath   string
	outputPath    string
	auditPath     string
}

func createPlan(args []string, stdout, stderr io.Writer) int {
	options, ok := parsePlanCreateOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	request, err := resources.LoadPlatformRequest(options.requestPath)
	if err != nil {
		return writeLoadError(stdout, "YARA-REQ-004", err)
	}
	inventory, err := resources.LoadInventory(options.inventoryPath)
	if err != nil {
		return writeLoadError(stdout, "YARA-INV-004", err)
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeLoadError(stdout, "YARA-CAT-004", err)
	}
	result := planner.Create(request, inventory, snapshot)
	if !result.Report.Valid {
		auditData, auditErr := planningFailureAudit(request, inventory, snapshot, result.Report)
		if auditErr != nil {
			return writeLoadError(stdout, "YARA-AUD-500", auditErr)
		}
		if err := writeExclusive(options.auditPath, auditData); err != nil {
			return writeLoadError(stdout, "YARA-AUD-005", err)
		}
		return writeReport(stdout, result.Report, ExitInfeasible)
	}

	planData, err := yaml.Marshal(result.Plan)
	if err != nil {
		return writeLoadError(stdout, "YARA-PLAN-500", fmt.Errorf("encode plan: %w", err))
	}
	auditData, err := planningAudit(result.Plan)
	if err != nil {
		return writeLoadError(stdout, "YARA-AUD-500", err)
	}
	if err := writeExclusive(options.outputPath, planData); err != nil {
		return writeLoadError(stdout, "YARA-PLAN-005", err)
	}
	if err := writeExclusive(options.auditPath, auditData); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}

	response := struct {
		Valid       bool   `json:"valid"`
		PlanID      string `json:"planId"`
		Output      string `json:"output"`
		AuditOutput string `json:"auditOutput"`
	}{true, result.Plan.Metadata.PlanID, options.outputPath, options.auditPath}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(response); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parsePlanCreateOptions(args []string, stderr io.Writer) (planCreateOptions, bool) {
	var options planCreateOptions
	flags := flag.NewFlagSet("plan create", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.requestPath, "request", "", "PlatformRequest file")
	flags.StringVar(&options.inventoryPath, "inventory", "", "Inventory file")
	flags.StringVar(&options.catalogPath, "catalog", "", "CatalogSnapshot file")
	flags.StringVar(&options.outputPath, "output", "", "Generated PlatformPlan file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.requestPath == "" || options.inventoryPath == "" || options.catalogPath == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "plan create requires --request, --inventory, --catalog, --output and --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}

func planningAudit(plan resources.PlatformPlan) ([]byte, error) {
	now := time.Now().UTC()
	correlationID := fmt.Sprintf("plan-%d", now.UnixNano())
	actorID, assurance := localActor()
	baseSpec := audit.Spec{
		CorrelationID:   correlationID,
		Actor:           audit.Actor{ID: actorID, Type: "user", Assurance: assurance},
		Reason:          audit.Reason{Type: "user-request", Reference: "cli"},
		Target:          "local",
		DiagnosticCodes: []string{},
	}
	chain := audit.NewChain()
	started, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: correlationID + "-started", OccurredAt: now.Format(time.RFC3339Nano)},
		Spec: mergeAuditSpec(baseSpec, "plan.create.started", "started", []audit.Subject{
			{Kind: "PlatformRequest", Digest: plan.Provenance.RequestDigest},
			{Kind: "Inventory", Digest: plan.Provenance.InventoryDigest},
			{Kind: "CatalogSnapshot", Digest: plan.Provenance.CatalogDigest},
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("create planning start audit event: %w", err)
	}
	completedSpec := mergeAuditSpec(baseSpec, "plan.create.completed", "success", []audit.Subject{
		{Kind: "PlatformRequest", Digest: plan.Provenance.RequestDigest},
		{Kind: "Inventory", Digest: plan.Provenance.InventoryDigest},
		{Kind: "CatalogSnapshot", Digest: plan.Provenance.CatalogDigest},
		{Kind: "PlatformPlan", Digest: plan.Metadata.PlanID},
	})
	completedSpec.CausationID = started.Metadata.ID
	completedSpec.DiagnosticCodes = diagnosticCodes(plan.Spec.Diagnostics)
	completed, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: correlationID + "-completed", OccurredAt: now.Format(time.RFC3339Nano)},
		Spec:     completedSpec,
	})
	if err != nil {
		return nil, fmt.Errorf("create planning completion audit event: %w", err)
	}
	var buffer bytes.Buffer
	if err := audit.EncodeJSONL(&buffer, []audit.Event{started, completed}); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func planningFailureAudit(request resources.PlatformRequest, inventory resources.Inventory, snapshot catalog.Snapshot, report diagnostics.Report) ([]byte, error) {
	requestDigest, err := canonical.Digest(request)
	if err != nil {
		return nil, fmt.Errorf("digest planning request for audit: %w", err)
	}
	inventoryDigest, err := canonical.Digest(inventory)
	if err != nil {
		return nil, fmt.Errorf("digest planning inventory for audit: %w", err)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return nil, fmt.Errorf("digest planning catalog for audit: %w", err)
	}
	codes := diagnosticCodes(report.Diagnostics)
	action, outcome := "plan.create.failed", "failed"
	for _, diagnostic := range report.Diagnostics {
		if diagnostic.Code == "YARA-PLAN-001" {
			action, outcome = "plan.create.infeasible", "infeasible"
		}
	}
	now := time.Now().UTC()
	correlationID := fmt.Sprintf("plan-%d", now.UnixNano())
	actorID, assurance := localActor()
	subjects := []audit.Subject{
		{Kind: "PlatformRequest", Digest: requestDigest},
		{Kind: "Inventory", Digest: inventoryDigest},
		{Kind: "CatalogSnapshot", Digest: catalogDigest},
	}
	baseSpec := audit.Spec{
		CorrelationID: correlationID,
		Actor:         audit.Actor{ID: actorID, Type: "user", Assurance: assurance},
		Reason:        audit.Reason{Type: "user-request", Reference: "cli"}, Target: "local",
		DiagnosticCodes: []string{},
	}
	chain := audit.NewChain()
	started, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: correlationID + "-started", OccurredAt: now.Format(time.RFC3339Nano)},
		Spec:     mergeAuditSpec(baseSpec, "plan.create.started", "started", subjects),
	})
	if err != nil {
		return nil, fmt.Errorf("create planning start audit event: %w", err)
	}
	terminalSpec := mergeAuditSpec(baseSpec, action, outcome, subjects)
	terminalSpec.CausationID = started.Metadata.ID
	terminalSpec.DiagnosticCodes = codes
	terminal, err := chain.Append(audit.Event{
		Metadata: audit.Metadata{ID: correlationID + "-terminal", OccurredAt: now.Format(time.RFC3339Nano)},
		Spec:     terminalSpec,
	})
	if err != nil {
		return nil, fmt.Errorf("create planning terminal audit event: %w", err)
	}
	var buffer bytes.Buffer
	if err := audit.EncodeJSONL(&buffer, []audit.Event{started, terminal}); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func diagnosticCodes(items []diagnostics.Diagnostic) []string {
	codes := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, diagnostic := range items {
		if _, exists := seen[diagnostic.Code]; exists {
			continue
		}
		seen[diagnostic.Code] = struct{}{}
		codes = append(codes, diagnostic.Code)
	}
	sort.Strings(codes)
	return codes
}

func mergeAuditSpec(base audit.Spec, action, outcome string, subjects []audit.Subject) audit.Spec {
	base.Action = action
	base.Outcome = outcome
	base.Subjects = subjects
	return base
}

func localActor() (string, string) {
	current, err := user.Current()
	if err != nil || current.Username == "" {
		return "local:unknown", "unknown-local"
	}
	return "local:" + current.Username, "self-asserted-local"
}

func writeExclusive(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	success := false
	defer func() {
		_ = file.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	success = true
	return nil
}

func explainPlan(path string, output io.Writer) int {
	plan, err := resources.LoadPlatformPlan(path)
	if err != nil {
		return writeLoadError(output, "YARA-PLAN-004", err)
	}
	if report := plan.Validate(); !report.Valid {
		return writeReport(output, report, ExitInvalidInput)
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(plan.Spec.Decisions); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func writeReport(output io.Writer, report diagnostics.Report, exitCode int) int {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return ExitInternal
	}
	return exitCode
}
