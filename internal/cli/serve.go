package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type serveOptions struct {
	catalogPath        string
	coverageReportPath string
	port               int
	ui                 bool
	workspacePath      string
}

type lifecyclePolicyAssertion struct {
	Assertion   string `json:"assertion"`
	Status      string `json:"status"`
	Blocker     string `json:"blocker,omitempty"`
	Code        string `json:"code,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type lifecyclePostureAssertion struct {
	Assertion            string `json:"assertion"`
	Ready                bool   `json:"ready"`
	LifecycleProof       string `json:"lifecycleProof"`
	IntegrationAttest    string `json:"integrationAttestation"`
	PublicationRehearsal string `json:"publicationRehearsal"`
	RenewalReview        string `json:"renewalReview"`
	Blocker              string `json:"blocker,omitempty"`
	Code                 string `json:"code,omitempty"`
	Remediation          string `json:"remediation,omitempty"`
}

func serveAPI(args []string, stdout, stderr io.Writer) int {
	options, ok := parseServeOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-SRV-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-SRV-500", err, ExitInternal)
	}
	report, err := catalogcoverage.Load(options.coverageReportPath)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-SRV-005", err, ExitInvalidInput)
	}
	handler, err := newServeAPIHandler(snapshot, catalogDigest, report, options.ui, options.workspacePath)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-SRV-500", err, ExitInternal)
	}
	address := fmt.Sprintf("127.0.0.1:%d", options.port)
	server := &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	_ = json.NewEncoder(stdout).Encode(map[string]any{
		"valid":          true,
		"listening":      "http://" + address,
		"catalog":        options.catalogPath,
		"coverageReport": options.coverageReportPath,
		"ui":             options.ui,
		"workspace":      mapValueOrDefault(options.workspacePath, "none"),
	})
	errChan := make(chan error, 1)
	go func() {
		if serveErr := server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errChan <- serveErr
		}
	}()
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case serveErr := <-errChan:
		return writeLoadErrorWithExit(stdout, "YARA-SRV-500", serveErr, ExitInternal)
	case <-signalContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := server.Shutdown(shutdownContext); shutdownErr != nil {
			return writeLoadErrorWithExit(stdout, "YARA-SRV-500", shutdownErr, ExitInternal)
		}
		return ExitSuccess
	}
}

func parseServeOptions(args []string, stderr io.Writer) (serveOptions, bool) {
	var options serveOptions
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "Validated CatalogSnapshot file")
	flags.StringVar(&options.coverageReportPath, "coverage-report", "", "Validated CatalogCoverageReport file")
	flags.IntVar(&options.port, "port", 7474, "Local listen port")
	flags.BoolVar(&options.ui, "ui", false, "Serve embedded web UI shell")
	flags.StringVar(&options.workspacePath, "workspace", "", "Workspace directory for interactive pipeline discovery")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.catalogPath == "" || options.coverageReportPath == "" {
		fmt.Fprintln(stderr, "serve requires --catalog and --coverage-report")
		return options, false
	}
	if options.port <= 0 || options.port > 65535 {
		fmt.Fprintln(stderr, "--port must be between 1 and 65535")
		return options, false
	}
	if options.workspacePath != "" {
		workspaceInfo, err := os.Stat(options.workspacePath)
		if err != nil || !workspaceInfo.IsDir() {
			fmt.Fprintln(stderr, "--workspace must point to an existing directory")
			return options, false
		}
	}
	return options, true
}

func newServeAPIHandler(snapshot catalog.Snapshot, catalogDigest string, report catalogcoverage.Report, uiEnabled bool, workspacePath string) (http.Handler, error) {
	apiMux := http.NewServeMux()
	inventory := snapshot.ManifestInventory()
	apiMux.HandleFunc("/api/v1/catalog", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		writeServeJSON(writer, http.StatusOK, map[string]any{
			"valid": true,
			"catalog": map[string]any{
				"apiVersion": snapshot.APIVersion,
				"kind":       snapshot.Kind,
				"metadata":   snapshot.Metadata,
				"digest":     catalogDigest,
			},
			"summary": map[string]int{
				"capabilities": len(inventory.Capabilities),
				"components":   len(inventory.Components),
				"models":       len(inventory.Models),
				"hardware":     len(inventory.Hardware),
				"assertions":   len(inventory.Compatibility),
				"topologies":   len(inventory.Topologies),
			},
		})
	})
	apiMux.HandleFunc("/api/v1/assertions", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		assertions := append([]catalog.AssertionDescriptor(nil), inventory.Compatibility...)
		sort.Slice(assertions, func(i, j int) bool { return assertions[i].ID < assertions[j].ID })
		writeServeJSON(writer, http.StatusOK, map[string]any{
			"valid":      true,
			"assertions": assertions,
		})
	})
	apiMux.HandleFunc("/api/v1/coverage", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		writeServeJSON(writer, http.StatusOK, map[string]any{
			"valid":  true,
			"report": report,
		})
	})
	apiMux.HandleFunc("/api/v1/drift-posture", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		posture, err := runtimeDriftPostureFromReport(report)
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", err.Error())
			return
		}
		assertion := strings.TrimSpace(request.URL.Query().Get("assertion"))
		if assertion != "" {
			filtered := make([]runtimeDriftPosture, 0, len(posture))
			for _, item := range posture {
				if item.Assertion == assertion {
					filtered = append(filtered, item)
				}
			}
			if len(filtered) == 0 {
				writeServeError(writer, http.StatusBadRequest, "YARA-SRV-007", "assertion is not present in runtime drift posture")
				return
			}
			posture = filtered
		}
		sort.Slice(posture, func(i, j int) bool { return posture[i].Assertion < posture[j].Assertion })
		rows := make([]map[string]string, 0, len(posture))
		for _, item := range posture {
			selectedSignal := item.SelectedSignal
			if selectedSignal == "" {
				selectedSignal = "none"
			}
			rows = append(rows, map[string]string{
				"assertion":      item.Assertion,
				"status":         item.Status,
				"blocker":        mapValueOrDefault(item.Blocker, "none"),
				"selectedSignal": selectedSignal,
				"auditReference": "report:" + report.Metadata.ReportID,
			})
		}
		writeServeJSON(writer, http.StatusOK, map[string]any{
			"valid": true,
			"assertionScope": map[string]string{
				"mode":      assertionScopeMode(assertion),
				"assertion": mapValueOrDefault(assertion, "all"),
			},
			"runtimeDriftPolicy":  map[string]any{"policyPassed": allRuntimeDriftInSync(posture)},
			"runtimeDriftPosture": rows,
		})
	})
	apiMux.HandleFunc("/api/v1/lifecycle-policy", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		assertion := strings.TrimSpace(request.URL.Query().Get("assertion"))
		lifecyclePolicy, lifecyclePosture, err := lifecyclePolicyFromReport(report, assertion)
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", err.Error())
			return
		}
		if assertion != "" && len(lifecyclePosture) == 0 {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-008", "assertion is not present in lifecycle policy posture")
			return
		}
		sort.Slice(lifecyclePolicy, func(i, j int) bool { return lifecyclePolicy[i].Assertion < lifecyclePolicy[j].Assertion })
		sort.Slice(lifecyclePosture, func(i, j int) bool { return lifecyclePosture[i].Assertion < lifecyclePosture[j].Assertion })
		writeServeJSON(writer, http.StatusOK, map[string]any{
			"valid": true,
			"assertionScope": map[string]string{
				"mode":      assertionScopeMode(assertion),
				"assertion": mapValueOrDefault(assertion, "all"),
			},
			"lifecyclePublicationPolicy": map[string]any{"policyPassed": len(lifecyclePolicy) == 0},
			"lifecyclePosture":           lifecyclePosture,
			"blockedAssertions":          lifecyclePolicy,
			"taxonomy":                   catalogcoverage.LifecyclePublicationBlockerTaxonomy(),
		})
	})
	apiMux.HandleFunc("/api/v1/workspace", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workspace scanning requires --workspace")
			return
		}
		stages, err := workspacePipelineStages(workspacePath)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-010", err.Error())
			return
		}
		writeServeJSON(writer, http.StatusOK, map[string]any{
			"valid": true,
			"workspace": map[string]any{
				"path":   workspacePath,
				"stages": stages,
			},
		})
	})
	apiMux.HandleFunc("/api/v1/workflow/plan", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow plan creation requires --workspace")
			return
		}
		payload, err := decodeWorkflowPlanCreateRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-011", err.Error())
			return
		}
		outputPath, err := ensureWorkspaceFilePath(workspacePath, payload.OutputPath, "outputPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-011", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-011", err.Error())
			return
		}
		if strings.EqualFold(outputPath, auditPath) {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-011", "outputPath and auditPath must be different files")
			return
		}
		var commandStdout bytes.Buffer
		var commandStderr bytes.Buffer
		exitCode := createPlan([]string{
			"--request", payload.RequestPath,
			"--inventory", payload.InventoryPath,
			"--catalog", payload.CatalogPath,
			"--output", outputPath,
			"--audit-output", auditPath,
		}, &commandStdout, &commandStderr)
		if exitCode != ExitSuccess {
			var failurePayload any
			if err := json.Unmarshal(commandStdout.Bytes(), &failurePayload); err == nil {
				writeServeJSON(writer, workflowPlanCreateStatus(exitCode), failurePayload)
				return
			}
			writeServeError(writer, workflowPlanCreateStatus(exitCode), "YARA-SRV-012", strings.TrimSpace(commandStderr.String()))
			return
		}
		var planCommandResult struct {
			Valid       bool   `json:"valid"`
			PlanID      string `json:"planId"`
			Output      string `json:"output"`
			AuditOutput string `json:"auditOutput"`
		}
		if err := json.Unmarshal(commandStdout.Bytes(), &planCommandResult); err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("decode plan workflow output: %v", err))
			return
		}
		plan, err := resources.LoadPlatformPlan(planCommandResult.Output)
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("load generated plan: %v", err))
			return
		}
		report := plan.Validate()
		if !report.Valid {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("generated plan failed validation: %s", report.Diagnostics[0].Code))
			return
		}
		componentReferences := make(map[string]struct{})
		for _, instance := range plan.Spec.Topology.Instances {
			componentReferences[instance.ComponentRef] = struct{}{}
		}
		response := workflowPlanCreateResponse{Valid: true}
		response.Plan.PlanID = plan.Metadata.PlanID
		response.Plan.PlanPath = planCommandResult.Output
		response.Plan.AuditPath = planCommandResult.AuditOutput
		response.Plan.Confidence = plan.Spec.Confidence.Level
		response.Plan.Decisions = len(plan.Spec.Decisions)
		response.Plan.Instances = len(plan.Spec.Topology.Instances)
		response.Plan.Components = len(componentReferences)
		response.Plan.Diagnostics = len(plan.Spec.Diagnostics)
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/render", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow render requires --workspace")
			return
		}
		payload, err := decodeWorkflowRenderRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-013", err.Error())
			return
		}
		outputPath, err := ensureWorkspaceFilePath(workspacePath, payload.OutputPath, "outputPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-013", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-013", err.Error())
			return
		}
		if strings.EqualFold(outputPath, auditPath) {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-013", "outputPath and auditPath must be different files")
			return
		}
		var commandStdout bytes.Buffer
		var commandStderr bytes.Buffer
		renderArgs := []string{
			"--plan", payload.PlanPath,
			"--catalog", payload.CatalogPath,
			"--name", payload.BundleName,
			"--output", outputPath,
			"--audit-output", auditPath,
		}
		exitCode := ExitInternal
		switch payload.Target {
		case "kubernetes-gitops":
			exitCode = renderKubernetesGitOps(renderArgs, &commandStdout, &commandStderr)
		case "docker-compose":
			exitCode = renderDockerCompose(renderArgs, &commandStdout, &commandStderr)
		default:
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-013", "target must be either kubernetes-gitops or docker-compose")
			return
		}
		if exitCode != ExitSuccess {
			var failurePayload any
			if err := json.Unmarshal(commandStdout.Bytes(), &failurePayload); err == nil {
				writeServeJSON(writer, workflowRenderStatus(exitCode), failurePayload)
				return
			}
			writeServeError(writer, workflowRenderStatus(exitCode), "YARA-SRV-014", strings.TrimSpace(commandStderr.String()))
			return
		}
		var renderCommandResult struct {
			Valid    bool   `json:"valid"`
			BundleID string `json:"bundleId"`
			Renderer struct {
				Target string `json:"target"`
			} `json:"renderer"`
			Output      string `json:"output"`
			AuditOutput string `json:"auditOutput"`
		}
		if err := json.Unmarshal(commandStdout.Bytes(), &renderCommandResult); err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("decode render workflow output: %v", err))
			return
		}
		bundle, err := resources.LoadDeploymentBundle(renderCommandResult.Output)
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("load generated bundle: %v", err))
			return
		}
		report := bundle.Validate()
		if !report.Valid {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("generated bundle failed validation: %s", report.Diagnostics[0].Code))
			return
		}
		response := workflowRenderResponse{Valid: true}
		response.Render.BundleID = bundle.Metadata.BundleID
		response.Render.BundlePath = renderCommandResult.Output
		response.Render.AuditPath = renderCommandResult.AuditOutput
		response.Render.Renderer = bundle.Spec.Renderer.Target
		response.Render.ManifestCount = len(bundle.Spec.Files)
		response.Render.ArtifactCount = len(bundle.Spec.Artifacts)
		response.Render.OperationCount = len(bundle.Spec.Operations)
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/preflight", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow preflight requires --workspace")
			return
		}
		payload, err := decodeWorkflowPreflightRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-015", err.Error())
			return
		}
		outputPath, err := ensureWorkspaceFilePath(workspacePath, payload.OutputPath, "outputPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-015", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-015", err.Error())
			return
		}
		if strings.EqualFold(outputPath, auditPath) {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-015", "outputPath and auditPath must be different files")
			return
		}
		var commandStdout bytes.Buffer
		var commandStderr bytes.Buffer
		preflightArgs := []string{
			"--bundle", payload.BundlePath,
			"--name", payload.Name,
			"--output", outputPath,
			"--audit-output", auditPath,
		}
		if payload.Kubeconfig != "" {
			preflightArgs = append(preflightArgs, "--kubeconfig", payload.Kubeconfig)
		}
		if payload.ContextName != "" {
			preflightArgs = append(preflightArgs, "--context", payload.ContextName)
		}
		if payload.Timeout != "" {
			preflightArgs = append(preflightArgs, "--timeout", payload.Timeout)
		}
		exitCode := workflowPreflightRunner(preflightArgs, &commandStdout, &commandStderr)
		var preflightCommandResult struct {
			Valid       bool   `json:"valid"`
			Outcome     string `json:"outcome"`
			ResultID    string `json:"resultId"`
			Output      string `json:"output"`
			AuditOutput string `json:"auditOutput"`
		}
		if err := json.Unmarshal(commandStdout.Bytes(), &preflightCommandResult); err != nil {
			if exitCode != ExitSuccess {
				var failurePayload any
				if unmarshalErr := json.Unmarshal(commandStdout.Bytes(), &failurePayload); unmarshalErr == nil {
					writeServeJSON(writer, workflowPreflightStatus(exitCode), failurePayload)
					return
				}
				writeServeError(writer, workflowPreflightStatus(exitCode), "YARA-SRV-016", strings.TrimSpace(commandStderr.String()))
				return
			}
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("decode preflight workflow output: %v", err))
			return
		}
		if !preflightCommandResult.Valid || preflightCommandResult.Output == "" || preflightCommandResult.AuditOutput == "" {
			if exitCode != ExitSuccess {
				var failurePayload any
				if unmarshalErr := json.Unmarshal(commandStdout.Bytes(), &failurePayload); unmarshalErr == nil {
					writeServeJSON(writer, workflowPreflightStatus(exitCode), failurePayload)
					return
				}
				writeServeError(writer, workflowPreflightStatus(exitCode), "YARA-SRV-016", strings.TrimSpace(commandStderr.String()))
				return
			}
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", "preflight workflow output omitted deterministic result metadata")
			return
		}
		preflightResult, err := resources.LoadTargetPreflightResult(preflightCommandResult.Output)
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("load generated preflight result: %v", err))
			return
		}
		report := preflightResult.Validate()
		if !report.Valid {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("generated preflight result failed validation: %s", report.Diagnostics[0].Code))
			return
		}
		response := workflowPreflightResponse{Valid: true}
		response.Preflight.ResultID = preflightResult.Metadata.ResultID
		response.Preflight.Outcome = preflightResult.Spec.Outcome
		response.Preflight.TargetReferenceDigest = preflightResult.Spec.Target.ReferenceDigest
		response.Preflight.ResultPath = preflightCommandResult.Output
		response.Preflight.AuditPath = preflightCommandResult.AuditOutput
		response.Preflight.CheckCount = len(preflightResult.Spec.Checks)
		for _, check := range preflightResult.Spec.Checks {
			switch check.Status {
			case "passed":
				response.Preflight.PassedChecks++
			case "blocked":
				response.Preflight.BlockedChecks++
			case "failed":
				response.Preflight.FailedChecks++
			}
		}
		writeServeJSON(writer, workflowPreflightStatus(exitCode), response)
	})
	apiMux.HandleFunc("/api/v1/workflow/changeset", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow changeset requires --workspace")
			return
		}
		payload, err := decodeWorkflowChangeSetRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-017", err.Error())
			return
		}
		outputPath, err := ensureWorkspaceFilePath(workspacePath, payload.OutputPath, "outputPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-017", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-017", err.Error())
			return
		}
		if strings.EqualFold(outputPath, auditPath) {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-017", "outputPath and auditPath must be different files")
			return
		}
		var commandStdout bytes.Buffer
		var commandStderr bytes.Buffer
		changeSetArgs := []string{
			"--bundle", payload.BundlePath,
			"--preflight", payload.PreflightPath,
			"--name", payload.Name,
			"--output", outputPath,
			"--audit-output", auditPath,
		}
		if payload.Kubeconfig != "" {
			changeSetArgs = append(changeSetArgs, "--kubeconfig", payload.Kubeconfig)
		}
		if payload.ContextName != "" {
			changeSetArgs = append(changeSetArgs, "--context", payload.ContextName)
		}
		if payload.Timeout != "" {
			changeSetArgs = append(changeSetArgs, "--timeout", payload.Timeout)
		}
		exitCode := workflowChangeSetRunner(changeSetArgs, &commandStdout, &commandStderr)
		var changeSetCommandResult struct {
			Valid       bool   `json:"valid"`
			Outcome     string `json:"outcome"`
			ChangeSetID string `json:"changeSetId"`
			Output      string `json:"output"`
			AuditOutput string `json:"auditOutput"`
		}
		if err := json.Unmarshal(commandStdout.Bytes(), &changeSetCommandResult); err != nil {
			if exitCode != ExitSuccess {
				var failurePayload any
				if unmarshalErr := json.Unmarshal(commandStdout.Bytes(), &failurePayload); unmarshalErr == nil {
					writeServeJSON(writer, workflowChangeSetStatus(exitCode), failurePayload)
					return
				}
				writeServeError(writer, workflowChangeSetStatus(exitCode), "YARA-SRV-018", strings.TrimSpace(commandStderr.String()))
				return
			}
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("decode changeset workflow output: %v", err))
			return
		}
		if !changeSetCommandResult.Valid || changeSetCommandResult.Output == "" || changeSetCommandResult.AuditOutput == "" {
			if exitCode != ExitSuccess {
				var failurePayload any
				if unmarshalErr := json.Unmarshal(commandStdout.Bytes(), &failurePayload); unmarshalErr == nil {
					writeServeJSON(writer, workflowChangeSetStatus(exitCode), failurePayload)
					return
				}
				writeServeError(writer, workflowChangeSetStatus(exitCode), "YARA-SRV-018", strings.TrimSpace(commandStderr.String()))
				return
			}
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", "changeset workflow output omitted deterministic result metadata")
			return
		}
		changeSet, err := resources.LoadKubernetesChangeSet(changeSetCommandResult.Output)
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("load generated change set: %v", err))
			return
		}
		report := changeSet.Validate()
		if !report.Valid {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("generated change set failed validation: %s", report.Diagnostics[0].Code))
			return
		}
		response := workflowChangeSetResponse{Valid: true}
		response.ChangeSet.ChangeSetID = changeSet.Metadata.ChangeSetID
		response.ChangeSet.Outcome = changeSet.Spec.Outcome
		response.ChangeSet.ChangeSetPath = changeSetCommandResult.Output
		response.ChangeSet.AuditPath = changeSetCommandResult.AuditOutput
		response.ChangeSet.Summary = changeSet.Spec.Summary
		response.ChangeSet.OperationCount = len(changeSet.Spec.Operations)
		response.ChangeSet.Operations = make([]workflowChangeSetOperation, 0, len(changeSet.Spec.Operations))
		for _, operation := range changeSet.Spec.Operations {
			if operation.Action == "conflict" || operation.Action == "unresolved" {
				response.ChangeSet.BlockedCount++
			}
			response.ChangeSet.Operations = append(response.ChangeSet.Operations, workflowChangeSetOperation{
				Resource:       formatKubernetesResource(operation.Resource),
				Action:         operation.Action,
				Ownership:      operation.Ownership,
				Severity:       workflowChangeSetSeverity(operation.Action),
				RiskClasses:    append([]string(nil), operation.RiskClasses...),
				DiagnosticCode: mapValueOrDefault(operation.DiagnosticCode, "none"),
			})
		}
		writeServeJSON(writer, workflowChangeSetStatus(exitCode), response)
	})
	apiMux.HandleFunc("/api/v1/workflow/approval", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow approval requires --workspace")
			return
		}
		payload, err := decodeWorkflowApprovalRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-019", err.Error())
			return
		}
		outputPath, err := ensureWorkspaceFilePath(workspacePath, payload.OutputPath, "outputPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-019", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-019", err.Error())
			return
		}
		if strings.EqualFold(outputPath, auditPath) {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-019", "outputPath and auditPath must be different files")
			return
		}
		var commandStdout bytes.Buffer
		var commandStderr bytes.Buffer
		exitCode := workflowApprovalRunner([]string{
			"--bundle", payload.BundlePath,
			"--preflight", payload.PreflightPath,
			"--change-set", payload.ChangeSetPath,
			"--name", "workflow-approval",
			"--decision", payload.Decision,
			"--reason-reference", payload.ReasonReference,
			"--output", outputPath,
			"--audit-output", auditPath,
		}, &commandStdout, &commandStderr)
		if exitCode != ExitSuccess {
			var failurePayload any
			if err := json.Unmarshal(commandStdout.Bytes(), &failurePayload); err == nil {
				writeServeJSON(writer, workflowApprovalStatus(exitCode), failurePayload)
				return
			}
			writeServeError(writer, workflowApprovalStatus(exitCode), "YARA-SRV-020", strings.TrimSpace(commandStderr.String()))
			return
		}
		var approvalCommandResult struct {
			Valid       bool   `json:"valid"`
			ApprovalID  string `json:"approvalId"`
			Decision    string `json:"decision"`
			Effect      string `json:"effect"`
			Output      string `json:"output"`
			AuditOutput string `json:"auditOutput"`
		}
		if err := json.Unmarshal(commandStdout.Bytes(), &approvalCommandResult); err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("decode approval workflow output: %v", err))
			return
		}
		approval, err := resources.LoadDeploymentApproval(approvalCommandResult.Output)
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("load generated approval: %v", err))
			return
		}
		report := approval.Validate()
		if !report.Valid {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("generated approval failed validation: %s", report.Diagnostics[0].Code))
			return
		}
		response := workflowApprovalResponse{Valid: true}
		response.Approval.ApprovalID = approval.Metadata.ApprovalID
		response.Approval.Decision = approval.Spec.Decision
		response.Approval.Effect = approval.Spec.Effect
		response.Approval.ApprovalPath = approvalCommandResult.Output
		response.Approval.AuditPath = approvalCommandResult.AuditOutput
		response.Approval.PlanID = approval.Spec.PlanID
		response.Approval.BundleID = approval.Spec.BundleID
		response.Approval.PreflightResultID = approval.Spec.PreflightResultID
		response.Approval.ChangeSetID = approval.Spec.ChangeSetID
		response.Approval.TargetReferenceDigest = approval.Spec.Target.ReferenceDigest
		response.Approval.ReasonReference = approval.Spec.Reason.Reference
		writeServeJSON(writer, workflowApprovalStatus(exitCode), response)
	})
	apiMux.HandleFunc("/api/v1/workflow/authorization-command", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "authorization command generation requires --workspace")
			return
		}
		stageLookup, err := workspaceStageArtifacts(workspacePath)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-010", err.Error())
			return
		}
		bundlePath, hasBundle := stageLookup["bundle"]
		preflightPath, hasPreflight := stageLookup["preflight"]
		changeSetPath, hasChangeSet := stageLookup["changeset"]
		approvalPath, hasApproval := stageLookup["approval"]
		if !hasBundle || !hasPreflight || !hasChangeSet || !hasApproval {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-021", "bundle, preflight, change-set, and approval artifacts must exist in workspace")
			return
		}
		query := request.URL.Query()
		privateKeyPath := strings.TrimSpace(query.Get("privateKeyPath"))
		if privateKeyPath == "" {
			privateKeyPath = "<private-key-path>"
		}
		keyID := strings.TrimSpace(query.Get("keyId"))
		if keyID == "" {
			keyID = "<key-id>"
		}
		name := strings.TrimSpace(query.Get("name"))
		if name == "" {
			name = "reference-authorization"
		}
		outputPath := strings.TrimSpace(query.Get("outputPath"))
		if outputPath == "" {
			outputPath = filepath.Join(workspacePath, "reference-authorization.yaml")
		}
		auditPath := strings.TrimSpace(query.Get("auditPath"))
		if auditPath == "" {
			auditPath = filepath.Join(workspacePath, "reference-authorization.audit.jsonl")
		}
		outputPath, err = ensureWorkspaceFilePath(workspacePath, outputPath, "outputPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-021", err.Error())
			return
		}
		auditPath, err = ensureWorkspaceFilePath(workspacePath, auditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-021", err.Error())
			return
		}
		command := strings.Join([]string{
			"yara", "authorization", "issue",
			"--bundle", shellQuote(bundlePath),
			"--preflight", shellQuote(preflightPath),
			"--change-set", shellQuote(changeSetPath),
			"--approval", shellQuote(approvalPath),
			"--private-key", shellQuote(privateKeyPath),
			"--key-id", shellQuote(keyID),
			"--name", shellQuote(name),
			"--output", shellQuote(outputPath),
			"--audit-output", shellQuote(auditPath),
		}, " ")
		writeServeJSON(writer, http.StatusOK, workflowAuthorizationCommandResponse{
			Valid:         true,
			Command:       command,
			BundlePath:    bundlePath,
			PreflightPath: preflightPath,
			ChangeSetPath: changeSetPath,
			ApprovalPath:  approvalPath,
			OutputPath:    outputPath,
			AuditPath:     auditPath,
		})
	})
	apiMux.HandleFunc("/api/v1/workflow/apply", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow apply requires --workspace")
			return
		}
		payload, err := decodeWorkflowApplyRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-022", err.Error())
			return
		}
		receiptPath, err := ensureWorkspaceFilePath(workspacePath, payload.ReceiptPath, "receiptPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-022", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-022", err.Error())
			return
		}
		if strings.EqualFold(receiptPath, auditPath) {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-022", "receiptPath and auditPath must be different files")
			return
		}
		applyArgs := []string{
			"--bundle", payload.BundlePath,
			"--preflight", payload.PreflightPath,
			"--change-set", payload.ChangeSetPath,
			"--approval", payload.ApprovalPath,
			"--import-receipt", payload.ImportReceiptPath,
			"--authorization", payload.AuthorizationPath,
			"--public-key", payload.PublicKeyPath,
			"--confirm-authorization", payload.ConfirmAuthorization,
			"--name", payload.Name,
			"--receipt-output", receiptPath,
			"--audit-output", auditPath,
		}
		for _, path := range payload.TransferReceiptPaths {
			if strings.TrimSpace(path) != "" {
				applyArgs = append(applyArgs, "--transfer-receipt", path)
			}
		}
		for _, path := range payload.ScanReceiptPaths {
			if strings.TrimSpace(path) != "" {
				applyArgs = append(applyArgs, "--scan-receipt", path)
			}
		}
		if payload.AirgapGateResultPath != "" {
			applyArgs = append(applyArgs, "--airgap-gate-result", payload.AirgapGateResultPath)
		}
		if payload.AirgapGateTrustPolicyPath != "" {
			applyArgs = append(applyArgs, "--airgap-gate-trust-policy", payload.AirgapGateTrustPolicyPath)
		}
		if payload.ConfirmAirgapGateTrustPolicy != "" {
			applyArgs = append(applyArgs, "--confirm-airgap-gate-trust-policy", payload.ConfirmAirgapGateTrustPolicy)
		}
		if payload.AirgapGatePolicyDiffPath != "" {
			applyArgs = append(applyArgs, "--airgap-gate-policy-diff", payload.AirgapGatePolicyDiffPath)
		}
		if payload.ConfirmAirgapGatePolicyDiff != "" {
			applyArgs = append(applyArgs, "--confirm-airgap-gate-policy-diff", payload.ConfirmAirgapGatePolicyDiff)
		}
		if payload.AirgapGateTransitionReviewPath != "" {
			applyArgs = append(applyArgs, "--airgap-gate-transition-review", payload.AirgapGateTransitionReviewPath)
		}
		if payload.ConfirmAirgapGateTransitionReview != "" {
			applyArgs = append(applyArgs, "--confirm-airgap-gate-transition-review", payload.ConfirmAirgapGateTransitionReview)
		}
		if payload.Kubeconfig != "" {
			applyArgs = append(applyArgs, "--kubeconfig", payload.Kubeconfig)
		}
		if payload.ContextName != "" {
			applyArgs = append(applyArgs, "--context", payload.ContextName)
		}
		if payload.Timeout != "" {
			applyArgs = append(applyArgs, "--timeout", payload.Timeout)
		}
		var commandStdout bytes.Buffer
		var commandStderr bytes.Buffer
		exitCode := workflowApplyRunner(applyArgs, &commandStdout, &commandStderr)
		if exitCode != ExitSuccess {
			var failurePayload any
			if err := json.Unmarshal(commandStdout.Bytes(), &failurePayload); err == nil {
				writeServeJSON(writer, workflowApplyStatus(exitCode), failurePayload)
				return
			}
			writeServeError(writer, workflowApplyStatus(exitCode), "YARA-SRV-023", strings.TrimSpace(commandStderr.String()))
			return
		}
		var applyCommandResult struct {
			Valid           bool   `json:"valid"`
			Outcome         string `json:"outcome"`
			ReceiptID       string `json:"receiptId"`
			AuthorizationID string `json:"authorizationId"`
			ReceiptOutput   string `json:"receiptOutput"`
			AuditOutput     string `json:"auditOutput"`
		}
		if err := json.Unmarshal(commandStdout.Bytes(), &applyCommandResult); err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("decode apply workflow output: %v", err))
			return
		}
		receipt, err := resources.LoadDeploymentReceipt(applyCommandResult.ReceiptOutput)
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("load generated receipt: %v", err))
			return
		}
		report := receipt.Validate()
		if !report.Valid {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("generated receipt failed validation: %s", report.Diagnostics[0].Code))
			return
		}
		response := workflowApplyResponse{Valid: applyCommandResult.Valid}
		response.Apply.Outcome = applyCommandResult.Outcome
		response.Apply.ReceiptID = receipt.Metadata.ReceiptID
		response.Apply.AuthorizationID = receipt.Spec.AuthorizationID
		response.Apply.ReceiptPath = applyCommandResult.ReceiptOutput
		response.Apply.AuditPath = applyCommandResult.AuditOutput
		response.Apply.PlanID = receipt.Spec.PlanID
		response.Apply.BundleID = receipt.Spec.BundleID
		response.Apply.PreflightResultID = receipt.Spec.PreflightResultID
		response.Apply.ChangeSetID = receipt.Spec.ChangeSetID
		response.Apply.ApprovalID = receipt.Spec.ApprovalID
		response.Apply.TargetReferenceDigest = receipt.Spec.Target.ReferenceDigest
		response.Apply.TransferReceiptIDs = append([]string(nil), receipt.Spec.TransferReceiptIDs...)
		response.Apply.ScanReceiptIDs = append([]string(nil), receipt.Spec.ScanReceiptIDs...)
		response.Apply.AirgapGateResultID = receipt.Spec.AirgapGateResultID
		response.Apply.AirgapTrustPolicyID = receipt.Spec.AirgapGateTrustPolicyID
		response.Apply.AirgapPolicyDiffID = receipt.Spec.AirgapGateTrustPolicyDiffID
		response.Apply.AirgapReviewID = receipt.Spec.AirgapGateTransitionReviewID
		writeServeJSON(writer, workflowApplyStatus(exitCode), response)
	})
	apiMux.HandleFunc("/api/v1/workflow/runbook", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow runbook requires --workspace")
			return
		}
		runbook, _, err := buildWorkflowRunbook(workspacePath)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-024", err.Error())
			return
		}
		writeServeJSON(writer, http.StatusOK, runbook)
	})
	apiMux.HandleFunc("/api/v1/workflow/runbook/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow runbook export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRunbookExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-025", err.Error())
			return
		}
		markdownPath, err := ensureWorkspaceFilePath(workspacePath, payload.MarkdownPath, "markdownPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-025", err.Error())
			return
		}
		jsonPath, err := ensureWorkspaceFilePath(workspacePath, payload.JSONPath, "jsonPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-025", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-025", err.Error())
			return
		}
		if markdownPath == jsonPath || markdownPath == auditPath || jsonPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-025", "markdownPath, jsonPath and auditPath must be different files")
			return
		}
		runbook, subjects, err := buildWorkflowRunbook(workspacePath)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-025", err.Error())
			return
		}
		markdownBytes := []byte(runbook.Runbook.Markdown + "\n")
		if err := writeExclusive(markdownPath, markdownBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-025", err.Error())
			return
		}
		jsonBytes, err := json.MarshalIndent(runbook, "", "  ")
		if err != nil {
			_ = os.Remove(markdownPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode runbook export json: %v", err))
			return
		}
		jsonBytes = append(jsonBytes, '\n')
		if err := writeExclusive(jsonPath, jsonBytes); err != nil {
			_ = os.Remove(markdownPath)
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-025", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "RunbookMarkdown", Digest: digestBytes(markdownBytes)},
			audit.Subject{Kind: "RunbookJSON", Digest: digestBytes(jsonBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.runbook.export", "completed", "success", "kubernetes:"+runbook.Runbook.Evidence.TargetReferenceDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(markdownPath)
			_ = os.Remove(jsonPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRunbookExportResponse{Valid: true}
		response.Export.MarkdownPath = markdownPath
		response.Export.JSONPath = jsonPath
		response.Export.AuditPath = auditPath
		response.Export.StepCount = len(runbook.Runbook.Steps)
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/capsule", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow capsule requires --workspace")
			return
		}
		capsule, err := buildWorkflowCapsule(workspacePath)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-026", err.Error())
			return
		}
		writeServeJSON(writer, http.StatusOK, capsule)
	})
	var (
		uiFileSystem fs.FS
		uiFiles      http.Handler
	)
	if uiEnabled {
		var err error
		uiFileSystem, err = serveUIFileSystem()
		if err != nil {
			return nil, err
		}
		uiFiles = http.FileServer(http.FS(uiFileSystem))
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/api/") {
			_, pattern := apiMux.Handler(request)
			if pattern == "" {
				writeServeNotFound(writer)
				return
			}
			apiMux.ServeHTTP(writer, request)
			return
		}
		if !uiEnabled || request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		if request.URL.Path == "/" {
			serveUIIndex(writer, uiFileSystem)
			return
		}
		cleanPath := strings.TrimPrefix(request.URL.Path, "/")
		if cleanPath == "" {
			serveUIIndex(writer, uiFileSystem)
			return
		}
		if _, err := fs.Stat(uiFileSystem, cleanPath); err == nil {
			uiFiles.ServeHTTP(writer, request)
			return
		}
		serveUIIndex(writer, uiFileSystem)
	}), nil
}

type workspaceStageStatus struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Status       string `json:"status"`
	ArtifactPath string `json:"artifactPath,omitempty"`
}

type workflowPlanCreateRequest struct {
	RequestPath   string `json:"requestPath"`
	InventoryPath string `json:"inventoryPath"`
	CatalogPath   string `json:"catalogPath"`
	OutputPath    string `json:"outputPath"`
	AuditPath     string `json:"auditPath"`
}

type workflowPlanCreateResponse struct {
	Valid bool `json:"valid"`
	Plan  struct {
		PlanID      string `json:"planId"`
		PlanPath    string `json:"planPath"`
		AuditPath   string `json:"auditPath"`
		Confidence  string `json:"confidence"`
		Decisions   int    `json:"decisions"`
		Instances   int    `json:"instances"`
		Components  int    `json:"components"`
		Diagnostics int    `json:"diagnostics"`
	} `json:"plan"`
}

type workflowRenderRequest struct {
	PlanPath    string `json:"planPath"`
	CatalogPath string `json:"catalogPath"`
	Target      string `json:"target"`
	BundleName  string `json:"bundleName"`
	OutputPath  string `json:"outputPath"`
	AuditPath   string `json:"auditPath"`
}

type workflowRenderResponse struct {
	Valid  bool `json:"valid"`
	Render struct {
		BundleID       string `json:"bundleId"`
		BundlePath     string `json:"bundlePath"`
		AuditPath      string `json:"auditPath"`
		Renderer       string `json:"renderer"`
		ManifestCount  int    `json:"manifestCount"`
		ArtifactCount  int    `json:"artifactCount"`
		OperationCount int    `json:"operationCount"`
	} `json:"render"`
}

type workflowPreflightRequest struct {
	BundlePath  string `json:"bundlePath"`
	Name        string `json:"name"`
	OutputPath  string `json:"outputPath"`
	AuditPath   string `json:"auditPath"`
	Kubeconfig  string `json:"kubeconfig,omitempty"`
	ContextName string `json:"context,omitempty"`
	Timeout     string `json:"timeout,omitempty"`
}

type workflowPreflightResponse struct {
	Valid     bool `json:"valid"`
	Preflight struct {
		ResultID              string `json:"resultId"`
		Outcome               string `json:"outcome"`
		TargetReferenceDigest string `json:"targetReferenceDigest"`
		ResultPath            string `json:"resultPath"`
		AuditPath             string `json:"auditPath"`
		CheckCount            int    `json:"checkCount"`
		PassedChecks          int    `json:"passedChecks"`
		BlockedChecks         int    `json:"blockedChecks"`
		FailedChecks          int    `json:"failedChecks"`
	} `json:"preflight"`
}

type workflowChangeSetRequest struct {
	BundlePath    string `json:"bundlePath"`
	PreflightPath string `json:"preflightPath"`
	Name          string `json:"name"`
	OutputPath    string `json:"outputPath"`
	AuditPath     string `json:"auditPath"`
	Kubeconfig    string `json:"kubeconfig,omitempty"`
	ContextName   string `json:"context,omitempty"`
	Timeout       string `json:"timeout,omitempty"`
}

type workflowChangeSetOperation struct {
	Resource       string   `json:"resource"`
	Action         string   `json:"action"`
	Ownership      string   `json:"ownership"`
	Severity       string   `json:"severity"`
	RiskClasses    []string `json:"riskClasses"`
	DiagnosticCode string   `json:"diagnosticCode,omitempty"`
}

type workflowChangeSetResponse struct {
	Valid     bool `json:"valid"`
	ChangeSet struct {
		ChangeSetID    string                            `json:"changeSetId"`
		Outcome        string                            `json:"outcome"`
		ChangeSetPath  string                            `json:"changeSetPath"`
		AuditPath      string                            `json:"auditPath"`
		OperationCount int                               `json:"operationCount"`
		BlockedCount   int                               `json:"blockedCount"`
		Summary        resources.KubernetesChangeSummary `json:"summary"`
		Operations     []workflowChangeSetOperation      `json:"operations"`
	} `json:"changeSet"`
}

var workflowPreflightRunner = kubernetesTargetPreflight
var workflowChangeSetRunner = kubernetesChangeSet
var workflowApprovalRunner = recordDeploymentApproval
var workflowApplyRunner = applyKubernetesDeployment

type workflowApprovalRequest struct {
	BundlePath      string `json:"bundlePath"`
	PreflightPath   string `json:"preflightPath"`
	ChangeSetPath   string `json:"changeSetPath"`
	Decision        string `json:"decision"`
	ReasonReference string `json:"reasonReference"`
	OutputPath      string `json:"outputPath"`
	AuditPath       string `json:"auditPath"`
}

type workflowApprovalResponse struct {
	Valid    bool `json:"valid"`
	Approval struct {
		ApprovalID            string `json:"approvalId"`
		Decision              string `json:"decision"`
		Effect                string `json:"effect"`
		ApprovalPath          string `json:"approvalPath"`
		AuditPath             string `json:"auditPath"`
		PlanID                string `json:"planId"`
		BundleID              string `json:"bundleId"`
		PreflightResultID     string `json:"preflightResultId"`
		ChangeSetID           string `json:"changeSetId"`
		TargetReferenceDigest string `json:"targetReferenceDigest"`
		ReasonReference       string `json:"reasonReference"`
	} `json:"approval"`
}

type workflowAuthorizationCommandResponse struct {
	Valid         bool   `json:"valid"`
	Command       string `json:"command"`
	BundlePath    string `json:"bundlePath"`
	PreflightPath string `json:"preflightPath"`
	ChangeSetPath string `json:"changeSetPath"`
	ApprovalPath  string `json:"approvalPath"`
	OutputPath    string `json:"outputPath"`
	AuditPath     string `json:"auditPath"`
}

type workflowApplyRequest struct {
	BundlePath                        string   `json:"bundlePath"`
	PreflightPath                     string   `json:"preflightPath"`
	ChangeSetPath                     string   `json:"changeSetPath"`
	ApprovalPath                      string   `json:"approvalPath"`
	ImportReceiptPath                 string   `json:"importReceiptPath"`
	TransferReceiptPaths              []string `json:"transferReceiptPaths,omitempty"`
	ScanReceiptPaths                  []string `json:"scanReceiptPaths,omitempty"`
	AirgapGateResultPath              string   `json:"airgapGateResultPath,omitempty"`
	AirgapGateTrustPolicyPath         string   `json:"airgapGateTrustPolicyPath,omitempty"`
	ConfirmAirgapGateTrustPolicy      string   `json:"confirmAirgapGateTrustPolicy,omitempty"`
	AirgapGatePolicyDiffPath          string   `json:"airgapGatePolicyDiffPath,omitempty"`
	ConfirmAirgapGatePolicyDiff       string   `json:"confirmAirgapGatePolicyDiff,omitempty"`
	AirgapGateTransitionReviewPath    string   `json:"airgapGateTransitionReviewPath,omitempty"`
	ConfirmAirgapGateTransitionReview string   `json:"confirmAirgapGateTransitionReview,omitempty"`
	AuthorizationPath                 string   `json:"authorizationPath"`
	PublicKeyPath                     string   `json:"publicKeyPath"`
	ConfirmAuthorization              string   `json:"confirmAuthorization"`
	TypedConfirmationDigest           string   `json:"typedConfirmationDigest"`
	Name                              string   `json:"name"`
	ReceiptPath                       string   `json:"receiptPath"`
	AuditPath                         string   `json:"auditPath"`
	Kubeconfig                        string   `json:"kubeconfig,omitempty"`
	ContextName                       string   `json:"context,omitempty"`
	Timeout                           string   `json:"timeout,omitempty"`
}

type workflowApplyResponse struct {
	Valid bool `json:"valid"`
	Apply struct {
		Outcome               string   `json:"outcome"`
		ReceiptID             string   `json:"receiptId"`
		AuthorizationID       string   `json:"authorizationId"`
		ReceiptPath           string   `json:"receiptPath"`
		AuditPath             string   `json:"auditPath"`
		PlanID                string   `json:"planId"`
		BundleID              string   `json:"bundleId"`
		PreflightResultID     string   `json:"preflightResultId"`
		ChangeSetID           string   `json:"changeSetId"`
		ApprovalID            string   `json:"approvalId"`
		TargetReferenceDigest string   `json:"targetReferenceDigest"`
		TransferReceiptIDs    []string `json:"transferReceiptIds,omitempty"`
		ScanReceiptIDs        []string `json:"scanReceiptIds,omitempty"`
		AirgapGateResultID    string   `json:"airgapGateResultId,omitempty"`
		AirgapTrustPolicyID   string   `json:"airgapTrustPolicyId,omitempty"`
		AirgapPolicyDiffID    string   `json:"airgapPolicyDiffId,omitempty"`
		AirgapReviewID        string   `json:"airgapReviewId,omitempty"`
	} `json:"apply"`
}

type workflowRunbookStep struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
}

type workflowRunbookResponse struct {
	Valid   bool `json:"valid"`
	Runbook struct {
		WorkspacePath string `json:"workspacePath"`
		Artifacts     struct {
			PlanPath          string `json:"planPath"`
			BundlePath        string `json:"bundlePath"`
			PreflightPath     string `json:"preflightPath"`
			ChangeSetPath     string `json:"changeSetPath"`
			ApprovalPath      string `json:"approvalPath"`
			AuthorizationPath string `json:"authorizationPath"`
		} `json:"artifacts"`
		Evidence struct {
			PlanID                string `json:"planId"`
			BundleID              string `json:"bundleId"`
			PreflightResultID     string `json:"preflightResultId"`
			ChangeSetID           string `json:"changeSetId"`
			ApprovalID            string `json:"approvalId"`
			AuthorizationID       string `json:"authorizationId"`
			TargetReferenceDigest string `json:"targetReferenceDigest"`
		} `json:"evidence"`
		FailClosedCheckpoints []string              `json:"failClosedCheckpoints"`
		Steps                 []workflowRunbookStep `json:"steps"`
		Markdown              string                `json:"markdown"`
	} `json:"runbook"`
}

type workflowRunbookExportRequest struct {
	MarkdownPath string `json:"markdownPath"`
	JSONPath     string `json:"jsonPath"`
	AuditPath    string `json:"auditPath"`
}

type workflowRunbookExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		MarkdownPath string `json:"markdownPath"`
		JSONPath     string `json:"jsonPath"`
		AuditPath    string `json:"auditPath"`
		StepCount    int    `json:"stepCount"`
	} `json:"export"`
}

type workflowCapsuleBlocker struct {
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

type workflowCapsuleResponse struct {
	Valid   bool `json:"valid"`
	Capsule struct {
		WorkspacePath string                 `json:"workspacePath"`
		Ready         bool                   `json:"ready"`
		Stages        []workspaceStageStatus `json:"stages"`
		Evidence      struct {
			PlanID                string `json:"planId,omitempty"`
			BundleID              string `json:"bundleId,omitempty"`
			PreflightResultID     string `json:"preflightResultId,omitempty"`
			ChangeSetID           string `json:"changeSetId,omitempty"`
			ApprovalID            string `json:"approvalId,omitempty"`
			AuthorizationID       string `json:"authorizationId,omitempty"`
			TargetReferenceDigest string `json:"targetReferenceDigest,omitempty"`
		} `json:"evidence"`
		RunbookExports struct {
			MarkdownPaths []string `json:"markdownPaths"`
			JSONPaths     []string `json:"jsonPaths"`
		} `json:"runbookExports"`
		Blockers []workflowCapsuleBlocker `json:"blockers"`
	} `json:"capsule"`
}

func workspacePipelineStages(workspacePath string) ([]workspaceStageStatus, error) {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return nil, fmt.Errorf("read workspace directory: %w", err)
	}
	artifacts := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			artifacts = append(artifacts, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(artifacts)
	stageArtifacts := map[string]string{}
	for _, artifactPath := range artifacts {
		stageID, err := classifyWorkspaceArtifact(artifactPath)
		if err != nil {
			return nil, err
		}
		if existing, hasExisting := stageArtifacts[stageID]; hasExisting {
			return nil, fmt.Errorf("multiple workspace artifacts matched stage %s: %s and %s", stageID, filepath.Base(existing), filepath.Base(artifactPath))
		}
		stageArtifacts[stageID] = artifactPath
	}
	stages := []workspaceStageStatus{
		{ID: "plan", Label: "Plan"},
		{ID: "bundle", Label: "Bundle"},
		{ID: "preflight", Label: "Preflight"},
		{ID: "changeset", Label: "Change-set"},
		{ID: "approval", Label: "Approval"},
		{ID: "authorization", Label: "Authorization"},
		{ID: "receipt", Label: "Apply receipt"},
	}
	for index := range stages {
		if artifactPath, exists := stageArtifacts[stages[index].ID]; exists {
			stages[index].Status = "complete"
			stages[index].ArtifactPath = artifactPath
			continue
		}
		if index == 0 {
			stages[index].Status = "ready"
			continue
		}
		stages[index].Status = "not-started"
	}
	return stages, nil
}

func workspaceStageArtifacts(workspacePath string) (map[string]string, error) {
	stages, err := workspacePipelineStages(workspacePath)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, stage := range stages {
		if stage.ArtifactPath != "" && stage.ArtifactPath != "none" {
			result[stage.ID] = stage.ArtifactPath
		}
	}
	return result, nil
}

func classifyWorkspaceArtifact(path string) (string, error) {
	if plan, err := resources.LoadPlatformPlan(path); err == nil {
		if report := plan.Validate(); !report.Valid {
			return "", fmt.Errorf("workspace artifact %s is malformed PlatformPlan: %s", filepath.Base(path), report.Diagnostics[0].Code)
		}
		return "plan", nil
	}
	if bundle, err := resources.LoadDeploymentBundle(path); err == nil {
		if report := bundle.Validate(); !report.Valid {
			return "", fmt.Errorf("workspace artifact %s is malformed DeploymentBundle: %s", filepath.Base(path), report.Diagnostics[0].Code)
		}
		return "bundle", nil
	}
	if preflight, err := resources.LoadTargetPreflightResult(path); err == nil {
		if report := preflight.Validate(); !report.Valid {
			return "", fmt.Errorf("workspace artifact %s is malformed TargetPreflightResult: %s", filepath.Base(path), report.Diagnostics[0].Code)
		}
		return "preflight", nil
	}
	if changeSet, err := resources.LoadKubernetesChangeSet(path); err == nil {
		if report := changeSet.Validate(); !report.Valid {
			return "", fmt.Errorf("workspace artifact %s is malformed KubernetesChangeSet: %s", filepath.Base(path), report.Diagnostics[0].Code)
		}
		return "changeset", nil
	}
	if approval, err := resources.LoadDeploymentApproval(path); err == nil {
		if report := approval.Validate(); !report.Valid {
			return "", fmt.Errorf("workspace artifact %s is malformed DeploymentApproval: %s", filepath.Base(path), report.Diagnostics[0].Code)
		}
		return "approval", nil
	}
	if authorization, err := resources.LoadExecutionAuthorization(path); err == nil {
		if report := authorization.Validate(); !report.Valid {
			return "", fmt.Errorf("workspace artifact %s is malformed ExecutionAuthorization: %s", filepath.Base(path), report.Diagnostics[0].Code)
		}
		return "authorization", nil
	}
	if receipt, err := resources.LoadDeploymentReceipt(path); err == nil {
		if report := receipt.Validate(); !report.Valid {
			return "", fmt.Errorf("workspace artifact %s is malformed DeploymentReceipt: %s", filepath.Base(path), report.Diagnostics[0].Code)
		}
		return "receipt", nil
	}
	return "", fmt.Errorf("workspace artifact %s is unknown or unsupported", filepath.Base(path))
}

func decodeWorkflowPlanCreateRequest(request *http.Request) (workflowPlanCreateRequest, error) {
	var payload workflowPlanCreateRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.RequestPath) == "" || strings.TrimSpace(payload.InventoryPath) == "" || strings.TrimSpace(payload.CatalogPath) == "" || strings.TrimSpace(payload.OutputPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("requestPath, inventoryPath, catalogPath, outputPath and auditPath are required")
	}
	if payload.OutputPath == payload.AuditPath {
		return payload, errors.New("outputPath and auditPath must be different files")
	}
	return payload, nil
}

func ensureWorkspaceFilePath(workspacePath, candidatePath, label string) (string, error) {
	workspaceAbsolute, err := filepath.Abs(workspacePath)
	if err != nil {
		return "", fmt.Errorf("resolve workspace path: %w", err)
	}
	candidateAbsolute, err := filepath.Abs(candidatePath)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	relative, err := filepath.Rel(workspaceAbsolute, candidateAbsolute)
	if err != nil {
		return "", fmt.Errorf("resolve %s relative path: %w", label, err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s must be inside workspace directory", label)
	}
	return candidateAbsolute, nil
}

func workflowPlanCreateStatus(exitCode int) int {
	switch exitCode {
	case ExitInvalidInput:
		return http.StatusBadRequest
	case ExitInfeasible:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

func workflowRenderStatus(exitCode int) int {
	switch exitCode {
	case ExitSuccess:
		return http.StatusOK
	case ExitInvalidInput:
		return http.StatusBadRequest
	case ExitUnsupported:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

func workflowPreflightStatus(exitCode int) int {
	switch exitCode {
	case ExitSuccess:
		return http.StatusOK
	case ExitInvalidInput:
		return http.StatusBadRequest
	case ExitInfeasible, ExitUnsupported:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

func workflowChangeSetStatus(exitCode int) int {
	switch exitCode {
	case ExitSuccess:
		return http.StatusOK
	case ExitInvalidInput:
		return http.StatusBadRequest
	case ExitInfeasible, ExitUnsupported:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

func workflowApprovalStatus(exitCode int) int {
	switch exitCode {
	case ExitSuccess:
		return http.StatusOK
	case ExitInvalidInput:
		return http.StatusBadRequest
	case ExitInfeasible, ExitUnsupported:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

func workflowApplyStatus(exitCode int) int {
	switch exitCode {
	case ExitSuccess:
		return http.StatusOK
	case ExitInvalidInput:
		return http.StatusBadRequest
	case ExitInfeasible, ExitUnsupported:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

func decodeWorkflowRenderRequest(request *http.Request) (workflowRenderRequest, error) {
	var payload workflowRenderRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.PlanPath) == "" || strings.TrimSpace(payload.CatalogPath) == "" || strings.TrimSpace(payload.Target) == "" || strings.TrimSpace(payload.BundleName) == "" || strings.TrimSpace(payload.OutputPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("planPath, catalogPath, target, bundleName, outputPath and auditPath are required")
	}
	if payload.OutputPath == payload.AuditPath {
		return payload, errors.New("outputPath and auditPath must be different files")
	}
	if payload.Target != "kubernetes-gitops" && payload.Target != "docker-compose" {
		return payload, errors.New("target must be either kubernetes-gitops or docker-compose")
	}
	return payload, nil
}

func decodeWorkflowPreflightRequest(request *http.Request) (workflowPreflightRequest, error) {
	var payload workflowPreflightRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.BundlePath) == "" || strings.TrimSpace(payload.Name) == "" || strings.TrimSpace(payload.OutputPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("bundlePath, name, outputPath and auditPath are required")
	}
	if payload.OutputPath == payload.AuditPath {
		return payload, errors.New("outputPath and auditPath must be different files")
	}
	if payload.Timeout != "" {
		if _, err := time.ParseDuration(payload.Timeout); err != nil {
			return payload, errors.New("timeout must be a valid Go duration string")
		}
	}
	return payload, nil
}

func decodeWorkflowChangeSetRequest(request *http.Request) (workflowChangeSetRequest, error) {
	var payload workflowChangeSetRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.BundlePath) == "" || strings.TrimSpace(payload.PreflightPath) == "" || strings.TrimSpace(payload.Name) == "" || strings.TrimSpace(payload.OutputPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("bundlePath, preflightPath, name, outputPath and auditPath are required")
	}
	if payload.OutputPath == payload.AuditPath {
		return payload, errors.New("outputPath and auditPath must be different files")
	}
	if payload.Timeout != "" {
		if _, err := time.ParseDuration(payload.Timeout); err != nil {
			return payload, errors.New("timeout must be a valid Go duration string")
		}
	}
	return payload, nil
}

func decodeWorkflowApprovalRequest(request *http.Request) (workflowApprovalRequest, error) {
	var payload workflowApprovalRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.BundlePath) == "" || strings.TrimSpace(payload.PreflightPath) == "" || strings.TrimSpace(payload.ChangeSetPath) == "" || strings.TrimSpace(payload.Decision) == "" || strings.TrimSpace(payload.ReasonReference) == "" || strings.TrimSpace(payload.OutputPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("bundlePath, preflightPath, changeSetPath, decision, reasonReference, outputPath and auditPath are required")
	}
	if payload.OutputPath == payload.AuditPath {
		return payload, errors.New("outputPath and auditPath must be different files")
	}
	if payload.Decision != "approve" && payload.Decision != "reject" {
		return payload, errors.New("decision must be either approve or reject")
	}
	return payload, nil
}

func decodeWorkflowApplyRequest(request *http.Request) (workflowApplyRequest, error) {
	var payload workflowApplyRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.BundlePath) == "" || strings.TrimSpace(payload.PreflightPath) == "" || strings.TrimSpace(payload.ChangeSetPath) == "" || strings.TrimSpace(payload.ApprovalPath) == "" || strings.TrimSpace(payload.ImportReceiptPath) == "" || strings.TrimSpace(payload.AuthorizationPath) == "" || strings.TrimSpace(payload.PublicKeyPath) == "" || strings.TrimSpace(payload.ConfirmAuthorization) == "" || strings.TrimSpace(payload.TypedConfirmationDigest) == "" || strings.TrimSpace(payload.Name) == "" || strings.TrimSpace(payload.ReceiptPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("bundlePath, preflightPath, changeSetPath, approvalPath, importReceiptPath, authorizationPath, publicKeyPath, confirmAuthorization, typedConfirmationDigest, name, receiptPath and auditPath are required")
	}
	if payload.ReceiptPath == payload.AuditPath {
		return payload, errors.New("receiptPath and auditPath must be different files")
	}
	if payload.ConfirmAuthorization != payload.TypedConfirmationDigest {
		return payload, errors.New("typedConfirmationDigest must exactly match confirmAuthorization")
	}
	if payload.AirgapGateResultPath != "" && (strings.TrimSpace(payload.AirgapGateTrustPolicyPath) == "" || strings.TrimSpace(payload.ConfirmAirgapGateTrustPolicy) == "") {
		return payload, errors.New("airgapGateTrustPolicyPath and confirmAirgapGateTrustPolicy are required when airgapGateResultPath is set")
	}
	if (strings.TrimSpace(payload.AirgapGatePolicyDiffPath) == "") != (strings.TrimSpace(payload.ConfirmAirgapGatePolicyDiff) == "") {
		return payload, errors.New("airgapGatePolicyDiffPath and confirmAirgapGatePolicyDiff must both be set when either is provided")
	}
	if (strings.TrimSpace(payload.AirgapGateTransitionReviewPath) == "") != (strings.TrimSpace(payload.ConfirmAirgapGateTransitionReview) == "") {
		return payload, errors.New("airgapGateTransitionReviewPath and confirmAirgapGateTransitionReview must both be set when either is provided")
	}
	if payload.Timeout != "" {
		if _, err := time.ParseDuration(payload.Timeout); err != nil {
			return payload, errors.New("timeout must be a valid Go duration string")
		}
	}
	return payload, nil
}

func decodeWorkflowRunbookExportRequest(request *http.Request) (workflowRunbookExportRequest, error) {
	var payload workflowRunbookExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.MarkdownPath) == "" || strings.TrimSpace(payload.JSONPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("markdownPath, jsonPath and auditPath are required")
	}
	if payload.MarkdownPath == payload.JSONPath || payload.MarkdownPath == payload.AuditPath || payload.JSONPath == payload.AuditPath {
		return payload, errors.New("markdownPath, jsonPath and auditPath must be different files")
	}
	return payload, nil
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	escaped := strings.ReplaceAll(value, `'`, `'"'"'`)
	return "'" + escaped + "'"
}

func buildWorkflowRunbook(workspacePath string) (workflowRunbookResponse, []audit.Subject, error) {
	stageLookup, err := workspaceStageArtifacts(workspacePath)
	if err != nil {
		return workflowRunbookResponse{}, nil, err
	}
	planPath, hasPlan := stageLookup["plan"]
	bundlePath, hasBundle := stageLookup["bundle"]
	preflightPath, hasPreflight := stageLookup["preflight"]
	changeSetPath, hasChangeSet := stageLookup["changeset"]
	approvalPath, hasApproval := stageLookup["approval"]
	authorizationPath, hasAuthorization := stageLookup["authorization"]
	if !hasPlan || !hasBundle || !hasPreflight || !hasChangeSet || !hasApproval || !hasAuthorization {
		return workflowRunbookResponse{}, nil, errors.New("runbook requires plan, bundle, preflight, change-set, approval, and authorization artifacts in workspace")
	}
	plan, err := resources.LoadPlatformPlan(planPath)
	if err != nil || !plan.Validate().Valid {
		return workflowRunbookResponse{}, nil, errors.New("workspace plan artifact is invalid")
	}
	bundle, err := resources.LoadDeploymentBundle(bundlePath)
	if err != nil || !bundle.Validate().Valid {
		return workflowRunbookResponse{}, nil, errors.New("workspace bundle artifact is invalid")
	}
	preflight, err := resources.LoadTargetPreflightResult(preflightPath)
	if err != nil || !preflight.Validate().Valid {
		return workflowRunbookResponse{}, nil, errors.New("workspace preflight artifact is invalid")
	}
	changeSet, err := resources.LoadKubernetesChangeSet(changeSetPath)
	if err != nil || !changeSet.Validate().Valid {
		return workflowRunbookResponse{}, nil, errors.New("workspace change-set artifact is invalid")
	}
	approval, err := resources.LoadDeploymentApproval(approvalPath)
	if err != nil || !approval.Validate().Valid {
		return workflowRunbookResponse{}, nil, errors.New("workspace approval artifact is invalid")
	}
	authorization, err := resources.LoadExecutionAuthorization(authorizationPath)
	if err != nil || !authorization.Validate().Valid {
		return workflowRunbookResponse{}, nil, errors.New("workspace authorization artifact is invalid")
	}
	runbook := workflowRunbookResponse{Valid: true}
	runbook.Runbook.WorkspacePath = workspacePath
	runbook.Runbook.Artifacts.PlanPath = planPath
	runbook.Runbook.Artifacts.BundlePath = bundlePath
	runbook.Runbook.Artifacts.PreflightPath = preflightPath
	runbook.Runbook.Artifacts.ChangeSetPath = changeSetPath
	runbook.Runbook.Artifacts.ApprovalPath = approvalPath
	runbook.Runbook.Artifacts.AuthorizationPath = authorizationPath
	runbook.Runbook.Evidence.PlanID = plan.Metadata.PlanID
	runbook.Runbook.Evidence.BundleID = bundle.Metadata.BundleID
	runbook.Runbook.Evidence.PreflightResultID = preflight.Metadata.ResultID
	runbook.Runbook.Evidence.ChangeSetID = changeSet.Metadata.ChangeSetID
	runbook.Runbook.Evidence.ApprovalID = approval.Metadata.ApprovalID
	runbook.Runbook.Evidence.AuthorizationID = authorization.Metadata.AuthorizationID
	runbook.Runbook.Evidence.TargetReferenceDigest = authorization.Spec.Target.ReferenceDigest
	runbook.Runbook.FailClosedCheckpoints = []string{
		"Never send private key material to the API; run authorization signing locally.",
		"Before apply, --confirm-authorization must equal the authorization ID and typed confirmation digest.",
		"When using --airgap-gate-result, require trust-policy path and explicit trust-policy ID confirmation.",
		"When using a destructive trust-policy diff, require a reviewed transition artifact and explicit review ID confirmation.",
	}
	runbook.Runbook.Steps = []workflowRunbookStep{
		{
			ID:          "review-evidence",
			Title:       "Review immutable evidence chain",
			Description: "Verify plan, bundle, preflight, change-set, approval, and authorization IDs before execution.",
		},
		{
			ID:          "authorization-verify",
			Title:       "Verify signed authorization",
			Description: "Verify the signed authorization against a trusted public key before apply.",
			Command: strings.Join([]string{
				"yara", "authorization", "verify",
				"--authorization", shellQuote(authorizationPath),
				"--public-key", shellQuote("<public-key-path>"),
			}, " "),
		},
		{
			ID:          "deployment-apply",
			Title:       "Execute bounded apply",
			Description: "Run apply with explicit confirmation. Add optional air-gap flags only when gate artifacts exist.",
			Command: strings.Join([]string{
				"yara", "deployment", "apply", "kubernetes",
				"--bundle", shellQuote(bundlePath),
				"--preflight", shellQuote(preflightPath),
				"--change-set", shellQuote(changeSetPath),
				"--approval", shellQuote(approvalPath),
				"--import-receipt", shellQuote("<import-receipt-path>"),
				"--authorization", shellQuote(authorizationPath),
				"--public-key", shellQuote("<public-key-path>"),
				"--confirm-authorization", shellQuote(authorization.Metadata.AuthorizationID),
				"--name", shellQuote("reference-receipt"),
				"--receipt-output", shellQuote(filepath.Join(workspacePath, "reference-receipt.yaml")),
				"--audit-output", shellQuote(filepath.Join(workspacePath, "reference-apply.audit.jsonl")),
				"[--transfer-receipt <path> --scan-receipt <path> ...]",
				"[--airgap-gate-result <path> --airgap-gate-trust-policy <path> --confirm-airgap-gate-trust-policy <sha256:id>]",
				"[--airgap-gate-policy-diff <path> --confirm-airgap-gate-policy-diff <sha256:id>]",
				"[--airgap-gate-transition-review <path> --confirm-airgap-gate-transition-review <sha256:id>]",
			}, " "),
		},
	}
	runbook.Runbook.Markdown = strings.Join([]string{
		"# YARA workflow runbook",
		"",
		"## Evidence chain",
		"- Plan ID: " + runbook.Runbook.Evidence.PlanID,
		"- Bundle ID: " + runbook.Runbook.Evidence.BundleID,
		"- Preflight result ID: " + runbook.Runbook.Evidence.PreflightResultID,
		"- Change-set ID: " + runbook.Runbook.Evidence.ChangeSetID,
		"- Approval ID: " + runbook.Runbook.Evidence.ApprovalID,
		"- Authorization ID: " + runbook.Runbook.Evidence.AuthorizationID,
		"- Target digest: " + runbook.Runbook.Evidence.TargetReferenceDigest,
		"",
		"## Fail-closed checkpoints",
		"- Never send private key material to the API.",
		"- Confirmation digest must match authorization ID before apply.",
		"- Gate trust-policy and transition-review confirmations are required when applicable.",
	}, "\n")
	subjects := []audit.Subject{
		{Kind: "PlatformPlan", Digest: plan.Metadata.PlanID},
		{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID},
		{Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID},
		{Kind: "KubernetesChangeSet", Digest: changeSet.Metadata.ChangeSetID},
		{Kind: "DeploymentApproval", Digest: approval.Metadata.ApprovalID},
		{Kind: "ExecutionAuthorization", Digest: authorization.Metadata.AuthorizationID},
	}
	return runbook, subjects, nil
}

func buildWorkflowCapsule(workspacePath string) (workflowCapsuleResponse, error) {
	stages, err := workspacePipelineStages(workspacePath)
	if err != nil {
		return workflowCapsuleResponse{}, err
	}
	stageLookup := map[string]workspaceStageStatus{}
	for _, stage := range stages {
		stageLookup[stage.ID] = stage
	}
	capsule := workflowCapsuleResponse{Valid: true}
	capsule.Capsule.WorkspacePath = workspacePath
	capsule.Capsule.Stages = append([]workspaceStageStatus(nil), stages...)
	capsule.Capsule.Ready = true

	requirements := []struct {
		id, code, remediation string
	}{
		{id: "plan", code: "YARA-CAP-001", remediation: "run workflow plan create"},
		{id: "bundle", code: "YARA-CAP-002", remediation: "run workflow render"},
		{id: "preflight", code: "YARA-CAP-003", remediation: "run workflow preflight"},
		{id: "changeset", code: "YARA-CAP-004", remediation: "run workflow changeset"},
		{id: "approval", code: "YARA-CAP-005", remediation: "run workflow approval"},
		{id: "authorization", code: "YARA-CAP-006", remediation: "issue authorization and place file in workspace"},
	}
	for _, requirement := range requirements {
		stage, exists := stageLookup[requirement.id]
		if !exists || stage.Status != "complete" || stage.ArtifactPath == "" || stage.ArtifactPath == "none" {
			capsule.Capsule.Ready = false
			capsule.Capsule.Blockers = append(capsule.Capsule.Blockers, workflowCapsuleBlocker{
				Code:        requirement.code,
				Severity:    "error",
				Message:     fmt.Sprintf("%s stage is incomplete", requirement.id),
				Remediation: requirement.remediation,
			})
		}
	}
	capsule.Capsule.RunbookExports.MarkdownPaths, capsule.Capsule.RunbookExports.JSONPaths = discoverRunbookExports(workspacePath)
	if !capsule.Capsule.Ready {
		return capsule, nil
	}

	plan, err := resources.LoadPlatformPlan(stageLookup["plan"].ArtifactPath)
	if err != nil || !plan.Validate().Valid {
		capsule.Capsule.Ready = false
		capsule.Capsule.Blockers = append(capsule.Capsule.Blockers, workflowCapsuleBlocker{
			Code:        "YARA-CAP-007",
			Severity:    "error",
			Message:     "plan artifact is malformed",
			Remediation: "recreate plan artifact through workflow plan create",
		})
		return capsule, nil
	}
	bundle, err := resources.LoadDeploymentBundle(stageLookup["bundle"].ArtifactPath)
	if err != nil || !bundle.Validate().Valid {
		capsule.Capsule.Ready = false
		capsule.Capsule.Blockers = append(capsule.Capsule.Blockers, workflowCapsuleBlocker{
			Code:        "YARA-CAP-008",
			Severity:    "error",
			Message:     "bundle artifact is malformed",
			Remediation: "recreate bundle through workflow render",
		})
		return capsule, nil
	}
	preflight, err := resources.LoadTargetPreflightResult(stageLookup["preflight"].ArtifactPath)
	if err != nil || !preflight.Validate().Valid {
		capsule.Capsule.Ready = false
		capsule.Capsule.Blockers = append(capsule.Capsule.Blockers, workflowCapsuleBlocker{
			Code:        "YARA-CAP-009",
			Severity:    "error",
			Message:     "preflight artifact is malformed",
			Remediation: "rerun workflow preflight",
		})
		return capsule, nil
	}
	changeSet, err := resources.LoadKubernetesChangeSet(stageLookup["changeset"].ArtifactPath)
	if err != nil || !changeSet.Validate().Valid {
		capsule.Capsule.Ready = false
		capsule.Capsule.Blockers = append(capsule.Capsule.Blockers, workflowCapsuleBlocker{
			Code:        "YARA-CAP-010",
			Severity:    "error",
			Message:     "change-set artifact is malformed",
			Remediation: "rerun workflow changeset",
		})
		return capsule, nil
	}
	approval, err := resources.LoadDeploymentApproval(stageLookup["approval"].ArtifactPath)
	if err != nil || !approval.Validate().Valid {
		capsule.Capsule.Ready = false
		capsule.Capsule.Blockers = append(capsule.Capsule.Blockers, workflowCapsuleBlocker{
			Code:        "YARA-CAP-011",
			Severity:    "error",
			Message:     "approval artifact is malformed",
			Remediation: "rerun workflow approval",
		})
		return capsule, nil
	}
	authorization, err := resources.LoadExecutionAuthorization(stageLookup["authorization"].ArtifactPath)
	if err != nil || !authorization.Validate().Valid {
		capsule.Capsule.Ready = false
		capsule.Capsule.Blockers = append(capsule.Capsule.Blockers, workflowCapsuleBlocker{
			Code:        "YARA-CAP-012",
			Severity:    "error",
			Message:     "authorization artifact is malformed",
			Remediation: "reissue authorization and replace workspace authorization artifact",
		})
		return capsule, nil
	}

	capsule.Capsule.Evidence.PlanID = plan.Metadata.PlanID
	capsule.Capsule.Evidence.BundleID = bundle.Metadata.BundleID
	capsule.Capsule.Evidence.PreflightResultID = preflight.Metadata.ResultID
	capsule.Capsule.Evidence.ChangeSetID = changeSet.Metadata.ChangeSetID
	capsule.Capsule.Evidence.ApprovalID = approval.Metadata.ApprovalID
	capsule.Capsule.Evidence.AuthorizationID = authorization.Metadata.AuthorizationID
	capsule.Capsule.Evidence.TargetReferenceDigest = authorization.Spec.Target.ReferenceDigest

	if bundle.Spec.PlanID != preflight.Spec.PlanID || bundle.Spec.PlanID != changeSet.Spec.PlanID || bundle.Spec.PlanID != approval.Spec.PlanID || bundle.Spec.PlanID != authorization.Spec.PlanID ||
		bundle.Metadata.BundleID != preflight.Spec.BundleID || bundle.Metadata.BundleID != changeSet.Spec.BundleID || bundle.Metadata.BundleID != approval.Spec.BundleID || bundle.Metadata.BundleID != authorization.Spec.BundleID ||
		preflight.Metadata.ResultID != changeSet.Spec.PreflightResultID || preflight.Metadata.ResultID != approval.Spec.PreflightResultID || preflight.Metadata.ResultID != authorization.Spec.PreflightResultID ||
		changeSet.Metadata.ChangeSetID != approval.Spec.ChangeSetID || changeSet.Metadata.ChangeSetID != authorization.Spec.ChangeSetID || approval.Metadata.ApprovalID != authorization.Spec.ApprovalID ||
		preflight.Spec.Target != changeSet.Spec.Target || preflight.Spec.Target != approval.Spec.Target || preflight.Spec.Target != authorization.Spec.Target {
		capsule.Capsule.Ready = false
		capsule.Capsule.Blockers = append(capsule.Capsule.Blockers, workflowCapsuleBlocker{
			Code:        "YARA-CAP-013",
			Severity:    "error",
			Message:     "evidence artifacts are mismatched across plan, target, or approvals",
			Remediation: "regenerate the workflow chain from plan through authorization using one consistent artifact set",
		})
	}
	return capsule, nil
}

func discoverRunbookExports(workspacePath string) ([]string, []string) {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}, []string{}
	}
	markdownPaths := []string{}
	jsonPaths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".runbook.md") {
			markdownPaths = append(markdownPaths, filepath.Join(workspacePath, name))
		}
		if strings.HasSuffix(name, ".runbook.json") {
			jsonPaths = append(jsonPaths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(markdownPaths)
	sort.Strings(jsonPaths)
	return markdownPaths, jsonPaths
}

func formatKubernetesResource(reference resources.KubernetesObjectReference) string {
	if reference.Namespace == "" {
		return fmt.Sprintf("%s/%s %s", reference.APIVersion, reference.Kind, reference.Name)
	}
	return fmt.Sprintf("%s/%s %s/%s", reference.APIVersion, reference.Kind, reference.Namespace, reference.Name)
}

func workflowChangeSetSeverity(action string) string {
	switch action {
	case "conflict", "unresolved":
		return "blocker"
	default:
		return "review"
	}
}

func serveUIIndex(writer http.ResponseWriter, uiFileSystem fs.FS) {
	indexHTML, err := fs.ReadFile(uiFileSystem, "index.html")
	if err != nil {
		writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", "embedded web ui index is unavailable")
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(indexHTML)
}

func lifecyclePolicyFromReport(report catalogcoverage.Report, assertionFilter string) ([]lifecyclePolicyAssertion, []lifecyclePostureAssertion, error) {
	blocked := make([]lifecyclePolicyAssertion, 0, len(report.Spec.Assertions))
	posture := make([]lifecyclePostureAssertion, 0, len(report.Spec.Assertions))
	for _, assertion := range report.Spec.Assertions {
		if assertionFilter != "" && assertion.ID != assertionFilter {
			continue
		}
		lifecycleProof, ok := serveGateStatus(assertion.Gates, "lifecycle-proof-publication-approval")
		if !ok {
			return nil, nil, fmt.Errorf("assertion %s omits lifecycle proof publication gate", assertion.ID)
		}
		integrationAttestation, ok := serveGateStatus(assertion.Gates, "integration-publication-attestation")
		if !ok {
			return nil, nil, fmt.Errorf("assertion %s omits integration publication gate", assertion.ID)
		}
		publicationRehearsal, ok := serveGateStatus(assertion.Gates, "publication-chain-rehearsal")
		if !ok {
			return nil, nil, fmt.Errorf("assertion %s omits publication rehearsal gate", assertion.ID)
		}
		renewalReview, ok := serveGateStatus(assertion.Gates, "publication-chain-renewal-review")
		if !ok {
			return nil, nil, fmt.Errorf("assertion %s omits renewal review gate", assertion.ID)
		}
		row := lifecyclePostureAssertion{
			Assertion:            assertion.ID,
			Ready:                assertion.LifecyclePublicationReady,
			LifecycleProof:       lifecycleProof,
			IntegrationAttest:    integrationAttestation,
			PublicationRehearsal: publicationRehearsal,
			RenewalReview:        renewalReview,
		}
		if assertion.LifecyclePublicationReady {
			posture = append(posture, row)
			continue
		}
		if assertion.LifecyclePublicationBlocker == "" {
			return nil, nil, fmt.Errorf("assertion %s omits lifecycle publication blocker", assertion.ID)
		}
		parsed, err := catalogcoverage.ParseLifecyclePublicationBlocker(assertion.LifecyclePublicationBlocker)
		if err != nil {
			return nil, nil, fmt.Errorf("assertion %s has malformed lifecycle publication blocker: %w", assertion.ID, err)
		}
		row.Blocker = assertion.LifecyclePublicationBlocker
		row.Code = parsed.Code
		row.Remediation = parsed.Remediation
		posture = append(posture, row)
		blocked = append(blocked, lifecyclePolicyAssertion{
			Assertion: assertion.ID, Status: "blocked", Blocker: assertion.LifecyclePublicationBlocker, Code: parsed.Code, Remediation: parsed.Remediation,
		})
	}
	return blocked, posture, nil
}

func serveGateStatus(gates []catalogcoverage.GateCoverage, gateID string) (string, bool) {
	for _, gate := range gates {
		if gate.ID == gateID {
			return gate.Status, true
		}
	}
	return "", false
}

func allRuntimeDriftInSync(posture []runtimeDriftPosture) bool {
	for _, item := range posture {
		if item.Status != "in-sync" {
			return false
		}
	}
	return true
}

func mapValueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func assertionScopeMode(assertion string) string {
	if assertion == "" {
		return "all"
	}
	return "single-assertion"
}

func writeServeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeServeError(writer http.ResponseWriter, status int, code, message string) {
	writeServeJSON(writer, status, map[string]any{
		"valid":       false,
		"diagnostics": []map[string]string{{"code": code, "severity": "error", "message": message}},
	})
}

func writeServeNotFound(writer http.ResponseWriter) {
	writeServeError(writer, http.StatusNotFound, "YARA-SRV-404", "route not found")
}
