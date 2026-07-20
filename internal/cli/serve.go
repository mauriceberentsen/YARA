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
