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
	"gopkg.in/yaml.v3"
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
		capsule, _, err := buildWorkflowCapsule(workspacePath)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-026", err.Error())
			return
		}
		writeServeJSON(writer, http.StatusOK, capsule)
	})
	apiMux.HandleFunc("/api/v1/workflow/capsule/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow capsule export requires --workspace")
			return
		}
		payload, err := decodeWorkflowCapsuleExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-027", err.Error())
			return
		}
		markdownPath, err := ensureWorkspaceFilePath(workspacePath, payload.MarkdownPath, "markdownPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-027", err.Error())
			return
		}
		jsonPath, err := ensureWorkspaceFilePath(workspacePath, payload.JSONPath, "jsonPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-027", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-027", err.Error())
			return
		}
		if markdownPath == jsonPath || markdownPath == auditPath || jsonPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-027", "markdownPath, jsonPath and auditPath must be different files")
			return
		}
		capsule, subjects, err := buildWorkflowCapsule(workspacePath)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-027", err.Error())
			return
		}
		if !capsule.Capsule.Ready && !payload.AllowBlocked {
			writeServeError(writer, http.StatusUnprocessableEntity, "YARA-SRV-027", "capsule is blocked; set allowBlocked=true with allowBlockedReasonReference to archive blocked state")
			return
		}
		if !capsule.Capsule.Ready && strings.TrimSpace(payload.AllowBlockedReasonReference) == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-027", "allowBlockedReasonReference is required when exporting a blocked capsule")
			return
		}
		diagnosticCodes := []string{}
		if !capsule.Capsule.Ready {
			diagnosticCodes = append(diagnosticCodes, "YARA-CAP-014")
		}
		markdownBytes := []byte(renderCapsuleMarkdown(capsule, payload.AllowBlockedReasonReference) + "\n")
		if err := writeExclusive(markdownPath, markdownBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-027", err.Error())
			return
		}
		jsonBytes, err := json.MarshalIndent(capsule, "", "  ")
		if err != nil {
			_ = os.Remove(markdownPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode capsule export json: %v", err))
			return
		}
		jsonBytes = append(jsonBytes, '\n')
		if err := writeExclusive(jsonPath, jsonBytes); err != nil {
			_ = os.Remove(markdownPath)
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-027", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "CapsuleMarkdown", Digest: digestBytes(markdownBytes)},
			audit.Subject{Kind: "CapsuleJSON", Digest: digestBytes(jsonBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.capsule.export", "completed", "success", "kubernetes:"+mapValueOrDefault(capsule.Capsule.Evidence.TargetReferenceDigest, "unknown"), exportSubjects, diagnosticCodes); err != nil {
			_ = os.Remove(markdownPath)
			_ = os.Remove(jsonPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowCapsuleExportResponse{Valid: true}
		response.Export.MarkdownPath = markdownPath
		response.Export.JSONPath = jsonPath
		response.Export.AuditPath = auditPath
		response.Export.Ready = capsule.Capsule.Ready
		response.Export.BlockedArchival = !capsule.Capsule.Ready
		response.Export.BlockerCount = len(capsule.Capsule.Blockers)
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/evidence-bundle/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow evidence bundle export requires --workspace")
			return
		}
		payload, err := decodeWorkflowEvidenceBundleExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-028", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-028", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-028", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-028", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowEvidenceBundleManifest(workspacePath)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-028", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode evidence bundle manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-028", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowEvidenceBundleManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.evidence-bundle.export", "completed", "success", "kubernetes:"+manifest.Manifest.Evidence.TargetReferenceDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowEvidenceBundleExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.RunbookExportCount = len(manifest.Manifest.RunbookExports)
		response.Export.CapsuleExportCount = len(manifest.Manifest.CapsuleExports)
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/receipt-timeline", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow receipt timeline requires --workspace")
			return
		}
		timeline, _, err := buildWorkflowReceiptTimeline(workspacePath)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-029", err.Error())
			return
		}
		writeServeJSON(writer, http.StatusOK, timeline)
	})
	apiMux.HandleFunc("/api/v1/workflow/receipt-timeline/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow receipt timeline export requires --workspace")
			return
		}
		payload, err := decodeWorkflowReceiptTimelineExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-030", err.Error())
			return
		}
		markdownPath, err := ensureWorkspaceFilePath(workspacePath, payload.MarkdownPath, "markdownPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-030", err.Error())
			return
		}
		jsonPath, err := ensureWorkspaceFilePath(workspacePath, payload.JSONPath, "jsonPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-030", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-030", err.Error())
			return
		}
		if markdownPath == jsonPath || markdownPath == auditPath || jsonPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-030", "markdownPath, jsonPath and auditPath must be different files")
			return
		}
		timeline, subjects, err := buildWorkflowReceiptTimeline(workspacePath)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-030", err.Error())
			return
		}
		markdownBytes := []byte(renderReceiptTimelineMarkdown(timeline) + "\n")
		if err := writeExclusive(markdownPath, markdownBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-030", err.Error())
			return
		}
		jsonBytes, err := json.MarshalIndent(timeline, "", "  ")
		if err != nil {
			_ = os.Remove(markdownPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode receipt timeline export json: %v", err))
			return
		}
		jsonBytes = append(jsonBytes, '\n')
		if err := writeExclusive(jsonPath, jsonBytes); err != nil {
			_ = os.Remove(markdownPath)
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-030", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "ReceiptTimelineMarkdown", Digest: digestBytes(markdownBytes)},
			audit.Subject{Kind: "ReceiptTimelineJSON", Digest: digestBytes(jsonBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.receipt-timeline.export", "completed", "success", "kubernetes:"+timeline.Timeline.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(markdownPath)
			_ = os.Remove(jsonPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowReceiptTimelineExportResponse{Valid: true}
		response.Export.MarkdownPath = markdownPath
		response.Export.JSONPath = jsonPath
		response.Export.AuditPath = auditPath
		response.Export.ReceiptCount = len(timeline.Timeline.Prior) + 1
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/closure-package/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow closure package export requires --workspace")
			return
		}
		payload, err := decodeWorkflowClosurePackageExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-031", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-031", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-031", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-031", "manifestPath and auditPath must be different files")
			return
		}
		closurePackage, subjects, err := buildWorkflowClosurePackageManifest(workspacePath, payload.ReleaseReadinessReference)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-031", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(closurePackage, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode closure package manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-031", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowClosurePackageManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.closure-package.export", "completed", "success", "kubernetes:"+closurePackage.Package.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowClosurePackageExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.EvidenceBundleCount = len(closurePackage.Package.EvidenceBundles)
		response.Export.ReceiptTimelineCount = len(closurePackage.Package.ReceiptTimelines)
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/closure-package/review-gate", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow closure review gate requires --workspace")
			return
		}
		releaseReadinessReference := strings.TrimSpace(request.URL.Query().Get("releaseReadinessReference"))
		reviewerReference := strings.TrimSpace(request.URL.Query().Get("reviewerReference"))
		decision := strings.TrimSpace(request.URL.Query().Get("decision"))
		gate, _, err := evaluateWorkflowClosureReviewGate(workspacePath, releaseReadinessReference, reviewerReference, decision)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-032", err.Error())
			return
		}
		writeServeJSON(writer, http.StatusOK, gate)
	})
	apiMux.HandleFunc("/api/v1/workflow/closure-package/review-gate/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow closure review gate export requires --workspace")
			return
		}
		payload, err := decodeWorkflowClosureReviewGateExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-033", err.Error())
			return
		}
		markdownPath, err := ensureWorkspaceFilePath(workspacePath, payload.MarkdownPath, "markdownPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-033", err.Error())
			return
		}
		jsonPath, err := ensureWorkspaceFilePath(workspacePath, payload.JSONPath, "jsonPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-033", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-033", err.Error())
			return
		}
		if markdownPath == jsonPath || markdownPath == auditPath || jsonPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-033", "markdownPath, jsonPath and auditPath must be different files")
			return
		}
		gate, subjects, err := evaluateWorkflowClosureReviewGate(workspacePath, payload.ReleaseReadinessReference, payload.ReviewerReference, payload.Decision)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-033", err.Error())
			return
		}
		markdownBytes := []byte(renderClosureReviewGateMarkdown(gate) + "\n")
		if err := writeExclusive(markdownPath, markdownBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-033", err.Error())
			return
		}
		jsonBytes, err := json.MarshalIndent(gate, "", "  ")
		if err != nil {
			_ = os.Remove(markdownPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode closure review gate export json: %v", err))
			return
		}
		jsonBytes = append(jsonBytes, '\n')
		if err := writeExclusive(jsonPath, jsonBytes); err != nil {
			_ = os.Remove(markdownPath)
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-033", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "ClosureReviewGateMarkdown", Digest: digestBytes(markdownBytes)},
			audit.Subject{Kind: "ClosureReviewGateJSON", Digest: digestBytes(jsonBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.closure-package.review-gate.export", "completed", gate.Gate.Outcome, "kubernetes:"+gate.Gate.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(markdownPath)
			_ = os.Remove(jsonPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowClosureReviewGateExportResponse{Valid: true}
		response.Export.MarkdownPath = markdownPath
		response.Export.JSONPath = jsonPath
		response.Export.AuditPath = auditPath
		response.Export.Outcome = gate.Gate.Outcome
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/release-decision/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow release decision export requires --workspace")
			return
		}
		payload, err := decodeWorkflowReleaseDecisionExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-034", err.Error())
			return
		}
		ledgerPath, err := ensureWorkspaceFilePath(workspacePath, payload.LedgerPath, "ledgerPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-034", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-034", err.Error())
			return
		}
		if ledgerPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-034", "ledgerPath and auditPath must be different files")
			return
		}
		ledger, subjects, err := buildWorkflowReleaseDecisionLedger(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-034", err.Error())
			return
		}
		ledgerBytes, err := json.MarshalIndent(ledger, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode release decision ledger: %v", err))
			return
		}
		ledgerBytes = append(ledgerBytes, '\n')
		if err := writeExclusive(ledgerPath, ledgerBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-034", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "ReleaseDecisionLedger", Digest: digestBytes(ledgerBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.release-decision.export", "completed", ledger.Ledger.PublicationState, "kubernetes:"+ledger.Ledger.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(ledgerPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowReleaseDecisionExportResponse{Valid: true}
		response.Export.LedgerPath = ledgerPath
		response.Export.AuditPath = auditPath
		response.Export.PublicationState = ledger.Ledger.PublicationState
		response.Export.BlockerCode = ledger.Ledger.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/release-publication/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow release publication export requires --workspace")
			return
		}
		payload, err := decodeWorkflowReleasePublicationExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-035", err.Error())
			return
		}
		attestationPath, err := ensureWorkspaceFilePath(workspacePath, payload.AttestationPath, "attestationPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-035", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-035", err.Error())
			return
		}
		if attestationPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-035", "attestationPath and auditPath must be different files")
			return
		}
		attestation, subjects, err := buildWorkflowReleasePublicationAttestation(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-035", err.Error())
			return
		}
		attestationBytes, err := json.MarshalIndent(attestation, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode release publication attestation: %v", err))
			return
		}
		attestationBytes = append(attestationBytes, '\n')
		if err := writeExclusive(attestationPath, attestationBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-035", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "ReleasePublicationAttestation", Digest: digestBytes(attestationBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.release-publication.export", "completed", attestation.Publication.PublicationState, "kubernetes:"+attestation.Publication.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(attestationPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowReleasePublicationExportResponse{Valid: true}
		response.Export.AttestationPath = attestationPath
		response.Export.AuditPath = auditPath
		response.Export.PublicationState = attestation.Publication.PublicationState
		response.Export.BlockerCode = attestation.Publication.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/release-publication/index/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow release publication index export requires --workspace")
			return
		}
		payload, err := decodeWorkflowReleasePublicationIndexExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-036", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-036", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-036", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-036", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowReleasePublicationIndexManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-036", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode release publication index manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-036", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "ReleasePublicationIndexManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.release-publication.index.export", "completed", manifest.Index.IndexState, "kubernetes:"+manifest.Index.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowReleasePublicationIndexExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.IndexState = manifest.Index.IndexState
		response.Export.BlockerCode = manifest.Index.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/release-publication/package/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow release publication package export requires --workspace")
			return
		}
		payload, err := decodeWorkflowReleasePublicationPackageExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-037", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-037", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-037", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-037", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowReleasePublicationPackageManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-037", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode release publication package manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-037", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "ReleasePublicationPackageManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.release-publication.package.export", "completed", manifest.Package.PackageState, "kubernetes:"+manifest.Package.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowReleasePublicationPackageExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.PackageState = manifest.Package.PackageState
		response.Export.BlockerCode = manifest.Package.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/release-publication/envelope/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow release publication envelope export requires --workspace")
			return
		}
		payload, err := decodeWorkflowReleasePublicationEnvelopeExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-038", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-038", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-038", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-038", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowReleasePublicationEnvelopeManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-038", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode release publication envelope manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-038", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "ReleasePublicationEnvelopeManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.release-publication.envelope.export", "completed", manifest.Envelope.DeliveryState, "kubernetes:"+manifest.Envelope.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowReleasePublicationEnvelopeExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.DeliveryState = manifest.Envelope.DeliveryState
		response.Export.BlockerCode = manifest.Envelope.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/release-publication/handoff-receipt/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow release publication handoff receipt export requires --workspace")
			return
		}
		payload, err := decodeWorkflowReleasePublicationHandoffReceiptExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-039", err.Error())
			return
		}
		receiptPath, err := ensureWorkspaceFilePath(workspacePath, payload.ReceiptPath, "receiptPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-039", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-039", err.Error())
			return
		}
		if receiptPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-039", "receiptPath and auditPath must be different files")
			return
		}
		receipt, subjects, err := buildWorkflowReleasePublicationHandoffReceipt(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-039", err.Error())
			return
		}
		receiptBytes, err := json.MarshalIndent(receipt, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode release publication handoff receipt: %v", err))
			return
		}
		receiptBytes = append(receiptBytes, '\n')
		if err := writeExclusive(receiptPath, receiptBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-039", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "ReleasePublicationHandoffReceipt", Digest: digestBytes(receiptBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.release-publication.handoff-receipt.export", "completed", receipt.Handoff.HandoffState, "kubernetes:"+receipt.Handoff.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(receiptPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowReleasePublicationHandoffReceiptExportResponse{Valid: true}
		response.Export.ReceiptPath = receiptPath
		response.Export.AuditPath = auditPath
		response.Export.HandoffState = receipt.Handoff.HandoffState
		response.Export.BlockerCode = receipt.Handoff.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/release-publication/acknowledgment/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow release publication acknowledgment export requires --workspace")
			return
		}
		payload, err := decodeWorkflowReleasePublicationAcknowledgmentExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-040", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-040", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-040", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-040", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowReleasePublicationAcknowledgmentManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-040", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode release publication acknowledgment manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-040", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "ReleasePublicationAcknowledgmentManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.release-publication.acknowledgment.export", "completed", manifest.Acknowledgment.AcknowledgmentState, "kubernetes:"+manifest.Acknowledgment.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowReleasePublicationAcknowledgmentExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.AcknowledgmentState = manifest.Acknowledgment.AcknowledgmentState
		response.Export.BlockerCode = manifest.Acknowledgment.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure-summary/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure summary export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureSummaryExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-041", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-041", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-041", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-041", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureSummaryManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-041", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure summary manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-041", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureSummaryManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure-summary.export", "completed", manifest.Summary.SummaryState, "kubernetes:"+manifest.Summary.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureSummaryExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.SummaryState = manifest.Summary.SummaryState
		response.Export.BlockerCode = manifest.Summary.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure-delivery/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure delivery export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureDeliveryExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-042", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-042", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-042", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-042", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureDeliveryManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-042", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure delivery manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-042", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureDeliveryManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure-delivery.export", "completed", manifest.Delivery.DeliveryRecordState, "kubernetes:"+manifest.Delivery.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureDeliveryExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.DeliveryRecordState = manifest.Delivery.DeliveryRecordState
		response.Export.BlockerCode = manifest.Delivery.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure-acceptance/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure acceptance export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureAcceptanceExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-043", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-043", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-043", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-043", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureAcceptanceManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-043", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure acceptance manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-043", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureAcceptanceManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure-acceptance.export", "completed", manifest.Acceptance.AcceptanceState, "kubernetes:"+manifest.Acceptance.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureAcceptanceExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.AcceptanceState = manifest.Acceptance.AcceptanceState
		response.Export.BlockerCode = manifest.Acceptance.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure-certificate/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure certificate export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureCertificateExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-044", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-044", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-044", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-044", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureCertificateManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-044", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure certificate manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-044", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureCertificateManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure-certificate.export", "completed", manifest.Certificate.CertificateState, "kubernetes:"+manifest.Certificate.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureCertificateExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.CertificateState = manifest.Certificate.CertificateState
		response.Export.BlockerCode = manifest.Certificate.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure-ledger/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure ledger export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureLedgerExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-045", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-045", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-045", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-045", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureLedgerManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-045", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure ledger manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-045", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureLedgerManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure-ledger.export", "completed", manifest.Ledger.LedgerState, "kubernetes:"+manifest.Ledger.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureLedgerExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.LedgerState = manifest.Ledger.LedgerState
		response.Export.BlockerCode = manifest.Ledger.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure-docket/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure docket export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureDocketExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-046", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-046", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-046", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-046", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureDocketManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-046", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure docket manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-046", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureDocketManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure-docket.export", "completed", manifest.Docket.DocketState, "kubernetes:"+manifest.Docket.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureDocketExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.DocketState = manifest.Docket.DocketState
		response.Export.BlockerCode = manifest.Docket.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure-bulletin/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure bulletin export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureBulletinExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-047", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-047", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-047", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-047", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureBulletinManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-047", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure bulletin manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-047", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureBulletinManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure-bulletin.export", "completed", manifest.Bulletin.BulletinState, "kubernetes:"+manifest.Bulletin.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureBulletinExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.BulletinState = manifest.Bulletin.BulletinState
		response.Export.BlockerCode = manifest.Bulletin.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure-packet/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure packet export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosurePacketExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-048", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-048", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-048", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-048", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosurePacketManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-048", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure packet manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-048", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosurePacketManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure-packet.export", "completed", manifest.Packet.PacketState, "kubernetes:"+manifest.Packet.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosurePacketExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.PacketState = manifest.Packet.PacketState
		response.Export.BlockerCode = manifest.Packet.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure-recipient-package/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure recipient package export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureRecipientPackageExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-049", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-049", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-049", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-049", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureRecipientPackageManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-049", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure recipient package manifest: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-049", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureRecipientPackageManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure-recipient-package.export", "completed", manifest.RecipientPackage.RecipientPackageState, "kubernetes:"+manifest.RecipientPackage.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureRecipientPackageExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.RecipientPackageState = manifest.RecipientPackage.RecipientPackageState
		response.Export.BlockerCode = manifest.RecipientPackage.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure/verify", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure verify requires --workspace")
			return
		}
		verification := verifyWorkflowRolloutClosureChain(workspacePath)
		writeServeJSON(writer, http.StatusOK, verification)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure/verify/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure verify export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureVerifyExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-050", err.Error())
			return
		}
		markdownPath, err := ensureWorkspaceFilePath(workspacePath, payload.MarkdownPath, "markdownPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-050", err.Error())
			return
		}
		jsonPath, err := ensureWorkspaceFilePath(workspacePath, payload.JSONPath, "jsonPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-050", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-050", err.Error())
			return
		}
		if markdownPath == jsonPath || markdownPath == auditPath || jsonPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-050", "markdownPath, jsonPath and auditPath must be different files")
			return
		}
		verification := verifyWorkflowRolloutClosureChain(workspacePath)
		if !verification.Verification.Ready && !payload.AllowBlocked {
			writeServeError(writer, http.StatusUnprocessableEntity, "YARA-SRV-050", "YARA-RCVX-003: verification is blocked; set allowBlocked=true with allowBlockedReasonReference to export blocked verification")
			return
		}
		if !verification.Verification.Ready && strings.TrimSpace(payload.AllowBlockedReasonReference) == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-050", "YARA-RCVX-004: allowBlockedReasonReference is required when exporting a blocked verification")
			return
		}
		markdownBytes := []byte(renderWorkflowRolloutClosureVerifyMarkdown(payload, verification) + "\n")
		if err := writeExclusive(markdownPath, markdownBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-050", err.Error())
			return
		}
		exportBundle := workflowRolloutClosureVerifyExportBundle{Valid: true}
		exportBundle.Export.WorkspacePath = workspacePath
		exportBundle.Export.VerificationReference = strings.TrimSpace(payload.VerificationReference)
		exportBundle.Export.OperatorReference = strings.TrimSpace(payload.OperatorReference)
		exportBundle.Export.VerificationTimestamp = strings.TrimSpace(payload.VerificationTimestamp)
		exportBundle.Export.AllowBlocked = payload.AllowBlocked
		exportBundle.Export.AllowBlockedReasonReference = strings.TrimSpace(payload.AllowBlockedReasonReference)
		exportBundle.Export.Ready = verification.Verification.Ready
		exportBundle.Export.VerificationState = verification.Verification.VerificationState
		exportBundle.Export.BlockerCode = verification.Verification.BlockerCode
		exportBundle.Export.Continuity = verification.Verification.Continuity
		exportBundle.Export.Coverage = verification.Verification.Coverage
		exportBundle.Export.Diagnostics = verification.Verification.Diagnostics
		jsonBytes, err := json.MarshalIndent(exportBundle, "", "  ")
		if err != nil {
			_ = os.Remove(markdownPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure verify export json: %v", err))
			return
		}
		jsonBytes = append(jsonBytes, '\n')
		if err := writeExclusive(jsonPath, jsonBytes); err != nil {
			_ = os.Remove(markdownPath)
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-050", err.Error())
			return
		}
		exportSubjects := []audit.Subject{
			{Kind: "WorkflowRolloutClosureVerifyMarkdown", Digest: digestBytes(markdownBytes)},
			{Kind: "WorkflowRolloutClosureVerifyJSON", Digest: digestBytes(jsonBytes)},
			{
				Kind: "WorkflowRolloutClosureVerifyReference",
				Digest: digestBytes([]byte(strings.Join([]string{
					exportBundle.Export.VerificationReference,
					exportBundle.Export.OperatorReference,
					exportBundle.Export.VerificationTimestamp,
					verification.Verification.BlockerCode,
					verification.Verification.Continuity.AuthorizationID,
					verification.Verification.Continuity.TargetDigest,
				}, "|"))),
			},
		}
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure.verify.export", "completed", verification.Verification.VerificationState, "kubernetes:"+verification.Verification.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(markdownPath)
			_ = os.Remove(jsonPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureVerifyExportResponse{Valid: true}
		response.Export.MarkdownPath = markdownPath
		response.Export.JSONPath = jsonPath
		response.Export.AuditPath = auditPath
		response.Export.Ready = verification.Verification.Ready
		response.Export.BlockedArchival = !verification.Verification.Ready
		response.Export.VerificationState = verification.Verification.VerificationState
		response.Export.BlockerCode = verification.Verification.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure/verify/attest", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure verify attest requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureVerifyAttestationExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-051", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-051", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-051", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-051", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureVerifyAttestationManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-051", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure verify attestation: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-051", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureVerifyAttestation", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure.verify.attest", "completed", manifest.Attestation.AttestationState, "kubernetes:"+manifest.Attestation.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureVerifyAttestationExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.AttestationState = manifest.Attestation.AttestationState
		response.Export.BlockerCode = manifest.Attestation.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure/verify/attest/index/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure verify attestation index export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureVerifyAttestationIndexExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-052", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-052", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-052", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-052", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureVerifyAttestationIndexManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-052", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure verify attestation index: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-052", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureVerifyAttestationIndexManifest", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure.verify.attest.index.export", "completed", manifest.Index.IndexState, "kubernetes:"+manifest.Index.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureVerifyAttestationIndexExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.IndexState = manifest.Index.IndexState
		response.Export.BlockerCode = manifest.Index.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
	})
	apiMux.HandleFunc("/api/v1/workflow/rollout-closure/verify/publication-package/export", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeServeNotFound(writer)
			return
		}
		if workspacePath == "" {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-009", "workflow rollout closure verify publication package export requires --workspace")
			return
		}
		payload, err := decodeWorkflowRolloutClosureVerifyPublicationPackageExportRequest(request)
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-053", err.Error())
			return
		}
		manifestPath, err := ensureWorkspaceFilePath(workspacePath, payload.ManifestPath, "manifestPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-053", err.Error())
			return
		}
		auditPath, err := ensureWorkspaceFilePath(workspacePath, payload.AuditPath, "auditPath")
		if err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-053", err.Error())
			return
		}
		if manifestPath == auditPath {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-053", "manifestPath and auditPath must be different files")
			return
		}
		manifest, subjects, err := buildWorkflowRolloutClosureVerifyPublicationPackageManifest(workspacePath, payload)
		if err != nil {
			status := http.StatusBadRequest
			if gateErr, ok := err.(workflowGateError); ok {
				status = gateErr.Status
			}
			writeServeError(writer, status, "YARA-SRV-053", err.Error())
			return
		}
		manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", fmt.Sprintf("encode rollout closure verify publication package: %v", err))
			return
		}
		manifestBytes = append(manifestBytes, '\n')
		if err := writeExclusive(manifestPath, manifestBytes); err != nil {
			writeServeError(writer, http.StatusBadRequest, "YARA-SRV-053", err.Error())
			return
		}
		exportSubjects := append(append([]audit.Subject(nil), subjects...),
			audit.Subject{Kind: "WorkflowRolloutClosureVerifyPublicationPackage", Digest: digestBytes(manifestBytes)},
		)
		if err := persistOperationAuditForTarget(auditPath, "workflow.rollout-closure.verify.publication-package.export", "completed", manifest.Package.PackageState, "kubernetes:"+manifest.Package.Continuity.TargetDigest, exportSubjects, nil); err != nil {
			_ = os.Remove(manifestPath)
			writeServeError(writer, http.StatusInternalServerError, "YARA-AUD-005", err.Error())
			return
		}
		response := workflowRolloutClosureVerifyPublicationPackageExportResponse{Valid: true}
		response.Export.ManifestPath = manifestPath
		response.Export.AuditPath = auditPath
		response.Export.PackageState = manifest.Package.PackageState
		response.Export.BlockerCode = manifest.Package.BlockerCode
		writeServeJSON(writer, http.StatusOK, response)
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

type workflowCapsuleExportRequest struct {
	MarkdownPath                string `json:"markdownPath"`
	JSONPath                    string `json:"jsonPath"`
	AuditPath                   string `json:"auditPath"`
	AllowBlocked                bool   `json:"allowBlocked"`
	AllowBlockedReasonReference string `json:"allowBlockedReasonReference,omitempty"`
}

type workflowCapsuleExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		MarkdownPath    string `json:"markdownPath"`
		JSONPath        string `json:"jsonPath"`
		AuditPath       string `json:"auditPath"`
		Ready           bool   `json:"ready"`
		BlockedArchival bool   `json:"blockedArchival"`
		BlockerCount    int    `json:"blockerCount"`
	} `json:"export"`
}

type workflowEvidenceBundleExportRequest struct {
	ManifestPath string `json:"manifestPath"`
	AuditPath    string `json:"auditPath"`
}

type workflowEvidenceBundleExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath       string `json:"manifestPath"`
		AuditPath          string `json:"auditPath"`
		RunbookExportCount int    `json:"runbookExportCount"`
		CapsuleExportCount int    `json:"capsuleExportCount"`
	} `json:"export"`
}

type workflowEvidenceBundleManifest struct {
	Valid    bool `json:"valid"`
	Manifest struct {
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
		RunbookExports []workflowExportReference `json:"runbookExports"`
		CapsuleExports []workflowExportReference `json:"capsuleExports"`
	} `json:"manifest"`
}

type workflowExportReference struct {
	MarkdownPath string `json:"markdownPath"`
	JSONPath     string `json:"jsonPath"`
	MarkdownID   string `json:"markdownId"`
	JSONID       string `json:"jsonId"`
	Ready        bool   `json:"ready,omitempty"`
	Blockers     int    `json:"blockers,omitempty"`
}

type workflowReceiptTimelineResponse struct {
	Valid    bool `json:"valid"`
	Timeline struct {
		WorkspacePath string                           `json:"workspacePath"`
		Latest        workflowReceiptTimelineReceipt   `json:"latest"`
		Prior         []workflowReceiptTimelineReceipt `json:"prior"`
		Continuity    struct {
			AuthorizationID string `json:"authorizationId"`
			TargetDigest    string `json:"targetDigest"`
		} `json:"continuity"`
	} `json:"timeline"`
}

type workflowReceiptTimelineReceipt struct {
	ReceiptID       string `json:"receiptId"`
	Path            string `json:"path"`
	Outcome         string `json:"outcome"`
	StartedAt       string `json:"startedAt"`
	CompletedAt     string `json:"completedAt"`
	AuthorizationID string `json:"authorizationId"`
	TargetDigest    string `json:"targetDigest"`
}

type workflowReceiptTimelineExportRequest struct {
	MarkdownPath string `json:"markdownPath"`
	JSONPath     string `json:"jsonPath"`
	AuditPath    string `json:"auditPath"`
}

type workflowReceiptTimelineExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		MarkdownPath string `json:"markdownPath"`
		JSONPath     string `json:"jsonPath"`
		AuditPath    string `json:"auditPath"`
		ReceiptCount int    `json:"receiptCount"`
	} `json:"export"`
}

type workflowClosurePackageExportRequest struct {
	ManifestPath              string `json:"manifestPath"`
	AuditPath                 string `json:"auditPath"`
	ReleaseReadinessReference string `json:"releaseReadinessReference"`
}

type workflowClosurePackageExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath         string `json:"manifestPath"`
		AuditPath            string `json:"auditPath"`
		EvidenceBundleCount  int    `json:"evidenceBundleCount"`
		ReceiptTimelineCount int    `json:"receiptTimelineCount"`
	} `json:"export"`
}

type workflowClosurePackageManifest struct {
	Valid   bool `json:"valid"`
	Package struct {
		WorkspacePath             string                    `json:"workspacePath"`
		ReleaseReadinessReference string                    `json:"releaseReadinessReference"`
		Continuity                workflowClosureContinuity `json:"continuity"`
		EvidenceBundles           []workflowClosureArtifact `json:"evidenceBundles"`
		ReceiptTimelines          []workflowClosureArtifact `json:"receiptTimelines"`
		RunbookExports            []workflowExportReference `json:"runbookExports"`
		CapsuleExports            []workflowExportReference `json:"capsuleExports"`
	} `json:"closurePackage"`
}

type workflowClosureContinuity struct {
	AuthorizationID string `json:"authorizationId"`
	TargetDigest    string `json:"targetDigest"`
}

type workflowClosureArtifact struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type workflowClosureReviewGateResponse struct {
	Valid bool `json:"valid"`
	Gate  struct {
		ClosurePackagePath        string                    `json:"closurePackagePath"`
		ReleaseReadinessReference string                    `json:"releaseReadinessReference"`
		ReviewerReference         string                    `json:"reviewerReference"`
		Decision                  string                    `json:"decision"`
		Outcome                   string                    `json:"outcome"`
		BlockerCode               string                    `json:"blockerCode,omitempty"`
		Continuity                workflowClosureContinuity `json:"continuity"`
	} `json:"gate"`
}

type workflowClosureReviewGateExportRequest struct {
	ReleaseReadinessReference string `json:"releaseReadinessReference"`
	ReviewerReference         string `json:"reviewerReference"`
	Decision                  string `json:"decision"`
	MarkdownPath              string `json:"markdownPath"`
	JSONPath                  string `json:"jsonPath"`
	AuditPath                 string `json:"auditPath"`
}

type workflowClosureReviewGateExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		MarkdownPath string `json:"markdownPath"`
		JSONPath     string `json:"jsonPath"`
		AuditPath    string `json:"auditPath"`
		Outcome      string `json:"outcome"`
	} `json:"export"`
}

type workflowReleaseDecisionExportRequest struct {
	ReleaseReadinessReference string `json:"releaseReadinessReference"`
	ReviewerReference         string `json:"reviewerReference"`
	Decision                  string `json:"decision"`
	OperatorReference         string `json:"operatorReference"`
	DecisionTimestamp         string `json:"decisionTimestamp"`
	LedgerPath                string `json:"ledgerPath"`
	AuditPath                 string `json:"auditPath"`
}

type workflowReleaseDecisionExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		LedgerPath       string `json:"ledgerPath"`
		AuditPath        string `json:"auditPath"`
		PublicationState string `json:"publicationState"`
		BlockerCode      string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowReleaseDecisionLedger struct {
	Valid  bool `json:"valid"`
	Ledger struct {
		WorkspacePath             string                    `json:"workspacePath"`
		ReleaseReadinessReference string                    `json:"releaseReadinessReference"`
		ReviewerReference         string                    `json:"reviewerReference"`
		Decision                  string                    `json:"decision"`
		OperatorReference         string                    `json:"operatorReference"`
		DecisionTimestamp         string                    `json:"decisionTimestamp"`
		PublicationState          string                    `json:"publicationState"`
		BlockerCode               string                    `json:"blockerCode,omitempty"`
		Continuity                workflowClosureContinuity `json:"continuity"`
		ClosurePackage            workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                workflowClosureArtifact   `json:"reviewGate"`
	} `json:"releaseDecision"`
}

type workflowReleasePublicationExportRequest struct {
	PublicationChannel        string `json:"publicationChannel"`
	ArtifactLocationReference string `json:"artifactLocationReference"`
	PublicationTimestamp      string `json:"publicationTimestamp"`
	OperatorReference         string `json:"operatorReference"`
	AttestationPath           string `json:"attestationPath"`
	AuditPath                 string `json:"auditPath"`
}

type workflowReleasePublicationExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		AttestationPath  string `json:"attestationPath"`
		AuditPath        string `json:"auditPath"`
		PublicationState string `json:"publicationState"`
		BlockerCode      string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowReleasePublicationAttestation struct {
	Valid       bool `json:"valid"`
	Publication struct {
		WorkspacePath             string                    `json:"workspacePath"`
		ReleaseDecision           workflowClosureArtifact   `json:"releaseDecision"`
		ClosurePackage            workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                workflowClosureArtifact   `json:"reviewGate"`
		Continuity                workflowClosureContinuity `json:"continuity"`
		PublicationChannel        string                    `json:"publicationChannel"`
		ArtifactLocationReference string                    `json:"artifactLocationReference"`
		PublicationTimestamp      string                    `json:"publicationTimestamp"`
		OperatorReference         string                    `json:"operatorReference"`
		PublicationState          string                    `json:"publicationState"`
		BlockerCode               string                    `json:"blockerCode,omitempty"`
	} `json:"releasePublication"`
}

type workflowReleasePublicationIndexExportRequest struct {
	PublicationBatchReference string `json:"publicationBatchReference"`
	OperatorReference         string `json:"operatorReference"`
	ManifestPath              string `json:"manifestPath"`
	AuditPath                 string `json:"auditPath"`
}

type workflowReleasePublicationIndexExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath string `json:"manifestPath"`
		AuditPath    string `json:"auditPath"`
		IndexState   string `json:"indexState"`
		BlockerCode  string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowReleasePublicationIndexManifest struct {
	Valid bool `json:"valid"`
	Index struct {
		WorkspacePath             string                    `json:"workspacePath"`
		PublicationBatchReference string                    `json:"publicationBatchReference"`
		OperatorReference         string                    `json:"operatorReference"`
		IndexState                string                    `json:"indexState"`
		BlockerCode               string                    `json:"blockerCode,omitempty"`
		Continuity                workflowClosureContinuity `json:"continuity"`
		ClosurePackage            workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                workflowClosureArtifact   `json:"reviewGate"`
		ReleaseDecision           workflowClosureArtifact   `json:"releaseDecision"`
		ReleasePublication        workflowClosureArtifact   `json:"releasePublication"`
	} `json:"releasePublicationIndex"`
}

type workflowReleasePublicationPackageExportRequest struct {
	PackageReference           string `json:"packageReference"`
	PublicationWindowReference string `json:"publicationWindowReference"`
	OperatorReference          string `json:"operatorReference"`
	ManifestPath               string `json:"manifestPath"`
	AuditPath                  string `json:"auditPath"`
}

type workflowReleasePublicationPackageExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath string `json:"manifestPath"`
		AuditPath    string `json:"auditPath"`
		PackageState string `json:"packageState"`
		BlockerCode  string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowReleasePublicationPackageManifest struct {
	Valid   bool `json:"valid"`
	Package struct {
		WorkspacePath              string                    `json:"workspacePath"`
		PackageReference           string                    `json:"packageReference"`
		PublicationWindowReference string                    `json:"publicationWindowReference"`
		OperatorReference          string                    `json:"operatorReference"`
		PackageState               string                    `json:"packageState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
	} `json:"releasePublicationPackage"`
}

type workflowReleasePublicationEnvelopeExportRequest struct {
	DeliveryReference    string `json:"deliveryReference"`
	DestinationReference string `json:"destinationReference"`
	OperatorReference    string `json:"operatorReference"`
	ManifestPath         string `json:"manifestPath"`
	AuditPath            string `json:"auditPath"`
}

type workflowReleasePublicationEnvelopeExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath  string `json:"manifestPath"`
		AuditPath     string `json:"auditPath"`
		DeliveryState string `json:"deliveryState"`
		BlockerCode   string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowReleasePublicationEnvelopeManifest struct {
	Valid    bool `json:"valid"`
	Envelope struct {
		WorkspacePath             string                    `json:"workspacePath"`
		DeliveryReference         string                    `json:"deliveryReference"`
		DestinationReference      string                    `json:"destinationReference"`
		OperatorReference         string                    `json:"operatorReference"`
		DeliveryState             string                    `json:"deliveryState"`
		BlockerCode               string                    `json:"blockerCode,omitempty"`
		Continuity                workflowClosureContinuity `json:"continuity"`
		ClosurePackage            workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                workflowClosureArtifact   `json:"reviewGate"`
		ReleaseDecision           workflowClosureArtifact   `json:"releaseDecision"`
		ReleasePublication        workflowClosureArtifact   `json:"releasePublication"`
		ReleasePublicationIndex   workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublicationPackage workflowClosureArtifact   `json:"releasePublicationPackage"`
	} `json:"releasePublicationEnvelope"`
}

type workflowReleasePublicationHandoffReceiptExportRequest struct {
	ReceiverReference string `json:"receiverReference"`
	HandoffTimestamp  string `json:"handoffTimestamp"`
	OperatorReference string `json:"operatorReference"`
	ReceiptPath       string `json:"receiptPath"`
	AuditPath         string `json:"auditPath"`
}

type workflowReleasePublicationHandoffReceiptExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ReceiptPath  string `json:"receiptPath"`
		AuditPath    string `json:"auditPath"`
		HandoffState string `json:"handoffState"`
		BlockerCode  string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowReleasePublicationHandoffReceipt struct {
	Valid   bool `json:"valid"`
	Handoff struct {
		WorkspacePath              string                    `json:"workspacePath"`
		ReceiverReference          string                    `json:"receiverReference"`
		HandoffTimestamp           string                    `json:"handoffTimestamp"`
		OperatorReference          string                    `json:"operatorReference"`
		HandoffState               string                    `json:"handoffState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
	} `json:"releasePublicationHandoffReceipt"`
}

type workflowReleasePublicationAcknowledgmentExportRequest struct {
	AcknowledgmentReference string `json:"acknowledgmentReference"`
	AcknowledgedByReference string `json:"acknowledgedByReference"`
	AcknowledgmentTimestamp string `json:"acknowledgmentTimestamp"`
	ManifestPath            string `json:"manifestPath"`
	AuditPath               string `json:"auditPath"`
}

type workflowReleasePublicationAcknowledgmentExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath        string `json:"manifestPath"`
		AuditPath           string `json:"auditPath"`
		AcknowledgmentState string `json:"acknowledgmentState"`
		BlockerCode         string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowReleasePublicationAcknowledgmentManifest struct {
	Valid          bool `json:"valid"`
	Acknowledgment struct {
		WorkspacePath              string                    `json:"workspacePath"`
		AcknowledgmentReference    string                    `json:"acknowledgmentReference"`
		AcknowledgedByReference    string                    `json:"acknowledgedByReference"`
		AcknowledgmentTimestamp    string                    `json:"acknowledgmentTimestamp"`
		AcknowledgmentState        string                    `json:"acknowledgmentState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
		HandoffReceipt             workflowClosureArtifact   `json:"handoffReceipt"`
	} `json:"releasePublicationAcknowledgment"`
}

type workflowRolloutClosureSummaryExportRequest struct {
	SummaryReference  string `json:"summaryReference"`
	OperatorReference string `json:"operatorReference"`
	SummaryTimestamp  string `json:"summaryTimestamp"`
	ManifestPath      string `json:"manifestPath"`
	AuditPath         string `json:"auditPath"`
}

type workflowRolloutClosureSummaryExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath string `json:"manifestPath"`
		AuditPath    string `json:"auditPath"`
		SummaryState string `json:"summaryState"`
		BlockerCode  string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureSummaryManifest struct {
	Valid   bool `json:"valid"`
	Summary struct {
		WorkspacePath              string                    `json:"workspacePath"`
		SummaryReference           string                    `json:"summaryReference"`
		OperatorReference          string                    `json:"operatorReference"`
		SummaryTimestamp           string                    `json:"summaryTimestamp"`
		SummaryState               string                    `json:"summaryState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		CapsuleExport              workflowClosureArtifact   `json:"capsuleExport"`
		EvidenceBundle             workflowClosureArtifact   `json:"evidenceBundle"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
		HandoffReceipt             workflowClosureArtifact   `json:"handoffReceipt"`
		Acknowledgment             workflowClosureArtifact   `json:"acknowledgment"`
	} `json:"rolloutClosureSummary"`
}

type workflowRolloutClosureDeliveryExportRequest struct {
	DeliveryReference    string `json:"deliveryReference"`
	DestinationReference string `json:"destinationReference"`
	OperatorReference    string `json:"operatorReference"`
	DeliveryTimestamp    string `json:"deliveryTimestamp"`
	ManifestPath         string `json:"manifestPath"`
	AuditPath            string `json:"auditPath"`
}

type workflowRolloutClosureDeliveryExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath        string `json:"manifestPath"`
		AuditPath           string `json:"auditPath"`
		DeliveryRecordState string `json:"deliveryRecordState"`
		BlockerCode         string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureDeliveryManifest struct {
	Valid    bool `json:"valid"`
	Delivery struct {
		WorkspacePath              string                    `json:"workspacePath"`
		DeliveryReference          string                    `json:"deliveryReference"`
		DestinationReference       string                    `json:"destinationReference"`
		OperatorReference          string                    `json:"operatorReference"`
		DeliveryTimestamp          string                    `json:"deliveryTimestamp"`
		DeliveryRecordState        string                    `json:"deliveryRecordState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		ClosureSummary             workflowClosureArtifact   `json:"closureSummary"`
		Acknowledgment             workflowClosureArtifact   `json:"acknowledgment"`
		HandoffReceipt             workflowClosureArtifact   `json:"handoffReceipt"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
	} `json:"rolloutClosureDelivery"`
}

type workflowRolloutClosureAcceptanceExportRequest struct {
	AcceptanceReference string `json:"acceptanceReference"`
	AcceptedByReference string `json:"acceptedByReference"`
	AcceptanceTimestamp string `json:"acceptanceTimestamp"`
	ManifestPath        string `json:"manifestPath"`
	AuditPath           string `json:"auditPath"`
}

type workflowRolloutClosureAcceptanceExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath    string `json:"manifestPath"`
		AuditPath       string `json:"auditPath"`
		AcceptanceState string `json:"acceptanceState"`
		BlockerCode     string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureAcceptanceManifest struct {
	Valid      bool `json:"valid"`
	Acceptance struct {
		WorkspacePath              string                    `json:"workspacePath"`
		AcceptanceReference        string                    `json:"acceptanceReference"`
		AcceptedByReference        string                    `json:"acceptedByReference"`
		AcceptanceTimestamp        string                    `json:"acceptanceTimestamp"`
		AcceptanceState            string                    `json:"acceptanceState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		DeliveryRecord             workflowClosureArtifact   `json:"deliveryRecord"`
		ClosureSummary             workflowClosureArtifact   `json:"closureSummary"`
		Acknowledgment             workflowClosureArtifact   `json:"acknowledgment"`
		HandoffReceipt             workflowClosureArtifact   `json:"handoffReceipt"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
	} `json:"rolloutClosureAcceptance"`
}

type workflowRolloutClosureCertificateExportRequest struct {
	CertificateReference string `json:"certificateReference"`
	IssuedByReference    string `json:"issuedByReference"`
	IssuedTimestamp      string `json:"issuedTimestamp"`
	ManifestPath         string `json:"manifestPath"`
	AuditPath            string `json:"auditPath"`
}

type workflowRolloutClosureCertificateExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath     string `json:"manifestPath"`
		AuditPath        string `json:"auditPath"`
		CertificateState string `json:"certificateState"`
		BlockerCode      string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureCertificateManifest struct {
	Valid       bool `json:"valid"`
	Certificate struct {
		WorkspacePath              string                    `json:"workspacePath"`
		CertificateReference       string                    `json:"certificateReference"`
		IssuedByReference          string                    `json:"issuedByReference"`
		IssuedTimestamp            string                    `json:"issuedTimestamp"`
		CertificateState           string                    `json:"certificateState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		AcceptanceReceipt          workflowClosureArtifact   `json:"acceptanceReceipt"`
		DeliveryRecord             workflowClosureArtifact   `json:"deliveryRecord"`
		ClosureSummary             workflowClosureArtifact   `json:"closureSummary"`
		Acknowledgment             workflowClosureArtifact   `json:"acknowledgment"`
		HandoffReceipt             workflowClosureArtifact   `json:"handoffReceipt"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
	} `json:"rolloutClosureCertificate"`
}

type workflowRolloutClosureLedgerExportRequest struct {
	LedgerReference     string `json:"ledgerReference"`
	RecordedByReference string `json:"recordedByReference"`
	RecordedTimestamp   string `json:"recordedTimestamp"`
	ManifestPath        string `json:"manifestPath"`
	AuditPath           string `json:"auditPath"`
}

type workflowRolloutClosureLedgerExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath string `json:"manifestPath"`
		AuditPath    string `json:"auditPath"`
		LedgerState  string `json:"ledgerState"`
		BlockerCode  string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureLedgerManifest struct {
	Valid  bool `json:"valid"`
	Ledger struct {
		WorkspacePath              string                    `json:"workspacePath"`
		LedgerReference            string                    `json:"ledgerReference"`
		RecordedByReference        string                    `json:"recordedByReference"`
		RecordedTimestamp          string                    `json:"recordedTimestamp"`
		LedgerState                string                    `json:"ledgerState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		PublicationCertificate     workflowClosureArtifact   `json:"publicationCertificate"`
		AcceptanceReceipt          workflowClosureArtifact   `json:"acceptanceReceipt"`
		DeliveryRecord             workflowClosureArtifact   `json:"deliveryRecord"`
		ClosureSummary             workflowClosureArtifact   `json:"closureSummary"`
		Acknowledgment             workflowClosureArtifact   `json:"acknowledgment"`
		HandoffReceipt             workflowClosureArtifact   `json:"handoffReceipt"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
	} `json:"rolloutClosureLedger"`
}

type workflowRolloutClosureDocketExportRequest struct {
	DocketReference     string `json:"docketReference"`
	PreparedByReference string `json:"preparedByReference"`
	PreparedTimestamp   string `json:"preparedTimestamp"`
	ManifestPath        string `json:"manifestPath"`
	AuditPath           string `json:"auditPath"`
}

type workflowRolloutClosureDocketExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath string `json:"manifestPath"`
		AuditPath    string `json:"auditPath"`
		DocketState  string `json:"docketState"`
		BlockerCode  string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureDocketManifest struct {
	Valid  bool `json:"valid"`
	Docket struct {
		WorkspacePath              string                    `json:"workspacePath"`
		DocketReference            string                    `json:"docketReference"`
		PreparedByReference        string                    `json:"preparedByReference"`
		PreparedTimestamp          string                    `json:"preparedTimestamp"`
		DocketState                string                    `json:"docketState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		ArchivalLedger             workflowClosureArtifact   `json:"archivalLedger"`
		PublicationCertificate     workflowClosureArtifact   `json:"publicationCertificate"`
		AcceptanceReceipt          workflowClosureArtifact   `json:"acceptanceReceipt"`
		DeliveryRecord             workflowClosureArtifact   `json:"deliveryRecord"`
		ClosureSummary             workflowClosureArtifact   `json:"closureSummary"`
		Acknowledgment             workflowClosureArtifact   `json:"acknowledgment"`
		HandoffReceipt             workflowClosureArtifact   `json:"handoffReceipt"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
	} `json:"rolloutClosureDocket"`
}

type workflowRolloutClosureBulletinExportRequest struct {
	BulletinReference    string `json:"bulletinReference"`
	PublishedByReference string `json:"publishedByReference"`
	PublishedTimestamp   string `json:"publishedTimestamp"`
	ManifestPath         string `json:"manifestPath"`
	AuditPath            string `json:"auditPath"`
}

type workflowRolloutClosureBulletinExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath  string `json:"manifestPath"`
		AuditPath     string `json:"auditPath"`
		BulletinState string `json:"bulletinState"`
		BlockerCode   string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureBulletinManifest struct {
	Valid    bool `json:"valid"`
	Bulletin struct {
		WorkspacePath              string                    `json:"workspacePath"`
		BulletinReference          string                    `json:"bulletinReference"`
		PublishedByReference       string                    `json:"publishedByReference"`
		PublishedTimestamp         string                    `json:"publishedTimestamp"`
		BulletinState              string                    `json:"bulletinState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		HandoffDocket              workflowClosureArtifact   `json:"handoffDocket"`
		ArchivalLedger             workflowClosureArtifact   `json:"archivalLedger"`
		PublicationCertificate     workflowClosureArtifact   `json:"publicationCertificate"`
		AcceptanceReceipt          workflowClosureArtifact   `json:"acceptanceReceipt"`
		DeliveryRecord             workflowClosureArtifact   `json:"deliveryRecord"`
		ClosureSummary             workflowClosureArtifact   `json:"closureSummary"`
		Acknowledgment             workflowClosureArtifact   `json:"acknowledgment"`
		HandoffReceipt             workflowClosureArtifact   `json:"handoffReceipt"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
	} `json:"rolloutClosureBulletin"`
}

type workflowRolloutClosurePacketExportRequest struct {
	PacketReference     string `json:"packetReference"`
	PackagedByReference string `json:"packagedByReference"`
	PackagedTimestamp   string `json:"packagedTimestamp"`
	ManifestPath        string `json:"manifestPath"`
	AuditPath           string `json:"auditPath"`
}

type workflowRolloutClosurePacketExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath string `json:"manifestPath"`
		AuditPath    string `json:"auditPath"`
		PacketState  string `json:"packetState"`
		BlockerCode  string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosurePacketManifest struct {
	Valid  bool `json:"valid"`
	Packet struct {
		WorkspacePath              string                    `json:"workspacePath"`
		PacketReference            string                    `json:"packetReference"`
		PackagedByReference        string                    `json:"packagedByReference"`
		PackagedTimestamp          string                    `json:"packagedTimestamp"`
		PacketState                string                    `json:"packetState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		ReleaseBulletin            workflowClosureArtifact   `json:"releaseBulletin"`
		HandoffDocket              workflowClosureArtifact   `json:"handoffDocket"`
		ArchivalLedger             workflowClosureArtifact   `json:"archivalLedger"`
		PublicationCertificate     workflowClosureArtifact   `json:"publicationCertificate"`
		AcceptanceReceipt          workflowClosureArtifact   `json:"acceptanceReceipt"`
		DeliveryRecord             workflowClosureArtifact   `json:"deliveryRecord"`
		ClosureSummary             workflowClosureArtifact   `json:"closureSummary"`
		Acknowledgment             workflowClosureArtifact   `json:"acknowledgment"`
		HandoffReceipt             workflowClosureArtifact   `json:"handoffReceipt"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
	} `json:"rolloutClosurePacket"`
}

type workflowRolloutClosureRecipientPackageExportRequest struct {
	RecipientPackageReference string `json:"recipientPackageReference"`
	PreparedForReference      string `json:"preparedForReference"`
	PreparedTimestamp         string `json:"preparedTimestamp"`
	ManifestPath              string `json:"manifestPath"`
	AuditPath                 string `json:"auditPath"`
}

type workflowRolloutClosureRecipientPackageExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath          string `json:"manifestPath"`
		AuditPath             string `json:"auditPath"`
		RecipientPackageState string `json:"recipientPackageState"`
		BlockerCode           string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureRecipientPackageManifest struct {
	Valid            bool `json:"valid"`
	RecipientPackage struct {
		WorkspacePath              string                    `json:"workspacePath"`
		RecipientPackageReference  string                    `json:"recipientPackageReference"`
		PreparedForReference       string                    `json:"preparedForReference"`
		PreparedTimestamp          string                    `json:"preparedTimestamp"`
		RecipientPackageState      string                    `json:"recipientPackageState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		ReleasePacket              workflowClosureArtifact   `json:"releasePacket"`
		ReleaseBulletin            workflowClosureArtifact   `json:"releaseBulletin"`
		HandoffDocket              workflowClosureArtifact   `json:"handoffDocket"`
		ArchivalLedger             workflowClosureArtifact   `json:"archivalLedger"`
		PublicationCertificate     workflowClosureArtifact   `json:"publicationCertificate"`
		AcceptanceReceipt          workflowClosureArtifact   `json:"acceptanceReceipt"`
		DeliveryRecord             workflowClosureArtifact   `json:"deliveryRecord"`
		ClosureSummary             workflowClosureArtifact   `json:"closureSummary"`
		Acknowledgment             workflowClosureArtifact   `json:"acknowledgment"`
		HandoffReceipt             workflowClosureArtifact   `json:"handoffReceipt"`
		ReleasePublicationEnvelope workflowClosureArtifact   `json:"releasePublicationEnvelope"`
		ReleasePublicationPackage  workflowClosureArtifact   `json:"releasePublicationPackage"`
		ReleasePublicationIndex    workflowClosureArtifact   `json:"releasePublicationIndex"`
		ReleasePublication         workflowClosureArtifact   `json:"releasePublication"`
		ReleaseDecision            workflowClosureArtifact   `json:"releaseDecision"`
		ClosurePackage             workflowClosureArtifact   `json:"closurePackage"`
		ReviewGate                 workflowClosureArtifact   `json:"reviewGate"`
	} `json:"rolloutClosureRecipientPackage"`
}

type workflowRolloutClosureVerifyResponse struct {
	Valid        bool `json:"valid"`
	Verification struct {
		WorkspacePath     string                          `json:"workspacePath"`
		Ready             bool                            `json:"ready"`
		VerificationState string                          `json:"verificationState"`
		BlockerCode       string                          `json:"blockerCode,omitempty"`
		Continuity        workflowClosureContinuity       `json:"continuity"`
		Coverage          []workflowClosureVerifyCoverage `json:"coverage"`
		Diagnostics       []workflowCapsuleBlocker        `json:"diagnostics"`
	} `json:"verification"`
}

type workflowClosureVerifyCoverage struct {
	Artifact string `json:"artifact"`
	Status   string `json:"status"`
	Path     string `json:"path,omitempty"`
	Digest   string `json:"digest,omitempty"`
	State    string `json:"state,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type workflowRolloutClosureVerifyExportRequest struct {
	VerificationReference       string `json:"verificationReference"`
	OperatorReference           string `json:"operatorReference"`
	VerificationTimestamp       string `json:"verificationTimestamp"`
	MarkdownPath                string `json:"markdownPath"`
	JSONPath                    string `json:"jsonPath"`
	AuditPath                   string `json:"auditPath"`
	AllowBlocked                bool   `json:"allowBlocked"`
	AllowBlockedReasonReference string `json:"allowBlockedReasonReference,omitempty"`
}

type workflowRolloutClosureVerifyExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		MarkdownPath      string `json:"markdownPath"`
		JSONPath          string `json:"jsonPath"`
		AuditPath         string `json:"auditPath"`
		Ready             bool   `json:"ready"`
		BlockedArchival   bool   `json:"blockedArchival"`
		VerificationState string `json:"verificationState"`
		BlockerCode       string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureVerifyExportBundle struct {
	Valid  bool `json:"valid"`
	Export struct {
		WorkspacePath               string                          `json:"workspacePath"`
		VerificationReference       string                          `json:"verificationReference"`
		OperatorReference           string                          `json:"operatorReference"`
		VerificationTimestamp       string                          `json:"verificationTimestamp"`
		AllowBlocked                bool                            `json:"allowBlocked"`
		AllowBlockedReasonReference string                          `json:"allowBlockedReasonReference,omitempty"`
		Ready                       bool                            `json:"ready"`
		VerificationState           string                          `json:"verificationState"`
		BlockerCode                 string                          `json:"blockerCode,omitempty"`
		Continuity                  workflowClosureContinuity       `json:"continuity"`
		Coverage                    []workflowClosureVerifyCoverage `json:"coverage"`
		Diagnostics                 []workflowCapsuleBlocker        `json:"diagnostics"`
	} `json:"verificationExport"`
}

type workflowRolloutClosureVerifyAttestationExportRequest struct {
	AttestationReference string `json:"attestationReference"`
	AttestedByReference  string `json:"attestedByReference"`
	AttestationTimestamp string `json:"attestationTimestamp"`
	ManifestPath         string `json:"manifestPath"`
	AuditPath            string `json:"auditPath"`
}

type workflowRolloutClosureVerifyAttestationExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath     string `json:"manifestPath"`
		AuditPath        string `json:"auditPath"`
		AttestationState string `json:"attestationState"`
		BlockerCode      string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureVerifyAttestationManifest struct {
	Valid       bool `json:"valid"`
	Attestation struct {
		WorkspacePath         string                    `json:"workspacePath"`
		AttestationReference  string                    `json:"attestationReference"`
		AttestedByReference   string                    `json:"attestedByReference"`
		AttestationTimestamp  string                    `json:"attestationTimestamp"`
		AttestationState      string                    `json:"attestationState"`
		BlockerCode           string                    `json:"blockerCode,omitempty"`
		Continuity            workflowClosureContinuity `json:"continuity"`
		VerificationExport    workflowClosureArtifact   `json:"verificationExport"`
		VerificationMarkdown  workflowClosureArtifact   `json:"verificationMarkdown"`
		VerificationReference string                    `json:"verificationReference"`
		OperatorReference     string                    `json:"operatorReference"`
		VerificationTimestamp string                    `json:"verificationTimestamp"`
		VerificationState     string                    `json:"verificationState"`
		VerificationBlocker   string                    `json:"verificationBlockerCode,omitempty"`
	} `json:"rolloutClosureVerifyAttestation"`
}

type workflowRolloutClosureVerifyAttestationIndexExportRequest struct {
	AttestationIndexReference string `json:"attestationIndexReference"`
	PublishedByReference      string `json:"publishedByReference"`
	PublishedTimestamp        string `json:"publishedTimestamp"`
	ManifestPath              string `json:"manifestPath"`
	AuditPath                 string `json:"auditPath"`
}

type workflowRolloutClosureVerifyAttestationIndexExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath string `json:"manifestPath"`
		AuditPath    string `json:"auditPath"`
		IndexState   string `json:"indexState"`
		BlockerCode  string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureVerifyAttestationIndexManifest struct {
	Valid bool `json:"valid"`
	Index struct {
		WorkspacePath              string                    `json:"workspacePath"`
		AttestationIndexReference  string                    `json:"attestationIndexReference"`
		PublishedByReference       string                    `json:"publishedByReference"`
		PublishedTimestamp         string                    `json:"publishedTimestamp"`
		IndexState                 string                    `json:"indexState"`
		BlockerCode                string                    `json:"blockerCode,omitempty"`
		Continuity                 workflowClosureContinuity `json:"continuity"`
		VerificationAttestation    workflowClosureArtifact   `json:"verificationAttestation"`
		VerificationExportJSON     workflowClosureArtifact   `json:"verificationExportJson"`
		VerificationExportMarkdown workflowClosureArtifact   `json:"verificationExportMarkdown"`
		AttestationReference       string                    `json:"attestationReference"`
		AttestedByReference        string                    `json:"attestedByReference"`
		AttestationTimestamp       string                    `json:"attestationTimestamp"`
		VerificationReference      string                    `json:"verificationReference"`
		OperatorReference          string                    `json:"operatorReference"`
		VerificationTimestamp      string                    `json:"verificationTimestamp"`
	} `json:"rolloutClosureVerifyAttestationIndex"`
}

type workflowRolloutClosureVerifyPublicationPackageExportRequest struct {
	VerificationPackageReference string `json:"verificationPackageReference"`
	PackagedByReference          string `json:"packagedByReference"`
	PackagedTimestamp            string `json:"packagedTimestamp"`
	ManifestPath                 string `json:"manifestPath"`
	AuditPath                    string `json:"auditPath"`
}

type workflowRolloutClosureVerifyPublicationPackageExportResponse struct {
	Valid  bool `json:"valid"`
	Export struct {
		ManifestPath string `json:"manifestPath"`
		AuditPath    string `json:"auditPath"`
		PackageState string `json:"packageState"`
		BlockerCode  string `json:"blockerCode,omitempty"`
	} `json:"export"`
}

type workflowRolloutClosureVerifyPublicationPackageManifest struct {
	Valid   bool `json:"valid"`
	Package struct {
		WorkspacePath                string                    `json:"workspacePath"`
		VerificationPackageReference string                    `json:"verificationPackageReference"`
		PackagedByReference          string                    `json:"packagedByReference"`
		PackagedTimestamp            string                    `json:"packagedTimestamp"`
		PackageState                 string                    `json:"packageState"`
		BlockerCode                  string                    `json:"blockerCode,omitempty"`
		Continuity                   workflowClosureContinuity `json:"continuity"`
		VerificationAttestationIndex workflowClosureArtifact   `json:"verificationAttestationIndex"`
		VerificationAttestation      workflowClosureArtifact   `json:"verificationAttestation"`
		VerificationExportJSON       workflowClosureArtifact   `json:"verificationExportJson"`
		VerificationExportMarkdown   workflowClosureArtifact   `json:"verificationExportMarkdown"`
		AttestationIndexReference    string                    `json:"attestationIndexReference"`
		PublishedByReference         string                    `json:"publishedByReference"`
		PublishedTimestamp           string                    `json:"publishedTimestamp"`
		AttestationReference         string                    `json:"attestationReference"`
		VerificationReference        string                    `json:"verificationReference"`
		OperatorReference            string                    `json:"operatorReference"`
		VerificationTimestamp        string                    `json:"verificationTimestamp"`
	} `json:"rolloutClosureVerifyPublicationPackage"`
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
			if stageID == "receipt" {
				// Keep the first deterministic match for pipeline stage status;
				// receipt timeline endpoints enumerate all receipt artifacts.
				_ = existing
				continue
			}
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

func decodeWorkflowCapsuleExportRequest(request *http.Request) (workflowCapsuleExportRequest, error) {
	var payload workflowCapsuleExportRequest
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
	if payload.AllowBlocked && strings.TrimSpace(payload.AllowBlockedReasonReference) == "" {
		return payload, errors.New("allowBlockedReasonReference is required when allowBlocked=true")
	}
	return payload, nil
}

func decodeWorkflowEvidenceBundleExportRequest(request *http.Request) (workflowEvidenceBundleExportRequest, error) {
	var payload workflowEvidenceBundleExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	return payload, nil
}

func decodeWorkflowReceiptTimelineExportRequest(request *http.Request) (workflowReceiptTimelineExportRequest, error) {
	var payload workflowReceiptTimelineExportRequest
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

func decodeWorkflowClosurePackageExportRequest(request *http.Request) (workflowClosurePackageExportRequest, error) {
	var payload workflowClosurePackageExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" || strings.TrimSpace(payload.ReleaseReadinessReference) == "" {
		return payload, errors.New("manifestPath, auditPath and releaseReadinessReference are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	return payload, nil
}

func decodeWorkflowClosureReviewGateExportRequest(request *http.Request) (workflowClosureReviewGateExportRequest, error) {
	var payload workflowClosureReviewGateExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.ReleaseReadinessReference) == "" || strings.TrimSpace(payload.ReviewerReference) == "" || strings.TrimSpace(payload.Decision) == "" || strings.TrimSpace(payload.MarkdownPath) == "" || strings.TrimSpace(payload.JSONPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("releaseReadinessReference, reviewerReference, decision, markdownPath, jsonPath and auditPath are required")
	}
	if payload.MarkdownPath == payload.JSONPath || payload.MarkdownPath == payload.AuditPath || payload.JSONPath == payload.AuditPath {
		return payload, errors.New("markdownPath, jsonPath and auditPath must be different files")
	}
	return payload, nil
}

func decodeWorkflowReleaseDecisionExportRequest(request *http.Request) (workflowReleaseDecisionExportRequest, error) {
	var payload workflowReleaseDecisionExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.ReleaseReadinessReference) == "" || strings.TrimSpace(payload.ReviewerReference) == "" || strings.TrimSpace(payload.Decision) == "" || strings.TrimSpace(payload.OperatorReference) == "" || strings.TrimSpace(payload.DecisionTimestamp) == "" || strings.TrimSpace(payload.LedgerPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("releaseReadinessReference, reviewerReference, decision, operatorReference, decisionTimestamp, ledgerPath and auditPath are required")
	}
	if payload.LedgerPath == payload.AuditPath {
		return payload, errors.New("ledgerPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.DecisionTimestamp); err != nil {
		return payload, errors.New("decisionTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowReleasePublicationExportRequest(request *http.Request) (workflowReleasePublicationExportRequest, error) {
	var payload workflowReleasePublicationExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.PublicationChannel) == "" || strings.TrimSpace(payload.ArtifactLocationReference) == "" || strings.TrimSpace(payload.PublicationTimestamp) == "" || strings.TrimSpace(payload.OperatorReference) == "" || strings.TrimSpace(payload.AttestationPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("publicationChannel, artifactLocationReference, publicationTimestamp, operatorReference, attestationPath and auditPath are required")
	}
	if payload.AttestationPath == payload.AuditPath {
		return payload, errors.New("attestationPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.PublicationTimestamp); err != nil {
		return payload, errors.New("publicationTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowReleasePublicationIndexExportRequest(request *http.Request) (workflowReleasePublicationIndexExportRequest, error) {
	var payload workflowReleasePublicationIndexExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.PublicationBatchReference) == "" || strings.TrimSpace(payload.OperatorReference) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("publicationBatchReference, operatorReference, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	return payload, nil
}

func decodeWorkflowReleasePublicationPackageExportRequest(request *http.Request) (workflowReleasePublicationPackageExportRequest, error) {
	var payload workflowReleasePublicationPackageExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.PackageReference) == "" || strings.TrimSpace(payload.PublicationWindowReference) == "" || strings.TrimSpace(payload.OperatorReference) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("packageReference, publicationWindowReference, operatorReference, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	return payload, nil
}

func decodeWorkflowReleasePublicationEnvelopeExportRequest(request *http.Request) (workflowReleasePublicationEnvelopeExportRequest, error) {
	var payload workflowReleasePublicationEnvelopeExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.DeliveryReference) == "" || strings.TrimSpace(payload.DestinationReference) == "" || strings.TrimSpace(payload.OperatorReference) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("deliveryReference, destinationReference, operatorReference, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	return payload, nil
}

func decodeWorkflowReleasePublicationHandoffReceiptExportRequest(request *http.Request) (workflowReleasePublicationHandoffReceiptExportRequest, error) {
	var payload workflowReleasePublicationHandoffReceiptExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.ReceiverReference) == "" || strings.TrimSpace(payload.HandoffTimestamp) == "" || strings.TrimSpace(payload.OperatorReference) == "" || strings.TrimSpace(payload.ReceiptPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("receiverReference, handoffTimestamp, operatorReference, receiptPath and auditPath are required")
	}
	if payload.ReceiptPath == payload.AuditPath {
		return payload, errors.New("receiptPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.HandoffTimestamp); err != nil {
		return payload, errors.New("handoffTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowReleasePublicationAcknowledgmentExportRequest(request *http.Request) (workflowReleasePublicationAcknowledgmentExportRequest, error) {
	var payload workflowReleasePublicationAcknowledgmentExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.AcknowledgmentReference) == "" || strings.TrimSpace(payload.AcknowledgedByReference) == "" || strings.TrimSpace(payload.AcknowledgmentTimestamp) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("acknowledgmentReference, acknowledgedByReference, acknowledgmentTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.AcknowledgmentTimestamp); err != nil {
		return payload, errors.New("acknowledgmentTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureSummaryExportRequest(request *http.Request) (workflowRolloutClosureSummaryExportRequest, error) {
	var payload workflowRolloutClosureSummaryExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.SummaryReference) == "" || strings.TrimSpace(payload.OperatorReference) == "" || strings.TrimSpace(payload.SummaryTimestamp) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("summaryReference, operatorReference, summaryTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.SummaryTimestamp); err != nil {
		return payload, errors.New("summaryTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureDeliveryExportRequest(request *http.Request) (workflowRolloutClosureDeliveryExportRequest, error) {
	var payload workflowRolloutClosureDeliveryExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.DeliveryReference) == "" || strings.TrimSpace(payload.DestinationReference) == "" || strings.TrimSpace(payload.OperatorReference) == "" || strings.TrimSpace(payload.DeliveryTimestamp) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("deliveryReference, destinationReference, operatorReference, deliveryTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.DeliveryTimestamp); err != nil {
		return payload, errors.New("deliveryTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureAcceptanceExportRequest(request *http.Request) (workflowRolloutClosureAcceptanceExportRequest, error) {
	var payload workflowRolloutClosureAcceptanceExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.AcceptanceReference) == "" || strings.TrimSpace(payload.AcceptedByReference) == "" || strings.TrimSpace(payload.AcceptanceTimestamp) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("acceptanceReference, acceptedByReference, acceptanceTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.AcceptanceTimestamp); err != nil {
		return payload, errors.New("acceptanceTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureCertificateExportRequest(request *http.Request) (workflowRolloutClosureCertificateExportRequest, error) {
	var payload workflowRolloutClosureCertificateExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.CertificateReference) == "" || strings.TrimSpace(payload.IssuedByReference) == "" || strings.TrimSpace(payload.IssuedTimestamp) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("certificateReference, issuedByReference, issuedTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.IssuedTimestamp); err != nil {
		return payload, errors.New("issuedTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureLedgerExportRequest(request *http.Request) (workflowRolloutClosureLedgerExportRequest, error) {
	var payload workflowRolloutClosureLedgerExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.LedgerReference) == "" || strings.TrimSpace(payload.RecordedByReference) == "" || strings.TrimSpace(payload.RecordedTimestamp) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("ledgerReference, recordedByReference, recordedTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.RecordedTimestamp); err != nil {
		return payload, errors.New("recordedTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureDocketExportRequest(request *http.Request) (workflowRolloutClosureDocketExportRequest, error) {
	var payload workflowRolloutClosureDocketExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.DocketReference) == "" || strings.TrimSpace(payload.PreparedByReference) == "" || strings.TrimSpace(payload.PreparedTimestamp) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("docketReference, preparedByReference, preparedTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.PreparedTimestamp); err != nil {
		return payload, errors.New("preparedTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureBulletinExportRequest(request *http.Request) (workflowRolloutClosureBulletinExportRequest, error) {
	var payload workflowRolloutClosureBulletinExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.BulletinReference) == "" || strings.TrimSpace(payload.PublishedByReference) == "" || strings.TrimSpace(payload.PublishedTimestamp) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("bulletinReference, publishedByReference, publishedTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.PublishedTimestamp); err != nil {
		return payload, errors.New("publishedTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosurePacketExportRequest(request *http.Request) (workflowRolloutClosurePacketExportRequest, error) {
	var payload workflowRolloutClosurePacketExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.PacketReference) == "" || strings.TrimSpace(payload.PackagedByReference) == "" || strings.TrimSpace(payload.PackagedTimestamp) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("packetReference, packagedByReference, packagedTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.PackagedTimestamp); err != nil {
		return payload, errors.New("packagedTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureRecipientPackageExportRequest(request *http.Request) (workflowRolloutClosureRecipientPackageExportRequest, error) {
	var payload workflowRolloutClosureRecipientPackageExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.RecipientPackageReference) == "" || strings.TrimSpace(payload.PreparedForReference) == "" || strings.TrimSpace(payload.PreparedTimestamp) == "" || strings.TrimSpace(payload.ManifestPath) == "" || strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("recipientPackageReference, preparedForReference, preparedTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.PreparedTimestamp); err != nil {
		return payload, errors.New("preparedTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureVerifyExportRequest(request *http.Request) (workflowRolloutClosureVerifyExportRequest, error) {
	var payload workflowRolloutClosureVerifyExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.VerificationReference) == "" ||
		strings.TrimSpace(payload.OperatorReference) == "" ||
		strings.TrimSpace(payload.VerificationTimestamp) == "" ||
		strings.TrimSpace(payload.MarkdownPath) == "" ||
		strings.TrimSpace(payload.JSONPath) == "" ||
		strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("verificationReference, operatorReference, verificationTimestamp, markdownPath, jsonPath and auditPath are required")
	}
	if payload.MarkdownPath == payload.JSONPath || payload.MarkdownPath == payload.AuditPath || payload.JSONPath == payload.AuditPath {
		return payload, errors.New("markdownPath, jsonPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.VerificationTimestamp); err != nil {
		return payload, errors.New("verificationTimestamp must be a valid RFC3339 timestamp")
	}
	if payload.AllowBlocked && strings.TrimSpace(payload.AllowBlockedReasonReference) == "" {
		return payload, errors.New("allowBlockedReasonReference is required when allowBlocked=true")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureVerifyAttestationExportRequest(request *http.Request) (workflowRolloutClosureVerifyAttestationExportRequest, error) {
	var payload workflowRolloutClosureVerifyAttestationExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.AttestationReference) == "" ||
		strings.TrimSpace(payload.AttestedByReference) == "" ||
		strings.TrimSpace(payload.AttestationTimestamp) == "" ||
		strings.TrimSpace(payload.ManifestPath) == "" ||
		strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("attestationReference, attestedByReference, attestationTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.AttestationTimestamp); err != nil {
		return payload, errors.New("attestationTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureVerifyAttestationIndexExportRequest(request *http.Request) (workflowRolloutClosureVerifyAttestationIndexExportRequest, error) {
	var payload workflowRolloutClosureVerifyAttestationIndexExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.AttestationIndexReference) == "" ||
		strings.TrimSpace(payload.PublishedByReference) == "" ||
		strings.TrimSpace(payload.PublishedTimestamp) == "" ||
		strings.TrimSpace(payload.ManifestPath) == "" ||
		strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("attestationIndexReference, publishedByReference, publishedTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.PublishedTimestamp); err != nil {
		return payload, errors.New("publishedTimestamp must be a valid RFC3339 timestamp")
	}
	return payload, nil
}

func decodeWorkflowRolloutClosureVerifyPublicationPackageExportRequest(request *http.Request) (workflowRolloutClosureVerifyPublicationPackageExportRequest, error) {
	var payload workflowRolloutClosureVerifyPublicationPackageExportRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("decode request body: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return payload, errors.New("request body must contain exactly one JSON object")
	}
	if strings.TrimSpace(payload.VerificationPackageReference) == "" ||
		strings.TrimSpace(payload.PackagedByReference) == "" ||
		strings.TrimSpace(payload.PackagedTimestamp) == "" ||
		strings.TrimSpace(payload.ManifestPath) == "" ||
		strings.TrimSpace(payload.AuditPath) == "" {
		return payload, errors.New("verificationPackageReference, packagedByReference, packagedTimestamp, manifestPath and auditPath are required")
	}
	if payload.ManifestPath == payload.AuditPath {
		return payload, errors.New("manifestPath and auditPath must be different files")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.PackagedTimestamp); err != nil {
		return payload, errors.New("packagedTimestamp must be a valid RFC3339 timestamp")
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

func buildWorkflowCapsule(workspacePath string) (workflowCapsuleResponse, []audit.Subject, error) {
	stages, err := workspacePipelineStages(workspacePath)
	if err != nil {
		return workflowCapsuleResponse{}, nil, err
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
	subjects := []audit.Subject{}
	if !capsule.Capsule.Ready {
		return capsule, subjects, nil
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
		return capsule, subjects, nil
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
		return capsule, subjects, nil
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
		return capsule, subjects, nil
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
		return capsule, subjects, nil
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
		return capsule, subjects, nil
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
		return capsule, subjects, nil
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
	subjects = []audit.Subject{
		{Kind: "PlatformPlan", Digest: plan.Metadata.PlanID},
		{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID},
		{Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID},
		{Kind: "KubernetesChangeSet", Digest: changeSet.Metadata.ChangeSetID},
		{Kind: "DeploymentApproval", Digest: approval.Metadata.ApprovalID},
		{Kind: "ExecutionAuthorization", Digest: authorization.Metadata.AuthorizationID},
	}
	return capsule, subjects, nil
}

func buildWorkflowEvidenceBundleManifest(workspacePath string) (workflowEvidenceBundleManifest, []audit.Subject, error) {
	runbook, runbookSubjects, err := buildWorkflowRunbook(workspacePath)
	if err != nil {
		return workflowEvidenceBundleManifest{}, nil, fmt.Errorf("build runbook evidence chain: %w", err)
	}
	capsule, capsuleSubjects, err := buildWorkflowCapsule(workspacePath)
	if err != nil {
		return workflowEvidenceBundleManifest{}, nil, fmt.Errorf("build capsule readiness chain: %w", err)
	}
	runbookMarkdownPaths, runbookJSONPaths := discoverRunbookExports(workspacePath)
	capsuleMarkdownPaths, capsuleJSONPaths := discoverCapsuleExports(workspacePath)
	if len(runbookMarkdownPaths) == 0 || len(runbookJSONPaths) == 0 {
		return workflowEvidenceBundleManifest{}, nil, errors.New("evidence bundle requires runbook markdown and json exports in workspace")
	}
	if len(capsuleMarkdownPaths) == 0 || len(capsuleJSONPaths) == 0 {
		return workflowEvidenceBundleManifest{}, nil, errors.New("evidence bundle requires capsule markdown and json exports in workspace")
	}
	runbookRefs, runbookRefSubjects, err := collectRunbookExportReferences(runbook, runbookMarkdownPaths, runbookJSONPaths)
	if err != nil {
		return workflowEvidenceBundleManifest{}, nil, err
	}
	capsuleRefs, capsuleRefSubjects, err := collectCapsuleExportReferences(capsule, capsuleMarkdownPaths, capsuleJSONPaths)
	if err != nil {
		return workflowEvidenceBundleManifest{}, nil, err
	}
	manifest := workflowEvidenceBundleManifest{Valid: true}
	manifest.Manifest.WorkspacePath = workspacePath
	manifest.Manifest.Artifacts.PlanPath = runbook.Runbook.Artifacts.PlanPath
	manifest.Manifest.Artifacts.BundlePath = runbook.Runbook.Artifacts.BundlePath
	manifest.Manifest.Artifacts.PreflightPath = runbook.Runbook.Artifacts.PreflightPath
	manifest.Manifest.Artifacts.ChangeSetPath = runbook.Runbook.Artifacts.ChangeSetPath
	manifest.Manifest.Artifacts.ApprovalPath = runbook.Runbook.Artifacts.ApprovalPath
	manifest.Manifest.Artifacts.AuthorizationPath = runbook.Runbook.Artifacts.AuthorizationPath
	manifest.Manifest.Evidence.PlanID = runbook.Runbook.Evidence.PlanID
	manifest.Manifest.Evidence.BundleID = runbook.Runbook.Evidence.BundleID
	manifest.Manifest.Evidence.PreflightResultID = runbook.Runbook.Evidence.PreflightResultID
	manifest.Manifest.Evidence.ChangeSetID = runbook.Runbook.Evidence.ChangeSetID
	manifest.Manifest.Evidence.ApprovalID = runbook.Runbook.Evidence.ApprovalID
	manifest.Manifest.Evidence.AuthorizationID = runbook.Runbook.Evidence.AuthorizationID
	manifest.Manifest.Evidence.TargetReferenceDigest = runbook.Runbook.Evidence.TargetReferenceDigest
	manifest.Manifest.RunbookExports = runbookRefs
	manifest.Manifest.CapsuleExports = capsuleRefs
	subjects := append([]audit.Subject{}, runbookSubjects...)
	subjects = append(subjects, capsuleSubjects...)
	subjects = append(subjects, runbookRefSubjects...)
	subjects = append(subjects, capsuleRefSubjects...)
	return manifest, subjects, nil
}

type deploymentReceiptFile struct {
	Path      string
	Receipt   resources.DeploymentReceipt
	Completed time.Time
}

func buildWorkflowReceiptTimeline(workspacePath string) (workflowReceiptTimelineResponse, []audit.Subject, error) {
	stageLookup, receiptPaths, err := workflowCoreArtifacts(workspacePath)
	if err != nil {
		return workflowReceiptTimelineResponse{}, nil, err
	}
	authorizationPath, ok := stageLookup["authorization"]
	if !ok {
		return workflowReceiptTimelineResponse{}, nil, errors.New("receipt timeline requires authorization artifact in workspace")
	}
	authorization, err := resources.LoadExecutionAuthorization(authorizationPath)
	if err != nil || !authorization.Validate().Valid {
		return workflowReceiptTimelineResponse{}, nil, errors.New("workspace authorization artifact is invalid")
	}
	receipts, err := loadDeploymentReceipts(receiptPaths)
	if err != nil {
		return workflowReceiptTimelineResponse{}, nil, err
	}
	if len(receipts) == 0 {
		return workflowReceiptTimelineResponse{}, nil, errors.New("receipt timeline requires at least one deployment receipt in workspace")
	}
	for _, item := range receipts {
		if item.Receipt.Spec.AuthorizationID != authorization.Metadata.AuthorizationID {
			return workflowReceiptTimelineResponse{}, nil, fmt.Errorf("receipt %s authorization binding does not match workspace authorization", filepath.Base(item.Path))
		}
		if item.Receipt.Spec.Target.ReferenceDigest != authorization.Spec.Target.ReferenceDigest {
			return workflowReceiptTimelineResponse{}, nil, fmt.Errorf("receipt %s target digest diverges from workspace authorization", filepath.Base(item.Path))
		}
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].Completed.Equal(receipts[j].Completed) {
			return receipts[i].Receipt.Metadata.ReceiptID > receipts[j].Receipt.Metadata.ReceiptID
		}
		return receipts[i].Completed.After(receipts[j].Completed)
	})
	timeline := workflowReceiptTimelineResponse{Valid: true}
	timeline.Timeline.WorkspacePath = workspacePath
	timeline.Timeline.Continuity.AuthorizationID = authorization.Metadata.AuthorizationID
	timeline.Timeline.Continuity.TargetDigest = authorization.Spec.Target.ReferenceDigest
	timeline.Timeline.Latest = toWorkflowTimelineReceipt(receipts[0])
	timeline.Timeline.Prior = make([]workflowReceiptTimelineReceipt, 0, len(receipts)-1)
	subjects := []audit.Subject{
		{Kind: "ExecutionAuthorization", Digest: authorization.Metadata.AuthorizationID},
	}
	subjects = append(subjects, audit.Subject{Kind: "DeploymentReceipt", Digest: receipts[0].Receipt.Metadata.ReceiptID})
	for _, item := range receipts[1:] {
		timeline.Timeline.Prior = append(timeline.Timeline.Prior, toWorkflowTimelineReceipt(item))
		subjects = append(subjects, audit.Subject{Kind: "DeploymentReceipt", Digest: item.Receipt.Metadata.ReceiptID})
	}
	return timeline, subjects, nil
}

func buildWorkflowClosurePackageManifest(workspacePath, releaseReadinessReference string) (workflowClosurePackageManifest, []audit.Subject, error) {
	evidenceBundles, evidenceSubjects, evidenceSummary, err := collectEvidenceBundleArtifacts(workspacePath)
	if err != nil {
		return workflowClosurePackageManifest{}, nil, err
	}
	receiptTimelines, timelineSubjects, timelineSummary, err := collectReceiptTimelineArtifacts(workspacePath)
	if err != nil {
		return workflowClosurePackageManifest{}, nil, err
	}
	if evidenceSummary.AuthorizationID != timelineSummary.AuthorizationID {
		return workflowClosurePackageManifest{}, nil, errors.New("YARA-CLS-003: evidence bundle and receipt timeline authorization continuity is mismatched")
	}
	if evidenceSummary.TargetDigest != timelineSummary.TargetDigest {
		return workflowClosurePackageManifest{}, nil, errors.New("YARA-CLS-004: evidence bundle and receipt timeline target digest continuity is mismatched")
	}
	manifest := workflowClosurePackageManifest{Valid: true}
	manifest.Package.WorkspacePath = workspacePath
	manifest.Package.ReleaseReadinessReference = releaseReadinessReference
	manifest.Package.Continuity.AuthorizationID = evidenceSummary.AuthorizationID
	manifest.Package.Continuity.TargetDigest = evidenceSummary.TargetDigest
	manifest.Package.EvidenceBundles = evidenceBundles
	manifest.Package.ReceiptTimelines = receiptTimelines
	manifest.Package.RunbookExports = evidenceSummary.RunbookExports
	manifest.Package.CapsuleExports = evidenceSummary.CapsuleExports
	subjects := append([]audit.Subject{}, evidenceSubjects...)
	subjects = append(subjects, timelineSubjects...)
	return manifest, subjects, nil
}

type evidenceBundleSummary struct {
	AuthorizationID string
	TargetDigest    string
	RunbookExports  []workflowExportReference
	CapsuleExports  []workflowExportReference
}

func collectEvidenceBundleArtifacts(workspacePath string) ([]workflowClosureArtifact, []audit.Subject, evidenceBundleSummary, error) {
	paths := discoverEvidenceBundleExports(workspacePath)
	if len(paths) == 0 {
		return nil, nil, evidenceBundleSummary{}, errors.New("YARA-CLS-001: closure package requires at least one evidence bundle export")
	}
	artifacts := make([]workflowClosureArtifact, 0, len(paths))
	subjects := make([]audit.Subject, 0, len(paths))
	summary := evidenceBundleSummary{}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, evidenceBundleSummary{}, fmt.Errorf("read evidence bundle export %s: %w", filepath.Base(path), err)
		}
		manifest := workflowEvidenceBundleManifest{}
		if err := json.Unmarshal(content, &manifest); err != nil {
			return nil, nil, evidenceBundleSummary{}, fmt.Errorf("decode evidence bundle export %s: %w", filepath.Base(path), err)
		}
		if !manifest.Valid {
			return nil, nil, evidenceBundleSummary{}, fmt.Errorf("YARA-CLS-002: evidence bundle export %s is invalid", filepath.Base(path))
		}
		if summary.AuthorizationID == "" {
			summary.AuthorizationID = manifest.Manifest.Evidence.AuthorizationID
			summary.TargetDigest = manifest.Manifest.Evidence.TargetReferenceDigest
			summary.RunbookExports = append([]workflowExportReference(nil), manifest.Manifest.RunbookExports...)
			summary.CapsuleExports = append([]workflowExportReference(nil), manifest.Manifest.CapsuleExports...)
		} else if summary.AuthorizationID != manifest.Manifest.Evidence.AuthorizationID || summary.TargetDigest != manifest.Manifest.Evidence.TargetReferenceDigest {
			return nil, nil, evidenceBundleSummary{}, errors.New("YARA-CLS-003: evidence bundle exports are not bound to one authorization/target continuity chain")
		}
		artifacts = append(artifacts, workflowClosureArtifact{
			Path:   path,
			Digest: digestBytes(content),
		})
		subjects = append(subjects, audit.Subject{
			Kind:   "WorkflowEvidenceBundleManifest",
			Digest: digestBytes(content),
		})
	}
	return artifacts, subjects, summary, nil
}

type receiptTimelineSummary struct {
	AuthorizationID string
	TargetDigest    string
}

type workflowGateError struct {
	Status int
	Err    string
}

func (e workflowGateError) Error() string {
	return e.Err
}

func collectReceiptTimelineArtifacts(workspacePath string) ([]workflowClosureArtifact, []audit.Subject, receiptTimelineSummary, error) {
	markdownPaths, jsonPaths := discoverReceiptTimelineExports(workspacePath)
	if len(markdownPaths) == 0 || len(jsonPaths) == 0 {
		return nil, nil, receiptTimelineSummary{}, errors.New("YARA-CLS-005: closure package requires receipt timeline markdown and json exports")
	}
	jsonSet := map[string]struct{}{}
	for _, path := range jsonPaths {
		jsonSet[path] = struct{}{}
	}
	artifacts := make([]workflowClosureArtifact, 0, len(markdownPaths)+len(jsonPaths))
	subjects := make([]audit.Subject, 0, len(markdownPaths)+len(jsonPaths))
	summary := receiptTimelineSummary{}
	for _, markdownPath := range markdownPaths {
		base := strings.TrimSuffix(markdownPath, ".receipt-timeline.md")
		jsonPath := base + ".receipt-timeline.json"
		if _, ok := jsonSet[jsonPath]; !ok {
			return nil, nil, receiptTimelineSummary{}, fmt.Errorf("YARA-CLS-006: missing paired receipt timeline json for %s", filepath.Base(markdownPath))
		}
		markdownBytes, err := os.ReadFile(markdownPath)
		if err != nil {
			return nil, nil, receiptTimelineSummary{}, fmt.Errorf("read receipt timeline markdown %s: %w", filepath.Base(markdownPath), err)
		}
		jsonBytes, err := os.ReadFile(jsonPath)
		if err != nil {
			return nil, nil, receiptTimelineSummary{}, fmt.Errorf("read receipt timeline json %s: %w", filepath.Base(jsonPath), err)
		}
		timeline := workflowReceiptTimelineResponse{}
		if err := json.Unmarshal(jsonBytes, &timeline); err != nil {
			return nil, nil, receiptTimelineSummary{}, fmt.Errorf("decode receipt timeline json %s: %w", filepath.Base(jsonPath), err)
		}
		if !timeline.Valid {
			return nil, nil, receiptTimelineSummary{}, fmt.Errorf("YARA-CLS-007: receipt timeline export %s is invalid", filepath.Base(jsonPath))
		}
		if summary.AuthorizationID == "" {
			summary.AuthorizationID = timeline.Timeline.Continuity.AuthorizationID
			summary.TargetDigest = timeline.Timeline.Continuity.TargetDigest
		} else if summary.AuthorizationID != timeline.Timeline.Continuity.AuthorizationID || summary.TargetDigest != timeline.Timeline.Continuity.TargetDigest {
			return nil, nil, receiptTimelineSummary{}, errors.New("YARA-CLS-008: receipt timeline exports are not bound to one authorization/target continuity chain")
		}
		artifacts = append(artifacts,
			workflowClosureArtifact{Path: markdownPath, Digest: digestBytes(markdownBytes)},
			workflowClosureArtifact{Path: jsonPath, Digest: digestBytes(jsonBytes)},
		)
		subjects = append(subjects,
			audit.Subject{Kind: "ReceiptTimelineMarkdown", Digest: digestBytes(markdownBytes)},
			audit.Subject{Kind: "ReceiptTimelineJSON", Digest: digestBytes(jsonBytes)},
		)
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	return artifacts, subjects, summary, nil
}

func evaluateWorkflowClosureReviewGate(workspacePath, releaseReadinessReference, reviewerReference, decision string) (workflowClosureReviewGateResponse, []audit.Subject, error) {
	releaseReadinessReference = strings.TrimSpace(releaseReadinessReference)
	reviewerReference = strings.TrimSpace(reviewerReference)
	decision = strings.TrimSpace(decision)
	if releaseReadinessReference == "" || reviewerReference == "" || decision == "" {
		return workflowClosureReviewGateResponse{}, nil, workflowGateError{Status: http.StatusBadRequest, Err: "releaseReadinessReference, reviewerReference and decision are required"}
	}
	normalizedDecision, err := normalizeReviewGateDecision(decision)
	if err != nil {
		return workflowClosureReviewGateResponse{}, nil, workflowGateError{Status: http.StatusBadRequest, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowClosureReviewGateResponse{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	evidenceBundles, _, evidenceSummary, err := collectEvidenceBundleArtifacts(workspacePath)
	if err != nil {
		return workflowClosureReviewGateResponse{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	receiptTimelines, _, receiptSummary, err := collectReceiptTimelineArtifacts(workspacePath)
	if err != nil {
		return workflowClosureReviewGateResponse{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if closurePackage.Package.ReleaseReadinessReference != releaseReadinessReference {
		return workflowClosureReviewGateResponse{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RVG-004: release readiness reference does not match latest closure package"}
	}
	if closurePackage.Package.Continuity.AuthorizationID == "" || closurePackage.Package.Continuity.TargetDigest == "" {
		return workflowClosureReviewGateResponse{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RVG-005: closure package continuity metadata is incomplete"}
	}
	if closurePackage.Package.Continuity.AuthorizationID != evidenceSummary.AuthorizationID || closurePackage.Package.Continuity.AuthorizationID != receiptSummary.AuthorizationID ||
		closurePackage.Package.Continuity.TargetDigest != evidenceSummary.TargetDigest || closurePackage.Package.Continuity.TargetDigest != receiptSummary.TargetDigest {
		return workflowClosureReviewGateResponse{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RVG-006: closure package continuity is mismatched against current evidence bundle and receipt timeline exports"}
	}
	gate := workflowClosureReviewGateResponse{Valid: true}
	gate.Gate.ClosurePackagePath = closurePackagePath
	gate.Gate.ReleaseReadinessReference = releaseReadinessReference
	gate.Gate.ReviewerReference = reviewerReference
	gate.Gate.Decision = normalizedDecision
	gate.Gate.Continuity = closurePackage.Package.Continuity
	gate.Gate.Outcome = "passed"
	if normalizedDecision == "blocked" {
		gate.Gate.Outcome = "blocked"
		gate.Gate.BlockerCode = "YARA-RVG-010"
	}
	subjects := []audit.Subject{
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewDecision", Digest: digestBytes([]byte(strings.Join([]string{releaseReadinessReference, reviewerReference, normalizedDecision, gate.Gate.Outcome}, "|")))},
	}
	for _, artifact := range evidenceBundles {
		subjects = append(subjects, audit.Subject{Kind: "WorkflowEvidenceBundleManifest", Digest: artifact.Digest})
	}
	for _, artifact := range receiptTimelines {
		subjects = append(subjects, audit.Subject{Kind: "ReceiptTimelineArtifact", Digest: artifact.Digest})
	}
	return gate, subjects, nil
}

func normalizeReviewGateDecision(decision string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "approve", "approved", "pass", "passed":
		return "approved", nil
	case "block", "blocked":
		return "blocked", nil
	default:
		return "", errors.New("decision must be one of approve/approved/pass/passed/block/blocked")
	}
}

func loadLatestClosurePackage(workspacePath string) (workflowClosurePackageManifest, string, string, error) {
	paths := discoverClosurePackageExports(workspacePath)
	if len(paths) == 0 {
		return workflowClosurePackageManifest{}, "", "", errors.New("YARA-RVG-001: closure package review gate requires at least one closure package export")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowClosurePackageManifest{}, "", "", fmt.Errorf("read latest closure package %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowClosurePackageManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowClosurePackageManifest{}, "", "", fmt.Errorf("decode latest closure package %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowClosurePackageManifest{}, "", "", errors.New("YARA-RVG-002: latest closure package export is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func renderClosureReviewGateMarkdown(gate workflowClosureReviewGateResponse) string {
	lines := []string{
		"# YARA closure package review gate",
		"",
		"## Decision",
		"- Release readiness reference: " + gate.Gate.ReleaseReadinessReference,
		"- Reviewer reference: " + gate.Gate.ReviewerReference,
		"- Decision: " + gate.Gate.Decision,
		"- Outcome: " + gate.Gate.Outcome,
		"",
		"## Continuity",
		"- Authorization ID: " + gate.Gate.Continuity.AuthorizationID,
		"- Target digest: " + gate.Gate.Continuity.TargetDigest,
	}
	if gate.Gate.BlockerCode != "" {
		lines = append(lines, "", "## Blocker", "- Code: "+gate.Gate.BlockerCode)
	}
	return strings.Join(lines, "\n")
}

func buildWorkflowReleaseDecisionLedger(workspacePath string, payload workflowReleaseDecisionExportRequest) (workflowReleaseDecisionLedger, []audit.Subject, error) {
	normalizedDecision, err := normalizeReviewGateDecision(payload.Decision)
	if err != nil {
		return workflowReleaseDecisionLedger{}, nil, workflowGateError{Status: http.StatusBadRequest, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowReleaseDecisionLedger{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowReleaseDecisionLedger{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if strings.TrimSpace(payload.ReleaseReadinessReference) != reviewGate.Gate.ReleaseReadinessReference || strings.TrimSpace(payload.ReleaseReadinessReference) != closurePackage.Package.ReleaseReadinessReference {
		return workflowReleaseDecisionLedger{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RDL-003: release readiness reference is not aligned with closure package and review gate artifacts"}
	}
	if strings.TrimSpace(payload.ReviewerReference) != reviewGate.Gate.ReviewerReference {
		return workflowReleaseDecisionLedger{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RDL-004: reviewer reference does not match latest review gate artifact"}
	}
	if reviewGate.Gate.Decision != normalizedDecision {
		return workflowReleaseDecisionLedger{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RDL-005: decision does not match latest review gate artifact"}
	}
	if reviewGate.Gate.Continuity != closurePackage.Package.Continuity {
		return workflowReleaseDecisionLedger{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RDL-006: closure package and review gate continuity chains are mismatched"}
	}
	ledger := workflowReleaseDecisionLedger{Valid: true}
	ledger.Ledger.WorkspacePath = workspacePath
	ledger.Ledger.ReleaseReadinessReference = strings.TrimSpace(payload.ReleaseReadinessReference)
	ledger.Ledger.ReviewerReference = strings.TrimSpace(payload.ReviewerReference)
	ledger.Ledger.Decision = normalizedDecision
	ledger.Ledger.OperatorReference = strings.TrimSpace(payload.OperatorReference)
	ledger.Ledger.DecisionTimestamp = strings.TrimSpace(payload.DecisionTimestamp)
	ledger.Ledger.Continuity = closurePackage.Package.Continuity
	ledger.Ledger.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	ledger.Ledger.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	ledger.Ledger.PublicationState = "ready-to-publish"
	if normalizedDecision == "blocked" || reviewGate.Gate.Outcome == "blocked" {
		ledger.Ledger.PublicationState = "blocked"
		ledger.Ledger.BlockerCode = mapValueOrDefault(reviewGate.Gate.BlockerCode, "YARA-RDL-010")
	}
	subjects := []audit.Subject{
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "ReleaseDecision", Digest: digestBytes([]byte(strings.Join([]string{ledger.Ledger.ReleaseReadinessReference, ledger.Ledger.ReviewerReference, ledger.Ledger.Decision, ledger.Ledger.OperatorReference, ledger.Ledger.DecisionTimestamp, ledger.Ledger.PublicationState}, "|")))},
	}
	return ledger, subjects, nil
}

func loadLatestClosureReviewGate(workspacePath string) (workflowClosureReviewGateResponse, string, string, error) {
	paths := discoverClosureReviewGateExports(workspacePath)
	if len(paths) == 0 {
		return workflowClosureReviewGateResponse{}, "", "", errors.New("YARA-RDL-001: release decision export requires at least one closure review gate export")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowClosureReviewGateResponse{}, "", "", fmt.Errorf("read latest closure review gate %s: %w", filepath.Base(latestPath), err)
	}
	gate := workflowClosureReviewGateResponse{}
	if err := json.Unmarshal(content, &gate); err != nil {
		return workflowClosureReviewGateResponse{}, "", "", fmt.Errorf("decode latest closure review gate %s: %w", filepath.Base(latestPath), err)
	}
	if !gate.Valid {
		return workflowClosureReviewGateResponse{}, "", "", errors.New("YARA-RDL-002: latest closure review gate export is invalid")
	}
	return gate, latestPath, digestBytes(content), nil
}

func buildWorkflowReleasePublicationAttestation(workspacePath string, payload workflowReleasePublicationExportRequest) (workflowReleasePublicationAttestation, []audit.Subject, error) {
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowReleasePublicationAttestation{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if releaseDecision.Ledger.PublicationState != "ready-to-publish" {
		reason := mapValueOrDefault(releaseDecision.Ledger.BlockerCode, "none")
		return workflowReleasePublicationAttestation{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPB-003: latest release decision is blocked and cannot be published (decision blocker: " + reason + ")"}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowReleasePublicationAttestation{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowReleasePublicationAttestation{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if releaseDecision.Ledger.Continuity != closurePackage.Package.Continuity || releaseDecision.Ledger.Continuity != reviewGate.Gate.Continuity {
		return workflowReleasePublicationAttestation{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPB-004: release decision continuity diverges from latest closure/review artifacts"}
	}
	if releaseDecision.Ledger.ClosurePackage.Digest != closurePackageDigest || releaseDecision.Ledger.ReviewGate.Digest != reviewGateDigest {
		return workflowReleasePublicationAttestation{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPB-005: release decision digest bindings do not match latest closure/review artifacts"}
	}
	attestation := workflowReleasePublicationAttestation{Valid: true}
	attestation.Publication.WorkspacePath = workspacePath
	attestation.Publication.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	attestation.Publication.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	attestation.Publication.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	attestation.Publication.Continuity = releaseDecision.Ledger.Continuity
	attestation.Publication.PublicationChannel = strings.TrimSpace(payload.PublicationChannel)
	attestation.Publication.ArtifactLocationReference = strings.TrimSpace(payload.ArtifactLocationReference)
	attestation.Publication.PublicationTimestamp = strings.TrimSpace(payload.PublicationTimestamp)
	attestation.Publication.OperatorReference = strings.TrimSpace(payload.OperatorReference)
	attestation.Publication.PublicationState = "publishable"
	subjects := []audit.Subject{
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "ReleasePublication", Digest: digestBytes([]byte(strings.Join([]string{attestation.Publication.PublicationChannel, attestation.Publication.ArtifactLocationReference, attestation.Publication.PublicationTimestamp, attestation.Publication.OperatorReference, releaseDecisionDigest}, "|")))},
	}
	return attestation, subjects, nil
}

func loadLatestReleaseDecision(workspacePath string) (workflowReleaseDecisionLedger, string, string, error) {
	paths := discoverReleaseDecisionExports(workspacePath)
	if len(paths) == 0 {
		return workflowReleaseDecisionLedger{}, "", "", errors.New("YARA-RPB-001: release publication export requires at least one release decision ledger export")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowReleaseDecisionLedger{}, "", "", fmt.Errorf("read latest release decision %s: %w", filepath.Base(latestPath), err)
	}
	ledger := workflowReleaseDecisionLedger{}
	if err := json.Unmarshal(content, &ledger); err != nil {
		return workflowReleaseDecisionLedger{}, "", "", fmt.Errorf("decode latest release decision %s: %w", filepath.Base(latestPath), err)
	}
	if !ledger.Valid {
		return workflowReleaseDecisionLedger{}, "", "", errors.New("YARA-RPB-002: latest release decision export is invalid")
	}
	return ledger, latestPath, digestBytes(content), nil
}

func buildWorkflowReleasePublicationIndexManifest(workspacePath string, payload workflowReleasePublicationIndexExportRequest) (workflowReleasePublicationIndexManifest, []audit.Subject, error) {
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowReleasePublicationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowReleasePublicationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowReleasePublicationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowReleasePublicationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if releasePublication.Publication.PublicationState != "publishable" {
		blocker := mapValueOrDefault(releasePublication.Publication.BlockerCode, "none")
		return workflowReleasePublicationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPI-003: latest release publication attestation is blocked (blocker: " + blocker + ")"}
	}
	if releaseDecision.Ledger.PublicationState != "ready-to-publish" {
		blocker := mapValueOrDefault(releaseDecision.Ledger.BlockerCode, "none")
		return workflowReleasePublicationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPI-004: latest release decision ledger is blocked (blocker: " + blocker + ")"}
	}
	if closurePackage.Package.Continuity != reviewGate.Gate.Continuity || closurePackage.Package.Continuity != releaseDecision.Ledger.Continuity || closurePackage.Package.Continuity != releasePublication.Publication.Continuity {
		return workflowReleasePublicationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPI-005: publication artifact continuity chains are mismatched"}
	}
	if releaseDecision.Ledger.ClosurePackage.Digest != closurePackageDigest || releaseDecision.Ledger.ReviewGate.Digest != reviewGateDigest {
		return workflowReleasePublicationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPI-006: release decision digest bindings do not match latest closure/review artifacts"}
	}
	if releasePublication.Publication.ReleaseDecision.Digest != releaseDecisionDigest || releasePublication.Publication.ClosurePackage.Digest != closurePackageDigest || releasePublication.Publication.ReviewGate.Digest != reviewGateDigest {
		return workflowReleasePublicationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPI-007: release publication digest bindings do not match current publication chain"}
	}
	manifest := workflowReleasePublicationIndexManifest{Valid: true}
	manifest.Index.WorkspacePath = workspacePath
	manifest.Index.PublicationBatchReference = strings.TrimSpace(payload.PublicationBatchReference)
	manifest.Index.OperatorReference = strings.TrimSpace(payload.OperatorReference)
	manifest.Index.IndexState = "index-ready"
	manifest.Index.Continuity = closurePackage.Package.Continuity
	manifest.Index.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Index.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	manifest.Index.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Index.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleasePublicationIndex", Digest: digestBytes([]byte(strings.Join([]string{manifest.Index.PublicationBatchReference, manifest.Index.OperatorReference, closurePackageDigest, reviewGateDigest, releaseDecisionDigest, releasePublicationDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowReleasePublicationPackageManifest(workspacePath string, payload workflowReleasePublicationPackageExportRequest) (workflowReleasePublicationPackageManifest, []audit.Subject, error) {
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowReleasePublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowReleasePublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowReleasePublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowReleasePublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowReleasePublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if releasePublicationIndex.Index.IndexState != "index-ready" {
		blocker := mapValueOrDefault(releasePublicationIndex.Index.BlockerCode, "none")
		return workflowReleasePublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPK-003: latest release publication index is blocked (blocker: " + blocker + ")"}
	}
	if releasePublication.Publication.PublicationState != "publishable" || releaseDecision.Ledger.PublicationState != "ready-to-publish" {
		return workflowReleasePublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPK-004: publication chain contains blocked decision or publication state"}
	}
	if closurePackage.Package.Continuity != reviewGate.Gate.Continuity || closurePackage.Package.Continuity != releaseDecision.Ledger.Continuity || closurePackage.Package.Continuity != releasePublication.Publication.Continuity || closurePackage.Package.Continuity != releasePublicationIndex.Index.Continuity {
		return workflowReleasePublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPK-005: publication package continuity chains are mismatched"}
	}
	if releasePublicationIndex.Index.ClosurePackage.Digest != closurePackageDigest || releasePublicationIndex.Index.ReviewGate.Digest != reviewGateDigest || releasePublicationIndex.Index.ReleaseDecision.Digest != releaseDecisionDigest || releasePublicationIndex.Index.ReleasePublication.Digest != releasePublicationDigest {
		return workflowReleasePublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPK-006: publication index digest bindings do not match current publication chain"}
	}
	manifest := workflowReleasePublicationPackageManifest{Valid: true}
	manifest.Package.WorkspacePath = workspacePath
	manifest.Package.PackageReference = strings.TrimSpace(payload.PackageReference)
	manifest.Package.PublicationWindowReference = strings.TrimSpace(payload.PublicationWindowReference)
	manifest.Package.OperatorReference = strings.TrimSpace(payload.OperatorReference)
	manifest.Package.PackageState = "package-ready"
	manifest.Package.Continuity = closurePackage.Package.Continuity
	manifest.Package.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Package.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	manifest.Package.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Package.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Package.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationPackage", Digest: digestBytes([]byte(strings.Join([]string{manifest.Package.PackageReference, manifest.Package.PublicationWindowReference, manifest.Package.OperatorReference, closurePackageDigest, reviewGateDigest, releaseDecisionDigest, releasePublicationDigest, releasePublicationIndexDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowReleasePublicationEnvelopeManifest(workspacePath string, payload workflowReleasePublicationEnvelopeExportRequest) (workflowReleasePublicationEnvelopeManifest, []audit.Subject, error) {
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowReleasePublicationEnvelopeManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowReleasePublicationEnvelopeManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowReleasePublicationEnvelopeManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowReleasePublicationEnvelopeManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowReleasePublicationEnvelopeManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowReleasePublicationEnvelopeManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if releasePublicationPackage.Package.PackageState != "package-ready" {
		blocker := mapValueOrDefault(releasePublicationPackage.Package.BlockerCode, "none")
		return workflowReleasePublicationEnvelopeManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPE-003: latest release publication package is blocked (blocker: " + blocker + ")"}
	}
	if closurePackage.Package.Continuity != reviewGate.Gate.Continuity || closurePackage.Package.Continuity != releaseDecision.Ledger.Continuity || closurePackage.Package.Continuity != releasePublication.Publication.Continuity || closurePackage.Package.Continuity != releasePublicationIndex.Index.Continuity || closurePackage.Package.Continuity != releasePublicationPackage.Package.Continuity {
		return workflowReleasePublicationEnvelopeManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPE-004: publication envelope continuity chains are mismatched"}
	}
	if releasePublicationPackage.Package.ClosurePackage.Digest != closurePackageDigest || releasePublicationPackage.Package.ReviewGate.Digest != reviewGateDigest || releasePublicationPackage.Package.ReleaseDecision.Digest != releaseDecisionDigest || releasePublicationPackage.Package.ReleasePublication.Digest != releasePublicationDigest || releasePublicationPackage.Package.ReleasePublicationIndex.Digest != releasePublicationIndexDigest {
		return workflowReleasePublicationEnvelopeManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPE-005: publication package digest bindings do not match current publication chain"}
	}
	manifest := workflowReleasePublicationEnvelopeManifest{Valid: true}
	manifest.Envelope.WorkspacePath = workspacePath
	manifest.Envelope.DeliveryReference = strings.TrimSpace(payload.DeliveryReference)
	manifest.Envelope.DestinationReference = strings.TrimSpace(payload.DestinationReference)
	manifest.Envelope.OperatorReference = strings.TrimSpace(payload.OperatorReference)
	manifest.Envelope.DeliveryState = "delivery-ready"
	manifest.Envelope.Continuity = closurePackage.Package.Continuity
	manifest.Envelope.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Envelope.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	manifest.Envelope.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Envelope.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Envelope.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.Envelope.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationEnvelope", Digest: digestBytes([]byte(strings.Join([]string{manifest.Envelope.DeliveryReference, manifest.Envelope.DestinationReference, manifest.Envelope.OperatorReference, closurePackageDigest, reviewGateDigest, releaseDecisionDigest, releasePublicationDigest, releasePublicationIndexDigest, releasePublicationPackageDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowReleasePublicationHandoffReceipt(workspacePath string, payload workflowReleasePublicationHandoffReceiptExportRequest) (workflowReleasePublicationHandoffReceipt, []audit.Subject, error) {
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowReleasePublicationHandoffReceipt{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowReleasePublicationHandoffReceipt{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowReleasePublicationHandoffReceipt{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowReleasePublicationHandoffReceipt{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowReleasePublicationHandoffReceipt{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowReleasePublicationHandoffReceipt{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowReleasePublicationHandoffReceipt{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if releasePublicationEnvelope.Envelope.DeliveryState != "delivery-ready" {
		blocker := mapValueOrDefault(releasePublicationEnvelope.Envelope.BlockerCode, "none")
		return workflowReleasePublicationHandoffReceipt{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RHR-003: latest release publication envelope is blocked (blocker: " + blocker + ")"}
	}
	if closurePackage.Package.Continuity != reviewGate.Gate.Continuity || closurePackage.Package.Continuity != releaseDecision.Ledger.Continuity || closurePackage.Package.Continuity != releasePublication.Publication.Continuity || closurePackage.Package.Continuity != releasePublicationIndex.Index.Continuity || closurePackage.Package.Continuity != releasePublicationPackage.Package.Continuity || closurePackage.Package.Continuity != releasePublicationEnvelope.Envelope.Continuity {
		return workflowReleasePublicationHandoffReceipt{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RHR-004: release publication handoff continuity chains are mismatched"}
	}
	if releasePublicationEnvelope.Envelope.ClosurePackage.Digest != closurePackageDigest || releasePublicationEnvelope.Envelope.ReviewGate.Digest != reviewGateDigest || releasePublicationEnvelope.Envelope.ReleaseDecision.Digest != releaseDecisionDigest || releasePublicationEnvelope.Envelope.ReleasePublication.Digest != releasePublicationDigest || releasePublicationEnvelope.Envelope.ReleasePublicationIndex.Digest != releasePublicationIndexDigest || releasePublicationEnvelope.Envelope.ReleasePublicationPackage.Digest != releasePublicationPackageDigest {
		return workflowReleasePublicationHandoffReceipt{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RHR-005: release publication envelope digest bindings do not match current publication chain"}
	}
	receipt := workflowReleasePublicationHandoffReceipt{Valid: true}
	receipt.Handoff.WorkspacePath = workspacePath
	receipt.Handoff.ReceiverReference = strings.TrimSpace(payload.ReceiverReference)
	receipt.Handoff.HandoffTimestamp = strings.TrimSpace(payload.HandoffTimestamp)
	receipt.Handoff.OperatorReference = strings.TrimSpace(payload.OperatorReference)
	receipt.Handoff.HandoffState = "handoff-ready"
	receipt.Handoff.Continuity = closurePackage.Package.Continuity
	receipt.Handoff.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	receipt.Handoff.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	receipt.Handoff.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	receipt.Handoff.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	receipt.Handoff.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	receipt.Handoff.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	receipt.Handoff.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: digestBytes([]byte(strings.Join([]string{receipt.Handoff.ReceiverReference, receipt.Handoff.HandoffTimestamp, receipt.Handoff.OperatorReference, closurePackageDigest, reviewGateDigest, releaseDecisionDigest, releasePublicationDigest, releasePublicationIndexDigest, releasePublicationPackageDigest, releasePublicationEnvelopeDigest}, "|")))},
	}
	return receipt, subjects, nil
}

func buildWorkflowReleasePublicationAcknowledgmentManifest(workspacePath string, payload workflowReleasePublicationAcknowledgmentExportRequest) (workflowReleasePublicationAcknowledgmentManifest, []audit.Subject, error) {
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	handoffReceipt, handoffReceiptPath, handoffReceiptDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if handoffReceipt.Handoff.HandoffState != "handoff-ready" {
		blocker := mapValueOrDefault(handoffReceipt.Handoff.BlockerCode, "none")
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RAK-003: latest release publication handoff receipt is blocked (blocker: " + blocker + ")"}
	}
	if closurePackage.Package.Continuity != reviewGate.Gate.Continuity || closurePackage.Package.Continuity != releaseDecision.Ledger.Continuity || closurePackage.Package.Continuity != releasePublication.Publication.Continuity || closurePackage.Package.Continuity != releasePublicationIndex.Index.Continuity || closurePackage.Package.Continuity != releasePublicationPackage.Package.Continuity || closurePackage.Package.Continuity != releasePublicationEnvelope.Envelope.Continuity || closurePackage.Package.Continuity != handoffReceipt.Handoff.Continuity {
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RAK-004: acknowledgment continuity chains are mismatched"}
	}
	if handoffReceipt.Handoff.ClosurePackage.Digest != closurePackageDigest || handoffReceipt.Handoff.ReviewGate.Digest != reviewGateDigest || handoffReceipt.Handoff.ReleaseDecision.Digest != releaseDecisionDigest || handoffReceipt.Handoff.ReleasePublication.Digest != releasePublicationDigest || handoffReceipt.Handoff.ReleasePublicationIndex.Digest != releasePublicationIndexDigest || handoffReceipt.Handoff.ReleasePublicationPackage.Digest != releasePublicationPackageDigest || handoffReceipt.Handoff.ReleasePublicationEnvelope.Digest != releasePublicationEnvelopeDigest {
		return workflowReleasePublicationAcknowledgmentManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RAK-005: handoff receipt digest bindings do not match current publication chain"}
	}
	manifest := workflowReleasePublicationAcknowledgmentManifest{Valid: true}
	manifest.Acknowledgment.WorkspacePath = workspacePath
	manifest.Acknowledgment.AcknowledgmentReference = strings.TrimSpace(payload.AcknowledgmentReference)
	manifest.Acknowledgment.AcknowledgedByReference = strings.TrimSpace(payload.AcknowledgedByReference)
	manifest.Acknowledgment.AcknowledgmentTimestamp = strings.TrimSpace(payload.AcknowledgmentTimestamp)
	manifest.Acknowledgment.AcknowledgmentState = "acknowledgment-ready"
	manifest.Acknowledgment.Continuity = closurePackage.Package.Continuity
	manifest.Acknowledgment.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Acknowledgment.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	manifest.Acknowledgment.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Acknowledgment.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Acknowledgment.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.Acknowledgment.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	manifest.Acknowledgment.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	manifest.Acknowledgment.HandoffReceipt = workflowClosureArtifact{Path: handoffReceiptPath, Digest: handoffReceiptDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: handoffReceiptDigest},
		{Kind: "ReleasePublicationAcknowledgment", Digest: digestBytes([]byte(strings.Join([]string{manifest.Acknowledgment.AcknowledgmentReference, manifest.Acknowledgment.AcknowledgedByReference, manifest.Acknowledgment.AcknowledgmentTimestamp, closurePackageDigest, reviewGateDigest, releaseDecisionDigest, releasePublicationDigest, releasePublicationIndexDigest, releasePublicationPackageDigest, releasePublicationEnvelopeDigest, handoffReceiptDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosureSummaryManifest(workspacePath string, payload workflowRolloutClosureSummaryExportRequest) (workflowRolloutClosureSummaryManifest, []audit.Subject, error) {
	capsule, capsulePath, capsuleDigest, err := loadLatestCapsuleExport(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if !capsule.Capsule.Ready {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCS-004: latest capsule export is blocked and cannot be summarized"}
	}
	evidenceBundle, evidenceBundlePath, evidenceBundleDigest, err := loadLatestWorkflowEvidenceBundle(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if reviewGate.Gate.Outcome != "passed" {
		blocker := mapValueOrDefault(reviewGate.Gate.BlockerCode, "none")
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCS-005: latest closure review gate is blocked (blocker: " + blocker + ")"}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	handoffReceipt, handoffReceiptPath, handoffReceiptDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acknowledgment, acknowledgmentPath, acknowledgmentDigest, err := loadLatestReleasePublicationAcknowledgment(workspacePath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if acknowledgment.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" {
		blocker := mapValueOrDefault(acknowledgment.Acknowledgment.BlockerCode, "none")
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCS-006: latest release publication acknowledgment is blocked (blocker: " + blocker + ")"}
	}
	if closurePackage.Package.Continuity.AuthorizationID != capsule.Capsule.Evidence.AuthorizationID || closurePackage.Package.Continuity.TargetDigest != capsule.Capsule.Evidence.TargetReferenceDigest ||
		closurePackage.Package.Continuity.AuthorizationID != evidenceBundle.Manifest.Evidence.AuthorizationID || closurePackage.Package.Continuity.TargetDigest != evidenceBundle.Manifest.Evidence.TargetReferenceDigest {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCS-007: capsule/evidence bundle continuity does not match closure continuity"}
	}
	if closurePackage.Package.Continuity != reviewGate.Gate.Continuity ||
		closurePackage.Package.Continuity != releaseDecision.Ledger.Continuity ||
		closurePackage.Package.Continuity != releasePublication.Publication.Continuity ||
		closurePackage.Package.Continuity != releasePublicationIndex.Index.Continuity ||
		closurePackage.Package.Continuity != releasePublicationPackage.Package.Continuity ||
		closurePackage.Package.Continuity != releasePublicationEnvelope.Envelope.Continuity ||
		closurePackage.Package.Continuity != handoffReceipt.Handoff.Continuity ||
		closurePackage.Package.Continuity != acknowledgment.Acknowledgment.Continuity {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCS-008: rollout closure summary continuity chains are mismatched"}
	}
	if acknowledgment.Acknowledgment.ClosurePackage.Digest != closurePackageDigest ||
		acknowledgment.Acknowledgment.ReviewGate.Digest != reviewGateDigest ||
		acknowledgment.Acknowledgment.ReleaseDecision.Digest != releaseDecisionDigest ||
		acknowledgment.Acknowledgment.ReleasePublication.Digest != releasePublicationDigest ||
		acknowledgment.Acknowledgment.ReleasePublicationIndex.Digest != releasePublicationIndexDigest ||
		acknowledgment.Acknowledgment.ReleasePublicationPackage.Digest != releasePublicationPackageDigest ||
		acknowledgment.Acknowledgment.ReleasePublicationEnvelope.Digest != releasePublicationEnvelopeDigest ||
		acknowledgment.Acknowledgment.HandoffReceipt.Digest != handoffReceiptDigest {
		return workflowRolloutClosureSummaryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCS-009: acknowledgment digest bindings do not match current publication chain"}
	}
	manifest := workflowRolloutClosureSummaryManifest{Valid: true}
	manifest.Summary.WorkspacePath = workspacePath
	manifest.Summary.SummaryReference = strings.TrimSpace(payload.SummaryReference)
	manifest.Summary.OperatorReference = strings.TrimSpace(payload.OperatorReference)
	manifest.Summary.SummaryTimestamp = strings.TrimSpace(payload.SummaryTimestamp)
	manifest.Summary.SummaryState = "summary-ready"
	manifest.Summary.Continuity = closurePackage.Package.Continuity
	manifest.Summary.CapsuleExport = workflowClosureArtifact{Path: capsulePath, Digest: capsuleDigest}
	manifest.Summary.EvidenceBundle = workflowClosureArtifact{Path: evidenceBundlePath, Digest: evidenceBundleDigest}
	manifest.Summary.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Summary.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	manifest.Summary.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Summary.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Summary.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.Summary.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	manifest.Summary.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	manifest.Summary.HandoffReceipt = workflowClosureArtifact{Path: handoffReceiptPath, Digest: handoffReceiptDigest}
	manifest.Summary.Acknowledgment = workflowClosureArtifact{Path: acknowledgmentPath, Digest: acknowledgmentDigest}
	subjects := []audit.Subject{
		{Kind: "CapsuleJSON", Digest: capsuleDigest},
		{Kind: "WorkflowEvidenceBundleManifest", Digest: evidenceBundleDigest},
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: handoffReceiptDigest},
		{Kind: "ReleasePublicationAcknowledgment", Digest: acknowledgmentDigest},
		{Kind: "RolloutClosureSummary", Digest: digestBytes([]byte(strings.Join([]string{manifest.Summary.SummaryReference, manifest.Summary.OperatorReference, manifest.Summary.SummaryTimestamp, capsuleDigest, evidenceBundleDigest, closurePackageDigest, reviewGateDigest, releaseDecisionDigest, releasePublicationDigest, releasePublicationIndexDigest, releasePublicationPackageDigest, releasePublicationEnvelopeDigest, handoffReceiptDigest, acknowledgmentDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosureDeliveryManifest(workspacePath string, payload workflowRolloutClosureDeliveryExportRequest) (workflowRolloutClosureDeliveryManifest, []audit.Subject, error) {
	closureSummary, closureSummaryPath, closureSummaryDigest, err := loadLatestRolloutClosureSummary(workspacePath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if closureSummary.Summary.SummaryState != "summary-ready" {
		blocker := mapValueOrDefault(closureSummary.Summary.BlockerCode, "none")
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCD-003: latest rollout closure summary is blocked (blocker: " + blocker + ")"}
	}
	acknowledgment, acknowledgmentPath, acknowledgmentDigest, err := loadLatestReleasePublicationAcknowledgment(workspacePath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	handoffReceipt, handoffReceiptPath, handoffReceiptDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if acknowledgment.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" {
		blocker := mapValueOrDefault(acknowledgment.Acknowledgment.BlockerCode, "none")
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCD-004: latest release publication acknowledgment is blocked (blocker: " + blocker + ")"}
	}
	if handoffReceipt.Handoff.HandoffState != "handoff-ready" || releasePublicationEnvelope.Envelope.DeliveryState != "delivery-ready" || releasePublicationPackage.Package.PackageState != "package-ready" || releasePublicationIndex.Index.IndexState != "index-ready" || releasePublication.Publication.PublicationState != "publishable" || releaseDecision.Ledger.PublicationState != "ready-to-publish" || reviewGate.Gate.Outcome != "passed" {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCD-005: rollout closure delivery requires ready publication chain states"}
	}
	if closureSummary.Summary.Continuity != acknowledgment.Acknowledgment.Continuity ||
		closureSummary.Summary.Continuity != handoffReceipt.Handoff.Continuity ||
		closureSummary.Summary.Continuity != releasePublicationEnvelope.Envelope.Continuity ||
		closureSummary.Summary.Continuity != releasePublicationPackage.Package.Continuity ||
		closureSummary.Summary.Continuity != releasePublicationIndex.Index.Continuity ||
		closureSummary.Summary.Continuity != releasePublication.Publication.Continuity ||
		closureSummary.Summary.Continuity != releaseDecision.Ledger.Continuity ||
		closureSummary.Summary.Continuity != closurePackage.Package.Continuity ||
		closureSummary.Summary.Continuity != reviewGate.Gate.Continuity {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCD-006: rollout closure delivery continuity chains are mismatched"}
	}
	if closureSummary.Summary.Acknowledgment.Digest != acknowledgmentDigest ||
		closureSummary.Summary.HandoffReceipt.Digest != handoffReceiptDigest ||
		closureSummary.Summary.ReleasePublicationEnvelope.Digest != releasePublicationEnvelopeDigest ||
		closureSummary.Summary.ReleasePublicationPackage.Digest != releasePublicationPackageDigest ||
		closureSummary.Summary.ReleasePublicationIndex.Digest != releasePublicationIndexDigest ||
		closureSummary.Summary.ReleasePublication.Digest != releasePublicationDigest ||
		closureSummary.Summary.ReleaseDecision.Digest != releaseDecisionDigest ||
		closureSummary.Summary.ClosurePackage.Digest != closurePackageDigest ||
		closureSummary.Summary.ReviewGate.Digest != reviewGateDigest {
		return workflowRolloutClosureDeliveryManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCD-007: closure summary digest bindings do not match current publication chain"}
	}
	manifest := workflowRolloutClosureDeliveryManifest{Valid: true}
	manifest.Delivery.WorkspacePath = workspacePath
	manifest.Delivery.DeliveryReference = strings.TrimSpace(payload.DeliveryReference)
	manifest.Delivery.DestinationReference = strings.TrimSpace(payload.DestinationReference)
	manifest.Delivery.OperatorReference = strings.TrimSpace(payload.OperatorReference)
	manifest.Delivery.DeliveryTimestamp = strings.TrimSpace(payload.DeliveryTimestamp)
	manifest.Delivery.DeliveryRecordState = "delivery-record-ready"
	manifest.Delivery.Continuity = closureSummary.Summary.Continuity
	manifest.Delivery.ClosureSummary = workflowClosureArtifact{Path: closureSummaryPath, Digest: closureSummaryDigest}
	manifest.Delivery.Acknowledgment = workflowClosureArtifact{Path: acknowledgmentPath, Digest: acknowledgmentDigest}
	manifest.Delivery.HandoffReceipt = workflowClosureArtifact{Path: handoffReceiptPath, Digest: handoffReceiptDigest}
	manifest.Delivery.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	manifest.Delivery.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	manifest.Delivery.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.Delivery.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Delivery.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Delivery.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Delivery.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosureSummaryManifest", Digest: closureSummaryDigest},
		{Kind: "ReleasePublicationAcknowledgment", Digest: acknowledgmentDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: handoffReceiptDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "RolloutClosureDeliveryRecord", Digest: digestBytes([]byte(strings.Join([]string{manifest.Delivery.DeliveryReference, manifest.Delivery.DestinationReference, manifest.Delivery.OperatorReference, manifest.Delivery.DeliveryTimestamp, closureSummaryDigest, acknowledgmentDigest, handoffReceiptDigest, releasePublicationEnvelopeDigest, releasePublicationPackageDigest, releasePublicationIndexDigest, releasePublicationDigest, releaseDecisionDigest, closurePackageDigest, reviewGateDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosureAcceptanceManifest(workspacePath string, payload workflowRolloutClosureAcceptanceExportRequest) (workflowRolloutClosureAcceptanceManifest, []audit.Subject, error) {
	deliveryRecord, deliveryRecordPath, deliveryRecordDigest, err := loadLatestRolloutClosureDelivery(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if deliveryRecord.Delivery.DeliveryRecordState != "delivery-record-ready" {
		blocker := mapValueOrDefault(deliveryRecord.Delivery.BlockerCode, "none")
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCA-003: latest rollout closure delivery record is blocked (blocker: " + blocker + ")"}
	}
	closureSummary, closureSummaryPath, closureSummaryDigest, err := loadLatestRolloutClosureSummary(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acknowledgment, acknowledgmentPath, acknowledgmentDigest, err := loadLatestReleasePublicationAcknowledgment(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	handoffReceipt, handoffReceiptPath, handoffReceiptDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if closureSummary.Summary.SummaryState != "summary-ready" || acknowledgment.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" || handoffReceipt.Handoff.HandoffState != "handoff-ready" || releasePublicationEnvelope.Envelope.DeliveryState != "delivery-ready" || releasePublicationPackage.Package.PackageState != "package-ready" || releasePublicationIndex.Index.IndexState != "index-ready" || releasePublication.Publication.PublicationState != "publishable" || releaseDecision.Ledger.PublicationState != "ready-to-publish" || reviewGate.Gate.Outcome != "passed" {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCA-004: rollout closure acceptance requires ready publication and closure states"}
	}
	if deliveryRecord.Delivery.Continuity != closureSummary.Summary.Continuity ||
		deliveryRecord.Delivery.Continuity != acknowledgment.Acknowledgment.Continuity ||
		deliveryRecord.Delivery.Continuity != handoffReceipt.Handoff.Continuity ||
		deliveryRecord.Delivery.Continuity != releasePublicationEnvelope.Envelope.Continuity ||
		deliveryRecord.Delivery.Continuity != releasePublicationPackage.Package.Continuity ||
		deliveryRecord.Delivery.Continuity != releasePublicationIndex.Index.Continuity ||
		deliveryRecord.Delivery.Continuity != releasePublication.Publication.Continuity ||
		deliveryRecord.Delivery.Continuity != releaseDecision.Ledger.Continuity ||
		deliveryRecord.Delivery.Continuity != closurePackage.Package.Continuity ||
		deliveryRecord.Delivery.Continuity != reviewGate.Gate.Continuity {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCA-005: rollout closure acceptance continuity chains are mismatched"}
	}
	if deliveryRecord.Delivery.ClosureSummary.Digest != closureSummaryDigest ||
		deliveryRecord.Delivery.Acknowledgment.Digest != acknowledgmentDigest ||
		deliveryRecord.Delivery.HandoffReceipt.Digest != handoffReceiptDigest ||
		deliveryRecord.Delivery.ReleasePublicationEnvelope.Digest != releasePublicationEnvelopeDigest ||
		deliveryRecord.Delivery.ReleasePublicationPackage.Digest != releasePublicationPackageDigest ||
		deliveryRecord.Delivery.ReleasePublicationIndex.Digest != releasePublicationIndexDigest ||
		deliveryRecord.Delivery.ReleasePublication.Digest != releasePublicationDigest ||
		deliveryRecord.Delivery.ReleaseDecision.Digest != releaseDecisionDigest ||
		deliveryRecord.Delivery.ClosurePackage.Digest != closurePackageDigest ||
		deliveryRecord.Delivery.ReviewGate.Digest != reviewGateDigest {
		return workflowRolloutClosureAcceptanceManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCA-006: delivery record digest bindings do not match current publication chain"}
	}
	manifest := workflowRolloutClosureAcceptanceManifest{Valid: true}
	manifest.Acceptance.WorkspacePath = workspacePath
	manifest.Acceptance.AcceptanceReference = strings.TrimSpace(payload.AcceptanceReference)
	manifest.Acceptance.AcceptedByReference = strings.TrimSpace(payload.AcceptedByReference)
	manifest.Acceptance.AcceptanceTimestamp = strings.TrimSpace(payload.AcceptanceTimestamp)
	manifest.Acceptance.AcceptanceState = "acceptance-ready"
	manifest.Acceptance.Continuity = deliveryRecord.Delivery.Continuity
	manifest.Acceptance.DeliveryRecord = workflowClosureArtifact{Path: deliveryRecordPath, Digest: deliveryRecordDigest}
	manifest.Acceptance.ClosureSummary = workflowClosureArtifact{Path: closureSummaryPath, Digest: closureSummaryDigest}
	manifest.Acceptance.Acknowledgment = workflowClosureArtifact{Path: acknowledgmentPath, Digest: acknowledgmentDigest}
	manifest.Acceptance.HandoffReceipt = workflowClosureArtifact{Path: handoffReceiptPath, Digest: handoffReceiptDigest}
	manifest.Acceptance.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	manifest.Acceptance.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	manifest.Acceptance.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.Acceptance.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Acceptance.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Acceptance.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Acceptance.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosureDeliveryManifest", Digest: deliveryRecordDigest},
		{Kind: "WorkflowRolloutClosureSummaryManifest", Digest: closureSummaryDigest},
		{Kind: "ReleasePublicationAcknowledgment", Digest: acknowledgmentDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: handoffReceiptDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "RolloutClosureAcceptanceReceipt", Digest: digestBytes([]byte(strings.Join([]string{manifest.Acceptance.AcceptanceReference, manifest.Acceptance.AcceptedByReference, manifest.Acceptance.AcceptanceTimestamp, deliveryRecordDigest, closureSummaryDigest, acknowledgmentDigest, handoffReceiptDigest, releasePublicationEnvelopeDigest, releasePublicationPackageDigest, releasePublicationIndexDigest, releasePublicationDigest, releaseDecisionDigest, closurePackageDigest, reviewGateDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosureCertificateManifest(workspacePath string, payload workflowRolloutClosureCertificateExportRequest) (workflowRolloutClosureCertificateManifest, []audit.Subject, error) {
	acceptanceReceipt, acceptancePath, acceptanceDigest, err := loadLatestRolloutClosureAcceptance(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if acceptanceReceipt.Acceptance.AcceptanceState != "acceptance-ready" {
		blocker := mapValueOrDefault(acceptanceReceipt.Acceptance.BlockerCode, "none")
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCC-003: latest rollout closure acceptance receipt is blocked (blocker: " + blocker + ")"}
	}
	deliveryRecord, deliveryRecordPath, deliveryRecordDigest, err := loadLatestRolloutClosureDelivery(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closureSummary, closureSummaryPath, closureSummaryDigest, err := loadLatestRolloutClosureSummary(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acknowledgment, acknowledgmentPath, acknowledgmentDigest, err := loadLatestReleasePublicationAcknowledgment(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	handoffReceipt, handoffReceiptPath, handoffReceiptDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if deliveryRecord.Delivery.DeliveryRecordState != "delivery-record-ready" || closureSummary.Summary.SummaryState != "summary-ready" || acknowledgment.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" || handoffReceipt.Handoff.HandoffState != "handoff-ready" || releasePublicationEnvelope.Envelope.DeliveryState != "delivery-ready" || releasePublicationPackage.Package.PackageState != "package-ready" || releasePublicationIndex.Index.IndexState != "index-ready" || releasePublication.Publication.PublicationState != "publishable" || releaseDecision.Ledger.PublicationState != "ready-to-publish" || reviewGate.Gate.Outcome != "passed" {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCC-004: rollout closure certificate requires ready publication and closure states"}
	}
	if acceptanceReceipt.Acceptance.Continuity != deliveryRecord.Delivery.Continuity ||
		acceptanceReceipt.Acceptance.Continuity != closureSummary.Summary.Continuity ||
		acceptanceReceipt.Acceptance.Continuity != acknowledgment.Acknowledgment.Continuity ||
		acceptanceReceipt.Acceptance.Continuity != handoffReceipt.Handoff.Continuity ||
		acceptanceReceipt.Acceptance.Continuity != releasePublicationEnvelope.Envelope.Continuity ||
		acceptanceReceipt.Acceptance.Continuity != releasePublicationPackage.Package.Continuity ||
		acceptanceReceipt.Acceptance.Continuity != releasePublicationIndex.Index.Continuity ||
		acceptanceReceipt.Acceptance.Continuity != releasePublication.Publication.Continuity ||
		acceptanceReceipt.Acceptance.Continuity != releaseDecision.Ledger.Continuity ||
		acceptanceReceipt.Acceptance.Continuity != closurePackage.Package.Continuity ||
		acceptanceReceipt.Acceptance.Continuity != reviewGate.Gate.Continuity {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCC-005: rollout closure certificate continuity chains are mismatched"}
	}
	if acceptanceReceipt.Acceptance.DeliveryRecord.Digest != deliveryRecordDigest ||
		acceptanceReceipt.Acceptance.ClosureSummary.Digest != closureSummaryDigest ||
		acceptanceReceipt.Acceptance.Acknowledgment.Digest != acknowledgmentDigest ||
		acceptanceReceipt.Acceptance.HandoffReceipt.Digest != handoffReceiptDigest ||
		acceptanceReceipt.Acceptance.ReleasePublicationEnvelope.Digest != releasePublicationEnvelopeDigest ||
		acceptanceReceipt.Acceptance.ReleasePublicationPackage.Digest != releasePublicationPackageDigest ||
		acceptanceReceipt.Acceptance.ReleasePublicationIndex.Digest != releasePublicationIndexDigest ||
		acceptanceReceipt.Acceptance.ReleasePublication.Digest != releasePublicationDigest ||
		acceptanceReceipt.Acceptance.ReleaseDecision.Digest != releaseDecisionDigest ||
		acceptanceReceipt.Acceptance.ClosurePackage.Digest != closurePackageDigest ||
		acceptanceReceipt.Acceptance.ReviewGate.Digest != reviewGateDigest {
		return workflowRolloutClosureCertificateManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RCC-006: acceptance receipt digest bindings do not match current publication chain"}
	}
	manifest := workflowRolloutClosureCertificateManifest{Valid: true}
	manifest.Certificate.WorkspacePath = workspacePath
	manifest.Certificate.CertificateReference = strings.TrimSpace(payload.CertificateReference)
	manifest.Certificate.IssuedByReference = strings.TrimSpace(payload.IssuedByReference)
	manifest.Certificate.IssuedTimestamp = strings.TrimSpace(payload.IssuedTimestamp)
	manifest.Certificate.CertificateState = "certificate-ready"
	manifest.Certificate.Continuity = acceptanceReceipt.Acceptance.Continuity
	manifest.Certificate.AcceptanceReceipt = workflowClosureArtifact{Path: acceptancePath, Digest: acceptanceDigest}
	manifest.Certificate.DeliveryRecord = workflowClosureArtifact{Path: deliveryRecordPath, Digest: deliveryRecordDigest}
	manifest.Certificate.ClosureSummary = workflowClosureArtifact{Path: closureSummaryPath, Digest: closureSummaryDigest}
	manifest.Certificate.Acknowledgment = workflowClosureArtifact{Path: acknowledgmentPath, Digest: acknowledgmentDigest}
	manifest.Certificate.HandoffReceipt = workflowClosureArtifact{Path: handoffReceiptPath, Digest: handoffReceiptDigest}
	manifest.Certificate.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	manifest.Certificate.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	manifest.Certificate.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.Certificate.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Certificate.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Certificate.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Certificate.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosureAcceptanceManifest", Digest: acceptanceDigest},
		{Kind: "WorkflowRolloutClosureDeliveryManifest", Digest: deliveryRecordDigest},
		{Kind: "WorkflowRolloutClosureSummaryManifest", Digest: closureSummaryDigest},
		{Kind: "ReleasePublicationAcknowledgment", Digest: acknowledgmentDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: handoffReceiptDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "RolloutClosurePublicationCertificate", Digest: digestBytes([]byte(strings.Join([]string{manifest.Certificate.CertificateReference, manifest.Certificate.IssuedByReference, manifest.Certificate.IssuedTimestamp, acceptanceDigest, deliveryRecordDigest, closureSummaryDigest, acknowledgmentDigest, handoffReceiptDigest, releasePublicationEnvelopeDigest, releasePublicationPackageDigest, releasePublicationIndexDigest, releasePublicationDigest, releaseDecisionDigest, closurePackageDigest, reviewGateDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosureLedgerManifest(workspacePath string, payload workflowRolloutClosureLedgerExportRequest) (workflowRolloutClosureLedgerManifest, []audit.Subject, error) {
	certificate, certificatePath, certificateDigest, err := loadLatestRolloutClosureCertificate(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if certificate.Certificate.CertificateState != "certificate-ready" {
		blocker := mapValueOrDefault(certificate.Certificate.BlockerCode, "none")
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RLG-003: latest rollout closure certificate is blocked (blocker: " + blocker + ")"}
	}
	acceptanceReceipt, acceptancePath, acceptanceDigest, err := loadLatestRolloutClosureAcceptance(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	deliveryRecord, deliveryRecordPath, deliveryRecordDigest, err := loadLatestRolloutClosureDelivery(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closureSummary, closureSummaryPath, closureSummaryDigest, err := loadLatestRolloutClosureSummary(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acknowledgment, acknowledgmentPath, acknowledgmentDigest, err := loadLatestReleasePublicationAcknowledgment(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	handoffReceipt, handoffReceiptPath, handoffReceiptDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if acceptanceReceipt.Acceptance.AcceptanceState != "acceptance-ready" || deliveryRecord.Delivery.DeliveryRecordState != "delivery-record-ready" || closureSummary.Summary.SummaryState != "summary-ready" || acknowledgment.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" || handoffReceipt.Handoff.HandoffState != "handoff-ready" || releasePublicationEnvelope.Envelope.DeliveryState != "delivery-ready" || releasePublicationPackage.Package.PackageState != "package-ready" || releasePublicationIndex.Index.IndexState != "index-ready" || releasePublication.Publication.PublicationState != "publishable" || releaseDecision.Ledger.PublicationState != "ready-to-publish" || reviewGate.Gate.Outcome != "passed" {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RLG-004: rollout closure ledger requires ready publication and closure states"}
	}
	if certificate.Certificate.Continuity != acceptanceReceipt.Acceptance.Continuity ||
		certificate.Certificate.Continuity != deliveryRecord.Delivery.Continuity ||
		certificate.Certificate.Continuity != closureSummary.Summary.Continuity ||
		certificate.Certificate.Continuity != acknowledgment.Acknowledgment.Continuity ||
		certificate.Certificate.Continuity != handoffReceipt.Handoff.Continuity ||
		certificate.Certificate.Continuity != releasePublicationEnvelope.Envelope.Continuity ||
		certificate.Certificate.Continuity != releasePublicationPackage.Package.Continuity ||
		certificate.Certificate.Continuity != releasePublicationIndex.Index.Continuity ||
		certificate.Certificate.Continuity != releasePublication.Publication.Continuity ||
		certificate.Certificate.Continuity != releaseDecision.Ledger.Continuity ||
		certificate.Certificate.Continuity != closurePackage.Package.Continuity ||
		certificate.Certificate.Continuity != reviewGate.Gate.Continuity {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RLG-005: rollout closure ledger continuity chains are mismatched"}
	}
	if certificate.Certificate.AcceptanceReceipt.Digest != acceptanceDigest ||
		certificate.Certificate.DeliveryRecord.Digest != deliveryRecordDigest ||
		certificate.Certificate.ClosureSummary.Digest != closureSummaryDigest ||
		certificate.Certificate.Acknowledgment.Digest != acknowledgmentDigest ||
		certificate.Certificate.HandoffReceipt.Digest != handoffReceiptDigest ||
		certificate.Certificate.ReleasePublicationEnvelope.Digest != releasePublicationEnvelopeDigest ||
		certificate.Certificate.ReleasePublicationPackage.Digest != releasePublicationPackageDigest ||
		certificate.Certificate.ReleasePublicationIndex.Digest != releasePublicationIndexDigest ||
		certificate.Certificate.ReleasePublication.Digest != releasePublicationDigest ||
		certificate.Certificate.ReleaseDecision.Digest != releaseDecisionDigest ||
		certificate.Certificate.ClosurePackage.Digest != closurePackageDigest ||
		certificate.Certificate.ReviewGate.Digest != reviewGateDigest {
		return workflowRolloutClosureLedgerManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RLG-006: certificate digest bindings do not match current publication chain"}
	}
	manifest := workflowRolloutClosureLedgerManifest{Valid: true}
	manifest.Ledger.WorkspacePath = workspacePath
	manifest.Ledger.LedgerReference = strings.TrimSpace(payload.LedgerReference)
	manifest.Ledger.RecordedByReference = strings.TrimSpace(payload.RecordedByReference)
	manifest.Ledger.RecordedTimestamp = strings.TrimSpace(payload.RecordedTimestamp)
	manifest.Ledger.LedgerState = "ledger-ready"
	manifest.Ledger.Continuity = certificate.Certificate.Continuity
	manifest.Ledger.PublicationCertificate = workflowClosureArtifact{Path: certificatePath, Digest: certificateDigest}
	manifest.Ledger.AcceptanceReceipt = workflowClosureArtifact{Path: acceptancePath, Digest: acceptanceDigest}
	manifest.Ledger.DeliveryRecord = workflowClosureArtifact{Path: deliveryRecordPath, Digest: deliveryRecordDigest}
	manifest.Ledger.ClosureSummary = workflowClosureArtifact{Path: closureSummaryPath, Digest: closureSummaryDigest}
	manifest.Ledger.Acknowledgment = workflowClosureArtifact{Path: acknowledgmentPath, Digest: acknowledgmentDigest}
	manifest.Ledger.HandoffReceipt = workflowClosureArtifact{Path: handoffReceiptPath, Digest: handoffReceiptDigest}
	manifest.Ledger.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	manifest.Ledger.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	manifest.Ledger.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.Ledger.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Ledger.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Ledger.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Ledger.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosureCertificateManifest", Digest: certificateDigest},
		{Kind: "WorkflowRolloutClosureAcceptanceManifest", Digest: acceptanceDigest},
		{Kind: "WorkflowRolloutClosureDeliveryManifest", Digest: deliveryRecordDigest},
		{Kind: "WorkflowRolloutClosureSummaryManifest", Digest: closureSummaryDigest},
		{Kind: "ReleasePublicationAcknowledgment", Digest: acknowledgmentDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: handoffReceiptDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "RolloutClosureArchivalLedger", Digest: digestBytes([]byte(strings.Join([]string{manifest.Ledger.LedgerReference, manifest.Ledger.RecordedByReference, manifest.Ledger.RecordedTimestamp, certificateDigest, acceptanceDigest, deliveryRecordDigest, closureSummaryDigest, acknowledgmentDigest, handoffReceiptDigest, releasePublicationEnvelopeDigest, releasePublicationPackageDigest, releasePublicationIndexDigest, releasePublicationDigest, releaseDecisionDigest, closurePackageDigest, reviewGateDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosureDocketManifest(workspacePath string, payload workflowRolloutClosureDocketExportRequest) (workflowRolloutClosureDocketManifest, []audit.Subject, error) {
	ledger, ledgerPath, ledgerDigest, err := loadLatestRolloutClosureLedger(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if ledger.Ledger.LedgerState != "ledger-ready" {
		blocker := mapValueOrDefault(ledger.Ledger.BlockerCode, "none")
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RDK-003: latest rollout closure ledger is blocked (blocker: " + blocker + ")"}
	}
	certificate, certificatePath, certificateDigest, err := loadLatestRolloutClosureCertificate(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acceptanceReceipt, acceptancePath, acceptanceDigest, err := loadLatestRolloutClosureAcceptance(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	deliveryRecord, deliveryRecordPath, deliveryRecordDigest, err := loadLatestRolloutClosureDelivery(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closureSummary, closureSummaryPath, closureSummaryDigest, err := loadLatestRolloutClosureSummary(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acknowledgment, acknowledgmentPath, acknowledgmentDigest, err := loadLatestReleasePublicationAcknowledgment(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	handoffReceipt, handoffReceiptPath, handoffReceiptDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if certificate.Certificate.CertificateState != "certificate-ready" || acceptanceReceipt.Acceptance.AcceptanceState != "acceptance-ready" || deliveryRecord.Delivery.DeliveryRecordState != "delivery-record-ready" || closureSummary.Summary.SummaryState != "summary-ready" || acknowledgment.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" || handoffReceipt.Handoff.HandoffState != "handoff-ready" || releasePublicationEnvelope.Envelope.DeliveryState != "delivery-ready" || releasePublicationPackage.Package.PackageState != "package-ready" || releasePublicationIndex.Index.IndexState != "index-ready" || releasePublication.Publication.PublicationState != "publishable" || releaseDecision.Ledger.PublicationState != "ready-to-publish" || reviewGate.Gate.Outcome != "passed" {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RDK-004: rollout closure docket requires ready publication and closure states"}
	}
	if ledger.Ledger.Continuity != certificate.Certificate.Continuity ||
		ledger.Ledger.Continuity != acceptanceReceipt.Acceptance.Continuity ||
		ledger.Ledger.Continuity != deliveryRecord.Delivery.Continuity ||
		ledger.Ledger.Continuity != closureSummary.Summary.Continuity ||
		ledger.Ledger.Continuity != acknowledgment.Acknowledgment.Continuity ||
		ledger.Ledger.Continuity != handoffReceipt.Handoff.Continuity ||
		ledger.Ledger.Continuity != releasePublicationEnvelope.Envelope.Continuity ||
		ledger.Ledger.Continuity != releasePublicationPackage.Package.Continuity ||
		ledger.Ledger.Continuity != releasePublicationIndex.Index.Continuity ||
		ledger.Ledger.Continuity != releasePublication.Publication.Continuity ||
		ledger.Ledger.Continuity != releaseDecision.Ledger.Continuity ||
		ledger.Ledger.Continuity != closurePackage.Package.Continuity ||
		ledger.Ledger.Continuity != reviewGate.Gate.Continuity {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RDK-005: rollout closure docket continuity chains are mismatched"}
	}
	if ledger.Ledger.PublicationCertificate.Digest != certificateDigest ||
		ledger.Ledger.AcceptanceReceipt.Digest != acceptanceDigest ||
		ledger.Ledger.DeliveryRecord.Digest != deliveryRecordDigest ||
		ledger.Ledger.ClosureSummary.Digest != closureSummaryDigest ||
		ledger.Ledger.Acknowledgment.Digest != acknowledgmentDigest ||
		ledger.Ledger.HandoffReceipt.Digest != handoffReceiptDigest ||
		ledger.Ledger.ReleasePublicationEnvelope.Digest != releasePublicationEnvelopeDigest ||
		ledger.Ledger.ReleasePublicationPackage.Digest != releasePublicationPackageDigest ||
		ledger.Ledger.ReleasePublicationIndex.Digest != releasePublicationIndexDigest ||
		ledger.Ledger.ReleasePublication.Digest != releasePublicationDigest ||
		ledger.Ledger.ReleaseDecision.Digest != releaseDecisionDigest ||
		ledger.Ledger.ClosurePackage.Digest != closurePackageDigest ||
		ledger.Ledger.ReviewGate.Digest != reviewGateDigest {
		return workflowRolloutClosureDocketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RDK-006: archival ledger digest bindings do not match current publication chain"}
	}
	manifest := workflowRolloutClosureDocketManifest{Valid: true}
	manifest.Docket.WorkspacePath = workspacePath
	manifest.Docket.DocketReference = strings.TrimSpace(payload.DocketReference)
	manifest.Docket.PreparedByReference = strings.TrimSpace(payload.PreparedByReference)
	manifest.Docket.PreparedTimestamp = strings.TrimSpace(payload.PreparedTimestamp)
	manifest.Docket.DocketState = "docket-ready"
	manifest.Docket.Continuity = ledger.Ledger.Continuity
	manifest.Docket.ArchivalLedger = workflowClosureArtifact{Path: ledgerPath, Digest: ledgerDigest}
	manifest.Docket.PublicationCertificate = workflowClosureArtifact{Path: certificatePath, Digest: certificateDigest}
	manifest.Docket.AcceptanceReceipt = workflowClosureArtifact{Path: acceptancePath, Digest: acceptanceDigest}
	manifest.Docket.DeliveryRecord = workflowClosureArtifact{Path: deliveryRecordPath, Digest: deliveryRecordDigest}
	manifest.Docket.ClosureSummary = workflowClosureArtifact{Path: closureSummaryPath, Digest: closureSummaryDigest}
	manifest.Docket.Acknowledgment = workflowClosureArtifact{Path: acknowledgmentPath, Digest: acknowledgmentDigest}
	manifest.Docket.HandoffReceipt = workflowClosureArtifact{Path: handoffReceiptPath, Digest: handoffReceiptDigest}
	manifest.Docket.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	manifest.Docket.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	manifest.Docket.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.Docket.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Docket.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Docket.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Docket.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosureLedgerManifest", Digest: ledgerDigest},
		{Kind: "WorkflowRolloutClosureCertificateManifest", Digest: certificateDigest},
		{Kind: "WorkflowRolloutClosureAcceptanceManifest", Digest: acceptanceDigest},
		{Kind: "WorkflowRolloutClosureDeliveryManifest", Digest: deliveryRecordDigest},
		{Kind: "WorkflowRolloutClosureSummaryManifest", Digest: closureSummaryDigest},
		{Kind: "ReleasePublicationAcknowledgment", Digest: acknowledgmentDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: handoffReceiptDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "RolloutClosureHandoffDocket", Digest: digestBytes([]byte(strings.Join([]string{manifest.Docket.DocketReference, manifest.Docket.PreparedByReference, manifest.Docket.PreparedTimestamp, ledgerDigest, certificateDigest, acceptanceDigest, deliveryRecordDigest, closureSummaryDigest, acknowledgmentDigest, handoffReceiptDigest, releasePublicationEnvelopeDigest, releasePublicationPackageDigest, releasePublicationIndexDigest, releasePublicationDigest, releaseDecisionDigest, closurePackageDigest, reviewGateDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosureBulletinManifest(workspacePath string, payload workflowRolloutClosureBulletinExportRequest) (workflowRolloutClosureBulletinManifest, []audit.Subject, error) {
	docket, docketPath, docketDigest, err := loadLatestRolloutClosureDocket(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if docket.Docket.DocketState != "docket-ready" {
		blocker := mapValueOrDefault(docket.Docket.BlockerCode, "none")
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RBL-003: latest rollout closure docket is blocked (blocker: " + blocker + ")"}
	}
	ledger, ledgerPath, ledgerDigest, err := loadLatestRolloutClosureLedger(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	certificate, certificatePath, certificateDigest, err := loadLatestRolloutClosureCertificate(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acceptanceReceipt, acceptancePath, acceptanceDigest, err := loadLatestRolloutClosureAcceptance(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	deliveryRecord, deliveryRecordPath, deliveryRecordDigest, err := loadLatestRolloutClosureDelivery(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closureSummary, closureSummaryPath, closureSummaryDigest, err := loadLatestRolloutClosureSummary(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acknowledgment, acknowledgmentPath, acknowledgmentDigest, err := loadLatestReleasePublicationAcknowledgment(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	handoffReceipt, handoffReceiptPath, handoffReceiptDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if ledger.Ledger.LedgerState != "ledger-ready" || certificate.Certificate.CertificateState != "certificate-ready" || acceptanceReceipt.Acceptance.AcceptanceState != "acceptance-ready" || deliveryRecord.Delivery.DeliveryRecordState != "delivery-record-ready" || closureSummary.Summary.SummaryState != "summary-ready" || acknowledgment.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" || handoffReceipt.Handoff.HandoffState != "handoff-ready" || releasePublicationEnvelope.Envelope.DeliveryState != "delivery-ready" || releasePublicationPackage.Package.PackageState != "package-ready" || releasePublicationIndex.Index.IndexState != "index-ready" || releasePublication.Publication.PublicationState != "publishable" || releaseDecision.Ledger.PublicationState != "ready-to-publish" || reviewGate.Gate.Outcome != "passed" {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RBL-004: rollout closure bulletin requires ready publication and closure states"}
	}
	if docket.Docket.Continuity != ledger.Ledger.Continuity ||
		docket.Docket.Continuity != certificate.Certificate.Continuity ||
		docket.Docket.Continuity != acceptanceReceipt.Acceptance.Continuity ||
		docket.Docket.Continuity != deliveryRecord.Delivery.Continuity ||
		docket.Docket.Continuity != closureSummary.Summary.Continuity ||
		docket.Docket.Continuity != acknowledgment.Acknowledgment.Continuity ||
		docket.Docket.Continuity != handoffReceipt.Handoff.Continuity ||
		docket.Docket.Continuity != releasePublicationEnvelope.Envelope.Continuity ||
		docket.Docket.Continuity != releasePublicationPackage.Package.Continuity ||
		docket.Docket.Continuity != releasePublicationIndex.Index.Continuity ||
		docket.Docket.Continuity != releasePublication.Publication.Continuity ||
		docket.Docket.Continuity != releaseDecision.Ledger.Continuity ||
		docket.Docket.Continuity != closurePackage.Package.Continuity ||
		docket.Docket.Continuity != reviewGate.Gate.Continuity {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RBL-005: rollout closure bulletin continuity chains are mismatched"}
	}
	if docket.Docket.ArchivalLedger.Digest != ledgerDigest ||
		docket.Docket.PublicationCertificate.Digest != certificateDigest ||
		docket.Docket.AcceptanceReceipt.Digest != acceptanceDigest ||
		docket.Docket.DeliveryRecord.Digest != deliveryRecordDigest ||
		docket.Docket.ClosureSummary.Digest != closureSummaryDigest ||
		docket.Docket.Acknowledgment.Digest != acknowledgmentDigest ||
		docket.Docket.HandoffReceipt.Digest != handoffReceiptDigest ||
		docket.Docket.ReleasePublicationEnvelope.Digest != releasePublicationEnvelopeDigest ||
		docket.Docket.ReleasePublicationPackage.Digest != releasePublicationPackageDigest ||
		docket.Docket.ReleasePublicationIndex.Digest != releasePublicationIndexDigest ||
		docket.Docket.ReleasePublication.Digest != releasePublicationDigest ||
		docket.Docket.ReleaseDecision.Digest != releaseDecisionDigest ||
		docket.Docket.ClosurePackage.Digest != closurePackageDigest ||
		docket.Docket.ReviewGate.Digest != reviewGateDigest {
		return workflowRolloutClosureBulletinManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RBL-006: handoff docket digest bindings do not match current publication chain"}
	}
	manifest := workflowRolloutClosureBulletinManifest{Valid: true}
	manifest.Bulletin.WorkspacePath = workspacePath
	manifest.Bulletin.BulletinReference = strings.TrimSpace(payload.BulletinReference)
	manifest.Bulletin.PublishedByReference = strings.TrimSpace(payload.PublishedByReference)
	manifest.Bulletin.PublishedTimestamp = strings.TrimSpace(payload.PublishedTimestamp)
	manifest.Bulletin.BulletinState = "bulletin-ready"
	manifest.Bulletin.Continuity = docket.Docket.Continuity
	manifest.Bulletin.HandoffDocket = workflowClosureArtifact{Path: docketPath, Digest: docketDigest}
	manifest.Bulletin.ArchivalLedger = workflowClosureArtifact{Path: ledgerPath, Digest: ledgerDigest}
	manifest.Bulletin.PublicationCertificate = workflowClosureArtifact{Path: certificatePath, Digest: certificateDigest}
	manifest.Bulletin.AcceptanceReceipt = workflowClosureArtifact{Path: acceptancePath, Digest: acceptanceDigest}
	manifest.Bulletin.DeliveryRecord = workflowClosureArtifact{Path: deliveryRecordPath, Digest: deliveryRecordDigest}
	manifest.Bulletin.ClosureSummary = workflowClosureArtifact{Path: closureSummaryPath, Digest: closureSummaryDigest}
	manifest.Bulletin.Acknowledgment = workflowClosureArtifact{Path: acknowledgmentPath, Digest: acknowledgmentDigest}
	manifest.Bulletin.HandoffReceipt = workflowClosureArtifact{Path: handoffReceiptPath, Digest: handoffReceiptDigest}
	manifest.Bulletin.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	manifest.Bulletin.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	manifest.Bulletin.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.Bulletin.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Bulletin.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Bulletin.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Bulletin.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosureDocketManifest", Digest: docketDigest},
		{Kind: "WorkflowRolloutClosureLedgerManifest", Digest: ledgerDigest},
		{Kind: "WorkflowRolloutClosureCertificateManifest", Digest: certificateDigest},
		{Kind: "WorkflowRolloutClosureAcceptanceManifest", Digest: acceptanceDigest},
		{Kind: "WorkflowRolloutClosureDeliveryManifest", Digest: deliveryRecordDigest},
		{Kind: "WorkflowRolloutClosureSummaryManifest", Digest: closureSummaryDigest},
		{Kind: "ReleasePublicationAcknowledgment", Digest: acknowledgmentDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: handoffReceiptDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "RolloutClosureReleaseBulletin", Digest: digestBytes([]byte(strings.Join([]string{manifest.Bulletin.BulletinReference, manifest.Bulletin.PublishedByReference, manifest.Bulletin.PublishedTimestamp, docketDigest, ledgerDigest, certificateDigest, acceptanceDigest, deliveryRecordDigest, closureSummaryDigest, acknowledgmentDigest, handoffReceiptDigest, releasePublicationEnvelopeDigest, releasePublicationPackageDigest, releasePublicationIndexDigest, releasePublicationDigest, releaseDecisionDigest, closurePackageDigest, reviewGateDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosurePacketManifest(workspacePath string, payload workflowRolloutClosurePacketExportRequest) (workflowRolloutClosurePacketManifest, []audit.Subject, error) {
	bulletin, bulletinPath, bulletinDigest, err := loadLatestRolloutClosureBulletin(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if bulletin.Bulletin.BulletinState != "bulletin-ready" {
		blocker := mapValueOrDefault(bulletin.Bulletin.BlockerCode, "none")
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPT-003: latest rollout closure bulletin is blocked (blocker: " + blocker + ")"}
	}
	docket, docketPath, docketDigest, err := loadLatestRolloutClosureDocket(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	ledger, ledgerPath, ledgerDigest, err := loadLatestRolloutClosureLedger(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	certificate, certificatePath, certificateDigest, err := loadLatestRolloutClosureCertificate(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acceptanceReceipt, acceptancePath, acceptanceDigest, err := loadLatestRolloutClosureAcceptance(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	deliveryRecord, deliveryRecordPath, deliveryRecordDigest, err := loadLatestRolloutClosureDelivery(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closureSummary, closureSummaryPath, closureSummaryDigest, err := loadLatestRolloutClosureSummary(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acknowledgment, acknowledgmentPath, acknowledgmentDigest, err := loadLatestReleasePublicationAcknowledgment(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	handoffReceipt, handoffReceiptPath, handoffReceiptDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if docket.Docket.DocketState != "docket-ready" || ledger.Ledger.LedgerState != "ledger-ready" || certificate.Certificate.CertificateState != "certificate-ready" || acceptanceReceipt.Acceptance.AcceptanceState != "acceptance-ready" || deliveryRecord.Delivery.DeliveryRecordState != "delivery-record-ready" || closureSummary.Summary.SummaryState != "summary-ready" || acknowledgment.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" || handoffReceipt.Handoff.HandoffState != "handoff-ready" || releasePublicationEnvelope.Envelope.DeliveryState != "delivery-ready" || releasePublicationPackage.Package.PackageState != "package-ready" || releasePublicationIndex.Index.IndexState != "index-ready" || releasePublication.Publication.PublicationState != "publishable" || releaseDecision.Ledger.PublicationState != "ready-to-publish" || reviewGate.Gate.Outcome != "passed" {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPT-004: rollout closure packet requires ready publication and closure states"}
	}
	if bulletin.Bulletin.Continuity != docket.Docket.Continuity ||
		bulletin.Bulletin.Continuity != ledger.Ledger.Continuity ||
		bulletin.Bulletin.Continuity != certificate.Certificate.Continuity ||
		bulletin.Bulletin.Continuity != acceptanceReceipt.Acceptance.Continuity ||
		bulletin.Bulletin.Continuity != deliveryRecord.Delivery.Continuity ||
		bulletin.Bulletin.Continuity != closureSummary.Summary.Continuity ||
		bulletin.Bulletin.Continuity != acknowledgment.Acknowledgment.Continuity ||
		bulletin.Bulletin.Continuity != handoffReceipt.Handoff.Continuity ||
		bulletin.Bulletin.Continuity != releasePublicationEnvelope.Envelope.Continuity ||
		bulletin.Bulletin.Continuity != releasePublicationPackage.Package.Continuity ||
		bulletin.Bulletin.Continuity != releasePublicationIndex.Index.Continuity ||
		bulletin.Bulletin.Continuity != releasePublication.Publication.Continuity ||
		bulletin.Bulletin.Continuity != releaseDecision.Ledger.Continuity ||
		bulletin.Bulletin.Continuity != closurePackage.Package.Continuity ||
		bulletin.Bulletin.Continuity != reviewGate.Gate.Continuity {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPT-005: rollout closure packet continuity chains are mismatched"}
	}
	if bulletin.Bulletin.HandoffDocket.Digest != docketDigest ||
		bulletin.Bulletin.ArchivalLedger.Digest != ledgerDigest ||
		bulletin.Bulletin.PublicationCertificate.Digest != certificateDigest ||
		bulletin.Bulletin.AcceptanceReceipt.Digest != acceptanceDigest ||
		bulletin.Bulletin.DeliveryRecord.Digest != deliveryRecordDigest ||
		bulletin.Bulletin.ClosureSummary.Digest != closureSummaryDigest ||
		bulletin.Bulletin.Acknowledgment.Digest != acknowledgmentDigest ||
		bulletin.Bulletin.HandoffReceipt.Digest != handoffReceiptDigest ||
		bulletin.Bulletin.ReleasePublicationEnvelope.Digest != releasePublicationEnvelopeDigest ||
		bulletin.Bulletin.ReleasePublicationPackage.Digest != releasePublicationPackageDigest ||
		bulletin.Bulletin.ReleasePublicationIndex.Digest != releasePublicationIndexDigest ||
		bulletin.Bulletin.ReleasePublication.Digest != releasePublicationDigest ||
		bulletin.Bulletin.ReleaseDecision.Digest != releaseDecisionDigest ||
		bulletin.Bulletin.ClosurePackage.Digest != closurePackageDigest ||
		bulletin.Bulletin.ReviewGate.Digest != reviewGateDigest {
		return workflowRolloutClosurePacketManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPT-006: release bulletin digest bindings do not match current publication chain"}
	}
	manifest := workflowRolloutClosurePacketManifest{Valid: true}
	manifest.Packet.WorkspacePath = workspacePath
	manifest.Packet.PacketReference = strings.TrimSpace(payload.PacketReference)
	manifest.Packet.PackagedByReference = strings.TrimSpace(payload.PackagedByReference)
	manifest.Packet.PackagedTimestamp = strings.TrimSpace(payload.PackagedTimestamp)
	manifest.Packet.PacketState = "packet-ready"
	manifest.Packet.Continuity = bulletin.Bulletin.Continuity
	manifest.Packet.ReleaseBulletin = workflowClosureArtifact{Path: bulletinPath, Digest: bulletinDigest}
	manifest.Packet.HandoffDocket = workflowClosureArtifact{Path: docketPath, Digest: docketDigest}
	manifest.Packet.ArchivalLedger = workflowClosureArtifact{Path: ledgerPath, Digest: ledgerDigest}
	manifest.Packet.PublicationCertificate = workflowClosureArtifact{Path: certificatePath, Digest: certificateDigest}
	manifest.Packet.AcceptanceReceipt = workflowClosureArtifact{Path: acceptancePath, Digest: acceptanceDigest}
	manifest.Packet.DeliveryRecord = workflowClosureArtifact{Path: deliveryRecordPath, Digest: deliveryRecordDigest}
	manifest.Packet.ClosureSummary = workflowClosureArtifact{Path: closureSummaryPath, Digest: closureSummaryDigest}
	manifest.Packet.Acknowledgment = workflowClosureArtifact{Path: acknowledgmentPath, Digest: acknowledgmentDigest}
	manifest.Packet.HandoffReceipt = workflowClosureArtifact{Path: handoffReceiptPath, Digest: handoffReceiptDigest}
	manifest.Packet.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	manifest.Packet.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	manifest.Packet.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.Packet.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.Packet.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.Packet.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.Packet.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosureBulletinManifest", Digest: bulletinDigest},
		{Kind: "WorkflowRolloutClosureDocketManifest", Digest: docketDigest},
		{Kind: "WorkflowRolloutClosureLedgerManifest", Digest: ledgerDigest},
		{Kind: "WorkflowRolloutClosureCertificateManifest", Digest: certificateDigest},
		{Kind: "WorkflowRolloutClosureAcceptanceManifest", Digest: acceptanceDigest},
		{Kind: "WorkflowRolloutClosureDeliveryManifest", Digest: deliveryRecordDigest},
		{Kind: "WorkflowRolloutClosureSummaryManifest", Digest: closureSummaryDigest},
		{Kind: "ReleasePublicationAcknowledgment", Digest: acknowledgmentDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: handoffReceiptDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "RolloutClosureReleasePacket", Digest: digestBytes([]byte(strings.Join([]string{manifest.Packet.PacketReference, manifest.Packet.PackagedByReference, manifest.Packet.PackagedTimestamp, bulletinDigest, docketDigest, ledgerDigest, certificateDigest, acceptanceDigest, deliveryRecordDigest, closureSummaryDigest, acknowledgmentDigest, handoffReceiptDigest, releasePublicationEnvelopeDigest, releasePublicationPackageDigest, releasePublicationIndexDigest, releasePublicationDigest, releaseDecisionDigest, closurePackageDigest, reviewGateDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosureRecipientPackageManifest(workspacePath string, payload workflowRolloutClosureRecipientPackageExportRequest) (workflowRolloutClosureRecipientPackageManifest, []audit.Subject, error) {
	packet, packetPath, packetDigest, err := loadLatestRolloutClosurePacket(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if packet.Packet.PacketState != "packet-ready" {
		blocker := mapValueOrDefault(packet.Packet.BlockerCode, "none")
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPKG-003: latest rollout closure packet is blocked (blocker: " + blocker + ")"}
	}
	bulletin, bulletinPath, bulletinDigest, err := loadLatestRolloutClosureBulletin(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	docket, docketPath, docketDigest, err := loadLatestRolloutClosureDocket(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	ledger, ledgerPath, ledgerDigest, err := loadLatestRolloutClosureLedger(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	certificate, certificatePath, certificateDigest, err := loadLatestRolloutClosureCertificate(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acceptanceReceipt, acceptancePath, acceptanceDigest, err := loadLatestRolloutClosureAcceptance(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	deliveryRecord, deliveryRecordPath, deliveryRecordDigest, err := loadLatestRolloutClosureDelivery(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closureSummary, closureSummaryPath, closureSummaryDigest, err := loadLatestRolloutClosureSummary(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	acknowledgment, acknowledgmentPath, acknowledgmentDigest, err := loadLatestReleasePublicationAcknowledgment(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	handoffReceipt, handoffReceiptPath, handoffReceiptDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationEnvelope, releasePublicationEnvelopePath, releasePublicationEnvelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationPackage, releasePublicationPackagePath, releasePublicationPackageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublicationIndex, releasePublicationIndexPath, releasePublicationIndexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releasePublication, releasePublicationPath, releasePublicationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	releaseDecision, releaseDecisionPath, releaseDecisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	closurePackage, closurePackagePath, closurePackageDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	reviewGate, reviewGatePath, reviewGateDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if bulletin.Bulletin.BulletinState != "bulletin-ready" || docket.Docket.DocketState != "docket-ready" || ledger.Ledger.LedgerState != "ledger-ready" || certificate.Certificate.CertificateState != "certificate-ready" || acceptanceReceipt.Acceptance.AcceptanceState != "acceptance-ready" || deliveryRecord.Delivery.DeliveryRecordState != "delivery-record-ready" || closureSummary.Summary.SummaryState != "summary-ready" || acknowledgment.Acknowledgment.AcknowledgmentState != "acknowledgment-ready" || handoffReceipt.Handoff.HandoffState != "handoff-ready" || releasePublicationEnvelope.Envelope.DeliveryState != "delivery-ready" || releasePublicationPackage.Package.PackageState != "package-ready" || releasePublicationIndex.Index.IndexState != "index-ready" || releasePublication.Publication.PublicationState != "publishable" || releaseDecision.Ledger.PublicationState != "ready-to-publish" || reviewGate.Gate.Outcome != "passed" {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPKG-004: rollout closure recipient package requires ready publication and closure states"}
	}
	if packet.Packet.Continuity != bulletin.Bulletin.Continuity ||
		packet.Packet.Continuity != docket.Docket.Continuity ||
		packet.Packet.Continuity != ledger.Ledger.Continuity ||
		packet.Packet.Continuity != certificate.Certificate.Continuity ||
		packet.Packet.Continuity != acceptanceReceipt.Acceptance.Continuity ||
		packet.Packet.Continuity != deliveryRecord.Delivery.Continuity ||
		packet.Packet.Continuity != closureSummary.Summary.Continuity ||
		packet.Packet.Continuity != acknowledgment.Acknowledgment.Continuity ||
		packet.Packet.Continuity != handoffReceipt.Handoff.Continuity ||
		packet.Packet.Continuity != releasePublicationEnvelope.Envelope.Continuity ||
		packet.Packet.Continuity != releasePublicationPackage.Package.Continuity ||
		packet.Packet.Continuity != releasePublicationIndex.Index.Continuity ||
		packet.Packet.Continuity != releasePublication.Publication.Continuity ||
		packet.Packet.Continuity != releaseDecision.Ledger.Continuity ||
		packet.Packet.Continuity != closurePackage.Package.Continuity ||
		packet.Packet.Continuity != reviewGate.Gate.Continuity {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPKG-005: rollout closure recipient package continuity chains are mismatched"}
	}
	if packet.Packet.ReleaseBulletin.Digest != bulletinDigest ||
		packet.Packet.HandoffDocket.Digest != docketDigest ||
		packet.Packet.ArchivalLedger.Digest != ledgerDigest ||
		packet.Packet.PublicationCertificate.Digest != certificateDigest ||
		packet.Packet.AcceptanceReceipt.Digest != acceptanceDigest ||
		packet.Packet.DeliveryRecord.Digest != deliveryRecordDigest ||
		packet.Packet.ClosureSummary.Digest != closureSummaryDigest ||
		packet.Packet.Acknowledgment.Digest != acknowledgmentDigest ||
		packet.Packet.HandoffReceipt.Digest != handoffReceiptDigest ||
		packet.Packet.ReleasePublicationEnvelope.Digest != releasePublicationEnvelopeDigest ||
		packet.Packet.ReleasePublicationPackage.Digest != releasePublicationPackageDigest ||
		packet.Packet.ReleasePublicationIndex.Digest != releasePublicationIndexDigest ||
		packet.Packet.ReleasePublication.Digest != releasePublicationDigest ||
		packet.Packet.ReleaseDecision.Digest != releaseDecisionDigest ||
		packet.Packet.ClosurePackage.Digest != closurePackageDigest ||
		packet.Packet.ReviewGate.Digest != reviewGateDigest {
		return workflowRolloutClosureRecipientPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: "YARA-RPKG-006: release packet digest bindings do not match current publication chain"}
	}
	manifest := workflowRolloutClosureRecipientPackageManifest{Valid: true}
	manifest.RecipientPackage.WorkspacePath = workspacePath
	manifest.RecipientPackage.RecipientPackageReference = strings.TrimSpace(payload.RecipientPackageReference)
	manifest.RecipientPackage.PreparedForReference = strings.TrimSpace(payload.PreparedForReference)
	manifest.RecipientPackage.PreparedTimestamp = strings.TrimSpace(payload.PreparedTimestamp)
	manifest.RecipientPackage.RecipientPackageState = "recipient-package-ready"
	manifest.RecipientPackage.Continuity = packet.Packet.Continuity
	manifest.RecipientPackage.ReleasePacket = workflowClosureArtifact{Path: packetPath, Digest: packetDigest}
	manifest.RecipientPackage.ReleaseBulletin = workflowClosureArtifact{Path: bulletinPath, Digest: bulletinDigest}
	manifest.RecipientPackage.HandoffDocket = workflowClosureArtifact{Path: docketPath, Digest: docketDigest}
	manifest.RecipientPackage.ArchivalLedger = workflowClosureArtifact{Path: ledgerPath, Digest: ledgerDigest}
	manifest.RecipientPackage.PublicationCertificate = workflowClosureArtifact{Path: certificatePath, Digest: certificateDigest}
	manifest.RecipientPackage.AcceptanceReceipt = workflowClosureArtifact{Path: acceptancePath, Digest: acceptanceDigest}
	manifest.RecipientPackage.DeliveryRecord = workflowClosureArtifact{Path: deliveryRecordPath, Digest: deliveryRecordDigest}
	manifest.RecipientPackage.ClosureSummary = workflowClosureArtifact{Path: closureSummaryPath, Digest: closureSummaryDigest}
	manifest.RecipientPackage.Acknowledgment = workflowClosureArtifact{Path: acknowledgmentPath, Digest: acknowledgmentDigest}
	manifest.RecipientPackage.HandoffReceipt = workflowClosureArtifact{Path: handoffReceiptPath, Digest: handoffReceiptDigest}
	manifest.RecipientPackage.ReleasePublicationEnvelope = workflowClosureArtifact{Path: releasePublicationEnvelopePath, Digest: releasePublicationEnvelopeDigest}
	manifest.RecipientPackage.ReleasePublicationPackage = workflowClosureArtifact{Path: releasePublicationPackagePath, Digest: releasePublicationPackageDigest}
	manifest.RecipientPackage.ReleasePublicationIndex = workflowClosureArtifact{Path: releasePublicationIndexPath, Digest: releasePublicationIndexDigest}
	manifest.RecipientPackage.ReleasePublication = workflowClosureArtifact{Path: releasePublicationPath, Digest: releasePublicationDigest}
	manifest.RecipientPackage.ReleaseDecision = workflowClosureArtifact{Path: releaseDecisionPath, Digest: releaseDecisionDigest}
	manifest.RecipientPackage.ClosurePackage = workflowClosureArtifact{Path: closurePackagePath, Digest: closurePackageDigest}
	manifest.RecipientPackage.ReviewGate = workflowClosureArtifact{Path: reviewGatePath, Digest: reviewGateDigest}
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosurePacketManifest", Digest: packetDigest},
		{Kind: "WorkflowRolloutClosureBulletinManifest", Digest: bulletinDigest},
		{Kind: "WorkflowRolloutClosureDocketManifest", Digest: docketDigest},
		{Kind: "WorkflowRolloutClosureLedgerManifest", Digest: ledgerDigest},
		{Kind: "WorkflowRolloutClosureCertificateManifest", Digest: certificateDigest},
		{Kind: "WorkflowRolloutClosureAcceptanceManifest", Digest: acceptanceDigest},
		{Kind: "WorkflowRolloutClosureDeliveryManifest", Digest: deliveryRecordDigest},
		{Kind: "WorkflowRolloutClosureSummaryManifest", Digest: closureSummaryDigest},
		{Kind: "ReleasePublicationAcknowledgment", Digest: acknowledgmentDigest},
		{Kind: "ReleasePublicationHandoffReceipt", Digest: handoffReceiptDigest},
		{Kind: "ReleasePublicationEnvelopeManifest", Digest: releasePublicationEnvelopeDigest},
		{Kind: "ReleasePublicationPackageManifest", Digest: releasePublicationPackageDigest},
		{Kind: "ReleasePublicationIndexManifest", Digest: releasePublicationIndexDigest},
		{Kind: "ReleasePublicationAttestation", Digest: releasePublicationDigest},
		{Kind: "ReleaseDecisionLedger", Digest: releaseDecisionDigest},
		{Kind: "WorkflowClosurePackageManifest", Digest: closurePackageDigest},
		{Kind: "ClosureReviewGateJSON", Digest: reviewGateDigest},
		{Kind: "RolloutClosureRecipientPackage", Digest: digestBytes([]byte(strings.Join([]string{manifest.RecipientPackage.RecipientPackageReference, manifest.RecipientPackage.PreparedForReference, manifest.RecipientPackage.PreparedTimestamp, packetDigest, bulletinDigest, docketDigest, ledgerDigest, certificateDigest, acceptanceDigest, deliveryRecordDigest, closureSummaryDigest, acknowledgmentDigest, handoffReceiptDigest, releasePublicationEnvelopeDigest, releasePublicationPackageDigest, releasePublicationIndexDigest, releasePublicationDigest, releaseDecisionDigest, closurePackageDigest, reviewGateDigest}, "|")))},
	}
	return manifest, subjects, nil
}

func loadLatestReleasePublication(workspacePath string) (workflowReleasePublicationAttestation, string, string, error) {
	paths := discoverReleasePublicationExports(workspacePath)
	if len(paths) == 0 {
		return workflowReleasePublicationAttestation{}, "", "", errors.New("YARA-RPI-001: release publication index export requires at least one release publication attestation")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowReleasePublicationAttestation{}, "", "", fmt.Errorf("read latest release publication %s: %w", filepath.Base(latestPath), err)
	}
	attestation := workflowReleasePublicationAttestation{}
	if err := json.Unmarshal(content, &attestation); err != nil {
		return workflowReleasePublicationAttestation{}, "", "", fmt.Errorf("decode latest release publication %s: %w", filepath.Base(latestPath), err)
	}
	if !attestation.Valid {
		return workflowReleasePublicationAttestation{}, "", "", errors.New("YARA-RPI-002: latest release publication attestation is invalid")
	}
	return attestation, latestPath, digestBytes(content), nil
}

func loadLatestReleasePublicationIndex(workspacePath string) (workflowReleasePublicationIndexManifest, string, string, error) {
	paths := discoverReleasePublicationIndexExports(workspacePath)
	if len(paths) == 0 {
		return workflowReleasePublicationIndexManifest{}, "", "", errors.New("YARA-RPK-001: release publication package export requires at least one release publication index manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowReleasePublicationIndexManifest{}, "", "", fmt.Errorf("read latest release publication index %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowReleasePublicationIndexManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowReleasePublicationIndexManifest{}, "", "", fmt.Errorf("decode latest release publication index %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowReleasePublicationIndexManifest{}, "", "", errors.New("YARA-RPK-002: latest release publication index manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestReleasePublicationPackage(workspacePath string) (workflowReleasePublicationPackageManifest, string, string, error) {
	paths := discoverReleasePublicationPackageExports(workspacePath)
	if len(paths) == 0 {
		return workflowReleasePublicationPackageManifest{}, "", "", errors.New("YARA-RPE-001: release publication envelope export requires at least one release publication package manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowReleasePublicationPackageManifest{}, "", "", fmt.Errorf("read latest release publication package %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowReleasePublicationPackageManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowReleasePublicationPackageManifest{}, "", "", fmt.Errorf("decode latest release publication package %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowReleasePublicationPackageManifest{}, "", "", errors.New("YARA-RPE-002: latest release publication package manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestReleasePublicationEnvelope(workspacePath string) (workflowReleasePublicationEnvelopeManifest, string, string, error) {
	paths := discoverReleasePublicationEnvelopeExports(workspacePath)
	if len(paths) == 0 {
		return workflowReleasePublicationEnvelopeManifest{}, "", "", errors.New("YARA-RHR-001: handoff receipt export requires at least one release publication envelope manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowReleasePublicationEnvelopeManifest{}, "", "", fmt.Errorf("read latest release publication envelope %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowReleasePublicationEnvelopeManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowReleasePublicationEnvelopeManifest{}, "", "", fmt.Errorf("decode latest release publication envelope %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowReleasePublicationEnvelopeManifest{}, "", "", errors.New("YARA-RHR-002: latest release publication envelope manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestReleasePublicationHandoffReceipt(workspacePath string) (workflowReleasePublicationHandoffReceipt, string, string, error) {
	paths := discoverReleasePublicationHandoffReceiptExports(workspacePath)
	if len(paths) == 0 {
		return workflowReleasePublicationHandoffReceipt{}, "", "", errors.New("YARA-RAK-001: acknowledgment export requires at least one release publication handoff receipt")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowReleasePublicationHandoffReceipt{}, "", "", fmt.Errorf("read latest handoff receipt %s: %w", filepath.Base(latestPath), err)
	}
	receipt := workflowReleasePublicationHandoffReceipt{}
	if err := json.Unmarshal(content, &receipt); err != nil {
		return workflowReleasePublicationHandoffReceipt{}, "", "", fmt.Errorf("decode latest handoff receipt %s: %w", filepath.Base(latestPath), err)
	}
	if !receipt.Valid {
		return workflowReleasePublicationHandoffReceipt{}, "", "", errors.New("YARA-RAK-002: latest release publication handoff receipt is invalid")
	}
	return receipt, latestPath, digestBytes(content), nil
}

func loadLatestReleasePublicationAcknowledgment(workspacePath string) (workflowReleasePublicationAcknowledgmentManifest, string, string, error) {
	paths := discoverReleasePublicationAcknowledgmentExports(workspacePath)
	if len(paths) == 0 {
		return workflowReleasePublicationAcknowledgmentManifest{}, "", "", errors.New("YARA-RCS-001: rollout closure summary export requires at least one release publication acknowledgment manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowReleasePublicationAcknowledgmentManifest{}, "", "", fmt.Errorf("read latest release publication acknowledgment %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowReleasePublicationAcknowledgmentManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowReleasePublicationAcknowledgmentManifest{}, "", "", fmt.Errorf("decode latest release publication acknowledgment %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowReleasePublicationAcknowledgmentManifest{}, "", "", errors.New("YARA-RCS-002: latest release publication acknowledgment manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestCapsuleExport(workspacePath string) (workflowCapsuleResponse, string, string, error) {
	_, jsonPaths := discoverCapsuleExports(workspacePath)
	if len(jsonPaths) == 0 {
		return workflowCapsuleResponse{}, "", "", errors.New("YARA-RCS-003: rollout closure summary export requires at least one capsule json export")
	}
	latestPath := jsonPaths[len(jsonPaths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowCapsuleResponse{}, "", "", fmt.Errorf("read latest capsule export %s: %w", filepath.Base(latestPath), err)
	}
	capsule := workflowCapsuleResponse{}
	if err := json.Unmarshal(content, &capsule); err != nil {
		return workflowCapsuleResponse{}, "", "", fmt.Errorf("decode latest capsule export %s: %w", filepath.Base(latestPath), err)
	}
	if !capsule.Valid {
		return workflowCapsuleResponse{}, "", "", errors.New("YARA-RCS-010: latest capsule json export is invalid")
	}
	return capsule, latestPath, digestBytes(content), nil
}

func loadLatestWorkflowEvidenceBundle(workspacePath string) (workflowEvidenceBundleManifest, string, string, error) {
	paths := discoverEvidenceBundleExports(workspacePath)
	if len(paths) == 0 {
		return workflowEvidenceBundleManifest{}, "", "", errors.New("YARA-RCS-011: rollout closure summary export requires at least one evidence bundle export")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowEvidenceBundleManifest{}, "", "", fmt.Errorf("read latest evidence bundle export %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowEvidenceBundleManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowEvidenceBundleManifest{}, "", "", fmt.Errorf("decode latest evidence bundle export %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowEvidenceBundleManifest{}, "", "", errors.New("YARA-RCS-012: latest evidence bundle export is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureSummary(workspacePath string) (workflowRolloutClosureSummaryManifest, string, string, error) {
	paths := discoverRolloutClosureSummaryExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureSummaryManifest{}, "", "", errors.New("YARA-RCD-001: rollout closure delivery export requires at least one rollout closure summary manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureSummaryManifest{}, "", "", fmt.Errorf("read latest rollout closure summary %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosureSummaryManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosureSummaryManifest{}, "", "", fmt.Errorf("decode latest rollout closure summary %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosureSummaryManifest{}, "", "", errors.New("YARA-RCD-002: latest rollout closure summary manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureDelivery(workspacePath string) (workflowRolloutClosureDeliveryManifest, string, string, error) {
	paths := discoverRolloutClosureDeliveryExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureDeliveryManifest{}, "", "", errors.New("YARA-RCA-001: rollout closure acceptance export requires at least one rollout closure delivery manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureDeliveryManifest{}, "", "", fmt.Errorf("read latest rollout closure delivery %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosureDeliveryManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosureDeliveryManifest{}, "", "", fmt.Errorf("decode latest rollout closure delivery %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosureDeliveryManifest{}, "", "", errors.New("YARA-RCA-002: latest rollout closure delivery manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureAcceptance(workspacePath string) (workflowRolloutClosureAcceptanceManifest, string, string, error) {
	paths := discoverRolloutClosureAcceptanceExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureAcceptanceManifest{}, "", "", errors.New("YARA-RCC-001: rollout closure certificate export requires at least one rollout closure acceptance manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, "", "", fmt.Errorf("read latest rollout closure acceptance %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosureAcceptanceManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosureAcceptanceManifest{}, "", "", fmt.Errorf("decode latest rollout closure acceptance %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosureAcceptanceManifest{}, "", "", errors.New("YARA-RCC-002: latest rollout closure acceptance manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureCertificate(workspacePath string) (workflowRolloutClosureCertificateManifest, string, string, error) {
	paths := discoverRolloutClosureCertificateExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureCertificateManifest{}, "", "", errors.New("YARA-RLG-001: rollout closure ledger export requires at least one rollout closure certificate manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureCertificateManifest{}, "", "", fmt.Errorf("read latest rollout closure certificate %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosureCertificateManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosureCertificateManifest{}, "", "", fmt.Errorf("decode latest rollout closure certificate %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosureCertificateManifest{}, "", "", errors.New("YARA-RLG-002: latest rollout closure certificate manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureLedger(workspacePath string) (workflowRolloutClosureLedgerManifest, string, string, error) {
	paths := discoverRolloutClosureLedgerExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureLedgerManifest{}, "", "", errors.New("YARA-RDK-001: rollout closure docket export requires at least one rollout closure ledger manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureLedgerManifest{}, "", "", fmt.Errorf("read latest rollout closure ledger %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosureLedgerManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosureLedgerManifest{}, "", "", fmt.Errorf("decode latest rollout closure ledger %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosureLedgerManifest{}, "", "", errors.New("YARA-RDK-002: latest rollout closure ledger manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureDocket(workspacePath string) (workflowRolloutClosureDocketManifest, string, string, error) {
	paths := discoverRolloutClosureDocketExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureDocketManifest{}, "", "", errors.New("YARA-RBL-001: rollout closure bulletin export requires at least one rollout closure docket manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureDocketManifest{}, "", "", fmt.Errorf("read latest rollout closure docket %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosureDocketManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosureDocketManifest{}, "", "", fmt.Errorf("decode latest rollout closure docket %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosureDocketManifest{}, "", "", errors.New("YARA-RBL-002: latest rollout closure docket manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureBulletin(workspacePath string) (workflowRolloutClosureBulletinManifest, string, string, error) {
	paths := discoverRolloutClosureBulletinExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureBulletinManifest{}, "", "", errors.New("YARA-RPT-001: rollout closure packet export requires at least one rollout closure bulletin manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureBulletinManifest{}, "", "", fmt.Errorf("read latest rollout closure bulletin %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosureBulletinManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosureBulletinManifest{}, "", "", fmt.Errorf("decode latest rollout closure bulletin %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosureBulletinManifest{}, "", "", errors.New("YARA-RPT-002: latest rollout closure bulletin manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosurePacket(workspacePath string) (workflowRolloutClosurePacketManifest, string, string, error) {
	paths := discoverRolloutClosurePacketExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosurePacketManifest{}, "", "", errors.New("YARA-RPKG-001: rollout closure recipient package export requires at least one rollout closure packet manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosurePacketManifest{}, "", "", fmt.Errorf("read latest rollout closure packet %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosurePacketManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosurePacketManifest{}, "", "", fmt.Errorf("decode latest rollout closure packet %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosurePacketManifest{}, "", "", errors.New("YARA-RPKG-002: latest rollout closure packet manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureRecipientPackage(workspacePath string) (workflowRolloutClosureRecipientPackageManifest, string, string, error) {
	paths := discoverRolloutClosureRecipientPackageExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureRecipientPackageManifest{}, "", "", errors.New("YARA-RCV-001: rollout closure verify requires at least one rollout closure recipient package manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, "", "", fmt.Errorf("read latest rollout closure recipient package %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosureRecipientPackageManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosureRecipientPackageManifest{}, "", "", fmt.Errorf("decode latest rollout closure recipient package %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosureRecipientPackageManifest{}, "", "", errors.New("YARA-RCV-002: latest rollout closure recipient package manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureVerifyExportBundle(workspacePath string) (workflowRolloutClosureVerifyExportBundle, string, string, error) {
	paths := discoverRolloutClosureVerifyExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureVerifyExportBundle{}, "", "", errors.New("YARA-RCVA-001: rollout closure verify attestation requires at least one closure verification export json")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureVerifyExportBundle{}, "", "", fmt.Errorf("read latest closure verification export %s: %w", filepath.Base(latestPath), err)
	}
	bundle := workflowRolloutClosureVerifyExportBundle{}
	if err := json.Unmarshal(content, &bundle); err != nil {
		return workflowRolloutClosureVerifyExportBundle{}, "", "", fmt.Errorf("decode latest closure verification export %s: %w", filepath.Base(latestPath), err)
	}
	if !bundle.Valid {
		return workflowRolloutClosureVerifyExportBundle{}, "", "", errors.New("YARA-RCVA-002: latest closure verification export bundle is invalid")
	}
	return bundle, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureVerifyAttestation(workspacePath string) (workflowRolloutClosureVerifyAttestationManifest, string, string, error) {
	paths := discoverRolloutClosureVerifyAttestationExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureVerifyAttestationManifest{}, "", "", errors.New("YARA-RCVAI-001: rollout closure verify attestation index export requires at least one closure verification attestation manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureVerifyAttestationManifest{}, "", "", fmt.Errorf("read latest closure verification attestation %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosureVerifyAttestationManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosureVerifyAttestationManifest{}, "", "", fmt.Errorf("decode latest closure verification attestation %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosureVerifyAttestationManifest{}, "", "", errors.New("YARA-RCVAI-002: latest closure verification attestation manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func loadLatestRolloutClosureVerifyAttestationIndex(workspacePath string) (workflowRolloutClosureVerifyAttestationIndexManifest, string, string, error) {
	paths := discoverRolloutClosureVerifyAttestationIndexExports(workspacePath)
	if len(paths) == 0 {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, "", "", errors.New("YARA-RCVP-001: verification publication package export requires at least one closure verification attestation index manifest")
	}
	latestPath := paths[len(paths)-1]
	content, err := os.ReadFile(latestPath)
	if err != nil {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, "", "", fmt.Errorf("read latest closure verification attestation index %s: %w", filepath.Base(latestPath), err)
	}
	manifest := workflowRolloutClosureVerifyAttestationIndexManifest{}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, "", "", fmt.Errorf("decode latest closure verification attestation index %s: %w", filepath.Base(latestPath), err)
	}
	if !manifest.Valid {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, "", "", errors.New("YARA-RCVP-002: latest closure verification attestation index manifest is invalid")
	}
	return manifest, latestPath, digestBytes(content), nil
}

func verifyWorkflowRolloutClosureChain(workspacePath string) workflowRolloutClosureVerifyResponse {
	response := workflowRolloutClosureVerifyResponse{Valid: true}
	response.Verification.WorkspacePath = workspacePath
	response.Verification.Ready = false
	response.Verification.VerificationState = "blocked"
	response.Verification.Coverage = []workflowClosureVerifyCoverage{
		{Artifact: "recipient-package", Status: "not-evaluated"},
		{Artifact: "packet", Status: "not-evaluated"},
		{Artifact: "bulletin", Status: "not-evaluated"},
		{Artifact: "docket", Status: "not-evaluated"},
		{Artifact: "ledger", Status: "not-evaluated"},
		{Artifact: "certificate", Status: "not-evaluated"},
		{Artifact: "acceptance", Status: "not-evaluated"},
		{Artifact: "delivery", Status: "not-evaluated"},
		{Artifact: "summary", Status: "not-evaluated"},
		{Artifact: "acknowledgment", Status: "not-evaluated"},
		{Artifact: "handoff", Status: "not-evaluated"},
		{Artifact: "envelope", Status: "not-evaluated"},
		{Artifact: "package", Status: "not-evaluated"},
		{Artifact: "index", Status: "not-evaluated"},
		{Artifact: "attestation", Status: "not-evaluated"},
		{Artifact: "decision", Status: "not-evaluated"},
		{Artifact: "closure", Status: "not-evaluated"},
		{Artifact: "review", Status: "not-evaluated"},
	}
	indexByArtifact := map[string]int{}
	for index := range response.Verification.Coverage {
		indexByArtifact[response.Verification.Coverage[index].Artifact] = index
	}
	setCoverage := func(artifact, status, path, digest, state, reason string) {
		index, ok := indexByArtifact[artifact]
		if !ok {
			return
		}
		response.Verification.Coverage[index] = workflowClosureVerifyCoverage{
			Artifact: artifact,
			Status:   status,
			Path:     path,
			Digest:   digest,
			State:    state,
			Reason:   reason,
		}
	}
	fail := func(code, artifact, reason, remediation string) workflowRolloutClosureVerifyResponse {
		setCoverage(artifact, "blocked", "", "", "", reason)
		response.Verification.BlockerCode = code
		response.Verification.Diagnostics = append(response.Verification.Diagnostics, workflowCapsuleBlocker{
			Code:        code,
			Severity:    "error",
			Message:     reason,
			Remediation: remediation,
		})
		return response
	}
	failMismatch := func(code, artifact, path, digest, state, reason, remediation string) workflowRolloutClosureVerifyResponse {
		setCoverage(artifact, "mismatched", path, digest, state, reason)
		response.Verification.BlockerCode = code
		response.Verification.Diagnostics = append(response.Verification.Diagnostics, workflowCapsuleBlocker{
			Code:        code,
			Severity:    "error",
			Message:     reason,
			Remediation: remediation,
		})
		return response
	}
	recipientPackage, recipientPackagePath, recipientPackageDigest, err := loadLatestRolloutClosureRecipientPackage(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "recipient-package", "rollout closure recipient package manifest is missing", "export rollout closure recipient package before verification")
		}
		return fail("YARA-RCV-002", "recipient-package", "rollout closure recipient package manifest is malformed", "regenerate the recipient package manifest from the latest packet")
	}
	setCoverage("recipient-package", "verified", recipientPackagePath, recipientPackageDigest, recipientPackage.RecipientPackage.RecipientPackageState, "")
	packet, packetPath, packetDigest, err := loadLatestRolloutClosurePacket(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "packet", "rollout closure packet manifest is missing", "export rollout closure packet before verification")
		}
		return fail("YARA-RCV-002", "packet", "rollout closure packet manifest is malformed", "regenerate the packet manifest from the latest bulletin")
	}
	setCoverage("packet", "verified", packetPath, packetDigest, packet.Packet.PacketState, "")
	bulletin, bulletinPath, bulletinDigest, err := loadLatestRolloutClosureBulletin(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "bulletin", "rollout closure bulletin manifest is missing", "export rollout closure bulletin before verification")
		}
		return fail("YARA-RCV-002", "bulletin", "rollout closure bulletin manifest is malformed", "regenerate the bulletin manifest from the latest docket")
	}
	setCoverage("bulletin", "verified", bulletinPath, bulletinDigest, bulletin.Bulletin.BulletinState, "")
	docket, docketPath, docketDigest, err := loadLatestRolloutClosureDocket(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "docket", "rollout closure docket manifest is missing", "export rollout closure docket before verification")
		}
		return fail("YARA-RCV-002", "docket", "rollout closure docket manifest is malformed", "regenerate the docket manifest from the latest ledger")
	}
	setCoverage("docket", "verified", docketPath, docketDigest, docket.Docket.DocketState, "")
	ledger, ledgerPath, ledgerDigest, err := loadLatestRolloutClosureLedger(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "ledger", "rollout closure ledger manifest is missing", "export rollout closure ledger before verification")
		}
		return fail("YARA-RCV-002", "ledger", "rollout closure ledger manifest is malformed", "regenerate the ledger manifest from the latest certificate")
	}
	setCoverage("ledger", "verified", ledgerPath, ledgerDigest, ledger.Ledger.LedgerState, "")
	certificate, certificatePath, certificateDigest, err := loadLatestRolloutClosureCertificate(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "certificate", "rollout closure certificate manifest is missing", "export rollout closure certificate before verification")
		}
		return fail("YARA-RCV-002", "certificate", "rollout closure certificate manifest is malformed", "regenerate the certificate manifest from the latest acceptance receipt")
	}
	setCoverage("certificate", "verified", certificatePath, certificateDigest, certificate.Certificate.CertificateState, "")
	acceptance, acceptancePath, acceptanceDigest, err := loadLatestRolloutClosureAcceptance(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "acceptance", "rollout closure acceptance manifest is missing", "export rollout closure acceptance before verification")
		}
		return fail("YARA-RCV-002", "acceptance", "rollout closure acceptance manifest is malformed", "regenerate the acceptance manifest from the latest delivery record")
	}
	setCoverage("acceptance", "verified", acceptancePath, acceptanceDigest, acceptance.Acceptance.AcceptanceState, "")
	delivery, deliveryPath, deliveryDigest, err := loadLatestRolloutClosureDelivery(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "delivery", "rollout closure delivery manifest is missing", "export rollout closure delivery before verification")
		}
		return fail("YARA-RCV-002", "delivery", "rollout closure delivery manifest is malformed", "regenerate the delivery manifest from the latest summary")
	}
	setCoverage("delivery", "verified", deliveryPath, deliveryDigest, delivery.Delivery.DeliveryRecordState, "")
	summary, summaryPath, summaryDigest, err := loadLatestRolloutClosureSummary(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "summary", "rollout closure summary manifest is missing", "export rollout closure summary before verification")
		}
		return fail("YARA-RCV-002", "summary", "rollout closure summary manifest is malformed", "regenerate the summary manifest from the latest acknowledgment")
	}
	setCoverage("summary", "verified", summaryPath, summaryDigest, summary.Summary.SummaryState, "")
	acknowledgment, acknowledgmentPath, acknowledgmentDigest, err := loadLatestReleasePublicationAcknowledgment(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "acknowledgment", "release publication acknowledgment manifest is missing", "export release publication acknowledgment before verification")
		}
		return fail("YARA-RCV-002", "acknowledgment", "release publication acknowledgment manifest is malformed", "regenerate the acknowledgment manifest from the latest handoff receipt")
	}
	setCoverage("acknowledgment", "verified", acknowledgmentPath, acknowledgmentDigest, acknowledgment.Acknowledgment.AcknowledgmentState, "")
	handoff, handoffPath, handoffDigest, err := loadLatestReleasePublicationHandoffReceipt(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "handoff", "release publication handoff receipt is missing", "export release publication handoff receipt before verification")
		}
		return fail("YARA-RCV-002", "handoff", "release publication handoff receipt is malformed", "regenerate the handoff receipt from the latest envelope")
	}
	setCoverage("handoff", "verified", handoffPath, handoffDigest, handoff.Handoff.HandoffState, "")
	envelope, envelopePath, envelopeDigest, err := loadLatestReleasePublicationEnvelope(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "envelope", "release publication envelope manifest is missing", "export release publication envelope before verification")
		}
		return fail("YARA-RCV-002", "envelope", "release publication envelope manifest is malformed", "regenerate the envelope manifest from the latest package")
	}
	setCoverage("envelope", "verified", envelopePath, envelopeDigest, envelope.Envelope.DeliveryState, "")
	pkg, packagePath, packageDigest, err := loadLatestReleasePublicationPackage(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "package", "release publication package manifest is missing", "export release publication package before verification")
		}
		return fail("YARA-RCV-002", "package", "release publication package manifest is malformed", "regenerate the package manifest from the latest index")
	}
	setCoverage("package", "verified", packagePath, packageDigest, pkg.Package.PackageState, "")
	index, indexPath, indexDigest, err := loadLatestReleasePublicationIndex(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "index", "release publication index manifest is missing", "export release publication index before verification")
		}
		return fail("YARA-RCV-002", "index", "release publication index manifest is malformed", "regenerate the index manifest from the latest attestation")
	}
	setCoverage("index", "verified", indexPath, indexDigest, index.Index.IndexState, "")
	attestation, attestationPath, attestationDigest, err := loadLatestReleasePublication(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "attestation", "release publication attestation is missing", "export release publication attestation before verification")
		}
		return fail("YARA-RCV-002", "attestation", "release publication attestation is malformed", "regenerate the publication attestation from the latest decision")
	}
	setCoverage("attestation", "verified", attestationPath, attestationDigest, attestation.Publication.PublicationState, "")
	decision, decisionPath, decisionDigest, err := loadLatestReleaseDecision(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "decision", "release decision ledger is missing", "export release decision ledger before verification")
		}
		return fail("YARA-RCV-002", "decision", "release decision ledger is malformed", "regenerate the release decision ledger from the latest review gate")
	}
	setCoverage("decision", "verified", decisionPath, decisionDigest, decision.Ledger.PublicationState, "")
	closure, closurePath, closureDigest, err := loadLatestClosurePackage(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "closure", "workflow closure package manifest is missing", "export workflow closure package before verification")
		}
		return fail("YARA-RCV-002", "closure", "workflow closure package manifest is malformed", "regenerate closure package from receipt timeline and evidence bundle")
	}
	setCoverage("closure", "verified", closurePath, closureDigest, "present", "")
	review, reviewPath, reviewDigest, err := loadLatestClosureReviewGate(workspacePath)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "requires at least one") {
			return fail("YARA-RCV-001", "review", "closure review gate artifact is missing", "export closure review gate before verification")
		}
		return fail("YARA-RCV-002", "review", "closure review gate artifact is malformed", "regenerate closure review gate from latest closure package")
	}
	setCoverage("review", "verified", reviewPath, reviewDigest, review.Gate.Outcome, "")
	expectedStates := []struct {
		artifact string
		state    string
		path     string
		digest   string
		expected string
	}{
		{"recipient-package", recipientPackage.RecipientPackage.RecipientPackageState, recipientPackagePath, recipientPackageDigest, "recipient-package-ready"},
		{"packet", packet.Packet.PacketState, packetPath, packetDigest, "packet-ready"},
		{"bulletin", bulletin.Bulletin.BulletinState, bulletinPath, bulletinDigest, "bulletin-ready"},
		{"docket", docket.Docket.DocketState, docketPath, docketDigest, "docket-ready"},
		{"ledger", ledger.Ledger.LedgerState, ledgerPath, ledgerDigest, "ledger-ready"},
		{"certificate", certificate.Certificate.CertificateState, certificatePath, certificateDigest, "certificate-ready"},
		{"acceptance", acceptance.Acceptance.AcceptanceState, acceptancePath, acceptanceDigest, "acceptance-ready"},
		{"delivery", delivery.Delivery.DeliveryRecordState, deliveryPath, deliveryDigest, "delivery-record-ready"},
		{"summary", summary.Summary.SummaryState, summaryPath, summaryDigest, "summary-ready"},
		{"acknowledgment", acknowledgment.Acknowledgment.AcknowledgmentState, acknowledgmentPath, acknowledgmentDigest, "acknowledgment-ready"},
		{"handoff", handoff.Handoff.HandoffState, handoffPath, handoffDigest, "handoff-ready"},
		{"envelope", envelope.Envelope.DeliveryState, envelopePath, envelopeDigest, "delivery-ready"},
		{"package", pkg.Package.PackageState, packagePath, packageDigest, "package-ready"},
		{"index", index.Index.IndexState, indexPath, indexDigest, "index-ready"},
		{"attestation", attestation.Publication.PublicationState, attestationPath, attestationDigest, "publishable"},
		{"decision", decision.Ledger.PublicationState, decisionPath, decisionDigest, "ready-to-publish"},
		{"review", review.Gate.Outcome, reviewPath, reviewDigest, "passed"},
	}
	for _, check := range expectedStates {
		if check.state != check.expected {
			return failMismatch(
				"YARA-RCV-003",
				check.artifact,
				check.path,
				check.digest,
				check.state,
				fmt.Sprintf("artifact state %q does not match required %q for %s", check.state, check.expected, check.artifact),
				"regenerate the blocked artifact and re-run verification",
			)
		}
	}
	continuity := recipientPackage.RecipientPackage.Continuity
	response.Verification.Continuity = continuity
	if continuity != packet.Packet.Continuity ||
		continuity != bulletin.Bulletin.Continuity ||
		continuity != docket.Docket.Continuity ||
		continuity != ledger.Ledger.Continuity ||
		continuity != certificate.Certificate.Continuity ||
		continuity != acceptance.Acceptance.Continuity ||
		continuity != delivery.Delivery.Continuity ||
		continuity != summary.Summary.Continuity ||
		continuity != acknowledgment.Acknowledgment.Continuity ||
		continuity != handoff.Handoff.Continuity ||
		continuity != envelope.Envelope.Continuity ||
		continuity != pkg.Package.Continuity ||
		continuity != index.Index.Continuity ||
		continuity != attestation.Publication.Continuity ||
		continuity != decision.Ledger.Continuity ||
		continuity != closure.Package.Continuity ||
		continuity != review.Gate.Continuity {
		return fail("YARA-RCV-005", "recipient-package", "closure publication continuity chains are mismatched", "rebuild downstream artifacts from the latest consistent closure package")
	}
	if recipientPackage.RecipientPackage.ReleasePacket.Digest != packetDigest ||
		recipientPackage.RecipientPackage.ReleaseBulletin.Digest != bulletinDigest ||
		recipientPackage.RecipientPackage.HandoffDocket.Digest != docketDigest ||
		recipientPackage.RecipientPackage.ArchivalLedger.Digest != ledgerDigest ||
		recipientPackage.RecipientPackage.PublicationCertificate.Digest != certificateDigest ||
		recipientPackage.RecipientPackage.AcceptanceReceipt.Digest != acceptanceDigest ||
		recipientPackage.RecipientPackage.DeliveryRecord.Digest != deliveryDigest ||
		recipientPackage.RecipientPackage.ClosureSummary.Digest != summaryDigest ||
		recipientPackage.RecipientPackage.Acknowledgment.Digest != acknowledgmentDigest ||
		recipientPackage.RecipientPackage.HandoffReceipt.Digest != handoffDigest ||
		recipientPackage.RecipientPackage.ReleasePublicationEnvelope.Digest != envelopeDigest ||
		recipientPackage.RecipientPackage.ReleasePublicationPackage.Digest != packageDigest ||
		recipientPackage.RecipientPackage.ReleasePublicationIndex.Digest != indexDigest ||
		recipientPackage.RecipientPackage.ReleasePublication.Digest != attestationDigest ||
		recipientPackage.RecipientPackage.ReleaseDecision.Digest != decisionDigest ||
		recipientPackage.RecipientPackage.ClosurePackage.Digest != closureDigest ||
		recipientPackage.RecipientPackage.ReviewGate.Digest != reviewDigest {
		return fail("YARA-RCV-004", "recipient-package", "recipient package digest bindings do not match the latest closure publication chain", "regenerate recipient package from the latest packet and closure publication chain")
	}
	if packet.Packet.ReleaseBulletin.Digest != bulletinDigest ||
		packet.Packet.HandoffDocket.Digest != docketDigest ||
		packet.Packet.ArchivalLedger.Digest != ledgerDigest ||
		packet.Packet.PublicationCertificate.Digest != certificateDigest ||
		packet.Packet.AcceptanceReceipt.Digest != acceptanceDigest ||
		packet.Packet.DeliveryRecord.Digest != deliveryDigest ||
		packet.Packet.ClosureSummary.Digest != summaryDigest ||
		packet.Packet.Acknowledgment.Digest != acknowledgmentDigest ||
		packet.Packet.HandoffReceipt.Digest != handoffDigest ||
		packet.Packet.ReleasePublicationEnvelope.Digest != envelopeDigest ||
		packet.Packet.ReleasePublicationPackage.Digest != packageDigest ||
		packet.Packet.ReleasePublicationIndex.Digest != indexDigest ||
		packet.Packet.ReleasePublication.Digest != attestationDigest ||
		packet.Packet.ReleaseDecision.Digest != decisionDigest ||
		packet.Packet.ClosurePackage.Digest != closureDigest ||
		packet.Packet.ReviewGate.Digest != reviewDigest {
		return fail("YARA-RCV-004", "packet", "packet digest bindings do not match the latest closure publication chain", "regenerate packet from the latest bulletin and closure publication chain")
	}
	response.Verification.Ready = true
	response.Verification.VerificationState = "pass"
	response.Verification.Diagnostics = []workflowCapsuleBlocker{}
	return response
}

func buildWorkflowRolloutClosureVerifyAttestationManifest(workspacePath string, payload workflowRolloutClosureVerifyAttestationExportRequest) (workflowRolloutClosureVerifyAttestationManifest, []audit.Subject, error) {
	verifyExport, verifyExportPath, verifyExportDigest, err := loadLatestRolloutClosureVerifyExportBundle(workspacePath)
	if err != nil {
		return workflowRolloutClosureVerifyAttestationManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	if !verifyExport.Export.Ready && strings.TrimSpace(verifyExport.Export.AllowBlockedReasonReference) == "" {
		return workflowRolloutClosureVerifyAttestationManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVA-003: latest closure verification export is blocked without archived blocked reason reference",
		}
	}
	currentVerification := verifyWorkflowRolloutClosureChain(workspacePath)
	if verifyExport.Export.Continuity != currentVerification.Verification.Continuity {
		return workflowRolloutClosureVerifyAttestationManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVA-004: latest closure verification export continuity diverges from current closure verification chain",
		}
	}
	verifyMarkdownPath := strings.TrimSuffix(verifyExportPath, ".json") + ".md"
	verifyMarkdownBytes, err := os.ReadFile(verifyMarkdownPath)
	if err != nil {
		return workflowRolloutClosureVerifyAttestationManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVA-005: latest closure verification markdown export is missing or unreadable",
		}
	}
	verifyJSONBytes, err := os.ReadFile(verifyExportPath)
	if err != nil {
		return workflowRolloutClosureVerifyAttestationManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVA-006: latest closure verification json export is missing or unreadable",
		}
	}
	attestationState := "attestation-ready"
	if !verifyExport.Export.Ready {
		attestationState = "attested-blocked"
	}
	manifest := workflowRolloutClosureVerifyAttestationManifest{Valid: true}
	manifest.Attestation.WorkspacePath = workspacePath
	manifest.Attestation.AttestationReference = strings.TrimSpace(payload.AttestationReference)
	manifest.Attestation.AttestedByReference = strings.TrimSpace(payload.AttestedByReference)
	manifest.Attestation.AttestationTimestamp = strings.TrimSpace(payload.AttestationTimestamp)
	manifest.Attestation.AttestationState = attestationState
	manifest.Attestation.Continuity = verifyExport.Export.Continuity
	manifest.Attestation.VerificationExport = workflowClosureArtifact{Path: verifyExportPath, Digest: verifyExportDigest}
	manifest.Attestation.VerificationMarkdown = workflowClosureArtifact{Path: verifyMarkdownPath, Digest: digestBytes(verifyMarkdownBytes)}
	manifest.Attestation.VerificationReference = verifyExport.Export.VerificationReference
	manifest.Attestation.OperatorReference = verifyExport.Export.OperatorReference
	manifest.Attestation.VerificationTimestamp = verifyExport.Export.VerificationTimestamp
	manifest.Attestation.VerificationState = verifyExport.Export.VerificationState
	manifest.Attestation.VerificationBlocker = verifyExport.Export.BlockerCode
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosureVerifyJSON", Digest: digestBytes(verifyJSONBytes)},
		{Kind: "WorkflowRolloutClosureVerifyMarkdown", Digest: digestBytes(verifyMarkdownBytes)},
		{
			Kind: "WorkflowRolloutClosureVerifyAttestationReference",
			Digest: digestBytes([]byte(strings.Join([]string{
				manifest.Attestation.AttestationReference,
				manifest.Attestation.AttestedByReference,
				manifest.Attestation.AttestationTimestamp,
				verifyExport.Export.VerificationReference,
				verifyExport.Export.OperatorReference,
				verifyExport.Export.VerificationTimestamp,
				verifyExport.Export.Continuity.AuthorizationID,
				verifyExport.Export.Continuity.TargetDigest,
			}, "|"))),
		},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosureVerifyAttestationIndexManifest(workspacePath string, payload workflowRolloutClosureVerifyAttestationIndexExportRequest) (workflowRolloutClosureVerifyAttestationIndexManifest, []audit.Subject, error) {
	attestation, attestationPath, attestationDigest, err := loadLatestRolloutClosureVerifyAttestation(workspacePath)
	if err != nil {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	verifyExport, verifyExportPath, verifyExportDigest, err := loadLatestRolloutClosureVerifyExportBundle(workspacePath)
	if err != nil {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	verifyMarkdownPath := strings.TrimSuffix(verifyExportPath, ".json") + ".md"
	verifyMarkdownBytes, err := os.ReadFile(verifyMarkdownPath)
	if err != nil {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVAI-003: latest closure verification markdown export is missing or unreadable",
		}
	}
	if !verifyExport.Export.Ready && strings.TrimSpace(verifyExport.Export.AllowBlockedReasonReference) == "" {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVAI-004: latest closure verification export is blocked without archived blocked reason reference",
		}
	}
	if attestation.Attestation.AttestationState == "attested-blocked" && strings.TrimSpace(verifyExport.Export.AllowBlockedReasonReference) == "" {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVAI-005: latest closure verification attestation is blocked without archived blocked reason reference",
		}
	}
	currentVerification := verifyWorkflowRolloutClosureChain(workspacePath)
	if attestation.Attestation.Continuity != verifyExport.Export.Continuity || attestation.Attestation.Continuity != currentVerification.Verification.Continuity {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVAI-006: latest attestation/export continuity diverges from current closure verification chain",
		}
	}
	if attestation.Attestation.VerificationExport.Digest != verifyExportDigest {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVAI-007: latest verification attestation does not bind the latest verification export digest",
		}
	}
	verifyMarkdownDigest := digestBytes(verifyMarkdownBytes)
	if attestation.Attestation.VerificationMarkdown.Digest != verifyMarkdownDigest {
		return workflowRolloutClosureVerifyAttestationIndexManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVAI-008: latest verification attestation does not bind the latest verification markdown digest",
		}
	}
	indexState := "index-ready"
	blockerCode := ""
	if attestation.Attestation.AttestationState == "attested-blocked" || !verifyExport.Export.Ready {
		indexState = "index-blocked"
		blockerCode = mapValueOrDefault(verifyExport.Export.BlockerCode, "YARA-RCVAI-004")
	}
	manifest := workflowRolloutClosureVerifyAttestationIndexManifest{Valid: true}
	manifest.Index.WorkspacePath = workspacePath
	manifest.Index.AttestationIndexReference = strings.TrimSpace(payload.AttestationIndexReference)
	manifest.Index.PublishedByReference = strings.TrimSpace(payload.PublishedByReference)
	manifest.Index.PublishedTimestamp = strings.TrimSpace(payload.PublishedTimestamp)
	manifest.Index.IndexState = indexState
	manifest.Index.BlockerCode = blockerCode
	manifest.Index.Continuity = attestation.Attestation.Continuity
	manifest.Index.VerificationAttestation = workflowClosureArtifact{Path: attestationPath, Digest: attestationDigest}
	manifest.Index.VerificationExportJSON = workflowClosureArtifact{Path: verifyExportPath, Digest: verifyExportDigest}
	manifest.Index.VerificationExportMarkdown = workflowClosureArtifact{Path: verifyMarkdownPath, Digest: verifyMarkdownDigest}
	manifest.Index.AttestationReference = attestation.Attestation.AttestationReference
	manifest.Index.AttestedByReference = attestation.Attestation.AttestedByReference
	manifest.Index.AttestationTimestamp = attestation.Attestation.AttestationTimestamp
	manifest.Index.VerificationReference = attestation.Attestation.VerificationReference
	manifest.Index.OperatorReference = attestation.Attestation.OperatorReference
	manifest.Index.VerificationTimestamp = attestation.Attestation.VerificationTimestamp
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosureVerifyAttestation", Digest: attestationDigest},
		{Kind: "WorkflowRolloutClosureVerifyJSON", Digest: verifyExportDigest},
		{Kind: "WorkflowRolloutClosureVerifyMarkdown", Digest: verifyMarkdownDigest},
		{
			Kind: "WorkflowRolloutClosureVerifyAttestationIndexReference",
			Digest: digestBytes([]byte(strings.Join([]string{
				manifest.Index.AttestationIndexReference,
				manifest.Index.PublishedByReference,
				manifest.Index.PublishedTimestamp,
				manifest.Index.AttestationReference,
				manifest.Index.VerificationReference,
				manifest.Index.Continuity.AuthorizationID,
				manifest.Index.Continuity.TargetDigest,
				manifest.Index.BlockerCode,
			}, "|"))),
		},
	}
	return manifest, subjects, nil
}

func buildWorkflowRolloutClosureVerifyPublicationPackageManifest(workspacePath string, payload workflowRolloutClosureVerifyPublicationPackageExportRequest) (workflowRolloutClosureVerifyPublicationPackageManifest, []audit.Subject, error) {
	attestationIndex, attestationIndexPath, attestationIndexDigest, err := loadLatestRolloutClosureVerifyAttestationIndex(workspacePath)
	if err != nil {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	attestation, attestationPath, attestationDigest, err := loadLatestRolloutClosureVerifyAttestation(workspacePath)
	if err != nil {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	verifyExport, verifyExportPath, verifyExportDigest, err := loadLatestRolloutClosureVerifyExportBundle(workspacePath)
	if err != nil {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{Status: http.StatusUnprocessableEntity, Err: err.Error()}
	}
	verifyMarkdownPath := strings.TrimSuffix(verifyExportPath, ".json") + ".md"
	verifyMarkdownBytes, err := os.ReadFile(verifyMarkdownPath)
	if err != nil {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVP-003: latest closure verification markdown export is missing or unreadable",
		}
	}
	if !verifyExport.Export.Ready && strings.TrimSpace(verifyExport.Export.AllowBlockedReasonReference) == "" {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVP-004: latest closure verification export is blocked without archived blocked reason reference",
		}
	}
	if attestation.Attestation.AttestationState == "attested-blocked" && strings.TrimSpace(verifyExport.Export.AllowBlockedReasonReference) == "" {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVP-005: latest closure verification attestation is blocked without archived blocked reason reference",
		}
	}
	if attestationIndex.Index.IndexState == "index-blocked" && strings.TrimSpace(verifyExport.Export.AllowBlockedReasonReference) == "" {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVP-006: latest closure verification attestation index is blocked without archived blocked reason reference",
		}
	}
	currentVerification := verifyWorkflowRolloutClosureChain(workspacePath)
	if attestationIndex.Index.Continuity != attestation.Attestation.Continuity ||
		attestationIndex.Index.Continuity != verifyExport.Export.Continuity ||
		attestationIndex.Index.Continuity != currentVerification.Verification.Continuity {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVP-007: latest attestation index/attestation/export continuity diverges from current closure verification chain",
		}
	}
	if attestationIndex.Index.VerificationAttestation.Digest != attestationDigest {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVP-008: latest attestation index does not bind the latest verification attestation digest",
		}
	}
	if attestationIndex.Index.VerificationExportJSON.Digest != verifyExportDigest {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVP-009: latest attestation index does not bind the latest verification export json digest",
		}
	}
	verifyMarkdownDigest := digestBytes(verifyMarkdownBytes)
	if attestationIndex.Index.VerificationExportMarkdown.Digest != verifyMarkdownDigest {
		return workflowRolloutClosureVerifyPublicationPackageManifest{}, nil, workflowGateError{
			Status: http.StatusUnprocessableEntity,
			Err:    "YARA-RCVP-010: latest attestation index does not bind the latest verification export markdown digest",
		}
	}
	packageState := "package-ready"
	blockerCode := ""
	if attestationIndex.Index.IndexState == "index-blocked" || attestation.Attestation.AttestationState == "attested-blocked" || !verifyExport.Export.Ready {
		packageState = "package-blocked"
		blockerCode = mapValueOrDefault(verifyExport.Export.BlockerCode, "YARA-RCVP-004")
	}
	manifest := workflowRolloutClosureVerifyPublicationPackageManifest{Valid: true}
	manifest.Package.WorkspacePath = workspacePath
	manifest.Package.VerificationPackageReference = strings.TrimSpace(payload.VerificationPackageReference)
	manifest.Package.PackagedByReference = strings.TrimSpace(payload.PackagedByReference)
	manifest.Package.PackagedTimestamp = strings.TrimSpace(payload.PackagedTimestamp)
	manifest.Package.PackageState = packageState
	manifest.Package.BlockerCode = blockerCode
	manifest.Package.Continuity = attestationIndex.Index.Continuity
	manifest.Package.VerificationAttestationIndex = workflowClosureArtifact{Path: attestationIndexPath, Digest: attestationIndexDigest}
	manifest.Package.VerificationAttestation = workflowClosureArtifact{Path: attestationPath, Digest: attestationDigest}
	manifest.Package.VerificationExportJSON = workflowClosureArtifact{Path: verifyExportPath, Digest: verifyExportDigest}
	manifest.Package.VerificationExportMarkdown = workflowClosureArtifact{Path: verifyMarkdownPath, Digest: verifyMarkdownDigest}
	manifest.Package.AttestationIndexReference = attestationIndex.Index.AttestationIndexReference
	manifest.Package.PublishedByReference = attestationIndex.Index.PublishedByReference
	manifest.Package.PublishedTimestamp = attestationIndex.Index.PublishedTimestamp
	manifest.Package.AttestationReference = attestationIndex.Index.AttestationReference
	manifest.Package.VerificationReference = attestationIndex.Index.VerificationReference
	manifest.Package.OperatorReference = attestationIndex.Index.OperatorReference
	manifest.Package.VerificationTimestamp = attestationIndex.Index.VerificationTimestamp
	subjects := []audit.Subject{
		{Kind: "WorkflowRolloutClosureVerifyAttestationIndexManifest", Digest: attestationIndexDigest},
		{Kind: "WorkflowRolloutClosureVerifyAttestation", Digest: attestationDigest},
		{Kind: "WorkflowRolloutClosureVerifyJSON", Digest: verifyExportDigest},
		{Kind: "WorkflowRolloutClosureVerifyMarkdown", Digest: verifyMarkdownDigest},
		{
			Kind: "WorkflowRolloutClosureVerifyPublicationPackageReference",
			Digest: digestBytes([]byte(strings.Join([]string{
				manifest.Package.VerificationPackageReference,
				manifest.Package.PackagedByReference,
				manifest.Package.PackagedTimestamp,
				manifest.Package.AttestationIndexReference,
				manifest.Package.AttestationReference,
				manifest.Package.VerificationReference,
				manifest.Package.Continuity.AuthorizationID,
				manifest.Package.Continuity.TargetDigest,
				manifest.Package.BlockerCode,
			}, "|"))),
		},
	}
	return manifest, subjects, nil
}

func workflowCoreArtifacts(workspacePath string) (map[string]string, []string, error) {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read workspace directory: %w", err)
	}
	stageLookup := map[string]string{}
	receiptPaths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		fullPath := filepath.Join(workspacePath, name)
		kind, err := detectResourceKind(fullPath)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect workspace artifact %s: %w", filepath.Base(fullPath), err)
		}
		if kind == "DeploymentReceipt" {
			receiptPaths = append(receiptPaths, fullPath)
			continue
		}
		stageID, err := classifyWorkspaceArtifact(fullPath)
		if err != nil {
			return nil, nil, err
		}
		if stageID == "receipt" {
			receiptPaths = append(receiptPaths, fullPath)
			continue
		}
		if existing := stageLookup[stageID]; existing != "" {
			return nil, nil, fmt.Errorf("multiple workspace artifacts matched stage %s: %s and %s", stageID, filepath.Base(existing), filepath.Base(fullPath))
		}
		stageLookup[stageID] = fullPath
	}
	sort.Strings(receiptPaths)
	return stageLookup, receiptPaths, nil
}

func loadDeploymentReceipts(paths []string) ([]deploymentReceiptFile, error) {
	receipts := make([]deploymentReceiptFile, 0, len(paths))
	targetDigest := ""
	for _, path := range paths {
		receipt, err := resources.LoadDeploymentReceipt(path)
		if err != nil {
			return nil, fmt.Errorf("load receipt %s: %w", filepath.Base(path), err)
		}
		report := receipt.Validate()
		if !report.Valid {
			return nil, fmt.Errorf("receipt %s failed validation: %s", filepath.Base(path), report.Diagnostics[0].Code)
		}
		completedAt, err := time.Parse(time.RFC3339Nano, receipt.Spec.CompletedAt)
		if err != nil {
			return nil, fmt.Errorf("receipt %s has invalid completedAt timestamp", filepath.Base(path))
		}
		if targetDigest == "" {
			targetDigest = receipt.Spec.Target.ReferenceDigest
		} else if receipt.Spec.Target.ReferenceDigest != targetDigest {
			return nil, fmt.Errorf("receipt %s target digest diverges from prior receipt chain", filepath.Base(path))
		}
		receipts = append(receipts, deploymentReceiptFile{
			Path:      path,
			Receipt:   receipt,
			Completed: completedAt,
		})
	}
	return receipts, nil
}

func toWorkflowTimelineReceipt(item deploymentReceiptFile) workflowReceiptTimelineReceipt {
	return workflowReceiptTimelineReceipt{
		ReceiptID:       item.Receipt.Metadata.ReceiptID,
		Path:            item.Path,
		Outcome:         item.Receipt.Spec.Outcome,
		StartedAt:       item.Receipt.Spec.StartedAt,
		CompletedAt:     item.Receipt.Spec.CompletedAt,
		AuthorizationID: item.Receipt.Spec.AuthorizationID,
		TargetDigest:    item.Receipt.Spec.Target.ReferenceDigest,
	}
}

func renderReceiptTimelineMarkdown(timeline workflowReceiptTimelineResponse) string {
	lines := []string{
		"# YARA receipt timeline",
		"",
		"## Continuity",
		"- Authorization ID: " + timeline.Timeline.Continuity.AuthorizationID,
		"- Target digest: " + timeline.Timeline.Continuity.TargetDigest,
		"",
		"## Latest receipt",
		"- Receipt ID: " + timeline.Timeline.Latest.ReceiptID,
		"- Path: " + timeline.Timeline.Latest.Path,
		"- Outcome: " + timeline.Timeline.Latest.Outcome,
		"- Completed at: " + timeline.Timeline.Latest.CompletedAt,
	}
	if len(timeline.Timeline.Prior) > 0 {
		lines = append(lines, "", "## Prior receipts")
		for _, prior := range timeline.Timeline.Prior {
			lines = append(lines, "- "+prior.CompletedAt+" | "+prior.ReceiptID+" | "+prior.Outcome+" | "+prior.Path)
		}
	}
	return strings.Join(lines, "\n")
}

func detectResourceKind(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	envelope := map[string]any{}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", errors.New("resource is empty")
	}
	if trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &envelope); err != nil {
			return "", err
		}
	} else {
		if err := yaml.Unmarshal(trimmed, &envelope); err != nil {
			return "", err
		}
	}
	kind, _ := envelope["kind"].(string)
	return kind, nil
}

func collectRunbookExportReferences(expected workflowRunbookResponse, markdownPaths, jsonPaths []string) ([]workflowExportReference, []audit.Subject, error) {
	jsonSet := map[string]struct{}{}
	for _, path := range jsonPaths {
		jsonSet[path] = struct{}{}
	}
	references := make([]workflowExportReference, 0, len(markdownPaths))
	subjects := []audit.Subject{}
	for _, markdownPath := range markdownPaths {
		base := strings.TrimSuffix(markdownPath, ".runbook.md")
		jsonPath := base + ".runbook.json"
		if _, ok := jsonSet[jsonPath]; !ok {
			return nil, nil, fmt.Errorf("runbook export pair is incomplete for %s", markdownPath)
		}
		markdownBytes, err := os.ReadFile(markdownPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read runbook markdown export %s: %w", markdownPath, err)
		}
		jsonBytes, err := os.ReadFile(jsonPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read runbook json export %s: %w", jsonPath, err)
		}
		var exported workflowRunbookResponse
		if err := json.Unmarshal(jsonBytes, &exported); err != nil {
			return nil, nil, fmt.Errorf("decode runbook json export %s: %w", jsonPath, err)
		}
		if exported.Runbook.Evidence.PlanID != expected.Runbook.Evidence.PlanID ||
			exported.Runbook.Evidence.BundleID != expected.Runbook.Evidence.BundleID ||
			exported.Runbook.Evidence.PreflightResultID != expected.Runbook.Evidence.PreflightResultID ||
			exported.Runbook.Evidence.ChangeSetID != expected.Runbook.Evidence.ChangeSetID ||
			exported.Runbook.Evidence.ApprovalID != expected.Runbook.Evidence.ApprovalID ||
			exported.Runbook.Evidence.AuthorizationID != expected.Runbook.Evidence.AuthorizationID ||
			exported.Runbook.Evidence.TargetReferenceDigest != expected.Runbook.Evidence.TargetReferenceDigest {
			return nil, nil, fmt.Errorf("runbook export %s is not bound to current workflow evidence chain", jsonPath)
		}
		references = append(references, workflowExportReference{
			MarkdownPath: markdownPath,
			JSONPath:     jsonPath,
			MarkdownID:   digestBytes(markdownBytes),
			JSONID:       digestBytes(jsonBytes),
		})
		subjects = append(subjects,
			audit.Subject{Kind: "RunbookMarkdown", Digest: digestBytes(markdownBytes)},
			audit.Subject{Kind: "RunbookJSON", Digest: digestBytes(jsonBytes)},
		)
	}
	sort.Slice(references, func(i, j int) bool { return references[i].JSONPath < references[j].JSONPath })
	return references, subjects, nil
}

func collectCapsuleExportReferences(expected workflowCapsuleResponse, markdownPaths, jsonPaths []string) ([]workflowExportReference, []audit.Subject, error) {
	jsonSet := map[string]struct{}{}
	for _, path := range jsonPaths {
		jsonSet[path] = struct{}{}
	}
	references := make([]workflowExportReference, 0, len(markdownPaths))
	subjects := []audit.Subject{}
	for _, markdownPath := range markdownPaths {
		base := strings.TrimSuffix(markdownPath, ".capsule.md")
		jsonPath := base + ".capsule.json"
		if _, ok := jsonSet[jsonPath]; !ok {
			return nil, nil, fmt.Errorf("capsule export pair is incomplete for %s", markdownPath)
		}
		markdownBytes, err := os.ReadFile(markdownPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read capsule markdown export %s: %w", markdownPath, err)
		}
		jsonBytes, err := os.ReadFile(jsonPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read capsule json export %s: %w", jsonPath, err)
		}
		var exported workflowCapsuleResponse
		if err := json.Unmarshal(jsonBytes, &exported); err != nil {
			return nil, nil, fmt.Errorf("decode capsule json export %s: %w", jsonPath, err)
		}
		if exported.Capsule.Evidence.PlanID != expected.Capsule.Evidence.PlanID ||
			exported.Capsule.Evidence.BundleID != expected.Capsule.Evidence.BundleID ||
			exported.Capsule.Evidence.PreflightResultID != expected.Capsule.Evidence.PreflightResultID ||
			exported.Capsule.Evidence.ChangeSetID != expected.Capsule.Evidence.ChangeSetID ||
			exported.Capsule.Evidence.ApprovalID != expected.Capsule.Evidence.ApprovalID ||
			exported.Capsule.Evidence.AuthorizationID != expected.Capsule.Evidence.AuthorizationID ||
			exported.Capsule.Evidence.TargetReferenceDigest != expected.Capsule.Evidence.TargetReferenceDigest {
			return nil, nil, fmt.Errorf("capsule export %s is not bound to current workflow evidence chain", jsonPath)
		}
		references = append(references, workflowExportReference{
			MarkdownPath: markdownPath,
			JSONPath:     jsonPath,
			MarkdownID:   digestBytes(markdownBytes),
			JSONID:       digestBytes(jsonBytes),
			Ready:        exported.Capsule.Ready,
			Blockers:     len(exported.Capsule.Blockers),
		})
		subjects = append(subjects,
			audit.Subject{Kind: "CapsuleMarkdown", Digest: digestBytes(markdownBytes)},
			audit.Subject{Kind: "CapsuleJSON", Digest: digestBytes(jsonBytes)},
		)
	}
	sort.Slice(references, func(i, j int) bool { return references[i].JSONPath < references[j].JSONPath })
	return references, subjects, nil
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

func discoverCapsuleExports(workspacePath string) ([]string, []string) {
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
		if strings.HasSuffix(name, ".capsule.md") {
			markdownPaths = append(markdownPaths, filepath.Join(workspacePath, name))
		}
		if strings.HasSuffix(name, ".capsule.json") {
			jsonPaths = append(jsonPaths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(markdownPaths)
	sort.Strings(jsonPaths)
	return markdownPaths, jsonPaths
}

func discoverEvidenceBundleExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".evidence-bundle.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverReceiptTimelineExports(workspacePath string) ([]string, []string) {
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
		if strings.HasSuffix(name, ".receipt-timeline.md") {
			markdownPaths = append(markdownPaths, filepath.Join(workspacePath, name))
		}
		if strings.HasSuffix(name, ".receipt-timeline.json") {
			jsonPaths = append(jsonPaths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(markdownPaths)
	sort.Strings(jsonPaths)
	return markdownPaths, jsonPaths
}

func discoverClosurePackageExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".closure-package.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverClosureReviewGateExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".closure-review-gate.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverReleaseDecisionExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".release-decision.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverReleasePublicationExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".release-publication.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverReleasePublicationIndexExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".release-publication.index.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverReleasePublicationPackageExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".release-publication.package.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverReleasePublicationEnvelopeExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".release-publication.envelope.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverReleasePublicationHandoffReceiptExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".release-publication.handoff-receipt.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverReleasePublicationAcknowledgmentExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".release-publication.acknowledgment.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureSummaryExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-summary.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureDeliveryExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-delivery.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureAcceptanceExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-acceptance.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureCertificateExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-certificate.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureLedgerExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-ledger.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureDocketExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-docket.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureBulletinExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-bulletin.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosurePacketExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-packet.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureRecipientPackageExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-recipient-package.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureVerifyExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-verify.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureVerifyAttestationExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-verify.attestation.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func discoverRolloutClosureVerifyAttestationIndexExports(workspacePath string) []string {
	entries, err := os.ReadDir(workspacePath)
	if err != nil {
		return []string{}
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".rollout-closure-verify.attestation.index.json") {
			paths = append(paths, filepath.Join(workspacePath, name))
		}
	}
	sort.Strings(paths)
	return paths
}

func renderCapsuleMarkdown(capsule workflowCapsuleResponse, blockedReasonReference string) string {
	lines := []string{
		"# YARA execution capsule",
		"",
		"## Readiness",
		"- Ready: " + fmt.Sprintf("%t", capsule.Capsule.Ready),
		"- Blocker count: " + fmt.Sprintf("%d", len(capsule.Capsule.Blockers)),
		"",
		"## Evidence",
		"- Plan ID: " + mapValueOrDefault(capsule.Capsule.Evidence.PlanID, "n/a"),
		"- Bundle ID: " + mapValueOrDefault(capsule.Capsule.Evidence.BundleID, "n/a"),
		"- Preflight ID: " + mapValueOrDefault(capsule.Capsule.Evidence.PreflightResultID, "n/a"),
		"- Change-set ID: " + mapValueOrDefault(capsule.Capsule.Evidence.ChangeSetID, "n/a"),
		"- Approval ID: " + mapValueOrDefault(capsule.Capsule.Evidence.ApprovalID, "n/a"),
		"- Authorization ID: " + mapValueOrDefault(capsule.Capsule.Evidence.AuthorizationID, "n/a"),
	}
	if blockedReasonReference != "" {
		lines = append(lines, "", "## Blocked archival reason", "- Reference: "+blockedReasonReference)
	}
	if len(capsule.Capsule.Blockers) > 0 {
		lines = append(lines, "", "## Blockers")
		for _, blocker := range capsule.Capsule.Blockers {
			lines = append(lines, "- "+blocker.Code+": "+blocker.Message+" | remediation="+blocker.Remediation)
		}
	}
	return strings.Join(lines, "\n")
}

func renderWorkflowRolloutClosureVerifyMarkdown(payload workflowRolloutClosureVerifyExportRequest, verification workflowRolloutClosureVerifyResponse) string {
	lines := []string{
		"# YARA rollout closure verification export",
		"",
		"## Verification metadata",
		"- Verification reference: " + strings.TrimSpace(payload.VerificationReference),
		"- Operator reference: " + strings.TrimSpace(payload.OperatorReference),
		"- Verification timestamp: " + strings.TrimSpace(payload.VerificationTimestamp),
		"- Workspace path: " + verification.Verification.WorkspacePath,
		"",
		"## Verification result",
		"- Ready: " + fmt.Sprintf("%t", verification.Verification.Ready),
		"- Verification state: " + mapValueOrDefault(verification.Verification.VerificationState, "n/a"),
		"- Blocker code: " + mapValueOrDefault(verification.Verification.BlockerCode, "none"),
		"- Authorization ID: " + mapValueOrDefault(verification.Verification.Continuity.AuthorizationID, "n/a"),
		"- Target digest: " + mapValueOrDefault(verification.Verification.Continuity.TargetDigest, "n/a"),
	}
	if strings.TrimSpace(payload.AllowBlockedReasonReference) != "" {
		lines = append(lines, "- Blocked archival reason reference: "+strings.TrimSpace(payload.AllowBlockedReasonReference))
	}
	lines = append(lines, "", "## Chain coverage")
	for _, entry := range verification.Verification.Coverage {
		lines = append(lines,
			"- "+entry.Artifact+
				" | status="+mapValueOrDefault(entry.Status, "n/a")+
				" | state="+mapValueOrDefault(entry.State, "n/a")+
				" | digest="+mapValueOrDefault(entry.Digest, "n/a"),
		)
	}
	if len(verification.Verification.Diagnostics) > 0 {
		lines = append(lines, "", "## Diagnostics")
		for _, diagnostic := range verification.Verification.Diagnostics {
			lines = append(lines, "- "+diagnostic.Code+": "+diagnostic.Message+" | remediation="+diagnostic.Remediation)
		}
	}
	return strings.Join(lines, "\n")
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
