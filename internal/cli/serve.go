package cli

import (
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
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/catalogcoverage"
)

type serveOptions struct {
	catalogPath        string
	coverageReportPath string
	port               int
	ui                 bool
}

type lifecyclePolicyAssertion struct {
	Assertion   string `json:"assertion"`
	Status      string `json:"status"`
	Blocker     string `json:"blocker,omitempty"`
	Code        string `json:"code,omitempty"`
	Remediation string `json:"remediation,omitempty"`
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
	handler, err := newServeAPIHandler(snapshot, catalogDigest, report, options.ui)
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
	return options, true
}

func newServeAPIHandler(snapshot catalog.Snapshot, catalogDigest string, report catalogcoverage.Report, uiEnabled bool) (http.Handler, error) {
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
		lifecyclePolicy, err := lifecyclePolicyFromReport(report)
		if err != nil {
			writeServeError(writer, http.StatusInternalServerError, "YARA-SRV-500", err.Error())
			return
		}
		sort.Slice(lifecyclePolicy, func(i, j int) bool { return lifecyclePolicy[i].Assertion < lifecyclePolicy[j].Assertion })
		writeServeJSON(writer, http.StatusOK, map[string]any{
			"valid":                      true,
			"lifecyclePublicationPolicy": map[string]any{"policyPassed": len(lifecyclePolicy) == 0},
			"blockedAssertions":          lifecyclePolicy,
			"taxonomy":                   catalogcoverage.LifecyclePublicationBlockerTaxonomy(),
		})
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

func lifecyclePolicyFromReport(report catalogcoverage.Report) ([]lifecyclePolicyAssertion, error) {
	blocked := make([]lifecyclePolicyAssertion, 0, len(report.Spec.Assertions))
	for _, assertion := range report.Spec.Assertions {
		if assertion.LifecyclePublicationReady {
			continue
		}
		if assertion.LifecyclePublicationBlocker == "" {
			return nil, fmt.Errorf("assertion %s omits lifecycle publication blocker", assertion.ID)
		}
		parsed, err := catalogcoverage.ParseLifecyclePublicationBlocker(assertion.LifecyclePublicationBlocker)
		if err != nil {
			return nil, fmt.Errorf("assertion %s has malformed lifecycle publication blocker: %w", assertion.ID, err)
		}
		blocked = append(blocked, lifecyclePolicyAssertion{
			Assertion: assertion.ID, Status: "blocked", Blocker: assertion.LifecyclePublicationBlocker, Code: parsed.Code, Remediation: parsed.Remediation,
		})
	}
	return blocked, nil
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
