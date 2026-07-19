package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/renderer"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type renderOptions struct {
	planPath    string
	catalogPath string
	name        string
	outputPath  string
	auditPath   string
}

func renderDockerCompose(args []string, stdout, stderr io.Writer) int {
	return renderBundle(args, stdout, stderr, renderer.DockerCompose{}, "docker-compose")
}

func renderKubernetesGitOps(args []string, stdout, stderr io.Writer) int {
	return renderBundle(args, stdout, stderr, renderer.KubernetesGitOps{}, "kubernetes-gitops")
}

func renderBundle(args []string, stdout, stderr io.Writer, selected renderer.Renderer, command string) int {
	options, ok := parseRenderOptions(args, stderr, command)
	if !ok {
		return ExitInvalidInput
	}
	action := "render." + command
	plan, err := resources.LoadPlatformPlan(options.planPath)
	if err != nil {
		return writeRenderFailure(stdout, options, action, []audit.Subject{attemptedInputSubject("PlatformPlan", options.planPath)}, "YARA-RND-004", err, ExitInvalidInput)
	}
	planSubject := audit.Subject{Kind: "PlatformPlan", Digest: plan.Metadata.PlanID}
	if report := plan.Validate(); !report.Valid {
		return writeRenderFailure(stdout, options, action, []audit.Subject{planSubject}, "YARA-RND-005", fmt.Errorf("plan is invalid: %s", report.Diagnostics[0].Code), ExitInvalidInput)
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeRenderFailure(stdout, options, action, []audit.Subject{planSubject, attemptedInputSubject("CatalogSnapshot", options.catalogPath)}, "YARA-RND-004", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeRenderFailure(stdout, options, action, []audit.Subject{planSubject}, "YARA-RND-500", err, ExitInternal)
	}
	catalogSubject := audit.Subject{Kind: "CatalogSnapshot", Digest: catalogDigest}
	bundle, err := selected.Render(options.name, plan, snapshot)
	if err != nil {
		return writeRenderFailure(stdout, options, action, []audit.Subject{planSubject, catalogSubject}, "YARA-RND-005", err, ExitUnsupported)
	}
	data, err := yaml.Marshal(bundle)
	if err != nil {
		return writeRenderFailure(stdout, options, action, []audit.Subject{planSubject, catalogSubject}, "YARA-RND-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeRenderFailure(stdout, options, action, []audit.Subject{planSubject, catalogSubject}, "YARA-RND-006", err, ExitInvalidInput)
	}
	bundleSubject := audit.Subject{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID}
	if err := persistOperationAudit(options.auditPath, action, "completed", "success", []audit.Subject{planSubject, catalogSubject, bundleSubject}, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid": true, "bundleId": bundle.Metadata.BundleID, "renderer": bundle.Spec.Renderer,
		"output": options.outputPath, "auditOutput": options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseRenderOptions(args []string, stderr io.Writer, command string) (renderOptions, bool) {
	var options renderOptions
	flags := flag.NewFlagSet("render "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.planPath, "plan", "", "Validated PlatformPlan file")
	flags.StringVar(&options.catalogPath, "catalog", "", "Exact CatalogSnapshot file bound by the plan")
	flags.StringVar(&options.name, "name", "", "DeploymentBundle and target project name")
	flags.StringVar(&options.outputPath, "output", "", "Generated DeploymentBundle YAML file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated audit JSONL file")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.planPath == "" || options.catalogPath == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintf(stderr, "render %s requires --plan, --catalog, --name, --output and --audit-output\n", command)
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	return options, true
}

func writeRenderFailure(output io.Writer, options renderOptions, action string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAudit(options.auditPath, action, "failed", "failed", subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}
