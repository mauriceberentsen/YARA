package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/targetpreflight"
	"gopkg.in/yaml.v3"
)

type targetPreflightOptions struct {
	bundlePath  string
	name        string
	outputPath  string
	auditPath   string
	kubeconfig  string
	contextName string
	timeout     time.Duration
}

type targetObserverFactory func(kubeconfig, contextName string) (targetpreflight.Observer, error)

func kubernetesTargetPreflight(args []string, stdout, stderr io.Writer) int {
	return runKubernetesTargetPreflight(args, stdout, stderr, func(kubeconfig, contextName string) (targetpreflight.Observer, error) {
		observer, err := targetpreflight.NewKubectlObserver(kubeconfig, contextName)
		if err != nil {
			return nil, err
		}
		return observer, nil
	}, time.Now)
}

func runKubernetesTargetPreflight(args []string, stdout, stderr io.Writer, factory targetObserverFactory, now func() time.Time) int {
	options, ok := parseTargetPreflightOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	action := "target.kubernetes-preflight"
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil {
		return writeTargetPreflightFailure(stdout, options, "kubernetes:unresolved", []audit.Subject{attemptedInputSubject("DeploymentBundle", options.bundlePath)}, "YARA-TPR-004", err, ExitInvalidInput)
	}
	bundleSubject := audit.Subject{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID}
	if report := bundle.Validate(); !report.Valid {
		return writeTargetPreflightFailure(stdout, options, "kubernetes:unresolved", []audit.Subject{bundleSubject}, "YARA-TPR-005", fmt.Errorf("bundle is invalid: %s", report.Diagnostics[0].Code), ExitInvalidInput)
	}
	if bundle.Spec.Renderer.Target != "kubernetes-gitops" {
		return writeTargetPreflightFailure(stdout, options, "kubernetes:unresolved", []audit.Subject{bundleSubject}, "YARA-TPR-006", fmt.Errorf("bundle target is not kubernetes-gitops"), ExitUnsupported)
	}
	observer, err := factory(options.kubeconfig, options.contextName)
	if err != nil {
		return writeTargetPreflightFailure(stdout, options, "kubernetes:unresolved", []audit.Subject{bundleSubject}, "YARA-TPR-007", fmt.Errorf("read-only Kubernetes observer is unavailable"), ExitUnsupported)
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	observation, err := observer.Observe(ctx, bundle.Metadata.Name, bundle.Spec.PlanID)
	if err != nil {
		return writeTargetPreflightFailure(stdout, options, "kubernetes:unresolved", []audit.Subject{bundleSubject}, "YARA-TPR-008", fmt.Errorf("read-only Kubernetes observation failed"), ExitInfeasible)
	}
	result, err := targetpreflight.Evaluate(options.name, bundle, observation, now())
	if err != nil {
		return writeTargetPreflightFailure(stdout, options, "kubernetes:"+observation.ReferenceDigest, []audit.Subject{bundleSubject}, "YARA-TPR-500", err, ExitInternal)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeTargetPreflightFailure(stdout, options, "kubernetes:"+observation.ReferenceDigest, []audit.Subject{bundleSubject}, "YARA-TPR-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeTargetPreflightFailure(stdout, options, "kubernetes:"+observation.ReferenceDigest, []audit.Subject{bundleSubject}, "YARA-TPR-009", err, ExitInvalidInput)
	}
	resultSubject := audit.Subject{Kind: "TargetPreflightResult", Digest: result.Metadata.ResultID}
	targetSubject := audit.Subject{Kind: "DeploymentTarget", Digest: observation.ReferenceDigest}
	suffix, auditOutcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, auditOutcome, exitCode = "blocked", "infeasible", ExitInfeasible
	} else if result.Spec.Outcome == "failed" {
		suffix, auditOutcome, exitCode = "failed", "failed", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, action, suffix, auditOutcome, "kubernetes:"+observation.ReferenceDigest, []audit.Subject{bundleSubject, targetSubject, resultSubject}, targetPreflightDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid": true, "outcome": result.Spec.Outcome, "resultId": result.Metadata.ResultID,
		"targetReferenceDigest": observation.ReferenceDigest, "output": options.outputPath, "auditOutput": options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return exitCode
}

func parseTargetPreflightOptions(args []string, stderr io.Writer) (targetPreflightOptions, bool) {
	options := targetPreflightOptions{timeout: 30 * time.Second}
	flags := flag.NewFlagSet("target preflight kubernetes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Validated Kubernetes DeploymentBundle")
	flags.StringVar(&options.name, "name", "", "TargetPreflightResult name")
	flags.StringVar(&options.outputPath, "output", "", "Generated TargetPreflightResult YAML file")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated mandatory audit JSONL file")
	flags.StringVar(&options.kubeconfig, "kubeconfig", "", "kubectl kubeconfig override (never persisted)")
	flags.StringVar(&options.contextName, "context", "", "kubectl context override (never persisted)")
	flags.DurationVar(&options.timeout, "timeout", options.timeout, "Overall read-only observation timeout")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.bundlePath == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "target preflight kubernetes requires --bundle, --name, --output and --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath || options.timeout < time.Second || options.timeout > 5*time.Minute {
		fmt.Fprintln(stderr, "output paths must differ and --timeout must be between 1s and 5m")
		return options, false
	}
	return options, true
}

func writeTargetPreflightFailure(output io.Writer, options targetPreflightOptions, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "target.kubernetes-preflight", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}

func targetPreflightDiagnosticCodes(result resources.TargetPreflightResult) []string {
	codes := make([]string, 0, len(result.Spec.Checks))
	for _, check := range result.Spec.Checks {
		if check.DiagnosticCode != "" {
			codes = append(codes, check.DiagnosticCode)
		}
	}
	return codes
}
