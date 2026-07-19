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
	"github.com/mauriceberentsen/YARA/internal/changeset"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

const maxPreflightAge = 15 * time.Minute

type changeSetOptions struct {
	bundlePath, preflightPath, name, outputPath, auditPath string
	kubeconfig, contextName                                string
	timeout                                                time.Duration
}

type changeSetObserverFactory func(kubeconfig, contextName string) (changeset.Observer, error)

func kubernetesChangeSet(args []string, stdout, stderr io.Writer) int {
	return runKubernetesChangeSet(args, stdout, stderr, func(kubeconfig, contextName string) (changeset.Observer, error) {
		observer, err := changeset.NewKubectlObserver(kubeconfig, contextName)
		if err != nil {
			return nil, err
		}
		return observer, nil
	}, time.Now)
}

func runKubernetesChangeSet(args []string, stdout, stderr io.Writer, factory changeSetObserverFactory, now func() time.Time) int {
	options, ok := parseChangeSetOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	action, unresolvedTarget := "target.kubernetes-changeset", "kubernetes:unresolved"
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil {
		return writeChangeSetFailure(stdout, options, unresolvedTarget, []audit.Subject{attemptedInputSubject("DeploymentBundle", options.bundlePath)}, "YARA-CHG-004", err, ExitInvalidInput)
	}
	bundleSubject := audit.Subject{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID}
	if report := bundle.Validate(); !report.Valid || bundle.Spec.Renderer.Target != "kubernetes-gitops" {
		return writeChangeSetFailure(stdout, options, unresolvedTarget, []audit.Subject{bundleSubject}, "YARA-CHG-005", fmt.Errorf("a valid kubernetes-gitops bundle is required"), ExitInvalidInput)
	}
	preflight, err := resources.LoadTargetPreflightResult(options.preflightPath)
	if err != nil {
		return writeChangeSetFailure(stdout, options, unresolvedTarget, []audit.Subject{bundleSubject, attemptedInputSubject("TargetPreflightResult", options.preflightPath)}, "YARA-CHG-006", err, ExitInvalidInput)
	}
	preflightSubject := audit.Subject{Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID}
	if report := preflight.Validate(); !report.Valid || preflight.Spec.BundleID != bundle.Metadata.BundleID || preflight.Spec.PlanID != bundle.Spec.PlanID {
		return writeChangeSetFailure(stdout, options, unresolvedTarget, []audit.Subject{bundleSubject, preflightSubject}, "YARA-CHG-007", fmt.Errorf("preflight does not validly bind the exact bundle"), ExitInvalidInput)
	}
	preflightTime, err := time.Parse(time.RFC3339Nano, preflight.Spec.ObservedAt)
	observedAt := now().UTC()
	if err != nil || observedAt.Before(preflightTime) || observedAt.Sub(preflightTime) > maxPreflightAge {
		return writeChangeSetFailure(stdout, options, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject}, "YARA-CHG-103", fmt.Errorf("preflight is older than the 15 minute change-set window"), ExitInfeasible)
	}
	desired, err := changeset.DesiredObjects(bundle)
	if err != nil {
		return writeChangeSetFailure(stdout, options, "kubernetes:"+preflight.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject}, "YARA-CHG-008", err, ExitInvalidInput)
	}
	observer, err := factory(options.kubeconfig, options.contextName)
	if err != nil {
		return writeChangeSetFailure(stdout, options, unresolvedTarget, []audit.Subject{bundleSubject, preflightSubject}, "YARA-CHG-009", fmt.Errorf("read-only Kubernetes change-set observer is unavailable"), ExitUnsupported)
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	observation, err := observer.Observe(ctx, desired, bundle.Spec.PlanID)
	if err != nil {
		return writeChangeSetFailure(stdout, options, unresolvedTarget, []audit.Subject{bundleSubject, preflightSubject}, "YARA-CHG-104", fmt.Errorf("read-only Kubernetes change-set observation failed"), ExitInfeasible)
	}
	result, err := changeset.Evaluate(options.name, bundle, preflight, observation, observedAt)
	if err != nil {
		return writeChangeSetFailure(stdout, options, unresolvedTarget, []audit.Subject{bundleSubject, preflightSubject}, "YARA-CHG-105", fmt.Errorf("change-set evaluation failed"), ExitInfeasible)
	}
	data, err := yaml.Marshal(result)
	if err != nil {
		return writeChangeSetFailure(stdout, options, "kubernetes:"+result.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject}, "YARA-CHG-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeChangeSetFailure(stdout, options, "kubernetes:"+result.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject}, "YARA-CHG-009", err, ExitInvalidInput)
	}
	targetSubject := audit.Subject{Kind: "DeploymentTarget", Digest: result.Spec.Target.ReferenceDigest}
	resultSubject := audit.Subject{Kind: "KubernetesChangeSet", Digest: result.Metadata.ChangeSetID}
	suffix, outcome, exitCode := "completed", "success", ExitSuccess
	if result.Spec.Outcome == "blocked" {
		suffix, outcome, exitCode = "blocked", "infeasible", ExitInfeasible
	}
	if err := persistOperationAuditForTarget(options.auditPath, action, suffix, outcome, "kubernetes:"+result.Spec.Target.ReferenceDigest, []audit.Subject{bundleSubject, preflightSubject, targetSubject, resultSubject}, changeSetDiagnosticCodes(result)); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{"valid": true, "outcome": result.Spec.Outcome, "changeSetId": result.Metadata.ChangeSetID, "summary": result.Spec.Summary, "output": options.outputPath, "auditOutput": options.auditPath}); err != nil {
		return ExitInternal
	}
	return exitCode
}

func parseChangeSetOptions(args []string, stderr io.Writer) (changeSetOptions, bool) {
	options := changeSetOptions{timeout: 30 * time.Second}
	flags := flag.NewFlagSet("target changeset kubernetes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Validated Kubernetes DeploymentBundle")
	flags.StringVar(&options.preflightPath, "preflight", "", "Fresh TargetPreflightResult")
	flags.StringVar(&options.name, "name", "", "KubernetesChangeSet name")
	flags.StringVar(&options.outputPath, "output", "", "Generated KubernetesChangeSet YAML")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated mandatory audit JSONL")
	flags.StringVar(&options.kubeconfig, "kubeconfig", "", "kubectl kubeconfig override (never persisted)")
	flags.StringVar(&options.contextName, "context", "", "kubectl context override (never persisted)")
	flags.DurationVar(&options.timeout, "timeout", options.timeout, "Overall read-only observation timeout")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.bundlePath == "" || options.preflightPath == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "target changeset kubernetes requires --bundle, --preflight, --name, --output and --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath || options.timeout < time.Second || options.timeout > 5*time.Minute {
		fmt.Fprintln(stderr, "output paths must differ and --timeout must be between 1s and 5m")
		return options, false
	}
	return options, true
}

func writeChangeSetFailure(output io.Writer, options changeSetOptions, target string, subjects []audit.Subject, code string, err error, exitCode int) int {
	if auditErr := persistOperationAuditForTarget(options.auditPath, "target.kubernetes-changeset", "failed", "failed", target, subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadErrorWithExit(output, code, err, exitCode)
}

func changeSetDiagnosticCodes(result resources.KubernetesChangeSet) []string {
	codes := []string{}
	for _, operation := range result.Spec.Operations {
		if operation.DiagnosticCode != "" {
			codes = append(codes, operation.DiagnosticCode)
		}
	}
	return codes
}
