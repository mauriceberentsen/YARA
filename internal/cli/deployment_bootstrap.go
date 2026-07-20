package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/executor"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
	"gopkg.in/yaml.v3"
)

var bootstrapNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var bootstrapStorageClassPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9_.]{0,251}[a-z0-9])?$`)
var bootstrapSizePattern = regexp.MustCompile(`^[1-9][0-9]*(?:Ei|Pi|Ti|Gi|Mi|Ki)?$`)
var bootstrapDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type deploymentBootstrapOptions struct {
	name, namespace, modelPVC, storageClass, size string
	targetDigest, receiptPath, auditPath          string
	kubeconfig, contextName                       string
	timeout                                       time.Duration
}

func bootstrapKubernetesDeployment(args []string, stdout, stderr io.Writer) int {
	return bootstrapKubernetesDeploymentAt(args, stdout, stderr, time.Now)
}

func bootstrapKubernetesDeploymentAt(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	options, ok := parseDeploymentBootstrapOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	correlationID := fmt.Sprintf("bootstrap-%d", now().UTC().UnixNano())
	subjects := []audit.Subject{{Kind: "TargetIdentity", Digest: options.targetDigest}}
	auditWriter, err := newExecutionAudit(options.auditPath, correlationID, "deployment.bootstrap", "kubernetes:"+options.targetDigest, subjects, now())
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AUD-005", err, ExitInvalidInput)
	}
	auditClosed := false
	defer func() {
		if !auditClosed {
			_ = auditWriter.file.Close()
		}
	}()
	fail := func(code string, cause error, exitCode int) int {
		if auditErr := auditWriter.finish("failed", subjects, []string{code}, now()); auditErr != nil {
			_ = auditWriter.file.Close()
			auditClosed = true
			return writeLoadErrorWithExit(stdout, "YARA-AUD-005", auditErr, ExitInternal)
		}
		auditClosed = true
		return writeLoadErrorWithExit(stdout, code, cause, exitCode)
	}
	binaryDigest, err := currentBinaryDigest()
	if err != nil {
		return fail("YARA-BST-113", err, ExitInternal)
	}
	receiptFile, err := reserveOutput(options.receiptPath)
	if err != nil {
		return fail("YARA-BST-112", err, ExitInvalidInput)
	}
	receiptWritten := false
	defer func() {
		_ = receiptFile.Close()
		if !receiptWritten {
			_ = os.Remove(options.receiptPath)
		}
	}()
	engine, err := newKubernetesExecutor(options.kubeconfig, options.contextName)
	if err != nil {
		return fail("YARA-BST-113", err, ExitUnsupported)
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	result, bootstrapErr := engine.Bootstrap(ctx, executor.BootstrapConfig{
		Namespace:             options.namespace,
		ModelPVC:              options.modelPVC,
		StorageClass:          options.storageClass,
		Size:                  options.size,
		TargetReferenceDigest: options.targetDigest,
	}, now().UTC())
	if !result.MutationStarted {
		if bootstrapErr == nil {
			bootstrapErr = errors.New("bootstrap executor returned without starting or explaining execution")
		}
		return fail("YARA-BST-114", bootstrapErr, ExitInfeasible)
	}
	receipt, err := buildBootstrapReceipt(options.name, correlationID, binaryDigest, options, result)
	if err != nil {
		return fail("YARA-BST-500", err, ExitInternal)
	}
	data, err := yaml.Marshal(receipt)
	if err == nil {
		err = writeReserved(receiptFile, data)
	}
	if err != nil {
		return fail("YARA-BST-115", err, ExitInternal)
	}
	receiptWritten = true
	receiptSubject := audit.Subject{Kind: "BootstrapReceipt", Digest: receipt.Metadata.ReceiptID}
	terminalSubjects := append(append([]audit.Subject(nil), subjects...), receiptSubject)
	terminalOutcome := "success"
	diagnosticCodes := bootstrapDiagnosticCodes(receipt)
	if receipt.Spec.Outcome != "succeeded" || bootstrapErr != nil {
		terminalOutcome = "failed"
		if len(diagnosticCodes) == 0 {
			diagnosticCodes = []string{"YARA-BST-114"}
		}
	}
	if err := auditWriter.finish(terminalOutcome, terminalSubjects, diagnosticCodes, now()); err != nil {
		_ = os.Remove(options.receiptPath)
		_ = auditWriter.file.Close()
		auditClosed = true
		return writeLoadErrorWithExit(stdout, "YARA-AUD-005", err, ExitInternal)
	}
	auditClosed = true
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":         receipt.Spec.Outcome == "succeeded",
		"outcome":       receipt.Spec.Outcome,
		"receiptId":     receipt.Metadata.ReceiptID,
		"target":        receipt.Spec.Target.ReferenceDigest,
		"receiptOutput": options.receiptPath,
		"auditOutput":   options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	if bootstrapErr != nil || receipt.Spec.Outcome != "succeeded" {
		return ExitInfeasible
	}
	return ExitSuccess
}

func parseDeploymentBootstrapOptions(args []string, stderr io.Writer) (deploymentBootstrapOptions, bool) {
	options := deploymentBootstrapOptions{timeout: 15 * time.Minute}
	flags := flag.NewFlagSet("deployment bootstrap kubernetes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.name, "name", "", "BootstrapReceipt name")
	flags.StringVar(&options.namespace, "namespace", "", "YARA-owned namespace to create or verify")
	flags.StringVar(&options.modelPVC, "model-pvc", "", "YARA-owned model PVC name to create or verify")
	flags.StringVar(&options.storageClass, "storage-class", "", "StorageClass name for the model PVC")
	flags.StringVar(&options.size, "size", "", "Model PVC storage request (for example 200Gi)")
	flags.StringVar(&options.targetDigest, "target", "", "Explicit confirmed target reference digest")
	flags.StringVar(&options.receiptPath, "receipt-output", "", "Exclusive BootstrapReceipt output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Exclusive durable audit JSONL output")
	flags.StringVar(&options.kubeconfig, "kubeconfig", "", "Kubeconfig path passed only to kubectl")
	flags.StringVar(&options.contextName, "context", "", "Kubernetes context passed only to kubectl")
	flags.DurationVar(&options.timeout, "timeout", options.timeout, "Overall execution timeout")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return options, false
	}
	if options.name == "" || options.namespace == "" || options.modelPVC == "" || options.storageClass == "" || options.size == "" || options.targetDigest == "" || options.receiptPath == "" || options.auditPath == "" || options.timeout <= 0 {
		fmt.Fprintln(stderr, "deployment bootstrap kubernetes requires --name --namespace --model-pvc --storage-class --size --target --receipt-output --audit-output")
		return options, false
	}
	if options.receiptPath == options.auditPath {
		fmt.Fprintln(stderr, "receipt and audit output paths must differ")
		return options, false
	}
	if !bootstrapNamePattern.MatchString(options.name) || !bootstrapNamePattern.MatchString(options.namespace) || !bootstrapNamePattern.MatchString(options.modelPVC) {
		fmt.Fprintln(stderr, "--name, --namespace and --model-pvc must be lowercase DNS-style names")
		return options, false
	}
	if !bootstrapStorageClassPattern.MatchString(options.storageClass) || !bootstrapSizePattern.MatchString(options.size) {
		fmt.Fprintln(stderr, "--storage-class and --size must be bounded, explicit values")
		return options, false
	}
	if !bootstrapDigestPattern.MatchString(options.targetDigest) {
		fmt.Fprintln(stderr, "--target must be a SHA-256 digest")
		return options, false
	}
	return options, true
}

func buildBootstrapReceipt(name, correlationID, binaryDigest string, options deploymentBootstrapOptions, result executor.BootstrapResult) (resources.BootstrapReceipt, error) {
	outcome := "succeeded"
	for _, operation := range result.Operations {
		if operation.Outcome == "failed" {
			outcome = "failed"
			break
		}
		if operation.Outcome == "skipped" || operation.Outcome == "unchanged" {
			outcome = "partial"
		}
	}
	receipt := resources.BootstrapReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "BootstrapReceipt",
		Metadata: resources.BootstrapReceiptMetadata{
			Name: name,
		},
		Spec: resources.BootstrapReceiptSpec{
			Outcome:                outcome,
			StartedAt:              result.StartedAt.Format(time.RFC3339Nano),
			CompletedAt:            result.CompletedAt.Format(time.RFC3339Nano),
			ExecutionCorrelationID: correlationID,
			Target:                 result.Target,
			Namespace:              options.namespace,
			ModelPVC:               options.modelPVC,
			StorageClass:           options.storageClass,
			Size:                   options.size,
			Executor: resources.DeploymentExecutorIdentity{
				Name:         "yara-kubernetes-executor",
				Version:      version.Version,
				BinaryDigest: binaryDigest,
			},
			Operations:  result.Operations,
			Limitations: result.Limitations,
		},
	}
	receipt, err := receipt.AssignReceiptID()
	if err != nil {
		return resources.BootstrapReceipt{}, err
	}
	if report := receipt.Validate(); !report.Valid {
		return resources.BootstrapReceipt{}, fmt.Errorf("constructed bootstrap receipt is invalid: %s", report.Diagnostics[0].Code)
	}
	return receipt, nil
}

func bootstrapDiagnosticCodes(receipt resources.BootstrapReceipt) []string {
	set := map[string]struct{}{}
	for _, operation := range receipt.Spec.Operations {
		if operation.DiagnosticCode != "" {
			set[operation.DiagnosticCode] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for code := range set {
		result = append(result, code)
	}
	slices.Sort(result)
	return result
}
