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
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/executor"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
	"gopkg.in/yaml.v3"
)

type deploymentImportOptions struct {
	bundlePath, preflightPath            string
	confirmBundle, targetDigest          string
	artifactRef, sourceDir, internalRoot string
	namespace, modelPVC                  string
	name, outputPath, auditPath          string
	kubeconfig, contextName              string
	timeout                              time.Duration
}

var verifyLocalImportPayload = verifyLocalArtifactPayload

func importKubernetesDeployment(args []string, stdout, stderr io.Writer) int {
	return importKubernetesDeploymentAt(args, stdout, stderr, time.Now)
}

func importKubernetesDeploymentAt(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	options, ok := parseDeploymentImportOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil || !bundle.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-IMP-101", errors.New("deployment bundle is invalid"), ExitInvalidInput)
	}
	if bundle.Metadata.BundleID != options.confirmBundle {
		return writeLoadErrorWithExit(stdout, "YARA-IMP-102", errors.New("explicit bundle confirmation does not match the supplied bundle"), ExitInvalidInput)
	}
	preflight, err := resources.LoadTargetPreflightResult(options.preflightPath)
	if err != nil || !preflight.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-IMP-103", errors.New("target preflight result is invalid"), ExitInvalidInput)
	}
	if preflight.Spec.BundleID != bundle.Metadata.BundleID || preflight.Spec.PlanID != bundle.Spec.PlanID {
		return writeLoadErrorWithExit(stdout, "YARA-IMP-104", errors.New("target preflight result does not bind the supplied bundle"), ExitInvalidInput)
	}
	if preflight.Spec.Target.ReferenceDigest != options.targetDigest {
		return writeLoadErrorWithExit(stdout, "YARA-IMP-105", errors.New("explicit target confirmation does not match the supplied preflight target"), ExitInvalidInput)
	}
	modelArtifacts, err := importModelArtifactsFromBundle(bundle, options.internalRoot)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-IMP-106", err, ExitInvalidInput)
	}
	selected, err := selectImportedModelArtifact(modelArtifacts, options.artifactRef)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-IMP-107", err, ExitInvalidInput)
	}
	if err := verifyLocalImportPayload(options.sourceDir, selected); err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-IMP-108", err, ExitInvalidInput)
	}
	importerImage, err := importerImageFromBundle(bundle)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-IMP-109", err, ExitInvalidInput)
	}
	correlationID := fmt.Sprintf("import-%d", now().UTC().UnixNano())
	subjects := []audit.Subject{
		{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID},
		{Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID},
	}
	auditWriter, err := newExecutionAudit(options.auditPath, correlationID, "deployment.import", "kubernetes:"+options.targetDigest, subjects, now())
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
	outputFile, err := reserveOutput(options.outputPath)
	if err != nil {
		return fail("YARA-IMP-110", err, ExitInvalidInput)
	}
	outputWritten := false
	defer func() {
		_ = outputFile.Close()
		if !outputWritten {
			_ = os.Remove(options.outputPath)
		}
	}()
	engine, err := newKubernetesExecutor(options.kubeconfig, options.contextName)
	if err != nil {
		return fail("YARA-IMP-111", err, ExitUnsupported)
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	result, importErr := engine.Import(ctx, executor.ImportConfig{
		Namespace:             options.namespace,
		ModelPVC:              options.modelPVC,
		TargetReferenceDigest: options.targetDigest,
		SourceRoot:            options.sourceDir,
		ImporterImage:         importerImage,
		Artifact:              selected,
	}, now().UTC())
	if !result.MutationStarted {
		if importErr == nil {
			importErr = errors.New("import executor returned without starting or explaining execution")
		}
		return fail("YARA-IMP-112", importErr, ExitInfeasible)
	}
	if importErr != nil {
		return fail("YARA-IMP-112", importErr, ExitInfeasible)
	}
	receipt := resources.ArtifactImportReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "ArtifactImportReceipt",
		Metadata: resources.ArtifactImportReceiptMetadata{
			Name: options.name,
		},
		Spec: resources.ArtifactImportReceiptSpec{
			RecordedAt: now().UTC().Format(time.RFC3339Nano),
			PlanID:     bundle.Spec.PlanID,
			BundleID:   bundle.Metadata.BundleID,
			Target:     result.Target,
			Importer: resources.ImporterIdentity{
				Name:    "yara-kubernetes-importer",
				Version: version.Version,
			},
			Verification: resources.ImportVerificationStatus{
				DigestVerified: true,
				SizeVerified:   true,
				CompleteSet:    true,
			},
			ModelArtifacts: []resources.ImportedModelArtifact{result.Artifact},
			Limitations:    result.Limitations,
		},
	}
	slices.Sort(receipt.Spec.Limitations)
	receipt, err = receipt.AssignImportReceiptID()
	if err != nil {
		return fail("YARA-IMP-500", err, ExitInternal)
	}
	if report := receipt.Validate(); !report.Valid {
		return fail("YARA-IMP-500", errors.New("constructed artifact import receipt is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(receipt)
	if err == nil {
		err = writeReserved(outputFile, data)
	}
	if err != nil {
		return fail("YARA-IMP-113", err, ExitInternal)
	}
	outputWritten = true
	receiptSubject := audit.Subject{Kind: "ArtifactImportReceipt", Digest: receipt.Metadata.ImportReceiptID}
	terminalSubjects := append(append([]audit.Subject(nil), subjects...), receiptSubject)
	if err := auditWriter.finish("success", terminalSubjects, nil, now()); err != nil {
		_ = os.Remove(options.outputPath)
		_ = auditWriter.file.Close()
		auditClosed = true
		return writeLoadErrorWithExit(stdout, "YARA-AUD-005", err, ExitInternal)
	}
	auditClosed = true
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":           true,
		"importReceiptId": receipt.Metadata.ImportReceiptID,
		"bundleId":        bundle.Metadata.BundleID,
		"target":          result.Target.ReferenceDigest,
		"output":          options.outputPath,
		"auditOutput":     options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseDeploymentImportOptions(args []string, stderr io.Writer) (deploymentImportOptions, bool) {
	options := deploymentImportOptions{timeout: 30 * time.Minute, internalRoot: "model"}
	flags := flag.NewFlagSet("deployment import kubernetes", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Exact DeploymentBundle")
	flags.StringVar(&options.confirmBundle, "confirm-bundle", "", "Explicit confirmed bundle ID")
	flags.StringVar(&options.preflightPath, "preflight", "", "Exact TargetPreflightResult")
	flags.StringVar(&options.targetDigest, "target", "", "Explicit confirmed target reference digest")
	flags.StringVar(&options.artifactRef, "artifact-ref", "", "Exact model artifact ref from bundle")
	flags.StringVar(&options.sourceDir, "source-dir", "", "Local source directory containing model files")
	flags.StringVar(&options.internalRoot, "internal-root", options.internalRoot, "Relative root path inside model PVC")
	flags.StringVar(&options.namespace, "namespace", "", "Existing YARA-owned namespace")
	flags.StringVar(&options.modelPVC, "model-pvc", "", "Existing YARA-owned model PVC name")
	flags.StringVar(&options.name, "name", "", "ArtifactImportReceipt name")
	flags.StringVar(&options.outputPath, "output", "", "Generated ArtifactImportReceipt YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Exclusive durable audit JSONL output")
	flags.StringVar(&options.kubeconfig, "kubeconfig", "", "Kubeconfig path passed only to kubectl")
	flags.StringVar(&options.contextName, "context", "", "Kubernetes context passed only to kubectl")
	flags.DurationVar(&options.timeout, "timeout", options.timeout, "Overall execution timeout")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return options, false
	}
	if options.bundlePath == "" || options.confirmBundle == "" || options.preflightPath == "" || options.targetDigest == "" || options.artifactRef == "" || options.sourceDir == "" || options.namespace == "" || options.modelPVC == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" || options.timeout <= 0 {
		fmt.Fprintln(stderr, "deployment import kubernetes requires --bundle --confirm-bundle --preflight --target --artifact-ref --source-dir --namespace --model-pvc --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	if !bootstrapDigestPattern.MatchString(options.confirmBundle) || !bootstrapDigestPattern.MatchString(options.targetDigest) {
		fmt.Fprintln(stderr, "--confirm-bundle and --target must be SHA-256 digests")
		return options, false
	}
	if !bootstrapNamePattern.MatchString(options.namespace) || !bootstrapNamePattern.MatchString(options.modelPVC) {
		fmt.Fprintln(stderr, "--namespace and --model-pvc must be lowercase DNS-style names")
		return options, false
	}
	if !validSafeImportPath(options.internalRoot) {
		fmt.Fprintln(stderr, "--internal-root must be a safe relative path")
		return options, false
	}
	return options, true
}

func selectImportedModelArtifact(artifacts []resources.ImportedModelArtifact, ref string) (resources.ImportedModelArtifact, error) {
	for _, artifact := range artifacts {
		if artifact.Ref == ref {
			return artifact, nil
		}
	}
	return resources.ImportedModelArtifact{}, errors.New("artifact-ref does not match any import-tracked bundle model artifact")
}

func verifyLocalArtifactPayload(sourceDir string, artifact resources.ImportedModelArtifact) error {
	root := filepath.Clean(sourceDir)
	if root == "" || root == "." {
		return errors.New("source directory is invalid")
	}
	for _, file := range artifact.Files {
		joined := filepath.Join(root, filepath.FromSlash(file.Path))
		cleaned := filepath.Clean(joined)
		relative, err := filepath.Rel(root, cleaned)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("bundle model file path escapes source directory")
		}
		stat, err := os.Stat(cleaned)
		if err != nil || stat.IsDir() {
			return errors.New("required model file is missing from source directory")
		}
		if stat.Size() != file.SizeBytes {
			return errors.New("source model file size does not match expected bundle identity")
		}
		digest, err := fileSHA256(cleaned)
		if err != nil {
			return err
		}
		if digest != file.Digest {
			return errors.New("source model file digest does not match expected bundle identity")
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return "", errors.New("source model file could not be opened")
	}
	defer handle.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, handle); err != nil {
		return "", errors.New("source model file could not be hashed")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func importerImageFromBundle(bundle resources.DeploymentBundle) (string, error) {
	for _, artifact := range bundle.Spec.Artifacts {
		if artifact.Type == "oci-image" && strings.Contains(artifact.Ref, "vllm") && artifact.Ref != "" && artifact.Digest != "" {
			return artifact.Ref + "@" + artifact.Digest, nil
		}
	}
	return "", errors.New("bundle does not contain a compatible importer image reference")
}
