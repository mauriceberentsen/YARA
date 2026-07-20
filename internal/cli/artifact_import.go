package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type importReceiptOptions struct {
	bundlePath, preflightPath, importerName, importerVersion string
	internalRoot, name, outputPath, auditPath                string
}

func recordArtifactImport(args []string, stdout, stderr io.Writer) int {
	options, ok := parseImportReceiptOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil || !bundle.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AIR-101", errors.New("deployment bundle is invalid"), ExitInvalidInput)
	}
	preflight, err := resources.LoadTargetPreflightResult(options.preflightPath)
	if err != nil || !preflight.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AIR-102", errors.New("target preflight result is invalid"), ExitInvalidInput)
	}
	if preflight.Spec.PlanID != bundle.Spec.PlanID || preflight.Spec.BundleID != bundle.Metadata.BundleID {
		return writeLoadErrorWithExit(stdout, "YARA-AIR-104", errors.New("target preflight result does not bind the supplied bundle"), ExitInvalidInput)
	}
	modelArtifacts, err := importModelArtifactsFromBundle(bundle, options.internalRoot)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AIR-105", err, ExitInvalidInput)
	}
	receipt := resources.ArtifactImportReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "ArtifactImportReceipt",
		Metadata: resources.ArtifactImportReceiptMetadata{
			Name: options.name,
		},
		Spec: resources.ArtifactImportReceiptSpec{
			RecordedAt: time.Now().UTC().Format(time.RFC3339Nano),
			PlanID:     bundle.Spec.PlanID,
			BundleID:   bundle.Metadata.BundleID,
			Target:     preflight.Spec.Target,
			Importer: resources.ImporterIdentity{
				Name:    options.importerName,
				Version: options.importerVersion,
			},
			Verification: resources.ImportVerificationStatus{
				DigestVerified: true,
				SizeVerified:   true,
				CompleteSet:    true,
			},
			ModelArtifacts: modelArtifacts,
			Limitations: []string{
				"Import receipt proves exact model-file placement only for this run.",
				"Import receipt excludes source artifact payloads, credentials and raw transfer logs.",
			},
		},
	}
	slices.Sort(receipt.Spec.Limitations)
	receipt, err = receipt.AssignImportReceiptID()
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AIR-500", err, ExitInternal)
	}
	if report := receipt.Validate(); !report.Valid {
		return writeLoadErrorWithExit(stdout, "YARA-AIR-500", errors.New("constructed import receipt is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(receipt)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AIR-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-AIR-106", err, ExitInvalidInput)
	}
	target := "kubernetes:" + preflight.Spec.Target.ReferenceDigest
	subjects := []audit.Subject{
		{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID},
		{Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID},
		{Kind: "ArtifactImportReceipt", Digest: receipt.Metadata.ImportReceiptID},
	}
	if err := persistOperationAuditForTarget(options.auditPath, "artifact.import.record", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":           true,
		"importReceiptId": receipt.Metadata.ImportReceiptID,
		"bundleId":        bundle.Metadata.BundleID,
		"preflightId":     preflight.Metadata.ResultID,
		"output":          options.outputPath,
		"auditOutput":     options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseImportReceiptOptions(args []string, stderr io.Writer) (importReceiptOptions, bool) {
	var options importReceiptOptions
	flags := flag.NewFlagSet("artifact import record", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Exact DeploymentBundle")
	flags.StringVar(&options.preflightPath, "preflight", "", "Exact TargetPreflightResult")
	flags.StringVar(&options.importerName, "importer-name", "", "Importer tool name")
	flags.StringVar(&options.importerVersion, "importer-version", "", "Importer tool version")
	flags.StringVar(&options.internalRoot, "internal-root", "model", "Relative root directory used for imported model files")
	flags.StringVar(&options.name, "name", "", "ArtifactImportReceipt name")
	flags.StringVar(&options.outputPath, "output", "", "Generated ArtifactImportReceipt YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated import audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.bundlePath == "" || options.preflightPath == "" || options.importerName == "" || options.importerVersion == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "artifact import record requires --bundle --preflight --importer-name --importer-version --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	if !validSafeImportPath(options.internalRoot) {
		fmt.Fprintln(stderr, "--internal-root must be a safe relative path")
		return options, false
	}
	return options, true
}

func importModelArtifactsFromBundle(bundle resources.DeploymentBundle, internalRoot string) ([]resources.ImportedModelArtifact, error) {
	modelArtifacts := []resources.ImportedModelArtifact{}
	for _, artifact := range bundle.Spec.Artifacts {
		if artifact.Type != "huggingface-snapshot" {
			continue
		}
		files := make([]resources.ImportedModelArtifactBinding, 0, len(artifact.Files))
		for _, file := range artifact.Files {
			if !validSafeImportPath(file.Path) {
				return nil, errors.New("bundle model artifact file path is unsafe for import receipt")
			}
			internalPath := path.Clean(path.Join(internalRoot, file.Path))
			if !validSafeImportPath(internalPath) {
				return nil, errors.New("derived internal model artifact path is unsafe")
			}
			files = append(files, resources.ImportedModelArtifactBinding{
				Path:         file.Path,
				Digest:       file.Digest,
				SizeBytes:    file.SizeBytes,
				InternalPath: internalPath,
			})
		}
		slices.SortFunc(files, func(left, right resources.ImportedModelArtifactBinding) int {
			return strings.Compare(left.Path, right.Path)
		})
		modelArtifacts = append(modelArtifacts, resources.ImportedModelArtifact{
			Ref: artifact.Ref, Revision: artifact.Revision, Files: files,
		})
	}
	slices.SortFunc(modelArtifacts, func(left, right resources.ImportedModelArtifact) int {
		return strings.Compare(left.Ref, right.Ref)
	})
	if len(modelArtifacts) == 0 {
		return nil, errors.New("bundle does not contain import-tracked model artifacts")
	}
	return modelArtifacts, nil
}

func validSafeImportPath(value string) bool {
	clean := path.Clean(value)
	return strings.TrimSpace(value) != "" && clean == value && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../") && !path.IsAbs(clean)
}
