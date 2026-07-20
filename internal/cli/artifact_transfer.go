package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type transferReceiptOptions struct {
	bundlePath, importReceiptPath, stage, sourceRef, destinationRef string
	name, outputPath, auditPath                                     string
	priorReceiptIDs                                                 csvFlag
}

func recordArtifactTransfer(args []string, stdout, stderr io.Writer) int {
	options, ok := parseTransferReceiptOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil || !bundle.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-ATR-101", errors.New("deployment bundle is invalid"), ExitInvalidInput)
	}
	importReceipt, err := resources.LoadArtifactImportReceipt(options.importReceiptPath)
	if err != nil || !importReceipt.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-ATR-102", errors.New("artifact import receipt is invalid"), ExitInvalidInput)
	}
	if importReceipt.Spec.PlanID != bundle.Spec.PlanID || importReceipt.Spec.BundleID != bundle.Metadata.BundleID {
		return writeLoadErrorWithExit(stdout, "YARA-ATR-103", errors.New("import receipt does not bind the supplied bundle"), ExitInvalidInput)
	}
	modelArtifacts, err := modelArtifactsFromBundle(bundle)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-ATR-103", err, ExitInvalidInput)
	}
	priorIDs := uniqueSortedStrings(append(slices.Clone(options.priorReceiptIDs), importReceipt.Metadata.ImportReceiptID))
	receipt := resources.ArtifactTransferReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "ArtifactTransferReceipt",
		Metadata: resources.ArtifactTransferReceiptMetadata{
			Name: options.name,
		},
		Spec: resources.ArtifactTransferReceiptSpec{
			RecordedAt:                time.Now().UTC().Format(time.RFC3339Nano),
			PlanID:                    bundle.Spec.PlanID,
			BundleID:                  bundle.Metadata.BundleID,
			CatalogDigest:             bundle.Spec.CatalogDigest,
			Target:                    importReceipt.Spec.Target,
			Stage:                     options.stage,
			SourceAttestationRef:      options.sourceRef,
			DestinationAttestationRef: options.destinationRef,
			PriorReceiptIDs:           priorIDs,
			ModelArtifacts:            modelArtifacts,
			Limitations: []string{
				"Transfer receipt records bounded non-secret attestation references only.",
				"Transfer receipt does not mutate bundle, import or deployment state.",
			},
		},
	}
	slices.Sort(receipt.Spec.Limitations)
	receipt, err = receipt.AssignTransferReceiptID()
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-ATR-500", err, ExitInternal)
	}
	if report := receipt.Validate(); !report.Valid {
		return writeLoadErrorWithExit(stdout, "YARA-ATR-500", errors.New("constructed transfer receipt is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(receipt)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-ATR-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-ATR-104", err, ExitInvalidInput)
	}
	target := "kubernetes:" + receipt.Spec.Target.ReferenceDigest
	subjects := []audit.Subject{
		{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID},
		{Kind: "ArtifactImportReceipt", Digest: importReceipt.Metadata.ImportReceiptID},
		{Kind: "ArtifactTransferReceipt", Digest: receipt.Metadata.TransferReceiptID},
	}
	if err := persistOperationAuditForTarget(options.auditPath, "artifact.transfer.record", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":             true,
		"transferReceiptId": receipt.Metadata.TransferReceiptID,
		"bundleId":          bundle.Metadata.BundleID,
		"importReceiptId":   importReceipt.Metadata.ImportReceiptID,
		"output":            options.outputPath,
		"auditOutput":       options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseTransferReceiptOptions(args []string, stderr io.Writer) (transferReceiptOptions, bool) {
	var options transferReceiptOptions
	flags := flag.NewFlagSet("artifact transfer record", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Exact DeploymentBundle")
	flags.StringVar(&options.importReceiptPath, "import-receipt", "", "Exact ArtifactImportReceipt")
	flags.StringVar(&options.stage, "stage", "", "Transfer stage: staging-to-vault|vault-to-registry|registry-to-runtime")
	flags.StringVar(&options.sourceRef, "source-attestation-ref", "", "Non-secret source attestation reference")
	flags.StringVar(&options.destinationRef, "destination-attestation-ref", "", "Non-secret destination attestation reference")
	flags.Var(&options.priorReceiptIDs, "prior-receipt", "Additional prior receipt ID (repeatable)")
	flags.StringVar(&options.name, "name", "", "ArtifactTransferReceipt name")
	flags.StringVar(&options.outputPath, "output", "", "Generated ArtifactTransferReceipt YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated transfer audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.bundlePath == "" || options.importReceiptPath == "" || options.stage == "" || options.sourceRef == "" || options.destinationRef == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "artifact transfer record requires --bundle --import-receipt --stage --source-attestation-ref --destination-attestation-ref --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	if !slices.Contains([]string{"staging-to-vault", "vault-to-registry", "registry-to-runtime"}, options.stage) {
		fmt.Fprintln(stderr, "--stage must be one of staging-to-vault, vault-to-registry or registry-to-runtime")
		return options, false
	}
	for _, value := range options.priorReceiptIDs {
		if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
			fmt.Fprintln(stderr, "--prior-receipt values must be SHA-256 digests")
			return options, false
		}
	}
	return options, true
}

func modelArtifactsFromBundle(bundle resources.DeploymentBundle) ([]resources.ImportedModelArtifact, error) {
	modelArtifacts := []resources.ImportedModelArtifact{}
	for _, artifact := range bundle.Spec.Artifacts {
		if artifact.Type != "huggingface-snapshot" {
			continue
		}
		files := make([]resources.ImportedModelArtifactBinding, 0, len(artifact.Files))
		for _, file := range artifact.Files {
			files = append(files, resources.ImportedModelArtifactBinding{Path: file.Path, Digest: file.Digest, SizeBytes: file.SizeBytes})
		}
		modelArtifacts = append(modelArtifacts, resources.ImportedModelArtifact{
			Ref: artifact.Ref, Revision: artifact.Revision, Files: files,
		})
	}
	if len(modelArtifacts) == 0 {
		return nil, errors.New("bundle does not contain transfer-tracked model artifacts")
	}
	return modelArtifacts, nil
}
