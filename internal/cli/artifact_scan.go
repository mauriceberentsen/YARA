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

type scanReceiptOptions struct {
	bundlePath, transferReceiptPath, scannerName, scannerVersion, scannerProfile string
	policyDigest, verdict, reasonReference                                       string
	name, outputPath, auditPath                                                  string
	priorReceiptIDs                                                              csvFlag
}

func recordArtifactScan(args []string, stdout, stderr io.Writer) int {
	options, ok := parseScanReceiptOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil || !bundle.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-ASC-101", errors.New("deployment bundle is invalid"), ExitInvalidInput)
	}
	transferReceipt, err := resources.LoadArtifactTransferReceipt(options.transferReceiptPath)
	if err != nil || !transferReceipt.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-ASC-102", errors.New("artifact transfer receipt is invalid"), ExitInvalidInput)
	}
	if transferReceipt.Spec.PlanID != bundle.Spec.PlanID || transferReceipt.Spec.BundleID != bundle.Metadata.BundleID || transferReceipt.Spec.CatalogDigest != bundle.Spec.CatalogDigest {
		return writeLoadErrorWithExit(stdout, "YARA-ASC-103", errors.New("transfer receipt does not bind the supplied bundle"), ExitInvalidInput)
	}
	modelArtifacts, err := modelArtifactsFromBundle(bundle)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-ASC-103", err, ExitInvalidInput)
	}
	priorIDs := uniqueSortedStrings(append(slices.Clone(options.priorReceiptIDs), transferReceipt.Metadata.TransferReceiptID))
	receipt := resources.ArtifactScanReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "ArtifactScanReceipt",
		Metadata: resources.ArtifactScanReceiptMetadata{
			Name: options.name,
		},
		Spec: resources.ArtifactScanReceiptSpec{
			RecordedAt:      time.Now().UTC().Format(time.RFC3339Nano),
			PlanID:          bundle.Spec.PlanID,
			BundleID:        bundle.Metadata.BundleID,
			CatalogDigest:   bundle.Spec.CatalogDigest,
			Target:          transferReceipt.Spec.Target,
			Scanner:         resources.ScanToolIdentity{Name: options.scannerName, Version: options.scannerVersion, Profile: options.scannerProfile, PolicyDigest: options.policyDigest},
			Verdict:         options.verdict,
			ReasonReference: options.reasonReference,
			PriorReceiptIDs: priorIDs,
			ModelArtifacts:  modelArtifacts,
			Limitations: []string{
				"Scan receipt records scanner identity and non-secret verdict references only.",
				"Scan receipt excludes raw scanner output, findings payloads and secret-bearing metadata.",
			},
		},
	}
	slices.Sort(receipt.Spec.Limitations)
	receipt, err = receipt.AssignScanReceiptID()
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-ASC-500", err, ExitInternal)
	}
	if report := receipt.Validate(); !report.Valid {
		return writeLoadErrorWithExit(stdout, "YARA-ASC-500", errors.New("constructed scan receipt is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(receipt)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-ASC-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-ASC-104", err, ExitInvalidInput)
	}
	target := "kubernetes:" + receipt.Spec.Target.ReferenceDigest
	subjects := []audit.Subject{
		{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID},
		{Kind: "ArtifactTransferReceipt", Digest: transferReceipt.Metadata.TransferReceiptID},
		{Kind: "ArtifactScanReceipt", Digest: receipt.Metadata.ScanReceiptID},
	}
	if err := persistOperationAuditForTarget(options.auditPath, "artifact.scan.record", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":             true,
		"scanReceiptId":     receipt.Metadata.ScanReceiptID,
		"bundleId":          bundle.Metadata.BundleID,
		"transferReceiptId": transferReceipt.Metadata.TransferReceiptID,
		"output":            options.outputPath,
		"auditOutput":       options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseScanReceiptOptions(args []string, stderr io.Writer) (scanReceiptOptions, bool) {
	var options scanReceiptOptions
	flags := flag.NewFlagSet("artifact scan record", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.bundlePath, "bundle", "", "Exact DeploymentBundle")
	flags.StringVar(&options.transferReceiptPath, "transfer-receipt", "", "Exact ArtifactTransferReceipt")
	flags.StringVar(&options.scannerName, "scanner-name", "", "Scanner name")
	flags.StringVar(&options.scannerVersion, "scanner-version", "", "Scanner version")
	flags.StringVar(&options.scannerProfile, "scanner-profile", "", "Scanner profile")
	flags.StringVar(&options.policyDigest, "policy-digest", "", "Scanner policy digest")
	flags.StringVar(&options.verdict, "verdict", "", "Scan verdict: passed|failed|blocked")
	flags.StringVar(&options.reasonReference, "reason-reference", "", "Non-secret scan reason reference")
	flags.Var(&options.priorReceiptIDs, "prior-receipt", "Additional prior receipt ID (repeatable)")
	flags.StringVar(&options.name, "name", "", "ArtifactScanReceipt name")
	flags.StringVar(&options.outputPath, "output", "", "Generated ArtifactScanReceipt YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated scan audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 || options.bundlePath == "" || options.transferReceiptPath == "" || options.scannerName == "" || options.scannerVersion == "" || options.scannerProfile == "" || options.policyDigest == "" || options.verdict == "" || options.reasonReference == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" {
		fmt.Fprintln(stderr, "artifact scan record requires --bundle --transfer-receipt --scanner-name --scanner-version --scanner-profile --policy-digest --verdict --reason-reference --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	if !strings.HasPrefix(options.policyDigest, "sha256:") || len(options.policyDigest) != 71 {
		fmt.Fprintln(stderr, "--policy-digest must be a SHA-256 digest")
		return options, false
	}
	if !slices.Contains([]string{"passed", "failed", "blocked"}, options.verdict) {
		fmt.Fprintln(stderr, "--verdict must be one of passed, failed or blocked")
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
