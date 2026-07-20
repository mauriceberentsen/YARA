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
	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type runtimeDriftSignalOptions struct {
	catalogPath     string
	assertion       string
	bundlePath      string
	preflightPath   string
	confirmTarget   string
	observerName    string
	observerVersion string
	status          string
	maxPreflightAge string
	checkSet        csvFlag
	name            string
	outputPath      string
	auditPath       string
}

func recordRuntimeDriftSignal(args []string, stdout, stderr io.Writer) int {
	options, ok := parseRuntimeDriftSignalOptions(args, stderr)
	if !ok {
		return ExitInvalidInput
	}
	snapshot, err := catalog.Load(options.catalogPath)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-101", err, ExitInvalidInput)
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-500", err, ExitInternal)
	}
	contractTarget, found := snapshot.ContractTarget(options.assertion)
	if !found {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-102", errors.New("assertion is not supported or is absent from catalog contract targets"), ExitInvalidInput)
	}
	bundle, err := resources.LoadDeploymentBundle(options.bundlePath)
	if err != nil || !bundle.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-103", errors.New("deployment bundle is invalid"), ExitInvalidInput)
	}
	preflight, err := resources.LoadTargetPreflightResult(options.preflightPath)
	if err != nil || !preflight.Validate().Valid {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-104", errors.New("target preflight result is invalid"), ExitInvalidInput)
	}
	if preflight.Spec.PlanID != bundle.Spec.PlanID || preflight.Spec.BundleID != bundle.Metadata.BundleID {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-106", errors.New("target preflight result does not bind the supplied bundle"), ExitInvalidInput)
	}
	if preflight.Spec.Target.ReferenceDigest != options.confirmTarget {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-107", errors.New("confirmed target digest does not match preflight target digest"), ExitInvalidInput)
	}
	preflightObservedAt, err := time.Parse(time.RFC3339Nano, preflight.Spec.ObservedAt)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-108", errors.New("target preflight observation timestamp is invalid"), ExitInvalidInput)
	}
	maxPreflightAge, err := time.ParseDuration(options.maxPreflightAge)
	if err != nil || maxPreflightAge <= 0 {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-109", errors.New("max preflight age must be a positive duration"), ExitInvalidInput)
	}
	now := time.Now().UTC()
	if now.Sub(preflightObservedAt) > maxPreflightAge {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-110", errors.New("target preflight evidence is stale for runtime drift recording"), ExitInfeasible)
	}
	checks, derivedStatus, err := parseRuntimeDriftChecks(options.checkSet)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-111", err, ExitInvalidInput)
	}
	if derivedStatus != options.status {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-112", errors.New("requested status does not match check-level drift outcomes"), ExitInvalidInput)
	}
	signal := resources.RuntimeDriftSignal{
		APIVersion: resources.APIVersion,
		Kind:       "RuntimeDriftSignal",
		Metadata: resources.RuntimeDriftSignalMetadata{
			Name: options.name,
		},
		Spec: resources.RuntimeDriftSignalSpec{
			RecordedAt:          now.Format(time.RFC3339Nano),
			CatalogDigest:       catalogDigest,
			AssertionRef:        options.assertion,
			RuntimeRef:          contractTarget.RuntimeRef,
			BundleID:            bundle.Metadata.BundleID,
			PreflightResultID:   preflight.Metadata.ResultID,
			PreflightObservedAt: preflight.Spec.ObservedAt,
			MaxPreflightAge:     options.maxPreflightAge,
			Observer: resources.TargetPreflightObserver{
				Name:    options.observerName,
				Version: options.observerVersion,
				Mode:    "read-only",
			},
			Target: preflight.Spec.Target,
			Status: options.status,
			Checks: checks,
			Limitations: []string{
				"Runtime drift signal records bounded read-only observation facts only.",
				"Runtime drift signal does not authorize deployment, publication or rollback actions.",
			},
		},
	}
	slices.Sort(signal.Spec.Limitations)
	signal, err = signal.AssignSignalID()
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-500", err, ExitInternal)
	}
	if report := signal.Validate(); !report.Valid {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-500", errors.New("constructed runtime drift signal is invalid"), ExitInternal)
	}
	data, err := yaml.Marshal(signal)
	if err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-500", err, ExitInternal)
	}
	if err := writeExclusive(options.outputPath, data); err != nil {
		return writeLoadErrorWithExit(stdout, "YARA-RDS-113", err, ExitInvalidInput)
	}
	subjects := []audit.Subject{
		{Kind: "CatalogSnapshot", Digest: catalogDigest},
		{Kind: "DeploymentBundle", Digest: bundle.Metadata.BundleID},
		{Kind: "TargetPreflightResult", Digest: preflight.Metadata.ResultID},
		{Kind: "RuntimeDriftSignal", Digest: signal.Metadata.SignalID},
	}
	target := "kubernetes:" + preflight.Spec.Target.ReferenceDigest
	if err := persistOperationAuditForTarget(options.auditPath, "runtime.drift-signal.record", "completed", "success", target, subjects, nil); err != nil {
		_ = os.Remove(options.outputPath)
		return writeLoadError(stdout, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"valid":             true,
		"signalId":          signal.Metadata.SignalID,
		"catalogDigest":     catalogDigest,
		"assertion":         options.assertion,
		"runtimeRef":        signal.Spec.RuntimeRef,
		"status":            signal.Spec.Status,
		"bundleId":          bundle.Metadata.BundleID,
		"preflightResultId": preflight.Metadata.ResultID,
		"output":            options.outputPath,
		"auditOutput":       options.auditPath,
	}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func parseRuntimeDriftSignalOptions(args []string, stderr io.Writer) (runtimeDriftSignalOptions, bool) {
	var options runtimeDriftSignalOptions
	flags := flag.NewFlagSet("runtime drift-signal record", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&options.catalogPath, "catalog", "", "CatalogSnapshot file")
	flags.StringVar(&options.assertion, "assertion", "", "Compatibility assertion ID")
	flags.StringVar(&options.bundlePath, "bundle", "", "DeploymentBundle file")
	flags.StringVar(&options.preflightPath, "preflight", "", "TargetPreflightResult file")
	flags.StringVar(&options.confirmTarget, "confirm-target", "", "Confirmed target reference digest")
	flags.StringVar(&options.observerName, "observer-name", "", "Read-only observer name")
	flags.StringVar(&options.observerVersion, "observer-version", "", "Read-only observer version")
	flags.StringVar(&options.status, "status", "", "Derived drift status: in-sync|drifted")
	flags.StringVar(&options.maxPreflightAge, "max-preflight-age", "4h", "Maximum age for preflight evidence")
	flags.Var(&options.checkSet, "check", "Drift check: id=<id>,expected=<value>,observed=<value>,status=<matched|drifted>[,reason-code=<YARA-...>] (repeatable)")
	flags.StringVar(&options.name, "name", "", "RuntimeDriftSignal name")
	flags.StringVar(&options.outputPath, "output", "", "Generated RuntimeDriftSignal YAML output")
	flags.StringVar(&options.auditPath, "audit-output", "", "Generated runtime drift audit JSONL output")
	if err := flags.Parse(args); err != nil {
		return options, false
	}
	if flags.NArg() != 0 ||
		options.catalogPath == "" || options.assertion == "" ||
		options.bundlePath == "" || options.preflightPath == "" || options.confirmTarget == "" ||
		options.observerName == "" || options.observerVersion == "" ||
		options.status == "" || options.name == "" || options.outputPath == "" || options.auditPath == "" || len(options.checkSet) == 0 {
		fmt.Fprintln(stderr, "runtime drift-signal record requires --catalog --assertion --bundle --preflight --confirm-target --observer-name --observer-version --status --check --name --output --audit-output")
		return options, false
	}
	if options.outputPath == options.auditPath {
		fmt.Fprintln(stderr, "--output and --audit-output must be different files")
		return options, false
	}
	if !slices.Contains([]string{"in-sync", "drifted"}, options.status) {
		fmt.Fprintln(stderr, "--status must be in-sync or drifted")
		return options, false
	}
	if !strings.HasPrefix(options.confirmTarget, "sha256:") {
		fmt.Fprintln(stderr, "--confirm-target must be a SHA-256 digest")
		return options, false
	}
	return options, true
}

func parseRuntimeDriftChecks(values []string) ([]resources.RuntimeDriftCheck, string, error) {
	checks := make([]resources.RuntimeDriftCheck, 0, len(values))
	for _, value := range values {
		parts := strings.Split(value, ",")
		fields := map[string]string{}
		for _, part := range parts {
			keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(keyValue) != 2 || strings.TrimSpace(keyValue[0]) == "" || strings.TrimSpace(keyValue[1]) == "" {
				return nil, "", errors.New("each --check must contain non-empty key=value pairs")
			}
			key := strings.TrimSpace(keyValue[0])
			if _, exists := fields[key]; exists {
				return nil, "", errors.New("each --check must not repeat keys")
			}
			fields[key] = strings.TrimSpace(keyValue[1])
		}
		id := fields["id"]
		expected := fields["expected"]
		observed := fields["observed"]
		status := fields["status"]
		reasonCode := fields["reason-code"]
		if id == "" || expected == "" || observed == "" || (status != "matched" && status != "drifted") {
			return nil, "", errors.New("each --check requires id, expected, observed and status=matched|drifted")
		}
		if (status == "matched" && reasonCode != "") || (status == "drifted" && !strings.HasPrefix(reasonCode, "YARA-")) {
			return nil, "", errors.New("drifted checks require reason-code and matched checks must omit reason-code")
		}
		evidenceDigest, err := canonical.Digest(struct {
			ID       string
			Expected string
			Observed string
			Status   string
		}{
			ID: id, Expected: expected, Observed: observed, Status: status,
		})
		if err != nil {
			return nil, "", fmt.Errorf("digest runtime drift check: %w", err)
		}
		checks = append(checks, resources.RuntimeDriftCheck{
			ID: id, Expected: expected, Observed: observed, Status: status, ReasonCode: reasonCode, EvidenceDigest: evidenceDigest,
		})
	}
	slices.SortFunc(checks, func(left, right resources.RuntimeDriftCheck) int {
		return strings.Compare(left.ID, right.ID)
	})
	for index := 1; index < len(checks); index++ {
		if checks[index].ID == checks[index-1].ID {
			return nil, "", errors.New("runtime drift check IDs must be unique")
		}
	}
	derivedStatus := "in-sync"
	for _, check := range checks {
		if check.Status == "drifted" {
			derivedStatus = "drifted"
			break
		}
	}
	return checks, derivedStatus, nil
}
