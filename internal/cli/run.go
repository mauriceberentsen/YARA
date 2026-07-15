package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/version"
)

const (
	ExitSuccess      = 0
	ExitInvalidInput = 2
	ExitInfeasible   = 3
	ExitInternal     = 4
	ExitUnsupported  = 5
)

type validationResult struct {
	Valid      bool   `json:"valid"`
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
}

type auditVerificationResult struct {
	Valid      bool   `json:"valid"`
	Events     int    `json:"events"`
	HeadDigest string `json:"headDigest"`
}

type catalogValidationResult struct {
	Valid      bool   `json:"valid"`
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Digest     string `json:"digest"`
	Candidates int    `json:"candidates"`
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(stdout, version.Version)
		return ExitSuccess
	}
	if len(args) == 3 && args[0] == "audit" && args[1] == "verify" {
		return verifyAudit(args[2], stdout)
	}
	if len(args) >= 2 && args[0] == "plan" && args[1] == "create" {
		return createPlan(args[2:], stdout, stderr)
	}
	if len(args) == 3 && args[0] == "plan" && args[1] == "explain" {
		return explainPlan(args[2], stdout)
	}
	if len(args) != 3 || args[1] != "validate" {
		writeUsage(stderr)
		return ExitInvalidInput
	}

	switch args[0] {
	case "request":
		request, err := resources.LoadPlatformRequest(args[2])
		if err != nil {
			return writeLoadError(stdout, "YARA-REQ-004", err)
		}
		return writeValidation(stdout, request.APIVersion, request.Kind, request.Metadata.Name, request.Validate())
	case "inventory":
		inventory, err := resources.LoadInventory(args[2])
		if err != nil {
			return writeLoadError(stdout, "YARA-INV-004", err)
		}
		return writeValidation(stdout, inventory.APIVersion, inventory.Kind, inventory.Metadata.Name, inventory.Validate())
	case "catalog":
		snapshot, err := catalog.Load(args[2])
		if err != nil {
			return writeLoadError(stdout, "YARA-CAT-004", err)
		}
		digest, err := snapshot.Digest()
		if err != nil {
			return writeLoadError(stdout, "YARA-CAT-500", err)
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(catalogValidationResult{
			Valid: true, APIVersion: snapshot.APIVersion, Kind: snapshot.Kind,
			Name: snapshot.Metadata.Name, Version: snapshot.Metadata.Version,
			Digest: digest, Candidates: len(snapshot.Candidates()),
		}); err != nil {
			return ExitInternal
		}
		return ExitSuccess
	case "plan":
		plan, err := resources.LoadPlatformPlan(args[2])
		if err != nil {
			return writeLoadError(stdout, "YARA-PLAN-004", err)
		}
		return writeValidation(stdout, plan.APIVersion, plan.Kind, plan.Metadata.Name, plan.Validate())
	default:
		writeUsage(stderr)
		return ExitUnsupported
	}
}

func verifyAudit(path string, output io.Writer) int {
	events, err := audit.LoadJSONL(path)
	if err != nil {
		return writeLoadError(output, "YARA-AUD-004", err)
	}
	head, err := audit.Verify(events)
	if err != nil {
		return writeLoadError(output, "YARA-AUD-005", err)
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(auditVerificationResult{Valid: true, Events: len(events), HeadDigest: head}); err != nil {
		return ExitInternal
	}
	return ExitSuccess
}

func writeValidation(output io.Writer, apiVersion, kind, name string, report diagnostics.Report) int {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if report.Valid {
		if err := encoder.Encode(validationResult{Valid: true, APIVersion: apiVersion, Kind: kind, Name: name}); err != nil {
			return ExitInternal
		}
		return ExitSuccess
	}
	if err := encoder.Encode(report); err != nil {
		return ExitInternal
	}
	return ExitInvalidInput
}

func writeLoadError(output io.Writer, code string, err error) int {
	report := diagnostics.NewReport(diagnostics.Error(code, err.Error()))
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if encodeErr := encoder.Encode(report); encodeErr != nil {
		return ExitInternal
	}
	return ExitInvalidInput
}

func writeUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  yara version")
	fmt.Fprintln(output, "  yara request validate <file>")
	fmt.Fprintln(output, "  yara inventory validate <file>")
	fmt.Fprintln(output, "  yara catalog validate <snapshot-file>")
	fmt.Fprintln(output, "  yara plan create --request <file> --inventory <file> --catalog <file> --output <file> --audit-output <file>")
	fmt.Fprintln(output, "  yara plan validate <file>")
	fmt.Fprintln(output, "  yara plan explain <file>")
	fmt.Fprintln(output, "  yara audit verify <file>")
}
