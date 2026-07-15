package cli

import (
	"fmt"
	"io"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type validationOptions struct {
	inputPath string
	auditPath string
}

func parseValidationOptions(args []string, stderr io.Writer) (validationOptions, bool) {
	if len(args) == 1 && args[0] != "" {
		return validationOptions{inputPath: args[0]}, true
	}
	if len(args) == 3 && args[0] != "" && args[1] == "--audit-output" && args[2] != "" {
		return validationOptions{inputPath: args[0], auditPath: args[2]}, true
	}
	writeUsage(stderr)
	return validationOptions{}, false
}

func canonicalSubject(kind string, value any) (audit.Subject, error) {
	digest, err := canonical.Digest(value)
	if err != nil {
		return audit.Subject{}, fmt.Errorf("digest %s for audit: %w", kind, err)
	}
	return audit.Subject{Kind: kind, Digest: digest}, nil
}

func writeValidationResultWithAudit(output io.Writer, auditPath, action string, subject audit.Subject, apiVersion, kind, name string, report diagnostics.Report) int {
	terminalSuffix, outcome := "completed", "success"
	if !report.Valid {
		terminalSuffix, outcome = "failed", "failed"
	}
	if err := persistOperationAudit(auditPath, action, terminalSuffix, outcome, []audit.Subject{subject}, diagnosticCodes(report.Diagnostics)); err != nil {
		return writeLoadError(output, "YARA-AUD-005", err)
	}
	return writeValidation(output, apiVersion, kind, name, report)
}

func writeCatalogValidationAudit(auditPath string, subject audit.Subject, items []diagnostics.Diagnostic) error {
	return persistOperationAudit(auditPath, "catalog.validate", "completed", "success", []audit.Subject{subject}, diagnosticCodes(items))
}

func writeAuditedLoadError(output io.Writer, auditPath, action, kind, path, code string, err error, available []audit.Subject) int {
	subjects := append([]audit.Subject{}, available...)
	subjects = append(subjects, attemptedInputSubject(kind, path))
	if auditErr := persistOperationAudit(auditPath, action, "failed", "failed", subjects, []string{code}); auditErr != nil {
		return writeLoadError(output, "YARA-AUD-005", auditErr)
	}
	return writeLoadError(output, code, err)
}
