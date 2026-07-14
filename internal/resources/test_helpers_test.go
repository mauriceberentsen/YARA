package resources

import (
	"slices"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

func assertDiagnostic(t *testing.T, report diagnostics.Report, code, path string) {
	t.Helper()
	for _, item := range report.Diagnostics {
		if item.Code == code && slices.Contains(item.Paths, path) {
			return
		}
	}
	t.Fatalf("expected diagnostic %s at %s, got %#v", code, path, report.Diagnostics)
}
