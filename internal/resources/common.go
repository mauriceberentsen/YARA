package resources

import (
	"regexp"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

const APIVersion = "yara.dev/v1alpha1"

var resourceNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type Metadata struct {
	Name string `json:"name" yaml:"name"`
}

func validateEnvelope(apiVersion, kind, expectedKind, codeNamespace string, metadata Metadata) []diagnostics.Diagnostic {
	var items []diagnostics.Diagnostic
	if apiVersion != APIVersion {
		items = append(items, diagnostics.Error(
			"YARA-"+codeNamespace+"-001",
			"Unsupported apiVersion; expected "+APIVersion+".",
			"apiVersion",
		))
	}
	if kind != expectedKind {
		items = append(items, diagnostics.Error(
			"YARA-"+codeNamespace+"-002",
			"Unexpected resource kind; expected "+expectedKind+".",
			"kind",
		))
	}
	if !resourceNamePattern.MatchString(strings.TrimSpace(metadata.Name)) {
		items = append(items, diagnostics.Error(
			"YARA-"+codeNamespace+"-003",
			"metadata.name must be a lowercase DNS-style name of at most 63 characters.",
			"metadata.name",
		))
	}
	return items
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
