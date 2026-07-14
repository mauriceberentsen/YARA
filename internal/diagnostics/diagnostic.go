package diagnostics

// Severity describes the effect of a diagnostic on the requested operation.
type Severity string

const (
	SeverityError    Severity = "error"
	SeverityQuestion Severity = "question"
	SeverityWarning  Severity = "warning"
	SeverityAdvisory Severity = "advisory"
)

// Diagnostic is a stable, machine-readable domain condition.
type Diagnostic struct {
	Code        string   `json:"code" yaml:"code"`
	Severity    Severity `json:"severity" yaml:"severity"`
	Message     string   `json:"message" yaml:"message"`
	Paths       []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	Remediation []string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

// Report contains diagnostics produced while loading or validating a resource.
type Report struct {
	Valid       bool         `json:"valid" yaml:"valid"`
	Diagnostics []Diagnostic `json:"diagnostics" yaml:"diagnostics"`
}

// NewReport derives validity from the supplied diagnostics.
func NewReport(items ...Diagnostic) Report {
	report := Report{Valid: true, Diagnostics: items}
	for _, item := range items {
		if item.Severity == SeverityError || item.Severity == SeverityQuestion {
			report.Valid = false
			break
		}
	}
	return report
}

// Error creates an error-level diagnostic.
func Error(code, message string, paths ...string) Diagnostic {
	return Diagnostic{Code: code, Severity: SeverityError, Message: message, Paths: paths}
}
