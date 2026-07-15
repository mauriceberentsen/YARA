package debugbundle

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/diagnostics"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

func TestBuildIsDeterministicAndOmitsSensitivePlanContent(t *testing.T) {
	plan := loadExamplePlan(t)
	first, report := Build(plan)
	if !report.Valid {
		t.Fatalf("build bundle: %#v", report.Diagnostics)
	}
	second, report := Build(plan)
	if !report.Valid || !reflect.DeepEqual(first, second) {
		t.Fatalf("bundle is not deterministic: %#v", report.Diagnostics)
	}
	data, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("encode bundle: %v", err)
	}
	for _, sensitive := range []string{
		plan.Metadata.Name,
		plan.Spec.Topology.Instances[0].ComponentRef,
		plan.Spec.Topology.Instances[0].Placement,
		plan.Spec.Decisions[0].Reasons[0],
		plan.Spec.Diagnostics[0].Message,
		plan.Spec.Confidence.Factors[0].SubjectRefs[0],
	} {
		if strings.Contains(string(data), sensitive) {
			t.Fatalf("bundle leaks omitted plan content %q", sensitive)
		}
	}
	if first.Spec.SecretScan.Status != "passed" || first.Spec.SecretScan.Findings != 0 {
		t.Fatalf("unexpected scan result: %#v", first.Spec.SecretScan)
	}
	if validation := first.Validate(); !validation.Valid {
		t.Fatalf("generated bundle is invalid: %#v", validation.Diagnostics)
	}
}

func TestBuildRejectsSecretCanaryWithoutEchoingIt(t *testing.T) {
	plan := loadExamplePlan(t)
	const canary = "supersecretcanary123"
	plan.Provenance.PlannerVersion = "api_key=" + canary
	var err error
	plan, err = plan.AssignPlanID()
	if err != nil {
		t.Fatalf("assign plan ID: %v", err)
	}
	bundle, report := Build(plan)
	if report.Valid || !hasDiagnostic(report, "YARA-DBG-003") {
		t.Fatalf("expected secret-scan rejection: %#v", report.Diagnostics)
	}
	if bundle.Metadata.BundleID != "" {
		t.Fatal("secret-like input must not produce a bundle")
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	if strings.Contains(string(data), canary) {
		t.Fatal("secret rejection diagnostic echoed the canary")
	}
}

func TestSecretPatternGateCoversSupportedCredentialShapes(t *testing.T) {
	for _, candidate := range []string{
		`{"apiKey":"abcdefghijklmnop"}`,
		"password=abcdefghijklmnop",
		"Authorization: Bearer abcdefghijklmnop",
		"aws=AKIAIOSFODNN7EXAMPLE",
		"registry=https://operator:abcdefghijklmnop@example.invalid",
		"-----BEGIN PRIVATE KEY-----",
	} {
		if !hasSecretLikeContent([]byte(candidate)) {
			t.Fatalf("secret pattern was not detected in %q", candidate)
		}
	}
	for _, safe := range []string{`{"secretScan":{"status":"passed"}}`, "spec.secretReferences", "sha256:0123456789abcdef"} {
		if hasSecretLikeContent([]byte(safe)) {
			t.Fatalf("safe support metadata triggered secret pattern: %q", safe)
		}
	}
}

func loadExamplePlan(t *testing.T) resources.PlatformPlan {
	t.Helper()
	plan, err := resources.LoadPlatformPlan(filepath.Join("..", "..", "docs", "examples", "platform-plan.yaml"))
	if err != nil {
		t.Fatalf("load plan: %v", err)
	}
	return plan
}

func hasDiagnostic(report diagnostics.Report, code string) bool {
	for _, item := range report.Diagnostics {
		if item.Code == code {
			return true
		}
	}
	return false
}
