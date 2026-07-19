package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/audit"
	"github.com/mauriceberentsen/YARA/internal/changeset"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

func TestIssueAndVerifyExecutionAuthorization(t *testing.T) {
	directory := t.TempDir()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	bundlePath := writeKubernetesBundle(t, directory)
	bundle, _ := resources.LoadDeploymentBundle(bundlePath)
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('c'), ServerVersion: "v1.35.2"}
	preflightPath := writeFreshPreflight(t, directory, bundle, target, now)
	preflight, _ := resources.LoadTargetPreflightResult(preflightPath)
	desired, err := changeset.DesiredObjects(bundle)
	if err != nil {
		t.Fatal(err)
	}
	observation := changeset.Observation{Target: target}
	for _, object := range desired {
		observation.Objects = append(observation.Objects, changeset.ObjectObservation{Reference: object.Reference, Readable: true})
	}
	changeSet, err := changeset.Evaluate("reference-change-set", bundle, preflight, observation, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	changeSetPath := filepath.Join(directory, "change-set.yaml")
	writeYAMLFixture(t, changeSetPath, changeSet)
	approval := resources.DeploymentApproval{APIVersion: resources.APIVersion, Kind: "DeploymentApproval", Metadata: resources.DeploymentApprovalMetadata{Name: "reference-approval"}, Spec: resources.DeploymentApprovalSpec{
		Decision: "approved", Effect: "review-only", RecordedAt: now.Add(time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
		PlanID: bundle.Spec.PlanID, BundleID: bundle.Metadata.BundleID, PreflightResultID: preflight.Metadata.ResultID, ChangeSetID: changeSet.Metadata.ChangeSetID, Target: target,
		Actor: resources.ApprovalActor{ID: "local:reviewer", Type: "user", Assurance: "self-asserted-local"}, Reason: resources.ApprovalReason{Type: "user-review", Reference: "ticket-123"}, Limitations: []string{"Review only."},
	}}
	approval, err = approval.AssignApprovalID()
	if err != nil {
		t.Fatal(err)
	}
	approvalPath := filepath.Join(directory, "approval.yaml")
	writeYAMLFixture(t, approvalPath, approval)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privatePath, publicPath := writeAuthorizationKeys(t, directory, publicKey, privateKey)
	authorizationPath, auditPath := filepath.Join(directory, "authorization.yaml"), filepath.Join(directory, "authorization.audit.jsonl")
	args := []string{"--bundle", bundlePath, "--preflight", preflightPath, "--change-set", changeSetPath, "--approval", approvalPath, "--private-key", privatePath, "--key-id", "operations-key-1", "--name", "reference-authorization", "--output", authorizationPath, "--audit-output", auditPath, "--valid-for", "10m"}
	var stdout, stderr bytes.Buffer
	if exit := issueExecutionAuthorizationAt(args, &stdout, &stderr, func() time.Time { return now.Add(2 * time.Minute) }); exit != ExitSuccess {
		t.Fatalf("issue: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	authorization, err := resources.LoadExecutionAuthorization(authorizationPath)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Spec.Constraints.AllowDelete || !authorization.Spec.Constraints.AllowActiveVerification || len(authorization.Spec.Constraints.AcceptedPreflightBlockers) != 4 {
		t.Fatalf("unsafe/incomplete constraints: %#v", authorization.Spec.Constraints)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := verifyExecutionAuthorizationAt([]string{"--authorization", authorizationPath, "--public-key", publicPath}, &stdout, &stderr, func() time.Time { return now.Add(3 * time.Minute) }); exit != ExitSuccess {
		t.Fatalf("verify: exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	events, err := audit.LoadJSONL(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.Verify(events); err != nil {
		t.Fatal(err)
	}
	terminal := events[len(events)-1]
	if terminal.Spec.Action != "authorization.issue.completed" || len(terminal.Spec.Subjects) != 5 || terminal.Spec.Subjects[4].Digest != authorization.Metadata.AuthorizationID {
		t.Fatalf("unexpected authorization audit: %#v", terminal.Spec)
	}
	durable := string(mustReadFile(t, authorizationPath)) + string(mustReadFile(t, auditPath))
	if strings.Contains(durable, privatePath) || strings.Contains(durable, string(privateKey)) {
		t.Fatal("private key material/path leaked")
	}
}

func TestAuthorizationTamperAndAuditFailureFailClosed(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	authorization := resources.ExecutionAuthorization{APIVersion: resources.APIVersion, Kind: "ExecutionAuthorization", Metadata: resources.ExecutionAuthorizationMetadata{Name: "auth"}, Spec: resources.ExecutionAuthorizationSpec{
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano), PlanID: testCLIDigest('a'), BundleID: testCLIDigest('b'), PreflightResultID: testCLIDigest('c'), ChangeSetID: testCLIDigest('d'), ApprovalID: testCLIDigest('e'), Target: resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: testCLIDigest('f'), ServerVersion: "v1.35.2"}, Issuer: resources.ExecutionAuthorizationIssuer{KeyID: "key"}, Constraints: resources.ExecutionAuthorizationConstraints{AllowedActions: []string{"create"}, MaxOperations: 1},
	}}
	authorization, _ = authorization.Sign(privateKey)
	directory := t.TempDir()
	_, publicPath := writeAuthorizationKeys(t, directory, publicKey, privateKey)
	authorization.Spec.Constraints.MaxOperations = 2
	path := filepath.Join(directory, "tampered.yaml")
	writeYAMLFixture(t, path, authorization)
	var stdout, stderr bytes.Buffer
	if exit := verifyExecutionAuthorizationAt([]string{"--authorization", path, "--public-key", publicPath}, &stdout, &stderr, func() time.Time { return now.Add(time.Minute) }); exit != ExitInfeasible {
		t.Fatalf("tamper exit=%d stdout=%s", exit, stdout.String())
	}
}

func writeAuthorizationKeys(t *testing.T, directory string, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (string, string) {
	t.Helper()
	privateDER, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	publicDER, _ := x509.MarshalPKIXPublicKey(publicKey)
	privatePath, publicPath := filepath.Join(directory, "private.pem"), filepath.Join(directory, "public.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return privatePath, publicPath
}

func writeYAMLFixture(t *testing.T, path string, value any) {
	t.Helper()
	data, err := yaml.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
