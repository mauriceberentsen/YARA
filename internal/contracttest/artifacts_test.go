package contracttest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/catalog"
)

type fixedOCIInspector struct {
	raw []byte
	err error
}

func (i fixedOCIInspector) Raw(context.Context, string) ([]byte, error) {
	return i.raw, i.err
}

func TestRegistryArtifactVerifierChecksOCIAndHuggingFaceIdentities(t *testing.T) {
	const metadata = `{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","siblings":[{"rfilename":"model.safetensors","size":42,"lfs":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":42}}]}`
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !strings.Contains(request.URL.Path, "/org/model/revision/") || request.URL.Query().Get("blobs") != "true" {
			t.Fatalf("unexpected request: %s", request.URL.String())
		}
		_, _ = response.Write([]byte(metadata))
	}))
	defer server.Close()
	raw := []byte(`{"schemaVersion":2}`)
	sum := sha256.Sum256(raw)
	target := catalog.ContractTarget{
		RuntimeArtifacts: []catalog.ArtifactReference{{
			Type: "oci-image", Ref: "example/image:1", Digest: "sha256:" + hex.EncodeToString(sum[:]),
		}},
		ModelArtifact: catalog.ArtifactReference{
			Type: "huggingface-snapshot", Ref: "org/model", Revision: strings.Repeat("a", 40),
			Files: []catalog.ArtifactFile{{Path: "model.safetensors", Digest: "sha256:" + strings.Repeat("b", 64), SizeBytes: 42}},
		},
	}
	checks, err := (RegistryArtifactVerifier{
		Client: server.Client(), Inspector: fixedOCIInspector{raw: raw}, ModelAPIBase: server.URL,
	}).Verify(t.Context(), target)
	if err != nil {
		t.Fatalf("verify artifacts: %v", err)
	}
	if len(checks) != 4 {
		t.Fatalf("expected four checks, got %#v", checks)
	}
	for _, item := range checks {
		if item.Status != "passed" || item.DiagnosticCode != "" {
			t.Fatalf("unexpected check: %#v", item)
		}
	}
}

func TestRegistryArtifactVerifierPersistsDigestMismatchAsFailedCheck(t *testing.T) {
	const metadata = `{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","siblings":[]}`
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(metadata))
	}))
	defer server.Close()
	target := catalog.ContractTarget{
		RuntimeArtifacts: []catalog.ArtifactReference{{Type: "oci-image", Ref: "example/image:1", Digest: "sha256:" + strings.Repeat("c", 64)}},
		ModelArtifact:    catalog.ArtifactReference{Type: "huggingface-snapshot", Ref: "org/model", Revision: strings.Repeat("a", 40)},
	}
	checks, err := (RegistryArtifactVerifier{
		Client: server.Client(), Inspector: fixedOCIInspector{raw: []byte("different")}, ModelAPIBase: server.URL,
	}).Verify(t.Context(), target)
	if err != nil {
		t.Fatalf("verify artifacts: %v", err)
	}
	assertCheck(t, checks, "artifact.runtime.0.digest", "failed", "YARA-CTR-120")
}
