package contracttest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type ArtifactVerifier interface {
	Verify(context.Context, catalog.ContractTarget) ([]resources.ContractTestCheck, error)
}

type RegistryArtifactVerifier struct {
	Client       *http.Client
	Inspector    OCIInspector
	ModelAPIBase string
}

type OCIInspector interface {
	Raw(context.Context, string) ([]byte, error)
}

type DockerOCIInspector struct{}

func (DockerOCIInspector) Raw(ctx context.Context, reference string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", "buildx", "imagetools", "inspect", "--raw", reference).Output()
}

func (v RegistryArtifactVerifier) Verify(ctx context.Context, target catalog.ContractTarget) ([]resources.ContractTestCheck, error) {
	checks := make([]resources.ContractTestCheck, 0)
	inspector := v.Inspector
	if inspector == nil {
		inspector = DockerOCIInspector{}
	}
	for index, artifact := range target.RuntimeArtifacts {
		if artifact.Type != "oci-image" {
			continue
		}
		raw, err := inspector.Raw(ctx, artifact.Ref)
		if err != nil {
			return nil, fmt.Errorf("inspect OCI artifact %d: %w", index, err)
		}
		sum := sha256.Sum256(raw)
		observed := "sha256:" + hex.EncodeToString(sum[:])
		checks = append(checks, contractCheck(
			fmt.Sprintf("artifact.runtime.%d.digest", index), observed == artifact.Digest,
			"YARA-CTR-120", map[string]string{"expected": artifact.Digest, "observed": observed},
		))
	}
	modelChecks, err := v.verifyModel(ctx, target.ModelArtifact)
	if err != nil {
		return nil, err
	}
	checks = append(checks, modelChecks...)
	slices.SortFunc(checks, func(left, right resources.ContractTestCheck) int { return strings.Compare(left.ID, right.ID) })
	return checks, nil
}

func (v RegistryArtifactVerifier) verifyModel(ctx context.Context, artifact catalog.ArtifactReference) ([]resources.ContractTestCheck, error) {
	if artifact.Type != "huggingface-snapshot" {
		return nil, fmt.Errorf("unsupported model artifact type %q", artifact.Type)
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	base := strings.TrimSuffix(v.ModelAPIBase, "/")
	if base == "" {
		base = "https://huggingface.co/api/models"
	}
	endpoint := base + "/" + artifact.Ref + "/revision/" + artifact.Revision + "?blobs=true"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create model metadata request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch model metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch model metadata: HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read model metadata: %w", err)
	}
	var metadata struct {
		SHA      string `json:"sha"`
		Siblings []struct {
			Name string `json:"rfilename"`
			Size int64  `json:"size"`
			LFS  struct {
				SHA256 string `json:"sha256"`
				Size   int64  `json:"size"`
			} `json:"lfs"`
		} `json:"siblings"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("decode model metadata: %w", err)
	}
	checks := []resources.ContractTestCheck{contractCheck(
		"artifact.model.revision", metadata.SHA == artifact.Revision, "YARA-CTR-121",
		map[string]string{"expected": artifact.Revision, "observed": metadata.SHA},
	)}
	siblings := make(map[string]struct {
		Digest string
		Size   int64
	}, len(metadata.Siblings))
	for _, sibling := range metadata.Siblings {
		siblings[sibling.Name] = struct {
			Digest string
			Size   int64
		}{Digest: sibling.LFS.SHA256, Size: sibling.LFS.Size}
	}
	for index, expected := range artifact.Files {
		observed := siblings[expected.Path]
		checks = append(checks,
			contractCheck(fmt.Sprintf("artifact.model.file.%d.digest", index), "sha256:"+observed.Digest == expected.Digest, "YARA-CTR-122", map[string]string{"expected": expected.Digest, "observed": "sha256:" + observed.Digest}),
			contractCheck(fmt.Sprintf("artifact.model.file.%d.size", index), observed.Size == expected.SizeBytes, "YARA-CTR-123", map[string]int64{"expected": expected.SizeBytes, "observed": observed.Size}),
		)
	}
	return checks, nil
}

func contractCheck(id string, passed bool, code string, evidence any) resources.ContractTestCheck {
	status, diagnosticCode := "passed", ""
	if !passed {
		status, diagnosticCode = "failed", code
	}
	item, err := check(id, status, diagnosticCode, evidence)
	if err != nil {
		panic(err)
	}
	return item
}
