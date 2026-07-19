package resources

import "testing"

func TestDeploymentBundleIdentityAndContentDigest(t *testing.T) {
	content := "services: {}\n"
	bundle := DeploymentBundle{
		APIVersion: APIVersion,
		Kind:       "DeploymentBundle",
		Metadata:   DeploymentBundleMetadata{Name: "reference-stack"},
		Spec: DeploymentBundleSpec{
			PlanID:        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			CatalogDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Renderer:      BundleRenderer{Name: "yara.docker-compose", Version: "0.1.0", Target: "docker-compose"},
			Files:         []BundleFile{{Path: "compose.yaml", MediaType: "application/yaml", Digest: BundleContentDigest(content), Content: content}},
			Artifacts: []BundleArtifact{{
				Type: "oci-image", Ref: "example/image:1.0.0",
				Digest:    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				Platforms: []string{"linux/amd64"}, LicenseID: "MIT", LicenseSource: "https://example.invalid/license",
			}},
			RequiredInputs: []BundleRequiredInput{},
			Operations:     []BundleOperation{{Stage: 0, Action: "create", InstanceID: "gateway"}},
			Preflight:      []string{"Docker is available."},
			Postflight:     []string{"Health responds."},
			Limitations:    []string{"No deployment claim."},
		},
	}
	assigned, err := bundle.AssignBundleID()
	if err != nil {
		t.Fatalf("assign identity: %v", err)
	}
	if report := assigned.Validate(); !report.Valid {
		t.Fatalf("bundle is invalid: %#v", report.Diagnostics)
	}
	assigned.Spec.Files[0].Content = "services: {changed: {}}\n"
	if report := assigned.Validate(); report.Valid {
		t.Fatal("mutated file content retained its bundle identity")
	}
}

func TestDeploymentBundleRejectsUnpinnedOCIArtifact(t *testing.T) {
	bundle := validDeploymentBundle(t)
	bundle.Spec.Artifacts[0].Digest = ""
	if report := bundle.Validate(); report.Valid {
		t.Fatal("bundle accepted an unpinned OCI artifact")
	}
}

func validDeploymentBundle(t *testing.T) DeploymentBundle {
	t.Helper()
	content := "services: {}\n"
	bundle := DeploymentBundle{
		APIVersion: APIVersion, Kind: "DeploymentBundle", Metadata: DeploymentBundleMetadata{Name: "bundle"},
		Spec: DeploymentBundleSpec{
			PlanID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CatalogDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Renderer:       BundleRenderer{Name: "renderer", Version: "1.0.0", Target: "docker-compose"},
			Files:          []BundleFile{{Path: "compose.yaml", MediaType: "application/yaml", Digest: BundleContentDigest(content), Content: content}},
			Artifacts:      []BundleArtifact{{Type: "oci-image", Ref: "image:1", Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Platforms: []string{"linux/amd64"}, LicenseID: "MIT", LicenseSource: "https://example.invalid"}},
			RequiredInputs: []BundleRequiredInput{}, Operations: []BundleOperation{{Stage: 0, Action: "create", InstanceID: "service"}},
			Preflight: []string{"preflight"}, Postflight: []string{"postflight"}, Limitations: []string{"limitation"},
		},
	}
	assigned, err := bundle.AssignBundleID()
	if err != nil {
		t.Fatalf("assign identity: %v", err)
	}
	return assigned
}
