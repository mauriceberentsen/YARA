package resources

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

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
	addTestSupplyChain(t, &bundle, content)
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

func TestBundleArtifactFilesRejectPathTraversal(t *testing.T) {
	for _, candidate := range []string{"..", "../secret", "/absolute", "weights/../secret"} {
		if validBundleArtifactFiles([]BundleArtifactFile{{Path: candidate, Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", SizeBytes: 1}}) {
			t.Fatalf("accepted unsafe artifact path %q", candidate)
		}
	}
}

func TestDeploymentBundleRejectsMalformedSBOM(t *testing.T) {
	bundle := validDeploymentBundle(t)
	for index := range bundle.Spec.Files {
		if bundle.Spec.Files[index].Path == bundle.Spec.SupplyChain.SBOMPath {
			bundle.Spec.Files[index].Content = "{}"
			bundle.Spec.Files[index].Digest = BundleContentDigest("{}")
		}
	}
	bundle, _ = bundle.AssignBundleID()
	if report := bundle.Validate(); report.Valid {
		t.Fatal("bundle accepted a malformed SPDX document")
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
			Artifacts:      []BundleArtifact{{Type: "oci-image", Ref: "image:1", Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Platforms: []string{"linux/amd64"}, LicenseID: "MIT", LicenseSource: "https://example.invalid"}},
			RequiredInputs: []BundleRequiredInput{}, Operations: []BundleOperation{{Stage: 0, Action: "create", InstanceID: "service"}},
			Preflight: []string{"preflight"}, Postflight: []string{"postflight"}, Limitations: []string{"limitation"},
		},
	}
	addTestSupplyChain(t, &bundle, content)
	assigned, err := bundle.AssignBundleID()
	if err != nil {
		t.Fatalf("assign identity: %v", err)
	}
	return assigned
}

func addTestSupplyChain(t *testing.T, bundle *DeploymentBundle, composeContent string) {
	t.Helper()
	manifest := OfflineAcquisitionManifest{
		APIVersion: APIVersion, Kind: "OfflineAcquisitionManifest", Metadata: OfflineAcquisitionManifestMetadata{Name: bundle.Metadata.Name},
		Spec: OfflineAcquisitionManifestSpec{
			PlanID: bundle.Spec.PlanID, CatalogDigest: bundle.Spec.CatalogDigest, GeneratedBy: bundle.Spec.Renderer,
			Artifacts: []OfflineAcquisitionArtifact{{
				Type: "oci-image", Ref: bundle.Spec.Artifacts[0].Ref, Method: "mirror-oci-index", Digest: bundle.Spec.Artifacts[0].Digest,
				Platforms: []string{"linux/amd64"}, LicenseID: bundle.Spec.Artifacts[0].LicenseID, LicenseSource: bundle.Spec.Artifacts[0].LicenseSource,
			}},
			Policy: OfflineAcquisitionPolicy{NetworkRequiredDuringAcquisition: true, NetworkAllowedDuringExecution: false, RequireDigestVerification: true, RequireCompleteSet: true},
		},
	}
	manifest, err := manifest.AssignManifestID()
	if err != nil {
		t.Fatalf("assign manifest identity: %v", err)
	}
	offline, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	sbom, err := json.Marshal(map[string]any{
		"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "YARA-" + bundle.Metadata.Name,
		"documentNamespace": "https://yara.dev/spdx/test", "packages": []map[string]any{{
			"name": bundle.Spec.Artifacts[0].Ref, "versionInfo": bundle.Spec.Artifacts[0].Digest,
			"licenseDeclared": bundle.Spec.Artifacts[0].LicenseID, "licenseConcluded": "NOASSERTION",
		}},
	})
	if err != nil {
		t.Fatalf("marshal SPDX: %v", err)
	}
	bundle.Spec.SupplyChain = BundleSupplyChain{SBOMPath: "sbom.spdx.json", OfflineAcquisitionPath: "offline-acquisition.yaml"}
	bundle.Spec.Files = []BundleFile{
		{Path: "compose.yaml", MediaType: "application/yaml", Digest: BundleContentDigest(composeContent), Content: composeContent},
		{Path: "offline-acquisition.yaml", MediaType: "application/vnd.yara.offline-acquisition+yaml", Digest: BundleContentDigest(string(offline)), Content: string(offline)},
		{Path: "sbom.spdx.json", MediaType: "application/spdx+json", Digest: BundleContentDigest(string(sbom)), Content: string(sbom)},
	}
}
