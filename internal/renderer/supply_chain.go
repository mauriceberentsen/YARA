package renderer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

const (
	sbomPath               = "sbom.spdx.json"
	offlineAcquisitionPath = "offline-acquisition.yaml"
)

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	Comment           string             `json:"comment"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string         `json:"SPDXID"`
	Name             string         `json:"name"`
	VersionInfo      string         `json:"versionInfo"`
	DownloadLocation string         `json:"downloadLocation"`
	FilesAnalyzed    bool           `json:"filesAnalyzed"`
	LicenseConcluded string         `json:"licenseConcluded"`
	LicenseDeclared  string         `json:"licenseDeclared"`
	CopyrightText    string         `json:"copyrightText"`
	Checksums        []spdxChecksum `json:"checksums,omitempty"`
	LicenseComments  string         `json:"licenseComments"`
	PrimaryPurpose   string         `json:"primaryPackagePurpose,omitempty"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func supplyChainFiles(name, publishedAt string, planID, catalogDigest string, renderer resources.BundleRenderer, artifacts []resources.BundleArtifact) ([]resources.BundleFile, resources.BundleSupplyChain, error) {
	offline, err := buildOfflineAcquisitionManifest(name, planID, catalogDigest, renderer, artifacts)
	if err != nil {
		return nil, resources.BundleSupplyChain{}, err
	}
	offlineData, err := yaml.Marshal(offline)
	if err != nil {
		return nil, resources.BundleSupplyChain{}, fmt.Errorf("marshal offline acquisition manifest: %w", err)
	}

	sbomData, err := json.MarshalIndent(buildSPDX(name, publishedAt, planID, catalogDigest, renderer, artifacts), "", "  ")
	if err != nil {
		return nil, resources.BundleSupplyChain{}, fmt.Errorf("marshal SPDX SBOM: %w", err)
	}
	sbomData = append(sbomData, '\n')

	return []resources.BundleFile{
		bundleFile(offlineAcquisitionPath, "application/vnd.yara.offline-acquisition+yaml", string(offlineData)),
		bundleFile(sbomPath, "application/spdx+json", string(sbomData)),
	}, resources.BundleSupplyChain{SBOMPath: sbomPath, OfflineAcquisitionPath: offlineAcquisitionPath}, nil
}

func buildOfflineAcquisitionManifest(name, planID, catalogDigest string, renderer resources.BundleRenderer, artifacts []resources.BundleArtifact) (resources.OfflineAcquisitionManifest, error) {
	items := make([]resources.OfflineAcquisitionArtifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		method := "mirror-oci-index"
		if artifact.Type == "huggingface-snapshot" {
			method = "mirror-huggingface-snapshot"
		}
		items = append(items, resources.OfflineAcquisitionArtifact{
			Type: artifact.Type, Ref: artifact.Ref, Method: method, Digest: artifact.Digest, Revision: artifact.Revision,
			Platforms: artifact.Platforms, Files: artifact.Files, LicenseID: artifact.LicenseID, LicenseSource: artifact.LicenseSource,
		})
	}
	manifest := resources.OfflineAcquisitionManifest{
		APIVersion: resources.APIVersion, Kind: "OfflineAcquisitionManifest",
		Metadata: resources.OfflineAcquisitionManifestMetadata{Name: name},
		Spec: resources.OfflineAcquisitionManifestSpec{
			PlanID: planID, CatalogDigest: catalogDigest, GeneratedBy: renderer, Artifacts: items,
			Policy: resources.OfflineAcquisitionPolicy{
				NetworkRequiredDuringAcquisition: true, NetworkAllowedDuringExecution: false,
				RequireDigestVerification: true, RequireCompleteSet: true,
			},
		},
	}
	manifest, err := manifest.AssignManifestID()
	if err != nil {
		return resources.OfflineAcquisitionManifest{}, err
	}
	if report := manifest.Validate(); !report.Valid {
		return resources.OfflineAcquisitionManifest{}, fmt.Errorf("generated offline acquisition manifest is invalid: %s", report.Diagnostics[0].Code)
	}
	return manifest, nil
}

func buildSPDX(name, publishedAt, planID, catalogDigest string, renderer resources.BundleRenderer, artifacts []resources.BundleArtifact) spdxDocument {
	document := spdxDocument{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: "YARA-" + name,
		DocumentNamespace: fmt.Sprintf("https://yara.dev/spdx/%s/%s/%s/%s", strings.TrimPrefix(catalogDigest, "sha256:"), strings.TrimPrefix(planID, "sha256:"), renderer.Version, name),
		Comment:           fmt.Sprintf("Generated from plan %s and catalog %s. Package licenses are catalog declarations; licenseConcluded remains NOASSERTION.", planID, catalogDigest),
		CreationInfo:      spdxCreationInfo{Created: publishedAt, Creators: []string{"Tool: " + renderer.Name + "-" + renderer.Version}},
	}
	shardPackages := []spdxPackage{}
	shardRelationships := []spdxRelationship{}
	for artifactIndex, artifact := range artifacts {
		packageID := fmt.Sprintf("SPDXRef-Package-%d", artifactIndex+1)
		version := artifact.Digest
		checksums := []spdxChecksum(nil)
		if artifact.Type == "huggingface-snapshot" {
			version = artifact.Revision
		} else {
			checksums = []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: strings.TrimPrefix(artifact.Digest, "sha256:")}}
		}
		document.Packages = append(document.Packages, spdxPackage{
			SPDXID: packageID, Name: artifact.Ref, VersionInfo: version, DownloadLocation: "NOASSERTION", FilesAnalyzed: false,
			LicenseConcluded: "NOASSERTION", LicenseDeclared: artifact.LicenseID, CopyrightText: "NOASSERTION", Checksums: checksums,
			LicenseComments: "License source: " + artifact.LicenseSource,
		})
		document.Relationships = append(document.Relationships, spdxRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: packageID})
		for fileIndex, file := range artifact.Files {
			shardID := fmt.Sprintf("SPDXRef-Package-%d-Shard-%d", artifactIndex+1, fileIndex+1)
			shardPackages = append(shardPackages, spdxPackage{
				SPDXID: shardID, Name: artifact.Ref + "/" + file.Path, VersionInfo: file.Digest,
				DownloadLocation: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION",
				LicenseDeclared: artifact.LicenseID, CopyrightText: "NOASSERTION", PrimaryPurpose: "FILE",
				Checksums:       []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: strings.TrimPrefix(file.Digest, "sha256:")}},
				LicenseComments: "License source inherited from cataloged model snapshot: " + artifact.LicenseSource,
			})
			shardRelationships = append(shardRelationships, spdxRelationship{SPDXElementID: packageID, RelationshipType: "CONTAINS", RelatedSPDXElement: shardID})
		}
	}
	document.Packages = append(document.Packages, shardPackages...)
	document.Relationships = append(document.Relationships, shardRelationships...)
	return document
}
