package resources

import "testing"

func TestOfflineAcquisitionManifestRejectsExecutionNetworking(t *testing.T) {
	bundle := validDeploymentBundle(t)
	var manifest OfflineAcquisitionManifest
	for _, file := range bundle.Spec.Files {
		if file.Path == bundle.Spec.SupplyChain.OfflineAcquisitionPath {
			if err := decodeYAML([]byte(file.Content), &manifest); err != nil {
				t.Fatalf("decode embedded manifest: %v", err)
			}
		}
	}
	if report := manifest.Validate(); !report.Valid {
		t.Fatalf("manifest is invalid: %#v", report.Diagnostics)
	}
	manifest.Spec.Policy.NetworkAllowedDuringExecution = true
	manifest, err := manifest.AssignManifestID()
	if err != nil {
		t.Fatalf("reassign manifest identity: %v", err)
	}
	if report := manifest.Validate(); report.Valid {
		t.Fatal("manifest allowed execution-time networking")
	}
}

func TestDeploymentBundleRejectsDriftedOfflineInventory(t *testing.T) {
	bundle := validDeploymentBundle(t)
	for index := range bundle.Spec.Files {
		if bundle.Spec.Files[index].Path == bundle.Spec.SupplyChain.OfflineAcquisitionPath {
			bundle.Spec.Files[index].Content = stringsReplaceOnce(bundle.Spec.Files[index].Content, "image:1", "image:2")
			bundle.Spec.Files[index].Digest = BundleContentDigest(bundle.Spec.Files[index].Content)
		}
	}
	bundle, _ = bundle.AssignBundleID()
	if report := bundle.Validate(); report.Valid {
		t.Fatal("bundle accepted an offline manifest that drifted from its artifact inventory")
	}
}

func stringsReplaceOnce(value, old, replacement string) string {
	for index := 0; index+len(old) <= len(value); index++ {
		if value[index:index+len(old)] == old {
			return value[:index] + replacement + value[index+len(old):]
		}
	}
	return value
}
