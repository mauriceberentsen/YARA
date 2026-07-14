package resources

import "testing"

func TestInventoryRejectsUnsupportedHardware(t *testing.T) {
	inventory := validInventory()
	inventory.Spec.Hosts[0].Accelerators[0].Vendor = "amd"
	inventory.Spec.Hosts[0].Accelerators[0].AllocatableMemoryGiB = 25

	report := inventory.Validate()
	assertDiagnostic(t, report, "YARA-INV-029", "spec.hosts[0].accelerators[0].vendor")
	assertDiagnostic(t, report, "YARA-INV-031", "spec.hosts[0].accelerators[0].allocatableMemoryGiB")
}

func validInventory() Inventory {
	return Inventory{
		APIVersion: APIVersion,
		Kind:       "Inventory",
		Metadata:   Metadata{Name: "test-inventory"},
		Spec: InventorySpec{
			Source: InventorySource{Mode: "declared", ObservedAt: "2026-07-14T00:00:00Z"},
			Hosts: []Host{{
				ID:           "host-1",
				Platform:     HostPlatform{OS: "linux", Architecture: "amd64"},
				CPU:          CPU{Cores: 8},
				Memory:       Memory{InstalledGiB: 64, AllocatableGiB: 56},
				Accelerators: []Accelerator{{ID: "gpu-0", Vendor: "nvidia", Model: "example", MemoryGiB: 24, AllocatableMemoryGiB: 22, DriverVersion: "declared"}},
				Storage:      Storage{CapacityGiB: 1000, AllocatableGiB: 800, Class: "local-ssd"},
				Network:      Network{ExternalEgress: false},
			}},
		},
	}
}
