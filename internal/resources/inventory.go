package resources

import (
	"fmt"
	"time"

	"github.com/mauriceberentsen/YARA/internal/diagnostics"
)

type Inventory struct {
	APIVersion string        `json:"apiVersion" yaml:"apiVersion"`
	Kind       string        `json:"kind" yaml:"kind"`
	Metadata   Metadata      `json:"metadata" yaml:"metadata"`
	Spec       InventorySpec `json:"spec" yaml:"spec"`
}

type InventorySpec struct {
	Source   InventorySource `json:"source" yaml:"source"`
	Hosts    []Host          `json:"hosts" yaml:"hosts"`
	Unknowns []string        `json:"unknowns,omitempty" yaml:"unknowns,omitempty"`
}

type InventorySource struct {
	Mode       string `json:"mode" yaml:"mode"`
	ObservedAt string `json:"observedAt" yaml:"observedAt"`
}

type Host struct {
	ID           string        `json:"id" yaml:"id"`
	Platform     HostPlatform  `json:"platform" yaml:"platform"`
	CPU          CPU           `json:"cpu" yaml:"cpu"`
	Memory       Memory        `json:"memory" yaml:"memory"`
	Accelerators []Accelerator `json:"accelerators" yaml:"accelerators"`
	Storage      Storage       `json:"storage" yaml:"storage"`
	Network      Network       `json:"network" yaml:"network"`
}

type HostPlatform struct {
	OS           string `json:"os" yaml:"os"`
	Architecture string `json:"architecture" yaml:"architecture"`
}

type CPU struct {
	Cores int `json:"cores" yaml:"cores"`
}

type Memory struct {
	InstalledGiB   int `json:"installedGiB" yaml:"installedGiB"`
	AllocatableGiB int `json:"allocatableGiB" yaml:"allocatableGiB"`
}

type Accelerator struct {
	ID                   string `json:"id" yaml:"id"`
	Vendor               string `json:"vendor" yaml:"vendor"`
	Model                string `json:"model" yaml:"model"`
	MemoryGiB            int    `json:"memoryGiB" yaml:"memoryGiB"`
	AllocatableMemoryGiB int    `json:"allocatableMemoryGiB" yaml:"allocatableMemoryGiB"`
	DriverVersion        string `json:"driverVersion" yaml:"driverVersion"`
}

type Storage struct {
	CapacityGiB    int    `json:"capacityGiB" yaml:"capacityGiB"`
	AllocatableGiB int    `json:"allocatableGiB" yaml:"allocatableGiB"`
	Class          string `json:"class" yaml:"class"`
}

type Network struct {
	ExternalEgress bool `json:"externalEgress" yaml:"externalEgress"`
}

func (r Inventory) Validate() diagnostics.Report {
	items := validateEnvelope(r.APIVersion, r.Kind, "Inventory", "INV", r.Metadata)
	if !contains([]string{"declared", "discovered", "imported"}, r.Spec.Source.Mode) {
		items = append(items, diagnostics.Error("YARA-INV-010", "source.mode must be declared, discovered or imported.", "spec.source.mode"))
	}
	if _, err := time.Parse(time.RFC3339, r.Spec.Source.ObservedAt); err != nil {
		items = append(items, diagnostics.Error("YARA-INV-011", "source.observedAt must be an RFC 3339 timestamp.", "spec.source.observedAt"))
	}
	if len(r.Spec.Hosts) != 1 {
		items = append(items, diagnostics.Error("YARA-INV-020", "v0.1 requires exactly one host.", "spec.hosts"))
	}
	for hostIndex, host := range r.Spec.Hosts {
		base := fmt.Sprintf("spec.hosts[%d]", hostIndex)
		if host.ID == "" {
			items = append(items, diagnostics.Error("YARA-INV-021", "Host ID is required.", base+".id"))
		}
		if host.Platform.OS != "linux" {
			items = append(items, diagnostics.Error("YARA-INV-022", "v0.1 supports Linux target hosts only.", base+".platform.os"))
		}
		if !contains([]string{"amd64", "arm64"}, host.Platform.Architecture) {
			items = append(items, diagnostics.Error("YARA-INV-023", "architecture must be amd64 or arm64.", base+".platform.architecture"))
		}
		if host.CPU.Cores <= 0 {
			items = append(items, diagnostics.Error("YARA-INV-024", "CPU cores must be greater than zero.", base+".cpu.cores"))
		}
		if host.Memory.InstalledGiB <= 0 || host.Memory.AllocatableGiB <= 0 || host.Memory.AllocatableGiB > host.Memory.InstalledGiB {
			items = append(items, diagnostics.Error("YARA-INV-025", "Allocatable memory must be positive and no greater than installed memory.", base+".memory"))
		}
		if len(host.Accelerators) == 0 {
			items = append(items, diagnostics.Error("YARA-INV-026", "v0.1 requires at least one NVIDIA accelerator.", base+".accelerators"))
		}
		seenAccelerators := make(map[string]struct{}, len(host.Accelerators))
		var firstAccelerator *Accelerator
		for acceleratorIndex, accelerator := range host.Accelerators {
			acceleratorPath := fmt.Sprintf("%s.accelerators[%d]", base, acceleratorIndex)
			if accelerator.ID == "" {
				items = append(items, diagnostics.Error("YARA-INV-027", "Accelerator ID is required.", acceleratorPath+".id"))
			}
			if _, exists := seenAccelerators[accelerator.ID]; exists {
				items = append(items, diagnostics.Error("YARA-INV-028", "Accelerator IDs must be unique per host.", acceleratorPath+".id"))
			}
			seenAccelerators[accelerator.ID] = struct{}{}
			if accelerator.Vendor != "nvidia" {
				items = append(items, diagnostics.Error("YARA-INV-029", "v0.1 supports NVIDIA accelerators only.", acceleratorPath+".vendor"))
			}
			if accelerator.Model == "" {
				items = append(items, diagnostics.Error("YARA-INV-030", "Accelerator model is required.", acceleratorPath+".model"))
			}
			if accelerator.MemoryGiB <= 0 || accelerator.AllocatableMemoryGiB <= 0 || accelerator.AllocatableMemoryGiB > accelerator.MemoryGiB {
				items = append(items, diagnostics.Error("YARA-INV-031", "Allocatable accelerator memory must be positive and no greater than device memory.", acceleratorPath+".allocatableMemoryGiB"))
			}
			if firstAccelerator == nil {
				firstAccelerator = &host.Accelerators[acceleratorIndex]
			} else if accelerator.Vendor != firstAccelerator.Vendor || accelerator.Model != firstAccelerator.Model || accelerator.MemoryGiB != firstAccelerator.MemoryGiB {
				items = append(items, diagnostics.Error("YARA-INV-033", "v0.1 requires homogeneous accelerators on the target host.", acceleratorPath))
			}
		}
		if host.Storage.CapacityGiB <= 0 || host.Storage.AllocatableGiB <= 0 || host.Storage.AllocatableGiB > host.Storage.CapacityGiB {
			items = append(items, diagnostics.Error("YARA-INV-032", "Allocatable storage must be positive and no greater than storage capacity.", base+".storage"))
		}
	}
	return diagnostics.NewReport(items...)
}
