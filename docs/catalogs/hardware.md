# Hardware catalog and inventory

## Separation of concerns

The hardware catalog describes known device classes and software-stack compatibility. Inventory describes actual devices, topology and available capacity in one environment. Catalog defaults never overwrite discovered facts.

## Inventory facts

### Host

- stable local identifier, architecture and operating system;
- CPU model, cores, instruction sets and NUMA nodes;
- installed and allocatable RAM;
- storage devices, free capacity and measured class;
- network interfaces, bandwidth and reachability zones;
- container runtime/orchestrator and reserved resources.

### Accelerator

- vendor and normalized device identifier;
- count, per-device memory and available memory;
- topology, interconnect and NUMA affinity;
- driver and compute stack versions;
- supported precision/features;
- partitioning or sharing configuration;
- observed health and existing allocations.

## Discovery

Discovery adapters should prefer vendor/system APIs and emit raw evidence alongside normalized fields. Commands and access required are documented before execution. Discovery is read-only by default and reports inaccessible facts as unknown.

Inventory may be:

- automatically discovered on the planning host;
- produced by a remote signed agent;
- imported from a cluster inventory system;
- manually declared for hypothetical planning.

The plan records which mode supplied each material fact.

## Capacity reservations

YARA does not plan against total memory or disk capacity. Inventory identifies existing reservations; planner policy adds system, failure and operational headroom. Unknown existing usage prevents production capacity claims.

## Hardware profiles

A profile maps vendor identifiers and capabilities, including supported driver/compute ranges. Profiles provide identification and compatibility knowledge, not universal performance numbers. Actual performance lives in benchmark observations.

The v0.2 profiles record NVIDIA inventory aliases, VRAM, architecture and compute capability for RTX 4090, RTX 6000 Ada and L40S. The separate compatibility assertions bind those profiles to a minimum driver branch and CUDA runtime. They remain experimental until discovery aliases and runtime startup are exercised on the physical devices.

## Multi-device considerations

Total memory is not automatically additive. The planner considers serving runtime parallelism support, interconnect, topology, quantization, communication overhead and failure behavior. v0.1 supports only explicitly cataloged homogeneous combinations and never assumes two devices can serve a model requiring their summed memory.

## Future portability

Vendor-specific fields live behind normalized capabilities and namespaced extensions. NVIDIA-first v0.1 scope is an implementation boundary, not a permanent domain assumption. AMD, Apple and other accelerators should be addable without changing `PlatformRequest` semantics.
