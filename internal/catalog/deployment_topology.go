package catalog

import "slices"

// DeploymentTopology is the immutable topology projection exposed to bounded
// integration execution. It grants no planner or mutation authority.
type DeploymentTopology struct {
	Ref         string
	Status      string
	Roles       []TopologyRole
	Connections []TopologyConnection
}

func (s Snapshot) DeploymentTopology(reference string) (DeploymentTopology, bool) {
	for _, topology := range s.manifests.Topologies {
		if topology.Metadata.ID+"@"+topology.Metadata.Version != reference {
			continue
		}
		return DeploymentTopology{
			Ref:         reference,
			Status:      topology.Metadata.Status,
			Roles:       slices.Clone(topology.Spec.Roles),
			Connections: slices.Clone(topology.Spec.Connections),
		}, true
	}
	return DeploymentTopology{}, false
}
