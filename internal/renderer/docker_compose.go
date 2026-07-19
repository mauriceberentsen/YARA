package renderer

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

const (
	dockerComposeRendererName    = "yara.docker-compose"
	dockerComposeRendererVersion = "0.1.0"
)

var composeIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

type DockerCompose struct{}

var _ Renderer = DockerCompose{}

func (DockerCompose) Identity() Identity {
	return Identity{Name: dockerComposeRendererName, Version: dockerComposeRendererVersion, Target: "docker-compose"}
}

func (r DockerCompose) Render(name string, plan resources.PlatformPlan, snapshot catalog.Snapshot) (resources.DeploymentBundle, error) {
	if report := plan.Validate(); !report.Valid {
		return resources.DeploymentBundle{}, UnsupportedError{Reason: "plan is invalid", Path: "plan"}
	}
	catalogDigest, err := snapshot.Digest()
	if err != nil {
		return resources.DeploymentBundle{}, fmt.Errorf("digest catalog: %w", err)
	}
	if plan.Provenance.CatalogDigest != catalogDigest {
		return resources.DeploymentBundle{}, UnsupportedError{Reason: "plan does not bind the supplied catalog", Path: "plan.provenance.catalogDigest"}
	}
	if !composeIdentifierPattern.MatchString(name) {
		return resources.DeploymentBundle{}, UnsupportedError{Reason: "bundle name is not a safe Compose project identifier", Path: "name"}
	}

	instances := make(map[string]resources.PlanInstance, len(plan.Spec.Topology.Instances))
	for _, instance := range plan.Spec.Topology.Instances {
		if !composeIdentifierPattern.MatchString(instance.ID) {
			return resources.DeploymentBundle{}, UnsupportedError{Reason: "instance ID is not supported by Docker Compose", Path: "spec.topology.instances"}
		}
		instances[instance.ID] = instance
	}
	gateway, inference, err := supportedTopology(plan)
	if err != nil {
		return resources.DeploymentBundle{}, err
	}
	gatewayComponent, gatewayImage, err := deploymentOCI(snapshot, gateway.ComponentRef)
	if err != nil {
		return resources.DeploymentBundle{}, err
	}
	inferenceComponent, inferenceImage, err := deploymentOCI(snapshot, inference.ComponentRef)
	if err != nil {
		return resources.DeploymentBundle{}, err
	}
	model, ok := snapshot.DeploymentModel(inference.ModelRef)
	if !ok {
		return resources.DeploymentBundle{}, UnsupportedError{Reason: "model lacks immutable deployment metadata", Path: "spec.topology.instances.modelRef"}
	}

	compose, err := renderCompose(name, gateway, inference, gatewayImage, inferenceImage)
	if err != nil {
		return resources.DeploymentBundle{}, fmt.Errorf("render Compose document: %w", err)
	}
	litellmConfig, err := renderLiteLLMConfig(inference.ID)
	if err != nil {
		return resources.DeploymentBundle{}, fmt.Errorf("render LiteLLM configuration: %w", err)
	}
	files := []resources.BundleFile{
		bundleFile("compose.yaml", "application/vnd.docker.compose.project+yaml", compose),
		bundleFile("litellm-config.yaml", "application/yaml", litellmConfig),
	}
	artifacts := []resources.BundleArtifact{
		componentBundleArtifact(gatewayComponent, gatewayImage),
		componentBundleArtifact(inferenceComponent, inferenceImage),
		modelBundleArtifact(model),
	}
	slices.SortFunc(artifacts, func(left, right resources.BundleArtifact) int { return strings.Compare(left.Ref, right.Ref) })
	operations := operationsFromPlan(plan, instances)
	identity := r.Identity()
	bundle := resources.DeploymentBundle{
		APIVersion: resources.APIVersion,
		Kind:       "DeploymentBundle",
		Metadata:   resources.DeploymentBundleMetadata{Name: name},
		Spec: resources.DeploymentBundleSpec{
			PlanID: plan.Metadata.PlanID, CatalogDigest: catalogDigest,
			Renderer: resources.BundleRenderer{Name: identity.Name, Version: identity.Version, Target: identity.Target},
			Files:    files, Artifacts: artifacts,
			RequiredInputs: []resources.BundleRequiredInput{{
				Name: "YARA_MODEL_PATH", Secret: false,
				Description: "Absolute host path containing the exact verified model snapshot listed in spec.artifacts.",
			}},
			Operations: operations,
			Preflight: []string{
				"Docker Compose supports the rendered project schema.",
				"Every OCI image resolves to the cataloged digest for the target platform.",
				"YARA_MODEL_PATH contains every cataloged model file with matching size and SHA-256 digest.",
			},
			Postflight: []string{
				"Gateway health endpoint responds inside the isolated network.",
				"Inference health endpoint responds inside the isolated network.",
				"One bounded OpenAI-compatible request traverses gateway to inference.",
			},
			Limitations: []string{
				"Bundle rendering is offline and does not prove target compatibility or deployment success.",
				"No host port is published; an executor must add only an explicitly approved access boundary.",
				"No latency, throughput, availability, security-compliance or production-readiness claim is made.",
				"Rendering does not acquire model files, resolve secrets or mutate a target.",
			},
		},
	}
	slices.Sort(bundle.Spec.Preflight)
	slices.Sort(bundle.Spec.Postflight)
	slices.Sort(bundle.Spec.Limitations)
	bundle, err = bundle.AssignBundleID()
	if err != nil {
		return resources.DeploymentBundle{}, err
	}
	if report := bundle.Validate(); !report.Valid {
		return resources.DeploymentBundle{}, fmt.Errorf("renderer produced invalid bundle: %s", report.Diagnostics[0].Code)
	}
	return bundle, nil
}

func supportedTopology(plan resources.PlatformPlan) (resources.PlanInstance, resources.PlanInstance, error) {
	if len(plan.Spec.Topology.Instances) != 2 || len(plan.Spec.Topology.Connections) != 1 {
		return resources.PlanInstance{}, resources.PlanInstance{}, UnsupportedError{Reason: "reference renderer requires exactly one gateway and one inference instance", Path: "spec.topology"}
	}
	var gateway, inference resources.PlanInstance
	for _, instance := range plan.Spec.Topology.Instances {
		switch instance.Role {
		case "gateway.openai-compatible":
			gateway = instance
		case "inference.text-generation":
			inference = instance
		default:
			return resources.PlanInstance{}, resources.PlanInstance{}, UnsupportedError{Reason: "instance role has no typed adapter", Path: "spec.topology.instances.role"}
		}
	}
	if gateway.ID == "" || inference.ID == "" || gateway.ComponentRef != "core.litellm@1.93.0" || inference.ComponentRef != "core.vllm@0.25.1" || inference.ModelRef == "" {
		return resources.PlanInstance{}, resources.PlanInstance{}, UnsupportedError{Reason: "reference renderer supports only LiteLLM 1.93.0 and vLLM 0.25.1 with an exact model", Path: "spec.topology.instances"}
	}
	connection := plan.Spec.Topology.Connections[0]
	if connection.From != gateway.ID || connection.To != inference.ID || connection.Contract != "integration.api.openai-chat/v1" {
		return resources.PlanInstance{}, resources.PlanInstance{}, UnsupportedError{Reason: "topology connection has no typed adapter", Path: "spec.topology.connections"}
	}
	return gateway, inference, nil
}

func deploymentOCI(snapshot catalog.Snapshot, reference string) (catalog.DeploymentComponent, catalog.ArtifactReference, error) {
	component, ok := snapshot.DeploymentComponent(reference)
	if !ok || len(component.Artifacts) != 1 || component.Artifacts[0].Type != "oci-image" || component.Artifacts[0].Digest == "" {
		return catalog.DeploymentComponent{}, catalog.ArtifactReference{}, UnsupportedError{Reason: "component lacks one immutable OCI artifact", Path: "spec.topology.instances.componentRef"}
	}
	return component, component.Artifacts[0], nil
}

type composeDocument struct {
	Name     string                    `yaml:"name"`
	Services map[string]composeService `yaml:"services"`
	Networks map[string]composeNetwork `yaml:"networks"`
}

type composeService struct {
	Image       string                       `yaml:"image"`
	Command     []string                     `yaml:"command,omitempty"`
	ReadOnly    bool                         `yaml:"read_only"`
	CapDrop     []string                     `yaml:"cap_drop"`
	SecurityOpt []string                     `yaml:"security_opt"`
	Tmpfs       []string                     `yaml:"tmpfs"`
	Volumes     []string                     `yaml:"volumes,omitempty"`
	Networks    []string                     `yaml:"networks"`
	DependsOn   map[string]composeDependency `yaml:"depends_on,omitempty"`
	Healthcheck composeHealthcheck           `yaml:"healthcheck"`
	Deploy      *composeDeploy               `yaml:"deploy,omitempty"`
}

type composeDependency struct {
	Condition string `yaml:"condition"`
}

type composeHealthcheck struct {
	Test        []string `yaml:"test"`
	Interval    string   `yaml:"interval"`
	Timeout     string   `yaml:"timeout"`
	Retries     int      `yaml:"retries"`
	StartPeriod string   `yaml:"start_period"`
}

type composeDeploy struct {
	Resources composeResources `yaml:"resources"`
}

type composeResources struct {
	Reservations composeReservations `yaml:"reservations"`
}

type composeReservations struct {
	Devices []composeDevice `yaml:"devices"`
}

type composeDevice struct {
	Driver       string   `yaml:"driver"`
	Count        int      `yaml:"count"`
	Capabilities []string `yaml:"capabilities"`
}

type composeNetwork struct {
	Internal bool `yaml:"internal"`
}

func renderCompose(name string, gateway, inference resources.PlanInstance, gatewayImage, inferenceImage catalog.ArtifactReference) (string, error) {
	document := composeDocument{
		Name: name,
		Services: map[string]composeService{
			gateway.ID: {
				Image:    pinnedImage(gatewayImage),
				Command:  []string{"--config", "/app/config.yaml", "--host", "0.0.0.0", "--port", "4000"},
				ReadOnly: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
				Tmpfs: []string{"/tmp:mode=1777"}, Volumes: []string{"./litellm-config.yaml:/app/config.yaml:ro"}, Networks: []string{"yara-internal"},
				DependsOn:   map[string]composeDependency{inference.ID: {Condition: "service_healthy"}},
				Healthcheck: healthcheck("http://127.0.0.1:4000/health/liveliness"),
			},
			inference.ID: {
				Image:    pinnedImage(inferenceImage),
				Command:  []string{"--model", "/models/model", "--served-model-name", "yara-default", "--host", "0.0.0.0", "--port", "8000"},
				ReadOnly: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
				Tmpfs: []string{"/tmp:exec,mode=1777"}, Volumes: []string{"${YARA_MODEL_PATH:?YARA_MODEL_PATH is required}:/models/model:ro"}, Networks: []string{"yara-internal"},
				Healthcheck: healthcheck("http://127.0.0.1:8000/health"),
				Deploy:      &composeDeploy{Resources: composeResources{Reservations: composeReservations{Devices: []composeDevice{{Driver: "nvidia", Count: 1, Capabilities: []string{"gpu"}}}}}},
			},
		},
		Networks: map[string]composeNetwork{"yara-internal": {Internal: true}},
	}
	data, err := yaml.Marshal(document)
	return string(data), err
}

func healthcheck(url string) composeHealthcheck {
	return composeHealthcheck{
		Test:     []string{"CMD", "python", "-c", fmt.Sprintf("import urllib.request; urllib.request.urlopen(%q, timeout=2)", url)},
		Interval: "10s", Timeout: "3s", Retries: 12, StartPeriod: "30s",
	}
}

type liteLLMConfig struct {
	ModelList []liteLLMModel `yaml:"model_list"`
}

type liteLLMModel struct {
	ModelName     string             `yaml:"model_name"`
	LiteLLMParams liteLLMModelParams `yaml:"litellm_params"`
}

type liteLLMModelParams struct {
	Model   string `yaml:"model"`
	APIBase string `yaml:"api_base"`
}

func renderLiteLLMConfig(inferenceService string) (string, error) {
	data, err := yaml.Marshal(liteLLMConfig{ModelList: []liteLLMModel{{
		ModelName:     "yara-default",
		LiteLLMParams: liteLLMModelParams{Model: "hosted_vllm/yara-default", APIBase: "http://" + inferenceService + ":8000/v1"},
	}}})
	return string(data), err
}

func pinnedImage(artifact catalog.ArtifactReference) string {
	return artifact.Ref + "@" + artifact.Digest
}

func bundleFile(path, mediaType, content string) resources.BundleFile {
	return resources.BundleFile{Path: path, MediaType: mediaType, Digest: resources.BundleContentDigest(content), Content: content}
}

func componentBundleArtifact(component catalog.DeploymentComponent, artifact catalog.ArtifactReference) resources.BundleArtifact {
	return resources.BundleArtifact{
		Type: artifact.Type, Ref: artifact.Ref, Digest: artifact.Digest, Platforms: slices.Clone(artifact.Platforms),
		LicenseID: component.License.ID, LicenseSource: component.License.Source,
	}
}

func modelBundleArtifact(model catalog.DeploymentModel) resources.BundleArtifact {
	files := make([]resources.BundleArtifactFile, 0, len(model.Artifact.Files))
	for _, file := range model.Artifact.Files {
		files = append(files, resources.BundleArtifactFile{Path: file.Path, Digest: file.Digest, SizeBytes: file.SizeBytes})
	}
	return resources.BundleArtifact{
		Type: model.Artifact.Type, Ref: model.Artifact.Ref, Revision: model.Artifact.Revision, Files: files,
		LicenseID: model.License.ID, LicenseSource: model.License.Source,
	}
}

func operationsFromPlan(plan resources.PlatformPlan, instances map[string]resources.PlanInstance) []resources.BundleOperation {
	operations := make([]resources.BundleOperation, 0, len(instances))
	for stageIndex, stage := range plan.Spec.Topology.DeploymentStages {
		ids := slices.Clone(stage)
		slices.Sort(ids)
		for _, instanceID := range ids {
			if _, exists := instances[instanceID]; exists {
				operations = append(operations, resources.BundleOperation{Stage: stageIndex, Action: "create", InstanceID: instanceID})
			}
		}
	}
	return operations
}
