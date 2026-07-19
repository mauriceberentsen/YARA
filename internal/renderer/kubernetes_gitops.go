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
	kubernetesGitOpsRendererName    = "yara.kubernetes-gitops"
	kubernetesGitOpsRendererVersion = "0.1.0"
)

var kubernetesNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)

type KubernetesGitOps struct{}

var _ Renderer = KubernetesGitOps{}

func (KubernetesGitOps) Identity() Identity {
	return Identity{Name: kubernetesGitOpsRendererName, Version: kubernetesGitOpsRendererVersion, Target: "kubernetes-gitops"}
}

func (r KubernetesGitOps) Render(name string, plan resources.PlatformPlan, snapshot catalog.Snapshot) (resources.DeploymentBundle, error) {
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
	if !kubernetesNamePattern.MatchString(name) {
		return resources.DeploymentBundle{}, UnsupportedError{Reason: "bundle name must be a lowercase Kubernetes DNS label of at most 32 characters", Path: "name"}
	}

	instances := make(map[string]resources.PlanInstance, len(plan.Spec.Topology.Instances))
	for _, instance := range plan.Spec.Topology.Instances {
		if !kubernetesNamePattern.MatchString(instance.ID) {
			return resources.DeploymentBundle{}, UnsupportedError{Reason: "instance ID is not a supported Kubernetes name", Path: "spec.topology.instances"}
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
	if gatewayComponent.Health.Protocol != "http" || inferenceComponent.Health.Protocol != "http" {
		return resources.DeploymentBundle{}, UnsupportedError{Reason: "reference adapter requires HTTP health contracts", Path: "catalog.components.health"}
	}

	artifacts := []resources.BundleArtifact{
		componentBundleArtifact(gatewayComponent, gatewayImage),
		componentBundleArtifact(inferenceComponent, inferenceImage),
		modelBundleArtifact(model),
	}
	slices.SortFunc(artifacts, func(left, right resources.BundleArtifact) int { return strings.Compare(left.Ref, right.Ref) })
	identity := r.Identity()
	bundleRenderer := resources.BundleRenderer{Name: identity.Name, Version: identity.Version, Target: identity.Target}
	supplyFiles, supplyChain, err := supplyChainFiles(name, snapshot.Metadata.PublishedAt, plan.Metadata.PlanID, catalogDigest, bundleRenderer, artifacts)
	if err != nil {
		return resources.DeploymentBundle{}, fmt.Errorf("render supply-chain documents: %w", err)
	}

	litellmConfig, err := renderLiteLLMConfig(inference.ID)
	if err != nil {
		return resources.DeploymentBundle{}, fmt.Errorf("render LiteLLM configuration: %w", err)
	}
	files, err := renderKubernetesFiles(name, plan.Metadata.PlanID, gateway, inference, gatewayImage, inferenceImage, gatewayComponent.Health, inferenceComponent.Health, litellmConfig)
	if err != nil {
		return resources.DeploymentBundle{}, err
	}
	files = append(files, supplyFiles...)
	slices.SortFunc(files, func(left, right resources.BundleFile) int { return strings.Compare(left.Path, right.Path) })

	bundle := resources.DeploymentBundle{
		APIVersion: resources.APIVersion, Kind: "DeploymentBundle", Metadata: resources.DeploymentBundleMetadata{Name: name},
		Spec: resources.DeploymentBundleSpec{
			PlanID: plan.Metadata.PlanID, CatalogDigest: catalogDigest, Renderer: bundleRenderer, SupplyChain: supplyChain,
			Files: files, Artifacts: artifacts,
			RequiredInputs: []resources.BundleRequiredInput{{
				Name: "YARA_MODEL_PVC_READY", Secret: false,
				Description: "A pre-provisioned read-only PVC named yara-model contains the exact verified model snapshot listed in spec.artifacts.",
			}},
			Operations: operationsFromPlan(plan, instances),
			Preflight: []string{
				"A NetworkPolicy-enforcing CNI recognizes the rendered namespace and pod selectors.",
				"Cluster DNS is selected by namespace kubernetes.io/metadata.name=kube-system and pod k8s-app=kube-dns.",
				"Kubernetes server minor version is in the renderer-tested 1.34 through 1.36 range and accepts apps/v1, v1 and networking.k8s.io/v1 resources.",
				"NVIDIA drivers and a device plugin expose allocatable nvidia.com/gpu capacity.",
				"PVC yara-model exists in the rendered namespace and every model file matches its cataloged size and SHA-256 digest.",
				"The container runtime permits vLLM to execute generated objects from its dedicated emptyDir mounted at /tmp.",
			},
			Postflight: []string{
				"Gateway Deployment reports its single replica Available.",
				"Inference Deployment reports its single replica Available.",
				"One bounded OpenAI-compatible request from an explicitly labelled verifier traverses gateway to inference.",
				"Observed NetworkPolicy enforcement blocks all unlisted serving-pod egress.",
			},
			Limitations: []string{
				"Bundle rendering is offline and does not prove Kubernetes API, admission, CNI, CSI, DNS, GPU or runtime compatibility.",
				"Controller reconciliation and ReplicaSet history improve lifecycle primitives but do not prove rollback, availability or recovery.",
				"Images retain their catalog-tested user identity; non-root compatibility remains unproven.",
				"Model acquisition and PVC provisioning are separate approved workflows and are not rendered or authorized here.",
				"No external Gateway, Ingress, LoadBalancer or NodePort access boundary is rendered.",
				"The manifests are a GitOps handoff; YARA does not contact or mutate a cluster.",
				"Verifier labels grant the rendered probe path; admission and RBAC must restrict who may assign yara.dev/role=verifier.",
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

type kubeObject struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   kubeMetadata      `yaml:"metadata"`
	Immutable  bool              `yaml:"immutable,omitempty"`
	Data       map[string]string `yaml:"data,omitempty"`
	Spec       any               `yaml:"spec,omitempty"`
}

type kubeMetadata struct {
	Name        string            `yaml:"name,omitempty"`
	Namespace   string            `yaml:"namespace,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type kubeDeploymentSpec struct {
	Replicas                int               `yaml:"replicas"`
	RevisionHistoryLimit    int               `yaml:"revisionHistoryLimit"`
	ProgressDeadlineSeconds int               `yaml:"progressDeadlineSeconds"`
	Strategy                map[string]string `yaml:"strategy"`
	Selector                kubeLabelSelector `yaml:"selector"`
	Template                kubePodTemplate   `yaml:"template"`
}

type kubePodTemplate struct {
	Metadata kubeMetadata `yaml:"metadata"`
	Spec     kubePodSpec  `yaml:"spec"`
}

type kubePodSpec struct {
	AutomountServiceAccountToken bool                   `yaml:"automountServiceAccountToken"`
	SecurityContext              kubePodSecurityContext `yaml:"securityContext"`
	Containers                   []kubeContainer        `yaml:"containers"`
	Volumes                      []kubeVolume           `yaml:"volumes"`
}

type kubePodSecurityContext struct {
	SeccompProfile map[string]string `yaml:"seccompProfile"`
}

type kubeContainer struct {
	Name            string                       `yaml:"name"`
	Image           string                       `yaml:"image"`
	ImagePullPolicy string                       `yaml:"imagePullPolicy"`
	Args            []string                     `yaml:"args"`
	Ports           []kubeContainerPort          `yaml:"ports"`
	SecurityContext kubeContainerSecurityContext `yaml:"securityContext"`
	Resources       kubeResourceRequirements     `yaml:"resources"`
	VolumeMounts    []kubeVolumeMount            `yaml:"volumeMounts"`
	StartupProbe    kubeProbe                    `yaml:"startupProbe"`
	ReadinessProbe  kubeProbe                    `yaml:"readinessProbe"`
	LivenessProbe   kubeProbe                    `yaml:"livenessProbe"`
}

type kubeContainerPort struct {
	Name          string `yaml:"name"`
	ContainerPort int    `yaml:"containerPort"`
	Protocol      string `yaml:"protocol"`
}

type kubeContainerSecurityContext struct {
	AllowPrivilegeEscalation bool             `yaml:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   bool             `yaml:"readOnlyRootFilesystem"`
	Privileged               bool             `yaml:"privileged"`
	Capabilities             kubeCapabilities `yaml:"capabilities"`
}

type kubeCapabilities struct {
	Drop []string `yaml:"drop"`
}

type kubeResourceRequirements struct {
	Limits map[string]string `yaml:"limits,omitempty"`
}

type kubeVolumeMount struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
	SubPath   string `yaml:"subPath,omitempty"`
	ReadOnly  bool   `yaml:"readOnly,omitempty"`
}

type kubeVolume struct {
	Name                  string                     `yaml:"name"`
	ConfigMap             *kubeConfigMapVolume       `yaml:"configMap,omitempty"`
	PersistentVolumeClaim *kubePersistentVolumeClaim `yaml:"persistentVolumeClaim,omitempty"`
	EmptyDir              *map[string]any            `yaml:"emptyDir,omitempty"`
}

type kubeConfigMapVolume struct {
	Name string `yaml:"name"`
}

type kubePersistentVolumeClaim struct {
	ClaimName string `yaml:"claimName"`
	ReadOnly  bool   `yaml:"readOnly"`
}

type kubeProbe struct {
	HTTPGet             kubeHTTPGet `yaml:"httpGet"`
	PeriodSeconds       int         `yaml:"periodSeconds"`
	TimeoutSeconds      int         `yaml:"timeoutSeconds"`
	FailureThreshold    int         `yaml:"failureThreshold"`
	InitialDelaySeconds int         `yaml:"initialDelaySeconds,omitempty"`
}

type kubeHTTPGet struct {
	Path string `yaml:"path"`
	Port string `yaml:"port"`
}

type kubeServiceSpec struct {
	Type     string            `yaml:"type"`
	Selector map[string]string `yaml:"selector"`
	Ports    []kubeServicePort `yaml:"ports"`
}

type kubeServicePort struct {
	Name       string `yaml:"name"`
	Port       int    `yaml:"port"`
	TargetPort string `yaml:"targetPort"`
	Protocol   string `yaml:"protocol"`
}

type kubeNetworkPolicySpec struct {
	PodSelector kubeLabelSelector       `yaml:"podSelector"`
	PolicyTypes []string                `yaml:"policyTypes"`
	Ingress     []kubeNetworkPolicyRule `yaml:"ingress,omitempty"`
	Egress      []kubeNetworkPolicyRule `yaml:"egress,omitempty"`
}

type kubeLabelSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}

type kubeNetworkPolicyRule struct {
	From  []kubeNetworkPolicyPeer `yaml:"from,omitempty"`
	To    []kubeNetworkPolicyPeer `yaml:"to,omitempty"`
	Ports []kubeNetworkPolicyPort `yaml:"ports"`
}

type kubeNetworkPolicyPeer struct {
	PodSelector       *kubeLabelSelector `yaml:"podSelector,omitempty"`
	NamespaceSelector *kubeLabelSelector `yaml:"namespaceSelector,omitempty"`
}

type kubeNetworkPolicyPort struct {
	Protocol string `yaml:"protocol"`
	Port     int    `yaml:"port"`
}

func renderKubernetesFiles(name, planID string, gateway, inference resources.PlanInstance, gatewayImage, inferenceImage catalog.ArtifactReference, gatewayHealth, inferenceHealth catalog.HealthContract, litellmConfig string) ([]resources.BundleFile, error) {
	const gatewayPort = 4000
	const inferencePort = 8000
	commonLabels := map[string]string{"app.kubernetes.io/managed-by": "yara", "yara.dev/bundle": name}
	configName := name + "-litellm-" + strings.TrimPrefix(resources.BundleContentDigest(litellmConfig), "sha256:")[:12]
	metadata := func(resourceName string) kubeMetadata {
		return kubeMetadata{Name: resourceName, Namespace: name, Labels: cloneStringMap(commonLabels), Annotations: map[string]string{"yara.dev/plan-id": planID}}
	}
	objects := []struct {
		path   string
		object kubeObject
	}{
		{"00-namespace.yaml", kubeObject{APIVersion: "v1", Kind: "Namespace", Metadata: kubeMetadata{Name: name, Labels: cloneStringMap(commonLabels), Annotations: map[string]string{"yara.dev/plan-id": planID}}}},
		{"10-litellm-configmap.yaml", kubeObject{APIVersion: "v1", Kind: "ConfigMap", Metadata: metadata(configName), Immutable: true, Data: map[string]string{"config.yaml": litellmConfig}}},
		{"20-inference-deployment.yaml", deploymentObject(metadata(inference.ID), name, inference, pinnedImage(inferenceImage), []string{"--model", "/models/model", "--served-model-name", "yara-default", "--host", "0.0.0.0", "--port", "8000"}, inferenceHealth.Path, inferencePort, true)},
		{"21-inference-service.yaml", serviceObject(metadata(inference.ID), name, inference.ID, inferencePort)},
		{"30-gateway-deployment.yaml", gatewayDeploymentObject(metadata(gateway.ID), name, configName, gateway, pinnedImage(gatewayImage), gatewayHealth.Path, gatewayPort)},
		{"31-gateway-service.yaml", serviceObject(metadata(gateway.ID), name, gateway.ID, gatewayPort)},
		{"40-default-deny.yaml", defaultDenyObject(metadata(name + "-default-deny"))},
		{"41-gateway-egress-inference.yaml", gatewayEgressObject(metadata(name+"-gateway-to-inference"), name, gateway.ID, inference.ID, inferencePort)},
		{"42-inference-ingress-gateway.yaml", inferenceIngressObject(metadata(name+"-inference-from-gateway"), name, gateway.ID, inference.ID, inferencePort)},
		{"43-gateway-dns-egress.yaml", gatewayDNSObject(metadata(name+"-gateway-dns"), name, gateway.ID)},
		{"44-gateway-verifier-ingress.yaml", verifierIngressObject(metadata(name+"-gateway-verifier"), name, gateway.ID, gatewayPort)},
		{"45-verifier-egress.yaml", verifierEgressObject(metadata(name+"-verifier-egress"), name, gateway.ID, gatewayPort)},
	}
	files := make([]resources.BundleFile, 0, len(objects))
	for _, item := range objects {
		data, err := yaml.Marshal(item.object)
		if err != nil {
			return nil, fmt.Errorf("render Kubernetes object %s: %w", item.path, err)
		}
		files = append(files, bundleFile(item.path, "application/yaml", string(data)))
	}
	return files, nil
}

func deploymentObject(metadata kubeMetadata, namespace string, instance resources.PlanInstance, image string, args []string, healthPath string, healthPort int, gpu bool) kubeObject {
	labels := workloadLabels(namespace, instance.ID, instance.Role)
	limits := map[string]string(nil)
	volumes := []kubeVolume{{Name: "tmp", EmptyDir: &map[string]any{}}}
	mounts := []kubeVolumeMount{{Name: "tmp", MountPath: "/tmp"}}
	if gpu {
		limits = map[string]string{"nvidia.com/gpu": "1"}
		volumes = append(volumes, kubeVolume{Name: "model", PersistentVolumeClaim: &kubePersistentVolumeClaim{ClaimName: "yara-model", ReadOnly: true}})
		mounts = append(mounts, kubeVolumeMount{Name: "model", MountPath: "/models/model", ReadOnly: true})
	}
	return kubeObject{APIVersion: "apps/v1", Kind: "Deployment", Metadata: metadata, Spec: kubeDeploymentSpec{
		Replicas: 1, RevisionHistoryLimit: 2, ProgressDeadlineSeconds: 1800, Strategy: map[string]string{"type": "Recreate"},
		Selector: kubeLabelSelector{MatchLabels: selectorLabels(namespace, instance.ID)},
		Template: kubePodTemplate{Metadata: kubeMetadata{Labels: labels}, Spec: kubePodSpec{
			AutomountServiceAccountToken: false, SecurityContext: kubePodSecurityContext{SeccompProfile: map[string]string{"type": "RuntimeDefault"}},
			Containers: []kubeContainer{{
				Name: instance.ID, Image: image, ImagePullPolicy: "IfNotPresent", Args: args,
				Ports:           []kubeContainerPort{{Name: "http", ContainerPort: healthPort, Protocol: "TCP"}},
				SecurityContext: kubeContainerSecurityContext{AllowPrivilegeEscalation: false, ReadOnlyRootFilesystem: true, Privileged: false, Capabilities: kubeCapabilities{Drop: []string{"ALL"}}},
				Resources:       kubeResourceRequirements{Limits: limits}, VolumeMounts: mounts,
				StartupProbe: probe(healthPath, 120), ReadinessProbe: probe(healthPath, 12), LivenessProbe: probe(healthPath, 12),
			}}, Volumes: volumes,
		}},
	}}
}

func gatewayDeploymentObject(metadata kubeMetadata, namespace, configName string, instance resources.PlanInstance, image, healthPath string, healthPort int) kubeObject {
	object := deploymentObject(metadata, namespace, instance, image, []string{"--config", "/app/config/config.yaml", "--host", "0.0.0.0", "--port", "4000"}, healthPath, healthPort, false)
	spec := object.Spec.(kubeDeploymentSpec)
	spec.ProgressDeadlineSeconds = 600
	spec.Template.Spec.Volumes = append(spec.Template.Spec.Volumes, kubeVolume{Name: "config", ConfigMap: &kubeConfigMapVolume{Name: configName}})
	spec.Template.Spec.Containers[0].VolumeMounts = append(spec.Template.Spec.Containers[0].VolumeMounts, kubeVolumeMount{Name: "config", MountPath: "/app/config", ReadOnly: true})
	object.Spec = spec
	return object
}

func serviceObject(metadata kubeMetadata, namespace, instanceID string, port int) kubeObject {
	return kubeObject{APIVersion: "v1", Kind: "Service", Metadata: metadata, Spec: kubeServiceSpec{
		Type: "ClusterIP", Selector: selectorLabels(namespace, instanceID),
		Ports: []kubeServicePort{{Name: "http", Port: port, TargetPort: "http", Protocol: "TCP"}},
	}}
}

func defaultDenyObject(metadata kubeMetadata) kubeObject {
	return kubeObject{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Metadata: metadata, Spec: kubeNetworkPolicySpec{PodSelector: kubeLabelSelector{}, PolicyTypes: []string{"Ingress", "Egress"}}}
}

func gatewayEgressObject(metadata kubeMetadata, namespace, gatewayID, inferenceID string, port int) kubeObject {
	peer := kubeNetworkPolicyPeer{PodSelector: &kubeLabelSelector{MatchLabels: selectorLabels(namespace, inferenceID)}}
	return networkPolicyObject(metadata, selectorLabels(namespace, gatewayID), nil, []kubeNetworkPolicyRule{{To: []kubeNetworkPolicyPeer{peer}, Ports: []kubeNetworkPolicyPort{{Protocol: "TCP", Port: port}}}}, []string{"Egress"})
}

func inferenceIngressObject(metadata kubeMetadata, namespace, gatewayID, inferenceID string, port int) kubeObject {
	peer := kubeNetworkPolicyPeer{PodSelector: &kubeLabelSelector{MatchLabels: selectorLabels(namespace, gatewayID)}}
	return networkPolicyObject(metadata, selectorLabels(namespace, inferenceID), []kubeNetworkPolicyRule{{From: []kubeNetworkPolicyPeer{peer}, Ports: []kubeNetworkPolicyPort{{Protocol: "TCP", Port: port}}}}, nil, []string{"Ingress"})
}

func gatewayDNSObject(metadata kubeMetadata, namespace, gatewayID string) kubeObject {
	peer := clusterDNSPeer()
	ports := []kubeNetworkPolicyPort{{Protocol: "TCP", Port: 53}, {Protocol: "UDP", Port: 53}}
	return networkPolicyObject(metadata, selectorLabels(namespace, gatewayID), nil, []kubeNetworkPolicyRule{{To: []kubeNetworkPolicyPeer{peer}, Ports: ports}}, []string{"Egress"})
}

func verifierIngressObject(metadata kubeMetadata, namespace, gatewayID string, port int) kubeObject {
	peer := kubeNetworkPolicyPeer{PodSelector: &kubeLabelSelector{MatchLabels: map[string]string{"yara.dev/role": "verifier"}}}
	return networkPolicyObject(metadata, selectorLabels(namespace, gatewayID), []kubeNetworkPolicyRule{{From: []kubeNetworkPolicyPeer{peer}, Ports: []kubeNetworkPolicyPort{{Protocol: "TCP", Port: port}}}}, nil, []string{"Ingress"})
}

func verifierEgressObject(metadata kubeMetadata, namespace, gatewayID string, port int) kubeObject {
	gatewayPeer := kubeNetworkPolicyPeer{PodSelector: &kubeLabelSelector{MatchLabels: selectorLabels(namespace, gatewayID)}}
	dnsPorts := []kubeNetworkPolicyPort{{Protocol: "TCP", Port: 53}, {Protocol: "UDP", Port: 53}}
	rules := []kubeNetworkPolicyRule{
		{To: []kubeNetworkPolicyPeer{gatewayPeer}, Ports: []kubeNetworkPolicyPort{{Protocol: "TCP", Port: port}}},
		{To: []kubeNetworkPolicyPeer{clusterDNSPeer()}, Ports: dnsPorts},
	}
	return networkPolicyObject(metadata, map[string]string{"yara.dev/role": "verifier"}, nil, rules, []string{"Egress"})
}

func clusterDNSPeer() kubeNetworkPolicyPeer {
	return kubeNetworkPolicyPeer{
		NamespaceSelector: &kubeLabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
		PodSelector:       &kubeLabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
	}
}

func networkPolicyObject(metadata kubeMetadata, selected map[string]string, ingress, egress []kubeNetworkPolicyRule, policyTypes []string) kubeObject {
	return kubeObject{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Metadata: metadata, Spec: kubeNetworkPolicySpec{PodSelector: kubeLabelSelector{MatchLabels: selected}, PolicyTypes: policyTypes, Ingress: ingress, Egress: egress}}
}

func probe(path string, failureThreshold int) kubeProbe {
	return kubeProbe{HTTPGet: kubeHTTPGet{Path: path, Port: "http"}, PeriodSeconds: 5, TimeoutSeconds: 2, FailureThreshold: failureThreshold}
}

func selectorLabels(namespace, instanceID string) map[string]string {
	return map[string]string{"yara.dev/bundle": namespace, "yara.dev/instance": instanceID}
}

func workloadLabels(namespace, instanceID, role string) map[string]string {
	labels := selectorLabels(namespace, instanceID)
	labels["app.kubernetes.io/managed-by"] = "yara"
	labels["yara.dev/role"] = role
	return labels
}

func cloneStringMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
