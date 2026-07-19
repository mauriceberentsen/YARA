package targetpreflight

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
)

const maxKubectlOutputBytes = 4 << 20

type Observer interface {
	Observe(ctx context.Context, namespace, planID string) (Observation, error)
}

type CommandRunner interface {
	Run(ctx context.Context, executable string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, executable string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, args...)
	var output limitedBuffer
	output.remaining = maxKubectlOutputBytes
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, errors.New("read-only kubectl observation failed")
	}
	return output.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	remaining int
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.remaining {
		return 0, errors.New("kubectl output exceeds 4 MiB limit")
	}
	written, err := b.Buffer.Write(data)
	b.remaining -= written
	return written, err
}

type KubectlObserver struct {
	Executable string
	Kubeconfig string
	Context    string
	Runner     CommandRunner
}

func NewKubectlObserver(kubeconfig, contextName string) (KubectlObserver, error) {
	executable, err := exec.LookPath("kubectl")
	if err != nil {
		return KubectlObserver{}, errors.New("kubectl executable is unavailable")
	}
	return KubectlObserver{Executable: executable, Kubeconfig: kubeconfig, Context: contextName, Runner: ExecRunner{}}, nil
}

func (o KubectlObserver) Observe(ctx context.Context, namespace, planID string) (Observation, error) {
	if o.Executable == "" || o.Runner == nil {
		return Observation{}, errors.New("kubectl observer is incomplete")
	}
	configData, err := o.run(ctx, "config", "view", "--minify", "--raw=false", "-o", "json")
	if err != nil {
		return Observation{}, err
	}
	var config struct {
		Clusters []struct {
			Cluster struct {
				Server string `json:"server"`
			} `json:"cluster"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(configData, &config); err != nil || len(config.Clusters) != 1 || config.Clusters[0].Cluster.Server == "" {
		return Observation{}, errors.New("kubectl context does not resolve one API server")
	}
	versionData, err := o.run(ctx, "get", "--raw=/version")
	if err != nil {
		return Observation{}, err
	}
	var version struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := json.Unmarshal(versionData, &version); err != nil || version.GitVersion == "" {
		return Observation{}, errors.New("Kubernetes server version is unavailable")
	}
	systemData, err := o.run(ctx, "get", "namespace", "kube-system", "-o", "json")
	if err != nil {
		return Observation{}, err
	}
	var systemNamespace struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(systemData, &systemNamespace); err != nil || systemNamespace.Metadata.UID == "" {
		return Observation{}, errors.New("kube-system identity is unavailable")
	}
	referenceDigest, err := targetReferenceDigest(config.Clusters[0].Cluster.Server, systemNamespace.Metadata.UID)
	if err != nil {
		return Observation{}, err
	}

	observation := Observation{ReferenceDigest: referenceDigest, ServerVersion: version.GitVersion}
	observation.CoreV1 = o.rawAvailable(ctx, "/api/v1")
	observation.AppsV1 = o.rawAvailable(ctx, "/apis/apps/v1")
	observation.NetworkingV1 = o.rawAvailable(ctx, "/apis/networking.k8s.io/v1")
	o.observeNodes(ctx, &observation)
	o.observeDNS(ctx, &observation)
	o.observeNamespace(ctx, namespace, planID, &observation)
	o.observePVC(ctx, namespace, &observation)
	return observation, nil
}

func (o KubectlObserver) run(ctx context.Context, args ...string) ([]byte, error) {
	base := []string{}
	if o.Kubeconfig != "" {
		base = append(base, "--kubeconfig", o.Kubeconfig)
	}
	if o.Context != "" {
		base = append(base, "--context", o.Context)
	}
	return o.Runner.Run(ctx, o.Executable, append(base, args...)...)
}

func (o KubectlObserver) rawAvailable(ctx context.Context, path string) bool {
	_, err := o.run(ctx, "get", "--raw="+path)
	return err == nil
}

func (o KubectlObserver) observeNodes(ctx context.Context, observation *Observation) {
	data, err := o.run(ctx, "get", "nodes", "-o", "json")
	if err != nil {
		return
	}
	var list struct {
		Items []struct {
			Status struct {
				Allocatable map[string]string `json:"allocatable"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal(data, &list) != nil {
		return
	}
	observation.NodesReadable = true
	for _, node := range list.Items {
		count, err := strconv.Atoi(node.Status.Allocatable["nvidia.com/gpu"])
		if err == nil && count > 0 {
			observation.GPUCount += count
		}
	}
}

func (o KubectlObserver) observeDNS(ctx context.Context, observation *Observation) {
	data, err := o.run(ctx, "get", "pods", "-n", "kube-system", "-l", "k8s-app=kube-dns", "-o", "json")
	if err != nil {
		return
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(data, &list) != nil {
		return
	}
	observation.DNSReadable = true
	observation.DNSPodCount = len(list.Items)
}

func (o KubectlObserver) observeNamespace(ctx context.Context, namespace, planID string, observation *Observation) {
	data, err := o.run(ctx, "get", "namespace", namespace, "-o", "json", "--ignore-not-found")
	if err != nil {
		return
	}
	observation.NamespaceReadable = true
	if len(bytes.TrimSpace(data)) == 0 {
		return
	}
	var resource struct {
		Metadata struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if json.Unmarshal(data, &resource) != nil {
		observation.NamespaceReadable = false
		return
	}
	observation.NamespaceExists = true
	observation.NamespaceManaged = resource.Metadata.Labels["app.kubernetes.io/managed-by"] == "yara"
	observation.NamespacePlanMatch = resource.Metadata.Annotations["yara.dev/plan-id"] == planID
}

func (o KubectlObserver) observePVC(ctx context.Context, namespace string, observation *Observation) {
	data, err := o.run(ctx, "get", "pvc", "yara-model", "-n", namespace, "-o", "json", "--ignore-not-found")
	if err != nil {
		return
	}
	observation.PVCReadable = true
	if len(bytes.TrimSpace(data)) == 0 {
		return
	}
	var resource struct {
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	}
	if json.Unmarshal(data, &resource) != nil {
		observation.PVCReadable = false
		return
	}
	observation.PVCExists = true
	observation.PVCPhase = resource.Status.Phase
}

func targetReferenceDigest(server, systemUID string) (string, error) {
	server = strings.TrimSpace(server)
	systemUID = strings.TrimSpace(systemUID)
	if server == "" || systemUID == "" {
		return "", errors.New("target identity inputs are incomplete")
	}
	digest, err := canonical.Digest(struct {
		Server          string `json:"server"`
		SystemNamespace string `json:"systemNamespaceUid"`
	}{Server: server, SystemNamespace: systemUID})
	if err != nil {
		return "", fmt.Errorf("digest pseudonymous target identity: %w", err)
	}
	return digest, nil
}
