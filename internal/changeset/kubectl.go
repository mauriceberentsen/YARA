package changeset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"github.com/mauriceberentsen/YARA/internal/targetpreflight"
)

type Observer interface {
	Observe(ctx context.Context, desired []DesiredObject, planID string) (Observation, error)
}

type KubectlObserver struct {
	Executable string
	Kubeconfig string
	Context    string
	Runner     targetpreflight.CommandRunner
}

func NewKubectlObserver(kubeconfig, contextName string) (KubectlObserver, error) {
	executable, err := exec.LookPath("kubectl")
	if err != nil {
		return KubectlObserver{}, errors.New("kubectl executable is unavailable")
	}
	return KubectlObserver{Executable: executable, Kubeconfig: kubeconfig, Context: contextName, Runner: targetpreflight.ExecRunner{}}, nil
}

func (o KubectlObserver) Observe(ctx context.Context, desired []DesiredObject, planID string) (Observation, error) {
	if o.Executable == "" || o.Runner == nil {
		return Observation{}, errors.New("kubectl observer is incomplete")
	}
	target, err := o.identify(ctx)
	if err != nil {
		return Observation{}, err
	}
	observation := Observation{Target: target, Objects: make([]ObjectObservation, 0, len(desired))}
	for _, object := range desired {
		args := []string{"get", object.Reference.Kind, object.Reference.Name}
		if object.Reference.Namespace != "" {
			args = append(args, "-n", object.Reference.Namespace)
		}
		args = append(args, "-o", "json", "--ignore-not-found")
		data, err := o.run(ctx, args...)
		if err != nil {
			observation.Objects = append(observation.Objects, ObjectObservation{Reference: object.Reference})
			continue
		}
		current, err := DecodeCurrentObject(data, object.Reference, planID)
		if err != nil {
			observation.Objects = append(observation.Objects, ObjectObservation{Reference: object.Reference})
			continue
		}
		observation.Objects = append(observation.Objects, current)
	}
	return observation, nil
}

func (o KubectlObserver) identify(ctx context.Context) (resources.TargetIdentity, error) {
	configData, err := o.run(ctx, "config", "view", "--minify", "--raw=false", "-o", "json")
	if err != nil {
		return resources.TargetIdentity{}, err
	}
	var config struct {
		Clusters []struct {
			Cluster struct {
				Server string `json:"server"`
			} `json:"cluster"`
		} `json:"clusters"`
	}
	if json.Unmarshal(configData, &config) != nil || len(config.Clusters) != 1 || config.Clusters[0].Cluster.Server == "" {
		return resources.TargetIdentity{}, errors.New("kubectl context does not resolve one API server")
	}
	versionData, err := o.run(ctx, "get", "--raw=/version")
	if err != nil {
		return resources.TargetIdentity{}, err
	}
	var version struct {
		GitVersion string `json:"gitVersion"`
	}
	if json.Unmarshal(versionData, &version) != nil || version.GitVersion == "" {
		return resources.TargetIdentity{}, errors.New("Kubernetes server version is unavailable")
	}
	systemData, err := o.run(ctx, "get", "namespace", "kube-system", "-o", "json")
	if err != nil {
		return resources.TargetIdentity{}, err
	}
	var namespace struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if json.Unmarshal(systemData, &namespace) != nil || namespace.Metadata.UID == "" {
		return resources.TargetIdentity{}, errors.New("kube-system identity is unavailable")
	}
	digest, err := canonical.Digest(struct {
		Server string `json:"server"`
		UID    string `json:"systemNamespaceUid"`
	}{Server: strings.TrimSpace(config.Clusters[0].Cluster.Server), UID: strings.TrimSpace(namespace.Metadata.UID)})
	if err != nil {
		return resources.TargetIdentity{}, fmt.Errorf("digest target identity: %w", err)
	}
	return resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: digest, ServerVersion: version.GitVersion}, nil
}

func (o KubectlObserver) run(ctx context.Context, args ...string) ([]byte, error) {
	base := []string{}
	if o.Kubeconfig != "" {
		base = append(base, "--kubeconfig", o.Kubeconfig)
	}
	if o.Context != "" {
		base = append(base, "--context", o.Context)
	}
	data, err := o.Runner.Run(ctx, o.Executable, append(base, args...)...)
	if err != nil {
		return nil, errors.New("read-only kubectl observation failed")
	}
	return bytes.TrimSpace(data), nil
}
