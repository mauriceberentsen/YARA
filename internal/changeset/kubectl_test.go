package changeset

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mauriceberentsen/YARA/internal/resources"
)

type recordingRunner struct{ calls [][]string }

func (r *recordingRunner) Run(_ context.Context, executable string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{executable}, args...))
	command := strings.Join(args, " ")
	switch {
	case strings.Contains(command, "config view"):
		return []byte(`{"clusters":[{"cluster":{"server":"https://cluster.internal:6443"}}]}`), nil
	case strings.Contains(command, "--raw=/version"):
		return []byte(`{"gitVersion":"v1.35.2"}`), nil
	case strings.Contains(command, "namespace kube-system"):
		return []byte(`{"metadata":{"uid":"system-uid"}}`), nil
	case strings.Contains(command, "get ConfigMap gateway-config"):
		return nil, nil
	default:
		return nil, errors.New("unexpected command")
	}
}

func TestKubectlChangeSetObserverUsesOnlyGetAndOmitsRawIdentity(t *testing.T) {
	runner := &recordingRunner{}
	observer := KubectlObserver{Executable: "kubectl", Kubeconfig: "/private/admin.conf", Context: "production-admin", Runner: runner}
	desired := []DesiredObject{{Reference: resources.KubernetesObjectReference{APIVersion: "v1", Kind: "ConfigMap", Namespace: "reference-stack", Name: "gateway-config"}}}
	observation, err := observer.Observe(context.Background(), desired, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Objects) != 1 || !observation.Objects[0].Readable || observation.Objects[0].Exists || strings.Contains(observation.Target.ReferenceDigest, "cluster.internal") {
		t.Fatalf("unexpected observation: %#v", observation)
	}
	for _, call := range runner.calls {
		joined := " " + strings.Join(call, " ") + " "
		for _, forbidden := range []string{" create ", " apply ", " patch ", " delete ", " exec ", " diff ", "--dry-run=server"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("observer issued forbidden command: %v", call)
			}
		}
		if !strings.Contains(joined, " config view ") && !strings.Contains(joined, " get ") {
			t.Fatalf("observer issued non-read command: %v", call)
		}
	}
}
