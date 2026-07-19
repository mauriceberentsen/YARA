package targetpreflight

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls [][]string
}

func (f *fakeRunner) Run(_ context.Context, executable string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{executable}, args...))
	command := strings.Join(args, " ")
	switch {
	case strings.Contains(command, "config view"):
		return []byte(`{"clusters":[{"cluster":{"server":"https://cluster.internal:6443"}}]}`), nil
	case strings.Contains(command, "--raw=/version"):
		return []byte(`{"gitVersion":"v1.35.2"}`), nil
	case strings.Contains(command, "namespace kube-system"):
		return []byte(`{"metadata":{"uid":"system-uid-secret"}}`), nil
	case strings.Contains(command, "--raw=/api/v1"), strings.Contains(command, "--raw=/apis/apps/v1"), strings.Contains(command, "--raw=/apis/networking.k8s.io/v1"):
		return []byte(`{}`), nil
	case strings.Contains(command, "get nodes"):
		return []byte(`{"items":[{"metadata":{"name":"worker-secret"},"status":{"allocatable":{"nvidia.com/gpu":"2"},"nodeInfo":{"architecture":"amd64","operatingSystem":"linux"}}}]}`), nil
	case strings.Contains(command, "get pods"):
		return []byte(`{"items":[{"metadata":{"name":"coredns-secret"}}]}`), nil
	case strings.Contains(command, "namespace reference-stack"):
		return nil, nil
	case strings.Contains(command, "get pvc yara-model"):
		return []byte(`{"status":{"phase":"Bound"}}`), nil
	default:
		return nil, errors.New("unexpected read")
	}
}

func TestKubectlObserverUsesOnlyBoundedReadsAndPseudonymizesTarget(t *testing.T) {
	runner := &fakeRunner{}
	observer := KubectlObserver{Executable: "kubectl", Kubeconfig: "/secret/admin.conf", Context: "production-admin", Runner: runner}
	observed, err := observer.Observe(context.Background(), "reference-stack", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if observed.ReferenceDigest == "" || observed.GPUCount != 2 || !reflect.DeepEqual(observed.NodePlatforms, []string{"linux/amd64"}) || observed.DNSPodCount != 1 || !observed.PVCExists {
		t.Fatalf("incomplete observation: %#v", observed)
	}
	if strings.Contains(observed.ReferenceDigest, "cluster.internal") || strings.Contains(observed.ReferenceDigest, "system-uid-secret") {
		t.Fatalf("target reference is not pseudonymous: %s", observed.ReferenceDigest)
	}
	for _, call := range runner.calls {
		joined := strings.Join(call, " ")
		for _, forbidden := range []string{" create ", " apply ", " patch ", " delete ", " exec ", "--dry-run=server"} {
			if strings.Contains(" "+joined+" ", forbidden) {
				t.Fatalf("observer issued mutating/active command: %v", call)
			}
		}
		if !strings.Contains(joined, " config view ") && !strings.Contains(joined, " get ") {
			t.Fatalf("observer issued non-read command: %v", call)
		}
	}
}

func TestTargetReferenceDigestIsDeterministicAndSensitive(t *testing.T) {
	first, err := targetReferenceDigest("https://cluster.example", "uid-a")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := targetReferenceDigest("https://cluster.example", "uid-a")
	third, _ := targetReferenceDigest("https://cluster.example", "uid-b")
	if first != second || first == third || reflect.DeepEqual(first, "https://cluster.example") {
		t.Fatalf("unexpected identity behavior: %q %q %q", first, second, third)
	}
}
