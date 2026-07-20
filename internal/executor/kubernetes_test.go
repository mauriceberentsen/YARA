package executor

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/changeset"
	"github.com/mauriceberentsen/YARA/internal/planner"
	"github.com/mauriceberentsen/YARA/internal/renderer"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

type fakeKubectl struct {
	planID           string
	namespace        string
	desired          map[string]map[string]any
	objects          map[string]map[string]any
	calls            []string
	podCommands      [][]string
	verifierFailure  bool
	holder           string
	authorizationID  string
	foreignNamespace bool
}

func (f *fakeKubectl) Run(_ context.Context, _ string, stdin []byte, args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	command := strings.Join(args, " ")
	switch {
	case command == "config view --minify --raw=false -o json":
		return []byte(`{"clusters":[{"cluster":{"server":"https://cluster.invalid"}}]}`), nil
	case command == "get --raw=/version":
		return []byte(`{"gitVersion":"v1.35.2"}`), nil
	case command == "get namespace kube-system -o json":
		return []byte(`{"metadata":{"uid":"system-uid"}}`), nil
	case strings.HasPrefix(command, "get --raw=/api") || strings.HasPrefix(command, "get --raw=/apis"):
		return []byte(`{}`), nil
	case command == "get nodes -o json" || command == "get pods -n kube-system -l k8s-app=kube-dns -o json":
		return []byte(`{"items":[]}`), nil
	case strings.HasPrefix(command, "get namespace yara-identity-only") || strings.HasPrefix(command, "get pvc yara-model -n yara-identity-only"):
		return nil, nil
	case command == "create -f -":
		var object map[string]any
		if err := yaml.Unmarshal(stdin, &object); err != nil {
			return nil, err
		}
		kind, _ := object["kind"].(string)
		metadata, _ := object["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if kind == "Lease" {
			spec, _ := object["spec"].(map[string]any)
			f.holder, _ = spec["holderIdentity"].(string)
			annotations, _ := metadata["annotations"].(map[string]any)
			f.authorizationID, _ = annotations["yara.dev/authorization-id"].(string)
			return nil, nil
		}
		if kind == "Pod" {
			spec, _ := object["spec"].(map[string]any)
			containers, _ := spec["containers"].([]any)
			if len(containers) == 1 {
				container, _ := containers[0].(map[string]any)
				command, _ := container["command"].([]any)
				values := make([]string, 0, len(command))
				for _, value := range command {
					text, _ := value.(string)
					values = append(values, text)
				}
				f.podCommands = append(f.podCommands, values)
			}
			return nil, nil
		}
		return nil, errors.New("unexpected create: " + name)
	case command == "apply --server-side --field-manager=yara-executor -f -":
		var object map[string]any
		if err := yaml.Unmarshal(stdin, &object); err != nil {
			return nil, err
		}
		ref := referenceOf(object)
		f.objects[keyOf(ref)] = object
		return nil, nil
	case strings.HasPrefix(command, "wait --for=jsonpath={.status.phase}=Succeeded pod/"):
		return nil, nil
	case strings.HasPrefix(command, "get pod "):
		name := args[2]
		authorizationID := testDigest('b')
		if strings.Contains(name, strings.TrimPrefix(testDigest('d'), "sha256:")[:12]) {
			authorizationID = testDigest('d')
		}
		phase := "Succeeded"
		containerStatuses := []any{}
		if f.verifierFailure {
			phase = "Failed"
			containerStatuses = []any{map[string]any{"state": map[string]any{"waiting": map[string]any{"reason": "ContainerCannotRun"}}}}
		}
		return json.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "yara", "yara.dev/role": "verifier"}, "annotations": map[string]any{"yara.dev/authorization-id": authorizationID}}, "status": map[string]any{"phase": phase, "containerStatuses": containerStatuses}})
	case strings.HasPrefix(command, "delete pod ") || strings.HasPrefix(command, "rollout status deployment/"):
		return nil, nil
	case strings.HasPrefix(command, "delete ") && !strings.HasPrefix(command, "delete lease ") && !strings.HasPrefix(command, "delete pod "):
		ref, ok := referenceFromDelete(args)
		if !ok {
			return nil, errors.New("unexpected delete")
		}
		delete(f.objects, keyOf(ref))
		return nil, nil
	case strings.HasPrefix(command, "get lease "):
		data, _ := json.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "yara"}, "annotations": map[string]any{"yara.dev/authorization-id": f.authorizationID}}, "spec": map[string]any{"holderIdentity": f.holder}})
		return data, nil
	case strings.HasPrefix(command, "delete lease "):
		f.holder = ""
		return nil, nil
	case strings.HasPrefix(command, "get service gateway "):
		return serviceWithIP(f.objects, "gateway", f.namespace, "10.0.0.10")
	case strings.HasPrefix(command, "get service inference "):
		return serviceWithIP(f.objects, "inference", f.namespace, "10.0.0.11")
	case strings.HasPrefix(command, "get "):
		ref, ok := referenceFromGet(args)
		if !ok {
			return nil, errors.New("unexpected get")
		}
		object := f.objects[keyOf(ref)]
		if object == nil {
			return nil, nil
		}
		if f.foreignNamespace && ref.Kind == "Namespace" && ref.Name == f.namespace {
			object = cloneObject(object)
			metadata := object["metadata"].(map[string]any)
			metadata["labels"] = map[string]any{"app.kubernetes.io/managed-by": "foreign"}
		}
		return json.Marshal(object)
	default:
		return nil, errors.New("unexpected kubectl command: " + command)
	}
}

func TestKubernetesExecutorAppliesOnlyApprovedObjectsUnderLock(t *testing.T) {
	bundle, desired, changeSet, authorization, importReceipt, fake := executorFixture(t, false)
	engine := Kubernetes{Executable: "kubectl", Runner: fake}
	result, err := engine.Execute(t.Context(), bundle, changeSet, authorization, importReceipt, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !result.MutationStarted || len(result.Operations) != len(desired) {
		t.Fatalf("incomplete execution result: %#v", result)
	}
	leaseCreate, firstApply, leaseDelete := callIndex(fake.calls, "create -f -"), callIndex(fake.calls, "apply --server-side"), callIndex(fake.calls, "delete lease")
	if leaseCreate < 0 || firstApply <= leaseCreate || leaseDelete <= firstApply {
		t.Fatalf("mutation escaped lock ordering: %#v", fake.calls)
	}
	applyCount := 0
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "apply --server-side") {
			applyCount++
		}
		if strings.Contains(call, "delete") && !strings.HasPrefix(call, "delete pod") && !strings.HasPrefix(call, "delete lease") {
			t.Fatalf("executor issued managed deletion: %s", call)
		}
	}
	if applyCount != len(desired)-1 {
		t.Fatalf("applied %d objects, expected %d", applyCount, len(desired)-1)
	}
	if len(fake.podCommands) != 2 {
		t.Fatalf("expected prerequisite and postflight verifier Pods, got %#v", fake.podCommands)
	}
	for _, command := range fake.podCommands {
		if len(command) == 0 || command[0] != "/usr/bin/python3" {
			t.Fatalf("verifier must use the image's stable Python entrypoint: %#v", command)
		}
	}
	for _, operation := range result.Operations {
		if operation.Resource.Kind == "Namespace" && operation.Outcome != "unchanged" {
			t.Fatalf("existing namespace mutated: %#v", operation)
		}
	}
}

func TestKubernetesExecutorSecondReviewedApplyIsIdempotent(t *testing.T) {
	bundle, desired, changeSet, authorization, importReceipt, fake := executorFixture(t, false)
	engine := Kubernetes{Executable: "kubectl", Runner: fake}
	if _, err := engine.Execute(t.Context(), bundle, changeSet, authorization, importReceipt, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	before := countCalls(fake.calls, "apply --server-side")
	operations := make([]resources.KubernetesChangeOperation, 0, len(desired))
	for _, object := range desired {
		operations = append(operations, resources.KubernetesChangeOperation{Resource: object.Reference, Action: "no-op", Ownership: "owned", DesiredDigest: object.Digest, CurrentDigest: object.Digest, RiskClasses: riskForTest(object.Reference.Kind)})
	}
	second := changeSet
	second.Spec.Operations = operations
	second.Spec.Summary = resources.KubernetesChangeSummary{NoOps: len(operations)}
	second.Metadata.ChangeSetID = testDigest('c')
	authorization.Metadata.AuthorizationID = testDigest('d')
	authorization.Spec.Constraints.AllowedActions = []string{"no-op"}
	result, err := engine.Execute(t.Context(), bundle, second, authorization, importReceipt, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if after := countCalls(fake.calls, "apply --server-side"); after != before {
		t.Fatalf("second apply wrote bundle objects: before=%d after=%d", before, after)
	}
	for _, operation := range result.Operations {
		if operation.Outcome != "unchanged" {
			t.Fatalf("second apply was not no-op: %#v", operation)
		}
	}
}

func TestKubernetesExecutorRejectsStaleForeignStateBeforeObjectApply(t *testing.T) {
	bundle, _, changeSet, authorization, importReceipt, fake := executorFixture(t, true)
	engine := Kubernetes{Executable: "kubectl", Runner: fake}
	result, err := engine.Execute(t.Context(), bundle, changeSet, authorization, importReceipt, time.Now().UTC())
	if err == nil || !result.MutationStarted {
		t.Fatalf("foreign state was not rejected: result=%#v err=%v", result, err)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "apply --server-side") {
			t.Fatalf("object applied after stale-state detection: %s", call)
		}
	}
	if callIndex(fake.calls, "delete lease") < 0 {
		t.Fatalf("lock not released: %#v", fake.calls)
	}
	if len(result.Operations) == 0 || !slices.ContainsFunc(result.Operations, func(operation resources.DeploymentOperationReceipt) bool { return operation.Outcome == "skipped" }) {
		t.Fatalf("partial receipt evidence missing: %#v", result)
	}
}

func TestKubernetesExecutorStopsOnTerminalVerifierFailureBeforeObjectApply(t *testing.T) {
	bundle, _, changeSet, authorization, importReceipt, fake := executorFixture(t, false)
	fake.verifierFailure = true
	engine := Kubernetes{Executable: "kubectl", Runner: fake}
	result, err := engine.Execute(t.Context(), bundle, changeSet, authorization, importReceipt, time.Now().UTC())
	if err == nil || !result.MutationStarted {
		t.Fatalf("terminal verifier failure was not reported: result=%#v err=%v", result, err)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "apply --server-side") {
			t.Fatalf("object applied after terminal verifier failure: %s", call)
		}
	}
	if callIndex(fake.calls, "delete pod") < 0 || callIndex(fake.calls, "delete lease") < 0 {
		t.Fatalf("verifier or lease cleanup missing: %#v", fake.calls)
	}
}

func TestKubernetesExecutorRejectsChangeSetNotMatchingBundleBeforeTargetAccess(t *testing.T) {
	bundle, _, changeSet, authorization, importReceipt, fake := executorFixture(t, false)
	changeSet.Spec.Operations[0].DesiredDigest = testDigest('f')
	engine := Kubernetes{Executable: "kubectl", Runner: fake}
	result, err := engine.Execute(t.Context(), bundle, changeSet, authorization, importReceipt, time.Now().UTC())
	if err == nil || result.MutationStarted || len(fake.calls) != 0 {
		t.Fatalf("mismatched change set reached target: result=%#v err=%v calls=%#v", result, err, fake.calls)
	}
}

func TestKubernetesRollbackAppliesReviewedRollbackSetUnderLock(t *testing.T) {
	bundle, desired, changeSet, authorization, _, fake := executorFixture(t, false)
	authorization.Metadata.AuthorizationID = testDigest('c')
	authorization.Spec.Constraints.AllowedActions = []string{"create", "no-op"}
	authorization.Spec.Constraints.AllowDelete = false
	authorization.Spec.Constraints.AllowActiveVerification = false
	authorization.Spec.Constraints.AcceptedPreflightBlockers = nil
	authorization.Spec.Constraints.MaxOperations = len(desired)
	engine := Kubernetes{Executable: "kubectl", Runner: fake}
	result, err := engine.Rollback(t.Context(), bundle, changeSet, authorization, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !result.MutationStarted || len(result.Operations) != len(desired) {
		t.Fatalf("rollback did not complete: %#v", result)
	}
	leaseCreate, firstApply, leaseDelete := callIndex(fake.calls, "create -f -"), callIndex(fake.calls, "apply --server-side"), callIndex(fake.calls, "delete lease")
	if leaseCreate < 0 || firstApply <= leaseCreate || leaseDelete <= firstApply {
		t.Fatalf("rollback escaped lock ordering: %#v", fake.calls)
	}
}

func TestKubernetesRollbackRejectsStaleForeignStateBeforeApply(t *testing.T) {
	bundle, desired, changeSet, authorization, _, fake := executorFixture(t, false)
	foreign := cloneObject(desired[1].Object)
	metadata := foreign["metadata"].(map[string]any)
	metadata["labels"] = map[string]any{"app.kubernetes.io/managed-by": "foreign"}
	fake.objects[keyOf(desired[1].Reference)] = foreign
	authorization.Metadata.AuthorizationID = testDigest('d')
	authorization.Spec.Constraints.AllowedActions = []string{"create", "no-op"}
	authorization.Spec.Constraints.AllowDelete = false
	authorization.Spec.Constraints.AllowActiveVerification = false
	authorization.Spec.Constraints.AcceptedPreflightBlockers = nil
	authorization.Spec.Constraints.MaxOperations = len(desired)
	engine := Kubernetes{Executable: "kubectl", Runner: fake}
	result, err := engine.Rollback(t.Context(), bundle, changeSet, authorization, time.Now().UTC())
	if err == nil || !result.MutationStarted {
		t.Fatalf("rollback stale state was not rejected: result=%#v err=%v", result, err)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "apply --server-side") {
			t.Fatalf("rollback applied objects after stale-state detection: %s", call)
		}
	}
}

func TestKubernetesRetirementDeletesOwnedReviewedResourcesUnderLock(t *testing.T) {
	bundle, desired, changeSet, authorization, _, fake := executorFixture(t, false)
	retireSet := changeSet
	retireOps := make([]resources.KubernetesChangeOperation, 0, len(desired))
	for _, object := range desired {
		retireOps = append(retireOps, resources.KubernetesChangeOperation{
			Resource:      object.Reference,
			Action:        "no-op",
			Ownership:     "owned",
			DesiredDigest: object.Digest,
			CurrentDigest: object.Digest,
			RiskClasses:   riskForTest(object.Reference.Kind),
		})
		fake.objects[keyOf(object.Reference)] = cloneObject(object.Object)
	}
	retireSet.Spec.Operations = retireOps
	retireSet.Spec.Summary = resources.KubernetesChangeSummary{NoOps: len(retireOps)}
	authorization.Metadata.AuthorizationID = testDigest('c')
	authorization.Spec.Constraints.AllowedActions = []string{"delete"}
	authorization.Spec.Constraints.AllowDelete = true
	authorization.Spec.Constraints.AllowActiveVerification = false
	authorization.Spec.Constraints.AcceptedPreflightBlockers = nil
	authorization.Spec.Constraints.MaxOperations = len(desired) - 1
	engine := Kubernetes{Executable: "kubectl", Runner: fake}
	result, err := engine.Retire(t.Context(), bundle, retireSet, authorization, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !result.MutationStarted {
		t.Fatalf("retirement did not start mutation: %#v", result)
	}
	for _, operation := range result.Operations {
		if operation.Resource.Kind == "Namespace" {
			t.Fatalf("namespace should not be retired: %#v", operation)
		}
		if operation.Outcome != "deleted" {
			t.Fatalf("retirement operation did not delete: %#v", operation)
		}
	}
	leaseCreate, firstDelete, leaseDelete := callIndex(fake.calls, "create -f -"), callIndex(fake.calls, "delete "), callIndex(fake.calls, "delete lease")
	if leaseCreate < 0 || firstDelete <= leaseCreate || leaseDelete <= firstDelete {
		t.Fatalf("retirement escaped lock ordering: %#v", fake.calls)
	}
}

func TestKubernetesRetirementRejectsDriftBeforeDelete(t *testing.T) {
	bundle, desired, changeSet, authorization, _, fake := executorFixture(t, false)
	retireSet := changeSet
	retireOps := make([]resources.KubernetesChangeOperation, 0, len(desired))
	for _, object := range desired {
		retireOps = append(retireOps, resources.KubernetesChangeOperation{
			Resource:      object.Reference,
			Action:        "no-op",
			Ownership:     "owned",
			DesiredDigest: object.Digest,
			CurrentDigest: object.Digest,
			RiskClasses:   riskForTest(object.Reference.Kind),
		})
	}
	retireSet.Spec.Operations = retireOps
	retireSet.Spec.Summary = resources.KubernetesChangeSummary{NoOps: len(retireOps)}
	for _, object := range desired {
		if object.Reference.Kind == "Deployment" {
			drifted := cloneObject(object.Object)
			metadata := drifted["metadata"].(map[string]any)
			metadata["labels"] = map[string]any{"app.kubernetes.io/managed-by": "foreign"}
			fake.objects[keyOf(object.Reference)] = drifted
			continue
		}
		fake.objects[keyOf(object.Reference)] = cloneObject(object.Object)
	}
	authorization.Metadata.AuthorizationID = testDigest('d')
	authorization.Spec.Constraints.AllowedActions = []string{"delete"}
	authorization.Spec.Constraints.AllowDelete = true
	authorization.Spec.Constraints.AllowActiveVerification = false
	authorization.Spec.Constraints.AcceptedPreflightBlockers = nil
	authorization.Spec.Constraints.MaxOperations = len(desired) - 1
	engine := Kubernetes{Executable: "kubectl", Runner: fake}
	result, err := engine.Retire(t.Context(), bundle, retireSet, authorization, time.Now().UTC())
	if err == nil || !result.MutationStarted {
		t.Fatalf("retirement drift was not rejected: result=%#v err=%v", result, err)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "delete ") && !strings.HasPrefix(call, "delete lease ") {
			t.Fatalf("retirement deleted after drift detection: %s", call)
		}
	}
}

func executorFixture(t *testing.T, foreign bool) (resources.DeploymentBundle, []changeset.DesiredObject, resources.KubernetesChangeSet, resources.ExecutionAuthorization, resources.ArtifactImportReceipt, *fakeKubectl) {
	t.Helper()
	root := filepath.Join("..", "..")
	request, err := resources.LoadPlatformRequest(filepath.Join(root, "docs", "examples", "v0.2-platform-request.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := resources.LoadInventory(filepath.Join(root, "docs", "examples", "v0.2-inventory.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := catalog.Load(filepath.Join(root, "catalog", "v0.2", "snapshot.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	created := planner.Create(request, inventory, snapshot)
	if !created.Report.Valid {
		t.Fatalf("fixture plan failed: %#v", created.Report.Diagnostics)
	}
	bundle, err := (renderer.KubernetesGitOps{}).Render("reference-stack", created.Plan, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := changeset.DesiredObjects(bundle)
	if err != nil {
		t.Fatal(err)
	}
	server := "https://cluster.invalid"
	uid := "system-uid"
	digest, _ := canonical.Digest(struct {
		Server string `json:"server"`
		UID    string `json:"systemNamespaceUid"`
	}{server, uid})
	target := resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: digest, ServerVersion: "v1.35.2"}
	objects := map[string]map[string]any{}
	operations := make([]resources.KubernetesChangeOperation, 0, len(desired))
	summary := resources.KubernetesChangeSummary{}
	for _, object := range desired {
		action, ownership, current := "create", "absent", ""
		if object.Reference.Kind == "Namespace" {
			action, ownership, current = "no-op", "owned", object.Digest
			objects[keyOf(object.Reference)] = cloneObject(object.Object)
			summary.NoOps++
		} else {
			summary.Creates++
		}
		operations = append(operations, resources.KubernetesChangeOperation{Resource: object.Reference, Action: action, Ownership: ownership, DesiredDigest: object.Digest, CurrentDigest: current, RiskClasses: riskForTest(object.Reference.Kind)})
	}
	changeSet := resources.KubernetesChangeSet{APIVersion: resources.APIVersion, Kind: "KubernetesChangeSet", Metadata: resources.KubernetesChangeSetMetadata{Name: "approved"}, Spec: resources.KubernetesChangeSetSpec{Outcome: "review-required", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), BundleID: bundle.Metadata.BundleID, PlanID: bundle.Spec.PlanID, PreflightResultID: testDigest('a'), Observer: resources.TargetPreflightObserver{Name: "observer", Version: "0.1.0", Mode: "read-only"}, Target: target, Summary: summary, Operations: operations, Limitations: []string{"Test."}}}
	changeSet, err = changeSet.AssignChangeSetID()
	if err != nil {
		t.Fatal(err)
	}
	authorization := resources.ExecutionAuthorization{Metadata: resources.ExecutionAuthorizationMetadata{AuthorizationID: testDigest('b')}, Spec: resources.ExecutionAuthorizationSpec{Target: target, Constraints: resources.ExecutionAuthorizationConstraints{AllowedActions: []string{"create", "no-op"}, MaxOperations: len(desired), AllowActiveVerification: true}}}
	desiredMap := map[string]map[string]any{}
	for _, object := range desired {
		desiredMap[keyOf(object.Reference)] = object.Object
	}
	fake := &fakeKubectl{planID: bundle.Spec.PlanID, namespace: bundle.Metadata.Name, desired: desiredMap, objects: objects, foreignNamespace: foreign}
	modelArtifact := executorModelArtifact(t, bundle)
	importReceipt := resources.ArtifactImportReceipt{
		APIVersion: resources.APIVersion,
		Kind:       "ArtifactImportReceipt",
		Metadata:   resources.ArtifactImportReceiptMetadata{Name: "import"},
		Spec: resources.ArtifactImportReceiptSpec{
			RecordedAt: time.Now().UTC().Format(time.RFC3339Nano),
			PlanID:     bundle.Spec.PlanID,
			BundleID:   bundle.Metadata.BundleID,
			Target:     target,
			Importer:   resources.ImporterIdentity{Name: "yara-importer", Version: "0.1.0"},
			Verification: resources.ImportVerificationStatus{
				DigestVerified: true,
				SizeVerified:   true,
				CompleteSet:    true,
			},
			ModelArtifacts: []resources.ImportedModelArtifact{{
				Ref:      modelArtifact.Ref,
				Revision: modelArtifact.Revision,
				Files: []resources.ImportedModelArtifactBinding{
					{Path: modelArtifact.Files[0].Path, Digest: modelArtifact.Files[0].Digest, SizeBytes: modelArtifact.Files[0].SizeBytes, InternalPath: "model/" + modelArtifact.Files[0].Path},
					{Path: modelArtifact.Files[1].Path, Digest: modelArtifact.Files[1].Digest, SizeBytes: modelArtifact.Files[1].SizeBytes, InternalPath: "model/" + modelArtifact.Files[1].Path},
				},
			}},
			Limitations: []string{"Import evidence is external to executor mutation."},
		},
	}
	importReceipt, err = importReceipt.AssignImportReceiptID()
	if err != nil {
		t.Fatal(err)
	}
	return bundle, desired, changeSet, authorization, importReceipt, fake
}

func executorModelArtifact(t *testing.T, bundle resources.DeploymentBundle) resources.BundleArtifact {
	t.Helper()
	for _, artifact := range bundle.Spec.Artifacts {
		if artifact.Type == "huggingface-snapshot" {
			return artifact
		}
	}
	t.Fatal("fixture bundle missing huggingface-snapshot artifact")
	return resources.BundleArtifact{}
}

func referenceOf(object map[string]any) resources.KubernetesObjectReference {
	metadata := object["metadata"].(map[string]any)
	ref := resources.KubernetesObjectReference{APIVersion: object["apiVersion"].(string), Kind: object["kind"].(string), Name: metadata["name"].(string)}
	ref.Namespace, _ = metadata["namespace"].(string)
	return ref
}
func keyOf(ref resources.KubernetesObjectReference) string {
	return strings.Join([]string{ref.APIVersion, ref.Kind, ref.Namespace, ref.Name}, "\x00")
}
func cloneObject(object map[string]any) map[string]any {
	data, _ := yaml.Marshal(object)
	var cloned map[string]any
	_ = yaml.Unmarshal(data, &cloned)
	return cloned
}
func serviceWithIP(objects map[string]map[string]any, name, namespace, ip string) ([]byte, error) {
	ref := resources.KubernetesObjectReference{APIVersion: "v1", Kind: "Service", Namespace: namespace, Name: name}
	object := cloneObject(objects[keyOf(ref)])
	if object == nil {
		return nil, errors.New("service absent")
	}
	spec := object["spec"].(map[string]any)
	spec["clusterIP"] = ip
	return json.Marshal(object)
}
func referenceFromGet(args []string) (resources.KubernetesObjectReference, bool) {
	if len(args) < 3 {
		return resources.KubernetesObjectReference{}, false
	}
	ref := resources.KubernetesObjectReference{Kind: args[1], Name: args[2]}
	for index := 3; index+1 < len(args); index++ {
		if args[index] == "-n" {
			ref.Namespace = args[index+1]
		}
	}
	switch ref.Kind {
	case "Namespace":
		ref.APIVersion = "v1"
	case "ConfigMap", "Service":
		ref.APIVersion = "v1"
	case "Deployment":
		ref.APIVersion = "apps/v1"
	case "NetworkPolicy":
		ref.APIVersion = "networking.k8s.io/v1"
	default:
		return ref, false
	}
	return ref, true
}

func referenceFromDelete(args []string) (resources.KubernetesObjectReference, bool) {
	if len(args) < 3 {
		return resources.KubernetesObjectReference{}, false
	}
	ref := resources.KubernetesObjectReference{Kind: args[1], Name: args[2]}
	for index := 3; index+1 < len(args); index++ {
		if args[index] == "-n" {
			ref.Namespace = args[index+1]
		}
	}
	switch ref.Kind {
	case "Namespace":
		ref.APIVersion = "v1"
	case "ConfigMap", "Service":
		ref.APIVersion = "v1"
	case "Deployment":
		ref.APIVersion = "apps/v1"
	case "NetworkPolicy":
		ref.APIVersion = "networking.k8s.io/v1"
	default:
		return ref, false
	}
	return ref, true
}
func callIndex(calls []string, prefix string) int {
	for index, call := range calls {
		if strings.HasPrefix(call, prefix) {
			return index
		}
	}
	return -1
}
func countCalls(calls []string, prefix string) int {
	count := 0
	for _, call := range calls {
		if strings.HasPrefix(call, prefix) {
			count++
		}
	}
	return count
}
func testDigest(character byte) string { return "sha256:" + strings.Repeat(string(character), 64) }
func riskForTest(kind string) []string {
	switch kind {
	case "Namespace":
		return []string{"namespace"}
	case "ConfigMap":
		return []string{"configuration"}
	case "Service":
		return []string{"network"}
	case "NetworkPolicy":
		return []string{"network-policy"}
	case "Deployment":
		return []string{"workload"}
	}
	return nil
}
