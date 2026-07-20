// Package executor contains the privileged, explicitly authorized mutation
// boundary. It does not perform planning or replace renderer decisions.
package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/mauriceberentsen/YARA/internal/canonical"
	"github.com/mauriceberentsen/YARA/internal/changeset"
	"github.com/mauriceberentsen/YARA/internal/resources"
	"gopkg.in/yaml.v3"
)

const (
	Version               = "0.1.0"
	maxCommandOutputBytes = 4 << 20
)

type Runner interface {
	Run(ctx context.Context, executable string, stdin []byte, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, executable string, stdin []byte, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdin = bytes.NewReader(stdin)
	var output boundedBuffer
	output.remaining = maxCommandOutputBytes
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, errors.New("authorized kubectl operation failed")
	}
	return output.Bytes(), nil
}

type boundedBuffer struct {
	bytes.Buffer
	remaining int
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > b.remaining {
		return 0, errors.New("kubectl output exceeds 4 MiB limit")
	}
	written, err := b.Buffer.Write(data)
	b.remaining -= written
	return written, err
}

type Kubernetes struct {
	Executable string
	Kubeconfig string
	Context    string
	Runner     Runner
}

type ExecutionResult struct {
	StartedAt       time.Time
	CompletedAt     time.Time
	Target          resources.TargetIdentity
	MutationStarted bool
	Operations      []resources.DeploymentOperationReceipt
	Postflight      []resources.DeploymentPostflightCheck
	Limitations     []string
}

type RetirementResult struct {
	StartedAt       time.Time
	CompletedAt     time.Time
	Target          resources.TargetIdentity
	MutationStarted bool
	Operations      []resources.RetirementOperationReceipt
	Limitations     []string
}

type RollbackResult struct {
	StartedAt       time.Time
	CompletedAt     time.Time
	Target          resources.TargetIdentity
	MutationStarted bool
	Operations      []resources.RollbackOperationReceipt
	Limitations     []string
}

func NewKubernetes(kubeconfig, contextName string) (Kubernetes, error) {
	executable, err := exec.LookPath("kubectl")
	if err != nil {
		return Kubernetes{}, errors.New("kubectl executable is unavailable")
	}
	return Kubernetes{Executable: executable, Kubeconfig: kubeconfig, Context: contextName, Runner: ExecRunner{}}, nil
}

func (k Kubernetes) Retire(ctx context.Context, bundle resources.DeploymentBundle, approved resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization, startedAt time.Time) (result RetirementResult, err error) {
	result.StartedAt = startedAt.UTC()
	if k.Executable == "" || k.Runner == nil {
		return result, errors.New("Kubernetes executor is incomplete")
	}
	desired, err := changeset.DesiredObjects(bundle)
	if err != nil {
		return result, err
	}
	approvedByKey := map[string]resources.KubernetesChangeOperation{}
	for _, operation := range approved.Spec.Operations {
		approvedByKey[objectKey(operation.Resource)] = operation
	}
	targets := make([]changeset.DesiredObject, 0, len(desired))
	for _, object := range desired {
		operation, ok := approvedByKey[objectKey(object.Reference)]
		if !ok {
			return result, errors.New("change set does not cover exact bundle objects")
		}
		if operation.Resource.Kind == "Namespace" {
			continue
		}
		if operation.Action != "no-op" || operation.Ownership != "owned" || operation.CurrentDigest != object.Digest {
			return result, errors.New("retirement requires an exact owned no-op baseline before delete authorization")
		}
		targets = append(targets, object)
	}
	if len(targets) == 0 {
		return result, errors.New("retirement target set is empty")
	}
	if !strings.HasPrefix(authorization.Metadata.AuthorizationID, "sha256:") || len(authorization.Metadata.AuthorizationID) != 71 || !authorization.Spec.Constraints.AllowDelete || len(authorization.Spec.Constraints.AllowedActions) != 1 || authorization.Spec.Constraints.AllowedActions[0] != "delete" || authorization.Spec.Constraints.AllowActiveVerification || len(authorization.Spec.Constraints.AcceptedPreflightBlockers) != 0 || authorization.Spec.Constraints.MaxOperations != len(targets) {
		return result, errors.New("retirement authorization constraints are invalid")
	}
	target, err := k.identify(ctx)
	if err != nil {
		return result, err
	}
	result.Target = target
	if target != authorization.Spec.Target || target != approved.Spec.Target {
		return result, errors.New("target identity changed before retirement")
	}
	lockName := "yara-retire-lock-" + bundle.Metadata.Name
	holder := strings.TrimPrefix(authorization.Metadata.AuthorizationID, "sha256:")[:24]
	if err := k.acquireLock(ctx, bundle.Metadata.Name, lockName, holder, authorization.Metadata.AuthorizationID); err != nil {
		return result, err
	}
	result.MutationStarted = true
	locked := true
	defer func() {
		if locked {
			if releaseErr := k.releaseLock(context.WithoutCancel(ctx), bundle.Metadata.Name, lockName, holder, authorization.Metadata.AuthorizationID); releaseErr != nil && err == nil {
				err = releaseErr
			}
		}
		if result.MutationStarted {
			completeRetirementResult(&result, targets)
		}
	}()
	for _, object := range targets {
		observed, observeErr := k.observeObject(ctx, object.Reference, bundle.Spec.PlanID)
		if observeErr != nil || !observed.Exists || !observed.Owned || !observed.PlanMatch || observed.Digest != object.Digest {
			return result, errors.New("target state changed after reviewed retirement set")
		}
	}
	ordered := append([]changeset.DesiredObject(nil), targets...)
	slices.SortFunc(ordered, func(left, right changeset.DesiredObject) int {
		leftPriority, rightPriority := retirePriority(left.Reference.Kind), retirePriority(right.Reference.Kind)
		if leftPriority != rightPriority {
			return leftPriority - rightPriority
		}
		return strings.Compare(objectKey(left.Reference), objectKey(right.Reference))
	})
	failed := false
	for _, object := range ordered {
		receipt := resources.RetirementOperationReceipt{Resource: object.Reference, Action: "delete", BeforeDigest: object.Digest}
		if failed {
			receipt.Outcome = "skipped"
			result.Operations = append(result.Operations, receipt)
			continue
		}
		if err := k.deleteObject(ctx, object.Reference); err != nil {
			receipt.Outcome, receipt.DiagnosticCode = "failed", "YARA-RET-201"
			failed = true
			result.Operations = append(result.Operations, receipt)
			continue
		}
		observed, observeErr := k.observeObject(ctx, object.Reference, bundle.Spec.PlanID)
		if observeErr != nil {
			receipt.Outcome, receipt.DiagnosticCode = "failed", "YARA-RET-202"
			failed = true
		} else if !observed.Exists {
			receipt.Outcome = "deleted"
		} else if observed.Owned && observed.PlanMatch {
			receipt.Outcome, receipt.DiagnosticCode = "failed", "YARA-RET-202"
			failed = true
		} else {
			receipt.Outcome, receipt.DiagnosticCode = "failed", "YARA-RET-203"
			failed = true
		}
		result.Operations = append(result.Operations, receipt)
	}
	if releaseErr := k.releaseLock(ctx, bundle.Metadata.Name, lockName, holder, authorization.Metadata.AuthorizationID); releaseErr != nil {
		return result, releaseErr
	}
	locked = false
	return result, nil
}

func (k Kubernetes) Execute(ctx context.Context, bundle resources.DeploymentBundle, approved resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization, importReceipt resources.ArtifactImportReceipt, startedAt time.Time) (result ExecutionResult, err error) {
	result.StartedAt = startedAt.UTC()
	if k.Executable == "" || k.Runner == nil {
		return result, errors.New("Kubernetes executor is incomplete")
	}
	desired, err := changeset.DesiredObjects(bundle)
	if err != nil {
		return result, err
	}
	if len(desired) != authorization.Spec.Constraints.MaxOperations || len(desired) != len(approved.Spec.Operations) {
		return result, errors.New("authorized operation count does not match bundle")
	}
	desiredByKey := make(map[string]changeset.DesiredObject, len(desired))
	for _, object := range desired {
		desiredByKey[objectKey(object.Reference)] = object
	}
	if !strings.HasPrefix(authorization.Metadata.AuthorizationID, "sha256:") || len(authorization.Metadata.AuthorizationID) != 71 || authorization.Spec.Constraints.AllowDelete {
		return result, errors.New("execution authorization identity or constraints are invalid")
	}
	for _, operation := range approved.Spec.Operations {
		if !slices.Contains([]string{"create", "update", "no-op"}, operation.Action) || !slices.Contains(authorization.Spec.Constraints.AllowedActions, operation.Action) {
			return result, errors.New("change set contains an unauthorized action")
		}
		object, exists := desiredByKey[objectKey(operation.Resource)]
		if !exists || operation.DesiredDigest != object.Digest {
			return result, errors.New("change set does not match exact bundle objects")
		}
	}
	if namespaceAction(approved) != "no-op" {
		return result, errors.New("initial executor requires an existing exact YARA-owned namespace")
	}
	target, err := k.identify(ctx)
	if err != nil {
		return result, err
	}
	result.Target = target
	if target != authorization.Spec.Target || target != approved.Spec.Target {
		return result, errors.New("target identity changed before execution")
	}
	lockName := "yara-lock-" + bundle.Metadata.Name
	holder := strings.TrimPrefix(authorization.Metadata.AuthorizationID, "sha256:")[:24]
	if err := k.acquireLock(ctx, bundle.Metadata.Name, lockName, holder, authorization.Metadata.AuthorizationID); err != nil {
		return result, err
	}
	result.MutationStarted = true
	locked := true
	defer func() {
		if locked {
			if releaseErr := k.releaseLock(context.WithoutCancel(ctx), bundle.Metadata.Name, lockName, holder, authorization.Metadata.AuthorizationID); releaseErr != nil {
				appendPostflightOnce(&result, failedCheck("executor.lock-release", "YARA-EXE-206"))
				if err == nil {
					err = releaseErr
				}
			}
		}
		if result.MutationStarted {
			completeResult(&result, desired, approved)
		}
	}()
	if err := k.assertApprovedState(ctx, desired, approved, bundle.Spec.PlanID); err != nil {
		return result, err
	}
	if authorization.Spec.Constraints.AllowActiveVerification {
		if err := k.verifyModelAndTmp(ctx, bundle, authorization, importReceipt); err != nil {
			return result, err
		}
		result.Postflight = append(result.Postflight, passedCheck("prerequisite.model-files"), passedCheck("prerequisite.tmp-exec"))
	}
	ordered := append([]changeset.DesiredObject(nil), desired...)
	slices.SortFunc(ordered, func(left, right changeset.DesiredObject) int {
		leftPriority, rightPriority := applyPriority(left.Reference.Kind), applyPriority(right.Reference.Kind)
		if leftPriority != rightPriority {
			return leftPriority - rightPriority
		}
		return strings.Compare(objectKey(left.Reference), objectKey(right.Reference))
	})
	approvedByKey := map[string]resources.KubernetesChangeOperation{}
	for _, operation := range approved.Spec.Operations {
		approvedByKey[objectKey(operation.Resource)] = operation
	}
	failed := false
	for _, object := range ordered {
		operation := approvedByKey[objectKey(object.Reference)]
		receipt := resources.DeploymentOperationReceipt{Resource: object.Reference, Action: operation.Action, BeforeDigest: operation.CurrentDigest}
		if failed {
			receipt.Outcome = "skipped"
			result.Operations = append(result.Operations, receipt)
			continue
		}
		if operation.Action == "no-op" {
			receipt.Outcome, receipt.AfterDigest = "unchanged", object.Digest
			result.Operations = append(result.Operations, receipt)
			continue
		}
		manifest, marshalErr := yaml.Marshal(object.Object)
		if marshalErr != nil || k.applyObject(ctx, manifest) != nil {
			receipt.Outcome, receipt.DiagnosticCode = "failed", "YARA-EXE-201"
			failed = true
			result.Operations = append(result.Operations, receipt)
			continue
		}
		observed, observeErr := k.observeObject(ctx, object.Reference, bundle.Spec.PlanID)
		if observeErr != nil || !observed.Exists || !observed.Owned || !observed.PlanMatch || observed.Digest != object.Digest {
			receipt.Outcome, receipt.DiagnosticCode = "failed", "YARA-EXE-202"
			failed = true
		} else {
			receipt.Outcome, receipt.AfterDigest = "applied", observed.Digest
		}
		result.Operations = append(result.Operations, receipt)
	}
	if !failed {
		if err := k.verifyDeployments(ctx, bundle.Metadata.Name, desired); err != nil {
			result.Postflight = append(result.Postflight, failedCheck("workloads.available", "YARA-EXE-203"))
		} else {
			result.Postflight = append(result.Postflight, passedCheck("workloads.available"))
		}
		if err := k.verifyInferenceAndNetworkPolicy(ctx, bundle, authorization); err != nil {
			result.Postflight = append(result.Postflight, failedCheck("inference.network-policy", "YARA-EXE-204"))
		} else {
			result.Postflight = append(result.Postflight, passedCheck("inference.network-policy"))
		}
	} else {
		result.Postflight = append(result.Postflight, blockedCheck("inference.network-policy", "YARA-EXE-205"), blockedCheck("workloads.available", "YARA-EXE-205"))
	}
	if releaseErr := k.releaseLock(ctx, bundle.Metadata.Name, lockName, holder, authorization.Metadata.AuthorizationID); releaseErr != nil {
		appendPostflightOnce(&result, failedCheck("executor.lock-release", "YARA-EXE-206"))
		return result, releaseErr
	}
	locked = false
	return result, nil
}

func (k Kubernetes) Rollback(ctx context.Context, bundle resources.DeploymentBundle, approved resources.KubernetesChangeSet, authorization resources.ExecutionAuthorization, startedAt time.Time) (result RollbackResult, err error) {
	result.StartedAt = startedAt.UTC()
	if k.Executable == "" || k.Runner == nil {
		return result, errors.New("Kubernetes executor is incomplete")
	}
	desired, err := changeset.DesiredObjects(bundle)
	if err != nil {
		return result, err
	}
	desiredByKey := make(map[string]changeset.DesiredObject, len(desired))
	for _, object := range desired {
		desiredByKey[objectKey(object.Reference)] = object
	}
	if len(desired) != len(approved.Spec.Operations) || !strings.HasPrefix(authorization.Metadata.AuthorizationID, "sha256:") || len(authorization.Metadata.AuthorizationID) != 71 || authorization.Spec.Constraints.AllowDelete || authorization.Spec.Constraints.AllowActiveVerification || len(authorization.Spec.Constraints.AcceptedPreflightBlockers) != 0 || authorization.Spec.Constraints.MaxOperations != len(desired) {
		return result, errors.New("rollback authorization identity or constraints are invalid")
	}
	for _, operation := range approved.Spec.Operations {
		if !slices.Contains([]string{"create", "update", "no-op"}, operation.Action) || !slices.Contains(authorization.Spec.Constraints.AllowedActions, operation.Action) {
			return result, errors.New("change set contains an unauthorized rollback action")
		}
		object, exists := desiredByKey[objectKey(operation.Resource)]
		if !exists || operation.DesiredDigest != object.Digest {
			return result, errors.New("change set does not match exact rollback bundle objects")
		}
	}
	if namespaceAction(approved) != "no-op" {
		return result, errors.New("rollback requires an existing exact YARA-owned namespace")
	}
	target, err := k.identify(ctx)
	if err != nil {
		return result, err
	}
	result.Target = target
	if target != authorization.Spec.Target || target != approved.Spec.Target {
		return result, errors.New("target identity changed before rollback")
	}
	lockName := "yara-rollback-lock-" + bundle.Metadata.Name
	holder := strings.TrimPrefix(authorization.Metadata.AuthorizationID, "sha256:")[:24]
	if err := k.acquireLock(ctx, bundle.Metadata.Name, lockName, holder, authorization.Metadata.AuthorizationID); err != nil {
		return result, err
	}
	result.MutationStarted = true
	locked := true
	defer func() {
		if locked {
			if releaseErr := k.releaseLock(context.WithoutCancel(ctx), bundle.Metadata.Name, lockName, holder, authorization.Metadata.AuthorizationID); releaseErr != nil && err == nil {
				err = releaseErr
			}
		}
		if result.MutationStarted {
			completeRollbackResult(&result, desired, approved)
		}
	}()
	if err := k.assertApprovedState(ctx, desired, approved, bundle.Spec.PlanID); err != nil {
		return result, err
	}
	ordered := append([]changeset.DesiredObject(nil), desired...)
	slices.SortFunc(ordered, func(left, right changeset.DesiredObject) int {
		leftPriority, rightPriority := applyPriority(left.Reference.Kind), applyPriority(right.Reference.Kind)
		if leftPriority != rightPriority {
			return leftPriority - rightPriority
		}
		return strings.Compare(objectKey(left.Reference), objectKey(right.Reference))
	})
	approvedByKey := map[string]resources.KubernetesChangeOperation{}
	for _, operation := range approved.Spec.Operations {
		approvedByKey[objectKey(operation.Resource)] = operation
	}
	failed := false
	for _, object := range ordered {
		operation := approvedByKey[objectKey(object.Reference)]
		receipt := resources.RollbackOperationReceipt{Resource: object.Reference, Action: operation.Action, BeforeDigest: operation.CurrentDigest}
		if failed {
			receipt.Outcome = "skipped"
			result.Operations = append(result.Operations, receipt)
			continue
		}
		if operation.Action == "no-op" {
			receipt.Outcome, receipt.AfterDigest = "unchanged", object.Digest
			result.Operations = append(result.Operations, receipt)
			continue
		}
		manifest, marshalErr := yaml.Marshal(object.Object)
		if marshalErr != nil || k.applyObject(ctx, manifest) != nil {
			receipt.Outcome, receipt.DiagnosticCode = "failed", "YARA-RBK-201"
			failed = true
			result.Operations = append(result.Operations, receipt)
			continue
		}
		observed, observeErr := k.observeObject(ctx, object.Reference, bundle.Spec.PlanID)
		if observeErr != nil || !observed.Exists || !observed.Owned || !observed.PlanMatch || observed.Digest != object.Digest {
			receipt.Outcome, receipt.DiagnosticCode = "failed", "YARA-RBK-202"
			failed = true
		} else {
			receipt.Outcome, receipt.AfterDigest = "reverted", observed.Digest
		}
		result.Operations = append(result.Operations, receipt)
	}
	if releaseErr := k.releaseLock(ctx, bundle.Metadata.Name, lockName, holder, authorization.Metadata.AuthorizationID); releaseErr != nil {
		return result, releaseErr
	}
	locked = false
	return result, nil
}

func appendPostflightOnce(result *ExecutionResult, check resources.DeploymentPostflightCheck) {
	for _, existing := range result.Postflight {
		if existing.ID == check.ID {
			return
		}
	}
	result.Postflight = append(result.Postflight, check)
}

func completeResult(result *ExecutionResult, desired []changeset.DesiredObject, approved resources.KubernetesChangeSet) {
	if len(result.Operations) < len(desired) {
		recorded := map[string]struct{}{}
		for _, operation := range result.Operations {
			recorded[objectKey(operation.Resource)] = struct{}{}
		}
		approvedByKey := map[string]resources.KubernetesChangeOperation{}
		for _, operation := range approved.Spec.Operations {
			approvedByKey[objectKey(operation.Resource)] = operation
		}
		for _, object := range desired {
			if _, exists := recorded[objectKey(object.Reference)]; exists {
				continue
			}
			operation := approvedByKey[objectKey(object.Reference)]
			result.Operations = append(result.Operations, resources.DeploymentOperationReceipt{Resource: object.Reference, Action: operation.Action, Outcome: "skipped", BeforeDigest: operation.CurrentDigest})
		}
	}
	if len(result.Postflight) == 0 {
		result.Postflight = append(result.Postflight, failedCheck("prerequisites.active", "YARA-EXE-207"))
	}
	slices.SortFunc(result.Operations, func(left, right resources.DeploymentOperationReceipt) int {
		return strings.Compare(objectKey(left.Resource), objectKey(right.Resource))
	})
	slices.SortFunc(result.Postflight, func(left, right resources.DeploymentPostflightCheck) int {
		return strings.Compare(left.ID, right.ID)
	})
	result.Limitations = []string{
		"The initial executor does not create namespaces, PVCs, storage classes or import model artifacts.",
		"The initial executor never adopts, deletes or prunes managed or foreign resources.",
		"Verifier-label governance remains an explicitly accepted authorization limitation, not a proved postcondition.",
	}
	slices.Sort(result.Limitations)
	result.CompletedAt = time.Now().UTC()
}

func completeRetirementResult(result *RetirementResult, targets []changeset.DesiredObject) {
	if len(result.Operations) < len(targets) {
		recorded := map[string]struct{}{}
		for _, operation := range result.Operations {
			recorded[objectKey(operation.Resource)] = struct{}{}
		}
		for _, object := range targets {
			if _, exists := recorded[objectKey(object.Reference)]; exists {
				continue
			}
			result.Operations = append(result.Operations, resources.RetirementOperationReceipt{Resource: object.Reference, Action: "delete", Outcome: "skipped", BeforeDigest: object.Digest})
		}
	}
	slices.SortFunc(result.Operations, func(left, right resources.RetirementOperationReceipt) int {
		return strings.Compare(objectKey(left.Resource), objectKey(right.Resource))
	})
	result.Limitations = []string{
		"Retirement never deletes Namespace, PVCs, storage classes or unmanaged resources.",
		"Retirement runs only from a fresh exact no-op baseline and fails closed on any observed drift.",
		"Retirement does not implement rollback or re-provisioning.",
	}
	slices.Sort(result.Limitations)
	result.CompletedAt = time.Now().UTC()
}

func completeRollbackResult(result *RollbackResult, desired []changeset.DesiredObject, approved resources.KubernetesChangeSet) {
	if len(result.Operations) < len(desired) {
		recorded := map[string]struct{}{}
		for _, operation := range result.Operations {
			recorded[objectKey(operation.Resource)] = struct{}{}
		}
		approvedByKey := map[string]resources.KubernetesChangeOperation{}
		for _, operation := range approved.Spec.Operations {
			approvedByKey[objectKey(operation.Resource)] = operation
		}
		for _, object := range desired {
			if _, exists := recorded[objectKey(object.Reference)]; exists {
				continue
			}
			operation := approvedByKey[objectKey(object.Reference)]
			result.Operations = append(result.Operations, resources.RollbackOperationReceipt{Resource: object.Reference, Action: operation.Action, Outcome: "skipped", BeforeDigest: operation.CurrentDigest})
		}
	}
	slices.SortFunc(result.Operations, func(left, right resources.RollbackOperationReceipt) int {
		return strings.Compare(objectKey(left.Resource), objectKey(right.Resource))
	})
	result.Limitations = []string{
		"Rollback applies only the explicitly reviewed rollback bundle object set and never prunes or adopts resources.",
		"Rollback requires a fresh reviewed change set and signed authorization; it fails closed on stale or foreign state.",
		"Rollback does not restore external artifact import state or execute retirement.",
	}
	slices.Sort(result.Limitations)
	result.CompletedAt = time.Now().UTC()
}

func (k Kubernetes) assertApprovedState(ctx context.Context, desired []changeset.DesiredObject, approved resources.KubernetesChangeSet, planID string) error {
	approvedByKey := map[string]resources.KubernetesChangeOperation{}
	for _, operation := range approved.Spec.Operations {
		approvedByKey[objectKey(operation.Resource)] = operation
	}
	for _, object := range desired {
		observed, err := k.observeObject(ctx, object.Reference, planID)
		if err != nil {
			return errors.New("stale-state observation failed while lock is held")
		}
		expected := approvedByKey[objectKey(object.Reference)]
		action := "create"
		current := ""
		if observed.Exists {
			if !observed.Owned || !observed.PlanMatch {
				return errors.New("foreign ownership appeared after approval")
			}
			current = observed.Digest
			if current == object.Digest {
				action = "no-op"
			} else {
				action = "update"
			}
		}
		if action != expected.Action || current != expected.CurrentDigest {
			return errors.New("target state changed after approved change set")
		}
	}
	return nil
}

func (k Kubernetes) observeObject(ctx context.Context, reference resources.KubernetesObjectReference, planID string) (changeset.ObjectObservation, error) {
	args := []string{"get", reference.Kind, reference.Name}
	if reference.Namespace != "" {
		args = append(args, "-n", reference.Namespace)
	}
	args = append(args, "-o", "json", "--ignore-not-found")
	data, err := k.run(ctx, nil, args...)
	if err != nil {
		return changeset.ObjectObservation{}, err
	}
	return changeset.DecodeCurrentObject(data, reference, planID)
}

func (k Kubernetes) identify(ctx context.Context) (resources.TargetIdentity, error) {
	configData, err := k.run(ctx, nil, "config", "view", "--minify", "--raw=false", "-o", "json")
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
	if json.Unmarshal(configData, &config) != nil || len(config.Clusters) != 1 || strings.TrimSpace(config.Clusters[0].Cluster.Server) == "" {
		return resources.TargetIdentity{}, errors.New("kubectl context does not resolve one API server")
	}
	versionData, err := k.run(ctx, nil, "get", "--raw=/version")
	if err != nil {
		return resources.TargetIdentity{}, err
	}
	var version struct {
		GitVersion string `json:"gitVersion"`
	}
	if json.Unmarshal(versionData, &version) != nil || version.GitVersion == "" {
		return resources.TargetIdentity{}, errors.New("Kubernetes server version is unavailable")
	}
	namespaceData, err := k.run(ctx, nil, "get", "namespace", "kube-system", "-o", "json")
	if err != nil {
		return resources.TargetIdentity{}, err
	}
	var namespace struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if json.Unmarshal(namespaceData, &namespace) != nil || strings.TrimSpace(namespace.Metadata.UID) == "" {
		return resources.TargetIdentity{}, errors.New("kube-system identity is unavailable")
	}
	digest, err := canonical.Digest(struct {
		Server string `json:"server"`
		UID    string `json:"systemNamespaceUid"`
	}{strings.TrimSpace(config.Clusters[0].Cluster.Server), strings.TrimSpace(namespace.Metadata.UID)})
	if err != nil {
		return resources.TargetIdentity{}, errors.New("target identity could not be derived")
	}
	return resources.TargetIdentity{Type: "kubernetes", ReferenceDigest: digest, ServerVersion: version.GitVersion}, nil
}

func (k Kubernetes) acquireLock(ctx context.Context, namespace, name, holder, authorizationID string) error {
	lease := map[string]any{"apiVersion": "coordination.k8s.io/v1", "kind": "Lease", "metadata": map[string]any{"name": name, "namespace": namespace, "labels": map[string]any{"app.kubernetes.io/managed-by": "yara"}, "annotations": map[string]any{"yara.dev/authorization-id": authorizationID}}, "spec": map[string]any{"holderIdentity": holder, "leaseDurationSeconds": 900}}
	data, _ := yaml.Marshal(lease)
	_, err := k.run(ctx, data, "create", "-f", "-")
	if err != nil {
		return errors.New("exclusive target Lease could not be acquired")
	}
	return nil
}

func (k Kubernetes) releaseLock(ctx context.Context, namespace, name, holder, authorizationID string) error {
	data, err := k.run(ctx, nil, "get", "lease", name, "-n", namespace, "-o", "json")
	if err != nil {
		return errors.New("target Lease could not be read before release")
	}
	var lease struct {
		Metadata struct {
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			HolderIdentity string `json:"holderIdentity"`
		} `json:"spec"`
	}
	if json.Unmarshal(data, &lease) != nil || lease.Spec.HolderIdentity != holder || lease.Metadata.Labels["app.kubernetes.io/managed-by"] != "yara" || lease.Metadata.Annotations["yara.dev/authorization-id"] != authorizationID {
		return errors.New("target Lease ownership changed before release")
	}
	if _, err := k.run(ctx, nil, "delete", "lease", name, "-n", namespace, "--wait=true", "--timeout=30s"); err != nil {
		return errors.New("owned target Lease could not be released")
	}
	return nil
}

func (k Kubernetes) verifyModelAndTmp(ctx context.Context, bundle resources.DeploymentBundle, authorization resources.ExecutionAuthorization, importReceipt resources.ArtifactImportReceipt) error {
	model, image, err := verificationArtifacts(bundle)
	if err != nil {
		return err
	}
	expectedFiles, err := expectedImportedModelFiles(model, importReceipt)
	if err != nil {
		return err
	}
	expected, _ := json.Marshal(expectedFiles)
	script := `import hashlib,json,os,subprocess,sys
files=json.loads(sys.argv[1])
for item in files:
 p=os.path.join('/models/import-root',item['internalPath'])
 if os.path.getsize(p)!=item['sizeBytes']: raise SystemExit(11)
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for chunk in iter(lambda:f.read(1048576),b''): h.update(chunk)
 if 'sha256:'+h.hexdigest()!=item['digest']: raise SystemExit(12)
p='/tmp/yara-exec-check';open(p,'w').write('#!/bin/sh\nexit 0\n');os.chmod(p,0o700);subprocess.run([p],check=True)`
	name := "yara-prereq-" + strings.TrimPrefix(authorization.Metadata.AuthorizationID, "sha256:")[:12]
	pod := verifierPod(bundle.Metadata.Name, name, image, authorization.Metadata.AuthorizationID, []string{"/usr/bin/python3", "-c", script, string(expected)}, true)
	return k.runVerifierPod(ctx, bundle.Metadata.Name, name, authorization.Metadata.AuthorizationID, pod)
}

func (k Kubernetes) verifyDeployments(ctx context.Context, namespace string, desired []changeset.DesiredObject) error {
	for _, object := range desired {
		if object.Reference.Kind != "Deployment" {
			continue
		}
		if _, err := k.run(ctx, nil, "rollout", "status", "deployment/"+object.Reference.Name, "-n", namespace, "--timeout=10m"); err != nil {
			return err
		}
	}
	return nil
}

func (k Kubernetes) verifyInferenceAndNetworkPolicy(ctx context.Context, bundle resources.DeploymentBundle, authorization resources.ExecutionAuthorization) error {
	_, image, err := verificationArtifacts(bundle)
	if err != nil {
		return err
	}
	gatewayIP, err := k.serviceIP(ctx, bundle.Metadata.Name, "gateway")
	if err != nil {
		return err
	}
	inferenceIP, err := k.serviceIP(ctx, bundle.Metadata.Name, "inference")
	if err != nil {
		return err
	}
	script := `import json,sys,urllib.request
gateway,inference=sys.argv[1],sys.argv[2]
urllib.request.urlopen('http://'+gateway+':4000/health/liveliness',timeout=10).read()
body=json.dumps({'model':'yara-default','messages':[{'role':'user','content':'Reply with OK'}],'max_tokens':8}).encode()
request=urllib.request.Request('http://'+gateway+':4000/v1/chat/completions',data=body,headers={'Content-Type':'application/json'})
response=json.loads(urllib.request.urlopen(request,timeout=60).read());assert response.get('choices')
try:
 urllib.request.urlopen('http://'+inference+':8000/health',timeout=3).read();raise SystemExit(21)
except Exception as error:
 if isinstance(error,SystemExit): raise
`
	name := "yara-postflight-" + strings.TrimPrefix(authorization.Metadata.AuthorizationID, "sha256:")[:12]
	pod := verifierPod(bundle.Metadata.Name, name, image, authorization.Metadata.AuthorizationID, []string{"/usr/bin/python3", "-c", script, gatewayIP, inferenceIP}, false)
	return k.runVerifierPod(ctx, bundle.Metadata.Name, name, authorization.Metadata.AuthorizationID, pod)
}

func verifierPod(namespace, name, image, authorizationID string, command []string, model bool) map[string]any {
	volumes := []any{map[string]any{"name": "tmp", "emptyDir": map[string]any{}}}
	mounts := []any{map[string]any{"name": "tmp", "mountPath": "/tmp"}}
	if model {
		volumes = append(volumes, map[string]any{"name": "model", "persistentVolumeClaim": map[string]any{"claimName": "yara-model", "readOnly": true}})
		mounts = append(mounts, map[string]any{"name": "model", "mountPath": "/models/model", "readOnly": true})
	}
	return map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name, "namespace": namespace, "labels": map[string]any{"app.kubernetes.io/managed-by": "yara", "yara.dev/role": "verifier"}, "annotations": map[string]any{"yara.dev/authorization-id": authorizationID}}, "spec": map[string]any{"restartPolicy": "Never", "automountServiceAccountToken": false, "securityContext": map[string]any{"seccompProfile": map[string]any{"type": "RuntimeDefault"}}, "containers": []any{map[string]any{"name": "verifier", "image": image, "imagePullPolicy": "IfNotPresent", "command": command, "securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []any{"ALL"}}}, "volumeMounts": mounts}}, "volumes": volumes}}
}

func (k Kubernetes) runVerifierPod(ctx context.Context, namespace, name, authorizationID string, pod map[string]any) error {
	data, _ := yaml.Marshal(pod)
	if _, err := k.run(ctx, data, "create", "-f", "-"); err != nil {
		return errors.New("temporary verifier Pod could not be created")
	}
	cleanup := func() error {
		observed, err := k.run(context.WithoutCancel(ctx), nil, "get", "pod", name, "-n", namespace, "-o", "json")
		if err != nil {
			return err
		}
		var identity struct {
			Metadata struct {
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
		}
		if json.Unmarshal(observed, &identity) != nil || identity.Metadata.Labels["app.kubernetes.io/managed-by"] != "yara" || identity.Metadata.Labels["yara.dev/role"] != "verifier" || identity.Metadata.Annotations["yara.dev/authorization-id"] != authorizationID {
			return errors.New("temporary verifier Pod ownership changed before cleanup")
		}
		_, err = k.run(context.WithoutCancel(ctx), nil, "delete", "pod", name, "-n", namespace, "--wait=true", "--timeout=30s")
		return err
	}
	if err := k.waitForVerifierPod(ctx, namespace, name); err != nil {
		_ = cleanup()
		return errors.New("temporary verifier Pod did not succeed")
	}
	if err := cleanup(); err != nil {
		return errors.New("temporary verifier Pod cleanup failed")
	}
	return nil
}

func (k Kubernetes) waitForVerifierPod(ctx context.Context, namespace, name string) error {
	waitCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		observed, err := k.run(waitCtx, nil, "get", "pod", name, "-n", namespace, "-o", "json")
		if err != nil {
			return err
		}
		var status struct {
			Status struct {
				Phase             string `json:"phase"`
				ContainerStatuses []struct {
					State struct {
						Waiting *struct {
							Reason string `json:"reason"`
						} `json:"waiting"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		}
		if json.Unmarshal(observed, &status) != nil {
			return errors.New("temporary verifier Pod status is invalid")
		}
		if status.Status.Phase == "Succeeded" {
			return nil
		}
		if status.Status.Phase == "Failed" || verifierHasTerminalWaitingReason(status.Status.ContainerStatuses) {
			return errors.New("temporary verifier Pod entered a terminal failure state")
		}

		select {
		case <-waitCtx.Done():
			return waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func verifierHasTerminalWaitingReason(statuses []struct {
	State struct {
		Waiting *struct {
			Reason string `json:"reason"`
		} `json:"waiting"`
	} `json:"state"`
}) bool {
	for _, status := range statuses {
		if status.State.Waiting == nil {
			continue
		}
		switch status.State.Waiting.Reason {
		case "ContainerCannotRun", "CreateContainerConfigError", "InvalidImageName":
			return true
		}
	}
	return false
}

func (k Kubernetes) serviceIP(ctx context.Context, namespace, name string) (string, error) {
	data, err := k.run(ctx, nil, "get", "service", name, "-n", namespace, "-o", "json")
	if err != nil {
		return "", err
	}
	var service struct {
		Spec struct {
			ClusterIP string `json:"clusterIP"`
		} `json:"spec"`
	}
	if json.Unmarshal(data, &service) != nil || service.Spec.ClusterIP == "" || service.Spec.ClusterIP == "None" {
		return "", errors.New("service ClusterIP is unavailable")
	}
	return service.Spec.ClusterIP, nil
}

func verificationArtifacts(bundle resources.DeploymentBundle) (resources.BundleArtifact, string, error) {
	var model resources.BundleArtifact
	image := ""
	for _, artifact := range bundle.Spec.Artifacts {
		if artifact.Type == "huggingface-snapshot" {
			model = artifact
		}
		if artifact.Type == "oci-image" && strings.Contains(artifact.Ref, "vllm") {
			image = artifact.Ref + "@" + artifact.Digest
		}
	}
	if model.Ref == "" || image == "" {
		return resources.BundleArtifact{}, "", errors.New("verification artifacts are incomplete")
	}
	return model, image, nil
}

func expectedImportedModelFiles(model resources.BundleArtifact, importReceipt resources.ArtifactImportReceipt) ([]resources.ImportedModelArtifactBinding, error) {
	var imported resources.ImportedModelArtifact
	for _, artifact := range importReceipt.Spec.ModelArtifacts {
		if artifact.Ref == model.Ref {
			imported = artifact
			break
		}
	}
	if imported.Ref == "" || imported.Revision != model.Revision || len(imported.Files) != len(model.Files) {
		return nil, errors.New("import receipt does not match expected model artifact")
	}
	expected := make([]resources.ImportedModelArtifactBinding, 0, len(model.Files))
	importedByPath := map[string]resources.ImportedModelArtifactBinding{}
	for _, file := range imported.Files {
		importedByPath[file.Path] = file
	}
	for _, file := range model.Files {
		binding, ok := importedByPath[file.Path]
		if !ok || binding.Digest != file.Digest || binding.SizeBytes != file.SizeBytes {
			return nil, errors.New("import receipt model file binding does not match expected artifact identity")
		}
		expected = append(expected, binding)
	}
	return expected, nil
}

func (k Kubernetes) applyObject(ctx context.Context, manifest []byte) error {
	_, err := k.run(ctx, manifest, "apply", "--server-side", "--field-manager=yara-executor", "-f", "-")
	return err
}

func (k Kubernetes) deleteObject(ctx context.Context, reference resources.KubernetesObjectReference) error {
	args := []string{"delete", reference.Kind, reference.Name}
	if reference.Namespace != "" {
		args = append(args, "-n", reference.Namespace)
	}
	args = append(args, "--wait=true", "--timeout=60s")
	_, err := k.run(ctx, nil, args...)
	return err
}

func (k Kubernetes) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	base := []string{}
	if k.Kubeconfig != "" {
		base = append(base, "--kubeconfig", k.Kubeconfig)
	}
	if k.Context != "" {
		base = append(base, "--context", k.Context)
	}
	return k.Runner.Run(ctx, k.Executable, stdin, append(base, args...)...)
}

func namespaceAction(changeSet resources.KubernetesChangeSet) string {
	for _, operation := range changeSet.Spec.Operations {
		if operation.Resource.Kind == "Namespace" {
			return operation.Action
		}
	}
	return ""
}

func applyPriority(kind string) int {
	switch kind {
	case "Namespace":
		return 0
	case "ConfigMap":
		return 10
	case "Service":
		return 20
	case "NetworkPolicy":
		return 30
	case "Deployment":
		return 40
	default:
		return 100
	}
}

func retirePriority(kind string) int {
	switch kind {
	case "Deployment":
		return 0
	case "NetworkPolicy":
		return 10
	case "Service":
		return 20
	case "ConfigMap":
		return 30
	default:
		return 100
	}
}
func objectKey(reference resources.KubernetesObjectReference) string {
	return strings.Join([]string{reference.APIVersion, reference.Kind, reference.Namespace, reference.Name}, "\x00")
}
func passedCheck(id string) resources.DeploymentPostflightCheck { return check(id, "passed", "") }
func failedCheck(id, code string) resources.DeploymentPostflightCheck {
	return check(id, "failed", code)
}
func blockedCheck(id, code string) resources.DeploymentPostflightCheck {
	return check(id, "blocked", code)
}
func check(id, status, code string) resources.DeploymentPostflightCheck {
	digest, _ := canonical.Digest(struct{ ID, Status string }{id, status})
	return resources.DeploymentPostflightCheck{ID: id, Status: status, EvidenceDigest: digest, DiagnosticCode: code}
}
