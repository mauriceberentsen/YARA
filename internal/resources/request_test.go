package resources

import "testing"

func TestPlatformRequestValidationReportsStablePaths(t *testing.T) {
	request := validRequest()
	request.Spec.Workload.PeakConcurrentRequests = request.Spec.Workload.ExpectedUsers + 1
	request.Spec.Objectives.Weights.Quality = 0.5

	report := request.Validate()
	if report.Valid {
		t.Fatal("expected request to be invalid")
	}
	assertDiagnostic(t, report, "YARA-REQ-021", "spec.workload.peakConcurrentRequests")
	assertDiagnostic(t, report, "YARA-REQ-051", "spec.objectives.weights")
}

func TestPlatformRequestRejectsUnsupportedUseCase(t *testing.T) {
	request := validRequest()
	request.Spec.UseCases = append(request.Spec.UseCases, UseCase{ID: "image", Required: true})

	report := request.Validate()
	assertDiagnostic(t, report, "YARA-REQ-011", "spec.useCases[2].id")
}

func validRequest() PlatformRequest {
	openSourceOnly := true
	return PlatformRequest{
		APIVersion: APIVersion,
		Kind:       "PlatformRequest",
		Metadata:   Metadata{Name: "test-request"},
		Spec: PlatformRequestSpec{
			UseCases:    []UseCase{{ID: "chat", Required: true}, {ID: "coding", Required: true}},
			Workload:    Workload{ExpectedUsers: 10, PeakConcurrentRequests: 2, MaximumContextTokens: 8192},
			Environment: RequestEnvironment{Connectivity: "air-gapped", InventoryRef: "test-inventory", Lifecycle: "evaluation"},
			Policies:    RequestPolicies{OpenSourceOnly: &openSourceOnly, ExternalEgress: "forbidden", Telemetry: "forbidden", ArtifactVerification: "required"},
			Objectives: Objectives{
				Preset:  "balanced",
				Weights: ObjectiveWeights{Quality: 0.3, Latency: 0.1, Throughput: 0.1, Cost: 0.05, Simplicity: 0.3, Energy: 0.05, EvidenceConfidence: 0.1},
			},
		},
	}
}
