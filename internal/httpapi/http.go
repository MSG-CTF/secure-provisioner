package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/MSG-CTF/secure-provisioner/internal/isolation"
	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

type API struct {
	vmPolicy        func(*CreateWorkloadRequest) error
	createWorkload  provisioner.CreateWorkloadUseCase
	runtime         RuntimeUseCase
	directResolver  isolation.Resolver
	imagePolicies   *ImagePolicyCatalog
	ciSmokeTeamID   provisioner.TeamID
	ciSmokeTargetID string
}

func NewHandler(createWorkload provisioner.CreateWorkloadUseCase, authConfig ServiceAuthConfig) http.Handler {
	return newHandler(createWorkload, nil, authConfig, nil, nil)
}

func NewHandlerWithRuntime(createWorkload provisioner.CreateWorkloadUseCase, runtime RuntimeUseCase, authConfig ServiceAuthConfig) http.Handler {
	return newHandler(createWorkload, runtime, authConfig, nil, nil)
}

func NewHandlerWithRuntimePolicies(createWorkload provisioner.CreateWorkloadUseCase, runtime RuntimeUseCase, authConfig ServiceAuthConfig, policies *ImagePolicyCatalog) http.Handler {
	return newHandler(createWorkload, runtime, authConfig, policies, nil)
}

func NewHandlerWithRuntimeReadiness(createWorkload provisioner.CreateWorkloadUseCase, runtime RuntimeUseCase, authConfig ServiceAuthConfig, policies *ImagePolicyCatalog, readiness ReadinessConfig) http.Handler {
	return newHandler(createWorkload, runtime, authConfig, policies, &readiness)
}

func NewHandlerWithVM(createWorkload provisioner.CreateWorkloadUseCase, runtime RuntimeUseCase, authConfig ServiceAuthConfig, policies *ImagePolicyCatalog, readiness ReadinessConfig, vmPolicy func(*CreateWorkloadRequest) error) http.Handler {
	return newHandler(createWorkload, runtime, authConfig, policies, &readiness, vmPolicy)
}

func newHandler(createWorkload provisioner.CreateWorkloadUseCase, runtime RuntimeUseCase, authConfig ServiceAuthConfig, policies *ImagePolicyCatalog, readiness *ReadinessConfig, vmPolicies ...func(*CreateWorkloadRequest) error) http.Handler {
	api := &API{createWorkload: createWorkload, runtime: runtime, imagePolicies: policies, ciSmokeTeamID: authConfig.CISmokeTeamID, ciSmokeTargetID: authConfig.CISmokeTargetID}
	if runtime == nil {
		api.directResolver = isolation.NewStaticResolver()
	}
	if len(vmPolicies) > 0 {
		api.vmPolicy = vmPolicies[0]
	}
	mux := http.NewServeMux()
	if readiness != nil {
		mux.HandleFunc("GET /internal/v1/healthz", readiness.handle)
	}
	mux.HandleFunc("POST /internal/v1/instances", api.handleCreateInstance)
	if runtime != nil {
		mux.HandleFunc("GET /internal/v1/instances/{instance_id}/runtime-status", api.handleRuntimeStatus)
		mux.HandleFunc("DELETE /internal/v1/instances/{instance_id}", api.handleDeleteInstance)
		mux.HandleFunc("GET /internal/v1/operations/{operation_id}", api.handleGetOperation)
		mux.HandleFunc("POST /internal/v1/instances/{instance_id}/reconcile_create", api.handleReconcileCreate)
	}
	return newServiceAuthenticator(authConfig).wrap(requestSizeLimit(mux))
}

func (api *API) handleCreateInstance(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
		return
	}

	var createRequest CreateWorkloadRequest
	if err := decodeJSON(request, &createRequest); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON request body")
		return
	}
	if isCISmokeRequest(request) && !api.allowsCISmokeCreate(createRequest) {
		writeAPIError(writer, http.StatusForbidden, "FORBIDDEN", "CI smoke token cannot create this workload")
		return
	}
	encodedInput, err := json.Marshal(createRequest)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}
	inputHash := sha256.Sum256(encodedInput)
	fingerprint := hex.EncodeToString(inputHash[:])
	if replay, ok := api.runtime.(interface {
		FindCreateByRequest(string, string) (operations.Operation, bool, error)
	}); ok {
		operation, found, err := replay.FindCreateByRequest(createRequest.RequestID, fingerprint)
		if err != nil {
			if errors.Is(err, operations.ErrIdempotencyConflict) {
				writeAPIError(writer, http.StatusConflict, "REQUEST_ID_CONFLICT", "request_id is already used by another operation")
			} else {
				writeAPIError(writer, http.StatusBadGateway, "CREATE_QUEUE_FAILED", "workload creation could not be queued")
			}
			return
		}
		if found {
			writeAcceptedOperation(writer, operation, false)
			return
		}
	}
	if api.vmPolicy != nil {
		if err := api.vmPolicy(&createRequest); err != nil {
			writeAPIError(writer, http.StatusUnprocessableEntity, "VM_POLICY_REJECTED", "dedicated VM policy rejected the workload")
			return
		}
	} else if createRequest.Target.RuntimeType == RuntimeTypeVM {
		writeAPIError(writer, http.StatusUnprocessableEntity, "VM_POLICY_REJECTED", "dedicated VM targets are not configured")
		return
	}
	var policyErr error
	if createRequest.Target.RuntimeType != RuntimeTypeVM {
		policyErr = api.imagePolicies.Apply(&createRequest)
	}
	if err := policyErr; err != nil {
		writeAPIError(writer, http.StatusUnprocessableEntity, "IMAGE_POLICY_REJECTED", err.Error())
		return
	}
	if err := createRequest.Validate(); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}

	if api.runtime != nil {
		command := createRequest.ToCommand()
		command.RequestFingerprint = fingerprint
		operation, created, err := api.runtime.EnqueueCreate(command)
		if err != nil {
			if code, _ := operations.ClassifyExecutionError(err); code == "GATEWAY_SINGLE_ENDPOINT_REQUIRED" {
				writeAPIError(writer, http.StatusUnprocessableEntity, code, "Gateway v1 requires exactly one public endpoint")
				return
			}
			if errors.Is(err, isolation.ErrPolicyRejected) {
				writeAPIError(writer, http.StatusUnprocessableEntity, "ISOLATION_POLICY_REJECTED", "isolation policy was rejected")
				return
			}
			if errors.Is(err, operations.ErrIdempotencyConflict) {
				writeAPIError(writer, http.StatusConflict, "REQUEST_ID_CONFLICT", "request_id is already used by another operation")
				return
			}
			writeAPIError(writer, http.StatusBadGateway, "CREATE_QUEUE_FAILED", "workload creation could not be queued")
			return
		}
		writeAcceptedOperation(writer, operation, created)
		return
	}

	command := createRequest.ToCommand()
	policy, err := api.directResolver.Resolve(command.PolicyRequest)
	if err != nil {
		if errors.Is(err, isolation.ErrPolicyRejected) {
			writeAPIError(writer, http.StatusUnprocessableEntity, "ISOLATION_POLICY_REJECTED", "isolation policy was rejected")
			return
		}
		writeAPIError(writer, http.StatusBadGateway, "PROVISIONING_FAILED", "workload creation failed")
		return
	}
	command.Policy = policy
	command.ResourceLimits = provisioner.ResourceLimits{
		CPUMillicores:       policy.ResourceLimits.CPUMillicores,
		MemoryMiB:           policy.ResourceLimits.MemoryMiB,
		EphemeralStorageMiB: policy.ResourceLimits.EphemeralStorageMiB,
	}
	result, err := api.createWorkload.CreateWorkload(request.Context(), command)
	if err != nil {
		if errors.Is(err, isolation.ErrPolicyRejected) {
			writeAPIError(writer, http.StatusUnprocessableEntity, "ISOLATION_POLICY_REJECTED", "isolation policy was rejected")
			return
		}
		if errors.Is(err, provisioner.ErrRuntimeUnavailable) {
			writeAPIError(writer, http.StatusServiceUnavailable, "RUNTIME_UNAVAILABLE", "runtime adapter is unavailable")
			return
		}
		writeAPIError(writer, http.StatusBadGateway, "PROVISIONING_FAILED", "workload creation failed")
		return
	}

	writeJSON(writer, http.StatusCreated, NewCreateWorkloadResponse(result))
}

func decodeJSON(request *http.Request, destination any) error {
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func writeAPIError(writer http.ResponseWriter, status int, code string, message string) {
	writeJSON(writer, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func requestSizeLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
		next.ServeHTTP(writer, request)
	})
}
