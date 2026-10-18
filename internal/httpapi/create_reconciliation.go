package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime"
	"net/http"

	"github.com/MSG-CTF/secure-provisioner/internal/operations"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func (api *API) handleReconcileCreate(writer http.ResponseWriter, request *http.Request) {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
		return
	}
	var input CreateWorkloadRequest
	if err := decodeJSON(request, &input); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON request body")
		return
	}
	if input.InstanceID != request.PathValue("instance_id") {
		writeAPIError(writer, http.StatusConflict, "INSTANCE_BINDING_MISMATCH", "request does not match the instance")
		return
	}
	if isCISmokeRequest(request) && !api.allowsCISmokeCreate(input) {
		writeAPIError(writer, http.StatusForbidden, "FORBIDDEN", "CI smoke token cannot reconcile this workload")
		return
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}
	hash := sha256.Sum256(encoded)
	if err := input.Validate(); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	reconciler, ok := api.runtime.(interface {
		ReconcileCreate(provisioner.CreateWorkloadCommand) (operations.Operation, bool, error)
	})
	if !ok {
		writeAPIError(writer, http.StatusNotImplemented, "RECONCILIATION_UNAVAILABLE", "create reconciliation is unavailable")
		return
	}
	command := input.ToCommand()
	command.RequestFingerprint = hex.EncodeToString(hash[:])
	operation, created, err := reconciler.ReconcileCreate(command)
	if err != nil {
		if errors.Is(err, operations.ErrIdempotencyConflict) {
			writeAPIError(writer, http.StatusConflict, "REQUEST_ID_CONFLICT", "request_id is already used by another operation")
		} else {
			writeAPIError(writer, http.StatusBadGateway, "CREATE_RECONCILIATION_FAILED", "create acceptance could not be reconciled")
		}
		return
	}
	writeAcceptedOperation(writer, operation, created)
}
