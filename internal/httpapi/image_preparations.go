package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	"io"
	"mime"
	"net/http"
	"strings"
)

type PreparationService interface {
	Create(context.Context, string, imageprep.Request) (imageprep.Operation, error)
	Get(context.Context, string, string) (imageprep.Operation, error)
	Retry(context.Context, string, string, imageprep.Retry) (imageprep.Operation, error)
	Query(context.Context, imageprep.Query) (imageprep.Readiness, error)
}
type PreparationAuth struct {
	Enabled        bool
	ManagerToken   string
	ReadinessToken string
	Existing       ServiceAuthConfig
}

func constantToken(a, b string) bool {
	x, y := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return b != "" && subtle.ConstantTimeCompare(x[:], y[:]) == 1
}
func WithImagePreparations(next http.Handler, service PreparationService, auth PreparationAuth) http.Handler {
	mux := http.NewServeMux()
	accepted := func(w http.ResponseWriter, op imageprep.Operation, err error) {
		if err != nil {
			preparationError(w, err)
			return
		}
		w.Header().Set("Location", "/v1/image-preparations/"+op.ID)
		writeJSON(w, 202, struct {
			ID     string `json:"operation_id"`
			Parent string `json:"parent_operation_id,omitempty"`
			Set    string `json:"image_set_id"`
			Status string `json:"status"`
		}{op.ID, op.ParentID, op.ImageSetID, op.Status})
	}
	mux.HandleFunc("POST /v1/image-preparations", func(w http.ResponseWriter, r *http.Request) {
		var input imageprep.Request
		if preparationJSON(r, &input) != nil || input.Normalize() != nil {
			preparationError(w, imageprep.ErrInvalid)
			return
		}
		op, err := service.Create(r.Context(), "preparation-manager", input)
		accepted(w, op, err)
	})
	mux.HandleFunc("GET /v1/image-preparations/{operation_id}", func(w http.ResponseWriter, r *http.Request) {
		op, err := service.Get(r.Context(), "preparation-manager", r.PathValue("operation_id"))
		if err != nil {
			preparationError(w, err)
			return
		}
		writeJSON(w, 200, op)
	})
	mux.HandleFunc("POST /v1/image-preparations/{operation_id}/retry", func(w http.ResponseWriter, r *http.Request) {
		var input imageprep.Retry
		if preparationJSON(r, &input) != nil {
			preparationError(w, imageprep.ErrInvalid)
			return
		}
		op, err := service.Retry(r.Context(), "preparation-manager", r.PathValue("operation_id"), input)
		accepted(w, op, err)
	})
	mux.HandleFunc("POST /v1/image-readiness/query", func(w http.ResponseWriter, r *http.Request) {
		var input imageprep.Query
		if preparationJSON(r, &input) != nil || input.Validate() != nil {
			preparationError(w, imageprep.ErrInvalid)
			return
		}
		result, err := service.Query(r.Context(), input)
		if err != nil {
			preparationError(w, err)
			return
		}
		writeJSON(w, 200, result)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/image-readiness/query" && r.URL.Path != "/v1/image-preparations" && !strings.HasPrefix(r.URL.Path, "/v1/image-preparations/") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		ok = ok && len(r.Header.Values("Authorization")) == 1
		manager := ok && constantToken(token, auth.ManagerToken)
		reader := ok && constantToken(token, auth.ReadinessToken)
		existing := ok && (constantToken(token, auth.Existing.CurrentToken) || constantToken(token, auth.Existing.PreviousToken) || constantToken(token, auth.Existing.CISmokeToken))
		if !manager && !reader && !existing {
			writeAPIError(w, 401, "UNAUTHENTICATED", "service authentication required")
			return
		}
		if !manager && (!reader || r.URL.Path != "/v1/image-readiness/query") {
			writeAPIError(w, 403, "FORBIDDEN", "credential lacks image preparation permission")
			return
		}
		if !auth.Enabled || service == nil {
			writeAPIError(w, 503, "IMAGE_PREPARATION_UNAVAILABLE", "image preparation is disabled")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		mux.ServeHTTP(w, r)
	})
}
func preparationJSON(r *http.Request, destination any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return imageprep.ErrInvalid
	}
	b, err := io.ReadAll(r.Body)
	if err != nil || rejectDuplicateJSONKeys(b) != nil {
		return imageprep.ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || fields == nil {
		return imageprep.ErrInvalid
	}
	for _, v := range fields {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return imageprep.ErrInvalid
		}
	}
	if raw, exists := fields["release_id"]; exists {
		var value string
		if json.Unmarshal(raw, &value) != nil || value == "" {
			return imageprep.ErrInvalid
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(destination); err != nil {
		return imageprep.ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return imageprep.ErrInvalid
	}
	return nil
}
func preparationError(w http.ResponseWriter, err error) {
	status, code := 503, "IMAGE_PREPARATION_UNAVAILABLE"
	switch {
	case errors.Is(err, imageprep.ErrInvalid):
		status, code = 400, "INVALID_REQUEST"
	case errors.Is(err, imageprep.ErrConflict):
		status, code = 409, "REQUEST_ID_CONFLICT"
	case errors.Is(err, imageprep.ErrPolicy):
		status, code = 422, "POLICY_REJECTED"
	case errors.Is(err, imageprep.ErrNotFound):
		status, code = 404, "NOT_FOUND"
	}
	writeAPIError(w, status, code, "image preparation request could not be completed")
}
func (c *ImagePolicyCatalog) Approved(image string) bool {
	if c == nil {
		return false
	}
	p, ok := c.images[image]
	return ok && p.Status == "create_enabled" && !c.RequiresVMImage(image)
}

func (c *ImagePolicyCatalog) Revision() string {
	if c == nil {
		return ""
	}
	return c.revision
}
func (c *ImagePolicyCatalog) Validate(r imageprep.Request) error {
	if c == nil {
		return imageprep.ErrPolicy
	}
	request := CreateWorkloadRequest{IsolationProfile: r.IsolationProfile}
	for _, container := range r.Containers {
		if !c.Approved(container.Image) {
			return imageprep.ErrPolicy
		}
		request.Workload.Containers = append(request.Workload.Containers, RuntimeContainer{Name: container.Name, Image: container.Image, Ports: container.Ports})
	}
	if c.Apply(&request) != nil {
		return imageprep.ErrPolicy
	}
	return nil
}
