package httpapi

import (
	"context"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type preparationAPIStub struct{ request imageprep.Request }

func (s *preparationAPIStub) Create(_ context.Context, _ string, r imageprep.Request) (imageprep.Operation, error) {
	s.request = r
	return imageprep.Operation{ID: "op", RequestID: r.RequestID, ImageSetID: imageprep.ImageSetID(r.Architecture, r.Images()), Architecture: r.Architecture, Status: "QUEUED", Nodes: []imageprep.NodeResult{}}, nil
}
func (s *preparationAPIStub) Get(context.Context, string, string) (imageprep.Operation, error) {
	return imageprep.Operation{}, imageprep.ErrNotFound
}
func (s *preparationAPIStub) Retry(context.Context, string, string, imageprep.Retry) (imageprep.Operation, error) {
	return imageprep.Operation{}, imageprep.ErrConflict
}
func (s *preparationAPIStub) Query(context.Context, imageprep.Query) (imageprep.Readiness, error) {
	return imageprep.Readiness{}, nil
}
func TestPreparationDedicatedAuthorizationAndStrictJSON(t *testing.T) {
	stub := &preparationAPIStub{}
	h := WithImagePreparations(http.NotFoundHandler(), stub, PreparationAuth{Enabled: true, ManagerToken: "manager-secret", ReadinessToken: "readiness-secret", Existing: ServiceAuthConfig{CurrentToken: "full-secret", CISmokeToken: "ci-secret"}})
	body := `{"request_id":"req","release_id":"11111111-1111-4111-8111-111111111111","architecture":"AMD64","isolation_profile":"WEB","containers":[{"name":"web","image":"ghcr.io/msg-ctf/challenges/test/web@sha256:` + strings.Repeat("a", 64) + `","ports":[80]}],"target_ids":["target-a"]}`
	for _, tc := range []struct {
		token, body string
		status      int
	}{{"", body, 401}, {"full-secret", body, 403}, {"ci-secret", body, 403}, {"readiness-secret", body, 403}, {"manager-secret", body, 202}, {"manager-secret", strings.Replace(body, `"architecture":"AMD64"`, `"architecture":"AMD64","secret":"TOPSECRET"`, 1), 400}, {"manager-secret", strings.Replace(body, `"release_id":"11111111-1111-4111-8111-111111111111"`, `"release_id":null`, 1), 400}, {"manager-secret", strings.Replace(body, `"request_id":"req"`, `"request_id":"req","request_id":"other"`, 1), 400}} {
		r := httptest.NewRequest("POST", "/v1/image-preparations", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("token=%q status=%d body=%s", tc.token, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "TOPSECRET") {
			t.Fatal("secret echoed")
		}
	}
	for _, token := range []string{"manager-secret", "readiness-secret"} {
		r := httptest.NewRequest("POST", "/v1/image-readiness/query", strings.NewReader(`{"architecture":"AMD64","images":["ghcr.io/msg-ctf/challenges/test/web@sha256:`+strings.Repeat("a", 64)+`"],"target_ids":["target-a"]}`))
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("query=%d %s", w.Code, w.Body)
		}
	}
}
func TestPreparationPolicyFailsClosedAndValidatesWholeGraph(t *testing.T) {
	var catalog *ImagePolicyCatalog
	if catalog.Approved("any") {
		t.Fatal("nil policy approved")
	}
	if catalog.Validate(imageprep.Request{}) == nil {
		t.Fatal("nil policy validated")
	}
}

func TestPreparationRejectsEmptyReleaseAndDuplicateAuthorization(t *testing.T) {
	stub := &preparationAPIStub{}
	h := WithImagePreparations(http.NotFoundHandler(), stub, PreparationAuth{Enabled: true, ManagerToken: "manager"})
	request := `{"request_id":"req","release_id":"","architecture":"AMD64","isolation_profile":"WEB","containers":[{"name":"web","image":"ghcr.io/msg-ctf/challenges/test/web@sha256:` + strings.Repeat("a", 64) + `","ports":[80]}],"target_ids":["target-a"]}`
	r := httptest.NewRequest("POST", "/v1/image-preparations", strings.NewReader(request))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer manager")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Errorf("empty release accepted: %d", w.Code)
	}
	r = httptest.NewRequest("GET", "/v1/image-preparations/id", nil)
	r.Header.Add("Authorization", "Bearer manager")
	r.Header.Add("Authorization", "Bearer other")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("duplicate auth accepted: %d", w.Code)
	}
}
