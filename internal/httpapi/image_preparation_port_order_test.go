package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
)

// Persistence and Kubernetes are external to the HTTP/policy regression. Keep
// the actual preparation service, normalization and catalog validation in use.
type portOrderStore struct{ imageprep.Store }

func (portOrderStore) Find(context.Context, string, string, string) (imageprep.Record, bool, error) {
	return imageprep.Record{}, false, nil
}
func (portOrderStore) Insert(_ context.Context, record imageprep.Record) (imageprep.Record, error) {
	return record, nil
}

type portOrderInventory struct{}

func (portOrderInventory) Known(target string) bool { return target == "aws-dev" }
func (portOrderInventory) Enabled(target, arch string) bool {
	return target == "aws-dev" && arch == "AMD64"
}
func (portOrderInventory) Nodes(context.Context, string, string) ([]imageprep.Node, error) {
	return []imageprep.Node{{TargetID: "aws-dev", UID: "node-uid", Name: "node-a", BootID: "boot-a", Architecture: "AMD64", MachineID: "machine-a"}}, nil
}

func TestCreateAndPreparationHandlersAcceptApprovedPortSetInEitherOrder(t *testing.T) {
	policy := strings.Replace(testImagePolicies, `"ports": [8080]`, `"ports": [8081,8080]`, 1)
	for _, tc := range []struct {
		name            string
		ports           []int
		container       string
		profile         string
		image           string
		createStatus    int
		preparationCode int
	}{
		{"policy order", []int{8081, 8080}, "web", "WEB", gradePolicyImage, 201, 202},
		{"reverse order", []int{8080, 8081}, "web", "WEB", gradePolicyImage, 201, 202},
		{"missing port", []int{8080}, "web", "WEB", gradePolicyImage, 422, 422},
		{"extra port", []int{8080, 8081, 8082}, "web", "WEB", gradePolicyImage, 422, 422},
		{"different port", []int{8080, 8082}, "web", "WEB", gradePolicyImage, 422, 422},
		{"duplicate port", []int{8080, 8080}, "web", "WEB", gradePolicyImage, 422, 400},
		{"wrong container", []int{8080, 8081}, "other", "WEB", gradePolicyImage, 422, 422},
		{"wrong profile", []int{8080, 8081}, "web", "PWN", gradePolicyImage, 422, 422},
		{"unapproved digest", []int{8080, 8081}, "web", "WEB", strings.Replace(gradePolicyImage, "9ffbf", "affbf", 1), 422, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog, err := ParseImagePolicies([]byte(policy))
			if err != nil {
				t.Fatal(err)
			}
			useCase := &recordingCreateUseCase{}
			create := withTestServiceAuthentication(NewHandlerWithRuntimePolicies(useCase, nil, ServiceAuthConfig{CurrentToken: testCurrentServiceToken}, catalog))
			request := validCreateWorkloadRequest()
			request.IsolationProfile = tc.profile
			request.Workload.Containers = []RuntimeContainer{{Name: tc.container, Image: tc.image, Ports: slices.Clone(tc.ports)}}
			encoded, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			call := func(handler http.Handler, path, token string, body []byte) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", "Bearer "+token)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, r)
				return response
			}
			response := call(create, "/internal/v1/instances", testCurrentServiceToken, encoded)
			if response.Code != tc.createStatus {
				t.Errorf("create status=%d want=%d body=%s", response.Code, tc.createStatus, response.Body)
			}
			if response.Code == 201 && !slices.Equal(useCase.command.Containers[0].Ports, tc.ports) {
				t.Error("policy comparison changed the caller's create port order")
			}
			service := imageprep.NewService(portOrderStore{}, portOrderInventory{}, catalog, nil, imageprep.Config{})
			prepare := WithImagePreparations(http.NotFoundHandler(), service, PreparationAuth{Enabled: true, ManagerToken: "manager-test-only"})
			input := imageprep.Request{RequestID: "port-order-test", Architecture: "AMD64", IsolationProfile: tc.profile, Containers: []imageprep.Container{{Name: tc.container, Image: tc.image, Ports: slices.Clone(tc.ports)}}, TargetIDs: []string{"aws-dev"}}
			encoded, err = json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			response = call(prepare, "/v1/image-preparations", "manager-test-only", encoded)
			if response.Code != tc.preparationCode {
				t.Errorf("preparation status=%d want=%d body=%s", response.Code, tc.preparationCode, response.Body)
			}
			if !slices.Equal(catalog.images[gradePolicyImage].Ports, []int{8081, 8080}) {
				t.Error("policy comparison mutated the configured catalog")
			}
		})
	}
}
