package httpapi

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"sigs.k8s.io/yaml"
)

type openAPIDocument struct {
	Security   []map[string][]string      `yaml:"security"`
	Paths      map[string]openAPIPathItem `yaml:"paths"`
	Components openAPIComponents          `yaml:"components"`
}

type openAPIPathItem struct {
	Post   *openAPIOperation `yaml:"post"`
	Delete *openAPIOperation `yaml:"delete"`
	Get    *openAPIOperation `yaml:"get"`
}

type openAPIOperation struct {
	Responses map[string]openAPIResponseReference `yaml:"responses"`
}

type openAPIResponseReference struct {
	Ref string `json:"$ref" yaml:"$ref"`
}

type openAPIComponents struct {
	SecuritySchemes map[string]openAPISecurityScheme `yaml:"securitySchemes"`
	Responses       map[string]openAPIResponse       `yaml:"responses"`
}

type openAPISecurityScheme struct {
	Type   string `yaml:"type"`
	Scheme string `yaml:"scheme"`
}

type openAPIResponse struct {
	Headers map[string]openAPIHeader    `yaml:"headers"`
	Content map[string]openAPIMediaType `yaml:"content"`
}

type openAPIHeader struct {
	Schema openAPISchema `yaml:"schema"`
}

type openAPISchema struct {
	Type string `yaml:"type"`
}

type openAPIMediaType struct {
	Examples map[string]openAPIExample `yaml:"examples"`
}

type openAPIExample struct {
	Value openAPIErrorEnvelope `yaml:"value"`
}

type openAPIErrorEnvelope struct {
	Error struct {
		Code    string `yaml:"code"`
		Message string `yaml:"message"`
	} `yaml:"error"`
}

func TestOpenAPIRequiresServiceBearerAuthentication(t *testing.T) {
	document := readOpenAPIDocument(t)

	if len(document.Security) != 1 || len(document.Security[0]) != 1 {
		t.Fatalf("root security = %#v, want [{ServiceBearerAuth: []}]", document.Security)
	}
	if scopes, ok := document.Security[0]["ServiceBearerAuth"]; !ok || len(scopes) != 0 {
		t.Fatalf("root security = %#v, want [{ServiceBearerAuth: []}]", document.Security)
	}

	scheme, ok := document.Components.SecuritySchemes["ServiceBearerAuth"]
	if !ok || scheme.Type != "http" || scheme.Scheme != "bearer" {
		t.Fatalf("ServiceBearerAuth = %#v, want HTTP bearer scheme", scheme)
	}

	unauthenticated, ok := document.Components.Responses["Unauthenticated"]
	if !ok {
		t.Fatal("components.responses.Unauthenticated is missing")
	}
	if _, ok := unauthenticated.Headers["WWW-Authenticate"]; !ok {
		t.Fatal("Unauthenticated response has no WWW-Authenticate header")
	}
	example, ok := unauthenticated.Content["application/json"].Examples["Unauthenticated"]
	if !ok || example.Value.Error.Code != "UNAUTHENTICATED" || example.Value.Error.Message != "service authentication failed" {
		t.Fatalf("Unauthenticated response example = %#v, want UNAUTHENTICATED error envelope", example)
	}

	for _, testCase := range []struct {
		name      string
		operation *openAPIOperation
	}{
		{name: "create", operation: document.Paths["/internal/v1/instances"].Post},
		{name: "delete", operation: document.Paths["/internal/v1/instances/{instance_id}"].Delete},
		{name: "operation", operation: document.Paths["/internal/v1/operations/{operation_id}"].Get},
		{name: "runtime status", operation: document.Paths["/internal/v1/instances/{instance_id}/runtime-status"].Get},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.operation == nil {
				t.Fatal("operation is missing")
			}
			if response := testCase.operation.Responses["401"]; response.Ref != "#/components/responses/Unauthenticated" {
				t.Fatalf("401 response = %#v, want reusable Unauthenticated response", response)
			}
		})
	}
}

func readOpenAPIDocument(t *testing.T) openAPIDocument {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("find OpenAPI test file")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(testFile), "..", "..", "docs", "api", "secure-provisioner.openapi.yaml"))
	if err != nil {
		t.Fatalf("read OpenAPI document: %v", err)
	}
	var document openAPIDocument
	if err := yaml.Unmarshal(contents, &document); err != nil {
		t.Fatalf("decode OpenAPI document: %v", err)
	}
	return document
}
