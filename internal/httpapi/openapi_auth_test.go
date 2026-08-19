package httpapi

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"sigs.k8s.io/yaml"
)

type authOpenAPIDocument struct {
	Security []map[string][]string `yaml:"security"`
	Paths    map[string]struct {
		Post   *authOpenAPIOperation `yaml:"post"`
		Delete *authOpenAPIOperation `yaml:"delete"`
		Get    *authOpenAPIOperation `yaml:"get"`
	} `yaml:"paths"`
	Components struct {
		SecuritySchemes map[string]struct {
			Type   string `yaml:"type"`
			Scheme string `yaml:"scheme"`
		} `yaml:"securitySchemes"`
		Responses map[string]struct {
			Headers map[string]struct {
				Example string `yaml:"example"`
			} `yaml:"headers"`
		} `yaml:"responses"`
	} `yaml:"components"`
}

type authOpenAPIOperation struct {
	Responses map[string]struct {
		Ref string `json:"$ref" yaml:"$ref"`
	} `yaml:"responses"`
}

func TestOpenAPIRequiresServiceBearerAuthentication(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("find test file")
	}
	contents, err := os.ReadFile(filepath.Join(filepath.Dir(testFile), "..", "..", "docs", "api", "secure-provisioner.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document authOpenAPIDocument
	if err := yaml.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Security) != 1 || len(document.Security[0]["ServiceBearerAuth"]) != 0 {
		t.Fatalf("root security = %#v", document.Security)
	}
	scheme, ok := document.Components.SecuritySchemes["ServiceBearerAuth"]
	if !ok || scheme.Type != "http" || scheme.Scheme != "bearer" {
		t.Fatalf("scheme = %#v", scheme)
	}
	response, ok := document.Components.Responses["Unauthenticated"]
	if !ok || response.Headers["WWW-Authenticate"].Example != `Bearer realm="secure-provisioner"` {
		t.Fatalf("Unauthenticated = %#v", response)
	}
	for name, operation := range map[string]*authOpenAPIOperation{
		"create":         document.Paths["/internal/v1/instances"].Post,
		"delete":         document.Paths["/internal/v1/instances/{instance_id}"].Delete,
		"operation":      document.Paths["/internal/v1/operations/{operation_id}"].Get,
		"runtime_status": document.Paths["/internal/v1/instances/{instance_id}/runtime-status"].Get,
	} {
		if operation == nil || operation.Responses["401"].Ref != "#/components/responses/Unauthenticated" {
			t.Fatalf("%s 401 response missing", name)
		}
	}
}
