package provisioner

import (
	"reflect"
	"testing"
)

func TestDomainEnumsUseNamedTypes(t *testing.T) {
	var runtimeType RuntimeType = RuntimeTypeKubernetes
	var reason DeleteReason = DeleteReasonUserRequested
	if runtimeType != "KUBERNETES" || reason != "USER_REQUESTED" {
		t.Fatalf("runtimeType = %q, reason = %q", runtimeType, reason)
	}
}

func TestDomainModelsDoNotExposeJSONContract(t *testing.T) {
	for _, model := range []any{
		CreateWorkloadCommand{},
		CreateWorkloadResult{},
		DeleteWorkloadCommand{},
	} {
		modelType := reflect.TypeOf(model)
		for index := 0; index < modelType.NumField(); index++ {
			field := modelType.Field(index)
			if tag := field.Tag.Get("json"); tag != "" {
				// Storage-only omission preserves old durable-command fingerprints;
				// the HTTP DTO still owns the public snake_case field name.
				if field.Name == "SteadyCPUMillicores" && tag == ",omitempty" {
					continue
				}
				t.Fatalf("%s.%s JSON tag = %q, want none", modelType.Name(), field.Name, tag)
			}
		}
	}
}
