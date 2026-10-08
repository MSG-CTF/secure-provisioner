package httpapi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestExecutionSettingsSurviveAdmissionAndCommandCopy(t *testing.T) {
	reference := "152839e6-6c28-4ad7-b109-378df7d0092c"
	body := strings.Replace(validCreateRequestJSON(), `"name":"web",`, `"name":"web","env":{"APP_MODE":"ctf","LITERAL":"$(APP_MODE)"},"secret_ref":"`+reference+`",`, 1)
	var request CreateWorkloadRequest
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatal(err)
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	command := request.ToCommand()
	expected := map[string]string{"APP_MODE": "ctf", "LITERAL": "$(APP_MODE)"}
	if !reflect.DeepEqual(command.Containers[0].Env, expected) || command.Containers[0].SecretRef != reference {
		t.Fatal("execution settings were dropped during admission")
	}
	request.Workload.Containers[0].Env["APP_MODE"] = "mutated"
	if command.Containers[0].Env["APP_MODE"] != "ctf" {
		t.Fatal("command aliases request env")
	}
}

func TestExecutionSettingsRejectInvalidTypesReferencesAndPlainSecrets(t *testing.T) {
	for _, fields := range []string{
		`"env":null,`, `"env":{"APP_MODE":null},`, `"env":{"APP_MODE":1},`,
		`"env":{"FLAG":"private-fixture"},`, `"env":{"APP_MODE":"\u0000"},`,
		`"secret_ref":null,`, `"secret_ref":"",`,
		`"secret_ref":"00000000-0000-0000-0000-000000000000",`,
		`"secret_ref":"152839E6-6c28-4ad7-b109-378df7d0092c",`,
		`"requires_flag":false,`,
	} {
		body := strings.Replace(validCreateRequestJSON(), `"name":"web",`, `"name":"web",`+fields, 1)
		var request CreateWorkloadRequest
		err := json.Unmarshal([]byte(body), &request)
		if err == nil {
			err = request.Validate()
		}
		if err == nil || strings.Contains(err.Error(), "private-fixture") {
			t.Fatal("invalid execution settings were accepted or echoed")
		}
	}
}
