package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

const draftTeamID = "00000000-0000-4000-8000-000000000002"

func TestDraftContractPreservesWireFieldsAndRequiresOwnerAcknowledgement(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		alter      func(map[string]any)
		valid      bool
	}{
		{"plain", "plain", nil, true},
		{"tls", "tls", nil, true},
		{"missing owner", "plain", func(r map[string]any) { delete(r, "owner_team_id") }, false},
		{"foreign owner", "plain", func(r map[string]any) { r["owner_team_id"] = "00000000-0000-4000-8000-000000000003" }, false},
		{"missing mode", "plain", func(r map[string]any) { delete(r, "public_transport") }, false},
		{"wrong mode", "plain", func(r map[string]any) { r["public_transport"] = "tls" }, false},
		{"wrong TLS", "plain", func(r map[string]any) { r["tls"] = true }, false},
		{"TLS downgrade", "tls", func(r map[string]any) { r["tls"] = false }, false},
		{"missing enforcement", "plain", func(r map[string]any) { delete(r, "owner_access_enforced") }, false},
		{"null enforcement", "plain", func(r map[string]any) { r["owner_access_enforced"] = nil }, false},
		{"unprotected route", "plain", func(r map[string]any) { r["owner_access_enforced"] = false }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := map[string]any{"target_ip": "8.8.8.8", "target_port": float64(31042), "protocol": "tcp", "public_transport": tc.mode, "owner_team_id": draftTeamID}
			request, _ := json.Marshal(wire)
			var destination Destination
			if err := json.Unmarshal(request, &destination); err != nil {
				t.Fatal(err)
			}
			body := map[string]any{"instance_id": "instance-1", "hostname": "abc.gate.msgctf.kr", "port": 42817, "tls": tc.mode == "tls", "protocol": "tcp", "url": nil, "created_at": "2026-10-27T00:00:00Z", "public_transport": tc.mode, "owner_team_id": draftTeamID, "owner_access_enforced": true}
			if tc.alter != nil {
				tc.alter(body)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var got map[string]any
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil || !reflect.DeepEqual(got, wire) {
					t.Errorf("draft request changed: got=%v want=%v err=%v", got, wire, err)
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer server.Close()
			client := contractTestClient(t, server)
			route, err := client.Put(context.Background(), "instance-1", destination)
			if (err == nil) != tc.valid {
				t.Fatalf("route=%+v err=%v want valid=%v", route, err, tc.valid)
			}
			if tc.valid {
				raw, _ := json.Marshal(route)
				var got map[string]any
				_ = json.Unmarshal(raw, &got)
				if got["owner_team_id"] != draftTeamID || got["public_transport"] != tc.mode || got["owner_access_enforced"] != true {
					t.Fatalf("owner contract not preserved: %s", raw)
				}
			}
		})
	}
}

func TestLegacyContractKeepsExactV1RequestBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got map[string]any
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil || !reflect.DeepEqual(got, map[string]any{"target_ip": "8.8.8.8", "target_port": float64(31042), "protocol": "tcp"}) {
			t.Errorf("legacy request changed: %v %v", got, err)
		}
		_ = json.NewEncoder(w).Encode(Route{InstanceID: "instance-1", Hostname: "abc.gate.msgctf.kr", Port: 443, TLS: true, Protocol: "tcp", CreatedAt: time.Now()})
	}))
	defer server.Close()
	if _, err := contractTestClient(t, server).Put(context.Background(), "instance-1", Destination{TargetIP: "8.8.8.8", TargetPort: 31042, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
}

func TestDraftContractRejectsIncompleteRequestsBeforeHTTP(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("invalid contract contacted Gateway")
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	client := contractTestClient(t, server)
	for _, fields := range []string{
		`"public_transport":"plain"`,
		`"owner_team_id":"00000000-0000-4000-8000-000000000002"`,
		`"public_transport":"unknown","owner_team_id":"00000000-0000-4000-8000-000000000002"`,
		`"public_transport":"plain","owner_team_id":"not-a-team"`,
		`"public_transport":"plain","owner_team_id":"00000000-0000-0000-0000-000000000000"`,
	} {
		var destination Destination
		if err := json.Unmarshal([]byte(`{"target_ip":"8.8.8.8","target_port":31042,"protocol":"tcp",`+fields+`}`), &destination); err != nil {
			t.Fatal(err)
		}
		_, err := client.Put(context.Background(), "instance-1", destination)
		apiErr, ok := err.(*APIError)
		if !ok || apiErr.Code != "GATEWAY_INVALID_DESTINATION" || !apiErr.Permanent {
			t.Fatalf("invalid contract not rejected locally: %s %v", fields, err)
		}
	}
}

func contractTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("synthetic-runtime-token"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(server.URL, file, 90*time.Second, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestDraftErrorsKeepPreciseSafeCodesAndRetryClassification(t *testing.T) {
	for _, tc := range []struct {
		code      string
		status    int
		permanent bool
	}{
		{"PORT_POOL_EXHAUSTED", 503, false},
		{"PORT_ALLOCATION_CONFLICT", 409, false},
		{"OWNER_CONFLICT", 409, true},
		{"OWNER_ACCESS_NOT_CONFIGURED", 503, false},
		{"TRANSPORT_NOT_SUPPORTED", 422, true},
		{"ROUTE_CLEANUP_PENDING", 409, false},
	} {
		t.Run(tc.code, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": tc.code, "message": "synthetic-private-detail"}})
			}))
			defer server.Close()
			var d Destination
			_ = json.Unmarshal([]byte(`{"target_ip":"8.8.8.8","target_port":31042,"protocol":"tcp","public_transport":"plain","owner_team_id":"`+draftTeamID+`"}`), &d)
			_, err := contractTestClient(t, server).Put(context.Background(), "instance-1", d)
			failure, ok := err.(*APIError)
			if !ok || failure.Code != "GATEWAY_"+tc.code || failure.Status != tc.status || failure.Permanent != tc.permanent {
				t.Fatalf("unexpected classification: %+v", err)
			}
		})
	}
}
