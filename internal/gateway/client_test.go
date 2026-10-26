package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestClientAcceptsExplicitTCPTransportAndRejectsInvalidMetadata(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("synthetic-runtime-token"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, protocol, transport string
		valid                     bool
	}{
		{"plaintext TCP", "tcp", `"port":42817,"tls":false,"url":null`, true},
		{"TLS TCP on assigned port", "tcp", `"port":42818,"tls":true,"url":null`, true},
		{"legacy TLS TCP", "tcp", `"port":443,"tls":true,"url":null`, true},
		{"legacy HTTPS", "http", `"port":443,"tls":true,"url":"https://abc.gate.msgctf.kr"`, true},
		{"missing TLS", "tcp", `"port":42817,"url":null`, false},
		{"null TLS", "tcp", `"port":42817,"tls":null,"url":null`, false},
		{"zero port", "tcp", `"port":0,"tls":false,"url":null`, false},
		{"negative port", "tcp", `"port":-1,"tls":false,"url":null`, false},
		{"oversized port", "tcp", `"port":65536,"tls":false,"url":null`, false},
		{"plaintext HTTP", "http", `"port":443,"tls":false,"url":"https://abc.gate.msgctf.kr"`, false},
		{"HTTP assigned port", "http", `"port":42817,"tls":true,"url":"https://abc.gate.msgctf.kr"`, false},
		{"TCP URL payload", "tcp", `"port":42817,"tls":false,"url":"tcp://abc.gate.msgctf.kr:42817"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"instance_id":"instance-1","hostname":"abc.gate.msgctf.kr","protocol":%q,"created_at":"2026-10-24T00:00:00Z",%s}`, tc.protocol, tc.transport)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			client, err := NewClient(server.URL, file, 90*time.Second, server.Client().Transport)
			if err != nil {
				t.Fatal(err)
			}
			route, err := client.Put(context.Background(), "instance-1", Destination{TargetIP: "8.8.8.8", TargetPort: 31042, Protocol: tc.protocol})
			if (err == nil) != tc.valid {
				t.Fatalf("route=%+v, err=%v, want valid=%v", route, err, tc.valid)
			}
			if tc.valid {
				var want Route
				if err := json.Unmarshal([]byte(body), &want); err != nil || !reflect.DeepEqual(route, want) {
					t.Fatalf("returned transport changed: got=%+v want=%+v err=%v", route, want, err)
				}
			}
		})
	}
}

func TestClientIdempotentPUTAndDELETE(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-runtime-token" {
			t.Error("token missing")
		}
		if r.URL.Path != "/v1/routes/instance-1" {
			t.Error(r.URL.Path)
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(204)
			return
		}
		var got Destination
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got.TargetPort != 31042 || got.Protocol != "tcp" {
			t.Error(got, err)
		}
		calls++
		if calls == 1 {
			w.WriteHeader(201)
		}
		_ = json.NewEncoder(w).Encode(Route{InstanceID: "instance-1", Hostname: "abc.gate.msgctf.kr", Port: 443, TLS: true, Protocol: "tcp", CreatedAt: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)})
	}))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("synthetic-runtime-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(server.URL, file, 90*time.Second, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	dest := Destination{TargetIP: "8.8.8.8", TargetPort: 31042, Protocol: "tcp"}
	first, err := client.Put(context.Background(), "instance-1", dest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Put(context.Background(), "instance-1", dest)
	if err != nil || first != second {
		t.Fatal(second, err)
	}
	if err = client.Delete(context.Background(), "instance-1"); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsUnsafeConfigurationAndInvalidResponses(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(file, []byte("synthetic-runtime-token"), 0600)
	for _, base := range []string{"http://gate.msgctf.kr", "https://user:pass@gate.msgctf.kr", "https://gate.msgctf.kr/a", "https://gate.msgctf.kr?x=1"} {
		if _, err := NewClient(base, file, 90*time.Second, nil); err == nil {
			t.Fatalf("accepted %s", base)
		}
	}
	if _, err := NewClient("https://gate.msgctf.kr", file, 74*time.Second, nil); err == nil {
		t.Fatal("short timeout accepted")
	}
	for _, body := range []string{`<html>bad gateway</html>`, `{"instance_id":"wrong"}`, `{"instance_id":"instance-1","hostname":"evil.example","port":443,"tls":true,"protocol":"http","url":"https://evil.example","created_at":"2026-10-24T00:00:00Z"}`} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		client, err := NewClient(server.URL, file, 90*time.Second, server.Client().Transport)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.Put(context.Background(), "instance-1", Destination{TargetIP: "8.8.8.8", TargetPort: 31042, Protocol: "http"}); err == nil {
			t.Fatal("invalid response accepted")
		}
		server.Close()
	}
}

func TestClientClassifiesHTTPAndProxyErrorsWithoutLeakingBody(t *testing.T) {
	file := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(file, []byte("synthetic-runtime-token"), 0600)
	for _, test := range []struct {
		status     int
		body, code string
		permanent  bool
	}{{503, `{"error":{"code":"GATEWAY_BUSY","message":"synthetic-runtime-token"}}`, "GATEWAY_BUSY", false}, {409, `{"error":{"code":"TARGET_IN_USE"}}`, "GATEWAY_TARGET_IN_USE", true}, {422, `{"error":{"code":"VALIDATION_ERROR"}}`, "GATEWAY_VALIDATION_ERROR", true}, {502, `<html>synthetic-runtime-token</html>`, "GATEWAY_HTTP_ERROR", false}, {401, `{"error":{"code":"INVALID_RUNTIME_TOKEN"}}`, "GATEWAY_INVALID_RUNTIME_TOKEN", false}} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.status)
			_, _ = w.Write([]byte(test.body))
		}))
		client, err := NewClient(server.URL, file, 90*time.Second, server.Client().Transport)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Put(context.Background(), "instance-1", Destination{TargetIP: "8.8.8.8", TargetPort: 31042, Protocol: "http"})
		api, ok := err.(*APIError)
		if !ok || api.Code != test.code || api.Status != test.status || api.Permanent != test.permanent {
			t.Fatal(test, err)
		}
		server.Close()
	}
}
