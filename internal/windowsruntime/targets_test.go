package windowsruntime_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	win "github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
)

func TestBrokerListsWindowsTargetsWithOpaqueCursor(t *testing.T) {
	after := "cursor+/=next"
	next := "another-cursor"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/runtime/windows-vms" || r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("after") != after || r.Header.Get("Authorization") != "Bearer test-runtime-token" {
			t.Errorf("bad list request: %s %s", r.Method, r.URL)
		}
		_ = json.NewEncoder(w).Encode(win.VMPage{Items: []win.Connection{validConnection()}, NextCursor: &next})
	}))
	defer server.Close()
	b, err := win.NewBroker(server.URL+"/api", "test-runtime-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	page, err := b.List(context.Background(), 2, after)
	if err != nil || len(page.Items) != 1 || page.Items[0].TargetID != targetID || page.NextCursor == nil || *page.NextCursor != next {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestBrokerListAcceptsEmptyAndBoundsInputs(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("limit") != "200" || r.URL.Query().Has("after") {
			t.Error("wrong default query")
		}
		fmt.Fprint(w, `{"items":[],"next_cursor":null}`)
	}))
	defer server.Close()
	b, _ := win.NewBroker(server.URL, "test-token", server.Client())
	page, err := b.List(context.Background(), 200, "")
	if err != nil || page.Items == nil || len(page.Items) != 0 || page.NextCursor != nil {
		t.Fatalf("empty list=%+v %v", page, err)
	}
	for _, test := range []struct {
		limit int
		after string
	}{{0, ""}, {201, ""}, {1, "bad\nvalue"}, {1, strings.Repeat("a", 513)}} {
		if _, err := b.List(context.Background(), test.limit, test.after); err == nil {
			t.Fatal("bad input accepted", test)
		}
	}
	if calls != 1 {
		t.Fatalf("bad input reached broker: %d", calls)
	}
}

func TestBrokerListRejectsMalformedSnapshots(t *testing.T) {
	valid, _ := json.Marshal(validConnection())
	for name, body := range map[string]string{
		"missing items": `{"next_cursor":null}`,
		"null items":    `{"items":null,"next_cursor":null}`,
		"invalid VM":    `{"items":[{"resource_target_id":"invalid"}],"next_cursor":null}`,
		"over limit":    "{\"items\":[" + string(valid) + "," + string(valid) + "],\"next_cursor\":null}",
		"empty cursor":  `{"items":[],"next_cursor":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
			defer server.Close()
			b, _ := win.NewBroker(server.URL, "test-token", server.Client())
			if _, err := b.List(context.Background(), 1, ""); err == nil {
				t.Fatal("accepted malformed list")
			}
		})
	}
}
