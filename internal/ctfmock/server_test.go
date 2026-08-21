package ctfmock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMockContractUsesSnakeCase(t *testing.T) {
	payload, err := json.Marshal(struct {
		Scenario Scenario      `json:"scenario"`
		Event    RecordedEvent `json:"event"`
	}{
		Scenario: Scenario{SchedulerUnavailable: true},
		Event:    RecordedEvent{ReceivedAt: time.Unix(0, 0).UTC()},
	})
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(payload)
	for _, expected := range []string{`"scheduler_unavailable"`, `"received_at"`} {
		if !strings.Contains(jsonText, expected) {
			t.Fatalf("response %s does not contain %s", jsonText, expected)
		}
	}
	for _, forbidden := range []string{`"schedulerUnavailable"`, `"receivedAt"`} {
		if strings.Contains(jsonText, forbidden) {
			t.Fatalf("response %s contains camelCase field %s", jsonText, forbidden)
		}
	}
}

func TestChallengeEndpointServesXSSFixture(t *testing.T) {
	handler := NewHandler("")

	indexRequest := httptest.NewRequest(http.MethodGet, "/mock/v1/challenges/inst-xss", nil)
	indexResponse := httptest.NewRecorder()
	handler.ServeHTTP(indexResponse, indexRequest)

	if indexResponse.Code != http.StatusOK {
		t.Fatalf("expected challenge index status 200, got %d", indexResponse.Code)
	}
	if !strings.Contains(indexResponse.Body.String(), "Reflected Search") || !strings.Contains(indexResponse.Body.String(), "inst-xss") {
		t.Fatal("expected challenge index and instance ID")
	}

	payload := `<script>document.body.dataset.xss="ok"</script>`
	searchRequest := httptest.NewRequest(http.MethodGet, "/mock/v1/challenges/inst-xss?q="+url.QueryEscape(payload), nil)
	searchResponse := httptest.NewRecorder()
	handler.ServeHTTP(searchResponse, searchRequest)

	if searchResponse.Code != http.StatusOK {
		t.Fatalf("expected search status 200, got %d", searchResponse.Code)
	}
	if !strings.Contains(searchResponse.Body.String(), payload) {
		t.Fatal("expected intentionally unescaped reflected payload")
	}
	cookies := searchResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "flag" || cookies[0].Value != mockChallengeFlag {
		t.Fatalf("expected challenge flag cookie, got %+v", cookies)
	}
}
