package operations

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestExecutionErrorExposesOnlyStableCode(t *testing.T) {
	classified := NewExecutionError("TARGET_TEMPORARILY_UNAVAILABLE", true, errors.New("https://user:secret@cluster.example"))

	code, retryable := ClassifyExecutionError(classified)
	if code != "TARGET_TEMPORARILY_UNAVAILABLE" || !retryable {
		t.Fatalf("got %q, %v", code, retryable)
	}
	if strings.Contains(classified.Error(), "secret") {
		t.Fatalf("raw cause leaked: %s", classified)
	}
	if !errors.Is(classified, classified.Unwrap()) {
		t.Fatal("expected the cause to remain unwrap-able")
	}
}

func TestNewExecutionErrorDefaultsBlankCode(t *testing.T) {
	err := NewExecutionError("", true, errors.New("temporary runtime failure"))

	code, retryable := ClassifyExecutionError(err)
	if code != "EXECUTION_FAILED" || !retryable {
		t.Fatalf("got %q, %v", code, retryable)
	}
	if err.Error() != "EXECUTION_FAILED" {
		t.Fatalf("got error %q", err)
	}
}

func TestClassifyExecutionErrorFallsBackForUnclassifiedErrors(t *testing.T) {
	code, retryable := ClassifyExecutionError(fmt.Errorf("wrapped: %w", errors.New("target detail")))
	if code != "EXECUTION_FAILED" || retryable {
		t.Fatalf("got %q, %v", code, retryable)
	}
}
