package provisioner

import (
	"fmt"
	"strings"
	"testing"
)

func TestEnvironmentCountAndByteLimits(t *testing.T) {
	values := make(map[string]string)
	for i := 0; i < 128; i++ {
		values[fmt.Sprintf("SETTING_%d", i)] = fmt.Sprint(i)
	}
	if err := ValidateEnvironment(values, false); err != nil {
		t.Fatalf("128 entries should be accepted: %v", err)
	}
	values["EXTRA"] = "value"
	if ValidateEnvironment(values, false) == nil {
		t.Fatal("129 entries must be rejected")
	}
	oversized := map[string]string{}
	for i := 0; i < 5; i++ {
		oversized[fmt.Sprintf("V%d", i)] = strings.Repeat("x", 4096)
	}
	if ValidateEnvironment(oversized, false) == nil {
		t.Fatal("the total byte limit must remain enforced")
	}
}
