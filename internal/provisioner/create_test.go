package provisioner

import (
	"context"
	"errors"
	"testing"
)

func TestUnavailableCreateWorkloadUseCaseReportsRuntimeUnavailable(t *testing.T) {
	_, err := (UnavailableCreateWorkloadUseCase{}).CreateWorkload(context.Background(), CreateWorkloadCommand{})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("CreateWorkload() error = %v, want ErrRuntimeUnavailable", err)
	}
}
