package runtimebinding

import (
	"testing"
	"time"
)

func TestBindingCopiesPublicSelection(t *testing.T) {
	binding := validBinding(time.Now())
	binding.ContainerRequirements[0].Expose = false
	binding.ContainerRequirements[0].ExposedPorts = []int{8080}
	store := NewMemoryStore()
	saved, _, err := store.SaveCreated(binding)
	if err != nil {
		t.Fatal(err)
	}
	binding.ContainerRequirements[0].ExposedPorts[0] = 9000
	saved.ContainerRequirements[0].ExposedPorts[0] = 9001
	got, err := store.Get(binding.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ContainerRequirements[0].ExposedPorts[0] != 8080 {
		t.Fatal("stored public selection aliases caller slice")
	}
}
