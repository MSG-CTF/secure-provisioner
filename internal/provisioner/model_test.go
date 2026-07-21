package provisioner

import "testing"

func TestDomainEnumsUseNamedTypes(t *testing.T) {
	var runtimeType RuntimeType = RuntimeTypeKubernetes
	var reason DeleteReason = DeleteReasonUserRequested
	if runtimeType != "KUBERNETES" || reason != "USER_REQUESTED" {
		t.Fatalf("runtimeType = %q, reason = %q", runtimeType, reason)
	}
}
