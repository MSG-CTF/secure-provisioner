package httpapi

import "github.com/MSG-CTF/secure-provisioner/internal/operations"

func (api *API) allowsCISmokeCreate(request CreateWorkloadRequest) bool {
	if api.runtime == nil || api.imagePolicies == nil ||
		request.TeamID != api.ciSmokeTeamID ||
		request.Target.RuntimeType != RuntimeTypeKubernetes || request.Target.TargetID != api.ciSmokeTargetID ||
		request.IsolationProfile != "WEB" || len(request.Workload.Containers) != 1 ||
		request.Workload.ResourceLimits.CPUMillicores > 500 ||
		request.Workload.ResourceLimits.MemoryMiB > 512 ||
		request.Workload.ResourceLimits.EphemeralStorageMiB > 1024 {
		return false
	}
	return api.imagePolicies.AllowsCISmoke(request.Workload.Containers[0].Image)
}

func (api *API) allowsCISmokeOperation(operation operations.Operation) bool {
	switch operation.Type {
	case operations.OperationTypeCreate:
		return operation.CreateCommand != nil && operation.CreateCommand.TeamID == api.ciSmokeTeamID && operation.CreateCommand.TargetID == api.ciSmokeTargetID
	case operations.OperationTypeDelete:
		return operation.DeleteCommand != nil && operation.DeleteCommand.TeamID == api.ciSmokeTeamID && operation.DeleteCommand.TargetID == api.ciSmokeTargetID
	default:
		return false
	}
}
