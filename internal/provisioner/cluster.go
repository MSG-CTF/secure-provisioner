package provisioner

import "context"

type clusterAdapter interface {
	create(context.Context, Instance, Challenge, Reservation) (RuntimeResources, error)
	verify(context.Context, RuntimeResources) error
	delete(context.Context, string) error
	get(string) (RuntimeResources, bool)
}
