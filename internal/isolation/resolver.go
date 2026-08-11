package isolation

import "errors"

var ErrPolicyRejected = errors.New("isolation policy rejected")

type Resolver interface {
	Resolve(Request) (ResolvedPolicy, error)
}
