package imageprep

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Service struct {
	Store     Store
	Inventory Inventory
	Policy    Policy
	Runner    Runner
	Config    Config
	Now       func() time.Time
}

func NewService(store Store, inventory Inventory, policy Policy, runner Runner, config Config) *Service {
	return &Service{Store: store, Inventory: inventory, Policy: policy, Runner: runner, Config: config, Now: func() time.Time { return time.Now().UTC() }}
}
func (s *Service) replay(ctx context.Context, scope, endpoint, id, hash string) (Operation, bool, error) {
	r, found, err := s.Store.Find(ctx, scope, endpoint, id)
	if err != nil {
		return Operation{}, false, err
	}
	if found && r.Fingerprint != hash {
		return Operation{}, false, ErrConflict
	}
	return r.Operation, found, nil
}
func (s *Service) validatePolicy(r Request) error {
	if s.Policy == nil || s.Policy.Validate(r) != nil {
		return ErrPolicy
	}
	for _, target := range r.TargetIDs {
		if !s.Inventory.Enabled(target, r.Architecture) {
			return ErrPolicy
		}
	}
	return nil
}
func (s *Service) Create(ctx context.Context, scope string, r Request) (Operation, error) {
	if err := r.Normalize(); err != nil {
		return Operation{}, err
	}
	hash := fingerprint(r)
	if op, found, err := s.replay(ctx, scope, "create", r.RequestID, hash); found || err != nil {
		return op, err
	}
	if err := s.validatePolicy(r); err != nil {
		return Operation{}, err
	}
	nodes := []Node{}
	seen := map[string]bool{}
	for _, target := range r.TargetIDs {
		found, err := s.collectNodes(ctx, target, r.Architecture)
		if err != nil {
			return Operation{}, err
		}
		for _, n := range found {
			if seen[n.UID] || len(nodes) >= 1000 {
				return Operation{}, ErrPolicy
			}
			seen[n.UID] = true
			nodes = append(nodes, n)
		}
	}
	return s.insert(ctx, scope, "create", hash, r, "", nodes)
}
func (s *Service) insert(ctx context.Context, scope, endpoint, hash string, r Request, parent string, nodes []Node) (Operation, error) {
	op := Operation{ID: uuid.NewString(), ParentID: parent, RequestID: r.RequestID, ReleaseID: r.ReleaseID, ImageSetID: ImageSetID(r.Architecture, r.Images()), Architecture: r.Architecture, Status: "QUEUED", Nodes: []NodeResult{}}
	for _, n := range nodes {
		result := NodeResult{TargetID: n.TargetID, UID: n.UID, Name: n.Name, Architecture: n.Architecture, Status: "QUEUED", Images: []Image{}}
		for _, ref := range r.Images() {
			result.Images = append(result.Images, Image{Image: ref, Status: "QUEUED"})
		}
		op.Nodes = append(op.Nodes, result)
	}
	if len(nodes) == 0 {
		op.Status = "FAILED"
		op.ErrorCode = "NO_ELIGIBLE_NODES"
	}
	saved, err := s.Store.Insert(ctx, Record{Operation: op, Request: r, Scope: scope, Endpoint: endpoint, Fingerprint: hash, Frozen: nodes, Next: s.Now()})
	return saved.Operation, err
}
func (s *Service) Get(ctx context.Context, scope, id string) (Operation, error) {
	r, err := s.Store.Get(ctx, id)
	if err == nil && r.Scope != scope {
		return Operation{}, ErrNotFound
	}
	return r.Operation, err
}
func (s *Service) Retry(ctx context.Context, scope, parent string, retry Retry) (Operation, error) {
	if !validID(retry.RequestID) || (retry.NodeUIDs != nil && !uniqueStrings(retry.NodeUIDs, 1, 1000)) {
		return Operation{}, ErrInvalid
	}
	slices.Sort(retry.NodeUIDs)
	hash := fingerprint(retry)
	endpoint := "retry/" + parent
	if op, found, err := s.replay(ctx, scope, endpoint, retry.RequestID, hash); found || err != nil {
		return op, err
	}
	original, err := s.Store.Get(ctx, parent)
	if err != nil {
		return Operation{}, err
	}
	if original.Scope != scope {
		return Operation{}, ErrNotFound
	}
	if original.Operation.Status != "FAILED" && original.Operation.Status != "PARTIAL" {
		return Operation{}, ErrConflict
	}
	nodes := []Node{}
	for i, n := range original.Operation.Nodes {
		if n.Status == "FAILED" && (retry.NodeUIDs == nil || slices.Contains(retry.NodeUIDs, n.UID)) {
			nodes = append(nodes, original.Frozen[i])
		}
	}
	if len(nodes) == 0 || (retry.NodeUIDs != nil && len(nodes) != len(retry.NodeUIDs)) {
		return Operation{}, ErrInvalid
	}
	r := original.Request
	r.RequestID = retry.RequestID
	if err := s.validatePolicy(r); err != nil {
		return Operation{}, err
	}
	return s.insert(ctx, scope, endpoint, hash, r, parent, nodes)
}
func (s *Service) Query(ctx context.Context, q Query) (Readiness, error) {
	if err := q.Validate(); err != nil {
		return Readiness{}, err
	}
	result := Readiness{ImageSetID: ImageSetID(q.Architecture, q.Images), Architecture: q.Architecture, Targets: []TargetReadiness{}}
	now := s.Now()
	approved := s.Policy != nil
	for _, ref := range q.Images {
		if s.Policy == nil || !s.Policy.Approved(ref) {
			approved = false
		}
	}
	for _, target := range q.TargetIDs {
		if !s.Inventory.Known(target) {
			continue
		}
		row := TargetReadiness{TargetID: target}
		obs, found, err := s.Store.Observation(ctx, target, result.ImageSetID)
		if err != nil {
			return Readiness{}, err
		}
		if found && obs.Complete {
			row.ObservedAt = &obs.ObservedAt
			row.ValidUntil = &obs.ValidUntil
			row.EligibleNodeCount = len(obs.Nodes)
			if approved && obs.PolicyRevision == s.Policy.Revision() && s.Inventory.Enabled(target, q.Architecture) && !obs.ObservedAt.After(now) && obs.ValidUntil.After(now) && obs.ValidUntil.After(obs.ObservedAt) {
				for _, n := range obs.Nodes {
					ready := true
					for _, ref := range q.Images {
						if !validEvidence(n.Node, ref, n.Images[ref]) {
							ready = false
						}
					}
					if ready {
						row.ReadyNodeCount++
					}
				}
			}
			row.Ready = row.ReadyNodeCount > 0
		}
		result.Targets = append(result.Targets, row)
	}
	return result, nil
}
func validEvidence(n Node, ref string, e Evidence) bool {
	return e.Complete && e.NodeUID == n.UID && e.BootID != "" && e.BootID == n.BootID && e.OS == "linux" && e.Architecture == n.Architecture && e.Image == ref && DigestPattern.MatchString(e.ResolvedDigest)
}

// ReadyNodes is advisory: store failures and stale evidence return no preference.
func (s *Service) ReadyNodes(ctx context.Context, target, arch string, images []string) []string {
	if s == nil || !s.Inventory.Enabled(target, arch) {
		return nil
	}
	for _, image := range images {
		if s.Policy == nil || !s.Policy.Approved(image) {
			return nil
		}
	}
	obs, found, err := s.Store.Observation(ctx, target, ImageSetID(arch, images))
	now := s.Now()
	if err != nil || !found || !obs.Complete || obs.PolicyRevision != s.Policy.Revision() || obs.ObservedAt.After(now) || !obs.ValidUntil.After(now) {
		return nil
	}
	names := []string{}
	for _, n := range obs.Nodes {
		ready := true
		for _, image := range images {
			if !validEvidence(n.Node, image, n.Images[image]) {
				ready = false
			}
		}
		if ready {
			names = append(names, n.Node.Name)
		}
	}
	return names
}

// Observe collects whole target snapshots. Query never calls a node or extends a lease.
func (s *Service) Observe(ctx context.Context) error {
	queries, err := s.Store.Watch(ctx)
	if err != nil {
		return err
	}
	// Keep one observer per target so its node locks do not contend with other
	// image sets from this pass. Independent targets share bounded workers.
	byTarget := map[string][]Query{}
	order := []string{}
	for _, q := range queries {
		for _, target := range q.TargetIDs {
			if _, exists := byTarget[target]; !exists {
				order = append(order, target)
			}
			one := q
			one.TargetIDs = []string{target}
			byTarget[target] = append(byTarget[target], one)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan string)
	errors := make(chan error, 1)
	var workers sync.WaitGroup
	for range min(max(s.Config.Concurrency, 1), 8) {
		workers.Go(func() {
			for target := range jobs {
				if err := s.observeQueries(ctx, byTarget[target]); err != nil {
					select {
					case errors <- err:
					default:
					}
					cancel()
					return
				}
			}
		})
	}
dispatch:
	for _, target := range order {
		select {
		case jobs <- target:
		case <-ctx.Done():
			break dispatch
		}
	}
	close(jobs)
	workers.Wait()
	select {
	case err := <-errors:
		return err
	default:
		return ctx.Err()
	}
}

func (s *Service) observeQueries(ctx context.Context, queries []Query) error {
	for _, q := range queries {
		for _, target := range q.TargetIDs {
			started := s.Now()
			obs := Observation{TargetID: target, ImageSetID: ImageSetID(q.Architecture, q.Images), Architecture: q.Architecture, Images: q.Images, ObservedAt: started, ValidUntil: started.Add(s.Config.TTL), Nodes: []NodeObservation{}}
			if s.Policy != nil {
				obs.PolicyRevision = s.Policy.Revision()
			}
			if !s.Inventory.Enabled(target, q.Architecture) {
				if err := s.Store.PutObservation(ctx, obs); err != nil {
					return err
				}
				continue
			}
			nodes, err := s.collectNodes(ctx, target, q.Architecture)
			if err != nil {
				if saveErr := s.Store.PutObservation(ctx, obs); saveErr != nil {
					return saveErr
				}
				continue
			}
			obs.Complete = true
			for _, n := range nodes {
				observed := NodeObservation{Node: n, Images: map[string]Evidence{}}
				owner := uuid.NewString()
				locked, lockErr := s.Store.LockNode(ctx, n.UID, owner, s.Now(), 3*time.Minute)
				if lockErr != nil {
					return lockErr
				}
				if locked {
					runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
					for _, ref := range q.Images {
						if s.Policy == nil || !s.Policy.Approved(ref) {
							continue
						}
						e, err := s.Runner.Run(runCtx, n, ref, false)
						if err == nil && validEvidence(n, ref, e) {
							observed.Images[ref] = e
						}
					}
					cancel()
					_ = s.Store.UnlockNode(ctx, n.UID, owner)
				}
				obs.Nodes = append(obs.Nodes, observed)
			}
			if err := s.Store.PutObservation(ctx, obs); err != nil {
				return err
			}
		}
	}
	return nil
}

// Step claims one bounded image verification/pull. Persisting attempts before the
// agent call makes restart recovery bounded even when a worker dies mid-command.
func (s *Service) Step(ctx context.Context) (bool, error) {
	ctx, stop := context.WithTimeout(ctx, 150*time.Second)
	defer stop()
	r, found, err := s.Store.Claim(ctx, s.Now(), 3*time.Minute)
	if err != nil || !found {
		return found, err
	}
	r.Operation.Status = "RUNNING"
	for ni := range r.Operation.Nodes {
		n := &r.Operation.Nodes[ni]
		if n.Status == "READY" || n.Status == "FAILED" {
			continue
		}
		for ii := range n.Images {
			entry := &n.Images[ii]
			if entry.Status == "READY" || entry.Status == "FAILED" {
				continue
			}
			frozen := r.Frozen[ni]
			owner := r.Lease
			locked, err := s.Store.LockNode(ctx, n.UID, owner, s.Now(), 3*time.Minute)
			if err != nil {
				return true, err
			}
			if !locked {
				r.Next = s.Now().Add(time.Second)
				return true, s.Store.Save(ctx, r, true)
			}
			defer func() {
				unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				_ = s.Store.UnlockNode(unlockCtx, n.UID, owner)
			}()
			code := ""
			if s.validatePolicy(r.Request) != nil {
				code = "POLICY_REJECTED"
			}
			if entry.Attempts >= s.Config.MaxAttempts {
				code = entry.ErrorCode
				if code == "" {
					code = "REGISTRY_UNAVAILABLE"
				}
			}
			if code == "" {
				entry.Attempts++
				entry.Status = "VERIFYING"
				n.Status = "VERIFYING"
				if err := s.Store.Save(ctx, r, false); err != nil {
					return true, err
				}
				current, invErr := s.collectNodes(ctx, n.TargetID, r.Request.Architecture)
				if invErr != nil {
					code = ErrorCode(invErr)
				} else {
					match := false
					for _, candidate := range current {
						if candidate.UID == frozen.UID && candidate.Name == frozen.Name && candidate.BootID == frozen.BootID && candidate.MachineID == frozen.MachineID {
							match = true
						}
					}
					if !match {
						code = "NODE_IDENTITY_MISMATCH"
					}
				}
			}
			var e Evidence
			started := s.Now()
			if code == "" {
				entry.Status = "PULLING"
				n.Status = "PULLING"
				if err := s.Store.Save(ctx, r, false); err != nil {
					return true, err
				}
				runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				e, err = s.Runner.Run(runCtx, frozen, entry.Image, true)
				cancel()
				if err != nil {
					code = ErrorCode(err)
				} else if !validEvidence(frozen, entry.Image, e) {
					code = "NODE_IDENTITY_MISMATCH"
				}
			}
			if code == "" {
				entry.Status = "READY"
				entry.ResolvedDigest = e.ResolvedDigest
				entry.ObservedAt = &started
				entry.ErrorCode = ""
			} else {
				entry.ErrorCode = code
				if transient(code) && entry.Attempts < s.Config.MaxAttempts {
					entry.Status = "QUEUED"
					r.Next = s.Now().Add(time.Second * time.Duration(1<<min(entry.Attempts, 6)))
				} else {
					entry.Status = "FAILED"
				}
			}
			aggregate(&r.Operation)
			return true, s.Store.Save(ctx, r, true)
		}
	}
	aggregate(&r.Operation)
	return true, s.Store.Save(ctx, r, true)
}

func (s *Service) collectNodes(ctx context.Context, target, arch string) ([]Node, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	nodes, err := s.Inventory.Nodes(bounded, target, arch)
	if err != nil && bounded.Err() != nil {
		return nil, Failure{Code: "NETWORK_TIMEOUT"}
	}
	return nodes, err
}
func aggregate(op *Operation) {
	ready, failed := 0, 0
	for ni := range op.Nodes {
		n := &op.Nodes[ni]
		nr, nf := 0, 0
		var oldest *time.Time
		for _, i := range n.Images {
			if i.Status == "READY" {
				nr++
				if oldest == nil || i.ObservedAt.Before(*oldest) {
					oldest = i.ObservedAt
				}
			}
			if i.Status == "FAILED" {
				nf++
			}
		}
		if nr == len(n.Images) {
			n.Status = "READY"
			n.ObservedAt = oldest
			ready++
		} else if nr+nf == len(n.Images) {
			n.Status = "FAILED"
			failed++
		} else {
			n.Status = "QUEUED"
		}
	}
	if ready+failed < len(op.Nodes) {
		op.Status = "RUNNING"
	} else if ready == len(op.Nodes) && ready > 0 {
		op.Status = "SUCCEEDED"
	} else if ready > 0 {
		op.Status = "PARTIAL"
	} else {
		op.Status = "FAILED"
	}
}
func (s *Service) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var group sync.WaitGroup
	for range s.Config.Concurrency {
		group.Go(func() {
			for {
				worked, err := s.Step(ctx)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					slog.Warn("image preparation store step unavailable; retrying")
				}
				if !worked || err != nil {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Second):
					}
				}
				if ctx.Err() != nil {
					return
				}
			}
		})
	}
	group.Go(func() {
		for {
			if err := s.Observe(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.Warn("image observation store unavailable; retrying")
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.Config.ObserveInterval):
			}
		}
	})
	<-ctx.Done()
	cancel()
	group.Wait()
	return nil
}
