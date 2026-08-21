package runtimepg

import (
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/runtimebinding"
)

type BindingStore struct{ db *sql.DB }

func (store *BindingStore) SaveCreated(binding runtimebinding.Binding) (runtimebinding.Binding, bool, error) {
	if !validBinding(binding) {
		return runtimebinding.Binding{}, false, runtimebinding.ErrInvalidBinding
	}
	snapshot, err := json.Marshal(binding)
	if err != nil {
		return runtimebinding.Binding{}, false, err
	}
	endpoints, err := json.Marshal(binding.Endpoints)
	if err != nil {
		return runtimebinding.Binding{}, false, err
	}
	result, err := store.db.Exec(`INSERT INTO runtime_bindings
	  (instance_id,team_id,target_id,namespace,namespace_uid,runtime_workload_id,endpoints,policy_snapshot,state,created_at,updated_at)
	  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (instance_id) DO NOTHING`,
		binding.InstanceID, binding.TeamID, binding.TargetID, binding.Namespace, binding.NamespaceUID, binding.RuntimeWorkloadID, string(endpoints), string(snapshot), binding.State, binding.CreatedAt, binding.UpdatedAt)
	if err != nil {
		return runtimebinding.Binding{}, false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return runtimebinding.Binding{}, false, err
	}
	if rows == 1 {
		return binding, true, nil
	}
	existing, err := store.Get(binding.InstanceID)
	if err != nil {
		return runtimebinding.Binding{}, false, err
	}
	if existing.State != runtimebinding.StateCreated {
		return runtimebinding.Binding{}, false, runtimebinding.ErrInvalidTransition
	}
	if !sameBindingPlacement(existing, binding) {
		return runtimebinding.Binding{}, false, runtimebinding.ErrConflict
	}
	return existing, false, nil
}

func (store *BindingStore) Get(instanceID string) (runtimebinding.Binding, error) {
	return scanBinding(store.db.QueryRow(bindingSelect+" WHERE instance_id=$1", instanceID))
}

func (store *BindingStore) MarkDeleting(instanceID string, updatedAt time.Time) (runtimebinding.Binding, error) {
	if updatedAt.IsZero() {
		return runtimebinding.Binding{}, runtimebinding.ErrInvalidTransition
	}
	result, err := store.db.Exec(`UPDATE runtime_bindings SET state='DELETING',updated_at=$2 WHERE instance_id=$1 AND state='CREATED'`, instanceID, updatedAt)
	if err != nil {
		return runtimebinding.Binding{}, err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		binding, getErr := store.Get(instanceID)
		if getErr != nil {
			return runtimebinding.Binding{}, getErr
		}
		if binding.State != runtimebinding.StateDeleting {
			return runtimebinding.Binding{}, runtimebinding.ErrInvalidTransition
		}
		return binding, nil
	}
	return store.Get(instanceID)
}

func (store *BindingStore) RestoreCreated(instanceID string, updatedAt time.Time) (runtimebinding.Binding, error) {
	result, err := store.db.Exec(`UPDATE runtime_bindings SET state='CREATED',updated_at=$2,deleted_at=NULL WHERE instance_id=$1 AND state='DELETING'`, instanceID, updatedAt)
	if err != nil {
		return runtimebinding.Binding{}, err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return runtimebinding.Binding{}, runtimebinding.ErrInvalidTransition
	}
	return store.Get(instanceID)
}

func (store *BindingStore) MarkDeleted(instanceID string, deletedAt time.Time) (runtimebinding.Binding, error) {
	result, err := store.db.Exec(`UPDATE runtime_bindings SET state='DELETED',updated_at=$2,deleted_at=$2 WHERE instance_id=$1 AND state='DELETING'`, instanceID, deletedAt)
	if err != nil {
		return runtimebinding.Binding{}, err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		binding, getErr := store.Get(instanceID)
		if getErr != nil {
			return runtimebinding.Binding{}, getErr
		}
		if binding.State != runtimebinding.StateDeleted {
			return runtimebinding.Binding{}, runtimebinding.ErrInvalidTransition
		}
		return binding, nil
	}
	return store.Get(instanceID)
}

const bindingSelect = `SELECT instance_id,team_id,target_id,namespace,namespace_uid,runtime_workload_id,endpoints,policy_snapshot,state,created_at,updated_at,deleted_at FROM runtime_bindings`

func scanBinding(row rowScanner) (runtimebinding.Binding, error) {
	var binding runtimebinding.Binding
	var endpoints, snapshot []byte
	var deletedAt sql.NullTime
	if err := row.Scan(&binding.InstanceID, &binding.TeamID, &binding.TargetID, &binding.Namespace, &binding.NamespaceUID, &binding.RuntimeWorkloadID, &endpoints, &snapshot, &binding.State, &binding.CreatedAt, &binding.UpdatedAt, &deletedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return runtimebinding.Binding{}, runtimebinding.ErrNotFound
		}
		return runtimebinding.Binding{}, err
	}
	var policy runtimebinding.Binding
	if err := json.Unmarshal(snapshot, &policy); err != nil {
		return runtimebinding.Binding{}, err
	}
	binding.IsolationProfile = policy.IsolationProfile
	binding.WorkloadProfile = policy.WorkloadProfile
	binding.ContainerRequirements = policy.ContainerRequirements
	binding.InternalConnections = policy.InternalConnections
	binding.OutboundMode = policy.OutboundMode
	binding.ResourceLimits = policy.ResourceLimits
	if err := json.Unmarshal(endpoints, &binding.Endpoints); err != nil {
		return runtimebinding.Binding{}, err
	}
	if deletedAt.Valid {
		value := deletedAt.Time
		binding.DeletedAt = &value
	}
	return binding, nil
}

func validBinding(binding runtimebinding.Binding) bool {
	return strings.TrimSpace(binding.InstanceID) != "" && binding.TeamID.Valid() && strings.TrimSpace(binding.TargetID) != "" && strings.TrimSpace(binding.Namespace) != "" && strings.TrimSpace(binding.NamespaceUID) != "" && strings.TrimSpace(binding.RuntimeWorkloadID) != "" && binding.State == runtimebinding.StateCreated && !binding.CreatedAt.IsZero() && !binding.UpdatedAt.IsZero() && binding.DeletedAt == nil
}

func sameBindingPlacement(a, b runtimebinding.Binding) bool {
	a.State = b.State
	a.CreatedAt = b.CreatedAt
	a.UpdatedAt = b.UpdatedAt
	a.DeletedAt = b.DeletedAt
	return reflect.DeepEqual(a, b)
}

var _ runtimebinding.Store = (*BindingStore)(nil)
