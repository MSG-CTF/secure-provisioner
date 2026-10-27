package runtimepg

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/MSG-CTF/secure-provisioner/internal/gateway"
	"github.com/MSG-CTF/secure-provisioner/internal/provisioner"
)

func TestGatewayJournalLegacyTracingFieldsRecoverAcrossLifecycle(t *testing.T) {
	db := openTestDatabase(t)
	ctx := context.Background()
	for index, phases := range [][2]gateway.Phase{
		{gateway.PhaseApplyPending, gateway.PhaseApplied},
		{gateway.PhaseApplied, gateway.PhaseDeletePending},
		{gateway.PhaseDeletePending, gateway.PhaseRouteDeleted},
		{gateway.PhaseRouteDeleted, gateway.PhaseDeleted},
	} {
		t.Run(string(phases[0]), func(t *testing.T) {
			id := fmt.Sprintf("gateway-legacy-%d-%d", time.Now().UnixNano(), index)
			t.Cleanup(func() {
				_, _ = db.db.ExecContext(context.Background(), `DELETE FROM runtime_gateway_routes WHERE instance_id=$1`, id)
			})
			r := legacyGatewayRecord(id, 31200+index, phases[0])
			if err := db.GatewayJournal().WithLock(ctx, id, func(s gateway.Session) error { return s.Save(r) }); err != nil {
				t.Fatal(err)
			}
			// Simulate the exact pre-image-preparation JSON representation.
			if _, err := db.db.ExecContext(ctx, `UPDATE runtime_gateway_routes SET snapshot=jsonb_set(snapshot,'{Command}',(snapshot->'Command')-'ReleaseID'-'Architecture') WHERE instance_id=$1`, id); err != nil {
				t.Fatal(err)
			}
			if err := db.GatewayJournal().WithLock(ctx, id, func(s gateway.Session) error {
				loaded, err := s.Load()
				if err != nil {
					return err
				}
				loaded.Phase = phases[1]
				return s.Save(loaded)
			}); err != nil {
				t.Fatalf("legacy intent could not advance from %s to %s: %v", phases[0], phases[1], err)
			}
			loaded, err := db.GatewayJournal().Get(ctx, id)
			if err != nil || loaded.Phase != phases[1] || loaded.Command.ReleaseID != "" || loaded.Command.Architecture != "" {
				t.Fatal("legacy intent was not recovered without inventing tracing identity", loaded.Phase, err)
			}
		})
	}
}

func TestGatewayJournalTracingAndUnknownCommandFieldsRemainFenced(t *testing.T) {
	db := openTestDatabase(t)
	ctx := context.Background()
	for index, field := range []string{"ReleaseID", "Architecture", "unknown"} {
		t.Run(field, func(t *testing.T) {
			id := fmt.Sprintf("gateway-tracing-fence-%d-%d", time.Now().UnixNano(), index)
			t.Cleanup(func() {
				_, _ = db.db.ExecContext(context.Background(), `DELETE FROM runtime_gateway_routes WHERE instance_id=$1`, id)
			})
			r := legacyGatewayRecord(id, 31300+index, gateway.PhaseApplied)
			r.Command.ReleaseID = "11111111-1111-4111-8111-111111111111"
			r.Command.Architecture = "AMD64"
			if err := db.GatewayJournal().WithLock(ctx, id, func(s gateway.Session) error { return s.Save(r) }); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "ReleaseID":
				r.Command.ReleaseID = "22222222-2222-4222-8222-222222222222"
			case "Architecture":
				r.Command.Architecture = "ARM64"
			case "unknown":
				if _, err := db.db.ExecContext(ctx, `UPDATE runtime_gateway_routes SET snapshot=jsonb_set(snapshot,'{Command,FutureGuard}', '"retained"'::jsonb) WHERE instance_id=$1`, id); err != nil {
					t.Fatal(err)
				}
				var err error
				r, err = db.GatewayJournal().Get(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := db.GatewayJournal().WithLock(ctx, id, func(s gateway.Session) error { return s.Save(r) })
			if !errors.Is(err, gateway.ErrConflict) {
				t.Fatal("command identity change was not fenced", err)
			}
		})
	}
}

func legacyGatewayRecord(id string, port int, phase gateway.Phase) gateway.Record {
	return gateway.Record{Command: provisioner.CreateWorkloadCommand{InstanceID: id, TargetID: "test-target"}, Result: provisioner.CreateWorkloadResult{NamespaceUID: "ns-" + id, RuntimeWorkloadID: "test/ns/instance"}, Destination: gateway.Destination{TargetIP: "8.8.8.8", TargetPort: port, Protocol: "http"}, ServiceUID: "svc-" + id, Phase: phase, CreatedAt: time.Now().UTC()}
}
