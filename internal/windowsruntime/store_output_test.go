package windowsruntime_test

import (
	"context"
	win "github.com/MSG-CTF/secure-provisioner/internal/windowsruntime"
	"testing"
	"time"
)

func TestPostgresStoreNULOutputSurvivesRestart(t *testing.T) {
	store, db := postgresStore(t)
	ctx := context.Background()
	submitted := queuedRecord(targetID)
	if _, _, err := store.Submit(ctx, submitted); err != nil {
		t.Fatal(err)
	}
	r, err := store.Claim(ctx, "worker", time.Minute)
	if err != nil || r == nil {
		t.Fatal(err)
	}
	zero := int64(0)
	r.Phase = "FINISHED"
	r.BrokerPending = true
	r.Outcome = &win.Outcome{Result: "succeeded", ExitCode: &zero, Stdout: "before\x00after", Stderr: "\x00stderr"}
	connection := validConnection()
	connection.Name = "VM\x00name"
	connection.RDPFile = "unused\x00rdp file"
	r.Connection = &connection
	r.FinishedBody = []byte(`{"event":"finished"}`)
	if err = store.Save(ctx, *r, "worker"); err != nil {
		t.Fatal("output was not durably saved", err)
	}
	got, err := win.NewPostgresStore(db).Get(ctx, r.ID)
	if err != nil || got.Outcome == nil || got.Outcome.Stdout != "before\x00after" || got.Outcome.Stderr != "\x00stderr" || !got.BrokerPending {
		t.Fatalf("output lost: %+v %v", got.Outcome, err)
	}
	if got.Connection == nil || *got.Connection != connection {
		t.Fatalf("connection metadata lost: %#v", got.Connection)
	}
	if r.Outcome.Stdout != "before\x00after" || r.Outcome.Stderr != "\x00stderr" || r.Connection.RDPFile != "unused\x00rdp file" {
		t.Fatal("persistence mutated caller record")
	}
}
