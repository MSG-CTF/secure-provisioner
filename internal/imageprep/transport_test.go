package imageprep

import (
	"context"
	"strings"
	"testing"
)

func TestTransportRejectsMissingOrMismatchedOperatorIdentity(t *testing.T) {
	r := &Transport{Nodes: []AgentTarget{{TargetID: "target-a", NodeName: "node-a", NodeUID: "uid-a", Mode: "local", Command: "/does/not/exist"}}}
	for _, n := range []Node{{TargetID: "target-a", Name: "node-a", UID: "replacement"}, {TargetID: "target-b", Name: "node-a", UID: "uid-a"}} {
		if _, err := r.Run(context.Background(), n, testImage, true); ErrorCode(err) != "AGENT_UNAVAILABLE" {
			t.Fatalf("unknown identity=%v", err)
		}
	}
	if _, err := ParseAgentTargets([]byte(`{"nodes":[{"target_id":"a","node_name":"n","node_uid":"u","mode":"ssh","ssh_host":"host; unsafe","ssh_config":"/etc/config"}]}`)); err == nil {
		t.Fatal("unsafe SSH destination accepted")
	}
	_ = strings.Builder{}
}
