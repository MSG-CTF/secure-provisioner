package isolation

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const peerNetworkJSON = `{"id":"peers-v1","mode":"PEER_GROUPS_V1","isolation_profile":"WEB","containers":[{"name":"web","image":"ghcr.io/msg/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ports":[8080]},{"name":"db","image":"ghcr.io/msg/db@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","ports":[5432]}],"peer_groups":[{"name":"appnet","members":["web","db"]}],"egress":[{"from":"web","cidr":"10.20.30.40/32","ports":[443]}]}`

func decodePeerNetwork(t *testing.T, body string) *WorkloadNetwork {
	t.Helper()
	var graph WorkloadNetwork
	if err := json.Unmarshal([]byte(body), &graph); err != nil {
		t.Fatal(err)
	}
	return &graph
}

func peerNetworkRequirements() []ContainerRequirement {
	return []ContainerRequirement{{Name: "web", Ports: []int{8080}}, {Name: "db", Ports: []int{5432}}}
}

func TestPeerGroupsAndExactEgressSurviveCloning(t *testing.T) {
	graph := decodePeerNetwork(t, peerNetworkJSON)
	if err := ValidateWorkloadNetwork(graph, WorkloadProfileWeb, peerNetworkRequirements()); err != nil {
		t.Fatal(err)
	}
	cloned := CloneWorkloadNetwork(graph)
	encoded, err := json.Marshal(cloned)
	if err != nil || !strings.Contains(string(encoded), `"members":["web","db"]`) || !strings.Contains(string(encoded), `"cidr":"10.20.30.40/32"`) {
		t.Fatalf("clone lost approved peers or egress: %s, %v", encoded, err)
	}
	// Mutating caller-owned nested slices must not widen the saved snapshot.
	graph.PeerGroups[0].Members[0] = "db"
	graph.Egress[0].Ports[0] = 80
	if !reflect.DeepEqual(cloned, decodePeerNetwork(t, peerNetworkJSON)) {
		t.Fatal("nested peer or egress slices alias the caller")
	}
}

func TestWorkloadNetworkModesDoNotMixPeerGroupsAndTCPAllowLists(t *testing.T) {
	graph := decodePeerNetwork(t, peerNetworkJSON)
	graph.Allow = []NetworkEdge{}
	if err := ValidateWorkloadNetwork(graph, WorkloadProfileWeb, peerNetworkRequirements()); err == nil {
		t.Fatal("peer mode accepted a directed TCP allow list")
	}
	graph.Mode = NetworkModeExplicitTCPV1
	if err := ValidateWorkloadNetwork(graph, WorkloadProfileWeb, peerNetworkRequirements()); err == nil {
		t.Fatal("TCP mode accepted peer groups")
	}
	graph.PeerGroups = nil
	if err := ValidateWorkloadNetwork(graph, WorkloadProfileWeb, peerNetworkRequirements()); err != nil {
		t.Fatalf("TCP mode rejected exact egress: %v", err)
	}
	graph.Mode = NetworkModePeerGroupsV1
	graph.Allow = nil
	if err := ValidateWorkloadNetwork(graph, WorkloadProfileWeb, peerNetworkRequirements()); err != nil {
		t.Fatalf("egress-only peer network rejected: %v", err)
	}
}

func TestPeerGroupsRejectInvalidMembership(t *testing.T) {
	for _, replacement := range []string{
		`[{"name":"appnet","members":["web","unknown"]}]`,
		`[{"name":"appnet","members":["web","web"]}]`,
		`[{"name":"appnet","members":[]}]`,
		`[{"name":"Bad_Name","members":["web","db"]}]`,
		`[{"name":"appnet","members":["web"]},{"name":"appnet","members":["db"]}]`,
	} {
		body := strings.Replace(peerNetworkJSON, `[{"name":"appnet","members":["web","db"]}]`, replacement, 1)
		if err := ValidateWorkloadNetwork(decodePeerNetwork(t, body), WorkloadProfileWeb, peerNetworkRequirements()); err == nil {
			t.Fatalf("invalid membership accepted: %s", replacement)
		}
	}
}

func TestExactEgressRejectsInvalidDestinationsSourcesAndPorts(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "10.20.30.40/24", "10.20.30.40", "127.0.0.1/32", "169.254.169.254/32", "224.0.0.1/32", "0.0.0.0/32", "255.255.255.255/32", "192.0.2.1/32", "198.51.100.1/32", "203.0.113.1/32", "::/128", "::1/128", "fe80::1/128", "ff02::1/128", "2001:db8::1/128", "3fff::1/128", "::ffff:10.20.30.40/128", "fd00:0:0:0::1/128"} {
		body := strings.Replace(peerNetworkJSON, "10.20.30.40/32", cidr, 1)
		if err := ValidateWorkloadNetwork(decodePeerNetwork(t, body), WorkloadProfileWeb, peerNetworkRequirements()); err == nil {
			t.Errorf("invalid destination accepted: %s", cidr)
		}
	}
	for _, rule := range []string{`{"from":"unknown","cidr":"10.20.30.40/32","ports":[443]}`, `{"from":"web","cidr":"10.20.30.40/32","ports":[]}`, `{"from":"web","cidr":"10.20.30.40/32","ports":[0]}`, `{"from":"web","cidr":"10.20.30.40/32","ports":[65536]}`, `{"from":"web","cidr":"10.20.30.40/32","ports":[443,443]}`, `{"from":"web","cidr":"10.20.30.40/32","ports":[443]},{"from":"web","cidr":"10.20.30.40/32","ports":[443]}`} {
		body := strings.Replace(peerNetworkJSON, `{"from":"web","cidr":"10.20.30.40/32","ports":[443]}`, rule, 1)
		if err := ValidateWorkloadNetwork(decodePeerNetwork(t, body), WorkloadProfileWeb, peerNetworkRequirements()); err == nil {
			t.Errorf("invalid egress accepted: %s", rule)
		}
	}
}

func TestExactEgressAllowsCanonicalPrivateAndPublicUnicastHosts(t *testing.T) {
	for _, cidr := range []string{"10.20.30.40/32", "100.64.1.2/32", "1.1.1.1/32", "fd00::1/128", "2606:4700:4700::1111/128"} {
		body := strings.Replace(peerNetworkJSON, "10.20.30.40/32", cidr, 1)
		if err := ValidateWorkloadNetwork(decodePeerNetwork(t, body), WorkloadProfileWeb, peerNetworkRequirements()); err != nil {
			t.Errorf("valid exact host %s: %v", cidr, err)
		}
	}
}
