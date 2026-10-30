package k3s

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestBrokerDefaultDiscoveryIntervalIsOneHour(t *testing.T) {
	f := newBrokerFixture(t)
	f.config.Interval = 0
	if s := f.controller(); s.config.Interval != time.Hour {
		t.Fatal("default discovery interval must be one hour", s.config.Interval)
	}
}

func TestBrokerAddsNewVMWithoutRefreshingKnownCredentials(t *testing.T) {
	f := newBrokerFixture(t)
	one := f.credential(brokerResource1, brokerNode1, "192.0.2.10")
	f.page("", []map[string]any{one}, nil)
	s := f.controller()
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := f.registry.LookupForCreate(brokerNode1)
	one["client_certificate_fingerprint_sha256"] = "invalid-new-credential-for-existing-vm"
	one["server_url"] = "https://192.0.2.99:6443"
	two := f.credential(brokerResource2, brokerNode2, "192.0.2.20")
	f.page("", []map[string]any{one, two}, nil)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := f.registry.LookupForCreate(brokerNode1)
	if err != nil || before.Client != after.Client || !reflect.DeepEqual(before.Config, after.Config) {
		t.Fatal("existing target or credentials were modified", err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode2); err != nil {
		t.Fatal("new target was not added", err)
	}
	state, err := loadBrokerState(f.config.StateDirectory)
	if err != nil || len(state) != 2 || state[brokerNode1].Credential.Fingerprint != f.fingerprint {
		t.Fatal("existing credential cache was replaced", err)
	}
}

func TestBrokerMissingVMStaysEnabledAndNoOpDoesNotRewriteState(t *testing.T) {
	f := newBrokerFixture(t)
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	s := f.controller()
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := f.registry.LookupForCreate(brokerNode1)
	path := filepath.Join(f.config.StateDirectory, "targets.json")
	data, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	f.page("", nil, nil)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := f.registry.LookupForCreate(brokerNode1)
	if err != nil || before.Client != after.Client || !reflect.DeepEqual(before.Config, after.Config) {
		t.Fatal("a missing VM was disabled or changed", err)
	}
	current, _ := os.ReadFile(path)
	currentInfo, _ := os.Stat(path)
	if string(current) != string(data) || !info.ModTime().Equal(currentInfo.ModTime()) {
		t.Fatal("no additions still rewrote credential state")
	}
}

func TestBrokerAddOnlyRestartKeepsSavedEligibility(t *testing.T) {
	f := newBrokerFixture(t)
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	if _, err := f.controller().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.registry, _ = NewRegistry(nil, nil)
	f.page("", nil, nil)
	f.controller()
	if _, err := f.registry.LookupForCreate(brokerNode1); err != nil {
		t.Fatal("restart changed existing eligibility", err)
	}
}

func TestBrokerAddOnlySkipsFileBackedTargetsWithoutChangingTheirPolicy(t *testing.T) {
	f := newBrokerFixture(t)
	cfg := validClusterConfig(brokerNode1, ProviderGCP, "manual.yaml")
	cfg.BrokerResourceTargetID = brokerResource1
	f.registry, _ = NewRegistry([]ClusterConfig{cfg}, &sequenceFactory{clients: []kubernetes.Interface{fake.NewClientset()}})
	before, _ := f.registry.LookupForCreate(brokerNode1)
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	if _, err := f.controller().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := f.registry.LookupForCreate(brokerNode1)
	if err != nil || before.Client != after.Client || !reflect.DeepEqual(before.Config, after.Config) {
		t.Fatal("file-backed target was modified", err)
	}
	if _, err := os.Stat(filepath.Join(f.config.StateDirectory, "targets.json")); !os.IsNotExist(err) {
		t.Fatal("known file target was reimported into credential state", err)
	}
}

func TestBrokerAddOnlyIgnoresReplacementOfKnownResource(t *testing.T) {
	f := newBrokerFixture(t)
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	s := f.controller()
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode2, "192.0.2.20")}, nil)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode1); err != nil {
		t.Fatal("known resource was replaced", err)
	}
	if _, err := f.registry.LookupForMaintenance(brokerNode2); err == nil {
		t.Fatal("known resource replacement was automatically registered")
	}
}

func TestBrokerAddOnlyDeduplicatesUnmappedFileNodeUID(t *testing.T) {
	for _, advertised := range []bool{false, true} {
		t.Run(map[bool]string{false: "observed", true: "advertised"}[advertised], func(t *testing.T) {
			f := newBrokerFixture(t)
			cfg := validClusterConfig(brokerNode1, ProviderGCP, "manual.yaml")
			f.registry, _ = NewRegistry([]ClusterConfig{cfg}, &sequenceFactory{clients: []kubernetes.Interface{fake.NewClientset()}})
			before, _ := f.registry.LookupForCreate(brokerNode1)
			credential := f.credential(brokerResource1, brokerNode1, "192.0.2.10")
			if !advertised {
				delete(credential, "target_id")
			}
			f.page("", []map[string]any{credential}, nil)
			result, err := f.controller().Sync(context.Background())
			if err != nil || result.Added != 0 || result.Skipped != 1 || result.Rejected != 0 {
				t.Fatal("existing UID was not skipped", result, err)
			}
			after, err := f.registry.LookupForCreate(brokerNode1)
			if err != nil || before.Client != after.Client || !reflect.DeepEqual(before.Config, after.Config) {
				t.Fatal("existing UID was modified", err)
			}
		})
	}
}

func TestBrokerCacheRestoreKeepsFileClientAndExplicitDisable(t *testing.T) {
	f := newBrokerFixture(t)
	f.page("", []map[string]any{f.credential(brokerResource1, brokerNode1, "192.0.2.10")}, nil)
	if _, err := f.controller().Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg := validClusterConfig(brokerNode1, ProviderGCP, "operator-replacement.yaml")
	cfg.Enabled = false
	f.registry, _ = NewRegistry([]ClusterConfig{cfg}, &sequenceFactory{clients: []kubernetes.Interface{fake.NewClientset()}})
	before, _ := f.registry.LookupForMaintenance(brokerNode1)
	f.config.Factory = brokerFactoryFunc(func([]byte) (ClientSet, error) { return ClientSet{}, os.ErrPermission })
	f.controller()
	after, err := f.registry.LookupForMaintenance(brokerNode1)
	if err != nil || before.Client != after.Client || !reflect.DeepEqual(before.Config, after.Config) {
		t.Fatal("cache replaced the file target", err)
	}
	if _, err := f.registry.LookupForCreate(brokerNode1); err == nil {
		t.Fatal("cache overrode operator disable")
	}
}
