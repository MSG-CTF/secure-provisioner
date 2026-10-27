package k3s

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type BrokerClientFactory interface {
	FromKubeconfigData([]byte) (ClientSet, error)
}

type BrokerSyncConfig struct {
	BaseURL, TokenFile, PolicyPath, StateDirectory string
	Interval, RequestTimeout, SyncTimeout          time.Duration
	HTTPClient                                     *http.Client
	Factory                                        BrokerClientFactory
	ReadOnly                                       bool
}

type brokerPolicy struct {
	Provider             Provider                      `json:"provider,omitempty"`
	Region               string                        `json:"region,omitempty"`
	Enabled              *bool                         `json:"enabled"`
	GatewayEnabled       bool                          `json:"gateway_enabled,omitempty"`
	SecurityCapabilities *registrySecurityCapabilities `json:"security_capabilities"`
}

type BrokerSyncResult struct{ Added, Skipped, Rejected int }

var errBrokerTargetExists = brokerError("BROKER_TARGET_ALREADY_REGISTERED")

type BrokerSync struct {
	mu       sync.Mutex
	registry *Registry
	config   BrokerSyncConfig
	policy   brokerPolicy
	http     *http.Client
	state    map[string]brokerStateEntry
}

func NewBrokerSync(registry *Registry, config BrokerSyncConfig) (*BrokerSync, error) {
	if registry == nil || config.TokenFile == "" || config.PolicyPath == "" || config.StateDirectory == "" {
		return nil, brokerError("BROKER_CONFIGURATION_INCOMPLETE")
	}
	if _, err := brokerHTTPS(config.BaseURL); err != nil {
		return nil, err
	}
	if config.Interval == 0 {
		config.Interval = time.Hour
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Second
	}
	if config.SyncTimeout == 0 {
		config.SyncTimeout = 2 * time.Minute
	}
	if config.Interval < 0 || config.RequestTimeout < 0 || config.SyncTimeout < 0 {
		return nil, brokerError("BROKER_INVALID_TIMEOUT")
	}
	if config.Factory == nil {
		config.Factory = KubeconfigClientFactory{}
	}
	var policy brokerPolicy
	raw, err := os.ReadFile(config.PolicyPath)
	if err != nil {
		return nil, brokerError("BROKER_POLICY_UNAVAILABLE")
	}
	if err := brokerJSON(raw, &policy, true); err != nil {
		return nil, err
	}
	caps := policy.SecurityCapabilities
	if policy.Enabled == nil || caps == nil || caps.NetworkPolicyEnforced == nil || caps.SupplementalGroupsPolicyStrict == nil || caps.PodPIDLimitEnforced == nil || !validSecurityCapabilities(caps.clusterCapabilities(), ExposureModeNodePort) {
		return nil, brokerError("BROKER_EXPLICIT_FLEET_POLICY_REQUIRED")
	}
	if err := privateBrokerDirectory(config.StateDirectory, !config.ReadOnly); err != nil {
		return nil, err
	}
	state, err := loadBrokerState(config.StateDirectory)
	if err != nil {
		return nil, err
	}
	client := &http.Client{}
	if config.HTTPClient != nil {
		*client = *config.HTTPClient
	}
	client.Timeout = config.RequestTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s := &BrokerSync{registry: registry, config: config, policy: policy, http: client, state: state}
	targets := registry.snapshot()
	for id, entry := range state {
		if id != entry.Config.TargetID || id != entry.Credential.TargetID || entry.Config.BrokerResourceTargetID != entry.Credential.ResourceID {
			return nil, brokerError("BROKER_STATE_IDENTITY_MISMATCH")
		}
		if existing, ok := targets[id]; ok {
			if existing.Config.BrokerResourceTargetID != "" && existing.Config.BrokerResourceTargetID != entry.Credential.ResourceID {
				return nil, brokerError("BROKER_TARGET_ID_CONFLICT")
			}
			continue
		}
		raw, err := verifiedBrokerConfig(entry.Credential, false)
		if err != nil {
			return nil, err
		}
		clients, err := config.Factory.FromKubeconfigData(raw)
		if err != nil || clients.Kubernetes == nil || clients.Metrics == nil {
			return nil, brokerError("BROKER_STATE_CLIENT_UNAVAILABLE")
		}
		cfg := entry.Config
		if config.ReadOnly {
			cfg.Enabled = false
		}
		if _, err := validateClusterConfig(cfg, map[string]struct{}{}); err != nil {
			return nil, brokerError("BROKER_STATE_POLICY_INVALID")
		}
		targets[id] = Cluster{Config: cfg, Client: clients.Kubernetes, Metrics: clients.Metrics, restConfig: cloneRESTConfig(clients.restConfig)}
	}
	registry.replaceSnapshot(targets)
	return s, nil
}

func (s *BrokerSync) RequiresGateway() bool { return s.policy.GatewayEnabled }

func (s *BrokerSync) list(ctx context.Context) ([]json.RawMessage, error) {
	token, err := os.ReadFile(s.config.TokenFile)
	if err != nil {
		return nil, brokerError("BROKER_TOKEN_UNAVAILABLE")
	}
	value := strings.TrimSpace(string(token))
	if len(value) < 32 || strings.ContainsAny(value, " \t\r\n") {
		return nil, brokerError("BROKER_INVALID_RUNTIME_TOKEN")
	}
	var result []json.RawMessage
	totalBytes := 0
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		u, _ := url.Parse(strings.TrimRight(s.config.BaseURL, "/") + "/v1/runtime/k3s-credentials")
		query := url.Values{"limit": {"50"}}
		if cursor != "" {
			query.Set("after", cursor)
		}
		u.RawQuery = query.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, brokerError("BROKER_REQUEST_FAILED")
		}
		request.Header.Set("Authorization", "Bearer "+value)
		request.Header.Set("Accept", "application/json")
		response, err := s.http.Do(request)
		if err != nil {
			return nil, brokerError("BROKER_UNAVAILABLE")
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024*1024+1))
		response.Body.Close()
		if response.StatusCode != http.StatusOK || readErr != nil || len(raw) > 64*1024*1024 {
			return nil, brokerError("BROKER_CREDENTIAL_LIST_REJECTED")
		}
		totalBytes += len(raw)
		if totalBytes > 128*1024*1024 {
			return nil, brokerError("BROKER_CREDENTIAL_LIST_TOO_LARGE")
		}
		var body struct {
			Items      *[]json.RawMessage `json:"items"`
			NextCursor *string            `json:"next_cursor"`
		}
		if err := brokerJSON(raw, &body, false); err != nil || body.Items == nil {
			return nil, brokerError("BROKER_INVALID_CREDENTIAL_LIST")
		}
		result = append(result, (*body.Items)...)
		if body.NextCursor == nil {
			return result, nil
		}
		cursor = *body.NextCursor
		if cursor == "" || len(cursor) > 1024 || seen[cursor] {
			return nil, brokerError("BROKER_INVALID_PAGINATION")
		}
		seen[cursor] = true
	}
	return nil, brokerError("BROKER_PAGINATION_LIMIT")
}

func (s *BrokerSync) prepare(ctx context.Context, credential brokerCredential, snapshot map[string]Cluster) (brokerStateEntry, Cluster, error) {
	fail := func() (brokerStateEntry, Cluster, error) {
		return brokerStateEntry{}, Cluster{}, brokerError("BROKER_TARGET_REJECTED")
	}
	if ctx.Err() != nil {
		return fail()
	}
	raw, err := verifiedBrokerConfig(credential, true)
	if err != nil {
		return fail()
	}
	clients, err := s.config.Factory.FromKubeconfigData(raw)
	if err != nil || clients.Kubernetes == nil || clients.Metrics == nil {
		return fail()
	}
	nodeCtx, cancel := context.WithTimeout(ctx, s.config.RequestTimeout)
	defer cancel()
	nodes, err := clients.Kubernetes.CoreV1().Nodes().List(nodeCtx, metav1.ListOptions{Limit: 2})
	if err != nil || len(nodes.Items) != 1 || nodes.Continue != "" {
		return fail()
	}
	node := nodes.Items[0]
	id := string(node.UID)
	ready := false
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready || !brokerUUID(id) || (credential.TargetID != "" && credential.TargetID != id) {
		return fail()
	}
	credential.TargetID = id
	if legacy, ok := snapshot[credential.ResourceID]; ok && legacy.Config.TargetID != id {
		return fail()
	}
	if existing, ok := snapshot[id]; ok {
		if existing.Config.BrokerResourceTargetID != "" && existing.Config.BrokerResourceTargetID != credential.ResourceID {
			return fail()
		}
		return brokerStateEntry{}, Cluster{}, errBrokerTargetExists
	}
	cfg := ClusterConfig{TargetID: id, BrokerResourceTargetID: credential.ResourceID, Enabled: *s.policy.Enabled, Provider: s.policy.Provider, Region: s.policy.Region, ExposureMode: ExposureModeNodePort, SecurityCapabilities: s.policy.SecurityCapabilities.clusterCapabilities()}
	{
		switch strings.SplitN(node.Spec.ProviderID, ":", 2)[0] {
		case "gce", "gcp":
			cfg.Provider = ProviderGCP
		case "aws":
			cfg.Provider = ProviderAWS
		case "ncp", "ncloud":
			cfg.Provider = ProviderNCP
		}
	}
	if region := node.Labels[corev1.LabelTopologyRegion]; region != "" {
		cfg.Region = region
	}
	cfg.Architecture = strings.ToLower(node.Status.NodeInfo.Architecture)
	if cfg.Architecture != "amd64" && cfg.Architecture != "arm64" {
		return fail()
	}
	cfg.TargetID = id
	cfg.BrokerResourceTargetID = credential.ResourceID
	cfg.KubeconfigPath = "broker://" + credential.ResourceID + "/" + id
	server, _ := url.Parse(credential.ServerURL)
	if cfg.ExposureMode == ExposureModeNodePort {
		host := server.Hostname()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		cfg.PublicGateway = (&url.URL{Scheme: "http", Host: host}).String()
		if s.policy.GatewayEnabled {
			cfg.Gateway = &GatewayConfig{Enabled: true, UpstreamIP: server.Hostname()}
		}
	}
	normalized, err := validateClusterConfig(cfg, map[string]struct{}{})
	if err != nil {
		return fail()
	}
	entry := brokerStateEntry{Config: normalized, Credential: credential, DesiredEnabled: normalized.Enabled}
	return entry, Cluster{Config: normalized, Client: clients.Kubernetes, Metrics: clients.Metrics, restConfig: cloneRESTConfig(clients.restConfig)}, nil
}

// Sync enrolls only resources not already registered. Existing credentials,
// policy, clients and eligibility are preserved, including missing resources.
func (s *BrokerSync) Sync(ctx context.Context) (BrokerSyncResult, error) {
	if s.config.ReadOnly {
		return BrokerSyncResult{}, brokerError("BROKER_DISCOVERY_READ_ONLY")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, s.config.SyncTimeout)
	defer cancel()
	items, err := s.list(ctx)
	if err != nil {
		return BrokerSyncResult{}, err
	}
	result := BrokerSyncResult{}
	snapshot := s.registry.snapshot()
	known := make(map[string]bool, len(snapshot))
	for _, cluster := range snapshot {
		if cluster.Config.BrokerResourceTargetID != "" {
			known[cluster.Config.BrokerResourceTargetID] = true
		}
	}
	for _, entry := range s.state {
		known[entry.Credential.ResourceID] = true
	}
	credentials := make([]brokerCredential, 0, len(items))
	seenResources := map[string]bool{}
	for _, raw := range items {
		var credential brokerCredential
		if err := brokerJSON(raw, &credential, false); err != nil || !brokerUUID(credential.ResourceID) {
			result.Rejected++
			continue
		}
		if seenResources[credential.ResourceID] {
			return BrokerSyncResult{}, brokerError("BROKER_DUPLICATE_RESOURCE")
		}
		seenResources[credential.ResourceID] = true
		if known[credential.ResourceID] {
			result.Skipped++
			continue
		}
		if existing, ok := snapshot[credential.TargetID]; ok {
			if existing.Config.BrokerResourceTargetID != "" && existing.Config.BrokerResourceTargetID != credential.ResourceID {
				result.Rejected++
			} else {
				result.Skipped++
			}
			continue
		}
		credentials = append(credentials, credential)
	}
	next := make(map[string]brokerStateEntry, len(s.state)+len(credentials))
	for id, entry := range s.state {
		next[id] = entry
	}
	type prepared struct {
		entry   brokerStateEntry
		cluster Cluster
		err     error
	}
	jobs := make(chan brokerCredential, len(credentials))
	results := make(chan prepared, len(credentials))
	for _, credential := range credentials {
		jobs <- credential
	}
	close(jobs)
	var workers sync.WaitGroup
	for n := 0; n < min(4, len(credentials)); n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for credential := range jobs {
				entry, cluster, err := s.prepare(ctx, credential, snapshot)
				results <- prepared{entry, cluster, err}
			}
		}()
	}
	workers.Wait()
	close(results)
	seenNodes := map[string]bool{}
	readyClusters := map[string]Cluster{}
	for prepared := range results {
		if prepared.err == errBrokerTargetExists {
			result.Skipped++
			continue
		}
		if prepared.err != nil {
			result.Rejected++
			continue
		}
		id := prepared.entry.Config.TargetID
		if seenNodes[id] {
			return BrokerSyncResult{}, brokerError("BROKER_DUPLICATE_NODE")
		}
		seenNodes[id] = true
		next[id] = prepared.entry
		readyClusters[id] = prepared.cluster
		result.Added++
	}
	if ctx.Err() != nil {
		return BrokerSyncResult{}, brokerError("BROKER_SYNC_CANCELLED")
	}
	if result.Added == 0 {
		return result, nil
	}
	for id, cluster := range readyClusters {
		snapshot[id] = cluster
	}
	if err := saveBrokerState(s.config.StateDirectory, next); err != nil {
		return BrokerSyncResult{}, err
	}
	s.state = next
	s.registry.replaceSnapshot(snapshot)
	return result, nil
}

func (s *BrokerSync) Run(ctx context.Context, report func(BrokerSyncResult, error)) {
	if s.config.ReadOnly {
		return
	}
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := s.Sync(ctx)
			if report != nil && ctx.Err() == nil {
				report(result, err)
			}
		}
	}
}
