package k3s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/client-go/util/flowcontrol"
)

func TestLifecycleClientsShareBoundedBudgetAcrossAPIGroupsAndCredentialForms(t *testing.T) {
	raw := []byte(`{"apiVersion":"v1","kind":"Config","clusters":[{"name":"target","cluster":{"server":"https://127.0.0.1:6443"}}],"users":[{"name":"operator","user":{"token":"synthetic-client-budget-test"}}],"contexts":[{"name":"target","context":{"cluster":"target","user":"operator"}}],"current-context":"target"}`)
	for _, inline := range []bool{false, true} {
		t.Run(fmt.Sprint("inline=", inline), func(t *testing.T) {
			var clients ClientSet
			var err error
			if inline {
				clients, err = (KubeconfigClientFactory{}).FromKubeconfigData(raw)
			} else {
				path := filepath.Join(t.TempDir(), "kubeconfig")
				if err = os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				clients, err = (KubeconfigClientFactory{}).FromKubeconfig(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			core := clients.Kubernetes.CoreV1().RESTClient().GetRateLimiter()
			metrics := clients.Metrics.MetricsV1beta1().RESTClient().GetRateLimiter()
			if core != metrics || core.QPS() != 20 {
				t.Fatal("API groups must share one bounded lifecycle request budget")
			}
			for i := 0; i < 40; i++ {
				if ![]flowcontrol.RateLimiter{core, metrics}[i%2].TryAccept() {
					t.Fatalf("initial bounded burst ended at request %d", i)
				}
			}
			if core.TryAccept() || metrics.TryAccept() {
				t.Fatal("metrics bypassed the shared burst limit")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := metrics.Wait(ctx); err != nil {
				t.Fatalf("budget did not replenish: %v", err)
			}
		})
	}
}
