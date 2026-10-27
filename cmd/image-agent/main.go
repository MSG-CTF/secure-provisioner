// image-agent is invoked by a trusted local/SSH command; it never starts a pod.
package main

import (
	"context"
	"encoding/json"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--idle" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		<-ctx.Done()
		return
	}
	response := run()
	_ = json.NewEncoder(os.Stdout).Encode(response)
}
func run() imageprep.AgentResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	kubernetesMode := len(os.Args) == 2 && os.Args[1] == "--kubernetes"
	var client kubernetes.Interface
	var config struct {
		NodeUID   string `json:"node_uid"`
		K3sBinary string `json:"k3s_binary"`
	}
	if kubernetesMode {
		cfg, err := rest.InClusterConfig()
		if err != nil {
			return imageprep.AgentResponse{ErrorCode: "AGENT_UNAVAILABLE"}
		}
		client, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			return imageprep.AgentResponse{ErrorCode: "AGENT_UNAVAILABLE"}
		}
		config.K3sBinary = "/host-bin/k3s"
	} else {
		file, err := os.Open("/etc/secure-provisioner/image-agent.json")
		if err != nil {
			return imageprep.AgentResponse{ErrorCode: "AGENT_UNAVAILABLE"}
		}
		defer file.Close()
		d := json.NewDecoder(io.LimitReader(file, 64<<10))
		d.DisallowUnknownFields()
		if d.Decode(&config) != nil || config.NodeUID == "" || !strings.HasPrefix(config.K3sBinary, "/") {
			return imageprep.AgentResponse{ErrorCode: "AGENT_UNAVAILABLE"}
		}
	}
	var request imageprep.AgentRequest
	d := json.NewDecoder(io.LimitReader(os.Stdin, 64<<10))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
		return imageprep.AgentResponse{ErrorCode: "AGENT_UNAVAILABLE"}
	}
	agent := imageprep.Agent{Commands: imageprep.ExecCommands{Binary: config.K3sBinary}, Identity: func() (imageprep.AgentIdentity, error) {
		machinePath, bootPath := "/etc/machine-id", "/proc/sys/kernel/random/boot_id"
		if kubernetesMode {
			machinePath, bootPath = "/host-identity/machine-id", "/host-identity/boot-id"
		}
		machine, err := os.ReadFile(machinePath)
		if err != nil {
			return imageprep.AgentIdentity{}, err
		}
		boot, err := os.ReadFile(bootPath)
		if err != nil {
			return imageprep.AgentIdentity{}, err
		}
		identity := imageprep.AgentIdentity{NodeUID: config.NodeUID, MachineID: strings.TrimSpace(string(machine)), BootID: strings.TrimSpace(string(boot)), OS: runtime.GOOS, Architecture: strings.ToUpper(runtime.GOARCH)}
		if kubernetesMode {
			return kubernetesIdentity(ctx, client, os.Getenv("NODE_NAME"), identity)
		}
		return identity, nil
	}}
	e, err := agent.Prepare(ctx, request)
	if err != nil {
		return imageprep.AgentResponse{ErrorCode: imageprep.ErrorCode(err)}
	}
	return imageprep.AgentResponse{Evidence: &e}
}

func kubernetesIdentity(ctx context.Context, client kubernetes.Interface, name string, actual imageprep.AgentIdentity) (imageprep.AgentIdentity, error) {
	node, err := client.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return imageprep.AgentIdentity{}, imageprep.Failure{Code: "AGENT_UNAVAILABLE"}
	}
	info := node.Status.NodeInfo
	if node.UID == "" || actual.MachineID == "" || actual.BootID == "" || info.MachineID != actual.MachineID || info.BootID != actual.BootID || info.OperatingSystem != actual.OS || !strings.EqualFold(info.Architecture, actual.Architecture) {
		return imageprep.AgentIdentity{}, imageprep.Failure{Code: "NODE_IDENTITY_MISMATCH"}
	}
	actual.NodeUID = string(node.UID)
	return actual, nil
}
