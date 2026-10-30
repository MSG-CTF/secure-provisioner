package k3s

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/MSG-CTF/secure-provisioner/internal/imageprep"
	"io"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"strings"
)

func selectImageAgent(ctx context.Context, client kubernetes.Interface, target imageprep.AgentTarget, n imageprep.Node) (string, error) {
	failure := imageprep.Failure{Code: "AGENT_UNAVAILABLE"}
	current, err := client.CoreV1().Nodes().Get(ctx, n.Name, metav1.GetOptions{})
	if err != nil {
		return "", failure
	}
	info := current.Status.NodeInfo
	if string(current.UID) != n.UID || info.MachineID != n.MachineID || info.BootID != n.BootID || info.OperatingSystem != "linux" || !strings.EqualFold(info.Architecture, n.Architecture) {
		return "", imageprep.Failure{Code: "NODE_IDENTITY_MISMATCH"}
	}
	pods, err := client.CoreV1().Pods(target.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=runtime-image-agent", FieldSelector: "spec.nodeName=" + n.Name})
	if err != nil {
		return "", failure
	}
	selected := ""
	for _, pod := range pods.Items {
		if pod.Spec.NodeName != n.Name || pod.DeletionTimestamp != nil || pod.UID == "" || pod.Status.Phase != corev1.PodRunning || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "agent" || pod.Spec.Containers[0].Image != target.AgentImage {
			continue
		}
		ready := false
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				ready = true
			}
		}
		if ready {
			if selected != "" {
				return "", failure
			}
			selected = pod.Name
		}
	}
	if selected == "" {
		return "", failure
	}
	return selected, nil
}

type limitedAgentOutput struct{ bytes.Buffer }

func (b *limitedAgentOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 64<<10 {
		return 0, imageprep.Failure{Code: "AGENT_UNAVAILABLE"}
	}
	return b.Buffer.Write(p)
}
func KubernetesImageRunner(registry *Registry) func(context.Context, imageprep.AgentTarget, imageprep.Node, imageprep.AgentRequest) (imageprep.Evidence, error) {
	return func(ctx context.Context, target imageprep.AgentTarget, n imageprep.Node, input imageprep.AgentRequest) (imageprep.Evidence, error) {
		failure := imageprep.Failure{Code: "AGENT_UNAVAILABLE"}
		cluster, err := registry.LookupForCreate(n.TargetID)
		if err != nil {
			return imageprep.Evidence{}, failure
		}
		pod, err := selectImageAgent(ctx, cluster.Client, target, n)
		if err != nil {
			return imageprep.Evidence{}, err
		}
		config := cloneRESTConfig(cluster.restConfig)
		if config == nil {
			// Broker locations identify inline credentials, never local files.
			if strings.HasPrefix(cluster.Config.KubeconfigPath, "broker:") {
				return imageprep.Evidence{}, failure
			}
			config, err = clientcmd.BuildConfigFromFlags("", cluster.Config.KubeconfigPath)
			if err != nil {
				return imageprep.Evidence{}, failure
			}
		}
		if config.Insecure {
			return imageprep.Evidence{}, failure
		}
		client, err := kubernetes.NewForConfig(config)
		if err != nil {
			return imageprep.Evidence{}, failure
		}
		request := client.CoreV1().RESTClient().Post().Resource("pods").Namespace(target.Namespace).Name(pod).SubResource("exec").VersionedParams(&corev1.PodExecOptions{Container: "agent", Command: []string{"/usr/local/bin/image-agent", "--kubernetes"}, Stdin: true, Stdout: true, Stderr: true, TTY: false}, scheme.ParameterCodec)
		executor, err := remotecommand.NewSPDYExecutor(config, "POST", request.URL())
		if err != nil {
			return imageprep.Evidence{}, failure
		}
		body, _ := json.Marshal(input)
		out := &limitedAgentOutput{}
		if err := executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: bytes.NewReader(body), Stdout: out, Stderr: io.Discard, Tty: false}); err != nil {
			if ctx.Err() != nil {
				return imageprep.Evidence{}, imageprep.Failure{Code: "NETWORK_TIMEOUT"}
			}
			return imageprep.Evidence{}, failure
		}
		var result imageprep.AgentResponse
		decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF {
			return imageprep.Evidence{}, failure
		}
		if result.ErrorCode != "" {
			return imageprep.Evidence{}, imageprep.Failure{Code: imageprep.ErrorCode(imageprep.Failure{Code: result.ErrorCode})}
		}
		if result.Evidence == nil {
			return imageprep.Evidence{}, failure
		}
		return *result.Evidence, nil
	}
}
