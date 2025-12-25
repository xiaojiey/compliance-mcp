package compliance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// ComplianceClient wraps Kubernetes clients for compliance resources
type ComplianceClient struct {
	dynamicClient dynamic.Interface
	kubeClient    kubernetes.Interface
	namespace     string
}

// GVRs for compliance resources
var (
	ComplianceSuiteGVR = schema.GroupVersionResource{
		Group:    "compliance.openshift.io",
		Version:  "v1alpha1",
		Resource: "compliancesuites",
	}
	ComplianceScanGVR = schema.GroupVersionResource{
		Group:    "compliance.openshift.io",
		Version:  "v1alpha1",
		Resource: "compliancescans",
	}
	ComplianceCheckResultGVR = schema.GroupVersionResource{
		Group:    "compliance.openshift.io",
		Version:  "v1alpha1",
		Resource: "compliancecheckresults",
	}
	ComplianceRemediationGVR = schema.GroupVersionResource{
		Group:    "compliance.openshift.io",
		Version:  "v1alpha1",
		Resource: "complianceremediations",
	}
)

// NewComplianceClient creates a new compliance client
func NewComplianceClient(namespace string) (*ComplianceClient, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &ComplianceClient{
		dynamicClient: dynamicClient,
		kubeClient:    kubeClient,
		namespace:     namespace,
	}, nil
}

// getKubeConfig gets the Kubernetes config from various sources
func getKubeConfig() (*rest.Config, error) {
	// Try KUBECONFIG env var first
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err == nil {
			return config, nil
		}
	}

	// Try ~/.kube/config
	if home := homedir.HomeDir(); home != "" {
		kubeconfig := filepath.Join(home, ".kube", "config")
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err == nil {
			return config, nil
		}
	}

	// Try in-cluster config
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	return nil, fmt.Errorf("failed to find kubeconfig")
}

// GetComplianceSuites returns all compliance suites in the namespace
func (c *ComplianceClient) GetComplianceSuites(ctx context.Context) ([]ComplianceSuite, error) {
	list, err := c.dynamicClient.Resource(ComplianceSuiteGVR).Namespace(c.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list compliance suites: %w", err)
	}

	suites := make([]ComplianceSuite, 0, len(list.Items))
	for _, item := range list.Items {
		suite, err := unstructuredToComplianceSuite(&item)
		if err != nil {
			continue
		}
		suites = append(suites, suite)
	}

	return suites, nil
}

// GetComplianceSuite returns a specific compliance suite
func (c *ComplianceClient) GetComplianceSuite(ctx context.Context, name string) (*ComplianceSuite, error) {
	obj, err := c.dynamicClient.Resource(ComplianceSuiteGVR).Namespace(c.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance suite %s: %w", name, err)
	}

	suite, err := unstructuredToComplianceSuite(obj)
	if err != nil {
		return nil, err
	}

	return &suite, nil
}

// GetComplianceScans returns scans for a specific suite or all scans
func (c *ComplianceClient) GetComplianceScans(ctx context.Context, suiteLabel string) ([]ComplianceScan, error) {
	listOpts := metav1.ListOptions{}
	if suiteLabel != "" {
		listOpts.LabelSelector = fmt.Sprintf("%s=%s", SuiteLabel, suiteLabel)
	}

	list, err := c.dynamicClient.Resource(ComplianceScanGVR).Namespace(c.namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list compliance scans: %w", err)
	}

	scans := make([]ComplianceScan, 0, len(list.Items))
	for _, item := range list.Items {
		scan, err := unstructuredToComplianceScan(&item)
		if err != nil {
			continue
		}
		scans = append(scans, scan)
	}

	return scans, nil
}

// GetComplianceScan returns a specific compliance scan
func (c *ComplianceClient) GetComplianceScan(ctx context.Context, name string) (*ComplianceScan, error) {
	obj, err := c.dynamicClient.Resource(ComplianceScanGVR).Namespace(c.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance scan %s: %w", name, err)
	}

	scan, err := unstructuredToComplianceScan(obj)
	if err != nil {
		return nil, err
	}

	return &scan, nil
}

// GetComplianceCheckResults returns check results for a scan
func (c *ComplianceClient) GetComplianceCheckResults(ctx context.Context, scanName string, statusFilter string) ([]ComplianceCheckResult, error) {
	listOpts := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", ScanLabel, scanName),
	}

	if statusFilter != "" {
		listOpts.LabelSelector = fmt.Sprintf("%s,%s=%s", listOpts.LabelSelector, "compliance.openshift.io/check-status", statusFilter)
	}

	list, err := c.dynamicClient.Resource(ComplianceCheckResultGVR).Namespace(c.namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list check results: %w", err)
	}

	results := make([]ComplianceCheckResult, 0, len(list.Items))
	for _, item := range list.Items {
		result, err := unstructuredToCheckResult(&item)
		if err != nil {
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

// GetComplianceRemediations returns remediations for a scan
func (c *ComplianceClient) GetComplianceRemediations(ctx context.Context, scanName string) ([]ComplianceRemediation, error) {
	listOpts := metav1.ListOptions{}
	if scanName != "" {
		listOpts.LabelSelector = fmt.Sprintf("%s=%s", ScanLabel, scanName)
	}

	list, err := c.dynamicClient.Resource(ComplianceRemediationGVR).Namespace(c.namespace).List(ctx, listOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to list remediations: %w", err)
	}

	remediations := make([]ComplianceRemediation, 0, len(list.Items))
	for _, item := range list.Items {
		remediation, err := unstructuredToRemediation(&item)
		if err != nil {
			continue
		}
		remediations = append(remediations, remediation)
	}

	return remediations, nil
}

// GetOperatorPods returns compliance operator pods
func (c *ComplianceClient) GetOperatorPods(ctx context.Context) ([]corev1.Pod, error) {
	pods, err := c.kubeClient.CoreV1().Pods(c.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "name=compliance-operator",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list operator pods: %w", err)
	}

	return pods.Items, nil
}

// GetScannerPods returns scanner pods for a specific scan
func (c *ComplianceClient) GetScannerPods(ctx context.Context, scanName string) ([]corev1.Pod, error) {
	pods, err := c.kubeClient.CoreV1().Pods(c.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s,workload=scanner", ScanLabel, scanName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list scanner pods: %w", err)
	}

	return pods.Items, nil
}

// GetPodLogs returns logs from a specific pod
func (c *ComplianceClient) GetPodLogs(ctx context.Context, podName string, tailLines int64) (string, error) {
	req := c.kubeClient.CoreV1().Pods(c.namespace).GetLogs(podName, &corev1.PodLogOptions{
		TailLines: &tailLines,
	})

	logs, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get pod logs: %w", err)
	}
	defer logs.Close()

	buf := make([]byte, 1024*1024) // 1MB buffer
	n, _ := logs.Read(buf)

	return string(buf[:n]), nil
}

// GetEvents returns events for a specific object
func (c *ComplianceClient) GetEvents(ctx context.Context, objectKind, objectName string) ([]corev1.Event, error) {
	events, err := c.kubeClient.CoreV1().Events(c.namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.kind=%s,involvedObject.name=%s", objectKind, objectName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list events: %w", err)
	}

	return events.Items, nil
}

// Helper functions to convert unstructured to typed objects

func unstructuredToComplianceSuite(obj *unstructured.Unstructured) (ComplianceSuite, error) {
	suite := ComplianceSuite{
		TypeMeta: metav1.TypeMeta{
			Kind:       obj.GetKind(),
			APIVersion: obj.GetAPIVersion(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
			Labels:    obj.GetLabels(),
		},
	}

	// Extract spec
	if spec, found, _ := unstructured.NestedMap(obj.Object, "spec"); found {
		suite.Spec.AutoApplyRemediations, _, _ = unstructured.NestedBool(spec, "autoApplyRemediations")
		suite.Spec.Schedule, _, _ = unstructured.NestedString(spec, "schedule")
	}

	// Extract status
	if status, found, _ := unstructured.NestedMap(obj.Object, "status"); found {
		phase, _, _ := unstructured.NestedString(status, "phase")
		suite.Status.Phase = ComplianceScanPhase(phase)

		result, _, _ := unstructured.NestedString(status, "result")
		suite.Status.Result = ComplianceScanResult(result)

		suite.Status.ErrorMessage, _, _ = unstructured.NestedString(status, "errorMessage")
	}

	return suite, nil
}

func unstructuredToComplianceScan(obj *unstructured.Unstructured) (ComplianceScan, error) {
	scan := ComplianceScan{
		TypeMeta: metav1.TypeMeta{
			Kind:       obj.GetKind(),
			APIVersion: obj.GetAPIVersion(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
			Labels:    obj.GetLabels(),
		},
	}

	// Extract spec
	if spec, found, _ := unstructured.NestedMap(obj.Object, "spec"); found {
		scanType, _, _ := unstructured.NestedString(spec, "scanType")
		scan.Spec.ScanType = ComplianceScanType(scanType)
		scan.Spec.Profile, _, _ = unstructured.NestedString(spec, "profile")
		scan.Spec.Content, _, _ = unstructured.NestedString(spec, "content")
	}

	// Extract status
	if status, found, _ := unstructured.NestedMap(obj.Object, "status"); found {
		phase, _, _ := unstructured.NestedString(status, "phase")
		scan.Status.Phase = ComplianceScanPhase(phase)

		result, _, _ := unstructured.NestedString(status, "result")
		scan.Status.Result = ComplianceScanResult(result)

		scan.Status.ErrorMessage, _, _ = unstructured.NestedString(status, "errorMessage")
	}

	return scan, nil
}

func unstructuredToCheckResult(obj *unstructured.Unstructured) (ComplianceCheckResult, error) {
	result := ComplianceCheckResult{
		TypeMeta: metav1.TypeMeta{
			Kind:       obj.GetKind(),
			APIVersion: obj.GetAPIVersion(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
			Labels:    obj.GetLabels(),
		},
	}

	result.ID, _, _ = unstructured.NestedString(obj.Object, "id")

	status, _, _ := unstructured.NestedString(obj.Object, "status")
	result.Status = ComplianceCheckStatus(status)

	result.Severity, _, _ = unstructured.NestedString(obj.Object, "severity")
	result.Description, _, _ = unstructured.NestedString(obj.Object, "description")
	result.Instructions, _, _ = unstructured.NestedString(obj.Object, "instructions")

	return result, nil
}

func unstructuredToRemediation(obj *unstructured.Unstructured) (ComplianceRemediation, error) {
	remediation := ComplianceRemediation{
		TypeMeta: metav1.TypeMeta{
			Kind:       obj.GetKind(),
			APIVersion: obj.GetAPIVersion(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      obj.GetName(),
			Namespace: obj.GetNamespace(),
			Labels:    obj.GetLabels(),
		},
	}

	if spec, found, _ := unstructured.NestedMap(obj.Object, "spec"); found {
		remediation.Spec.Apply, _, _ = unstructured.NestedBool(spec, "apply")
	}

	if status, found, _ := unstructured.NestedMap(obj.Object, "status"); found {
		remediation.Status.ApplicationState, _, _ = unstructured.NestedString(status, "applicationState")
	}

	return remediation, nil
}
