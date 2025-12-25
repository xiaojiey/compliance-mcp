package compliance

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// ComplianceData holds comprehensive compliance data from the cluster
type ComplianceData struct {
	Suites         []ComplianceSuite
	Scans          map[string]ComplianceScan
	CheckResults   map[string][]ComplianceCheckResult
	Remediations   map[string][]ComplianceRemediation
	OperatorStatus OperatorHealthStatus
	Timestamp      time.Time
}

// OperatorHealthStatus represents the health of the compliance operator
type OperatorHealthStatus struct {
	OperatorPods []PodStatus
	IsHealthy    bool
	Issues       []string
}

// PodStatus represents a pod's status
type PodStatus struct {
	Name      string
	Phase     corev1.PodPhase
	Reason    string
	Ready     bool
	Restarts  int32
}

// SuiteData holds data for a specific suite
type SuiteData struct {
	Suite        ComplianceSuite
	Scans        []ComplianceScan
	CheckResults map[string][]ComplianceCheckResult
	Remediations map[string][]ComplianceRemediation
}

// CheckCounts holds counts of checks by status
type CheckCounts struct {
	Pass   int
	Fail   int
	Manual int
	Error  int
	Info   int
	Total  int
}

// Collector collects compliance data from the cluster
type Collector struct {
	client *ComplianceClient
}

// NewCollector creates a new collector
func NewCollector(client *ComplianceClient) *Collector {
	return &Collector{client: client}
}

// CollectAllData collects all compliance data from the cluster
func (c *Collector) CollectAllData(ctx context.Context) (*ComplianceData, error) {
	data := &ComplianceData{
		Scans:        make(map[string]ComplianceScan),
		CheckResults: make(map[string][]ComplianceCheckResult),
		Remediations: make(map[string][]ComplianceRemediation),
		Timestamp:    time.Now(),
	}

	// Collect suites
	suites, err := c.client.GetComplianceSuites(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect suites: %w", err)
	}
	data.Suites = suites

	// Collect all scans
	allScans, err := c.client.GetComplianceScans(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to collect scans: %w", err)
	}

	// Organize scans by name and collect their check results and remediations
	for _, scan := range allScans {
		data.Scans[scan.Name] = scan

		// Get check results for this scan
		checkResults, err := c.client.GetComplianceCheckResults(ctx, scan.Name, "")
		if err == nil {
			data.CheckResults[scan.Name] = checkResults
		}

		// Get remediations for this scan
		remediations, err := c.client.GetComplianceRemediations(ctx, scan.Name)
		if err == nil {
			data.Remediations[scan.Name] = remediations
		}
	}

	// Collect operator health status
	operatorStatus, err := c.collectOperatorStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect operator status: %w", err)
	}
	data.OperatorStatus = operatorStatus

	return data, nil
}

// CollectSuiteData collects data for a specific suite
func (c *Collector) CollectSuiteData(ctx context.Context, suiteName string) (*SuiteData, error) {
	// Get the suite
	suite, err := c.client.GetComplianceSuite(ctx, suiteName)
	if err != nil {
		return nil, fmt.Errorf("failed to get suite: %w", err)
	}

	data := &SuiteData{
		Suite:        *suite,
		Scans:        []ComplianceScan{},
		CheckResults: make(map[string][]ComplianceCheckResult),
		Remediations: make(map[string][]ComplianceRemediation),
	}

	// Get scans for this suite
	scans, err := c.client.GetComplianceScans(ctx, suiteName)
	if err != nil {
		return nil, fmt.Errorf("failed to get scans for suite: %w", err)
	}
	data.Scans = scans

	// Collect check results and remediations for each scan
	for _, scan := range scans {
		checkResults, err := c.client.GetComplianceCheckResults(ctx, scan.Name, "")
		if err == nil {
			data.CheckResults[scan.Name] = checkResults
		}

		remediations, err := c.client.GetComplianceRemediations(ctx, scan.Name)
		if err == nil {
			data.Remediations[scan.Name] = remediations
		}
	}

	return data, nil
}

// collectOperatorStatus collects the compliance operator health status
func (c *Collector) collectOperatorStatus(ctx context.Context) (OperatorHealthStatus, error) {
	status := OperatorHealthStatus{
		IsHealthy: true,
		Issues:    []string{},
	}

	// Get operator pods
	pods, err := c.client.GetOperatorPods(ctx)
	if err != nil {
		return status, fmt.Errorf("failed to get operator pods: %w", err)
	}

	if len(pods) == 0 {
		status.IsHealthy = false
		status.Issues = append(status.Issues, "No compliance operator pods found")
		return status, nil
	}

	// Check each pod's status
	for _, pod := range pods {
		podStatus := PodStatus{
			Name:  pod.Name,
			Phase: pod.Status.Phase,
		}

		// Check if pod is ready
		podStatus.Ready = isPodReady(&pod)

		// Count restarts
		for _, cs := range pod.Status.ContainerStatuses {
			podStatus.Restarts += cs.RestartCount
		}

		// Check for issues
		if pod.Status.Phase != corev1.PodRunning {
			status.IsHealthy = false
			podStatus.Reason = string(pod.Status.Phase)
			status.Issues = append(status.Issues, fmt.Sprintf("Pod %s is in phase %s", pod.Name, pod.Status.Phase))
		}

		if !podStatus.Ready {
			status.IsHealthy = false
			status.Issues = append(status.Issues, fmt.Sprintf("Pod %s is not ready", pod.Name))
		}

		if podStatus.Restarts > 5 {
			status.Issues = append(status.Issues, fmt.Sprintf("Pod %s has restarted %d times", pod.Name, podStatus.Restarts))
		}

		status.OperatorPods = append(status.OperatorPods, podStatus)
	}

	return status, nil
}

// GetCheckCounts calculates check counts from check results
func GetCheckCounts(checkResults []ComplianceCheckResult) CheckCounts {
	counts := CheckCounts{}

	for _, check := range checkResults {
		counts.Total++
		switch check.Status {
		case CheckPass:
			counts.Pass++
		case CheckFail:
			counts.Fail++
		case CheckManual:
			counts.Manual++
		case CheckError:
			counts.Error++
		case CheckInfo:
			counts.Info++
		}
	}

	return counts
}

// CalculateCompliancePercentage calculates compliance percentage
func CalculateCompliancePercentage(counts CheckCounts) float64 {
	if counts.Total == 0 {
		return 0
	}

	// Calculate based on pass vs automated checks (pass + fail)
	automatedChecks := counts.Pass + counts.Fail
	if automatedChecks == 0 {
		return 0
	}

	return (float64(counts.Pass) / float64(automatedChecks)) * 100
}

// Helper function to check if pod is ready
func isPodReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}
