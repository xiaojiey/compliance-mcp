package compliance

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// IssueType represents the type of issue detected
type IssueType string

const (
	IssueTypeStuckScan          IssueType = "StuckScan"
	IssueTypeFailedPod          IssueType = "FailedPod"
	IssueTypePermission         IssueType = "Permission"
	IssueTypeResourceConstraint IssueType = "ResourceConstraint"
	IssueTypeOOM                IssueType = "OutOfMemory"
	IssueTypeMisconfiguration   IssueType = "Misconfiguration"
)

// IssueSeverity represents the severity of an issue
type IssueSeverity string

const (
	SeverityCritical IssueSeverity = "Critical"
	SeverityWarning  IssueSeverity = "Warning"
	SeverityInfo     IssueSeverity = "Info"
)

// Issue represents a detected problem
type Issue struct {
	Type        IssueType
	Severity    IssueSeverity
	Description string
	Resources   []string
	Suggestion  string
}

// DiagnosisResult holds the results of diagnosis
type DiagnosisResult struct {
	Issues      []Issue
	Warnings    []Issue
	Suggestions []string
}

// Analyzer analyzes compliance operator state and detects issues
type Analyzer struct {
	client *ComplianceClient
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer(client *ComplianceClient) *Analyzer {
	return &Analyzer{client: client}
}

// AnalyzeAll performs comprehensive analysis of the compliance operator
func (a *Analyzer) AnalyzeAll(ctx context.Context) (*DiagnosisResult, error) {
	result := &DiagnosisResult{
		Issues:      []Issue{},
		Warnings:    []Issue{},
		Suggestions: []string{},
	}

	// Get all scans
	scans, err := a.client.GetComplianceScans(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get scans: %w", err)
	}

	// Detect stuck scans
	stuckIssues := a.DetectStuckScans(ctx, scans)
	result.Issues = append(result.Issues, stuckIssues...)

	// Detect failed pods
	for _, scan := range scans {
		pods, err := a.client.GetScannerPods(ctx, scan.Name)
		if err != nil {
			continue
		}

		failedPodIssues := a.DetectFailedPods(ctx, pods)
		result.Issues = append(result.Issues, failedPodIssues...)

		resourceIssues := a.DetectResourceConstraints(ctx, pods)
		result.Issues = append(result.Issues, resourceIssues...)

		permissionIssues, err := a.DetectPermissionIssuesForScan(ctx, scan.Name)
		if err == nil {
			result.Issues = append(result.Issues, permissionIssues...)
		}
	}

	// Separate issues by severity
	var criticalIssues, warnings []Issue
	for _, issue := range result.Issues {
		if issue.Severity == SeverityCritical {
			criticalIssues = append(criticalIssues, issue)
		} else {
			warnings = append(warnings, issue)
		}
	}

	result.Issues = criticalIssues
	result.Warnings = warnings

	// Add general suggestions
	if len(criticalIssues) == 0 && len(warnings) == 0 {
		result.Suggestions = append(result.Suggestions, "No issues detected. Compliance operator appears to be functioning normally.")
	}

	return result, nil
}

// DetectStuckScans detects scans that have been running too long
func (a *Analyzer) DetectStuckScans(ctx context.Context, scans []ComplianceScan) []Issue {
	issues := []Issue{}

	for _, scan := range scans {
		// Check if scan is stuck in RUNNING phase
		if scan.Status.Phase == PhaseRunning {
			if scan.Status.StartTimestamp != nil {
				elapsed := time.Since(scan.Status.StartTimestamp.Time)

				// If running for more than 30 minutes, it's likely stuck
				if elapsed > 30*time.Minute {
					issue := Issue{
						Type:        IssueTypeStuckScan,
						Severity:    SeverityCritical,
						Description: fmt.Sprintf("Scan '%s' has been in RUNNING phase for %v", scan.Name, elapsed.Round(time.Minute)),
						Resources:   []string{scan.Name},
						Suggestion:  "Check scanner pod logs and events. The scan may be stuck due to pod failures, resource constraints, or permission issues.",
					}
					issues = append(issues, issue)
				}
			}
		}

		// Check for scans stuck in other phases
		if scan.Status.Phase == PhaseLaunching {
			if scan.Status.StartTimestamp != nil && time.Since(scan.Status.StartTimestamp.Time) > 10*time.Minute {
				issue := Issue{
					Type:        IssueTypeStuckScan,
					Severity:    SeverityCritical,
					Description: fmt.Sprintf("Scan '%s' stuck in LAUNCHING phase", scan.Name),
					Resources:   []string{scan.Name},
					Suggestion:  "Check if scanner pods are being created. Look for resource constraints or ImagePullBackOff errors.",
				}
				issues = append(issues, issue)
			}
		}

		// Check for error results
		if scan.Status.Result == ResultError {
			issue := Issue{
				Type:        IssueTypeFailedPod,
				Severity:    SeverityCritical,
				Description: fmt.Sprintf("Scan '%s' completed with ERROR result: %s", scan.Name, scan.Status.ErrorMessage),
				Resources:   []string{scan.Name},
				Suggestion:  "Review scan logs and error message. Common causes include missing content, invalid profiles, or scanner pod failures.",
			}
			issues = append(issues, issue)
		}
	}

	return issues
}

// DetectFailedPods detects failed scanner pods
func (a *Analyzer) DetectFailedPods(ctx context.Context, pods []corev1.Pod) []Issue {
	issues := []Issue{}

	for _, pod := range pods {
		// Check for failed pods
		if pod.Status.Phase == corev1.PodFailed {
			issue := Issue{
				Type:        IssueTypeFailedPod,
				Severity:    SeverityCritical,
				Description: fmt.Sprintf("Scanner pod '%s' failed with reason: %s", pod.Name, pod.Status.Reason),
				Resources:   []string{pod.Name},
				Suggestion:  "Check pod logs for error details. The scanner may have encountered an error during scan execution.",
			}
			issues = append(issues, issue)
		}

		// Check for pods stuck in ImagePullBackOff
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Waiting != nil {
				reason := cs.State.Waiting.Reason
				if reason == "ImagePullBackOff" || reason == "ErrImagePull" {
					issue := Issue{
						Type:        IssueTypeFailedPod,
						Severity:    SeverityCritical,
						Description: fmt.Sprintf("Pod '%s' cannot pull image: %s", pod.Name, cs.State.Waiting.Message),
						Resources:   []string{pod.Name},
						Suggestion:  "Verify image name and registry credentials. Check network connectivity to image registry.",
					}
					issues = append(issues, issue)
				} else if reason == "CrashLoopBackOff" {
					issue := Issue{
						Type:        IssueTypeFailedPod,
						Severity:    SeverityCritical,
						Description: fmt.Sprintf("Pod '%s' is crash looping", pod.Name),
						Resources:   []string{pod.Name},
						Suggestion:  "Check container logs for crash details. The scanner may be encountering a runtime error.",
					}
					issues = append(issues, issue)
				}
			}

			// Check for recent OOM kills
			if cs.LastTerminationState.Terminated != nil {
				if cs.LastTerminationState.Terminated.Reason == "OOMKilled" {
					issue := Issue{
						Type:        IssueTypeOOM,
						Severity:    SeverityCritical,
						Description: fmt.Sprintf("Container '%s' in pod '%s' was killed due to out of memory", cs.Name, pod.Name),
						Resources:   []string{pod.Name},
						Suggestion:  "Increase memory limits for scanner pods in ScanSetting. The scan requires more memory than allocated.",
					}
					issues = append(issues, issue)
				}
			}
		}

		// Check for high restart count
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.RestartCount > 5 {
				issue := Issue{
					Type:        IssueTypeFailedPod,
					Severity:    SeverityWarning,
					Description: fmt.Sprintf("Container '%s' in pod '%s' has restarted %d times", cs.Name, pod.Name, cs.RestartCount),
					Resources:   []string{pod.Name},
					Suggestion:  "Investigate why the container is restarting. Check logs for errors.",
				}
				issues = append(issues, issue)
			}
		}
	}

	return issues
}

// DetectResourceConstraints detects resource constraint issues
func (a *Analyzer) DetectResourceConstraints(ctx context.Context, pods []corev1.Pod) []Issue {
	issues := []Issue{}

	for _, pod := range pods {
		// Check for pending pods due to resource constraints
		if pod.Status.Phase == corev1.PodPending {
			for _, condition := range pod.Status.Conditions {
				if condition.Type == corev1.PodScheduled && condition.Status == corev1.ConditionFalse {
					if strings.Contains(condition.Reason, "Insufficient") || strings.Contains(condition.Message, "Insufficient") {
						issue := Issue{
							Type:        IssueTypeResourceConstraint,
							Severity:    SeverityCritical,
							Description: fmt.Sprintf("Pod '%s' cannot be scheduled: %s", pod.Name, condition.Message),
							Resources:   []string{pod.Name},
							Suggestion:  "Increase cluster resources or reduce scanner pod resource requests in ScanSetting.",
						}
						issues = append(issues, issue)
					}
				}
			}
		}
	}

	return issues
}

// DetectPermissionIssuesForScan detects permission issues for a scan
func (a *Analyzer) DetectPermissionIssuesForScan(ctx context.Context, scanName string) ([]Issue, error) {
	issues := []Issue{}

	// Get events for the scan
	events, err := a.client.GetEvents(ctx, "ComplianceScan", scanName)
	if err != nil {
		return issues, err
	}

	permissionKeywords := []string{
		"Forbidden",
		"Unauthorized",
		"denied",
		"insufficient permissions",
		"cannot create",
		"cannot get",
		"cannot list",
	}

	for _, event := range events {
		if event.Type == corev1.EventTypeWarning {
			for _, keyword := range permissionKeywords {
				if strings.Contains(event.Message, keyword) {
					issue := Issue{
						Type:        IssueTypePermission,
						Severity:    SeverityCritical,
						Description: fmt.Sprintf("Permission issue in scan '%s': %s", scanName, event.Message),
						Resources:   []string{scanName, event.InvolvedObject.Name},
						Suggestion:  "Check ServiceAccount permissions and RBAC configuration. The compliance operator may not have sufficient permissions.",
					}
					issues = append(issues, issue)
					break
				}
			}
		}
	}

	return issues, nil
}

// AnalyzeScanFailure provides detailed analysis of a specific scan failure
func (a *Analyzer) AnalyzeScanFailure(ctx context.Context, scan ComplianceScan) []Issue {
	issues := []Issue{}

	if scan.Status.Result != ResultError && scan.Status.Result != ResultNonCompliant {
		return issues
	}

	// Add issue for scan failure
	if scan.Status.ErrorMessage != "" {
		issue := Issue{
			Type:        IssueTypeFailedPod,
			Severity:    SeverityCritical,
			Description: fmt.Sprintf("Scan '%s' failed: %s", scan.Name, scan.Status.ErrorMessage),
			Resources:   []string{scan.Name},
			Suggestion:  "Review the error message and check scanner pod logs for more details.",
		}
		issues = append(issues, issue)
	}

	// Check if it's a non-compliant result
	if scan.Status.Result == ResultNonCompliant {
		issue := Issue{
			Type:        IssueTypeMisconfiguration,
			Severity:    SeverityWarning,
			Description: fmt.Sprintf("Scan '%s' found compliance violations", scan.Name),
			Resources:   []string{scan.Name},
			Suggestion:  "Review failed checks and apply available remediations. Some checks may require manual remediation.",
		}
		issues = append(issues, issue)
	}

	return issues
}

// FormatDiagnosisResult formats the diagnosis result as a string
func FormatDiagnosisResult(result *DiagnosisResult) string {
	var output strings.Builder

	output.WriteString("# Compliance Operator Diagnosis\n\n")

	if len(result.Issues) == 0 && len(result.Warnings) == 0 {
		output.WriteString("✅ No critical issues detected.\n\n")
	} else {
		// Critical issues
		if len(result.Issues) > 0 {
			output.WriteString(fmt.Sprintf("## Critical Issues (%d)\n\n", len(result.Issues)))
			for i, issue := range result.Issues {
				output.WriteString(fmt.Sprintf("### %d. %s\n", i+1, issue.Type))
				output.WriteString(fmt.Sprintf("**Severity:** %s\n", issue.Severity))
				output.WriteString(fmt.Sprintf("**Description:** %s\n", issue.Description))
				if len(issue.Resources) > 0 {
					output.WriteString(fmt.Sprintf("**Affected Resources:** %s\n", strings.Join(issue.Resources, ", ")))
				}
				output.WriteString(fmt.Sprintf("**Suggestion:** %s\n\n", issue.Suggestion))
			}
		}

		// Warnings
		if len(result.Warnings) > 0 {
			output.WriteString(fmt.Sprintf("## Warnings (%d)\n\n", len(result.Warnings)))
			for i, warning := range result.Warnings {
				output.WriteString(fmt.Sprintf("### %d. %s\n", i+1, warning.Description))
				output.WriteString(fmt.Sprintf("**Suggestion:** %s\n\n", warning.Suggestion))
			}
		}
	}

	// Suggestions
	if len(result.Suggestions) > 0 {
		output.WriteString("## Suggestions\n\n")
		for _, suggestion := range result.Suggestions {
			output.WriteString(fmt.Sprintf("- %s\n", suggestion))
		}
	}

	return output.String()
}
