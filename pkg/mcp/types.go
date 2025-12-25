package mcp

import (
	"fmt"
	"strings"

	"github.com/xiyuan/compliance-mcp/pkg/compliance"
)

// FormatSuiteStatus formats a suite status for display
func FormatSuiteStatus(suite compliance.ComplianceSuite) string {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("# Suite: %s\n\n", suite.Name))
	output.WriteString(fmt.Sprintf("**Phase:** %s\n", suite.Status.Phase))
	output.WriteString(fmt.Sprintf("**Result:** %s\n", suite.Status.Result))

	if suite.Status.ErrorMessage != "" {
		output.WriteString(fmt.Sprintf("**Error:** %s\n", suite.Status.ErrorMessage))
	}

	if len(suite.Status.ScanStatuses) > 0 {
		output.WriteString(fmt.Sprintf("\n## Scans (%d)\n\n", len(suite.Status.ScanStatuses)))
		for _, scan := range suite.Status.ScanStatuses {
			output.WriteString(fmt.Sprintf("- **%s**: %s (%s)\n", scan.Name, scan.Phase, scan.Result))
		}
	}

	return output.String()
}

// FormatScanStatus formats a scan status for display
func FormatScanStatus(scan compliance.ComplianceScan, checkCounts *compliance.CheckCounts, pods []string) string {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("# Scan: %s\n\n", scan.Name))
	output.WriteString(fmt.Sprintf("**Phase:** %s\n", scan.Status.Phase))
	output.WriteString(fmt.Sprintf("**Result:** %s\n", scan.Status.Result))
	output.WriteString(fmt.Sprintf("**Scan Type:** %s\n", scan.Spec.ScanType))
	output.WriteString(fmt.Sprintf("**Profile:** %s\n", scan.Spec.Profile))

	if scan.Status.StartTimestamp != nil {
		output.WriteString(fmt.Sprintf("**Started:** %s\n", scan.Status.StartTimestamp.Format("2006-01-02 15:04:05")))
	}

	if scan.Status.ErrorMessage != "" {
		output.WriteString(fmt.Sprintf("\n**Error:** %s\n", scan.Status.ErrorMessage))
	}

	if scan.Status.Warnings != "" {
		output.WriteString(fmt.Sprintf("\n**Warnings:** %s\n", scan.Status.Warnings))
	}

	if checkCounts != nil {
		output.WriteString("\n## Check Results\n\n")
		output.WriteString(fmt.Sprintf("- Total: %d\n", checkCounts.Total))
		output.WriteString(fmt.Sprintf("- Pass: %d ✅\n", checkCounts.Pass))
		output.WriteString(fmt.Sprintf("- Fail: %d ❌\n", checkCounts.Fail))
		output.WriteString(fmt.Sprintf("- Manual: %d ⚠️\n", checkCounts.Manual))
		output.WriteString(fmt.Sprintf("- Error: %d 🔴\n", checkCounts.Error))

		if checkCounts.Pass+checkCounts.Fail > 0 {
			percentage := compliance.CalculateCompliancePercentage(*checkCounts)
			output.WriteString(fmt.Sprintf("\n**Compliance:** %.1f%%\n", percentage))
		}
	}

	if len(pods) > 0 {
		output.WriteString(fmt.Sprintf("\n## Scanner Pods (%d)\n\n", len(pods)))
		for _, pod := range pods {
			output.WriteString(fmt.Sprintf("- %s\n", pod))
		}
	}

	return output.String()
}

// FormatCheckResults formats check results for display
func FormatCheckResults(results []compliance.ComplianceCheckResult) string {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("# Check Results (%d)\n\n", len(results)))

	if len(results) == 0 {
		output.WriteString("No check results found.\n")
		return output.String()
	}

	for i, result := range results {
		statusIcon := getStatusIcon(result.Status)
		severityBadge := getSeverityBadge(result.Severity)

		output.WriteString(fmt.Sprintf("## %d. %s %s %s\n\n", i+1, result.Name, statusIcon, severityBadge))

		if result.Description != "" {
			output.WriteString(fmt.Sprintf("**Description:** %s\n\n", result.Description))
		}

		if result.Instructions != "" && result.Status == compliance.CheckFail {
			output.WriteString(fmt.Sprintf("**Remediation Instructions:**\n%s\n\n", result.Instructions))
		}
	}

	return output.String()
}

// FormatRemediations formats remediations for display
func FormatRemediations(remediations []compliance.ComplianceRemediation) string {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("# Remediations (%d)\n\n", len(remediations)))

	if len(remediations) == 0 {
		output.WriteString("No remediations found.\n")
		return output.String()
	}

	appliedCount := 0
	for _, rem := range remediations {
		if rem.Spec.Apply {
			appliedCount++
		}
	}

	output.WriteString(fmt.Sprintf("**Applied:** %d / %d\n\n", appliedCount, len(remediations)))

	for i, rem := range remediations {
		applied := "❌"
		if rem.Spec.Apply {
			applied = "✅"
		}

		output.WriteString(fmt.Sprintf("## %d. %s %s\n\n", i+1, rem.Name, applied))
		output.WriteString(fmt.Sprintf("**Application State:** %s\n", rem.Status.ApplicationState))

		// Extract remediation type from labels or annotations
		if remType, ok := rem.Labels["compliance.openshift.io/remediation-type"]; ok {
			output.WriteString(fmt.Sprintf("**Type:** %s\n", remType))
		}

		output.WriteString("\n")
	}

	return output.String()
}

// Helper functions

func getStatusIcon(status compliance.ComplianceCheckStatus) string {
	switch status {
	case compliance.CheckPass:
		return "✅"
	case compliance.CheckFail:
		return "❌"
	case compliance.CheckManual:
		return "⚠️"
	case compliance.CheckError:
		return "🔴"
	case compliance.CheckInfo:
		return "ℹ️"
	default:
		return "❓"
	}
}

func getSeverityBadge(severity string) string {
	switch strings.ToLower(severity) {
	case "high":
		return "🔴 HIGH"
	case "medium":
		return "🟠 MEDIUM"
	case "low":
		return "🟡 LOW"
	default:
		return ""
	}
}
