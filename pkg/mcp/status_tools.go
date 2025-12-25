package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/xiyuan/compliance-mcp/pkg/compliance"
)

// StatusOverviewArgs holds arguments for compliance_status_overview tool
type StatusOverviewArgs struct {
	Namespace string  `json:"namespace"`
	SuiteName *string `json:"suite_name,omitempty"`
}

// ScanDetailsArgs holds arguments for compliance_scan_details tool
type ScanDetailsArgs struct {
	ScanName             string `json:"scan_name"`
	Namespace            string `json:"namespace"`
	IncludeCheckResults bool   `json:"include_check_results"`
}

// ComplianceStatusOverview gets overall compliance operator health and suite status
func ComplianceStatusOverview(ctx context.Context, client *compliance.ComplianceClient, collector *compliance.Collector, args StatusOverviewArgs) (string, error) {
	var output strings.Builder

	output.WriteString("# Compliance Operator Status Overview\n\n")

	// Get operator status
	operatorStatus, err := collector.CollectAllData(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to collect data: %w", err)
	}

	// Operator health
	output.WriteString("## Operator Health\n\n")
	if operatorStatus.OperatorStatus.IsHealthy {
		output.WriteString("✅ **Status:** Healthy\n")
	} else {
		output.WriteString("❌ **Status:** Unhealthy\n")
	}

	output.WriteString(fmt.Sprintf("**Operator Pods:** %d\n", len(operatorStatus.OperatorStatus.OperatorPods)))

	for _, pod := range operatorStatus.OperatorStatus.OperatorPods {
		readyIcon := "❌"
		if pod.Ready {
			readyIcon = "✅"
		}
		output.WriteString(fmt.Sprintf("  - %s: %s %s (Restarts: %d)\n", pod.Name, pod.Phase, readyIcon, pod.Restarts))
	}

	if len(operatorStatus.OperatorStatus.Issues) > 0 {
		output.WriteString("\n**Issues:**\n")
		for _, issue := range operatorStatus.OperatorStatus.Issues {
			output.WriteString(fmt.Sprintf("  - %s\n", issue))
		}
	}

	// Compliance suites
	output.WriteString("\n## Compliance Suites\n\n")

	if len(operatorStatus.Suites) == 0 {
		output.WriteString("No compliance suites found.\n")
	} else {
		// If specific suite requested, filter
		var suitesToShow []compliance.ComplianceSuite
		if args.SuiteName != nil && *args.SuiteName != "" {
			for _, suite := range operatorStatus.Suites {
				if suite.Name == *args.SuiteName {
					suitesToShow = append(suitesToShow, suite)
					break
				}
			}
			if len(suitesToShow) == 0 {
				return "", fmt.Errorf("suite '%s' not found", *args.SuiteName)
			}
		} else {
			suitesToShow = operatorStatus.Suites
		}

		for _, suite := range suitesToShow {
			output.WriteString(fmt.Sprintf("### %s\n\n", suite.Name))
			output.WriteString(fmt.Sprintf("**Phase:** %s\n", suite.Status.Phase))
			output.WriteString(fmt.Sprintf("**Result:** %s\n", suite.Status.Result))

			if suite.Status.ErrorMessage != "" {
				output.WriteString(fmt.Sprintf("**Error:** %s\n", suite.Status.ErrorMessage))
			}

			// Show scan statuses
			if len(suite.Status.ScanStatuses) > 0 {
				output.WriteString(fmt.Sprintf("\n**Scans:** %d\n", len(suite.Status.ScanStatuses)))

				// Count scans by result
				resultCounts := make(map[compliance.ComplianceScanResult]int)
				for _, scanStatus := range suite.Status.ScanStatuses {
					resultCounts[scanStatus.Result]++
				}

				for result, count := range resultCounts {
					output.WriteString(fmt.Sprintf("  - %s: %d\n", result, count))
				}

				// Calculate overall compliance
				var totalChecks, passedChecks, failedChecks int
				for scanName := range operatorStatus.Scans {
					if checkResults, ok := operatorStatus.CheckResults[scanName]; ok {
						counts := compliance.GetCheckCounts(checkResults)
						totalChecks += counts.Total
						passedChecks += counts.Pass
						failedChecks += counts.Fail
					}
				}

				if totalChecks > 0 {
					automatedChecks := passedChecks + failedChecks
					if automatedChecks > 0 {
						compliancePercentage := (float64(passedChecks) / float64(automatedChecks)) * 100
						output.WriteString(fmt.Sprintf("\n**Overall Compliance:** %.1f%% (%d/%d checks passed)\n", compliancePercentage, passedChecks, automatedChecks))
					}
				}
			}

			output.WriteString("\n")
		}
	}

	// Summary statistics
	output.WriteString("## Summary\n\n")
	output.WriteString(fmt.Sprintf("- **Total Suites:** %d\n", len(operatorStatus.Suites)))
	output.WriteString(fmt.Sprintf("- **Total Scans:** %d\n", len(operatorStatus.Scans)))

	// Count total checks
	var totalChecks, passedChecks, failedChecks, manualChecks int
	for _, checkResults := range operatorStatus.CheckResults {
		counts := compliance.GetCheckCounts(checkResults)
		totalChecks += counts.Total
		passedChecks += counts.Pass
		failedChecks += counts.Fail
		manualChecks += counts.Manual
	}

	output.WriteString(fmt.Sprintf("- **Total Checks:** %d\n", totalChecks))
	output.WriteString(fmt.Sprintf("  - Passed: %d ✅\n", passedChecks))
	output.WriteString(fmt.Sprintf("  - Failed: %d ❌\n", failedChecks))
	output.WriteString(fmt.Sprintf("  - Manual: %d ⚠️\n", manualChecks))

	return output.String(), nil
}

// ComplianceScanDetails gets detailed information about a specific scan
func ComplianceScanDetails(ctx context.Context, client *compliance.ComplianceClient, args ScanDetailsArgs) (string, error) {
	// Get the scan
	scan, err := client.GetComplianceScan(ctx, args.ScanName)
	if err != nil {
		return "", fmt.Errorf("failed to get scan: %w", err)
	}

	// Get scanner pods
	pods, err := client.GetScannerPods(ctx, args.ScanName)
	if err != nil {
		return "", fmt.Errorf("failed to get scanner pods: %w", err)
	}

	podNames := make([]string, len(pods))
	for i, pod := range pods {
		podNames[i] = fmt.Sprintf("%s (%s)", pod.Name, pod.Status.Phase)
	}

	// Get check results if requested
	var checkCounts *compliance.CheckCounts
	if args.IncludeCheckResults {
		checkResults, err := client.GetComplianceCheckResults(ctx, args.ScanName, "")
		if err == nil {
			counts := compliance.GetCheckCounts(checkResults)
			checkCounts = &counts
		}
	}

	return FormatScanStatus(*scan, checkCounts, podNames), nil
}
