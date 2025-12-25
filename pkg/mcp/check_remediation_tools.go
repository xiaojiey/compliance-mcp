package mcp

import (
	"context"
	"fmt"

	"github.com/xiyuan/compliance-mcp/pkg/compliance"
)

// CheckResultsArgs holds arguments for compliance_check_results tool
type CheckResultsArgs struct {
	ScanName       string  `json:"scan_name"`
	Namespace      string  `json:"namespace"`
	StatusFilter   *string `json:"status_filter,omitempty"`
	SeverityFilter *string `json:"severity_filter,omitempty"`
}

// RemediationsArgs holds arguments for compliance_remediations tool
type RemediationsArgs struct {
	ScanName    string  `json:"scan_name,omitempty"`
	Namespace   string  `json:"namespace"`
	AppliedOnly bool    `json:"applied_only"`
}

// ComplianceCheckResults lists check results for a scan
func ComplianceCheckResults(ctx context.Context, client *compliance.ComplianceClient, args CheckResultsArgs) (string, error) {
	statusFilter := ""
	if args.StatusFilter != nil {
		statusFilter = *args.StatusFilter
	}

	// Get check results
	checkResults, err := client.GetComplianceCheckResults(ctx, args.ScanName, statusFilter)
	if err != nil {
		return "", fmt.Errorf("failed to get check results: %w", err)
	}

	// Filter by severity if requested
	if args.SeverityFilter != nil && *args.SeverityFilter != "" {
		filtered := []compliance.ComplianceCheckResult{}
		for _, result := range checkResults {
			if result.Severity == *args.SeverityFilter {
				filtered = append(filtered, result)
			}
		}
		checkResults = filtered
	}

	return FormatCheckResults(checkResults), nil
}

// ComplianceRemediations gets available remediations
func ComplianceRemediations(ctx context.Context, client *compliance.ComplianceClient, args RemediationsArgs) (string, error) {
	// Get remediations
	remediations, err := client.GetComplianceRemediations(ctx, args.ScanName)
	if err != nil {
		return "", fmt.Errorf("failed to get remediations: %w", err)
	}

	// Filter by applied status if requested
	if args.AppliedOnly {
		filtered := []compliance.ComplianceRemediation{}
		for _, rem := range remediations {
			if rem.Spec.Apply {
				filtered = append(filtered, rem)
			}
		}
		remediations = filtered
	}

	return FormatRemediations(remediations), nil
}
