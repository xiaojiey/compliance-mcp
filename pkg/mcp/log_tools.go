package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/xiyuan/compliance-mcp/pkg/compliance"
)

// LogsArgs holds arguments for compliance_logs tool
type LogsArgs struct {
	PodType   string  `json:"pod_type"`
	ScanName  *string `json:"scan_name,omitempty"`
	Namespace string  `json:"namespace"`
	TailLines int64   `json:"tail_lines"`
	Analyze   bool    `json:"analyze"`
}

// ComplianceLogs fetches and analyzes logs from operator and scanner pods
func ComplianceLogs(ctx context.Context, client *compliance.ComplianceClient, args LogsArgs) (string, error) {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("# Logs: %s\n\n", args.PodType))

	var pods []string
	var err error

	switch args.PodType {
	case "operator":
		operatorPods, err := client.GetOperatorPods(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to get operator pods: %w", err)
		}
		if len(operatorPods) == 0 {
			return "No operator pods found", nil
		}
		for _, pod := range operatorPods {
			pods = append(pods, pod.Name)
		}

	case "scanner":
		if args.ScanName == nil || *args.ScanName == "" {
			return "", fmt.Errorf("scan_name is required for scanner pod logs")
		}
		scannerPods, err := client.GetScannerPods(ctx, *args.ScanName)
		if err != nil {
			return "", fmt.Errorf("failed to get scanner pods: %w", err)
		}
		if len(scannerPods) == 0 {
			return fmt.Sprintf("No scanner pods found for scan %s", *args.ScanName), nil
		}
		for _, pod := range scannerPods {
			pods = append(pods, pod.Name)
		}

	default:
		return "", fmt.Errorf("invalid pod_type: %s (must be 'operator' or 'scanner')", args.PodType)
	}

	// Fetch logs from each pod
	for _, podName := range pods {
		output.WriteString(fmt.Sprintf("## Pod: %s\n\n", podName))

		logs, err := client.GetPodLogs(ctx, podName, args.TailLines)
		if err != nil {
			output.WriteString(fmt.Sprintf("Error fetching logs: %v\n\n", err))
			continue
		}

		if logs == "" {
			output.WriteString("No logs available.\n\n")
			continue
		}

		// Analyze logs if requested
		if args.Analyze {
			errors, warnings := analyzeLogs(logs)

			if len(errors) > 0 {
				output.WriteString("### Errors Detected:\n")
				for _, errMsg := range errors {
					output.WriteString(fmt.Sprintf("- %s\n", errMsg))
				}
				output.WriteString("\n")
			}

			if len(warnings) > 0 {
				output.WriteString("### Warnings Detected:\n")
				for _, warnMsg := range warnings {
					output.WriteString(fmt.Sprintf("- %s\n", warnMsg))
				}
				output.WriteString("\n")
			}

			if len(errors) == 0 && len(warnings) == 0 {
				output.WriteString("✅ No obvious errors or warnings detected in logs.\n\n")
			}
		}

		// Include raw logs
		output.WriteString("### Raw Logs:\n```\n")
		output.WriteString(logs)
		output.WriteString("\n```\n\n")
	}

	return output.String(), err
}

// analyzeLogs analyzes log content for errors and warnings
func analyzeLogs(logs string) (errors []string, warnings []string) {
	lines := strings.Split(logs, "\n")

	errorKeywords := []string{
		"error",
		"failed",
		"fatal",
		"panic",
		"exception",
		"cannot",
		"unable to",
	}

	warningKeywords := []string{
		"warning",
		"warn",
		"deprecated",
		"retry",
	}

	seenErrors := make(map[string]bool)
	seenWarnings := make(map[string]bool)

	for _, line := range lines {
		lowerLine := strings.ToLower(line)

		// Check for errors
		for _, keyword := range errorKeywords {
			if strings.Contains(lowerLine, keyword) {
				// Avoid duplicates
				if !seenErrors[line] {
					errors = append(errors, line)
					seenErrors[line] = true
				}
				break
			}
		}

		// Check for warnings
		for _, keyword := range warningKeywords {
			if strings.Contains(lowerLine, keyword) {
				if !seenWarnings[line] {
					warnings = append(warnings, line)
					seenWarnings[line] = true
				}
				break
			}
		}
	}

	// Limit results to avoid overwhelming output
	if len(errors) > 20 {
		errors = errors[:20]
	}
	if len(warnings) > 20 {
		warnings = warnings[:20]
	}

	return errors, warnings
}
