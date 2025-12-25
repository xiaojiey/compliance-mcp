package mcp

import (
	"context"
	"fmt"

	"github.com/xiyuan/compliance-mcp/pkg/compliance"
)

// DiagnoseArgs holds arguments for compliance_diagnose tool
type DiagnoseArgs struct {
	Namespace string  `json:"namespace"`
	SuiteName *string `json:"suite_name,omitempty"`
}

// ComplianceDiagnose auto-detects common compliance operator issues
func ComplianceDiagnose(ctx context.Context, analyzer *compliance.Analyzer, args DiagnoseArgs) (string, error) {
	// Run comprehensive analysis
	result, err := analyzer.AnalyzeAll(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to analyze: %w", err)
	}

	return compliance.FormatDiagnosisResult(result), nil
}
