package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/xiyuan/compliance-mcp/pkg/compliance"
)

// MCPServer wraps the MCP server with compliance-specific functionality
type MCPServer struct {
	mcpServer  *server.MCPServer
	client     *compliance.ComplianceClient
	collector  *compliance.Collector
	analyzer   *compliance.Analyzer
	namespace  string
}

// NewMCPServer creates a new MCP server for compliance
func NewMCPServer(namespace string) (*MCPServer, error) {
	// Create compliance client
	client, err := compliance.NewComplianceClient(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create compliance client: %w", err)
	}

	// Create collector and analyzer
	collector := compliance.NewCollector(client)
	analyzer := compliance.NewAnalyzer(client)

	// Create MCP server
	mcpServer := server.NewMCPServer(
		"Compliance MCP Server",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	s := &MCPServer{
		mcpServer: mcpServer,
		client:    client,
		collector: collector,
		analyzer:  analyzer,
		namespace: namespace,
	}

	// Register all tools
	s.registerTools()

	return s, nil
}

// GetServer returns the underlying MCP server
func (s *MCPServer) GetServer() *server.MCPServer {
	return s.mcpServer
}

// registerTools registers all MCP tools
func (s *MCPServer) registerTools() {
	// Tool 1: compliance_status_overview
	s.mcpServer.AddTool(mcp.Tool{
		Name:        "compliance_status_overview",
		Description: "Get overall compliance operator health and suite status",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"namespace": map[string]interface{}{
					"type":        "string",
					"description": "Namespace where compliance operator is installed",
					"default":     s.namespace,
				},
				"suite_name": map[string]interface{}{
					"type":        "string",
					"description": "Optional: specific suite name to check",
				},
			},
		},
	}, s.handleStatusOverview)

	// Tool 2: compliance_scan_details
	s.mcpServer.AddTool(mcp.Tool{
		Name:        "compliance_scan_details",
		Description: "Get detailed information about a specific compliance scan",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"scan_name": map[string]interface{}{
					"type":        "string",
					"description": "Name of the ComplianceScan to inspect",
				},
				"namespace": map[string]interface{}{
					"type":        "string",
					"description": "Namespace",
					"default":     s.namespace,
				},
				"include_check_results": map[string]interface{}{
					"type":        "boolean",
					"description": "Include detailed check result counts",
					"default":     false,
				},
			},
			Required: []string{"scan_name"},
		},
	}, s.handleScanDetails)

	// Tool 3: compliance_check_results
	s.mcpServer.AddTool(mcp.Tool{
		Name:        "compliance_check_results",
		Description: "List check results for a scan with optional filtering",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"scan_name": map[string]interface{}{
					"type":        "string",
					"description": "Scan name to get results for",
				},
				"namespace": map[string]interface{}{
					"type":        "string",
					"description": "Namespace",
					"default":     s.namespace,
				},
				"status_filter": map[string]interface{}{
					"type":        "string",
					"description": "Filter by check status",
					"enum":        []string{"PASS", "FAIL", "MANUAL", "ERROR", "INFO"},
				},
				"severity_filter": map[string]interface{}{
					"type":        "string",
					"description": "Filter by severity",
					"enum":        []string{"low", "medium", "high", "unknown"},
				},
			},
			Required: []string{"scan_name"},
		},
	}, s.handleCheckResults)

	// Tool 4: compliance_remediations
	s.mcpServer.AddTool(mcp.Tool{
		Name:        "compliance_remediations",
		Description: "Get available remediations for failed checks",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"scan_name": map[string]interface{}{
					"type":        "string",
					"description": "Scan name to get remediations for",
				},
				"namespace": map[string]interface{}{
					"type":        "string",
					"description": "Namespace",
					"default":     s.namespace,
				},
				"applied_only": map[string]interface{}{
					"type":        "boolean",
					"description": "Show only applied remediations",
					"default":     false,
				},
			},
		},
	}, s.handleRemediations)

	// Tool 5: compliance_logs
	s.mcpServer.AddTool(mcp.Tool{
		Name:        "compliance_logs",
		Description: "Fetch and analyze logs from operator and scanner pods",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"pod_type": map[string]interface{}{
					"type":        "string",
					"description": "Type of pod to get logs from",
					"enum":        []string{"operator", "scanner"},
				},
				"scan_name": map[string]interface{}{
					"type":        "string",
					"description": "For scanner pods, the scan name",
				},
				"namespace": map[string]interface{}{
					"type":        "string",
					"description": "Namespace",
					"default":     s.namespace,
				},
				"tail_lines": map[string]interface{}{
					"type":        "integer",
					"description": "Number of log lines to fetch",
					"default":     100,
				},
				"analyze": map[string]interface{}{
					"type":        "boolean",
					"description": "Analyze logs for common errors",
					"default":     true,
				},
			},
			Required: []string{"pod_type"},
		},
	}, s.handleLogs)

	// Tool 6: compliance_diagnose
	s.mcpServer.AddTool(mcp.Tool{
		Name:        "compliance_diagnose",
		Description: "Auto-detect common compliance operator issues",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"namespace": map[string]interface{}{
					"type":        "string",
					"description": "Namespace",
					"default":     s.namespace,
				},
				"suite_name": map[string]interface{}{
					"type":        "string",
					"description": "Optional: focus diagnosis on specific suite",
				},
			},
		},
	}, s.handleDiagnose)
}

// Tool handlers

func (s *MCPServer) handleStatusOverview(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args StatusOverviewArgs
	args.Namespace = s.namespace // default

	if err := parseArgs(request.Params.Arguments, &args); err != nil {
		return createErrorResult(err), nil
	}

	result, err := ComplianceStatusOverview(ctx, s.client, s.collector, args)
	if err != nil {
		return createErrorResult(err), nil
	}

	return createTextResult(result), nil
}

func (s *MCPServer) handleScanDetails(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ScanDetailsArgs
	args.Namespace = s.namespace

	if err := parseArgs(request.Params.Arguments, &args); err != nil {
		return createErrorResult(err), nil
	}

	result, err := ComplianceScanDetails(ctx, s.client, args)
	if err != nil {
		return createErrorResult(err), nil
	}

	return createTextResult(result), nil
}

func (s *MCPServer) handleCheckResults(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args CheckResultsArgs
	args.Namespace = s.namespace

	if err := parseArgs(request.Params.Arguments, &args); err != nil {
		return createErrorResult(err), nil
	}

	result, err := ComplianceCheckResults(ctx, s.client, args)
	if err != nil {
		return createErrorResult(err), nil
	}

	return createTextResult(result), nil
}

func (s *MCPServer) handleRemediations(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args RemediationsArgs
	args.Namespace = s.namespace

	if err := parseArgs(request.Params.Arguments, &args); err != nil {
		return createErrorResult(err), nil
	}

	result, err := ComplianceRemediations(ctx, s.client, args)
	if err != nil {
		return createErrorResult(err), nil
	}

	return createTextResult(result), nil
}

func (s *MCPServer) handleLogs(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args LogsArgs
	args.Namespace = s.namespace
	args.TailLines = 100 // default

	if err := parseArgs(request.Params.Arguments, &args); err != nil {
		return createErrorResult(err), nil
	}

	result, err := ComplianceLogs(ctx, s.client, args)
	if err != nil {
		return createErrorResult(err), nil
	}

	return createTextResult(result), nil
}

func (s *MCPServer) handleDiagnose(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args DiagnoseArgs
	args.Namespace = s.namespace

	if err := parseArgs(request.Params.Arguments, &args); err != nil {
		return createErrorResult(err), nil
	}

	result, err := ComplianceDiagnose(ctx, s.analyzer, args)
	if err != nil {
		return createErrorResult(err), nil
	}

	return createTextResult(result), nil
}

// Helper functions

func parseArgs(arguments interface{}, target interface{}) error {
	// Convert arguments to JSON and back to populate struct
	jsonData, err := json.Marshal(arguments)
	if err != nil {
		return fmt.Errorf("failed to marshal arguments: %w", err)
	}

	if err := json.Unmarshal(jsonData, target); err != nil {
		return fmt.Errorf("failed to parse arguments: %w", err)
	}

	return nil
}

func createTextResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: text,
			},
		},
		IsError: false,
	}
}

func createErrorResult(err error) *mcp.CallToolResult {
	log.Printf("Error in tool execution: %v", err)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("Error: %v", err),
			},
		},
		IsError: true,
	}
}
