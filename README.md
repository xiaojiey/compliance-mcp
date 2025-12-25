# Compliance MCP Server

A Model Context Protocol (MCP) server for OpenShift Compliance Operator troubleshooting and audit reporting.

## Features

The Compliance MCP Server provides AI assistants with tools to:

- **Status Checking**: Monitor compliance operator health and scan status
- **Log Analysis**: Fetch and analyze logs from operator and scanner pods
- **Issue Diagnosis**: Auto-detect common problems (stuck scans, failed pods, permission issues, resource constraints)
- **Check Results**: View compliance check results with filtering
- **Remediation Management**: List available remediations and their status

## Quick Start

### Prerequisites

- Go 1.22 or later
- Access to an OpenShift/Kubernetes cluster with Compliance Operator installed
- `KUBECONFIG` configured to access the cluster

### Installation

```bash
# Clone the repository
cd /home/xiyuan/isc/compliance-mcp

# Build the server
go build -o compliance-mcp-server ./cmd/server

# Run the server
./compliance-mcp-server
```

### Configuration

The server is configured via environment variables:

- `COMPLIANCE_NAMESPACE`: Namespace where compliance operator is installed (default: `openshift-compliance`)
- `PORT`: HTTP server port (default: `8350`)
- `KUBECONFIG`: Path to kubeconfig file (default: `~/.kube/config`)

Example:

```bash
export COMPLIANCE_NAMESPACE=openshift-compliance
export PORT=8350
export KUBECONFIG=~/.kube/config
./compliance-mcp-server
```

## MCP Tools

### 1. compliance_status_overview

Get overall compliance operator health and suite status.

**Arguments:**
- `namespace` (string, optional): Compliance namespace
- `suite_name` (string, optional): Specific suite to check

**Example:**
```json
{
  "namespace": "openshift-compliance",
  "suite_name": "nist-moderate"
}
```

### 2. compliance_scan_details

Get detailed information about a specific compliance scan.

**Arguments:**
- `scan_name` (string, required): Name of the scan
- `namespace` (string, optional): Namespace
- `include_check_results` (boolean, optional): Include check counts

**Example:**
```json
{
  "scan_name": "rhcos4-moderate-master",
  "include_check_results": true
}
```

### 3. compliance_check_results

List check results for a scan with optional filtering.

**Arguments:**
- `scan_name` (string, required): Scan name
- `namespace` (string, optional): Namespace
- `status_filter` (string, optional): Filter by status (PASS/FAIL/MANUAL/ERROR/INFO)
- `severity_filter` (string, optional): Filter by severity (low/medium/high)

**Example:**
```json
{
  "scan_name": "rhcos4-moderate-master",
  "status_filter": "FAIL",
  "severity_filter": "high"
}
```

### 4. compliance_remediations

Get available remediations for failed checks.

**Arguments:**
- `scan_name` (string, optional): Scan name to filter
- `namespace` (string, optional): Namespace
- `applied_only` (boolean, optional): Show only applied remediations

**Example:**
```json
{
  "scan_name": "rhcos4-moderate-master",
  "applied_only": false
}
```

### 5. compliance_logs

Fetch and analyze logs from operator and scanner pods.

**Arguments:**
- `pod_type` (string, required): Type of pod (operator/scanner)
- `scan_name` (string, required for scanner): Scan name for scanner pods
- `namespace` (string, optional): Namespace
- `tail_lines` (integer, optional): Number of log lines (default: 100)
- `analyze` (boolean, optional): Analyze logs for errors (default: true)

**Example:**
```json
{
  "pod_type": "scanner",
  "scan_name": "rhcos4-moderate-master",
  "tail_lines": 200,
  "analyze": true
}
```

### 6. compliance_diagnose

Auto-detect common compliance operator issues.

**Arguments:**
- `namespace` (string, optional): Namespace
- `suite_name` (string, optional): Focus on specific suite

**Example:**
```json
{
  "namespace": "openshift-compliance"
}
```

## Usage with Claude Desktop

Add this configuration to your Claude Desktop MCP settings:

```json
{
  "mcpServers": {
    "compliance": {
      "url": "http://localhost:8350/mcp",
      "headers": {
        "Content-Type": "application/json"
      }
    }
  }
}
```

Then you can ask Claude:
- "Check my compliance operator status"
- "Why is the scan failing?"
- "Show me the high severity failed checks"
- "Diagnose compliance operator issues"

## Architecture

```
compliance-mcp/
├── cmd/server/          # Main entry point
├── pkg/
│   ├── compliance/      # Kubernetes client and core logic
│   │   ├── client.go    # K8s client wrapper
│   │   ├── collector.go # Data collection
│   │   ├── analyzer.go  # Issue detection
│   │   └── types.go     # CRD types
│   └── mcp/            # MCP tools implementation
│       ├── server.go    # MCP server setup
│       ├── status_tools.go
│       ├── diagnosis_tools.go
│       ├── log_tools.go
│       └── check_remediation_tools.go
└── templates/          # HTML report templates (future)
```

## Development

### Building

```bash
go build -o compliance-mcp-server ./cmd/server
```

### Testing

```bash
# Run the server
./compliance-mcp-server

# In another terminal, test the health endpoint
curl http://localhost:8350/health

# Test MCP endpoint (requires MCP client)
curl -X POST http://localhost:8350/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list"
  }'
```

## Troubleshooting

### "Failed to create compliance client"

- Verify your kubeconfig is correct
- Check network connectivity to the cluster
- Ensure you have permissions to access the compliance namespace

### "No compliance operator pods found"

- Verify compliance operator is installed: `oc get pods -n openshift-compliance`
- Check the namespace configuration

### "Failed to list compliance suites"

- Ensure compliance operator CRDs are installed: `oc get crds | grep compliance`
- Check RBAC permissions for your service account

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or pull request.
