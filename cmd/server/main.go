package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/mark3labs/mcp-go/server"
	"github.com/xiyuan/compliance-mcp/pkg/mcp"
)

func main() {
	// Get configuration from environment
	namespace := os.Getenv("COMPLIANCE_NAMESPACE")
	if namespace == "" {
		namespace = "openshift-compliance"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8350"
	}

	log.Printf("Starting Compliance MCP Server...")
	log.Printf("Namespace: %s", namespace)
	log.Printf("Port: %s", port)

	// Create MCP server
	mcpServer, err := mcp.NewMCPServer(namespace)
	if err != nil {
		log.Fatalf("Failed to create MCP server: %v", err)
	}

	// Create HTTP handler
	mcpHandler := server.NewStreamableHTTPServer(mcpServer.GetServer())

	// Set up HTTP server
	http.Handle("/mcp", mcpHandler)

	// Add health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	// Add root handler with info
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>Compliance MCP Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .info { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        code { background: #e0e0e0; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Compliance MCP Server</h1>
    <div class="info">
        <p><strong>Status:</strong> Running</p>
        <p><strong>Namespace:</strong> %s</p>
        <p><strong>MCP Endpoint:</strong> <code>http://localhost:%s/mcp</code></p>
        <p><strong>Health Check:</strong> <code>http://localhost:%s/health</code></p>
    </div>
    <h2>Available Tools</h2>
    <ul>
        <li><strong>compliance_status_overview</strong> - Get overall compliance operator health and suite status</li>
        <li><strong>compliance_scan_details</strong> - Get detailed information about a specific scan</li>
        <li><strong>compliance_check_results</strong> - List check results for a scan</li>
        <li><strong>compliance_remediations</strong> - Get available remediations</li>
        <li><strong>compliance_logs</strong> - Fetch and analyze pod logs</li>
        <li><strong>compliance_diagnose</strong> - Auto-detect common issues</li>
    </ul>
    <h2>Usage</h2>
    <p>Configure your MCP client to connect to this server at <code>http://localhost:%s/mcp</code></p>
    <p>See the <a href="https://github.com/xiyuan/compliance-mcp">documentation</a> for more information.</p>
</body>
</html>
`, namespace, port, port, port)
	})

	// Start server
	addr := fmt.Sprintf(":%s", port)
	log.Printf("Server listening on %s", addr)
	log.Printf("MCP endpoint available at http://localhost%s/mcp", addr)
	log.Printf("Health check available at http://localhost%s/health", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
