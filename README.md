# `argon-recon-mcp` — Localhost Attack Surface & CVE Reconnaissance MCP Server

Local-only **Model Context Protocol (MCP)** server (stdio JSON-RPC 2.0) that queries a local Argon Node (`http://127.0.0.1:8420`) for passive subdomain enumeration (`crt.sh` + TLS SANs), HTTP security header posture checks, and local SQLite correlation against CISA KEV, NIST NVD CVEs, and GitHub Security Advisories.

## Tools Exposed

1. **`scan_domain_surface(domain: str)`**
2. **`check_cve_exposure(query: str)`**

## Configuration (`mcp_config.json`)
```json
{
  "mcpServers": {
    "argon-recon": {
      "command": "argon-recon-mcp",
      "env": {
        "ARGON_BASE_URL": "http://127.0.0.1:8420"
      }
    }
  }
}
```
