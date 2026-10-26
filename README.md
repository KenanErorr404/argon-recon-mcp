# `argon-recon-mcp` — Continuous Attack Surface & Live CVE Reconnaissance MCP Server

Zero-config **Model Context Protocol (MCP)** server (stdio JSON-RPC 2.0) that equips Claude Desktop, Cursor, Windsurf, and autonomous AI coding agents with live passive subdomain discovery (`crt.sh` + TLS SANs), HTTP security header posture checks, and real-time correlation against **CISA Known Exploited Vulnerabilities (KEV)**, **NIST NVD CVEs**, and **GitHub High/Critical Supply-Chain Advisories (GHSA)**.

## Tools Exposed

1. **`scan_domain_surface(domain: str)`**
   - Performs passive Certificate Transparency subdomain enumeration, live TLS certificate inspection, HTTP security header posture scoring, and CVE banner correlation.
2. **`check_cve_exposure(query: str)`**
   - Queries the live Argon database of CISA KEV zero-days, NVD CVEs, and GitHub Security Advisories by package name, vendor, or CVE/GHSA ID.

## Quickstart

### 1. Install
```bash
pip install argon-recon-mcp
# or run directly from source:
python -m argon_recon_mcp.server
```

### 2. Configure in Claude Desktop / Cursor / Antigravity (`mcp_config.json`)
```json
{
  "mcpServers": {
    "argon-recon": {
      "command": "argon-recon-mcp",
      "env": {
        "ARGON_API_KEY": "optional_pro_api_key_for_unlimited_scans"
      }
    }
  }
}
```

## Free vs. Pro Tier
- **Free Tier (No API Key Required):** Up to 5 live scans per hour per IP.
- **Pro Tier (€49/mo):** Unlimited API scans, 6-hour automated domain drift & CVE monitoring, and real-time Slack/Discord/HTTPS webhook alerts.
  - Activate instant self-serve API access at **[https://argon.kenetic0x00.com](https://argon.kenetic0x00.com)**.
