# `argon-recon-mcp` — 100% Standalone Attack Surface & Live CVE Reconnaissance MCP Server

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/kenanerorr404)
[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-EA4AAA?style=for-the-badge&logo=github-sponsors&logoColor=white)](https://github.com/sponsors/KenanErorr404)

Zero-config, **100% standalone Model Context Protocol (MCP)** server (stdio JSON-RPC 2.0) that runs directly on the user's machine—**no backend server or API key required**.

Equips Claude Desktop, Cursor, Windsurf, and autonomous AI coding agents with live passive subdomain discovery (`crt.sh` + TLS SANs), SSL/TLS certificate inspection, HTTP security header posture scoring, and real-time correlation against **CISA Known Exploited Vulnerabilities (KEV)** and **GitHub Security Advisories (GHSA)**.

## Tools Exposed

1. **`scan_domain_surface(domain: str)`**
   - Performs passive Certificate Transparency (`crt.sh`) subdomain enumeration, live TLS socket certificate/SAN inspection, and HTTP security header posture scoring directly from the local client.
2. **`check_cve_exposure(query: str)`**
   - Queries the official CISA KEV catalog and GitHub Security Advisories API directly for any package, vendor, or CVE/GHSA ID.

## Quickstart (`mcp_config.json`)

```json
{
  "mcpServers": {
    "argon-recon": {
      "command": "uvx",
      "args": ["from", "git+https://github.com/KenanErorr404/argon-recon-mcp", "argon-recon-mcp"]
    }
  }
}
```

Or install locally via `pip`:
```bash
pip install git+https://github.com/KenanErorr404/argon-recon-mcp.git
```

## ☕ Support the Project

If `argon-recon-mcp` saves you time during security audits or attack surface recon, consider buying me a coffee!

<a href="https://www.buymeacoffee.com/kenanerorr404" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 50px !important;width: 181px !important;" ></a>
