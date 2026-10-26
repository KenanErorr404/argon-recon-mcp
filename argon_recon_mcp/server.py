import json
import os
import sys
from typing import Any, Dict
import httpx

ARGON_BASE_URL = os.environ.get("ARGON_BASE_URL", "https://argon.kenetic0x00.com").rstrip("/")
ARGON_API_KEY = os.environ.get("ARGON_API_KEY", "").strip()
UPGRADE_FOOTER = (
    "\n\n---\n"
    "⚡ Upgrade to unlimited scans & 6h automated webhook monitoring (€49/mo): https://argon.kenetic0x00.com"
)

TOOLS = [
    {
        "name": "scan_domain_surface",
        "description": (
            "Passive attack surface reconnaissance for a public domain: discovers subdomains via Certificate "
            "Transparency (crt.sh) & TLS SANs, inspects SSL/TLS certificates, scores HTTP security headers, "
            "and correlates detected server banners against CISA KEV & GitHub Critical Advisories."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Public domain name to scan (e.g. 'cloudflare.com', 'kenetic0x00.com').",
                }
            },
            "required": ["domain"],
        },
    },
    {
        "name": "check_cve_exposure",
        "description": (
            "Checks live CISA Known Exploited Vulnerabilities (KEV), NIST NVD CVEs, and GitHub High/Critical "
            "Security Advisories (GHSA) for a specific package, vendor, or CVE ID."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Package name, vendor, or CVE/GHSA identifier (e.g. 'wasmtime', 'CVE-2026-115889').",
                }
            },
            "required": ["query"],
        },
    },
]


def _call_argon_scan(target: str) -> str:
    headers: Dict[str, str] = {"Content-Type": "application/json", "User-Agent": "argon-recon-mcp/1.0.0"}
    if ARGON_API_KEY:
        headers["X-API-Key"] = ARGON_API_KEY

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(f"{ARGON_BASE_URL}/api/scan", headers=headers, json={"target": target})
            if resp.status_code == 429:
                return (
                    f"Rate limit reached (5 free scans/hour per IP): {resp.text}"
                    f"{UPGRADE_FOOTER}"
                )
            data = resp.json()
            formatted = json.dumps(data, indent=2)
            return f"{formatted}{UPGRADE_FOOTER}"
    except Exception as exc:
        return f"Error querying Argon Recon Node ({ARGON_BASE_URL}): {exc}{UPGRADE_FOOTER}"


def handle_rpc_request(req: Dict[str, Any]) -> Dict[str, Any] | None:
    method = req.get("method", "")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "argon-recon-mcp", "version": "1.0.0"},
            },
        }

    if method.startswith("notifications/"):
        return None

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params = req.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        if name == "scan_domain_surface":
            target = str(args.get("domain", "")).strip()
            output = _call_argon_scan(target)
        elif name == "check_cve_exposure":
            target = str(args.get("query", "")).strip()
            output = _call_argon_scan(target)
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {name}"},
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": output}], "isError": False},
        }

    if req_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def main() -> None:
    """Stdio JSON-RPC 2.0 loop for Model Context Protocol (MCP)."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = handle_rpc_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
