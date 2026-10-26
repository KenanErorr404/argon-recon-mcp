import json
import os
import sys
from typing import Any, Dict
import httpx

ARGON_BASE_URL = os.environ.get("ARGON_BASE_URL", "http://127.0.0.1:8420").rstrip("/")

TOOLS = [
    {
        "name": "scan_domain_surface",
        "description": "Passive attack surface reconnaissance for a public domain via local Argon node.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Public domain name to scan.",
                }
            },
            "required": ["domain"],
        },
    },
    {
        "name": "check_cve_exposure",
        "description": "Checks local CISA KEV, NVD CVE, and GHSA database for a package, vendor, or CVE ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Package name, vendor, or CVE/GHSA identifier.",
                }
            },
            "required": ["query"],
        },
    },
]


def _call_argon_scan(target: str) -> str:
    headers: Dict[str, str] = {"Content-Type": "application/json", "User-Agent": "argon-recon-mcp/1.0.1"}
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(f"{ARGON_BASE_URL}/api/scan", headers=headers, json={"target": target})
            return json.dumps(resp.json(), indent=2)
    except Exception as exc:
        return f"Error querying local Argon node ({ARGON_BASE_URL}): {exc}"


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
                "serverInfo": {"name": "argon-recon-mcp", "version": "1.0.1"},
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
            output = _call_argon_scan(str(args.get("domain", "")).strip())
        elif name == "check_cve_exposure":
            output = _call_argon_scan(str(args.get("query", "")).strip())
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
