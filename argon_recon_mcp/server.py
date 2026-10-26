import ipaddress
import json
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List
import httpx

DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
SPONSOR_FOOTER = (
    "\n\n---\n"
    "☕ Found argon-recon-mcp useful? Support open-source development: "
    "https://buymeacoffee.com/kenanerorr404 | https://github.com/sponsors/KenanErorr404"
)

TOOLS = [
    {
        "name": "scan_domain_surface",
        "description": (
            "100% standalone passive attack surface reconnaissance for a public domain: "
            "discovers subdomains via Certificate Transparency (crt.sh) & TLS SANs, "
            "inspects SSL/TLS certificates, and scores HTTP security header posture directly "
            "from the client machine (zero external server required)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Public domain name to scan (e.g. 'cloudflare.com').",
                }
            },
            "required": ["domain"],
        },
    },
    {
        "name": "check_cve_exposure",
        "description": (
            "Queries live CISA Known Exploited Vulnerabilities (KEV) and GitHub High/Critical "
            "Security Advisories (GHSA) directly from official upstream feeds for a package, vendor, or CVE ID."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Package name, vendor, or CVE/GHSA identifier (e.g. 'wasmtime', 'chromium', 'CVE-2026').",
                }
            },
            "required": ["query"],
        },
    },
]


def _is_safe_public_host(hostname: str) -> bool:
    host = hostname.strip().lower().rstrip(".")
    if not host or host in ("localhost", "ip6-localhost") or host.endswith((".local", ".internal", ".lan", ".arpa")):
        return False
    try:
        addr_info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        if not addr_info:
            return False
        for item in addr_info:
            ip_obj = ipaddress.ip_address(item[4][0])
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return False
        return True
    except Exception:
        return False


def _scan_domain_standalone(domain: str) -> Dict[str, Any]:
    d = re.sub(r"^https?://", "", domain.strip().lower()).split("/")[0].split(":")[0].strip(".")
    if not DOMAIN_REGEX.match(d) or not _is_safe_public_host(d):
        return {"error": f"Invalid or restricted domain: {d}"}

    resolved_ips = sorted({item[4][0] for item in socket.getaddrinfo(d, None, proto=socket.IPPROTO_TCP)})

    # 1. Direct TLS Certificate & SAN inspection
    tls_info: Dict[str, Any] = {"status": "unreachable", "san_domains": []}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((d, 443), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=d) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", [])) if cert else {}
                san = [val for key, val in cert.get("subjectAltName", []) if key == "DNS"] if cert else []
                tls_info = {
                    "status": "valid",
                    "protocol": ssock.version(),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName") or "Unknown CA",
                    "not_after": cert.get("notAfter", "") if cert else "",
                    "san_domains": san[:25],
                }
    except Exception as exc:
        tls_info["detail"] = str(exc)[:100]

    # 2. Passive Certificate Transparency (crt.sh) with 4.5s timeout
    crt_subs: List[str] = []
    crt_status = "ok"
    try:
        with httpx.Client(timeout=4.5, headers={"User-Agent": "argon-recon-mcp/2.0.0"}) as client:
            r = client.get(f"https://crt.sh/?q=%.{d}&output=json&deduplicate=Y")
            if r.status_code == 200:
                subs = set()
                for entry in r.json()[:200]:
                    for line in (entry.get("name_value") or "").splitlines():
                        clean = line.strip().lower().lstrip("*.")
                        if clean.endswith(d) and DOMAIN_REGEX.match(clean):
                            subs.add(clean)
                crt_subs = sorted(subs)[:35]
            else:
                crt_status = f"http_{r.status_code}"
    except Exception:
        crt_status = "degraded_timeout"

    # 3. HTTP Security Header Posture
    http_posture: Dict[str, Any] = {"status": "unreachable"}
    try:
        with httpx.Client(timeout=4.0, follow_redirects=False, headers={"User-Agent": "argon-recon-mcp/2.0.0"}) as client:
            resp = client.get(f"https://{d}/")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            checks = {
                "strict-transport-security": bool(hdrs.get("strict-transport-security")),
                "content-security-policy": bool(hdrs.get("content-security-policy")),
                "x-frame-options": bool(hdrs.get("x-frame-options")),
                "x-content-type-options": bool(hdrs.get("x-content-type-options")),
                "referrer-policy": bool(hdrs.get("referrer-policy")),
            }
            missing = [k for k, ok in checks.items() if not ok]
            http_posture = {
                "status_code": resp.status_code,
                "server_banner": hdrs.get("server", ""),
                "score": f"{5 - len(missing)}/5",
                "missing_headers": missing,
            }
    except Exception as exc:
        http_posture["detail"] = str(exc)[:100]

    combined_subs = sorted(set(crt_subs) | set(tls_info.get("san_domains", [])))
    return {
        "target": d,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "resolved_ips": resolved_ips[:10],
        "tls_certificate": tls_info,
        "http_security_posture": http_posture,
        "passive_subdomains": {
            "crtsh_status": crt_status,
            "total_discovered": len(combined_subs),
            "subdomains": combined_subs[:35],
        },
    }


def _check_cve_standalone(query: str) -> Dict[str, Any]:
    q = query.strip().lower()
    results: List[Dict[str, Any]] = []

    with httpx.Client(
        timeout=6.0,
        headers={"User-Agent": "argon-recon-mcp/2.0.0", "Accept": "application/vnd.github+json"},
    ) as client:
        # 1. Search GitHub High & Critical Reviewed Advisories
        try:
            r_gh = client.get("https://api.github.com/advisories?per_page=30&type=reviewed")
            if r_gh.status_code == 200:
                for adv in r_gh.json():
                    blob = json.dumps(adv).lower()
                    if q in blob:
                        results.append(
                            {
                                "source": "GHSA",
                                "id": adv.get("ghsa_id"),
                                "cve_id": adv.get("cve_id"),
                                "severity": adv.get("severity"),
                                "summary": adv.get("summary"),
                                "url": adv.get("html_url"),
                            }
                        )
        except Exception:
            pass

        # 2. Search CISA Known Exploited Vulnerabilities (KEV)
        try:
            r_kev = client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            if r_kev.status_code == 200:
                for v in reversed(r_kev.json().get("vulnerabilities", [])):
                    blob = f"{v.get('cveID','')} {v.get('vendorProject','')} {v.get('product','')} {v.get('vulnerabilityName','')}".lower()
                    if q in blob:
                        results.append(
                            {
                                "source": "CISA-KEV",
                                "cve_id": v.get("cveID"),
                                "vendor": v.get("vendorProject"),
                                "product": v.get("product"),
                                "name": v.get("vulnerabilityName"),
                                "date_added": v.get("dateAdded"),
                                "due_date": v.get("dueDate"),
                            }
                        )
                        if len(results) >= 15:
                            break
        except Exception:
            pass

    return {
        "query": query,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "matches_count": len(results),
        "advisories": results[:15],
    }


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
                "serverInfo": {"name": "argon-recon-mcp", "version": "2.0.0"},
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
            res = _scan_domain_standalone(str(args.get("domain", "")))
            output = json.dumps(res, indent=2) + SPONSOR_FOOTER
        elif name == "check_cve_exposure":
            res = _check_cve_standalone(str(args.get("query", "")))
            output = json.dumps(res, indent=2) + SPONSOR_FOOTER
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
