from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5432, 5900, 6379, 8080, 9200]

PORT_SERVICE_MAP = {
    21: {
        "service": "FTP",
        "score": 22,
        "surface": "legacy-transfer",
        "detail": "Legacy file transfer channel",
        "action": "Disable FTP or replace it with SFTP.",
    },
    22: {
        "service": "SSH",
        "score": 16,
        "surface": "remote-admin",
        "detail": "Remote administration surface",
        "action": "Restrict SSH to trusted sources and key-based auth.",
    },
    23: {
        "service": "Telnet",
        "score": 36,
        "surface": "legacy-admin",
        "detail": "Cleartext remote administration",
        "action": "Close Telnet immediately and replace it with SSH.",
    },
    25: {
        "service": "SMTP",
        "score": 10,
        "surface": "mail",
        "detail": "Mail transfer service",
        "action": "Confirm the mail relay is expected and hardened.",
    },
    53: {
        "service": "DNS",
        "score": 9,
        "surface": "infra",
        "detail": "Domain name resolution service",
        "action": "Verify recursion and access policy.",
    },
    80: {
        "service": "HTTP",
        "score": 10,
        "surface": "web",
        "detail": "Web application surface",
        "action": "Review web logs and enforce redirects to HTTPS.",
    },
    110: {
        "service": "POP3",
        "score": 14,
        "surface": "mail",
        "detail": "Legacy mail retrieval",
        "action": "Retire POP3 if it is no longer required.",
    },
    143: {
        "service": "IMAP",
        "score": 12,
        "surface": "mail",
        "detail": "Mail access surface",
        "action": "Limit exposure and require strong auth.",
    },
    443: {
        "service": "HTTPS",
        "score": 8,
        "surface": "web",
        "detail": "Encrypted web application surface",
        "action": "Keep TLS and web application patches current.",
    },
    445: {
        "service": "SMB",
        "score": 30,
        "surface": "lateral-movement",
        "detail": "File sharing and lateral movement surface",
        "action": "Restrict SMB to internal trusted networks only.",
    },
    3389: {
        "service": "RDP",
        "score": 28,
        "surface": "remote-admin",
        "detail": "Remote desktop administration surface",
        "action": "Protect RDP with VPN, MFA, and IP allow-lists.",
    },
    5432: {
        "service": "PostgreSQL",
        "score": 20,
        "surface": "data-store",
        "detail": "Database listener",
        "action": "Keep the database private and limit direct client access.",
    },
    5900: {
        "service": "VNC",
        "score": 26,
        "surface": "remote-admin",
        "detail": "Remote screen-sharing surface",
        "action": "Close VNC externally or tunnel it through trusted paths.",
    },
    6379: {
        "service": "Redis",
        "score": 32,
        "surface": "data-store",
        "detail": "High-risk in-memory datastore when exposed",
        "action": "Bind Redis privately and require authentication.",
    },
    8080: {
        "service": "HTTP-Alt",
        "score": 14,
        "surface": "web",
        "detail": "Alternate web or admin listener",
        "action": "Confirm the alternate web port is intentional and patched.",
    },
    9200: {
        "service": "Elasticsearch",
        "score": 30,
        "surface": "data-store",
        "detail": "Search API surface commonly abused when public",
        "action": "Keep Elasticsearch private behind authenticated access.",
    },
}

SIMULATION_PROFILES = {
    "perimeter-gateway": [22, 80, 443, 8080],
    "database-node": [22, 5432, 6379],
    "remote-access": [22, 3389, 445],
}


def scan_ports(
    host: str,
    ports: list[int] | None = None,
    *,
    simulate: bool = False,
    profile: str | None = None,
    timeout: float = 0.35,
) -> dict[str, Any]:
    normalized_host = (host or "").strip() or "127.0.0.1"
    normalized_ports = normalize_ports(ports)
    mode = "SIMULATED" if simulate else "LIVE"

    if simulate:
        open_port_numbers = simulate_ports(profile or normalized_host, normalized_ports)
        closed_port_numbers = [port for port in normalized_ports if port not in open_port_numbers]
    else:
        try:
            socket.gethostbyname(normalized_host)
        except socket.gaierror:
            return {
                "enabled": True,
                "mode": mode,
                "scan_status": "FAILED",
                "target": normalized_host,
                "risk_level": "LOW",
                "score": 0,
                "summary": {
                    "ports_checked": len(normalized_ports),
                    "open_port_count": 0,
                    "high_risk_open_ports": 0,
                    "remote_admin_surfaces": 0,
                },
                "open_ports": [],
                "closed_ports": normalized_ports[:6],
                "reasoning": [
                    {
                        "title": "Host resolution failed",
                        "detail": f"The target host '{normalized_host}' could not be resolved for a live scan.",
                        "weight": 0,
                    }
                ],
                "actions": [
                    "Check the hostname or use simulation mode for a controlled demo profile.",
                ],
                "error": f"Unable to resolve '{normalized_host}'.",
            }

        open_port_numbers = live_scan(normalized_host, normalized_ports, timeout)
        closed_port_numbers = [port for port in normalized_ports if port not in open_port_numbers]

    open_ports = []
    reasoning: list[dict[str, Any]] = []
    actions: set[str] = {"Re-scan after remediation to confirm the attack surface has been reduced."}

    remote_admin_surfaces = 0
    high_risk_open_ports = 0
    score = 0

    for port in open_port_numbers:
        metadata = PORT_SERVICE_MAP.get(
            port,
            {
                "service": "Unknown",
                "score": 8,
                "surface": "generic",
                "detail": "Unmapped network listener",
                "action": "Validate why this service is exposed and whether it should remain open.",
            },
        )
        risk_level = service_risk_level(metadata["score"])
        open_ports.append(
            {
                "port": port,
                "service": metadata["service"],
                "risk": risk_level,
                "surface": metadata["surface"],
                "detail": metadata["detail"],
                "recommended_action": metadata["action"],
            }
        )
        score += metadata["score"]
        actions.add(metadata["action"])
        if metadata["surface"] in {"remote-admin", "legacy-admin"}:
            remote_admin_surfaces += 1
        if metadata["score"] >= 26:
            high_risk_open_ports += 1

    if open_ports:
        reasoning.append(
            {
                "title": "Exposed network services",
                "detail": f"{len(open_ports)} ports responded on the target host.",
                "weight": min(24, len(open_ports) * 5),
            }
        )

    if high_risk_open_ports:
        weight = 18 if high_risk_open_ports == 1 else 28
        score += weight
        reasoning.append(
            {
                "title": "High-risk services exposed",
                "detail": f"{high_risk_open_ports} exposed services are commonly abused when reachable.",
                "weight": weight,
            }
        )

    if remote_admin_surfaces >= 2:
        score += 12
        reasoning.append(
            {
                "title": "Multiple remote administration paths",
                "detail": "More than one remote administration service is open simultaneously.",
                "weight": 12,
            }
        )
        actions.add("Consolidate remote administration onto a single hardened access path.")

    if not open_ports:
        reasoning.append(
            {
                "title": "Minimal exposed surface",
                "detail": "No listed ports responded during this scan.",
                "weight": 0,
            }
        )
        actions.add("Keep validating additional asset scopes if this host should provide public services.")

    score = min(score, 100)
    risk_level = overall_risk_level(score)

    return {
        "enabled": True,
        "mode": mode,
        "scan_status": "COMPLETE",
        "target": normalized_host,
        "risk_level": risk_level,
        "score": score,
        "summary": {
            "ports_checked": len(normalized_ports),
            "open_port_count": len(open_ports),
            "high_risk_open_ports": high_risk_open_ports,
            "remote_admin_surfaces": remote_admin_surfaces,
        },
        "open_ports": open_ports,
        "closed_ports": closed_port_numbers[:8],
        "reasoning": reasoning,
        "actions": sorted(actions),
        "error": None,
    }


def normalize_ports(ports: list[int] | None) -> list[int]:
    if not ports:
        return DEFAULT_PORTS.copy()
    cleaned = sorted({port for port in ports if 1 <= port <= 65535})
    if not cleaned:
        return DEFAULT_PORTS.copy()
    return cleaned[:32]


def live_scan(host: str, ports: list[int], timeout: float) -> list[int]:
    with ThreadPoolExecutor(max_workers=min(16, len(ports) or 1)) as executor:
        futures = {executor.submit(test_port, host, port, timeout): port for port in ports}
        open_ports = [port for future, port in futures.items() if future.result()]
    return sorted(open_ports)


def test_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def simulate_ports(profile: str, normalized_ports: list[int]) -> list[int]:
    profile_key = profile.strip().lower()
    simulated_open = SIMULATION_PROFILES.get(profile_key)
    if simulated_open is None:
        if "db" in profile_key:
            simulated_open = SIMULATION_PROFILES["database-node"]
        elif "remote" in profile_key or "rdp" in profile_key:
            simulated_open = SIMULATION_PROFILES["remote-access"]
        else:
            simulated_open = SIMULATION_PROFILES["perimeter-gateway"]
    return sorted([port for port in simulated_open if port in normalized_ports])


def service_risk_level(score: int) -> str:
    if score >= 28:
        return "HIGH"
    if score >= 16:
        return "MEDIUM"
    return "LOW"


def overall_risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"
