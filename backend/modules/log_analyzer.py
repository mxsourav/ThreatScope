from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

FAILED_LOGIN_PATTERNS = (
    re.compile(r"failed password", re.IGNORECASE),
    re.compile(r"authentication failure", re.IGNORECASE),
    re.compile(r"login failed", re.IGNORECASE),
    re.compile(r"invalid user", re.IGNORECASE),
    re.compile(r"failed login", re.IGNORECASE),
)

SUCCESS_LOGIN_PATTERNS = (
    re.compile(r"accepted password", re.IGNORECASE),
    re.compile(r"accepted publickey", re.IGNORECASE),
    re.compile(r"session opened", re.IGNORECASE),
    re.compile(r"login succeeded", re.IGNORECASE),
    re.compile(r"logged in", re.IGNORECASE),
)

PRIVILEGE_ESCALATION_PATTERNS = (
    re.compile(r"sudo:.*authentication failure", re.IGNORECASE),
    re.compile(r"su: authentication failure", re.IGNORECASE),
    re.compile(r"permission denied", re.IGNORECASE),
    re.compile(r"user=root", re.IGNORECASE),
    re.compile(r"pam_unix\(sudo:auth\)", re.IGNORECASE),
)

SUSPICIOUS_PATTERN_GROUPS = {
    "credential_abuse": (
        re.compile(r"password spray", re.IGNORECASE),
        re.compile(r"brute force", re.IGNORECASE),
        re.compile(r"credential stuffing", re.IGNORECASE),
    ),
    "web_exploit": (
        re.compile(r"or\s+1=1", re.IGNORECASE),
        re.compile(r"union\s+select", re.IGNORECASE),
        re.compile(r"\.\./", re.IGNORECASE),
        re.compile(r"etc/passwd", re.IGNORECASE),
        re.compile(r"<script", re.IGNORECASE),
        re.compile(r"wp-admin", re.IGNORECASE),
    ),
    "command_execution": (
        re.compile(r"(curl|wget).*(sh|bash)", re.IGNORECASE),
        re.compile(r"powershell\s+-enc", re.IGNORECASE),
        re.compile(r"cmd\.exe\s+/c", re.IGNORECASE),
        re.compile(r"nc\s+-e", re.IGNORECASE),
        re.compile(r"bash\s+-i", re.IGNORECASE),
    ),
    "reconnaissance": (
        re.compile(r"\bnmap\b", re.IGNORECASE),
        re.compile(r"\bmasscan\b", re.IGNORECASE),
        re.compile(r"\bnikto\b", re.IGNORECASE),
        re.compile(r"dirbuster", re.IGNORECASE),
        re.compile(r"sqlmap", re.IGNORECASE),
    ),
}

MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

IP_PATTERN = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
USER_PATTERNS = (
    re.compile(r"for (invalid user )?(?P<user>[\w.@-]+)", re.IGNORECASE),
    re.compile(r"user=(?P<user>[\w.@-]+)", re.IGNORECASE),
)


def analyze_logs(raw_text: str) -> dict[str, Any]:
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if not lines:
        return {
            "enabled": True,
            "risk_level": "LOW",
            "score": 0,
            "summary": {
                "lines_processed": 0,
                "failed_login_count": 0,
                "successful_login_count": 0,
                "suspicious_ip_count": 0,
                "off_hours_count": 0,
                "pattern_matches": 0,
                "privilege_escalation_count": 0,
            },
            "findings": [],
            "reasoning": [],
            "suspicious_ips": [],
            "detected_patterns": [],
            "timing": {
                "off_hours_events": 0,
                "hour_distribution": {},
                "off_hours_samples": [],
            },
            "actions": [
                "Provide raw auth, system, or application logs to activate log correlation.",
            ],
            "success_after_failure": [],
        }

    failed_login_events: list[dict[str, Any]] = []
    successful_login_events: list[dict[str, Any]] = []
    off_hours_events: list[dict[str, Any]] = []
    privilege_escalation_events: list[dict[str, Any]] = []
    suspicious_pattern_hits: dict[str, list[dict[str, str]]] = defaultdict(list)

    ip_failures: Counter[str] = Counter()
    ip_activity: Counter[str] = Counter()
    ip_user_targets: dict[str, set[str]] = defaultdict(set)
    hour_distribution: Counter[int] = Counter()

    for index, line in enumerate(lines, start=1):
        lowered = line.lower()
        ip_address = extract_ip(line)
        username = extract_username(line)
        hour = extract_hour(line)

        if ip_address:
            ip_activity[ip_address] += 1
        if hour is not None:
            hour_distribution[hour] += 1
            if hour < 6 or hour >= 22:
                off_hours_events.append(
                    {
                        "line_number": index,
                        "hour": hour,
                        "sample": clip_line(line),
                    }
                )

        if any(pattern.search(lowered) for pattern in FAILED_LOGIN_PATTERNS):
            failed_login_events.append(
                {
                    "line_number": index,
                    "ip": ip_address,
                    "user": username,
                    "sample": clip_line(line),
                }
            )
            if ip_address:
                ip_failures[ip_address] += 1
                if username:
                    ip_user_targets[ip_address].add(username)

        if any(pattern.search(lowered) for pattern in SUCCESS_LOGIN_PATTERNS):
            successful_login_events.append(
                {
                    "line_number": index,
                    "ip": ip_address,
                    "user": username,
                    "sample": clip_line(line),
                }
            )

        if any(pattern.search(lowered) for pattern in PRIVILEGE_ESCALATION_PATTERNS):
            privilege_escalation_events.append(
                {
                    "line_number": index,
                    "sample": clip_line(line),
                }
            )

        for pattern_name, patterns in SUSPICIOUS_PATTERN_GROUPS.items():
            if any(pattern.search(lowered) for pattern in patterns):
                suspicious_pattern_hits[pattern_name].append(
                    {
                        "line_number": str(index),
                        "sample": clip_line(line),
                    }
                )

    failed_pairs = {
        (event.get("ip") or "-", event.get("user") or "-")
        for event in failed_login_events
    }

    success_after_failure = []
    for event in successful_login_events:
        pair = (event.get("ip") or "-", event.get("user") or "-")
        if pair in failed_pairs:
            success_after_failure.append(event)

    username_spray_sources = []
    for ip_address, targeted_users in ip_user_targets.items():
        if len(targeted_users) >= 3 and ip_failures[ip_address] >= 5:
            username_spray_sources.append(
                {
                    "ip": ip_address,
                    "users_targeted": sorted(targeted_users),
                    "failed_attempts": ip_failures[ip_address],
                }
            )

    suspicious_ips = []
    for ip_address, count in ip_activity.most_common(5):
        if ip_failures[ip_address] >= 2 or count >= 3:
            suspicious_ips.append(
                {
                    "ip": ip_address,
                    "activity_count": count,
                    "failed_attempts": ip_failures[ip_address],
                    "risk_hint": build_ip_risk_hint(ip_failures[ip_address], count),
                }
            )

    reasoning: list[dict[str, Any]] = []
    actions: set[str] = {
        "Retain recent auth and application logs for continued correlation.",
    }
    score = 0

    failed_login_count = len(failed_login_events)
    if failed_login_count >= 3:
        weight = 16 if failed_login_count < 8 else 28 if failed_login_count < 15 else 38
        score += weight
        reasoning.append(
            {
                "title": "Repeated login failures",
                "detail": f"{failed_login_count} failed login events were detected in the supplied log set.",
                "weight": weight,
            }
        )
        actions.add("Review authentication controls and lockout policy for the targeted accounts.")

    if len(suspicious_ips) >= 1:
        weight = 12 if len(suspicious_ips) == 1 else 18
        score += weight
        reasoning.append(
            {
                "title": "Concentrated activity from suspicious IPs",
                "detail": f"{len(suspicious_ips)} IP addresses generated repeated or clustered events.",
                "weight": weight,
            }
        )
        actions.add("Block or rate-limit the most active source IPs if they are not expected.")

    if off_hours_events:
        weight = 8 if len(off_hours_events) < 4 else 14
        score += weight
        reasoning.append(
            {
                "title": "Unusual timing window",
                "detail": f"{len(off_hours_events)} events occurred outside the expected daytime window.",
                "weight": weight,
            }
        )
        actions.add("Validate whether overnight access is expected for the affected systems.")

    pattern_match_count = sum(len(items) for items in suspicious_pattern_hits.values())
    if pattern_match_count:
        weight = 20 if pattern_match_count < 3 else 30
        score += weight
        reasoning.append(
            {
                "title": "Suspicious attack strings detected",
                "detail": f"{pattern_match_count} log lines matched exploit, command, or recon patterns.",
                "weight": weight,
            }
        )
        actions.add("Inspect the originating requests and isolate exposed workloads if exploitation is suspected.")

    if privilege_escalation_events:
        weight = 22 if len(privilege_escalation_events) < 3 else 32
        score += weight
        reasoning.append(
            {
                "title": "Privilege escalation indicators",
                "detail": f"{len(privilege_escalation_events)} lines suggest privileged access attempts or denials.",
                "weight": weight,
            }
        )
        actions.add("Audit privileged accounts and recent sudo or root activity.")

    if username_spray_sources:
        score += 12
        reasoning.append(
            {
                "title": "Username spray behavior",
                "detail": f"{len(username_spray_sources)} source IPs targeted multiple usernames in a short sequence.",
                "weight": 12,
            }
        )
        actions.add("Enforce MFA on remote-access accounts that appeared in the spray sequence.")

    if success_after_failure:
        score += 18
        reasoning.append(
            {
                "title": "Successful access after failed attempts",
                "detail": f"{len(success_after_failure)} successful logins matched a prior failed login source or account.",
                "weight": 18,
            }
        )
        actions.add("Investigate whether a compromised credential or delayed brute-force success occurred.")

    score = min(score, 100)
    risk_level = score_to_level(score)

    detected_patterns = []
    for pattern_name, hits in suspicious_pattern_hits.items():
        detected_patterns.append(
            {
                "name": pattern_name.replace("_", " ").title(),
                "count": len(hits),
                "samples": [item["sample"] for item in hits[:2]],
            }
        )

    findings = build_findings(
        failed_login_events=failed_login_events,
        username_spray_sources=username_spray_sources,
        off_hours_events=off_hours_events,
        privilege_escalation_events=privilege_escalation_events,
        suspicious_pattern_hits=suspicious_pattern_hits,
        success_after_failure=success_after_failure,
    )

    return {
        "enabled": True,
        "risk_level": risk_level,
        "score": score,
        "summary": {
            "lines_processed": len(lines),
            "failed_login_count": failed_login_count,
            "successful_login_count": len(successful_login_events),
            "suspicious_ip_count": len(suspicious_ips),
            "off_hours_count": len(off_hours_events),
            "pattern_matches": pattern_match_count,
            "privilege_escalation_count": len(privilege_escalation_events),
        },
        "findings": findings,
        "reasoning": reasoning,
        "suspicious_ips": suspicious_ips,
        "detected_patterns": detected_patterns,
        "timing": {
            "off_hours_events": len(off_hours_events),
            "hour_distribution": {str(hour): count for hour, count in sorted(hour_distribution.items())},
            "off_hours_samples": [item["sample"] for item in off_hours_events[:3]],
        },
        "actions": sorted(actions),
        "success_after_failure": [
            {
                "ip": event.get("ip"),
                "user": event.get("user"),
                "sample": event.get("sample"),
            }
            for event in success_after_failure[:3]
        ],
    }


def build_findings(
    *,
    failed_login_events: list[dict[str, Any]],
    username_spray_sources: list[dict[str, Any]],
    off_hours_events: list[dict[str, Any]],
    privilege_escalation_events: list[dict[str, Any]],
    suspicious_pattern_hits: dict[str, list[dict[str, str]]],
    success_after_failure: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if failed_login_events:
        findings.append(
            {
                "title": "Failed login cluster",
                "severity": "MEDIUM" if len(failed_login_events) < 10 else "HIGH",
                "detail": f"{len(failed_login_events)} failed authentication events were found.",
                "evidence": [event["sample"] for event in failed_login_events[:2]],
            }
        )

    if username_spray_sources:
        first_source = username_spray_sources[0]
        findings.append(
            {
                "title": "Credential spray source",
                "severity": "HIGH",
                "detail": f"{first_source['ip']} targeted {len(first_source['users_targeted'])} different usernames.",
                "evidence": first_source["users_targeted"][:3],
            }
        )

    if off_hours_events:
        findings.append(
            {
                "title": "Off-hours activity",
                "severity": "MEDIUM",
                "detail": f"{len(off_hours_events)} events landed in the overnight monitoring window.",
                "evidence": [item["sample"] for item in off_hours_events[:2]],
            }
        )

    if privilege_escalation_events:
        findings.append(
            {
                "title": "Privileged access pressure",
                "severity": "HIGH",
                "detail": f"{len(privilege_escalation_events)} lines indicate sudo, root, or permission escalation attempts.",
                "evidence": [item["sample"] for item in privilege_escalation_events[:2]],
            }
        )

    for pattern_name, hits in suspicious_pattern_hits.items():
        findings.append(
            {
                "title": f"{pattern_name.replace('_', ' ').title()} indicators",
                "severity": "HIGH" if pattern_name in {"web_exploit", "command_execution"} else "MEDIUM",
                "detail": f"{len(hits)} lines matched the {pattern_name.replace('_', ' ')} rule set.",
                "evidence": [item["sample"] for item in hits[:2]],
            }
        )

    if success_after_failure:
        findings.append(
            {
                "title": "Success after failure",
                "severity": "HIGH",
                "detail": "A successful session followed a related failed authentication pattern.",
                "evidence": [item["sample"] for item in success_after_failure[:2]],
            }
        )

    return findings


def extract_ip(line: str) -> str | None:
    match = IP_PATTERN.search(line)
    if not match:
        return None
    candidate = match.group(0)
    octets = candidate.split(".")
    if any(int(octet) > 255 for octet in octets):
        return None
    return candidate


def extract_username(line: str) -> str | None:
    for pattern in USER_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group("user")
    return None


def extract_hour(line: str) -> int | None:
    iso_match = re.search(r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})[ T](?P<hour>\d{2}):(?P<minute>\d{2})", line)
    if iso_match:
        try:
            return int(iso_match.group("hour"))
        except ValueError:
            return None

    syslog_match = re.search(r"(?P<month>[A-Za-z]{3})\s+\d{1,2}\s+(?P<hour>\d{2}):(?P<minute>\d{2}):\d{2}", line)
    if syslog_match:
        month_key = syslog_match.group("month").lower()
        if month_key in MONTHS:
            try:
                parsed = datetime(
                    datetime.now().year,
                    MONTHS[month_key],
                    1,
                    int(syslog_match.group("hour")),
                    int(syslog_match.group("minute")),
                )
                return parsed.hour
            except ValueError:
                return None
    return None


def clip_line(line: str, limit: int = 140) -> str:
    stripped = " ".join(line.split())
    if len(stripped) <= limit:
        return stripped
    return f"{stripped[: limit - 3]}..."


def score_to_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def build_ip_risk_hint(failed_attempts: int, activity_count: int) -> str:
    if failed_attempts >= 5:
        return "Likely brute-force source"
    if activity_count >= 4:
        return "Concentrated event source"
    return "Watch for repeat access"
