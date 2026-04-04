from __future__ import annotations

from typing import Any


def correlate_results(
    log_analysis: dict[str, Any] | None,
    port_analysis: dict[str, Any] | None,
) -> dict[str, Any]:
    log_score = int((log_analysis or {}).get("score", 0))
    port_score = int((port_analysis or {}).get("score", 0))

    score = round((log_score * 0.6) + (port_score * 0.4))
    rules_fired: list[dict[str, Any]] = []
    reasons: list[dict[str, str]] = []
    attack_paths: list[dict[str, str]] = []
    suggested_actions: set[str] = set()

    log_summary = (log_analysis or {}).get("summary", {})
    failed_logins = int(log_summary.get("failed_login_count", 0))
    off_hours = int(log_summary.get("off_hours_count", 0))
    privilege_escalation = int(log_summary.get("privilege_escalation_count", 0))
    pattern_matches = int(log_summary.get("pattern_matches", 0))
    success_after_failure = len((log_analysis or {}).get("success_after_failure", []))

    open_ports = (port_analysis or {}).get("open_ports", [])
    open_port_numbers = {int(item.get("port", -1)) for item in open_ports}
    open_services = {str(item.get("service", "")).upper() for item in open_ports}

    if failed_logins >= 5 and 22 in open_port_numbers:
        add_rule(
            rules_fired,
            reasons,
            attack_paths,
            18,
            "Credential pressure on exposed SSH",
            "Multiple failed logins align with an exposed SSH service.",
            ["Failed login cluster", "Port 22 / SSH open"],
            "Remote access brute-force path",
        )
        suggested_actions.update(
            {
                "Restrict SSH exposure to trusted addresses.",
                "Rotate credentials or enforce MFA for SSH-facing accounts.",
            }
        )

    if failed_logins >= 5 and 3389 in open_port_numbers:
        add_rule(
            rules_fired,
            reasons,
            attack_paths,
            18,
            "Credential pressure on exposed RDP",
            "Authentication failures align with a reachable remote desktop service.",
            ["Failed login cluster", "Port 3389 / RDP open"],
            "Remote desktop intrusion path",
        )
        suggested_actions.update(
            {
                "Move RDP behind VPN or a bastion host.",
                "Review lockout controls on Windows remote-access accounts.",
            }
        )

    if pattern_matches >= 1 and ({80, 443, 8080} & open_port_numbers):
        add_rule(
            rules_fired,
            reasons,
            attack_paths,
            16,
            "Exploit strings against exposed web services",
            "Web attack signatures were found while HTTP or HTTPS services are reachable.",
            ["Web exploit patterns present", "Web service exposure confirmed"],
            "Application-layer intrusion path",
        )
        suggested_actions.update(
            {
                "Inspect web server access logs and WAF events around the matched requests.",
                "Patch the application entry points exposed on web ports.",
            }
        )

    if privilege_escalation >= 1 and ({22, 3389, 445} & open_port_numbers):
        add_rule(
            rules_fired,
            reasons,
            attack_paths,
            15,
            "Privilege escalation near an administrative surface",
            "Privileged access attempts occurred while remote administration services were available.",
            ["Privilege escalation indicators", "Administrative port exposure"],
            "Lateral movement and privilege escalation path",
        )
        suggested_actions.update(
            {
                "Audit administrative accounts used on exposed management services.",
                "Review whether privileged commands were attempted after remote logins.",
            }
        )

    if off_hours >= 2 and ({22, 3389, 5432, 6379, 9200} & open_port_numbers):
        add_rule(
            rules_fired,
            reasons,
            attack_paths,
            10,
            "Off-hours activity around sensitive services",
            "Nighttime activity coincides with services that warrant closer oversight.",
            ["Off-hours event spike", "Sensitive port exposed"],
            "Low-visibility persistence window",
        )
        suggested_actions.add("Increase alerting sensitivity for overnight access to sensitive services.")

    if success_after_failure >= 1:
        add_rule(
            rules_fired,
            reasons,
            attack_paths,
            18,
            "Potential brute-force success path",
            "A successful session appeared after related failed login attempts.",
            ["Successful access after prior failures"],
            "Credential compromise path",
        )
        suggested_actions.add("Validate whether the successful session belongs to a legitimate operator.")

    if {445, 6379, 9200} & open_port_numbers and pattern_matches:
        add_rule(
            rules_fired,
            reasons,
            attack_paths,
            14,
            "High-value service exposure with suspicious behavior",
            "Sensitive file-sharing or datastore services are exposed alongside suspicious log patterns.",
            ["Sensitive service open", "Suspicious pattern match"],
            "Data exposure or staging path",
        )
        suggested_actions.add("Keep data stores and file-sharing services off public interfaces.")

    score += sum(rule["weight"] for rule in rules_fired)
    score = min(score, 100)
    risk_level = score_to_level(score)
    confidence = min(0.97, 0.48 + (0.1 if log_analysis else 0) + (0.1 if port_analysis else 0) + (0.05 * len(rules_fired)))

    if not reasons:
        if score >= 35:
            reasons.append(
                {
                    "title": "Single-module elevated finding",
                    "detail": "One enabled module produced a meaningful risk score even without cross-module confirmation.",
                }
            )
        else:
            reasons.append(
                {
                    "title": "Limited correlated risk",
                    "detail": "The current data did not trigger strong multi-condition threat rules.",
                }
            )

    suggested_actions.update((log_analysis or {}).get("actions", []))
    suggested_actions.update((port_analysis or {}).get("actions", []))

    if risk_level == "HIGH":
        headline = "Multiple signals align into a likely active threat path."
    elif risk_level == "MEDIUM":
        headline = "Cross-signal risk is present and warrants active monitoring."
    else:
        headline = "Current evidence suggests a contained or low-confidence threat posture."

    if open_services:
        primary_surface = ", ".join(sorted(open_services)[:3])
    else:
        primary_surface = "log telemetry"

    return {
        "enabled": True,
        "risk_level": risk_level,
        "score": score,
        "confidence": round(confidence, 2),
        "headline": headline,
        "primary_surface": primary_surface,
        "reasons": reasons,
        "rules_fired": rules_fired,
        "attack_paths": attack_paths,
        "recommended_actions": sorted(suggested_actions),
    }


def add_rule(
    rules_fired: list[dict[str, Any]],
    reasons: list[dict[str, str]],
    attack_paths: list[dict[str, str]],
    weight: int,
    title: str,
    detail: str,
    evidence: list[str],
    attack_path: str,
) -> None:
    rules_fired.append(
        {
            "title": title,
            "detail": detail,
            "weight": weight,
            "evidence": evidence,
        }
    )
    reasons.append({"title": title, "detail": detail})
    attack_paths.append(
        {
            "name": attack_path,
            "severity": score_to_level(weight * 4),
            "summary": detail,
        }
    )


def score_to_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"
