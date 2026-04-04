from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory

try:
    from .ai_explainer import ai_available, generate_explanation
    from .modules.correlation import correlate_results
    from .modules.log_analyzer import analyze_logs
    from .modules.port_scanner import DEFAULT_PORTS, scan_ports
except ImportError:  # pragma: no cover
    from ai_explainer import ai_available, generate_explanation
    from modules.correlation import correlate_results
    from modules.log_analyzer import analyze_logs
    from modules.port_scanner import DEFAULT_PORTS, scan_ports

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")

    @app.get("/")
    def serve_index() -> Any:
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/api/health")
    def health_check() -> Any:
        return jsonify(
            {
                "status": "ok",
                "service": "ThreatScope backend",
                "ai_explainer_ready": ai_available(),
            }
        )

    @app.post("/api/analyze")
    def analyze() -> Any:
        payload = request.get_json(silent=True) or {}
        try:
            report = build_report(payload)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(report)

    @app.post("/api/explain")
    def explain() -> Any:
        payload = request.get_json(silent=True) or {}
        report = payload.get("report")
        if not isinstance(report, dict):
            return jsonify({"error": "A report object is required to generate an AI explanation."}), 400
        try:
            explanation = generate_explanation(report)
        except Exception as exc:  # pragma: no cover - network-dependent
            return jsonify({"error": f"AI explanation failed: {exc}"}), 502
        return jsonify(explanation)

    @app.get("/<path:path>")
    def serve_static(path: str) -> Any:
        file_path = FRONTEND_DIR / path
        if file_path.exists() and file_path.is_file():
            return send_from_directory(FRONTEND_DIR, path)
        return send_from_directory(FRONTEND_DIR, "index.html")

    return app


def build_report(payload: dict[str, Any]) -> dict[str, Any]:
    modules = payload.get("modules") or {}
    run_logs = bool(modules.get("logs", True))
    run_ports = bool(modules.get("ports", True))
    run_correlation = bool(modules.get("correlation", True))

    if not any([run_logs, run_ports, run_correlation]):
        raise ValueError("Enable at least one module before running an analysis.")
    if run_correlation and not any([run_logs, run_ports]):
        raise ValueError("Correlation needs log analysis, port scanning, or both to produce output.")

    log_text = str(payload.get("logText", ""))
    scan_target = payload.get("scanTarget") or {}
    port_list = parse_ports(scan_target.get("ports"))
    simulate = bool(scan_target.get("simulate", False))
    target_host = str(scan_target.get("host") or "127.0.0.1").strip()
    simulation_profile = str(scan_target.get("profile") or target_host).strip()

    log_analysis = analyze_logs(log_text) if run_logs else disabled_module("log_analyzer")
    port_analysis = (
        scan_ports(target_host, port_list, simulate=simulate, profile=simulation_profile)
        if run_ports
        else disabled_module("port_scanner")
    )
    correlation_analysis = (
        correlate_results(log_analysis if run_logs else None, port_analysis if run_ports else None)
        if run_correlation
        else disabled_module("correlation")
    )

    overall = build_overall(log_analysis, port_analysis, correlation_analysis, run_correlation)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_profile": {
            "modules": {
                "logs": run_logs,
                "ports": run_ports,
                "correlation": run_correlation,
            },
            "scan_target": {
                "host": target_host,
                "ports": port_list,
                "simulate": simulate,
                "profile": simulation_profile if simulate else None,
            },
            "log_lines_supplied": len([line for line in log_text.splitlines() if line.strip()]),
        },
        "overall": overall,
        "modules": {
            "log_analyzer": log_analysis,
            "port_scanner": port_analysis,
            "correlation": correlation_analysis,
        },
    }


def build_overall(
    log_analysis: dict[str, Any],
    port_analysis: dict[str, Any],
    correlation_analysis: dict[str, Any],
    correlation_enabled: bool,
) -> dict[str, Any]:
    if correlation_enabled:
        return {
            "threat_level": correlation_analysis.get("risk_level", "LOW"),
            "score": correlation_analysis.get("score", 0),
            "confidence": correlation_analysis.get("confidence", 0.0),
            "headline": correlation_analysis.get("headline", "Awaiting correlated evidence."),
            "reasons": correlation_analysis.get("reasons", []),
            "suggested_actions": correlation_analysis.get("recommended_actions", []),
        }

    dominant_module = max(
        [log_analysis, port_analysis],
        key=lambda item: int(item.get("score", 0)),
    )
    return {
        "threat_level": dominant_module.get("risk_level", "LOW"),
        "score": dominant_module.get("score", 0),
        "confidence": 0.55 if dominant_module.get("enabled") else 0.0,
        "headline": "Correlation module is disabled; showing the highest single-module risk.",
        "reasons": dominant_module.get("reasoning", []),
        "suggested_actions": dominant_module.get("actions", []),
    }


def parse_ports(raw_ports: Any) -> list[int]:
    if raw_ports is None or raw_ports == "":
        return DEFAULT_PORTS.copy()
    if isinstance(raw_ports, list):
        cleaned = []
        for item in raw_ports:
            try:
                value = int(item)
            except (TypeError, ValueError):
                continue
            if 1 <= value <= 65535:
                cleaned.append(value)
        return sorted(set(cleaned))[:32] or DEFAULT_PORTS.copy()

    if isinstance(raw_ports, str):
        cleaned = []
        for chunk in raw_ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                value = int(chunk)
            except ValueError:
                continue
            if 1 <= value <= 65535:
                cleaned.append(value)
        return sorted(set(cleaned))[:32] or DEFAULT_PORTS.copy()

    return DEFAULT_PORTS.copy()


def disabled_module(name: str) -> dict[str, Any]:
    return {
        "enabled": False,
        "module": name,
        "risk_level": "LOW",
        "score": 0,
        "summary": {},
        "reasoning": [],
        "actions": [],
    }


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
