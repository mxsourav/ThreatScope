from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"
load_dotenv(ENV_PATH)


def ai_available() -> bool:
    return bool(os.getenv("NVIDIA_API_KEY"))


def generate_explanation(report: dict[str, Any]) -> dict[str, Any]:
    if not ai_available():
        return {
            "available": False,
            "content": "AI explanation is unavailable because NVIDIA API credentials are not configured.",
            "model": None,
        }

    model = os.getenv("NVIDIA_MODEL", "meta/llama3-70b-instruct")
    client = OpenAI(
        base_url=os.getenv(
            "NVIDIA_BASE_URL",
            os.getenv("NVIDIA_API_BASE_URL", "https://integrate.api.nvidia.com/v1"),
        ),
        api_key=os.getenv("NVIDIA_API_KEY"),
    )

    payload = {
        "overall": report.get("overall", {}),
        "correlation": report.get("modules", {}).get("correlation", {}),
        "log_summary": report.get("modules", {}).get("log_analyzer", {}).get("summary", {}),
        "port_summary": report.get("modules", {}).get("port_scanner", {}).get("summary", {}),
        "open_ports": report.get("modules", {}).get("port_scanner", {}).get("open_ports", [])[:5],
        "log_findings": report.get("modules", {}).get("log_analyzer", {}).get("findings", [])[:5],
    }

    response = client.chat.completions.create(
        model=model,
        temperature=0.2,
        top_p=1,
        max_tokens=450,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an analyst assistant embedded inside a cybersecurity dashboard. "
                    "You may only explain the supplied structured findings. "
                    "Do not invent indicators, hosts, users, or remediation steps that are not supported."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Explain this threat analysis in markdown with exactly these sections: "
                    "Situation, Why It Was Flagged, Immediate Actions. "
                    "Each section must be concise and grounded only in the supplied JSON.\n\n"
                    f"{json.dumps(payload, ensure_ascii=True)}"
                ),
            },
        ],
    )

    content = response.choices[0].message.content if response.choices else ""
    return {
        "available": True,
        "content": (content or "").strip(),
        "model": model,
    }
