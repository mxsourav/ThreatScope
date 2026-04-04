# ThreatScope

<!-- Header image placeholder: add the project banner here later. -->

ThreatScope is a web-based cybersecurity analysis dashboard built for structured, logic-first threat review. It analyzes raw logs, checks exposed services, and correlates the results into a clear threat rating with concrete reasons and response suggestions.

## What it does

- Reads authentication, system, and application log text.
- Detects repeated failures, suspicious patterns, off-hours activity, and privilege escalation hints.
- Scans a selected host with either a basic live check or a stable simulation profile.
- Correlates findings across modules instead of treating each result in isolation.
- Presents structured output in a dashboard instead of plain text.
- Generates an optional NVIDIA-backed explanation after the core analysis is finished.

## Core modules

### Log Analyzer
Finds login pressure, suspicious strings, abnormal timing, and signs of privilege misuse.

### Port Scanner
Maps open ports to common services and applies basic exposure risk rules.

### Correlation Engine
Combines evidence from the other modules to produce the final threat level.

## Stack

- Frontend: HTML, CSS, JavaScript
- Backend: Python, Flask
- Optional explanation layer: NVIDIA API through the OpenAI-compatible client

## Project layout

```text
backend/
  engine.py
  ai_explainer.py
  modules/
    log_analyzer.py
    port_scanner.py
    correlation.py

frontend/
  index.html
  style.css
  app.js
  assets/
```

## Run locally

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the backend:

```bash
python backend/engine.py
```

4. Open `http://127.0.0.1:5000`

## Environment setup

Copy `.env.example` to `.env` and add your NVIDIA credentials if you want the optional explanation feature. The core analysis engine works without it.

## Open source

This project is released under the MIT License. See [LICENSE](LICENSE).

## Release

- Current release: `v1.0.0`
- Publish date: `2026-04-04`
- Release notes: [CHANGELOG.md](CHANGELOG.md)

## Repository description

Rule-based cybersecurity analysis dashboard for logs, ports, and correlated threat insights.
