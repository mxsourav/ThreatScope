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
  config.js
  assets/

render.yaml
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

## Render backend

The backend is ready to deploy on Render through `render.yaml`.

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn backend.engine:app`
- Default host binding: `0.0.0.0`
- Default CORS policy: `*` for `/api/*`
- NVIDIA env vars: `NVIDIA_API_KEY`, `NVIDIA_BASE_URL`, `NVIDIA_MODEL`

After deploying the backend, you can point the frontend to it in either of two ways:

- Paste the Render URL into the `API Base URL` field in the control deck.
- Set `window.THREATSCOPE_CONFIG.apiBaseUrl` in `frontend/config.js` before publishing the frontend.

## GitHub Pages

The repository includes a Pages workflow that publishes the frontend automatically from `main`.

- Hosted mode keeps the dashboard usable with an in-browser fallback engine.
- Live socket scanning and NVIDIA explanations require either the local Flask backend or a deployed backend such as Render.

## Open source

This project is released under the MIT License. See [LICENSE](LICENSE).

## Release

- Current release: `v1.2.2`
- Publish date: `2026-04-04`
- Release notes: [CHANGELOG.md](CHANGELOG.md)

## Repository description

Rule-based cybersecurity analysis dashboard for logs, ports, and correlated threat insights.
