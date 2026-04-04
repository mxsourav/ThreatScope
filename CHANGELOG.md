# Changelog

All notable changes to this project are recorded here.

## [1.1.0] - 2026-04-04
### Updated
- Reworked the control deck into wider horizontal module keys with clearer labels and calmer motion.
- Tightened action buttons into a more mechanical keyboard style with stronger press depth and reduced padding.
- Tuned light mode toward a cleaner white and sky-blue finish with higher text readability.
- Swapped idle `LOW` placeholders to yellow `NULL` states for ready-only cards.
- Added footer credit and GitHub profile link for MX SOURAV.
- Replaced the oversized draft mark with a smaller text-based logo and cleaned the hero cards in light mode.
- Rebuilt the control deck for a cleaner mobile-centered flow with a configurable API route field for hosted backends.
- Animated the ambient dotted background with slow drift layers in dark and light themes.

### Added
- Static-host fallback analysis path so the frontend can still run from GitHub Pages without the Flask backend.
- GitHub Pages deployment workflow for publishing the frontend automatically from `main`.
- Render deployment support with CORS-enabled backend startup and a checked-in `render.yaml`.

## [1.0.0] - 2026-04-04
### Published
- First public release of ThreatScope.

### Added
- Rule-based log analysis for repeated login failures, suspicious patterns, timing anomalies, and privilege escalation signals.
- Basic port scanning with live and deterministic simulation modes.
- Correlation engine that combines module output into a structured threat level with reasons and actions.
- Adaptive dashboard UI with dark and light themes, threat dial, export action, and optional NVIDIA explanation layer.
- MIT license and open-source repo packaging.
