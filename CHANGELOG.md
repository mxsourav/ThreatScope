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

### Added
- Static-host fallback analysis path so the frontend can still run from GitHub Pages without the Flask backend.
- GitHub Pages deployment workflow for publishing the frontend automatically from `main`.

## [1.0.0] - 2026-04-04
### Published
- First public release of ThreatScope.

### Added
- Rule-based log analysis for repeated login failures, suspicious patterns, timing anomalies, and privilege escalation signals.
- Basic port scanning with live and deterministic simulation modes.
- Correlation engine that combines module output into a structured threat level with reasons and actions.
- Adaptive dashboard UI with dark and light themes, threat dial, export action, and optional NVIDIA explanation layer.
- MIT license and open-source repo packaging.
