# Changelog

All notable changes to this project are recorded here.

## [1.2.4] - 2026-04-04
### Updated
- Increased the ambient grain visibility so the texture reads clearly again without overwhelming the UI.
- Added smoother roaming motion across the page so the grain drifts through the surface instead of zooming toward the viewer.
- Tuned drift, density, and opacity to keep the effect more cinematic and less like flat static.

## [1.2.3] - 2026-04-04
### Updated
- Smoothed the animated background texture by crossfading slow noise fields instead of redrawing hard random static every cycle.
- Reduced the harsh TV-static feel and shifted the motion toward softer, more cinematic surface shimmer.
- Kept the canvas effect lightweight while preserving the same background-only layout behavior.

## [1.2.2] - 2026-04-04
### Updated
- Replaced the CSS-only background grain with a live canvas-based shimmer layer for a finer Magic Eraser-style texture.
- Tuned the background particles toward denser micro-speckles with softer blur and low-amplitude drift instead of larger star-like points.
- Kept the effect behind the interface so the layout and content remain unchanged while the surface feels more alive.

## [1.2.1] - 2026-04-04
### Updated
- Replaced the animated dotted backdrop with a softer full-screen grain layer for a calmer textured surface.
- Added subtle film-noise flicker and micro-shift blending to the background without changing layout or readability.
- Wired the Vercel frontend host to the live Render backend URL provided for hosted analysis mode.

## [1.2.0] - 2026-04-04
### Updated
- Refined the findings board so reasons and actions render as clearer indexed callouts with stronger visual separation.
- Added capped internal scrolling to long output sections so the dashboard stays compact instead of stretching endlessly.
- Reworked the NVIDIA explanation card for split-screen and medium-width layouts to prevent collapsed vertical text.
- Added colored edge accents across findings, port exposure cards, trace cards, and attack-path cards for faster scanning.
- Restored the browser-side static analysis fallback by wiring the missing threat-level scoring helper.
- Audited the responsive layout across dark and light themes at multiple viewport sizes before publishing.

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
- Aligned the NVIDIA environment variable names with the hosted backend configuration and prewired the frontend to the Render API base.

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
