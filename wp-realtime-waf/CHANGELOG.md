# Changelog

## 1.0.0 - Signed feed & release packaging
- Added a signed rule feed updater with persisted state and verification to deliver incremental signature updates safely.
- Introduced a packaging helper that builds production-ready archives while pruning dev dependencies and ensuring vendor assets are bundled.
- Updated documentation, manifests, and version metadata for the 1.0.0 release, including new guidance on publishing feed updates.

## 0.1.0 - Initial scaffolding
- Initial plugin skeleton with early blocking proof of concept.
- Added bootstrap kernel, service container, and settings scaffolding for future phases.

## 0.1.1 - Core pipeline foundation
- Added request normalization, proxy-aware IP resolution, and prefilter allow/block logic.
- Implemented rule loader/engine with decision pipeline honoring monitor/block/challenge modes.
- Expanded admin settings defaults and added extensive unit tests for the new pipeline stages.

## 0.1.2 - Rate limiting infrastructure
- Introduced Redis-backed and options-based sliding window rate limit stores with automatic fallback handling.
- Wired adaptive IP and endpoint rate limiting into the prefilter and service container bootstrap.
- Extended settings defaults, sanitization, and unit coverage to configure rate limiting behaviour safely.

## 0.1.3 - Detection rules baseline
- Added OWASP-inspired SQLi, XSS, file inclusion, and command injection signatures under `rules/builtin/` with metadata.
- Normalized rule severity, enable/disable flags, and tags within the rule loader for consistent downstream processing.
- Ensured the rule engine skips disabled rules and extended unit coverage to validate the new normalization behaviours.

## 0.1.4 - Authentication hardening
- Added persistent login attempt limiting with configurable lockouts, IP/user thresholds, and two-factor integration hooks.
- Introduced REST API nonce enforcement/allowlist guards and XML-RPC method restrictions via settings-managed policies.
- Updated admin defaults, sanitization, and documentation plus comprehensive unit tests for the new auth protection services.

## 0.1.5 - Integrity monitoring and malware scan
- Implemented file integrity monitoring with baseline generation, change reporting, and quarantine metadata stored via multisite-safe options.
- Added configurable malware scanning heuristics with default signatures for high-risk PHP functions and automatic quarantine support.
- Wired the integrity services into the bootstrap container, exposed new settings defaults, and added targeted unit coverage for monitoring and storage layers.

## 0.1.6 - Admin dashboard, logging, and alerts
- Introduced a WordPress admin dashboard with threat metrics, top attacker summaries, paginated event logs, and configurable logging retention/anonymization.
- Added persistent event storage, JSON/CSV export, custom rule import/export management, and Monolog-backed file logging.
- Implemented email/webhook alerting with throttling, severity gating, and extensive unit coverage for the logging, alerting, and rule management subsystems.

## 0.1.7 - Quality gates and performance guidance
- Added PHPStan and Psalm configurations with Composer scripts so static analysis can run in CI alongside coverage reporting.
- Introduced an integration fuzz test exercising the request normalization and rule pipeline with complex payloads.
- Documented QA workflows and produced a standalone performance guide with benchmarking recommendations.
