# WP Realtime WAF

WP Realtime WAF provides a real-time web application firewall for WordPress installations.

## Installation

1. Copy the `wp-realtime-waf` directory into `wp-content/plugins`.
2. (Optional) Copy `mu-loader.php` into `wp-content/mu-plugins` to ensure early loading.
3. Run `composer install` inside the plugin directory to install dependencies.
4. Activate the plugin from the WordPress admin panel.

## Architecture Overview

The plugin uses a lightweight service container to wire the real-time inspection pipeline. Early boot is performed through a must-use loader and a dedicated bootstrapper so the firewall can observe traffic before WordPress core loads. Administrative settings register through the WordPress Settings API with monitor mode as the safe default.

### Core Request Pipeline

1. **Normalization** – Every request is converted into a normalized structure that flattens query/body/cookie data, lowercases headers, and resolves the client IP with trusted proxy awareness.
2. **Prefilter** – Low-cost checks short-circuit allow/deny decisions using IP allow/block lists, user-agent filters, and adaptive rate limiting before expensive rule evaluation.
3. **Rule Engine** – Cached JSON rules are evaluated with compiled regular expressions across configurable targets (URI, headers, body, etc.).
4. **Decision Engine** – Global mode (monitor/block/challenge) and per-rule outcomes are combined to produce the final action. Enforcement defaults to monitor-only until administrators opt-in to blocking.

Rate limiting prefers Redis (via Predis) when available and automatically falls back to a WordPress options-backed sliding window store. Rule sources are loaded once from `rules/builtin/*.json` via the rule loader to avoid I/O on hot paths.

### Built-in Detection Coverage

The plugin ships with a curated baseline of OWASP-inspired signatures located in `rules/builtin/`:

- **SQL Injection** – Detects UNION-based payloads, boolean tautologies, and timing attacks.
- **Cross-Site Scripting** – Blocks injected `<script>` tags, JavaScript protocol abuse, and event handler injection attempts.
- **Local/Remote File Inclusion** – Prevents directory traversal, sensitive file access, and remote URL inclusions.
- **Command Injection / RCE** – Flags shell command chaining, dangerous PHP execution functions, and backtick execution attempts.

Each rule defines severity, enable/disable flags, and descriptive metadata. Administrators will be able to extend or override these rules in later phases.

### Authentication Protections

Phase 5 introduces dedicated hardening for authentication entry points:

- **Login Attempt Limiter** – Enforces both per-IP and per-user thresholds with automatic lockouts and safe defaults. Counters persist through option storage so limits survive PHP restarts, while success resets clear lockouts.
- **REST API Guard** – Optional filter that can require a valid REST nonce for anonymous requests or fully disallow unauthenticated access except for administrator-configured allowlists.
- **XML-RPC Guard** – Allows installations to disable XML-RPC entirely or prune sensitive methods (pingbacks are blocked by default) without touching core files.
- **Two-Factor Hook** – When enabled, the firewall triggers the `wp_realtime_waf_two_factor_authenticate` filter and `wp_realtime_waf_two_factor_challenge` action so external providers can enforce additional verification before logins complete.

All features are exposed under the Settings API payload (`auth` group) and default to conservative values to avoid accidental lockouts. Administrators can adjust thresholds, messages, and allowlists directly from stored options.

### File Integrity Monitoring & Malware Scan

Phase 6 introduces file integrity monitoring that builds a SHA-256 baseline across WordPress core, plugins, and themes. Baselines are stored via the multisite-safe options store and can be regenerated on demand or automatically scheduled. When scans run, the monitor reports added, removed, and modified files and reuses quarantine metadata so administrators can triage suspicious artifacts without deleting them.

A lightweight malware scanner inspects the same directories for high-risk functions (`eval`, `system`, `shell_exec`, etc.). Matches are optionally quarantined, tagged with timestamps and reasons, and surfaced through the integrity report API so downstream alerting can warn operators.

Settings include toggles for auto-build, per-directory inclusion, and whether malware scans should quarantine matches or operate in audit-only mode.

### Admin Dashboard, Logging, and Alerts

Phase 7 introduces a lightweight WordPress-admin dashboard under **Settings → WP Realtime WAF** that surfaces:

- **Threat overview cards** summarizing allow/monitor/block/challenge decisions.
- **Top attackers** aggregated by IP address to quickly identify noisy clients.
- **Recent security events** with pagination, anonymized IP support, and contextual metadata (rule ID, path, severity).

All events are stored through a configurable ring buffer that defaults to anonymizing IP addresses and retains up to 1,000 entries. Administrators can adjust logging behaviour (max events, default severity, alert thresholds, anonymization) directly from the settings form.

#### Alerts

- Email alerts target the WordPress admin address by default and honour global throttling to avoid notification floods.
- Webhook alerts post JSON payloads with optional HMAC signatures so downstream systems can verify authenticity.
- Both transports can be restricted to only fire for blocking/challenge outcomes or for high-severity matches.

#### Export & Import

- One-click export of logs (JSON or CSV) and custom rule sets through signed admin-post endpoints.
- Custom rule imports accept JSON uploads, sanitize payloads, and persist through the rule manager so additional signatures survive cache clears.

The dashboard respects the emergency disable token and continues to render even if WordPress helper functions (e.g., `settings_fields`) are unavailable, falling back to safe read-only messaging.

## Rule Feed Auto-Updates

The plugin verifies a signed local rule feed (`rules/feed/local-feed.json`) on every bootstrap. The feed payload is signed with an HMAC-SHA256 digest using the shared secret `wprtwaf-local-feed-secret`. When the signature and expiry window validate, the updater stores the new rules in WordPress options so they persist even if the feed file becomes unavailable. To publish new feed rules:

1. Update the `payload` section of the feed file with the revised metadata and rules.
2. Recompute the signature using `hash_hmac('sha256', json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 'wprtwaf-local-feed-secret')`.
3. Replace the `signature` field in `local-feed.json` and commit the change.

Feed state (version, hashes, and the sanitized rules) is stored under the `wp_realtime_waf_rule_feed_state` option to support cache warmups and rollbacks.

## Safe Mode

Define `WP_REALTIME_WAF_DISABLE_UNTIL` with a future timestamp or set the site option `wp_realtime_waf_disable_until` to temporarily disable protections (default 15 minutes).

The plugin defaults to monitor-only mode. Configure the admin setting or set environment variable `WAF_MODE=block` to enforce blocking. IP allow/block lists and user-agent filters are available from the settings API and respected during prefiltering.

## Quality Assurance

### Automated Checks

- `composer test` – Runs the unit and integration suites.
- `composer phpstan` – Executes PHPStan level 7 analysis against `src/` with bleeding edge rules enabled.
- `composer psalm` – Runs Psalm (distributed as a PHAR) using `psalm.xml`. Use PHP 8.2+ when invoking the PHAR.
- `composer coverage` – Generates a coverage report. Enable Xdebug or PCOV by exporting `XDEBUG_MODE=coverage` before running.

### Fuzz Harness

`tests/integration/FuzzPipelineTest.php` feeds non-ASCII, deeply nested, and malicious markers through the normalization and rule engine pipeline to assert predictable behaviour. Execute only the fuzz suite via:

```bash
composer test -- --testsuite Integration
```

This harness doubles as a seed corpus for future property-based fuzzing.

### Static Analysis Configuration

- **PHPStan:** Configuration lives in `phpstan.neon` with a temporary directory under `var/phpstan`. Adjust the level or add ignore rules as needed.
- **Psalm:** `psalm.xml` ignores tests by default and lowers the severity of mixed-type issues to informative reports, making it safe to run in CI without breaking builds.

## Performance Notes

High-level recommendations and the current performance model live in [`docs/performance.md`](docs/performance.md). Key highlights:

- Configuration, rules, and counters are cached in-memory per request to avoid database calls.
- Rate limiting remains O(1) with hashed buckets, preferring Redis pipelines whenever possible.
- The admin dashboard surfaces threat ratios so noisy signatures can be flipped to monitor-only before impacting users.

Refer to the performance guide for benchmarking tips when tuning rules or enabling block mode.

## Packaging & Distribution

Run the release helper to generate a production zip without development dependencies:

```bash
composer package
```

The script copies runtime assets into `build/` and prunes dev-only Composer packages before emitting `dist/wp-realtime-waf-<version>.zip`. The resulting archive contains the MU loader, vendor dependencies, signed rule feed, and documentation, making it suitable for manual uploads or CI release jobs.
