# Performance Guidance

WP Realtime WAF is designed to execute in the early WordPress bootstrap without adding measurable latency.

## Hot Path Architecture

- **Immutable configuration cache:** Settings and compiled rules are hydrated once per request and stored in local memory so no database calls occur on the decision hot path.
- **O(1) rate limiting:** Sliding window counters use hashed keys and time bucketing to avoid linear scans. Redis pipelines are used automatically when the extension is available; the fallback options store keeps buckets bounded.
- **Low allocation normalizer:** Request normalization reuses array transforms and avoids recursion on common paths. Flattening short-circuits on scalar values to minimize string conversions.
- **Rule short-circuiting:** Rules are grouped by target, and once a match is found the engine stops processing. Compiled patterns are cached in-memory per request.

## Operational Recommendations

- Enable Redis for rate limiting to keep counter updates off the primary database connection.
- When enabling coverage reports, run PHPUnit with `XDEBUG_MODE=coverage` or pcov to avoid runtime overhead in production.
- Use the admin dashboard telemetry to watch allow vs. block ratios; noisy rules can be switched to monitor-only without disabling the firewall.
- Consider enabling IP anonymization in logging when operating behind CDNs to improve cache hit rates.

## Benchmark Harness

Use the integration fuzz test as a lightweight harness for stress-testing normalization and rule evaluation:

```bash
composer test -- --testsuite Integration
```

For load testing, replay sanitized access logs through the MU loader entry point using tools like `ab` or `wrk` while sampling PHP-FPM latency. Rule changes should be benchmarked before enabling block mode in production.
