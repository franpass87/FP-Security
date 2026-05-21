<?php
/**
 * Runtime diagnostics FP Security (read-only).
 *
 * @package FP\Security\Services\Diagnostics
 */

declare(strict_types=1);

namespace FP\Security\Services\Diagnostics;

if (!defined('ABSPATH')) {
    exit;
}

final class RuntimeDiagnostics
{
    public const SECTION_LOGIN_EVENTS_RECENT = 'login_events_recent';
    public const SECTION_BLOCKLIST_STATUS = 'blocklist_status';
    public const SECTION_LOGIN_PROTECTION = 'login_protection';
    public const SECTION_MODULES_STATUS = 'modules_status';
    public const SECTION_LOGS_TAIL = 'logs_tail';
    public const SECTION_FIREWALL_BLOCKS_RECENT = 'firewall_blocks_recent';
    public const SECTION_LOCKOUT_ESCALATION = 'lockout_escalation';
    public const SECTION_PROBLEMS = 'problems';

    public const ALL_SECTIONS = [
        self::SECTION_LOGIN_EVENTS_RECENT,
        self::SECTION_BLOCKLIST_STATUS,
        self::SECTION_LOGIN_PROTECTION,
        self::SECTION_MODULES_STATUS,
        self::SECTION_LOGS_TAIL,
        self::SECTION_FIREWALL_BLOCKS_RECENT,
        self::SECTION_LOCKOUT_ESCALATION,
        self::SECTION_PROBLEMS,
    ];

    /**
     * @param array<int, string> $sections
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public static function build(array $sections = [], array $options = []): array
    {
        $requested = $sections === [] ? self::ALL_SECTIONS : array_values(array_intersect($sections, self::ALL_SECTIONS));
        if ($requested === []) {
            $requested = self::ALL_SECTIONS;
        }

        $limit = isset($options['events_limit']) ? max(1, min(100, (int) $options['events_limit'])) : 25;
        $hours = isset($options['lookback_hours']) ? max(1, (int) $options['lookback_hours']) : 168;

        $payload = [
            'plugin_active' => true,
            'plugin_version' => defined('FP_SECURITY_VERSION') ? (string) FP_SECURITY_VERSION : '',
            'available_sections' => self::ALL_SECTIONS,
            'requested_sections' => $requested,
            'generated_at_gmt' => gmdate('Y-m-d H:i:s'),
        ];

        $settings = get_option('fp_security_settings', []);
        $settings = is_array($settings) ? $settings : [];
        $allLogs = get_option('fp_security_log', []);
        $allLogs = is_array($allLogs) ? $allLogs : [];

        foreach ($requested as $section) {
            switch ($section) {
                case self::SECTION_LOGIN_EVENTS_RECENT:
                    $payload['login_events_recent'] = self::filter_log_events(
                        $allLogs,
                        ['login_failed', 'login_lockout', 'login_blocked_lockout'],
                        $limit,
                        $hours
                    );
                    break;
                case self::SECTION_BLOCKLIST_STATUS:
                    $payload['blocklist_status'] = self::get_blocklist_status();
                    break;
                case self::SECTION_LOGIN_PROTECTION:
                    $payload['login_protection'] = self::get_login_protection($settings);
                    break;
                case self::SECTION_MODULES_STATUS:
                    $payload['modules_status'] = self::get_modules_status($settings);
                    break;
                case self::SECTION_LOGS_TAIL:
                    $payload['logs_tail'] = self::get_logs_tail($allLogs, $limit);
                    break;
                case self::SECTION_FIREWALL_BLOCKS_RECENT:
                    $payload['firewall_blocks_recent'] = self::filter_log_events(
                        $allLogs,
                        ['firewall_blocked', 'dangerous_upload_blocked'],
                        $limit,
                        $hours
                    );
                    break;
                case self::SECTION_LOCKOUT_ESCALATION:
                    $payload['lockout_escalation'] = self::get_lockout_escalation();
                    break;
                case self::SECTION_PROBLEMS:
                    $payload['problems'] = self::collect_problems($settings, $allLogs, $payload);
                    break;
            }
        }

        return $payload;
    }

    /**
     * @param array<int, array<string, mixed>> $logs
     * @param array<int, string> $eventNames
     * @return array<string, mixed>
     */
    private static function filter_log_events(array $logs, array $eventNames, int $limit, int $hours): array
    {
        $cutoff = time() - $hours * HOUR_IN_SECONDS;
        $items = [];
        foreach ($logs as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $event = (string) ($entry['event'] ?? '');
            if (!in_array($event, $eventNames, true)) {
                continue;
            }
            $ts = strtotime((string) ($entry['ts'] ?? ''));
            if ($ts !== false && $ts < $cutoff) {
                continue;
            }
            $items[] = [
                'ts' => (string) ($entry['ts'] ?? ''),
                'event' => $event,
                'ip_mask' => self::mask_ip((string) ($entry['ip'] ?? '')),
                'user_id' => $entry['user_id'] ?? null,
                'ctx' => self::scrub_ctx(is_array($entry['ctx'] ?? null) ? $entry['ctx'] : []),
            ];
            if (count($items) >= $limit) {
                break;
            }
        }

        return [
            'lookback_hours' => $hours,
            'limit' => $limit,
            'count' => count($items),
            'items' => $items,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function get_blocklist_status(): array
    {
        $data = get_option('fp_security_blocklist', []);
        $ips = is_array($data) && isset($data['ips']) && is_array($data['ips']) ? $data['ips'] : [];
        $masked = [];
        foreach (array_slice($ips, 0, 20) as $ip) {
            $masked[] = self::mask_ip((string) $ip);
        }

        return [
            'enabled' => self::bool_setting('blocklist_enabled'),
            'total' => count($ips),
            'updated' => is_array($data) ? (string) ($data['updated'] ?? '') : '',
            'sample_masked' => $masked,
        ];
    }

    /**
     * @param array<string, mixed> $settings
     * @return array<string, mixed>
     */
    private static function get_login_protection(array $settings): array
    {
        $enabled = !empty($settings['login_protection_enabled']);
        $whitelist = (string) ($settings['ip_whitelist'] ?? '');
        $lines = $whitelist !== '' ? count(array_filter(array_map('trim', explode("\n", $whitelist)))) : 0;

        return [
            'enabled' => $enabled,
            'max_login_attempts' => (int) ($settings['max_login_attempts'] ?? 5),
            'lockout_minutes' => (int) ($settings['lockout_minutes'] ?? 15),
            'add_to_blocklist_after' => (int) ($settings['add_to_blocklist_after'] ?? 0),
            'whitelist_line_count' => $lines,
            'email_on_lockout' => !empty(($settings['notifications'] ?? [])['email_on_lockout']),
        ];
    }

    /**
     * @param array<string, mixed> $settings
     * @return array<string, mixed>
     */
    private static function get_modules_status(array $settings): array
    {
        $sh = is_array($settings['security_headers'] ?? null) ? $settings['security_headers'] : [];
        $hp = is_array($settings['htaccess_protection'] ?? null) ? $settings['htaccess_protection'] : [];

        return [
            'hardening' => [
                'hide_wp_version' => !empty($settings['hide_wp_version']),
                'disable_file_edit' => !empty($settings['disable_file_edit']),
                'disable_xmlrpc' => !empty($settings['disable_xmlrpc']),
                'disable_rest_users' => !empty($settings['disable_rest_users']),
            ],
            'firewall_enabled' => !empty($settings['firewall_enabled']),
            'blocklist_enabled' => !empty($settings['blocklist_enabled']),
            'security_headers_enabled' => !empty($sh['enabled']),
            'htaccess_protection_enabled' => !empty($hp['enabled']),
            'uploads_php_protection' => !empty(($settings['uploads_php_protection'] ?? [])['enabled']),
            'dangerous_upload_blocker' => !empty(($settings['dangerous_upload_blocker'] ?? [])['enabled']),
            'fp_security_disabled_constant' => defined('FP_SECURITY_DISABLED') && FP_SECURITY_DISABLED,
        ];
    }

    /**
     * @param array<int, array<string, mixed>> $logs
     * @return array<string, mixed>
     */
    private static function get_logs_tail(array $logs, int $limit): array
    {
        $items = [];
        foreach (array_slice($logs, 0, $limit) as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $items[] = [
                'ts' => (string) ($entry['ts'] ?? ''),
                'event' => (string) ($entry['event'] ?? ''),
                'ip_mask' => self::mask_ip((string) ($entry['ip'] ?? '')),
                'user_id' => $entry['user_id'] ?? null,
            ];
        }

        return ['limit' => $limit, 'count' => count($items), 'items' => $items];
    }

    /**
     * @return array<string, mixed>
     */
    private static function get_lockout_escalation(): array
    {
        $counts = get_option('fp_security_lockout_counts', []);
        $counts = is_array($counts) ? $counts : [];

        return [
            'ips_pending_ban' => count($counts),
            'hashes_with_counts' => count($counts) > 0,
        ];
    }

    /**
     * @param array<string, mixed> $settings
     * @param array<int, array<string, mixed>> $logs
     * @param array<string, mixed> $partialPayload
     * @return array<int, string>
     */
    private static function collect_problems(array $settings, array $logs, array $partialPayload): array
    {
        $problems = [];
        if (defined('FP_SECURITY_DISABLED') && FP_SECURITY_DISABLED) {
            $problems[] = 'fp_security_disabled_via_constant';
        }
        if (empty($settings['login_protection_enabled'])) {
            $problems[] = 'login_protection_disabled';
        }
        if (empty($settings['firewall_enabled'])) {
            $problems[] = 'firewall_disabled';
        }
        $blocklist = self::get_blocklist_status();
        if (!empty($blocklist['enabled']) && (int) ($blocklist['total'] ?? 0) > 100) {
            $problems[] = 'blocklist_large';
        }

        $recentFails = 0;
        $cutoff = time() - 24 * HOUR_IN_SECONDS;
        foreach ($logs as $entry) {
            if (!is_array($entry) || ($entry['event'] ?? '') !== 'login_failed') {
                continue;
            }
            $ts = strtotime((string) ($entry['ts'] ?? ''));
            if ($ts !== false && $ts >= $cutoff) {
                $recentFails++;
            }
        }
        if ($recentFails >= 20) {
            $problems[] = 'high_login_failure_rate_24h';
        }

        return $problems;
    }

    private static function bool_setting(string $key): bool
    {
        $s = get_option('fp_security_settings', []);
        if (!is_array($s)) {
            return false;
        }

        return !empty($s[$key]);
    }

    /**
     * @param array<string, mixed> $ctx
     * @return array<string, mixed>
     */
    private static function scrub_ctx(array $ctx): array
    {
        unset($ctx['password']);
        if (isset($ctx['username']) && is_string($ctx['username'])) {
            $ctx['username'] = self::mask_username($ctx['username']);
        }

        return $ctx;
    }

    private static function mask_username(string $username): string
    {
        if ($username === '') {
            return '';
        }
        if (strlen($username) <= 2) {
            return '**';
        }

        return substr($username, 0, 1) . str_repeat('*', max(1, strlen($username) - 2)) . substr($username, -1);
    }

    private static function mask_ip(string $ip): string
    {
        if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return '[invalid]';
        }
        if (strpos($ip, ':') !== false) {
            return preg_replace('/:[0-9a-f]+$/i', ':****', $ip) ?? 'ipv6-masked';
        }
        $parts = explode('.', $ip);
        if (count($parts) === 4) {
            $parts[3] = '***';

            return implode('.', $parts);
        }

        return '***';
    }
}
