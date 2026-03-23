<?php

declare(strict_types=1);

namespace FP\Security\Log;

/**
 * Logger eventi di sicurezza.
 *
 * Salva su opzione WordPress (rotazione automatica) e opzionale error_log.
 */
final class SecurityLogger {

    private const OPTION_KEY = 'fp_security_log';
    private const MAX_ENTRIES = 500;

    public function log(string $event, array $context = []): void {
        $entry = [
            'ts'      => current_time('mysql'),
            'event'   => $event,
            'ip'      => $this->get_client_ip(),
            'user_id' => get_current_user_id() ?: null,
            'ctx'     => $context,
        ];

        add_action('shutdown', function () use ($entry): void {
            try {
                $logs = get_option(self::OPTION_KEY, []);
                $logs = is_array($logs) ? $logs : [];
                $maxAge = (int) apply_filters('fp_security_log_max_age_days', 90);
                if ($maxAge > 0) {
                    $cutoff = strtotime("-{$maxAge} days", current_time('timestamp'));
                    $logs = array_values(array_filter($logs, static function (array $e) use ($cutoff): bool {
                        $ts = strtotime($e['ts'] ?? '');
                        return $ts !== false && $ts >= $cutoff;
                    }));
                }
                array_unshift($logs, $entry);
                update_option(self::OPTION_KEY, array_slice($logs, 0, self::MAX_ENTRIES));
            } catch (Throwable $e) {
                if (function_exists('error_log')) {
                    error_log('[FP-Security] Log write failed: ' . $e->getMessage());
                }
            }
        }, 999);

        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[FP-Security] ' . $event . ' | ' . wp_json_encode($context));
        }
    }

    /**
     * @return array<int, array{ts: string, event: string, ip: string|null, user_id: int|null, ctx: array}>
     */
    public function get_recent(int $limit = 50): array {
        $logs = get_option(self::OPTION_KEY, []);
        $logs = is_array($logs) ? $logs : [];
        return array_slice($logs, 0, $limit);
    }

    private function get_client_ip(): ?string {
        if (!isset($_SERVER) || !is_array($_SERVER)) {
            return null;
        }
        $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        foreach ($keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = sanitize_text_field(wp_unslash($_SERVER[$key]));
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return null;
    }
}
