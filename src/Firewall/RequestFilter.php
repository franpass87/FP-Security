<?php

declare(strict_types=1);

namespace FP\Security\Firewall;

use FP\Security\Blocklist\IpBlocklist;
use FP\Security\Log\SecurityLogger;

/**
 * Firewall base: blocca richieste sospette (path, query, user-agent) e IP in blocklist.
 */
final class RequestFilter {

    public function __construct(
        private readonly SecurityLogger $logger,
        private readonly IpBlocklist $blocklist
    ) {}

    /** @var list<string> */
    private const BLOCKED_PATHS = [
        '/wp-config.php.bak',
        '/.env',
        '/.git/config',
        '/xmlrpc.php',
        '/readme.html',
        '/license.txt',
        '/wp-includes/version.php',
    ];

    /** @var list<string> Pattern specifici (es. base64_decode() non base64_decode) per ridurre falsi positivi */
    private const BLOCKED_QUERY_PATTERNS = [
        'eval(',
        'base64_decode(',
        'gzinflate(',
        'str_rot13(',
        'passthru(',
        'shell_exec(',
        'system(',
        'assert(',
        'create_function(',
        '../',
        '..\\',
    ];

    public function register_hooks(): void {
        add_action('init', [$this, 'check_request'], 1);
    }

    public function check_request(): void {
        if ($this->is_safe_context()) {
            return;
        }

        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $query = isset($_SERVER['QUERY_STRING']) ? sanitize_text_field(wp_unslash($_SERVER['QUERY_STRING'])) : '';

        if (apply_filters('fp_security_firewall_skip', false, $uri, $query)) {
            return;
        }

        $settings = $this->get_settings();
        if (empty($settings['firewall_enabled'])) {
            return;
        }

        $ip = $this->get_client_ip();
        if ($ip !== null && !empty($settings['blocklist_enabled']) && $this->blocklist->contains($ip)) {
            $this->block('blocklist_ip', ['ip' => $ip]);
        }

        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

        foreach (self::BLOCKED_PATHS as $path) {
            if (str_contains($uri, $path)) {
                $this->block('blocked_path', ['path' => $path, 'uri' => $uri]);
            }
        }

        if ($query !== '') {
            $decoded = urldecode($query);
            foreach (self::BLOCKED_QUERY_PATTERNS as $pattern) {
                if (stripos($decoded, $pattern) !== false) {
                    $this->block('blocked_query', ['pattern' => $pattern]);
                }
            }
        }

        if ($ua === '' && $this->is_suspicious_empty_ua_context($uri) && !$this->is_wp_cron_or_internal($uri)) {
            $this->block('empty_user_agent', ['uri' => $uri]);
        }
    }

    private function block(string $reason, array $ctx): void {
        $this->logger->log('firewall_blocked', array_merge(['reason' => $reason], $ctx));
        status_header(403);
        nocache_headers();
        wp_die(
            esc_html__('Accesso negato.', 'fp-security'),
            esc_html__('403 Forbidden', 'fp-security'),
            ['response' => 403]
        );
    }

    private function is_safe_context(): bool {
        if (defined('WP_CLI') && WP_CLI) {
            return true;
        }
        if (defined('DOING_CRON') && DOING_CRON) {
            return true;
        }
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }
        return false;
    }

    private function is_wp_cron_or_internal(string $uri): bool {
        return str_contains($uri, 'wp-cron.php') || str_contains($uri, 'admin-ajax.php');
    }

    private function is_suspicious_empty_ua_context(string $uri): bool {
        $suspicious = ['wp-admin', 'wp-login', 'xmlrpc'];
        foreach ($suspicious as $s) {
            if (str_contains($uri, $s)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return array<string, mixed>
     */
    private function get_settings(): array {
        $saved = get_option('fp_security_settings', []);
        $saved = is_array($saved) ? $saved : [];
        return wp_parse_args($saved, ['firewall_enabled' => true, 'blocklist_enabled' => true]);
    }

    private function get_client_ip(): ?string {
        if (!isset($_SERVER) || !is_array($_SERVER)) {
            return null;
        }
        $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        foreach ($keys as $k) {
            if (!empty($_SERVER[$k])) {
                $ip = sanitize_text_field(wp_unslash($_SERVER[$k]));
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
