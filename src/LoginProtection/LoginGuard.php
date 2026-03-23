<?php

declare(strict_types=1);

namespace FP\Security\LoginProtection;

use FP\Security\Blocklist\IpBlocklist;
use FP\Security\Log\SecurityLogger;

/**
 * Protezione login: limite tentativi, lockout temporaneo.
 */
final class LoginGuard {

    private const OPTION_PREFIX = 'fp_security_login_attempts_';
    private const LOCKOUT_PREFIX = 'fp_security_lockout_';
    private const DEFAULT_MAX_ATTEMPTS = 5;
    private const DEFAULT_LOCKOUT_MINUTES = 15;

    public function __construct(
        private readonly SecurityLogger $logger,
        private readonly IpBlocklist $blocklist
    ) {}

    public function register_hooks(): void {
        add_filter('authenticate', [$this, 'check_lockout'], 5, 3);
        add_action('wp_login_failed', [$this, 'on_login_failed'], 10, 2);
        add_action('wp_login', [$this, 'on_login_success'], 10, 2);
    }

    /**
     * @param \WP_User|\WP_Error|null $user
     * @param string                  $username
     * @param string                  $password
     * @return \WP_User|\WP_Error|null
     */
    public function check_lockout($user, string $username, string $password) {
        $ip = $this->get_client_ip();
        if ($ip === null) {
            return $user;
        }

        $settings = $this->get_settings();
        if (empty($settings['login_protection_enabled'])) {
            return $user;
        }

        if ($this->is_ip_whitelisted($ip, $settings)) {
            return $user;
        }

        $lock_key = self::LOCKOUT_PREFIX . md5($ip);
        $locked_until = get_transient($lock_key);
        if ($locked_until !== false) {
            $this->logger->log('login_blocked_lockout', ['ip' => $ip, 'username' => $username]);
            return new \WP_Error(
                'fp_security_locked',
                sprintf(
                    /* translators: %d: minutes remaining */
                    esc_html__('Troppi tentativi falliti. Blocco per %d minuti.', 'fp-security'),
                    (int) $settings['lockout_minutes']
                ),
                ['status' => 429]
            );
        }

        return $user;
    }

    public function on_login_failed(string $username, \WP_Error $error): void {
        $ip = $this->get_client_ip();
        if ($ip === null) {
            return;
        }

        $settings = $this->get_settings();
        if (empty($settings['login_protection_enabled'])) {
            return;
        }

        if ($this->is_ip_whitelisted($ip, $settings)) {
            return;
        }

        $max = (int) ($settings['max_login_attempts'] ?? self::DEFAULT_MAX_ATTEMPTS);
        $lock_min = (int) ($settings['lockout_minutes'] ?? self::DEFAULT_LOCKOUT_MINUTES);

        $key = self::OPTION_PREFIX . md5($ip);
        $attempts = (int) get_transient($key);
        $attempts++;
        set_transient($key, $attempts, $lock_min * MINUTE_IN_SECONDS);

        $this->logger->log('login_failed', [
            'ip' => $ip,
            'username' => $username,
            'attempt' => $attempts,
        ]);

        if ($attempts >= $max) {
            set_transient(self::LOCKOUT_PREFIX . md5($ip), time() + ($lock_min * MINUTE_IN_SECONDS), $lock_min * MINUTE_IN_SECONDS);
            $this->logger->log('login_lockout', ['ip' => $ip, 'attempts' => $attempts]);
            do_action('fp_security_login_lockout', 'login_lockout', ['ip' => $ip, 'attempts' => $attempts]);

            $this->maybe_add_to_blocklist($ip, $settings);
        }
    }

    public function on_login_success(string $username, \WP_User $user): void {
        $ip = $this->get_client_ip();
        if ($ip === null) {
            return;
        }

        $key = self::OPTION_PREFIX . md5($ip);
        delete_transient($key);

        $this->logger->log('login_success', ['ip' => $ip, 'user_id' => $user->ID]);
    }

    /**
     * @return array<string, mixed>
     */
    public function get_settings(): array {
        $saved = get_option('fp_security_settings', []);
        $saved = is_array($saved) ? $saved : [];
        $defaults = [
            'login_protection_enabled'    => true,
            'max_login_attempts'          => self::DEFAULT_MAX_ATTEMPTS,
            'lockout_minutes'             => self::DEFAULT_LOCKOUT_MINUTES,
            'ip_whitelist'                => '',
            'add_to_blocklist_after'      => 0,
        ];
        $merged = wp_parse_args($saved, $defaults);
        $merged['ip_whitelist'] = (string) apply_filters('fp_security_login_whitelist', $merged['ip_whitelist'] ?? '');
        return $merged;
    }

    private function maybe_add_to_blocklist(string $ip, array $settings): void {
        $after = (int) ($settings['add_to_blocklist_after'] ?? 0);
        if ($after < 1) {
            return;
        }
        $counts = get_option('fp_security_lockout_counts', []);
        $counts = is_array($counts) ? $counts : [];
        $hash = md5($ip);
        $count = (int) ($counts[$hash] ?? 0);
        $count++;
        $counts[$hash] = $count;
        if ($count >= $after) {
            $this->blocklist->add($ip);
            unset($counts[$hash]);
        }
        update_option('fp_security_lockout_counts', $counts);
    }

    private function is_ip_whitelisted(string $ip, array $settings): bool {
        $list = (string) ($settings['ip_whitelist'] ?? '');
        if ($list === '') {
            return false;
        }
        $ips = array_filter(array_map('trim', explode("\n", $list)));
        foreach ($ips as $allowed) {
            if ($allowed !== '' && filter_var($allowed, FILTER_VALIDATE_IP) && $allowed === $ip) {
                return true;
            }
        }
        return false;
    }

    private function get_client_ip(): ?string {
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
