<?php

declare(strict_types=1);

namespace FP\Security\Headers;

use FP\Security\Log\SecurityLogger;

/**
 * Security headers HTTP (HSTS, X-Frame-Options, X-Content-Type-Options, ecc.).
 *
 * Portato da FP-Performance HtaccessSecurity per centralizzare la sicurezza in FP-Security.
 */
final class SecurityHeaders {

    public function __construct(
        private readonly SecurityLogger $logger
    ) {}

    public function register_hooks(): void {
        add_action('send_headers', [$this, 'send'], 1);
    }

    public function send(): void {
        try {
            $settings = $this->get_settings();
            if (empty($settings['enabled'])) {
                return;
            }
            if (headers_sent()) {
                return;
            }
        } catch (Throwable $e) {
            return;
        }

        $headers = $settings;

        try {
            if (!empty($headers['x_content_type_options'])) {
                header('X-Content-Type-Options: nosniff');
            }
            if (!empty($headers['x_frame_options'])) {
                $opt = in_array($headers['x_frame_options'], ['DENY', 'SAMEORIGIN'], true)
                    ? $headers['x_frame_options'] : 'SAMEORIGIN';
                header('X-Frame-Options: ' . $opt);
            }
            if (!empty($headers['referrer_policy'])) {
                $allowed = [
                    'no-referrer', 'no-referrer-when-downgrade', 'origin',
                    'origin-when-cross-origin', 'same-origin', 'strict-origin',
                    'strict-origin-when-cross-origin', 'unsafe-url',
                ];
                if (in_array($headers['referrer_policy'], $allowed, true)) {
                    header('Referrer-Policy: ' . $headers['referrer_policy']);
                }
            }
            if (!empty($headers['permissions_policy']) && preg_match('/^[a-zA-Z0-9=(),\s\-*"]+$/', $headers['permissions_policy'])) {
                header('Permissions-Policy: ' . $headers['permissions_policy']);
            }
            if (!empty($headers['hsts'])) {
                $maxAge = absint($headers['hsts_max_age'] ?? 31536000);
                $hsts = "max-age={$maxAge}";
                if (!empty($headers['hsts_subdomains'])) {
                    $hsts .= '; includeSubDomains';
                }
                if (!empty($headers['hsts_preload'])) {
                    $hsts .= '; preload';
                }
                header('Strict-Transport-Security: ' . $hsts);
            }
        } catch (Throwable $e) {
            // Evita che header() o altro rompa il sito
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function get_settings(): array {
        $saved = get_option('fp_security_settings', []);
        $saved = is_array($saved) ? $saved : [];
        $sec = $saved['security_headers'] ?? [];
        $sec = is_array($sec) ? $sec : [];
        return wp_parse_args($sec, $this->get_defaults());
    }

    /**
     * @return array<string, mixed>
     */
    public function get_defaults(): array {
        return [
            'enabled'                => true,
            'x_content_type_options' => true,
            'x_frame_options'        => 'SAMEORIGIN',
            'referrer_policy'        => 'strict-origin-when-cross-origin',
            'permissions_policy'     => 'geolocation=(), microphone=(), camera=()',
            'hsts'                   => false,
            'hsts_max_age'           => 31536000,
            'hsts_subdomains'        => false,
            'hsts_preload'           => false,
        ];
    }
}
