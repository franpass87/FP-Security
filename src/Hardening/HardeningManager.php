<?php

declare(strict_types=1);

namespace FP\Security\Hardening;

use FP\Security\Log\SecurityLogger;

/**
 * Hardening WordPress: nasconde versioni, disabilita file edit, XML-RPC, ecc.
 */
final class HardeningManager {

    public function __construct(
        private readonly SecurityLogger $logger
    ) {}

    public function register_hooks(): void {
        $settings = $this->get_settings();

        if (!empty($settings['hide_wp_version'])) {
            add_filter('the_generator', '__return_empty_string');
            remove_action('wp_head', 'wp_generator');
        }

        if (!empty($settings['disable_file_edit']) && !defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }

        if (!empty($settings['disable_xmlrpc'])) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', [$this, 'remove_x_pingback_header']);
        }

        if (!empty($settings['remove_wlw_link'])) {
            remove_action('wp_head', 'wlwmanifest_link');
        }

        if (!empty($settings['remove_rsd_link'])) {
            remove_action('wp_head', 'rsd_link');
        }

        if (!empty($settings['disable_rest_users'])) {
            add_filter('rest_endpoints', [$this, 'disable_rest_users_endpoint']);
        }
    }

    /**
     * @param array<string, mixed> $headers
     * @return array<string, mixed>
     */
    public function remove_x_pingback_header(array $headers): array {
        unset($headers['X-Pingback']);
        return $headers;
    }

    /**
     * @param array<string, array<string, mixed>> $endpoints
     * @return array<string, array<string, mixed>>
     */
    public function disable_rest_users_endpoint(array $endpoints): array {
        if (isset($endpoints['/wp/v2/users']) && !current_user_can('list_users')) {
            unset($endpoints['/wp/v2/users']);
            if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
                unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
            }
        }
        return $endpoints;
    }

    /**
     * @return array<string, bool>
     */
    public function get_settings(): array {
        $saved = get_option('fp_security_settings', []);
        $saved = is_array($saved) ? $saved : [];
        return wp_parse_args($saved, $this->get_defaults());
    }

    /**
     * @return array<string, bool>
     */
    public function get_defaults(): array {
        return [
            'hide_wp_version'     => true,
            'disable_file_edit'   => true,
            'disable_xmlrpc'      => true,
            'remove_wlw_link'     => true,
            'remove_rsd_link'     => true,
            'disable_rest_users'  => true,
        ];
    }
}
