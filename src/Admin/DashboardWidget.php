<?php

declare(strict_types=1);

namespace FP\Security\Admin;

use FP\Security\Log\SecurityLogger;

/**
 * Widget dashboard WP con ultimi eventi FP Security.
 */
final class DashboardWidget {

    private const EVENT_LABELS = [
        'login_lockout' => 'Lockout login',
        'request_blocked' => 'Richiesta bloccata',
        'admin_login' => 'Login admin',
        'fp_security_settings_saved' => 'Impostazioni salvate',
        'plugin_activated' => 'Plugin attivato',
        'plugin_deactivated' => 'Plugin disattivato',
    ];

    public function __construct(
        private readonly SecurityLogger $logger
    ) {}

    public function register_hooks(): void {
        add_action('wp_dashboard_setup', [$this, 'add_widget']);
    }

    public function add_widget(): void {
        if (!current_user_can('manage_options')) {
            return;
        }
        wp_add_dashboard_widget(
            'fp_security_dashboard_widget',
            esc_html__('FP Security — Ultimi eventi', 'fp-security'),
            [$this, 'render']
        );
    }

    public function render(): void {
        $logs = $this->logger->get_recent(10);
        $log_url = admin_url('admin.php?page=fp_security_log');

        if (empty($logs)) {
            echo '<p>' . esc_html__('Nessun evento recente.', 'fp-security') . '</p>';
            echo '<p><a href="' . esc_url($log_url) . '" class="button button-secondary">' . esc_html__('Vai al Log Eventi', 'fp-security') . '</a></p>';
            return;
        }

        echo '<ul style="margin:0; padding:0; list-style:none;">';
        foreach ($logs as $entry) {
            $event = $entry['event'] ?? '';
            $label = self::EVENT_LABELS[$event] ?? $event;
            $ts = $entry['ts'] ?? '';
            $ip = $entry['ip'] ?? '-';
            $ctx = $entry['ctx'] ?? [];
            $extra = $this->format_ctx($ctx);
            echo '<li style="padding:6px 0; border-bottom:1px solid #eee; font-size:13px;">';
            echo '<strong>' . esc_html($label) . '</strong>';
            if ($ts) {
                echo ' <span style="color:#666;">' . esc_html($ts) . '</span>';
            }
            if ($ip && $ip !== '-') {
                echo ' <code style="font-size:11px;">' . esc_html($ip) . '</code>';
            }
            if ($extra !== '') {
                echo ' — ' . esc_html($extra);
            }
            echo '</li>';
        }
        echo '</ul>';
        echo '<p style="margin-top:12px;"><a href="' . esc_url($log_url) . '" class="button button-secondary">' . esc_html__('Vedi tutti i log', 'fp-security') . '</a></p>';
    }

    private function format_ctx(array $ctx): string {
        if (isset($ctx['login'])) {
            return (string) $ctx['login'];
        }
        if (isset($ctx['plugin'])) {
            return (string) $ctx['plugin'];
        }
        if (isset($ctx['path'])) {
            return (string) $ctx['path'];
        }
        if (isset($ctx['reason'])) {
            return (string) $ctx['reason'];
        }
        return '';
    }
}
