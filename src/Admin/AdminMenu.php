<?php

declare(strict_types=1);

namespace FP\Security\Admin;

use FP\Security\Blocklist\IpBlocklist;
use FP\Security\Firewall\RequestFilter;
use FP\Security\Hardening\HardeningManager;
use FP\Security\Headers\SecurityHeaders;
use FP\Security\Htaccess\HtaccessFileProtection;
use FP\Security\LoginProtection\LoginGuard;
use FP\Security\Log\SecurityLogger;

/**
 * Menu admin FP Security: Dashboard, Impostazioni, Blocklist, Log.
 */
final class AdminMenu {

    private const MENU_SLUG = 'fp_security_dashboard';
    private const OPTION_KEY = 'fp_security_settings';

    public function __construct(
        private readonly HardeningManager $hardening,
        private readonly LoginGuard $loginGuard,
        private readonly RequestFilter $firewall,
        private readonly SecurityHeaders $securityHeaders,
        private readonly HtaccessFileProtection $htaccessProtection,
        private readonly IpBlocklist $blocklist,
        private readonly SecurityLogger $logger
    ) {}

    public function register_hooks(): void {
        add_action('admin_menu', [$this, 'add_menu'], 25);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_action('admin_init', [$this, 'handle_save']);
        add_action('admin_init', [$this, 'handle_unblock']);
        add_action('admin_init', [$this, 'handle_export_log']);
        add_action('admin_init', [$this, 'handle_add_blocklist']);
    }

    public function add_menu(): void {
        add_menu_page(
            esc_html__('FP Security', 'fp-security'),
            esc_html__('FP Security', 'fp-security'),
            'manage_options',
            self::MENU_SLUG,
            [$this, 'render_dashboard'],
            'dashicons-shield',
            '56.11'
        );
        add_submenu_page(
            self::MENU_SLUG,
            esc_html__('Dashboard', 'fp-security'),
            esc_html__('Dashboard', 'fp-security'),
            'manage_options',
            self::MENU_SLUG,
            [$this, 'render_dashboard']
        );
        add_submenu_page(
            self::MENU_SLUG,
            esc_html__('Impostazioni', 'fp-security'),
            esc_html__('Impostazioni', 'fp-security'),
            'manage_options',
            'fp_security_settings',
            [$this, 'render_settings']
        );
        add_submenu_page(
            self::MENU_SLUG,
            esc_html__('Blocklist IP', 'fp-security'),
            esc_html__('Blocklist IP', 'fp-security'),
            'manage_options',
            'fp_security_blocklist',
            [$this, 'render_blocklist']
        );
        add_submenu_page(
            self::MENU_SLUG,
            esc_html__('Log Eventi', 'fp-security'),
            esc_html__('Log Eventi', 'fp-security'),
            'manage_options',
            'fp_security_log',
            [$this, 'render_log']
        );
    }

    public function enqueue_assets(string $hook): void {
        $is_our = (strpos($hook, 'fp_security') !== false)
            || (isset($_GET['page']) && sanitize_text_field(wp_unslash($_GET['page'] ?? '')) === self::MENU_SLUG)
            || (isset($_GET['page']) && in_array(sanitize_text_field(wp_unslash($_GET['page'] ?? '')), ['fp_security_settings', 'fp_security_log', 'fp_security_blocklist'], true));

        if (!$is_our) {
            return;
        }

        wp_enqueue_style(
            'fp-security-admin',
            FP_SECURITY_URL . 'assets/css/admin.css',
            [],
            FP_SECURITY_VERSION
        );
    }

    public function handle_save(): void {
        if (!isset($_POST['fp_security_save']) || !current_user_can('manage_options')) {
            return;
        }
        check_admin_referer('fp_security_save_settings', 'fp_security_nonce');

        $settings = $this->get_settings();
        $settings['hide_wp_version'] = !empty($_POST['hide_wp_version']);
        $settings['disable_file_edit'] = !empty($_POST['disable_file_edit']);
        $settings['disable_xmlrpc'] = !empty($_POST['disable_xmlrpc']);
        $settings['remove_wlw_link'] = !empty($_POST['remove_wlw_link']);
        $settings['remove_rsd_link'] = !empty($_POST['remove_rsd_link']);
        $settings['disable_rest_users'] = !empty($_POST['disable_rest_users']);
        $settings['login_protection_enabled'] = !empty($_POST['login_protection_enabled']);
        $settings['max_login_attempts'] = absint($_POST['max_login_attempts'] ?? 5);
        $settings['lockout_minutes'] = absint($_POST['lockout_minutes'] ?? 15);
        $settings['ip_whitelist'] = sanitize_textarea_field(wp_unslash($_POST['ip_whitelist'] ?? ''));
        $settings['add_to_blocklist_after'] = max(0, min(10, absint($_POST['add_to_blocklist_after'] ?? 0)));
        $settings['blocklist_enabled'] = !empty($_POST['blocklist_enabled']);
        $settings['firewall_enabled'] = !empty($_POST['firewall_enabled']);
        $settings['notifications'] = [
            'email_on_lockout'   => !empty($_POST['email_on_lockout']),
            'notification_email' => sanitize_email(wp_unslash($_POST['notification_email'] ?? '')) ?: get_option('admin_email'),
        ];

        $settings['max_login_attempts'] = max(3, min(20, $settings['max_login_attempts']));
        $settings['lockout_minutes'] = max(5, min(1440, $settings['lockout_minutes']));

        $existingSh = $this->securityHeaders->get_settings();
        $settings['security_headers'] = array_merge($existingSh, [
            'enabled'                => !empty($_POST['security_headers_enabled']),
            'x_content_type_options' => !empty($_POST['x_content_type_options']),
            'x_frame_options'        => in_array($_POST['x_frame_options'] ?? '', ['DENY', 'SAMEORIGIN'], true) ? sanitize_text_field(wp_unslash($_POST['x_frame_options'])) : 'SAMEORIGIN',
            'referrer_policy'        => sanitize_text_field(wp_unslash($_POST['referrer_policy'] ?? '')),
            'permissions_policy'     => sanitize_text_field(wp_unslash($_POST['permissions_policy'] ?? '')),
            'hsts'                   => !empty($_POST['hsts_enabled']),
            'hsts_max_age'           => absint($_POST['hsts_max_age'] ?? 31536000),
            'hsts_subdomains'        => !empty($_POST['hsts_subdomains']),
            'hsts_preload'           => !empty($_POST['hsts_preload']),
        ]);
        $settings['htaccess_protection'] = [
            'enabled' => !empty($_POST['htaccess_protection_enabled']),
        ];

        update_option(self::OPTION_KEY, $settings);

        do_action('fp_security_settings_saved', $settings);

        wp_safe_redirect(
            add_query_arg(['page' => 'fp_security_settings', 'saved' => '1'], admin_url('admin.php'))
        );
        exit;
    }

    public function handle_unblock(): void {
        if (!current_user_can('manage_options') || !isset($_GET['fp_security_unblock'])) {
            return;
        }
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'] ?? '')), 'fp_security_unblock')) {
            return;
        }
        $ip = sanitize_text_field(wp_unslash($_GET['fp_security_unblock']));
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }
        $this->blocklist->remove($ip);
        $this->blocklist->clear_lockout($ip);
        wp_safe_redirect(add_query_arg(['page' => 'fp_security_blocklist', 'unblocked' => '1'], admin_url('admin.php')));
        exit;
    }

    public function handle_export_log(): void {
        if (!current_user_can('manage_options') || !isset($_GET['fp_security_export_log'])) {
            return;
        }
        if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'] ?? '')), 'fp_security_export_log')) {
            return;
        }
        $logs = $this->logger->get_recent(1000);
        $filename = 'fp-security-log-' . gmdate('Y-m-d-His') . '.csv';
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        $out = fopen('php://output', 'w');
        if ($out) {
            fputcsv($out, ['Data', 'Evento', 'IP', 'User ID', 'Contesto']);
            foreach ($logs as $e) {
                fputcsv($out, [
                    $e['ts'] ?? '',
                    $e['event'] ?? '',
                    $e['ip'] ?? '',
                    (string) ($e['user_id'] ?? ''),
                    wp_json_encode($e['ctx'] ?? []),
                ]);
            }
            fclose($out);
        }
        exit;
    }

    public function handle_add_blocklist(): void {
        if (!current_user_can('manage_options') || !isset($_POST['fp_security_add_blocklist'])) {
            return;
        }
        check_admin_referer('fp_security_add_blocklist', 'fp_security_blocklist_nonce');
        $text = sanitize_textarea_field(wp_unslash($_POST['blocklist_ips'] ?? ''));
        if ($text === '') {
            wp_safe_redirect(add_query_arg(['page' => 'fp_security_blocklist'], admin_url('admin.php')));
            exit;
        }
        $added = $this->blocklist->add_from_text($text);
        wp_safe_redirect(add_query_arg(['page' => 'fp_security_blocklist', 'added' => $added], admin_url('admin.php')));
        exit;
    }

    public function render_dashboard(): void {
        $h = $this->hardening->get_settings();
        $l = $this->loginGuard->get_settings();
        $recent = $this->logger->get_recent(10);
        ?>
        <div class="wrap fpsecurity-admin-page">
            <h1 class="screen-reader-text"><?php esc_html_e('FP Security Dashboard', 'fp-security'); ?></h1>
            <div class="fpsecurity-page-header">
                <div class="fpsecurity-page-header-content">
                    <h2 class="fpsecurity-page-header-title" aria-hidden="true">
                        <span class="dashicons dashicons-shield"></span> <?php esc_html_e('FP Security', 'fp-security'); ?>
                    </h2>
                    <p><?php esc_html_e('Dashboard sicurezza: stato moduli e ultimi eventi.', 'fp-security'); ?></p>
                </div>
                <span class="fpsecurity-page-header-badge">v<?php echo esc_html(FP_SECURITY_VERSION); ?></span>
            </div>

            <?php
            $sh = $this->securityHeaders->get_settings();
            $hp = $this->htaccessProtection->get_settings();
            ?>
            <div class="fpsecurity-status-bar">
                <span class="fpsecurity-status-pill <?php echo !empty($h['hide_wp_version']) ? 'is-active' : ''; ?>">
                    <span class="dot"></span> <?php esc_html_e('Hardening', 'fp-security'); ?>
                </span>
                <span class="fpsecurity-status-pill <?php echo !empty($sh['enabled']) ? 'is-active' : ''; ?>">
                    <span class="dot"></span> <?php esc_html_e('Security Headers', 'fp-security'); ?>
                </span>
                <span class="fpsecurity-status-pill <?php echo !empty($hp['enabled']) ? 'is-active' : ''; ?>">
                    <span class="dot"></span> <?php esc_html_e('.htaccess', 'fp-security'); ?>
                </span>
                <span class="fpsecurity-status-pill <?php echo !empty($l['login_protection_enabled']) ? 'is-active' : ''; ?>">
                    <span class="dot"></span> <?php esc_html_e('Protezione Login', 'fp-security'); ?>
                </span>
                <span class="fpsecurity-status-pill is-active">
                    <span class="dot"></span> <?php esc_html_e('Firewall', 'fp-security'); ?>
                </span>
                <span class="fpsecurity-status-pill <?php echo count($this->blocklist->get()) > 0 ? 'is-active' : ''; ?>">
                    <span class="dot"></span> <?php echo esc_html(sprintf(__('Blocklist (%d)', 'fp-security'), count($this->blocklist->get()))); ?>
                </span>
            </div>

            <div class="fpsecurity-card">
                <div class="fpsecurity-card-header">
                    <span class="dashicons dashicons-list-view"></span>
                    <h2><?php esc_html_e('Ultimi eventi', 'fp-security'); ?></h2>
                </div>
                <div class="fpsecurity-card-body">
                    <?php if (empty($recent)) : ?>
                        <p class="description"><?php esc_html_e('Nessun evento registrato.', 'fp-security'); ?></p>
                    <?php else : ?>
                        <table class="fpsecurity-table">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e('Data', 'fp-security'); ?></th>
                                    <th><?php esc_html_e('Evento', 'fp-security'); ?></th>
                                    <th><?php esc_html_e('IP', 'fp-security'); ?></th>
                                    <th><?php esc_html_e('Dettagli', 'fp-security'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($recent as $e) : ?>
                                    <tr>
                                        <td><?php echo esc_html($e['ts'] ?? ''); ?></td>
                                        <td><code><?php echo esc_html($e['event'] ?? ''); ?></code></td>
                                        <td><?php echo esc_html($e['ip'] ?? '-'); ?></td>
                                        <td><small><?php echo esc_html(wp_json_encode($e['ctx'] ?? [])); ?></small></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php
    }

    public function render_settings(): void {
        $s = $this->get_settings();
        if (isset($_GET['saved'])) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Impostazioni salvate.', 'fp-security') . '</p></div>';
        }
        ?>
        <div class="wrap fpsecurity-admin-page">
            <h1 class="screen-reader-text"><?php esc_html_e('Impostazioni FP Security', 'fp-security'); ?></h1>
            <div class="fpsecurity-page-header">
                <div class="fpsecurity-page-header-content">
                    <h2 class="fpsecurity-page-header-title" aria-hidden="true">
                        <span class="dashicons dashicons-admin-generic"></span> <?php esc_html_e('Impostazioni', 'fp-security'); ?>
                    </h2>
                    <p><?php esc_html_e('Configura hardening, protezione login e firewall.', 'fp-security'); ?></p>
                </div>
            </div>

            <form method="post" action="">
                <?php wp_nonce_field('fp_security_save_settings', 'fp_security_nonce'); ?>

                <div class="fpsecurity-card">
                    <div class="fpsecurity-card-header">
                        <span class="dashicons dashicons-lock"></span>
                        <h2><?php esc_html_e('Hardening WordPress', 'fp-security'); ?></h2>
                    </div>
                    <div class="fpsecurity-card-body">
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Nascondi versione WP', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Rimuove generator meta e version dagli header.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="hide_wp_version" value="1" <?php checked(!empty($s['hide_wp_version'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Disabilita modifica file', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Editor plugin/temi in admin disattivato.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="disable_file_edit" value="1" <?php checked(!empty($s['disable_file_edit'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Disabilita XML-RPC', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Blocca pingback e attacchi via XML-RPC.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="disable_xmlrpc" value="1" <?php checked(!empty($s['disable_xmlrpc'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Rimuovi WLW manifest', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Rimuove link Windows Live Writer.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="remove_wlw_link" value="1" <?php checked(!empty($s['remove_wlw_link'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Rimuovi RSD link', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Rimuove Really Simple Discovery.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="remove_rsd_link" value="1" <?php checked(!empty($s['remove_rsd_link'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Disabilita REST /users', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Endpoint utenti REST solo per admin.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="disable_rest_users" value="1" <?php checked(!empty($s['disable_rest_users'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>
                </div>

                <?php
                $sh = $this->securityHeaders->get_settings();
                $hp = $this->htaccessProtection->get_settings();
                ?>
                <div class="fpsecurity-card">
                    <div class="fpsecurity-card-header">
                        <span class="dashicons dashicons-networking"></span>
                        <h2><?php esc_html_e('Security Headers', 'fp-security'); ?></h2>
                    </div>
                    <div class="fpsecurity-card-body">
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Abilita Security Headers', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, HSTS.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="security_headers_enabled" value="1" <?php checked(!empty($sh['enabled'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                        <div class="fpsecurity-fields-row">
                            <label>
                                <?php esc_html_e('X-Frame-Options', 'fp-security'); ?>
                                <select name="x_frame_options">
                                    <option value="SAMEORIGIN" <?php selected($sh['x_frame_options'] ?? 'SAMEORIGIN', 'SAMEORIGIN'); ?>>SAMEORIGIN</option>
                                    <option value="DENY" <?php selected($sh['x_frame_options'] ?? '', 'DENY'); ?>>DENY</option>
                                </select>
                            </label>
                            <label>
                                <input type="checkbox" name="x_content_type_options" value="1" <?php checked(!empty($sh['x_content_type_options'])); ?>>
                                <?php esc_html_e('X-Content-Type-Options', 'fp-security'); ?>
                            </label>
                            <label>
                                <input type="checkbox" name="hsts_enabled" value="1" <?php checked(!empty($sh['hsts'])); ?>>
                                <?php esc_html_e('HSTS', 'fp-security'); ?>
                            </label>
                            <label>
                                <?php esc_html_e('HSTS max-age', 'fp-security'); ?>
                                <input type="number" name="hsts_max_age" value="<?php echo esc_attr((string) ($sh['hsts_max_age'] ?? 31536000)); ?>" min="0" style="width:100px">
                            </label>
                            <label>
                                <input type="checkbox" name="hsts_subdomains" value="1" <?php checked(!empty($sh['hsts_subdomains'])); ?>>
                                <?php esc_html_e('HSTS includeSubDomains', 'fp-security'); ?>
                            </label>
                            <label>
                                <input type="checkbox" name="hsts_preload" value="1" <?php checked(!empty($sh['hsts_preload'])); ?>>
                                <?php esc_html_e('HSTS preload', 'fp-security'); ?>
                            </label>
                        </div>
                    </div>
                </div>

                <div class="fpsecurity-card">
                    <div class="fpsecurity-card-header">
                        <span class="dashicons dashicons-media-code"></span>
                        <h2><?php esc_html_e('Protezione .htaccess (Apache)', 'fp-security'); ?></h2>
                    </div>
                    <div class="fpsecurity-card-body">
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Proteggi file sensibili via .htaccess', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Blocca accesso a .htaccess, .ini, .log, wp-config.php, disabilita directory listing.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="htaccess_protection_enabled" value="1" <?php checked(!empty($hp['enabled'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>
                </div>

                <div class="fpsecurity-card">
                    <div class="fpsecurity-card-header">
                        <span class="dashicons dashicons-admin-users"></span>
                        <h2><?php esc_html_e('Protezione Login', 'fp-security'); ?></h2>
                    </div>
                    <div class="fpsecurity-card-body">
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Abilita protezione', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Limita tentativi e blocca brute force.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="login_protection_enabled" value="1" <?php checked(!empty($s['login_protection_enabled'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                        <div class="fpsecurity-fields-row">
                            <label>
                                <?php esc_html_e('Tentativi massimi', 'fp-security'); ?>
                                <input type="number" name="max_login_attempts" value="<?php echo esc_attr((string) ($s['max_login_attempts'] ?? 5)); ?>" min="3" max="20" style="width:80px">
                            </label>
                            <label>
                                <?php esc_html_e('Blocco (minuti)', 'fp-security'); ?>
                                <input type="number" name="lockout_minutes" value="<?php echo esc_attr((string) ($s['lockout_minutes'] ?? 15)); ?>" min="5" max="1440" style="width:80px">
                            </label>
                        </div>
                        <div style="margin-top: 16px;">
                            <label for="ip_whitelist" style="display:block; font-weight:600; margin-bottom:6px;">
                                <?php esc_html_e('Whitelist IP (uno per riga)', 'fp-security'); ?>
                            </label>
                            <textarea name="ip_whitelist" id="ip_whitelist" rows="4" style="width:100%; max-width:400px;" placeholder="127.0.0.1"><?php echo esc_textarea((string) ($s['ip_whitelist'] ?? '')); ?></textarea>
                            <p class="description"><?php esc_html_e('IP che non subiscono lockout. Aggiungi il tuo IP per evitare di restare bloccato.', 'fp-security'); ?></p>
                        </div>
                        <div class="fpsecurity-fields-row" style="margin-top:12px;">
                            <label>
                                <?php esc_html_e('Aggiungi a blocklist dopo N lockout', 'fp-security'); ?>
                                <input type="number" name="add_to_blocklist_after" value="<?php echo esc_attr((string) ($s['add_to_blocklist_after'] ?? 0)); ?>" min="0" max="10" style="width:60px" title="<?php esc_attr_e('0 = disabilitato', 'fp-security'); ?>">
                            </label>
                            <span class="description"><?php esc_html_e('0 = disabilitato. Dopo N lockout l\'IP viene bloccato permanentemente.', 'fp-security'); ?></span>
                        </div>
                    </div>
                </div>

                <div class="fpsecurity-card">
                    <div class="fpsecurity-card-header">
                        <span class="dashicons dashicons-email-alt"></span>
                        <h2><?php esc_html_e('Notifiche', 'fp-security'); ?></h2>
                    </div>
                    <div class="fpsecurity-card-body">
                        <?php $notif = $s['notifications'] ?? []; $notif = is_array($notif) ? $notif : []; ?>
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Email su lockout', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Invia email all\'admin quando un IP viene bloccato.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="email_on_lockout" value="1" <?php checked(!empty($notif['email_on_lockout'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                        <div style="margin-top:12px;">
                            <label for="notification_email"><?php esc_html_e('Email destinatario', 'fp-security'); ?></label>
                            <input type="email" name="notification_email" id="notification_email" value="<?php echo esc_attr($notif['notification_email'] ?? get_option('admin_email')); ?>" style="width:300px">
                        </div>
                    </div>
                </div>

                <div class="fpsecurity-card">
                    <div class="fpsecurity-card-header">
                        <span class="dashicons dashicons-superhero"></span>
                        <h2><?php esc_html_e('Firewall', 'fp-security'); ?></h2>
                    </div>
                    <div class="fpsecurity-card-body">
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Abilita firewall', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Blocca path sospetti e query malevole.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="firewall_enabled" value="1" <?php checked(!empty($s['firewall_enabled'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                        <div class="fpsecurity-toggle-row">
                            <div class="fpsecurity-toggle-info">
                                <strong><?php esc_html_e('Blocca IP in blocklist', 'fp-security'); ?></strong>
                                <span><?php esc_html_e('Il firewall blocca anche gli IP nella blocklist persistente.', 'fp-security'); ?></span>
                            </div>
                            <label class="fpsecurity-toggle">
                                <input type="checkbox" name="blocklist_enabled" value="1" <?php checked(!empty($s['blocklist_enabled'])); ?>>
                                <span class="fpsecurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>
                </div>

                <p><button type="submit" name="fp_security_save" class="button button-primary"><?php esc_html_e('Salva impostazioni', 'fp-security'); ?></button></p>
            </form>
        </div>
        <?php
    }

    public function render_blocklist(): void {
        $ips = $this->blocklist->get();
        if (isset($_GET['unblocked'])) {
            echo '<div class="notice notice-success"><p>' . esc_html__('IP rimosso dalla blocklist.', 'fp-security') . '</p></div>';
        }
        if (isset($_GET['added'])) {
            $n = (int) $_GET['added'];
            echo '<div class="notice notice-success"><p>' . esc_html(sprintf(_n('%d IP aggiunto alla blocklist.', '%d IP aggiunti alla blocklist.', $n, 'fp-security'), $n)) . '</p></div>';
        }
        ?>
        <div class="wrap fpsecurity-admin-page">
            <h1 class="screen-reader-text"><?php esc_html_e('Blocklist IP', 'fp-security'); ?></h1>
            <div class="fpsecurity-page-header">
                <div class="fpsecurity-page-header-content">
                    <h2 class="fpsecurity-page-header-title" aria-hidden="true">
                        <span class="dashicons dashicons-block-default"></span> <?php esc_html_e('Blocklist IP', 'fp-security'); ?>
                    </h2>
                    <p><?php esc_html_e('IP bloccati permanentemente dal firewall.', 'fp-security'); ?></p>
                </div>
            </div>

            <div class="fpsecurity-card" style="margin-bottom: 24px;">
                <div class="fpsecurity-card-header">
                    <span class="dashicons dashicons-plus-alt"></span>
                    <h2><?php esc_html_e('Aggiungi IP', 'fp-security'); ?></h2>
                </div>
                <div class="fpsecurity-card-body">
                    <form method="post" action="">
                        <?php wp_nonce_field('fp_security_add_blocklist', 'fp_security_blocklist_nonce'); ?>
                        <label for="blocklist_ips"><?php esc_html_e('IP da bloccare (uno per riga)', 'fp-security'); ?></label>
                        <textarea name="blocklist_ips" id="blocklist_ips" rows="4" style="width:100%; max-width:400px; display:block; margin:8px 0;" placeholder="192.168.1.100"></textarea>
                        <button type="submit" name="fp_security_add_blocklist" class="button button-primary"><?php esc_html_e('Aggiungi alla blocklist', 'fp-security'); ?></button>
                    </form>
                </div>
            </div>

            <div class="fpsecurity-card">
                <div class="fpsecurity-card-body">
                    <?php if (empty($ips)) : ?>
                        <p class="description"><?php esc_html_e('Nessun IP in blocklist.', 'fp-security'); ?></p>
                    <?php else : ?>
                        <table class="fpsecurity-table">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e('IP', 'fp-security'); ?></th>
                                    <th><?php esc_html_e('Azioni', 'fp-security'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($ips as $ip) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html($ip); ?></code></td>
                                        <td>
                                            <a href="<?php echo esc_url(wp_nonce_url(add_query_arg(['fp_security_unblock' => $ip, 'page' => 'fp_security_blocklist'], admin_url('admin.php')), 'fp_security_unblock')); ?>" class="button button-small">
                                                <?php esc_html_e('Rimuovi', 'fp-security'); ?>
                                            </a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php
    }

    public function render_log(): void {
        $logs = $this->logger->get_recent(100);
        $client_ip = $this->get_client_ip();
        ?>
        <div class="wrap fpsecurity-admin-page">
            <h1 class="screen-reader-text"><?php esc_html_e('Log Eventi FP Security', 'fp-security'); ?></h1>
            <div class="fpsecurity-page-header">
                <div class="fpsecurity-page-header-content">
                    <h2 class="fpsecurity-page-header-title" aria-hidden="true">
                        <span class="dashicons dashicons-media-text"></span> <?php esc_html_e('Log Eventi', 'fp-security'); ?>
                    </h2>
                    <p><?php esc_html_e('Ultimi 100 eventi di sicurezza.', 'fp-security'); ?></p>
                </div>
            </div>

            <p>
                <a href="<?php echo esc_url(wp_nonce_url(add_query_arg('fp_security_export_log', '1', admin_url('admin.php?page=fp_security_log')), 'fp_security_export_log')); ?>" class="button">
                    <?php esc_html_e('Esporta CSV', 'fp-security'); ?>
                </a>
                <?php if ($client_ip) : ?>
                    <a href="<?php echo esc_url(wp_nonce_url(add_query_arg(['fp_security_unblock' => $client_ip, 'page' => 'fp_security_blocklist'], admin_url('admin.php')), 'fp_security_unblock')); ?>" class="button">
                        <?php esc_html_e('Sblocca il mio IP', 'fp-security'); ?>
                    </a>
                    <span class="description"><?php echo esc_html(sprintf(__('Il tuo IP: %s', 'fp-security'), $client_ip)); ?></span>
                <?php endif; ?>
            </p>

            <div class="fpsecurity-card">
                <div class="fpsecurity-card-body">
                    <?php if (empty($logs)) : ?>
                        <p class="description"><?php esc_html_e('Nessun evento registrato.', 'fp-security'); ?></p>
                    <?php else : ?>
                        <table class="fpsecurity-table">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e('Data', 'fp-security'); ?></th>
                                    <th><?php esc_html_e('Evento', 'fp-security'); ?></th>
                                    <th><?php esc_html_e('IP', 'fp-security'); ?></th>
                                    <th><?php esc_html_e('User ID', 'fp-security'); ?></th>
                                    <th><?php esc_html_e('Contesto', 'fp-security'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($logs as $e) : ?>
                                    <tr>
                                        <td><?php echo esc_html($e['ts'] ?? ''); ?></td>
                                        <td><code><?php echo esc_html($e['event'] ?? ''); ?></code></td>
                                        <td><?php echo esc_html($e['ip'] ?? '-'); ?></td>
                                        <td><?php echo esc_html((string) ($e['user_id'] ?? '-')); ?></td>
                                        <td><small><pre><?php echo esc_html(wp_json_encode($e['ctx'] ?? [], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); ?></pre></small></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        <?php
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

    /**
     * @return array<string, mixed>
     */
    private function get_settings(): array {
        $saved = get_option(self::OPTION_KEY, []);
        $saved = is_array($saved) ? $saved : [];
        return wp_parse_args($saved, array_merge(
            $this->hardening->get_defaults(),
            [
                'login_protection_enabled' => true,
                'max_login_attempts'       => 5,
                'lockout_minutes'          => 15,
                'ip_whitelist'             => '',
                'add_to_blocklist_after'   => 0,
                'blocklist_enabled'        => true,
                'firewall_enabled'         => true,
            ]
        ));
    }
}
