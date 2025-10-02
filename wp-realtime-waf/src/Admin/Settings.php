<?php

namespace WPRTWAF\Admin;

use WPRTWAF\Logging\EventStoreInterface;
use WPRTWAF\Logging\LogExporter;
use WPRTWAF\Rules\RuleManager;

class Settings
{
    public const OPTION_KEY = 'wp_realtime_waf_settings';

    public function __construct(
        private readonly ?EventStoreInterface $eventStore = null,
        private readonly ?LogExporter $logExporter = null,
        private readonly ?RuleManager $ruleManager = null
    ) {
    }

    public function register(): void
    {
        if (!function_exists('add_action')) {
            return;
        }

        add_action('admin_init', [$this, 'registerSettings']);
        add_action('admin_menu', [$this, 'registerMenu']);
        add_action('admin_post_wp_realtime_waf_export_logs', [$this, 'handleExportLogs']);
        add_action('admin_post_wp_realtime_waf_export_rules', [$this, 'handleExportRules']);
        add_action('admin_post_wp_realtime_waf_import_rules', [$this, 'handleImportRules']);
    }

    public function registerSettings(): void
    {
        if (!function_exists('register_setting')) {
            return;
        }

        register_setting(
            'wp_realtime_waf',
            self::OPTION_KEY,
            [
                'type' => 'array',
                'sanitize_callback' => [$this, 'sanitize'],
                'default' => $this->getDefaultOptions(),
            ]
        );

        if (function_exists('add_settings_section')) {
            add_settings_section(
                'wp_realtime_waf_general',
                __('General', 'wp-realtime-waf'),
                '__return_null',
                'wp_realtime_waf'
            );

            add_settings_section(
                'wp_realtime_waf_logging',
                __('Logging & Alerts', 'wp-realtime-waf'),
                '__return_null',
                'wp_realtime_waf'
            );
        }

        if (function_exists('add_settings_field')) {
            add_settings_field(
                'wp_realtime_waf_mode',
                __('Default Mode', 'wp-realtime-waf'),
                [$this, 'renderModeField'],
                'wp_realtime_waf',
                'wp_realtime_waf_general'
            );

            add_settings_field(
                'wp_realtime_waf_logging_field',
                __('Logging Options', 'wp-realtime-waf'),
                [$this, 'renderLoggingField'],
                'wp_realtime_waf',
                'wp_realtime_waf_logging'
            );
        }
    }

    public function registerMenu(): void
    {
        if (!function_exists('add_options_page')) {
            return;
        }

        add_options_page(
            __('WP Realtime WAF', 'wp-realtime-waf'),
            __('WP Realtime WAF', 'wp-realtime-waf'),
            'manage_options',
            'wp-realtime-waf',
            [$this, 'renderPage']
        );
    }

    public function renderPage(): void
    {
        $title = $this->translate('WP Realtime WAF');
        $stats = $this->eventStore ? $this->eventStore->getDecisionCounts() : [];
        $topAttackers = $this->eventStore ? $this->eventStore->getTopAttackers(5) : [];
        $perPage = 20;
        $page = isset($_GET['paged']) ? max(1, (int) $_GET['paged']) : 1;
        $offset = ($page - 1) * $perPage;
        $events = $this->eventStore ? $this->eventStore->getEvents($perPage, $offset) : [];
        $total = $this->eventStore ? $this->eventStore->count() : 0;
        $totalPages = max(1, (int) ceil($total / $perPage));

        echo '<div class="wrap wp-realtime-waf-admin">';
        echo '<h1>' . $this->escapeHtml($title) . '</h1>';

        $this->renderNotices();

        if ($this->eventStore === null) {
            echo '<p>' . $this->escapeHtml($this->translate('Logging storage is not available. Events will not be persisted.')) . '</p>';
        } else {
            $this->renderSummarySection($stats, $topAttackers);
            $this->renderLogsTable($events, $page, $totalPages, $total);
        }

        $this->renderExportSection();

        if (function_exists('settings_fields')) {
            $action = function_exists('admin_url') ? admin_url('options.php') : 'options.php';
            echo '<h2>' . $this->escapeHtml($this->translate('Configuration')) . '</h2>';
            echo '<form method="post" action="' . $this->escapeAttr($action) . '">';
            settings_fields('wp_realtime_waf');
            do_settings_sections('wp_realtime_waf');
            submit_button();
            echo '</form>';
        } else {
            echo '<p>' . $this->escapeHtml($this->translate('Settings editing requires WordPress core functions.')) . '</p>';
        }

        echo '</div>';
    }

    public function renderModeField(): void
    {
        $options = $this->getOptions();
        $mode = $options['mode'] ?? 'monitor';

        echo '<select name="' . $this->escapeAttr(self::OPTION_KEY . '[mode]') . '">';
        foreach (['monitor', 'block', 'challenge'] as $value) {
            $label = ucfirst($value);
            $selected = $this->selected($mode, $value);
            echo '<option value="' . $this->escapeAttr($value) . '" ' . $selected . '>' . $this->escapeHtml($label) . '</option>';
        }
        echo '</select>';
    }

    public function renderLoggingField(): void
    {
        $options = $this->getOptions();
        $logging = $options['logging'];
        $alerts = $logging['alerts'];

        echo '<label><input type="checkbox" name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][anonymize_ip]') . '" value="1" ' . $this->checked(!empty($logging['anonymize_ip'])) . '> ' . $this->escapeHtml($this->translate('Anonymize IP addresses in logs')) . '</label><br />';
        echo '<label>' . $this->escapeHtml($this->translate('Max stored events')) . ' <input type="number" min="10" max="5000" name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][max_events]') . '" value="' . $this->escapeAttr((string) $logging['max_events']) . '"></label><br />';

        echo '<label>' . $this->escapeHtml($this->translate('Default rule severity')) . ' '; 
        echo '<select name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][default_severity]') . '">';
        foreach (['low', 'medium', 'high', 'critical'] as $severity) {
            $selected = $this->selected($logging['default_severity'], $severity);
            echo '<option value="' . $this->escapeAttr($severity) . '" ' . $selected . '>' . $this->escapeHtml(ucfirst($severity)) . '</option>';
        }
        echo '</select></label><br />';

        echo '<fieldset><legend>' . $this->escapeHtml($this->translate('Alerts')) . '</legend>';
        echo '<label>' . $this->escapeHtml($this->translate('Minimum severity to alert')) . ' <select name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][alerts][min_severity]') . '">';
        foreach (['low', 'medium', 'high', 'critical'] as $severity) {
            $selected = $this->selected($alerts['min_severity'], $severity);
            echo '<option value="' . $this->escapeAttr($severity) . '" ' . $selected . '>' . $this->escapeHtml(ucfirst($severity)) . '</option>';
        }
        echo '</select></label><br />';
        echo '<label>' . $this->escapeHtml($this->translate('Throttle (seconds)')) . ' <input type="number" min="30" max="86400" name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][alerts][throttle]') . '" value="' . $this->escapeAttr((string) $alerts['throttle']) . '"></label><br />';
        echo '<label><input type="checkbox" name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][alerts][only_blocking]') . '" value="1" ' . $this->checked(!empty($alerts['only_blocking'])) . '> ' . $this->escapeHtml($this->translate('Alert only on blocking actions')) . '</label><br />';

        $email = $alerts['email'];
        echo '<label><input type="checkbox" name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][alerts][email][enabled]') . '" value="1" ' . $this->checked(!empty($email['enabled'])) . '> ' . $this->escapeHtml($this->translate('Send email alerts')) . '</label><br />';
        echo '<input type="email" class="regular-text" name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][alerts][email][recipient]') . '" value="' . $this->escapeAttr((string) $email['recipient']) . '" placeholder="security@example.com"><br />';

        $webhook = $alerts['webhook'];
        echo '<label><input type="checkbox" name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][alerts][webhook][enabled]') . '" value="1" ' . $this->checked(!empty($webhook['enabled'])) . '> ' . $this->escapeHtml($this->translate('Send webhook alerts')) . '</label><br />';
        echo '<input type="url" class="regular-text" name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][alerts][webhook][url]') . '" value="' . $this->escapeAttr((string) $webhook['url']) . '" placeholder="https://example.com/webhook"><br />';
        echo '<input type="text" class="regular-text" name="' . $this->escapeAttr(self::OPTION_KEY . '[logging][alerts][webhook][secret]') . '" value="' . $this->escapeAttr((string) $webhook['secret']) . '" placeholder="' . $this->escapeAttr($this->translate('Shared secret')) . '">';
        echo '</fieldset>';
    }

    public function handleExportLogs(): void
    {
        if (!$this->canManage() || $this->eventStore === null || $this->logExporter === null) {
            return;
        }

        if (!$this->verifyNonce('wp_realtime_waf_export_logs')) {
            $this->deny();

            return;
        }

        $type = isset($_REQUEST['type']) ? strtolower((string) $_REQUEST['type']) : 'json';
        $events = $this->eventStore->all();

        if ($type === 'csv') {
            $contentType = 'text/csv';
            $filename = 'wp-realtime-waf-logs.csv';
            $body = $this->logExporter->toCsv($events);
        } else {
            $contentType = 'application/json';
            $filename = 'wp-realtime-waf-logs.json';
            $body = $this->logExporter->toJson($events);
        }

        if (!headers_sent()) {
            header('Content-Type: ' . $contentType);
            header('Content-Disposition: attachment; filename=' . $filename);
            header('Pragma: no-cache');
        }

        echo $body;
        exit;
    }

    public function handleExportRules(): void
    {
        if (!$this->canManage() || $this->ruleManager === null) {
            return;
        }

        if (!$this->verifyNonce('wp_realtime_waf_export_rules')) {
            $this->deny();

            return;
        }

        $rules = $this->ruleManager->exportCustomRules();
        $body = json_encode($rules, JSON_PRETTY_PRINT) ?: '[]';

        if (!headers_sent()) {
            header('Content-Type: application/json');
            header('Content-Disposition: attachment; filename=wp-realtime-waf-custom-rules.json');
            header('Pragma: no-cache');
        }

        echo $body;
        exit;
    }

    public function handleImportRules(): void
    {
        if (!$this->canManage() || $this->ruleManager === null) {
            return;
        }

        if (!$this->verifyNonce('wp_realtime_waf_import_rules')) {
            $this->deny();

            return;
        }

        $redirect = $this->getSettingsUrl();
        $payload = '';

        if (isset($_FILES['rules_file']) && is_array($_FILES['rules_file']) && isset($_FILES['rules_file']['tmp_name'])) {
            $tmp = (string) $_FILES['rules_file']['tmp_name'];
            if (is_uploaded_file($tmp)) {
                $payload = (string) file_get_contents($tmp);
            }
        } elseif (isset($_POST['rules_json'])) {
            $payload = (string) $_POST['rules_json'];
        }

        if ($payload === '') {
            $this->redirectWithStatus($redirect, 'error');

            return;
        }

        $decoded = json_decode($payload, true);
        if (!is_array($decoded)) {
            $this->redirectWithStatus($redirect, 'error');

            return;
        }

        $this->ruleManager->replaceCustomRules($decoded);
        $this->redirectWithStatus($redirect, 'success');
    }

    private function renderNotices(): void
    {
        $status = '';
        if (isset($_GET['waf_import'])) {
            $raw = (string) $_GET['waf_import'];
            if (function_exists('sanitize_text_field')) {
                $status = sanitize_text_field($raw);
            } else {
                $status = preg_replace('/[^a-z0-9_\-]/i', '', $raw) ?? '';
            }
        }

        if ($status === 'success') {
            echo '<div class="notice notice-success"><p>' . $this->escapeHtml($this->translate('Custom rules imported successfully.')) . '</p></div>';
        } elseif ($status === 'error') {
            echo '<div class="notice notice-error"><p>' . $this->escapeHtml($this->translate('Rule import failed. Please verify the JSON payload.')) . '</p></div>';
        }
    }

    /**
     * @param array<string, int> $stats
     * @param array<int, array{ip: string, count: int}> $attackers
     */
    private function renderSummarySection(array $stats, array $attackers): void
    {
        echo '<h2>' . $this->escapeHtml($this->translate('Threat Overview')) . '</h2>';

        if ($stats === []) {
            echo '<p>' . $this->escapeHtml($this->translate('No security events have been recorded yet.')) . '</p>';
        } else {
            $labels = [
                'allow' => $this->translate('Allowed'),
                'monitor' => $this->translate('Monitored'),
                'block' => $this->translate('Blocked'),
                'challenge' => $this->translate('Challenged'),
            ];

            echo '<div class="wp-realtime-waf-metrics">';
            foreach ($labels as $key => $label) {
                $count = $stats[$key] ?? 0;
                echo '<div class="wp-realtime-waf-metric">';
                echo '<span class="wp-realtime-waf-metric__label">' . $this->escapeHtml($label) . '</span>';
                echo '<span class="wp-realtime-waf-metric__value">' . $this->escapeHtml((string) $count) . '</span>';
                echo '</div>';
            }
            echo '</div>';
        }

        echo '<h3>' . $this->escapeHtml($this->translate('Top Attackers')) . '</h3>';
        if ($attackers === []) {
            echo '<p>' . $this->escapeHtml($this->translate('No suspicious traffic detected yet.')) . '</p>';
        } else {
            echo '<ul class="wp-realtime-waf-attackers">';
            foreach ($attackers as $entry) {
                $ip = $this->escapeHtml((string) ($entry['ip'] ?? 'unknown'));
                $count = $this->escapeHtml((string) ($entry['count'] ?? 0));
                echo '<li><strong>' . $ip . '</strong> — ' . $count . ' ' . $this->escapeHtml($this->translate('events')) . '</li>';
            }
            echo '</ul>';
        }
    }

    /**
     * @param array<int, array<string, mixed>> $events
     */
    private function renderLogsTable(array $events, int $page, int $totalPages, int $total): void
    {
        echo '<h2>' . $this->escapeHtml($this->translate('Recent Security Events')) . '</h2>';

        if ($events === []) {
            echo '<p>' . $this->escapeHtml($this->translate('No events logged yet. The firewall is running in monitor mode by default.')) . '</p>';

            return;
        }

        echo '<table class="widefat striped">';
        echo '<thead><tr>';
        $headers = [
            $this->translate('Timestamp'),
            $this->translate('IP'),
            $this->translate('Decision'),
            $this->translate('Severity'),
            $this->translate('Rule'),
            $this->translate('Path'),
            $this->translate('Reason'),
        ];
        foreach ($headers as $header) {
            echo '<th>' . $this->escapeHtml($header) . '</th>';
        }
        echo '</tr></thead><tbody>';

        foreach ($events as $event) {
            $timestamp = isset($event['timestamp']) ? (int) $event['timestamp'] : time();
            $ruleId = isset($event['rule_id']) ? (string) $event['rule_id'] : '';
            echo '<tr>';
            echo '<td>' . $this->escapeHtml($this->formatTimestamp($timestamp)) . '</td>';
            echo '<td>' . $this->escapeHtml((string) ($event['ip'] ?? '')) . '</td>';
            echo '<td>' . $this->escapeHtml(ucfirst((string) ($event['decision'] ?? ''))) . '</td>';
            echo '<td>' . $this->escapeHtml(ucfirst((string) ($event['severity'] ?? ''))) . '</td>';
            echo '<td>' . $this->escapeHtml($ruleId !== '' ? $ruleId : $this->translate('n/a')) . '</td>';
            echo '<td>' . $this->escapeHtml((string) ($event['path'] ?? '')) . '</td>';
            echo '<td>' . $this->escapeHtml((string) ($event['reason'] ?? '')) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';

        $this->renderPagination($page, $totalPages, $total);
    }

    private function renderExportSection(): void
    {
        $actionUrl = function_exists('admin_url') ? admin_url('admin-post.php') : 'admin-post.php';

        echo '<h2>' . $this->escapeHtml($this->translate('Log Tools & Rule Management')) . '</h2>';
        echo '<div class="wp-realtime-waf-tools">';

        echo '<form method="post" action="' . $this->escapeAttr($actionUrl) . '">';
        echo '<input type="hidden" name="action" value="wp_realtime_waf_export_logs">';
        echo '<input type="hidden" name="type" value="json">';
        $this->renderNonceField('wp_realtime_waf_export_logs');
        echo '<button class="button button-secondary" type="submit">' . $this->escapeHtml($this->translate('Export Logs (JSON)')) . '</button>';
        echo '</form>';

        echo '<form method="post" action="' . $this->escapeAttr($actionUrl) . '">';
        echo '<input type="hidden" name="action" value="wp_realtime_waf_export_logs">';
        echo '<input type="hidden" name="type" value="csv">';
        $this->renderNonceField('wp_realtime_waf_export_logs');
        echo '<button class="button button-secondary" type="submit">' . $this->escapeHtml($this->translate('Export Logs (CSV)')) . '</button>';
        echo '</form>';

        echo '<form method="post" action="' . $this->escapeAttr($actionUrl) . '">';
        echo '<input type="hidden" name="action" value="wp_realtime_waf_export_rules">';
        $this->renderNonceField('wp_realtime_waf_export_rules');
        echo '<button class="button button-secondary" type="submit">' . $this->escapeHtml($this->translate('Export Custom Rules')) . '</button>';
        echo '</form>';

        echo '<form method="post" enctype="multipart/form-data" action="' . $this->escapeAttr($actionUrl) . '">';
        echo '<input type="hidden" name="action" value="wp_realtime_waf_import_rules">';
        $this->renderNonceField('wp_realtime_waf_import_rules');
        echo '<label class="screen-reader-text" for="waf-rules-file">' . $this->escapeHtml($this->translate('Import rules JSON file')) . '</label>';
        echo '<input type="file" id="waf-rules-file" name="rules_file" accept="application/json"> ';
        echo '<button class="button button-primary" type="submit">' . $this->escapeHtml($this->translate('Import Rules')) . '</button>';
        echo '</form>';

        echo '</div>';
    }

    private function renderPagination(int $page, int $totalPages, int $total): void
    {
        if ($totalPages <= 1) {
            return;
        }

        echo '<p>' . $this->escapeHtml(sprintf($this->translate('Page %d of %d (%d events total)'), $page, $totalPages, $total)) . '</p>';

        if (!function_exists('add_query_arg') || !function_exists('remove_query_arg')) {
            return;
        }

        echo '<div class="tablenav">';
        echo '<div class="tablenav-pages">';
        echo '<span class="pagination-links">';

        $baseUrl = remove_query_arg(['paged'], $_SERVER['REQUEST_URI'] ?? '');

        if ($page > 1) {
            $prev = add_query_arg('paged', $page - 1, $baseUrl);
            echo '<a class="prev-page" href="' . $this->escapeAttr($prev) . '">&lsaquo;</a>';
        }

        if ($page < $totalPages) {
            $next = add_query_arg('paged', $page + 1, $baseUrl);
            echo '<a class="next-page" href="' . $this->escapeAttr($next) . '">&rsaquo;</a>';
        }

        echo '</span>';
        echo '</div>';
        echo '</div>';
    }

    private function renderNonceField(string $action, string $name = '_wpnonce'): void
    {
        if (function_exists('wp_nonce_field')) {
            wp_nonce_field($action, $name);

            return;
        }

        echo '<input type="hidden" name="' . $this->escapeAttr($name) . '" value="' . $this->escapeAttr(hash('sha256', $action)) . '">';
    }

    private function formatTimestamp(int $timestamp): string
    {
        if (function_exists('date_i18n')) {
            $dateFormat = function_exists('get_option') ? (string) get_option('date_format', 'Y-m-d') : 'Y-m-d';
            $timeFormat = function_exists('get_option') ? (string) get_option('time_format', 'H:i:s') : 'H:i:s';

            return date_i18n($dateFormat . ' ' . $timeFormat, $timestamp);
        }

        return date('Y-m-d H:i:s', $timestamp);
    }

    public function sanitize(mixed $input): array
    {
        if (!is_array($input)) {
            return $this->getDefaultOptions();
        }

        $mode = $input['mode'] ?? 'monitor';
        if (!in_array($mode, ['monitor', 'block', 'challenge'], true)) {
            $mode = 'monitor';
        }

        $trustedProxies = $this->sanitizeList($input['trusted_proxies'] ?? []);
        $ipAllow = $this->sanitizeList($input['ip_allowlist'] ?? []);
        $ipBlock = $this->sanitizeList($input['ip_blocklist'] ?? []);
        $uaBlock = $this->sanitizeList($input['user_agent_blocklist'] ?? []);

        return [
            'mode' => $mode,
            'trusted_proxies' => $trustedProxies,
            'ip_allowlist' => $ipAllow,
            'ip_blocklist' => $ipBlock,
            'user_agent_blocklist' => $uaBlock,
            'rate_limit' => $this->sanitizeRateLimit($input['rate_limit'] ?? []),
            'auth' => $this->sanitizeAuth($input['auth'] ?? []),
            'integrity' => $this->sanitizeIntegrity($input['integrity'] ?? []),
            'logging' => $this->sanitizeLogging($input['logging'] ?? []),
        ];
    }

    public function getOptions(): array
    {
        if (!function_exists('get_option')) {
            return $this->getDefaultOptions();
        }

        $options = get_option(self::OPTION_KEY, $this->getDefaultOptions());
        if (!is_array($options)) {
            return $this->getDefaultOptions();
        }

        return array_replace_recursive($this->getDefaultOptions(), $options);
    }

    private function getDefaultOptions(): array
    {
        return [
            'mode' => 'monitor',
            'trusted_proxies' => [],
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
            'rate_limit' => [
                'enabled' => false,
                'ip_max' => 600,
                'ip_window' => 60,
                'endpoint_max' => 120,
                'endpoint_window' => 60,
            ],
            'auth' => [
                'login_limit' => [
                    'enabled' => true,
                    'ip_max' => 20,
                    'user_max' => 5,
                    'window' => 900,
                    'lockout' => 900,
                    'lock_message' => 'Too many login attempts. Please try again later.',
                ],
                'rest' => [
                    'enabled' => false,
                    'allow_anonymous' => false,
                    'require_nonce' => true,
                    'message' => 'REST API access restricted.',
                    'allow_routes' => [],
                ],
                'xmlrpc' => [
                    'enabled' => true,
                    'disable_all' => false,
                    'allow_methods' => [],
                    'block_methods' => ['pingback.ping'],
                ],
                'two_factor' => [
                    'enabled' => false,
                    'failure_message' => 'Two-factor authentication required.',
                ],
            ],
            'integrity' => [
                'enabled' => true,
                'auto_build' => true,
                'quarantine' => true,
                'include_core' => true,
                'include_plugins' => true,
                'include_themes' => true,
                'malware_scan' => [
                    'enabled' => true,
                    'quarantine' => true,
                ],
            ],
            'logging' => [
                'anonymize_ip' => true,
                'max_events' => 1000,
                'default_severity' => 'medium',
                'alerts' => [
                    'min_severity' => 'high',
                    'throttle' => 300,
                    'only_blocking' => true,
                    'email' => [
                        'enabled' => false,
                        'recipient' => '',
                    ],
                    'webhook' => [
                        'enabled' => false,
                        'url' => '',
                        'secret' => '',
                    ],
                ],
            ],
        ];
    }

    /**
     * @param mixed $value
     * @return array<int, string>
     */
    private function sanitizeList(mixed $value): array
    {
        if (is_string($value)) {
            $value = preg_split('/\r?\n/', $value) ?: [];
        }

        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter(array_map('trim', $value)));
    }

    /**
     * @param mixed $value
     * @return array{enabled: bool, ip_max: int, ip_window: int, endpoint_max: int, endpoint_window: int}
     */
    private function sanitizeRateLimit(mixed $value): array
    {
        $defaults = $this->getDefaultOptions()['rate_limit'];

        if (!is_array($value)) {
            return $defaults;
        }

        return [
            'enabled' => !empty($value['enabled']),
            'ip_max' => $this->sanitizePositiveInt($value['ip_max'] ?? $defaults['ip_max']),
            'ip_window' => $this->sanitizeWindow($value['ip_window'] ?? $defaults['ip_window'], $defaults['ip_window']),
            'endpoint_max' => $this->sanitizePositiveInt($value['endpoint_max'] ?? $defaults['endpoint_max']),
            'endpoint_window' => $this->sanitizeWindow($value['endpoint_window'] ?? $defaults['endpoint_window'], $defaults['endpoint_window']),
        ];
    }

    /**
     * @param mixed $value
     * @return array<string, mixed>
     */
    private function sanitizeAuth(mixed $value): array
    {
        if (!is_array($value)) {
            $value = [];
        }

        return [
            'login_limit' => $this->sanitizeLoginLimit($value['login_limit'] ?? []),
            'rest' => $this->sanitizeRestGuard($value['rest'] ?? []),
            'xmlrpc' => $this->sanitizeXmlRpc($value['xmlrpc'] ?? []),
            'two_factor' => $this->sanitizeTwoFactor($value['two_factor'] ?? []),
        ];
    }

    /**
     * @param mixed $value
     * @return array{enabled: bool, auto_build: bool, quarantine: bool, include_core: bool, include_plugins: bool, include_themes: bool, malware_scan: array{enabled: bool, quarantine: bool}}
     */
    private function sanitizeIntegrity(mixed $value): array
    {
        $defaults = $this->getDefaultOptions()['integrity'];

        if (!is_array($value)) {
            $value = [];
        }

        $malware = $value['malware_scan'] ?? [];
        if (!is_array($malware)) {
            $malware = [];
        }

        return [
            'enabled' => array_key_exists('enabled', $value) ? !empty($value['enabled']) : (bool) $defaults['enabled'],
            'auto_build' => array_key_exists('auto_build', $value) ? !empty($value['auto_build']) : (bool) $defaults['auto_build'],
            'quarantine' => array_key_exists('quarantine', $value) ? !empty($value['quarantine']) : (bool) $defaults['quarantine'],
            'include_core' => array_key_exists('include_core', $value) ? !empty($value['include_core']) : (bool) $defaults['include_core'],
            'include_plugins' => array_key_exists('include_plugins', $value) ? !empty($value['include_plugins']) : (bool) $defaults['include_plugins'],
            'include_themes' => array_key_exists('include_themes', $value) ? !empty($value['include_themes']) : (bool) $defaults['include_themes'],
            'malware_scan' => [
                'enabled' => array_key_exists('enabled', $malware) ? !empty($malware['enabled']) : (bool) $defaults['malware_scan']['enabled'],
                'quarantine' => array_key_exists('quarantine', $malware) ? !empty($malware['quarantine']) : (bool) $defaults['malware_scan']['quarantine'],
            ],
        ];
    }

    private function sanitizeLogging(mixed $value): array
    {
        $defaults = $this->getDefaultOptions()['logging'];

        if (!is_array($value)) {
            $value = [];
        }

        $alerts = is_array($value['alerts'] ?? null) ? $value['alerts'] : [];
        $email = is_array($alerts['email'] ?? null) ? $alerts['email'] : [];
        $webhook = is_array($alerts['webhook'] ?? null) ? $alerts['webhook'] : [];

        $maxEvents = $this->sanitizePositiveInt($value['max_events'] ?? $defaults['max_events']);
        if ($maxEvents <= 0) {
            $maxEvents = $defaults['max_events'];
        }

        return [
            'anonymize_ip' => !empty($value['anonymize_ip']),
            'max_events' => min(5000, max(10, $maxEvents)),
            'default_severity' => $this->sanitizeSeverity($value['default_severity'] ?? $defaults['default_severity']),
            'alerts' => [
                'min_severity' => $this->sanitizeSeverity($alerts['min_severity'] ?? $defaults['alerts']['min_severity']),
                'throttle' => $this->sanitizeWindow($alerts['throttle'] ?? $defaults['alerts']['throttle'], $defaults['alerts']['throttle']),
                'only_blocking' => !empty($alerts['only_blocking']),
                'email' => [
                    'enabled' => !empty($email['enabled']),
                    'recipient' => $this->sanitizeEmail($email['recipient'] ?? ($defaults['alerts']['email']['recipient'] ?? '')),
                ],
                'webhook' => [
                    'enabled' => !empty($webhook['enabled']),
                    'url' => $this->sanitizeUrl($webhook['url'] ?? ($defaults['alerts']['webhook']['url'] ?? '')),
                    'secret' => is_string($webhook['secret'] ?? null) ? trim($webhook['secret']) : '',
                ],
            ],
        ];
    }

    /**
     * @param mixed $value
     * @return array{enabled: bool, ip_max: int, user_max: int, window: int, lockout: int, lock_message: string}
     */
    private function sanitizeLoginLimit(mixed $value): array
    {
        $defaults = $this->getDefaultOptions()['auth']['login_limit'];

        if (!is_array($value)) {
            $value = [];
        }

        $message = is_string($value['lock_message'] ?? null) ? trim((string) $value['lock_message']) : $defaults['lock_message'];
        if ($message === '') {
            $message = $defaults['lock_message'];
        }

        return [
            'enabled' => !empty($value['enabled']),
            'ip_max' => $this->sanitizePositiveInt($value['ip_max'] ?? $defaults['ip_max']),
            'user_max' => $this->sanitizePositiveInt($value['user_max'] ?? $defaults['user_max']),
            'window' => $this->sanitizeWindow($value['window'] ?? $defaults['window'], $defaults['window']),
            'lockout' => $this->sanitizeWindow($value['lockout'] ?? $defaults['lockout'], $defaults['lockout']),
            'lock_message' => $message,
        ];
    }

    /**
     * @param mixed $value
     * @return array{enabled: bool, allow_anonymous: bool, require_nonce: bool, message: string, allow_routes: array<int, string>}
     */
    private function sanitizeRestGuard(mixed $value): array
    {
        $defaults = $this->getDefaultOptions()['auth']['rest'];

        if (!is_array($value)) {
            $value = [];
        }

        $message = is_string($value['message'] ?? null) ? trim((string) $value['message']) : $defaults['message'];
        if ($message === '') {
            $message = $defaults['message'];
        }

        return [
            'enabled' => !empty($value['enabled']),
            'allow_anonymous' => !empty($value['allow_anonymous']),
            'require_nonce' => !empty($value['require_nonce']),
            'message' => $message,
            'allow_routes' => $this->sanitizeList($value['allow_routes'] ?? $defaults['allow_routes']),
        ];
    }

    /**
     * @param mixed $value
     * @return array{enabled: bool, disable_all: bool, allow_methods: array<int, string>, block_methods: array<int, string>}
     */
    private function sanitizeXmlRpc(mixed $value): array
    {
        $defaults = $this->getDefaultOptions()['auth']['xmlrpc'];

        if (!is_array($value)) {
            $value = [];
        }

        return [
            'enabled' => array_key_exists('enabled', $value) ? !empty($value['enabled']) : (bool) $defaults['enabled'],
            'disable_all' => !empty($value['disable_all']),
            'allow_methods' => $this->sanitizeList($value['allow_methods'] ?? $defaults['allow_methods']),
            'block_methods' => $this->sanitizeList($value['block_methods'] ?? $defaults['block_methods']),
        ];
    }

    /**
     * @param mixed $value
     * @return array{enabled: bool, failure_message: string}
     */
    private function sanitizeTwoFactor(mixed $value): array
    {
        $defaults = $this->getDefaultOptions()['auth']['two_factor'];

        if (!is_array($value)) {
            $value = [];
        }

        $message = is_string($value['failure_message'] ?? null) ? trim((string) $value['failure_message']) : $defaults['failure_message'];
        if ($message === '') {
            $message = $defaults['failure_message'];
        }

        return [
            'enabled' => !empty($value['enabled']),
            'failure_message' => $message,
        ];
    }

    private function sanitizeSeverity(mixed $value): string
    {
        $value = strtolower(is_string($value) ? $value : '');

        return match ($value) {
            'critical', 'high', 'medium', 'low' => $value,
            default => 'medium',
        };
    }

    private function sanitizeEmail(mixed $value): string
    {
        $email = is_string($value) ? trim($value) : '';

        if ($email === '') {
            return '';
        }

        $validated = filter_var($email, FILTER_VALIDATE_EMAIL);

        return $validated !== false ? (string) $validated : '';
    }

    private function sanitizeUrl(mixed $value): string
    {
        $url = is_string($value) ? trim($value) : '';

        if ($url === '') {
            return '';
        }

        $validated = filter_var($url, FILTER_VALIDATE_URL);
        if ($validated === false) {
            return '';
        }

        $scheme = strtolower((string) parse_url($validated, PHP_URL_SCHEME));

        return in_array($scheme, ['http', 'https'], true) ? (string) $validated : '';
    }

    private function sanitizePositiveInt(mixed $value): int
    {
        $value = filter_var($value, FILTER_VALIDATE_INT);

        return $value !== false && $value > 0 ? (int) $value : 0;
    }

    private function sanitizeWindow(mixed $value, int $default = 60): int
    {
        $value = filter_var($value, FILTER_VALIDATE_INT);

        return $value !== false && $value > 0 ? (int) $value : max(1, $default);
    }

    private function canManage(): bool
    {
        if (function_exists('current_user_can')) {
            return current_user_can('manage_options');
        }

        return true;
    }

    private function verifyNonce(string $action, string $name = '_wpnonce'): bool
    {
        if (function_exists('check_admin_referer')) {
            check_admin_referer($action, $name);

            return true;
        }

        if (!isset($_REQUEST[$name])) {
            return false;
        }

        return hash_equals(hash('sha256', $action), (string) $_REQUEST[$name]);
    }

    private function deny(): void
    {
        if (function_exists('wp_die')) {
            wp_die($this->translate('Access denied.'), $this->translate('WP Realtime WAF'), ['response' => 403]);
        }

        exit;
    }

    private function getSettingsUrl(): string
    {
        if (function_exists('admin_url')) {
            return admin_url('options-general.php?page=wp-realtime-waf');
        }

        return 'options-general.php?page=wp-realtime-waf';
    }

    private function redirectWithStatus(string $url, string $status): void
    {
        if (function_exists('add_query_arg')) {
            $url = add_query_arg('waf_import', $status, $url);
        } else {
            $url .= (str_contains($url, '?') ? '&' : '?') . 'waf_import=' . rawurlencode($status);
        }

        if (function_exists('wp_safe_redirect')) {
            wp_safe_redirect($url);
        } else {
            header('Location: ' . $url);
        }

        exit;
    }

    private function translate(string $text): string
    {
        if (function_exists('__')) {
            return __($text, 'wp-realtime-waf');
        }

        return $text;
    }

    private function escapeHtml(string $text): string
    {
        if (function_exists('esc_html')) {
            return esc_html($text);
        }

        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }

    private function escapeAttr(string $text): string
    {
        if (function_exists('esc_attr')) {
            return esc_attr($text);
        }

        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }

    private function selected(string $current, string $value): string
    {
        if (function_exists('selected')) {
            return selected($current, $value, false);
        }

        return $current === $value ? 'selected' : '';
    }

    private function checked(bool $isChecked): string
    {
        if (function_exists('checked')) {
            return checked(true, $isChecked, false);
        }

        return $isChecked ? 'checked' : '';
    }
}
