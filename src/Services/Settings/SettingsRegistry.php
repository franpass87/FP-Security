<?php
/**
 * Registry impostazioni FP Security (chiavi virtuali su fp_security_settings).
 *
 * @package FP\Security\Services\Settings
 */

declare(strict_types=1);

namespace FP\Security\Services\Settings;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Catalogo chiavi virtuali che mappano su sotto-chiavi di `fp_security_settings`.
 */
final class SettingsRegistry
{
    public const PARENT_OPTION = 'fp_security_settings';

    public const REGISTRY_VERSION = '1.0.0';

    /**
     * @return array<string, array<string, mixed>>
     */
    public static function get_settings(): array
    {
        $catalog = [
            'hide_wp_version' => self::field('hardening', 'bool', 'low', 'Nascondi versione WordPress', 'Rimuove generator meta e query string ?ver= su asset.'),
            'disable_file_edit' => self::field('hardening', 'bool', 'low', 'Disabilita editor file temi/plugin', 'Imposta DISALLOW_FILE_EDIT.'),
            'disable_xmlrpc' => self::field('hardening', 'bool', 'low', 'Disabilita XML-RPC', 'Blocca xmlrpc.php (salvo eccezioni Jetpack/WPML via filtri).'),
            'remove_wlw_link' => self::field('hardening', 'bool', 'low', 'Rimuovi wlwmanifest', 'Rimuove link Windows Live Writer.'),
            'remove_rsd_link' => self::field('hardening', 'bool', 'low', 'Rimuovi RSD link', 'Rimuove Really Simple Discovery link.'),
            'disable_rest_users' => self::field('hardening', 'bool', 'medium', 'Blocca REST listing utenti', 'Limita endpoint /wp/v2/users per anonimi.'),
            'login_protection_enabled' => self::field('login', 'bool', 'low', 'Protezione login attiva', 'Abilita limite tentativi e lockout temporaneo per IP.'),
            'max_login_attempts' => self::field('login', 'int', 'low', 'Max tentativi login', 'Default 5, range 3-20.', 5),
            'lockout_minutes' => self::field('login', 'int', 'low', 'Minuti lockout', 'Default 15, range 5-1440.', 15),
            'ip_whitelist' => self::field('login', 'string', 'medium', 'IP whitelist login', 'Un IP per riga, esclusi dal lockout.'),
            'add_to_blocklist_after' => self::field('login', 'int', 'medium', 'Lockout prima del ban permanente', 'Numero lockout consecutivi prima di aggiungere IP alla blocklist (0=disabilitato).', 0),
            'blocklist_enabled' => self::field('firewall', 'bool', 'low', 'Blocklist IP attiva', 'Blocca richieste da IP in fp_security_blocklist.'),
            'firewall_enabled' => self::field('firewall', 'bool', 'low', 'Firewall attivo', 'Filtra path/query/user-agent sospetti su parse_request.'),
            'notifications.email_on_lockout' => self::field('notifications', 'bool', 'low', 'Email su lockout', 'Invia notifica email quando un IP viene bloccato.'),
            'notifications.notification_email' => self::field('notifications', 'string', 'medium', 'Email notifiche', 'Destinatario alert lockout (default admin_email).'),
            'security_headers.enabled' => self::field('headers', 'bool', 'low', 'Security headers attivi', 'Invia header HTTP di sicurezza sul frontend.'),
            'security_headers.x_content_type_options' => self::field('headers', 'bool', 'low', 'X-Content-Type-Options', 'nosniff'),
            'security_headers.x_frame_options' => self::field('headers', 'enum', 'low', 'X-Frame-Options', 'DENY o SAMEORIGIN', 'SAMEORIGIN', ['DENY', 'SAMEORIGIN']),
            'security_headers.referrer_policy' => self::field('headers', 'string', 'low', 'Referrer-Policy', 'Valore header Referrer-Policy.'),
            'security_headers.permissions_policy' => self::field('headers', 'string', 'low', 'Permissions-Policy', 'Valore Permissions-Policy.'),
            'security_headers.hsts' => self::field('headers', 'bool', 'medium', 'HSTS attivo', 'Strict-Transport-Security (solo se sito già HTTPS).'),
            'security_headers.hsts_max_age' => self::field('headers', 'int', 'low', 'HSTS max-age', 'Secondi max-age HSTS.', 31536000),
            'security_headers.hsts_subdomains' => self::field('headers', 'bool', 'low', 'HSTS includeSubDomains', ''),
            'security_headers.hsts_preload' => self::field('headers', 'bool', 'low', 'HSTS preload', ''),
            'htaccess_protection.enabled' => self::field('htaccess', 'bool', 'medium', 'Protezione .htaccess', 'Scrive regole in .htaccess (backup automatico).'),
            'uploads_php_protection.enabled' => self::field('uploads', 'bool', 'low', 'Blocca PHP in uploads', 'index.php + .htaccess in uploads.'),
            'dangerous_upload_blocker.enabled' => self::field('uploads', 'bool', 'low', 'Blocca upload pericolosi', 'Estensioni eseguibili (.php, .phtml, ecc.).'),
        ];

        $filtered = apply_filters('fp_security_remote_settings_registry', $catalog);

        return is_array($filtered) ? $filtered : $catalog;
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    public static function get_current_states(): array
    {
        $catalog = self::get_settings();
        $parent = get_option(self::PARENT_OPTION, []);
        $parent = is_array($parent) ? $parent : [];
        $states = [];
        foreach ($catalog as $key => $meta) {
            $value = self::get_nested($parent, (string) $key, $meta['default'] ?? null);
            $states[$key] = [
                'value' => $value,
                'is_set' => $value !== null && $value !== '',
                'area' => $meta['area'] ?? 'general',
                'type' => $meta['type'] ?? 'string',
                'risk' => $meta['risk'] ?? 'low',
            ];
        }

        return $states;
    }

    /**
     * @param array<int, array<string, mixed>> $items Ogni item: key + value (chiave virtuale).
     * @return array<string, mixed>
     */
    public static function apply_settings(array $items, bool $dry_run = true): array
    {
        $catalog = self::get_settings();
        $results = [];
        $applied = 0;
        $changed = 0;
        $skipped = 0;
        $errors = 0;

        $parent = get_option(self::PARENT_OPTION, []);
        $parent = is_array($parent) ? $parent : [];
        $working = $parent;

        foreach ($items as $idx => $row) {
            if (!is_array($row)) {
                $errors++;
                $results[] = ['ok' => false, 'index' => $idx, 'status' => 'invalid_item'];
                continue;
            }
            $key = '';
            if (isset($row['key']) && is_string($row['key'])) {
                $key = trim($row['key']);
            } elseif (isset($row['option']) && is_string($row['option'])) {
                $key = trim($row['option']);
            }
            if ($key === '' || !isset($catalog[$key])) {
                $errors++;
                $results[] = ['ok' => false, 'index' => $idx, 'key' => $key, 'status' => 'unknown_key'];
                continue;
            }
            if (!array_key_exists('value', $row)) {
                $errors++;
                $results[] = ['ok' => false, 'index' => $idx, 'key' => $key, 'status' => 'missing_value'];
                continue;
            }

            $meta = $catalog[$key];
            $newValue = self::sanitize_value($key, $row['value'], $meta);
            if ($newValue === null && ($meta['type'] ?? '') === 'enum') {
                $errors++;
                $results[] = ['ok' => false, 'index' => $idx, 'key' => $key, 'status' => 'invalid_enum'];
                continue;
            }

            $oldValue = self::get_nested($working, $key, $meta['default'] ?? null);
            $wouldChange = $oldValue !== $newValue;

            if ($dry_run) {
                $skipped++;
                $results[] = [
                    'ok' => true,
                    'index' => $idx,
                    'key' => $key,
                    'status' => 'preview',
                    'would_change' => $wouldChange,
                ];
                continue;
            }

            $working = self::set_nested($working, $key, $newValue);
            $applied++;
            if ($wouldChange) {
                $changed++;
            }
            $results[] = [
                'ok' => true,
                'index' => $idx,
                'key' => $key,
                'status' => $wouldChange ? 'applied' : 'unchanged',
            ];
        }

        if (!$dry_run && $applied > 0) {
            update_option(self::PARENT_OPTION, $working, false);
            do_action('fp_security_settings_saved', $working);
            do_action('fp_security_settings_applied_remote', $working, $parent);
        }

        return [
            'success' => $errors === 0,
            'dry_run' => $dry_run,
            'results' => $results,
            'summary' => [
                'applied' => $applied,
                'changed' => $changed,
                'skipped' => $skipped,
                'errors' => $errors,
            ],
        ];
    }

    /**
     * @param array<string, mixed> $meta
     * @param array<int, string>|null $allowed
     * @return array<string, mixed>
     */
    private static function field(
        string $area,
        string $type,
        string $risk,
        string $label,
        string $description,
        mixed $default = null,
        ?array $allowed = null
    ): array {
        $f = [
            'parent_option' => self::PARENT_OPTION,
            'area' => $area,
            'type' => $type,
            'risk' => $risk,
            'label' => $label,
            'description' => $description,
            'default' => $default,
        ];
        if ($allowed !== null) {
            $f['allowed_values'] = $allowed;
        }

        return $f;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function get_nested(array $data, string $dotKey, mixed $default): mixed
    {
        $parts = explode('.', $dotKey);
        $cur = $data;
        foreach ($parts as $p) {
            if (!is_array($cur) || !array_key_exists($p, $cur)) {
                return $default;
            }
            $cur = $cur[$p];
        }

        return $cur;
    }

    /**
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private static function set_nested(array $data, string $dotKey, mixed $value): array
    {
        $parts = explode('.', $dotKey);
        $ref = &$data;
        foreach ($parts as $i => $p) {
            if ($i === count($parts) - 1) {
                $ref[$p] = $value;
                break;
            }
            if (!isset($ref[$p]) || !is_array($ref[$p])) {
                $ref[$p] = [];
            }
            $ref = &$ref[$p];
        }

        return $data;
    }

    /**
     * @param array<string, mixed> $meta
     */
    private static function sanitize_value(string $key, mixed $value, array $meta): mixed
    {
        $type = (string) ($meta['type'] ?? 'string');
        if ($type === 'bool') {
            return filter_var($value, FILTER_VALIDATE_BOOLEAN);
        }
        if ($type === 'int') {
            $i = (int) $value;
            if ($key === 'max_login_attempts') {
                return max(3, min(20, $i));
            }
            if ($key === 'lockout_minutes') {
                return max(5, min(1440, $i));
            }
            if ($key === 'add_to_blocklist_after') {
                return max(0, min(10, $i));
            }

            return $i;
        }
        if ($type === 'enum') {
            $allowed = $meta['allowed_values'] ?? [];
            $s = is_string($value) ? $value : (string) $value;

            return in_array($s, $allowed, true) ? $s : null;
        }
        if ($key === 'notifications.notification_email') {
            return sanitize_email(is_string($value) ? $value : '');
        }
        if ($key === 'ip_whitelist') {
            return sanitize_textarea_field(is_string($value) ? $value : '');
        }

        return is_string($value) ? sanitize_text_field($value) : $value;
    }
}
