<?php

declare(strict_types=1);

namespace FP\Security\Uploads;

use FP\Security\Log\SecurityLogger;

/**
 * Impedisce esecuzione PHP in wp-content/uploads via .htaccess (Apache).
 *
 * Previene shell upload: anche se un file .php viene caricato (bypass), non sarà eseguibile.
 */
final class UploadsPhpProtection {

    private const MARKER = '# FP Security - No PHP in uploads';

    public function __construct(
        private readonly SecurityLogger $logger
    ) {}

    public function register_hooks(): void {
        add_action('fp_security_settings_saved', [$this, 'maybe_update']);
    }

    public function on_activation(): void {
        $settings = $this->get_settings();
        if (!empty($settings['enabled'])) {
            $this->maybe_update([]);
        }
    }

    /**
     * @param array<string, mixed> $settings
     */
    public function maybe_update(array $settings = []): void {
        $s = isset($settings['uploads_php_protection']) && is_array($settings['uploads_php_protection'])
            ? $settings['uploads_php_protection']
            : $this->get_settings();
        $enabled = !empty($s['enabled']);

        $upload_dir = wp_upload_dir();
        if (!empty($upload_dir['error'])) {
            return;
        }
        $base = $upload_dir['basedir'];
        if (!is_dir($base) || !is_writable($base)) {
            return;
        }

        $htpath = $base . '/.htaccess';

        if (!$enabled) {
            if (file_exists($htpath)) {
                $content = (string) file_get_contents($htpath);
                if (str_contains($content, self::MARKER)) {
                    $pattern = '/\n?' . preg_quote(self::MARKER, '/') . '.*?<\/FilesMatch>\s*/s';
                    $cleaned = trim((string) preg_replace($pattern, '', $content));
                    if ($cleaned === '') {
                        @unlink($htpath);
                    } else {
                        @file_put_contents($htpath, $cleaned . "\n", LOCK_EX);
                    }
                    $this->logger->log('uploads_php_protection_removed', []);
                }
            }
            return;
        }

        if (file_exists($htpath)) {
            $content = (string) file_get_contents($htpath);
            if (str_contains($content, self::MARKER)) {
                return;
            }
        }

        $rules = $this->get_rules();
        $existing = file_exists($htpath) ? (string) file_get_contents($htpath) : '';
        $newContent = $existing === '' ? $rules : $existing . "\n" . $rules;

        try {
            if (@file_put_contents($htpath, $newContent, LOCK_EX) !== false) {
                $this->logger->log('uploads_php_protection_applied', []);
            }
        } catch (Throwable $e) {
            $this->logger->log('uploads_php_protection_error', ['error' => $e->getMessage()]);
        }
    }

    private function get_rules(): string {
        return '
' . self::MARKER . '
<FilesMatch "\.(php|php3|php4|php5|php7|php8|phtml|phar|phps|pht|phpt|exe|bat|cmd|com|sh|pl|py|cgi|asp|aspx|jsp|shtml)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
    </IfModule>
</FilesMatch>
';
    }

    /**
     * @return array<string, mixed>
     */
    public function get_settings(): array {
        $saved = get_option('fp_security_settings', []);
        $saved = is_array($saved) ? $saved : [];
        $u = $saved['uploads_php_protection'] ?? [];
        $u = is_array($u) ? $u : [];
        return wp_parse_args($u, ['enabled' => true]);
    }
}
