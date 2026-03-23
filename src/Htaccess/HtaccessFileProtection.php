<?php

declare(strict_types=1);

namespace FP\Security\Htaccess;

use FP\Security\Log\SecurityLogger;

/**
 * Regole .htaccess per protezione file sensibili (Apache).
 *
 * Portato da FP-Performance per centralizzare la sicurezza in FP-Security.
 * Scrive solo le regole di protezione file, non i cache headers (restano in FP-Performance).
 */
final class HtaccessFileProtection {

    private const MARKER = '# FP Security File Protection';
    private const BACKUP_PREFIX = '.htaccess.fp-security-backup-';
    private const MAX_BACKUPS = 5;

    public function __construct(
        private readonly SecurityLogger $logger
    ) {}

    public function register_hooks(): void {
        add_action('wp_loaded', [$this, 'maybe_update'], 20);
    }

    public function maybe_update(): void {
        if (is_admin()) {
            return;
        }

        $settings = $this->get_settings();
        if (empty($settings['enabled'])) {
            return;
        }

        $htaccess = ABSPATH . '.htaccess';
        if (!file_exists($htaccess) || !is_writable($htaccess)) {
            return;
        }

        $content = file_get_contents($htaccess);
        if ($content === false) {
            return;
        }

        if (str_contains($content, self::MARKER)) {
            return;
        }

        $this->update_htaccess($htaccess, $content);
    }

    private function update_htaccess(string $path, string $content): void {
        $backup = $path . self::BACKUP_PREFIX . gmdate('Y-m-d-H-i-s');
        if (!@copy($path, $backup)) {
            $this->logger->log('htaccess_backup_failed', ['path' => $path]);
            return;
        }

        try {
            $rules = $this->get_rules();
            $updated = $content . "\n" . $rules;

            if (@file_put_contents($path, $updated, LOCK_EX) === false) {
                @copy($backup, $path);
                $this->logger->log('htaccess_write_failed', ['path' => $path]);
                return;
            }

            $this->cleanup_backups();
            $this->logger->log('htaccess_protection_applied', []);
        } catch (Throwable $e) {
            if (file_exists($backup)) {
                @copy($backup, $path);
            }
            $this->logger->log('htaccess_update_error', ['error' => $e->getMessage()]);
        }
    }

    private function get_rules(): string {
        return '
' . self::MARKER . '
<FilesMatch "\.(htaccess|htpasswd|ini|log|sh|sql|tar|gz)$">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</FilesMatch>

<IfModule mod_autoindex.c>
    Options -Indexes
</IfModule>

<Files "wp-config.php">
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>
</Files>
';
    }

    private function cleanup_backups(): void {
        $pattern = ABSPATH . self::BACKUP_PREFIX . '*';
        $backups = glob($pattern);
        if (!$backups || count($backups) <= self::MAX_BACKUPS) {
            return;
        }
        $absPath = realpath(ABSPATH) ?: ABSPATH;
        $safe = [];
        foreach ($backups as $b) {
            $real = realpath($b);
            if ($real && str_starts_with($real, $absPath)) {
                $safe[] = $real;
            }
        }
        if (count($safe) <= self::MAX_BACKUPS) {
            return;
        }
        usort($safe, fn($a, $b) => filemtime($a) <=> filemtime($b));
        foreach (array_slice($safe, 0, -self::MAX_BACKUPS) as $old) {
            @unlink($old);
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function get_settings(): array {
        $saved = get_option('fp_security_settings', []);
        $saved = is_array($saved) ? $saved : [];
        $hp = $saved['htaccess_protection'] ?? [];
        $hp = is_array($hp) ? $hp : [];
        return wp_parse_args($hp, ['enabled' => true]);
    }
}
