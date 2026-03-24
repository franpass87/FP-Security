<?php

declare(strict_types=1);

namespace FP\Security\Uploads;

use FP\Security\Log\SecurityLogger;

/**
 * Blocca upload di file con estensioni pericolose (PHP, script, eseguibili).
 *
 * Previene shell upload e doppie estensioni (es. malware.php.jpg).
 */
final class DangerousUploadBlocker {

    /** Estensioni sempre bloccate. */
    private const DANGEROUS_EXT = [
        'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'phps', 'pht', 'phpt', 'phtml',
        'exe', 'bat', 'cmd', 'com', 'sh', 'bash', 'ps1', 'pl', 'py', 'cgi',
        'asp', 'aspx', 'asa', 'cer', 'cdx', 'htr', 'jsp', 'jspx', 'shtml',
    ];

    public function __construct(
        private readonly SecurityLogger $logger
    ) {}

    public function register_hooks(): void {
        add_filter('wp_handle_upload_prefilter', [$this, 'filter_upload'], 1);
    }

    /**
     * @param array{name: string, type: string, tmp_name: string, error: int, size: int} $file
     * @return array{name: string, type: string, tmp_name: string, error: int, size: int}|array{error: string}
     */
    public function filter_upload(array $file): array {
        $settings = $this->get_settings();
        if (empty($settings['enabled'])) {
            return $file;
        }

        $name = $file['name'] ?? '';
        if ($name === '') {
            return $file;
        }

        $lower = strtolower($name);

        foreach (self::DANGEROUS_EXT as $ext) {
            if (preg_match('/\.' . preg_quote($ext, '/') . '(\.?|$)/', $lower)) {
                $this->logger->log('dangerous_upload_blocked', [
                    'filename' => $name,
                    'extension' => $ext,
                ]);
                $file['error'] = UPLOAD_ERR_EXTENSION;
                $file['upload_error_string'] = __('Estensione non consentita per motivi di sicurezza.', 'fp-security');
                return $file;
            }
        }

        return $file;
    }

    /**
     * @return array<string, mixed>
     */
    public function get_settings(): array {
        $saved = get_option('fp_security_settings', []);
        $saved = is_array($saved) ? $saved : [];
        $u = $saved['dangerous_upload_blocker'] ?? [];
        $u = is_array($u) ? $u : [];
        return wp_parse_args($u, ['enabled' => true]);
    }
}
