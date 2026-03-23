<?php
/**
 * Plugin Name:       FP Security
 * Plugin URI:        https://github.com/franpass87/FP-Security
 * Description:       Firewall, hardening, protezione login e scanner. Alternativa leggera e modulare a Wordfence.
 * Version:           1.3.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
 * Author:            Francesco Passeri
 * Author URI:        https://francescopasseri.com
 * License:           Proprietary
 * Text Domain:       fp-security
 * GitHub Plugin URI: franpass87/FP-Security
 * Primary Branch:    main
 *
 * Emergency disable: aggiungi in wp-config.php: define('FP_SECURITY_DISABLED', true);
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

define('FP_SECURITY_VERSION', '1.3.0');
define('FP_SECURITY_FILE', __FILE__);
define('FP_SECURITY_DIR', plugin_dir_path(__FILE__));
define('FP_SECURITY_URL', plugin_dir_url(__FILE__));
define('FP_SECURITY_BASENAME', plugin_basename(__FILE__));

if (defined('FP_SECURITY_DISABLED') && FP_SECURITY_DISABLED) {
    return;
}

$autoload = FP_SECURITY_DIR . 'vendor/autoload.php';
if (!file_exists($autoload)) {
    add_action('admin_notices', static function (): void {
        echo '<div class="notice notice-error"><p><strong>FP Security:</strong> ' .
            esc_html__('Esegui `composer install` nella cartella del plugin oppure carica la cartella vendor.', 'fp-security') .
            '</p></div>';
    });
    return;
}
require_once $autoload;

add_action('plugins_loaded', static function (): void {
    try {
        \FP\Security\Core\Plugin::instance()->init();
    } catch (Throwable $e) {
        if (function_exists('error_log')) {
            error_log('[FP-Security] Init failed (site kept running): ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
        }
        add_action('admin_notices', static function () use ($e): void {
            if (current_user_can('manage_options')) {
                echo '<div class="notice notice-warning"><p><strong>FP Security:</strong> ' .
                    esc_html__('Errore durante l\'avvio. Il plugin è disattivato per evitare blocchi al sito.', 'fp-security') . ' ' .
                    (defined('WP_DEBUG') && WP_DEBUG ? esc_html($e->getMessage()) : '') . '</p></div>';
            }
        });
    }
});
