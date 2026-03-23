<?php
/**
 * Pulizia alla disinstallazione di FP Security.
 *
 * @package FP\Security
 */

declare(strict_types=1);

defined('WP_UNINSTALL_PLUGIN') || exit;

// Opzioni
delete_option('fp_security_settings');
delete_option('fp_security_db_version');
delete_option('fp_security_blocklist');
delete_option('fp_security_lockout_counts');

// Transient lockout
global $wpdb;
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '%fp_security_lockout_%'");
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '%fp_security_login_attempts_%'");

// Tabelle custom (se presenti in future versioni)
// $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}fp_security_log");
// $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}fp_security_blocklist");
