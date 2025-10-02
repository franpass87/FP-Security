<?php
/**
 * Must-use loader for WP Realtime WAF.
 */

if (!defined('ABSPATH')) {
    return;
}

if (defined('WP_PLUGIN_DIR')) {
    require_once WP_PLUGIN_DIR . '/wp-realtime-waf/wp-realtime-waf.php';
}
