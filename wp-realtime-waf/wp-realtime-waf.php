<?php
/**
 * Plugin Name: WP Realtime WAF
 * Description: Real-time Web Application Firewall and Intrusion Prevention for WordPress.
 * Version: 1.0.0
 * Requires at least: 6.0
 * Requires PHP: 8.0
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('MINUTE_IN_SECONDS')) {
    define('MINUTE_IN_SECONDS', 60);
}

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

use WPRTWAF\Bootstrap\EarlyBlocker;
use WPRTWAF\Bootstrap\Plugin;
use WPRTWAF\Bootstrap\ServiceContainer;

// Default configuration constants.
if (!defined('WP_REALTIME_WAF_MODE')) {
    define('WP_REALTIME_WAF_MODE', getenv('WAF_MODE') ?: 'monitor');
}

if (!defined('WP_REALTIME_WAF_DISABLE_TTL')) {
    define('WP_REALTIME_WAF_DISABLE_TTL', 15 * MINUTE_IN_SECONDS);
}

$container = new ServiceContainer();
$plugin = new Plugin($container);
$plugin->register();

$blocker = new EarlyBlocker();
$blocker->register();
