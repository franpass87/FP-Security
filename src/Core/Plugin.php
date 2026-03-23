<?php

declare(strict_types=1);

namespace FP\Security\Core;

use FP\Security\Admin\AdminMenu;
use FP\Security\Admin\DashboardWidget;
use FP\Security\Audit\AuditLog;
use FP\Security\Blocklist\IpBlocklist;
use FP\Security\Firewall\RequestFilter;
use FP\Security\Hardening\HardeningManager;
use FP\Security\Headers\SecurityHeaders;
use FP\Security\Htaccess\HtaccessFileProtection;
use FP\Security\LoginProtection\LoginGuard;
use FP\Security\Log\SecurityLogger;
use FP\Security\Notifications\LockoutNotifier;

/**
 * Bootstrap principale di FP Security.
 *
 * Moduli: Hardening, Login Protection, Firewall, Log, Admin.
 */
final class Plugin {

    private static ?self $instance = null;

    private function __construct() {}

    public static function instance(): self {
        return self::$instance ??= new self();
    }

    public function init(): void {
        $this->check_requirements();
        $this->run_migrations();

        $logger = new SecurityLogger();
        $blocklist = new IpBlocklist();

        $modules = [
            fn() => (new HardeningManager($logger))->register_hooks(),
            fn() => (new SecurityHeaders($logger))->register_hooks(),
            fn() => (new HtaccessFileProtection($logger))->register_hooks(),
            fn() => (new LoginGuard($logger, $blocklist))->register_hooks(),
            fn() => (new RequestFilter($logger, $blocklist))->register_hooks(),
            fn() => (new LockoutNotifier())->register_hooks(),
            fn() => (new AuditLog($logger))->register_hooks(),
        ];

        foreach ($modules as $module) {
            try {
                $module();
            } catch (Throwable $e) {
                if (function_exists('error_log')) {
                    error_log('[FP-Security] Module failed: ' . $e->getMessage());
                }
            }
        }

        if (is_admin()) {
            try {
                (new AdminMenu(
                    new HardeningManager($logger),
                    new LoginGuard($logger, $blocklist),
                    new RequestFilter($logger, $blocklist),
                    new SecurityHeaders($logger),
                    new HtaccessFileProtection($logger),
                    $blocklist,
                    $logger
                ))->register_hooks();
                (new DashboardWidget($logger))->register_hooks();
            } catch (Throwable $e) {
                if (function_exists('error_log')) {
                    error_log('[FP-Security] Admin failed: ' . $e->getMessage());
                }
            }
        }
    }

    private function check_requirements(): void {
        if (version_compare(PHP_VERSION, '8.1', '<')) {
            add_action('admin_notices', static function (): void {
                echo '<div class="notice notice-error"><p><strong>FP Security:</strong> ' .
                    esc_html__('Richiede PHP 8.1 o superiore.', 'fp-security') . '</p></div>';
            });
            return;
        }
    }

    private function run_migrations(): void {
        $db_version = get_option('fp_security_db_version', '0');
        if ($db_version === '0') {
            // Future migrations qui
            update_option('fp_security_db_version', '2025-03-23');
        }
    }
}
