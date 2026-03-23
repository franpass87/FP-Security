<?php

declare(strict_types=1);

namespace FP\Security\Audit;

use FP\Security\Log\SecurityLogger;

/**
 * Audit log: eventi amministrativi (login, impostazioni, plugin).
 */
final class AuditLog {

    public function __construct(
        private readonly SecurityLogger $logger
    ) {}

    public function register_hooks(): void {
        add_action('wp_login', [$this, 'on_login'], 10, 2);
        add_action('fp_security_settings_saved', [$this, 'on_settings_saved'], 10, 1);
        add_action('activated_plugin', [$this, 'on_plugin_activated'], 10, 2);
        add_action('deactivated_plugin', [$this, 'on_plugin_deactivated'], 10, 2);
    }

    /**
     * Log login riuscito (solo admin).
     */
    public function on_login(string $user_login, \WP_User $user): void {
        if (!user_can($user, 'manage_options')) {
            return;
        }
        $this->logger->log('admin_login', [
            'login' => $user_login,
            'user_id' => $user->ID,
        ]);
    }

    /**
     * Log salvataggio impostazioni FP Security.
     *
     * @param array<string, mixed> $settings
     */
    public function on_settings_saved(array $settings): void {
        $this->logger->log('fp_security_settings_saved', [
            'by_user' => get_current_user_id(),
        ]);
    }

    public function on_plugin_activated(string $plugin, bool $network_wide): void {
        $this->logger->log('plugin_activated', [
            'plugin' => $plugin,
            'network' => $network_wide,
        ]);
    }

    public function on_plugin_deactivated(string $plugin, bool $network_wide): void {
        $this->logger->log('plugin_deactivated', [
            'plugin' => $plugin,
            'network' => $network_wide,
        ]);
    }
}
