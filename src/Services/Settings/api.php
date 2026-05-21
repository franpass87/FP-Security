<?php
declare(strict_types=1);

use FP\Security\Services\Settings\SettingsRegistry;

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('fp_security_get_settings_registry')) {
    function fp_security_get_settings_registry(): array
    {
        return SettingsRegistry::get_settings();
    }
}

if (!function_exists('fp_security_get_settings_state')) {
    function fp_security_get_settings_state(): array
    {
        return SettingsRegistry::get_current_states();
    }
}

if (!function_exists('fp_security_apply_settings')) {
    function fp_security_apply_settings(array $items, bool $dry_run = true): array
    {
        return SettingsRegistry::apply_settings($items, $dry_run);
    }
}

if (!function_exists('fp_security_settings_get_version')) {
    function fp_security_settings_get_version(): string
    {
        return SettingsRegistry::REGISTRY_VERSION;
    }
}
