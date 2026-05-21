<?php
declare(strict_types=1);

use FP\Security\Services\Diagnostics\RuntimeDiagnostics;

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('fp_security_get_runtime_diagnostics')) {
    function fp_security_get_runtime_diagnostics(array $sections = [], array $options = []): array
    {
        return RuntimeDiagnostics::build($sections, $options);
    }
}

if (!function_exists('fp_security_get_runtime_diagnostics_sections')) {
    function fp_security_get_runtime_diagnostics_sections(): array
    {
        return RuntimeDiagnostics::ALL_SECTIONS;
    }
}
