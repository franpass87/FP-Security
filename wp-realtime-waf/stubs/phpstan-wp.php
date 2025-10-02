<?php

if (!function_exists('__')) {
    function __(string $text, ?string $domain = null): string
    {
        return $text;
    }
}

if (!function_exists('add_action')) {
    function add_action(string $hook, callable $callback, int $priority = 10, int $accepted_args = 1): void
    {
    }
}

if (!class_exists('WP_Error')) {
    class WP_Error
    {
        public function __construct(public string $code = '', public string $message = '', public mixed $data = null)
        {
        }
    }
}

if (!function_exists('do_settings_sections')) {
    function do_settings_sections(string $page): void
    {
    }
}

if (!function_exists('submit_button')) {
    function submit_button(
        string $text = 'Save Changes',
        string $type = 'primary',
        string $name = 'submit',
        bool $wrap = true,
        array $other_attributes = []
    ): void {
    }
}

if (!defined('WP_REALTIME_WAF_MODE')) {
    define('WP_REALTIME_WAF_MODE', 'monitor');
}
