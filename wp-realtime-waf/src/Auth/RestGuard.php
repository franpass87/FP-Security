<?php

namespace WPRTWAF\Auth;

use RuntimeException;

class RestGuard
{
    /** @var \Closure */
    private readonly \Closure $optionsProvider;

    public function __construct(callable $optionsProvider)
    {
        $this->optionsProvider = \Closure::fromCallable($optionsProvider);
    }

    public function register(): void
    {
        if (!function_exists('add_filter')) {
            return;
        }

        add_filter('rest_pre_dispatch', [$this, 'enforce'], 10, 3);
    }

    public function enforce(mixed $result, mixed $server, mixed $request): mixed
    {
        $config = $this->getConfig();
        if (!$config['enabled']) {
            return $result;
        }

        if (!is_object($request) || !method_exists($request, 'get_route')) {
            return $result;
        }

        $route = (string) $request->get_route();
        if ($this->routeAllowed($route, $config['allow_routes'])) {
            return $result;
        }

        $isLoggedIn = function_exists('is_user_logged_in') ? is_user_logged_in() : false;
        if ($isLoggedIn) {
            return $result;
        }

        if ($config['require_nonce']) {
            $nonce = $this->extractNonce($request);
            if ($nonce === '') {
                return $this->error('wprtwaf_rest_nonce_missing', $config['message']);
            }

            $valid = function_exists('wp_verify_nonce') ? wp_verify_nonce($nonce, 'wp_rest') : ($nonce !== '');
            if ($valid === false) {
                return $this->error('wprtwaf_rest_nonce_invalid', $config['message']);
            }
        }

        if (!$config['allow_anonymous']) {
            return $this->error('wprtwaf_rest_forbidden', $config['message']);
        }

        return $result;
    }

    /**
     * @return array{enabled: bool, allow_anonymous: bool, require_nonce: bool, message: string, allow_routes: array<int, string>}
     */
    private function getConfig(): array
    {
        $options = ($this->optionsProvider)();
        $auth = $options['auth'] ?? [];
        $rest = $auth['rest'] ?? [];

        return [
            'enabled' => (bool) ($rest['enabled'] ?? false),
            'allow_anonymous' => (bool) ($rest['allow_anonymous'] ?? false),
            'require_nonce' => (bool) ($rest['require_nonce'] ?? false),
            'message' => $this->translate((string) ($rest['message'] ?? 'REST API access restricted.')),
            'allow_routes' => $this->normalizeList($rest['allow_routes'] ?? []),
        ];
    }

    /**
     * @param array<int, string> $allow
     */
    private function routeAllowed(string $route, array $allow): bool
    {
        if ($allow === []) {
            return false;
        }

        foreach ($allow as $pattern) {
            if ($pattern === '') {
                continue;
            }

            if (strlen($pattern) >= 2 && $pattern[0] === '/' && substr($pattern, -1) === '/') {
                if (@preg_match($pattern, $route)) {
                    return true;
                }
                continue;
            }

            if ($pattern === $route) {
                return true;
            }

            if (function_exists('fnmatch') && fnmatch($pattern, $route)) {
                return true;
            }
        }

        return false;
    }

    private function extractNonce(object $request): string
    {
        $header = method_exists($request, 'get_header') ? $request->get_header('X-WP-Nonce') : '';
        if (!is_string($header)) {
            return '';
        }

        return trim($header);
    }

    /**
     * @param array<int, string>|string $value
     * @return array<int, string>
     */
    private function normalizeList(array|string $value): array
    {
        if (is_string($value)) {
            $value = preg_split('/\r?\n/', $value) ?: [];
        }

        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter(array_map('trim', $value)));
    }

    private function translate(string $text): string
    {
        if (function_exists('__')) {
            return __($text, 'wp-realtime-waf');
        }

        return $text;
    }

    private function error(string $code, string $message)
    {
        if (class_exists('\\WP_Error')) {
            return new \WP_Error($code, $message, ['status' => 401]);
        }

        return new RuntimeException($message);
    }
}
