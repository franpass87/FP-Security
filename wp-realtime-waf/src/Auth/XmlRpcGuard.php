<?php

namespace WPRTWAF\Auth;

class XmlRpcGuard
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

        add_filter('xmlrpc_enabled', [$this, 'filterEnabled']);
        add_filter('xmlrpc_methods', [$this, 'filterMethods']);
    }

    public function filterEnabled(bool $enabled): bool
    {
        $config = $this->getConfig();
        if (!$config['enabled']) {
            return $enabled;
        }

        if ($config['disable_all']) {
            return false;
        }

        return $enabled;
    }

    /**
     * @param array<string, callable|string> $methods
     * @return array<string, callable|string>
     */
    public function filterMethods(array $methods): array
    {
        $config = $this->getConfig();
        if (!$config['enabled']) {
            return $methods;
        }

        $allow = $config['allow_methods'];
        if ($config['disable_all'] && $allow !== []) {
            $filtered = [];
            foreach ($allow as $method) {
                if (isset($methods[$method])) {
                    $filtered[$method] = $methods[$method];
                }
            }

            return $filtered;
        }

        $blocked = $config['block_methods'];
        foreach ($blocked as $method) {
            unset($methods[$method]);
        }

        return $methods;
    }

    /**
     * @return array{enabled: bool, disable_all: bool, allow_methods: array<int, string>, block_methods: array<int, string>}
     */
    private function getConfig(): array
    {
        $options = ($this->optionsProvider)();
        $auth = $options['auth'] ?? [];
        $xmlrpc = $auth['xmlrpc'] ?? [];

        return [
            'enabled' => (bool) ($xmlrpc['enabled'] ?? false),
            'disable_all' => (bool) ($xmlrpc['disable_all'] ?? false),
            'allow_methods' => $this->normalizeList($xmlrpc['allow_methods'] ?? []),
            'block_methods' => $this->normalizeList($xmlrpc['block_methods'] ?? []),
        ];
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
}
