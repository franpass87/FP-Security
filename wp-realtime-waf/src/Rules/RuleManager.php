<?php

namespace WPRTWAF\Rules;

class RuleManager
{
    private const OPTION_KEY = 'wp_realtime_waf_custom_rules';

    public function __construct(private readonly RuleRepository $repository)
    {
    }

    public function bootstrap(): void
    {
        $this->repository->setCustomRules($this->loadPersisted());
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function loadPersisted(): array
    {
        if (!function_exists('get_option')) {
            return [];
        }

        $value = get_option(self::OPTION_KEY, []);

        return $this->sanitizeRules(is_array($value) ? $value : []);
    }

    /**
     * @param array<int, array<string, mixed>> $rules
     */
    public function replaceCustomRules(array $rules): void
    {
        $sanitized = $this->sanitizeRules($rules);
        if (function_exists('update_option')) {
            update_option(self::OPTION_KEY, $sanitized);
        }

        $this->repository->setCustomRules($sanitized);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function exportCustomRules(): array
    {
        return $this->repository->getCustomRules();
    }

    /**
     * @param array<int, mixed> $rules
     * @return array<int, array<string, mixed>>
     */
    private function sanitizeRules(array $rules): array
    {
        $sanitized = [];
        foreach ($rules as $rule) {
            if (!is_array($rule)) {
                continue;
            }

            $id = isset($rule['id']) && is_string($rule['id']) ? trim($rule['id']) : null;
            if ($id === null || $id === '') {
                $id = 'custom-' . substr(hash('sha1', json_encode($rule) ?: ''), 0, 8);
            }

            $pattern = isset($rule['pattern']) && is_string($rule['pattern']) ? trim($rule['pattern']) : '';
            if ($pattern === '') {
                continue;
            }

            $sanitized[] = [
                'id' => $id,
                'pattern' => $pattern,
                'type' => isset($rule['type']) && is_string($rule['type']) ? strtolower($rule['type']) : 'regex',
                'action' => isset($rule['action']) && is_string($rule['action']) ? strtolower($rule['action']) : 'block',
                'severity' => isset($rule['severity']) && is_string($rule['severity']) ? strtolower($rule['severity']) : 'medium',
                'enabled' => array_key_exists('enabled', $rule) ? (bool) $rule['enabled'] : true,
                'description' => isset($rule['description']) && is_string($rule['description']) ? trim($rule['description']) : '',
                'targets' => $this->sanitizeTargets($rule['targets'] ?? ['all']),
            ];
        }

        return array_values($sanitized);
    }

    /**
     * @param mixed $targets
     * @return array<int, string>
     */
    private function sanitizeTargets(mixed $targets): array
    {
        if (is_string($targets)) {
            $targets = [$targets];
        }

        if (!is_array($targets)) {
            return ['all'];
        }

        $normalized = [];
        foreach ($targets as $target) {
            $value = strtolower(trim((string) $target));
            if ($value !== '') {
                $normalized[] = $value;
            }
        }

        return $normalized === [] ? ['all'] : array_values(array_unique($normalized));
    }
}
