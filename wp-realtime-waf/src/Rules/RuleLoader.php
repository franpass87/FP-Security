<?php

namespace WPRTWAF\Rules;

use WPRTWAF\Actions\Decision;

class RuleLoader
{
    public function __construct(private readonly string $directory)
    {
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function load(): array
    {
        if (!is_dir($this->directory)) {
            return [];
        }

        $files = glob($this->directory . '/*.json');
        if ($files === false) {
            return [];
        }

        sort($files);

        $rules = [];
        foreach ($files as $file) {
            $contents = @file_get_contents($file);
            if (!is_string($contents) || $contents === '') {
                continue;
            }

            $decoded = json_decode($contents, true);
            if (!is_array($decoded)) {
                continue;
            }

            if ($this->isList($decoded)) {
                foreach ($decoded as $rule) {
                    if (is_array($rule)) {
                        $rules[] = $this->normalizeRule($rule, $file);
                    }
                }
                continue;
            }

            $rules[] = $this->normalizeRule($decoded, $file);
        }

        return $rules;
    }

    /**
     * @param array<string, mixed> $rule
     * @return array<string, mixed>
     */
    private function normalizeRule(array $rule, string $source): array
    {
        $rule['id'] = (string) ($rule['id'] ?? $this->generateId($source, $rule));
        $rule['type'] = $rule['type'] ?? 'regex';
        $rule['action'] = $this->normalizeAction($rule['action'] ?? Decision::BLOCK);
        $rule['targets'] = $this->normalizeTargets($rule['targets'] ?? ['all']);
        $rule['severity'] = $this->normalizeSeverity($rule['severity'] ?? 'medium');
        $rule['enabled'] = $this->normalizeEnabled($rule['enabled'] ?? true);
        $rule['tags'] = $this->normalizeTags($rule['tags'] ?? []);

        return $rule;
    }

    /**
     * @param array<int|string, mixed> $value
     */
    private function isList(array $value): bool
    {
        return array_keys($value) === range(0, count($value) - 1);
    }

    /**
     * @param mixed $targets
     * @return array<int, string>
     */
    private function normalizeTargets(mixed $targets): array
    {
        if (is_string($targets)) {
            $targets = [$targets];
        }

        if (!is_array($targets)) {
            return ['all'];
        }

        $normalized = [];
        foreach ($targets as $target) {
            $normalized[] = strtolower((string) $target);
        }

        return array_values(array_unique(array_filter($normalized)));
    }

    private function normalizeSeverity(mixed $severity): string
    {
        $severity = is_string($severity) ? strtolower($severity) : 'medium';

        return in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? $severity : 'medium';
    }

    private function normalizeEnabled(mixed $enabled): bool
    {
        if (is_bool($enabled)) {
            return $enabled;
        }

        if (is_string($enabled)) {
            $value = strtolower($enabled);
            if ($value === 'true' || $value === '1' || $value === 'yes' || $value === 'on') {
                return true;
            }

            if ($value === 'false' || $value === '0' || $value === 'no' || $value === 'off') {
                return false;
            }
        }

        if (is_numeric($enabled)) {
            return (int) $enabled !== 0;
        }

        return (bool) $enabled;
    }

    /**
     * @param mixed $tags
     * @return array<int, string>
     */
    private function normalizeTags(mixed $tags): array
    {
        if ($tags === null) {
            return [];
        }

        if (is_string($tags)) {
            $tags = [$tags];
        }

        if (!is_array($tags)) {
            return [];
        }

        $normalized = [];
        foreach ($tags as $tag) {
            if ($tag === null) {
                continue;
            }

            $normalized[] = strtolower((string) $tag);
        }

        return array_values(array_unique(array_filter($normalized)));
    }

    private function normalizeAction(mixed $action): string
    {
        $action = is_string($action) ? strtolower($action) : Decision::BLOCK;

        return match ($action) {
            Decision::ALLOW, Decision::MONITOR, Decision::BLOCK, Decision::CHALLENGE => $action,
            default => Decision::BLOCK,
        };
    }

    /**
     * @param array<string, mixed> $rule
     */
    private function generateId(string $source, array $rule): string
    {
        $base = basename($source, '.json');
        $raw = isset($rule['pattern']) ? (string) $rule['pattern'] : (string) (json_encode($rule) ?: serialize($rule));
        $pattern = md5($raw);

        return $base . '-' . substr($pattern, 0, 8);
    }
}
