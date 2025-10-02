<?php

namespace WPRTWAF\Rules;

use WPRTWAF\Http\NormalizedRequest;

class RuleEngine
{
    /** @var array<string, string> */
    private array $compiledPatterns = [];

    public function __construct(private readonly RuleRepository $repository)
    {
    }

    public function match(NormalizedRequest $request): ?RuleMatch
    {
        foreach ($this->repository->all() as $rule) {
            if (!is_array($rule)) {
                continue;
            }

            if (array_key_exists('enabled', $rule) && !$rule['enabled']) {
                continue;
            }

            $type = $rule['type'] ?? 'regex';
            if ($type !== 'regex') {
                continue;
            }

            $pattern = $this->compilePattern((string) ($rule['pattern'] ?? ''));
            if ($pattern === null) {
                continue;
            }

            $targets = $this->normalizeTargets($rule['targets'] ?? ['all']);
            foreach ($targets as $target) {
                $value = $request->getTargetValue($target);
                if ($value === '') {
                    continue;
                }

                if (@preg_match($pattern, $value, $matches)) {
                    /** @var array<int|string, string> $matches */
                    return new RuleMatch($rule, $target, $matches);
                }
            }
        }

        return null;
    }

    private function compilePattern(string $pattern): ?string
    {
        if ($pattern === '') {
            return null;
        }

        if (isset($this->compiledPatterns[$pattern])) {
            return $this->compiledPatterns[$pattern];
        }

        $compiled = $pattern;

        if (!preg_match('/^\/.+\/[a-zA-Z]*$/', $compiled)) {
            $compiled = '/' . str_replace('/', '\/', $compiled) . '/i';
        }

        $this->compiledPatterns[$pattern] = $compiled;

        return $compiled;
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

        if ($normalized === []) {
            return ['all'];
        }

        return array_values(array_unique($normalized));
    }
}
