<?php

namespace WPRTWAF\Rules;

class RuleRepository
{
    /** @var array<int, array<string, mixed>> */
    private array $builtin = [];

    /** @var array<int, array<string, mixed>> */
    private array $feed = [];

    /** @var array<int, array<string, mixed>> */
    private array $custom = [];

    /**
     * @return array<int, array<string, mixed>>
     */
    public function all(): array
    {
        return array_values(array_merge($this->builtin, $this->feed, $this->custom));
    }

    /**
     * @param array<int, array<string, mixed>> $rules
     */
    public function setRules(array $rules): void
    {
        $this->builtin = $this->sanitizeRules($rules);
    }

    /**
     * @param array<int, array<string, mixed>> $rules
     */
    public function setFeedRules(array $rules): void
    {
        $this->feed = $this->sanitizeRules($rules);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function getFeedRules(): array
    {
        return $this->feed;
    }

    /**
     * @param array<int, array<string, mixed>> $rules
     */
    public function setCustomRules(array $rules): void
    {
        $this->custom = $this->sanitizeRules($rules);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function getCustomRules(): array
    {
        return $this->custom;
    }

    public function isEmpty(): bool
    {
        return $this->builtin === [] && $this->feed === [] && $this->custom === [];
    }

    /**
     * @param array<int, mixed> $rules
     * @return array<int, array<string, mixed>>
     */
    private function sanitizeRules(array $rules): array
    {
        $sanitized = [];
        foreach ($rules as $rule) {
            if (is_array($rule)) {
                $sanitized[] = $rule;
            }
        }

        return array_values($sanitized);
    }
}
