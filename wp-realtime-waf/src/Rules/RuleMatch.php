<?php

namespace WPRTWAF\Rules;

class RuleMatch
{
    /**
     * @param array<string, mixed> $rule
     * @param array<int|string, string> $matches
     */
    public function __construct(
        private readonly array $rule,
        private readonly string $target,
        private readonly array $matches
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function getRule(): array
    {
        return $this->rule;
    }

    public function getTarget(): string
    {
        return $this->target;
    }

    /**
     * @return array<int|string, string>
     */
    public function getMatches(): array
    {
        return $this->matches;
    }
}
