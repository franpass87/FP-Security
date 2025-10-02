<?php

namespace WPRTWAF\Actions;

use WPRTWAF\Rules\RuleMatch;

class DecisionResult
{
    public function __construct(
        public readonly string $decision,
        public readonly ?RuleMatch $match = null,
        public readonly ?string $reason = null
    ) {
    }

    public function isBlocking(): bool
    {
        return $this->decision === Decision::BLOCK || $this->decision === Decision::CHALLENGE;
    }
}
