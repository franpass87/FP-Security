<?php

namespace WPRTWAF\Logging;

use WPRTWAF\Actions\Decision;

class Event
{
    /** @param array<int|string, string> $matches */
    public function __construct(
        public readonly string $id,
        public readonly int $timestamp,
        public readonly string $decision,
        public readonly string $severity,
        public readonly string $ip,
        public readonly string $path,
        public readonly string $method,
        public readonly string $reason,
        public readonly ?string $ruleId,
        public readonly string $mode,
        public readonly string $target,
        public readonly array $matches,
        public readonly string $userAgent,
        public readonly array $context = []
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'timestamp' => $this->timestamp,
            'decision' => $this->decision,
            'severity' => $this->severity,
            'ip' => $this->ip,
            'path' => $this->path,
            'method' => $this->method,
            'reason' => $this->reason,
            'rule_id' => $this->ruleId,
            'mode' => $this->mode,
            'target' => $this->target,
            'matches' => $this->matches,
            'user_agent' => $this->userAgent,
            'context' => $this->context,
        ];
    }

    /**
     * @param array<int|string, string> $matches
     */
    public static function create(
        string $decision,
        string $severity,
        string $ip,
        string $path,
        string $method,
        string $reason,
        ?string $ruleId,
        string $mode,
        string $target,
        array $matches,
        string $userAgent,
        array $context = []
    ): self {
        try {
            $id = bin2hex(random_bytes(8));
        } catch (\Throwable $e) {
            try {
                $id = bin2hex(random_bytes(4));
            } catch (\Throwable $inner) {
                $id = substr(hash('sha256', uniqid('', true)), 0, 16);
            }
        }

        if ($id === '') {
            $id = substr(hash('sha256', uniqid('', true)), 0, 16);
        }

        return new self(
            $id,
            time(),
            $decision,
            $severity,
            $ip,
            $path,
            $method,
            $reason,
            $ruleId,
            $mode,
            $target,
            $matches,
            $userAgent,
            $context
        );
    }

    public function isBlocking(): bool
    {
        return $this->decision === Decision::BLOCK || $this->decision === Decision::CHALLENGE;
    }
}
