<?php

namespace WPRTWAF\Logging;

interface EventStoreInterface
{
    public function setMaxEvents(int $maxEvents): void;

    public function append(Event $event): void;

    /**
     * @return array<int, array<string, mixed>>
     */
    public function getEvents(int $limit, int $offset = 0): array;

    /**
     * @return array<int, array<string, mixed>>
     */
    public function all(): array;

    public function count(): int;

    /**
     * @return array<string, int>
     */
    public function getDecisionCounts(): array;

    /**
     * @return array<int, array{ip: string, count: int}>
     */
    public function getTopAttackers(int $limit = 5): array;

    public function replace(array $events): void;
}
