<?php

namespace WPRTWAF\Integrity;

class InMemoryBaselineStore implements BaselineStoreInterface
{
    /**
     * @var array{generated_at?: int, files?: array<string, array{hash: string, size: int, mtime: int}>}
     */
    private array $baseline = [];

    /**
     * @var array<string, array{flagged_at: int, reason: string}>
     */
    private array $quarantine = [];

    public function loadBaseline(): array
    {
        return $this->baseline;
    }

    public function saveBaseline(array $baseline): void
    {
        $this->baseline = $baseline;
    }

    public function loadQuarantine(): array
    {
        return $this->quarantine;
    }

    public function saveQuarantine(array $records): void
    {
        $this->quarantine = $records;
    }
}
