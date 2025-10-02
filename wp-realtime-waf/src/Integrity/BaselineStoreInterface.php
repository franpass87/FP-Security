<?php

namespace WPRTWAF\Integrity;

interface BaselineStoreInterface
{
    /**
     * @return array{generated_at?: int, files?: array<string, array{hash: string, size: int, mtime: int}>}
     */
    public function loadBaseline(): array;

    /**
     * @param array{generated_at?: int, files?: array<string, array{hash: string, size: int, mtime: int}>} $baseline
     */
    public function saveBaseline(array $baseline): void;

    /**
     * @return array<string, array{flagged_at: int, reason: string}>
     */
    public function loadQuarantine(): array;

    /**
     * @param array<string, array{flagged_at: int, reason: string}> $records
     */
    public function saveQuarantine(array $records): void;
}
