<?php

namespace WPRTWAF\Integrity;

class IntegrityReport
{
    /**
     * @param array<int, string> $added
     * @param array<int, string> $removed
     * @param array<int, string> $modified
     * @param array<int, string> $quarantined
     */
    public function __construct(
        private readonly array $added,
        private readonly array $removed,
        private readonly array $modified,
        private readonly array $quarantined,
        private readonly int $baselineGeneratedAt,
        private readonly int $scannedAt
    ) {
    }

    /**
     * @return array<int, string>
     */
    public function getAdded(): array
    {
        return $this->added;
    }

    /**
     * @return array<int, string>
     */
    public function getRemoved(): array
    {
        return $this->removed;
    }

    /**
     * @return array<int, string>
     */
    public function getModified(): array
    {
        return $this->modified;
    }

    /**
     * @return array<int, string>
     */
    public function getQuarantined(): array
    {
        return $this->quarantined;
    }

    public function getBaselineGeneratedAt(): int
    {
        return $this->baselineGeneratedAt;
    }

    public function getScannedAt(): int
    {
        return $this->scannedAt;
    }
}
