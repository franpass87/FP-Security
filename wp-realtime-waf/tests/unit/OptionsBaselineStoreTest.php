<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Integrity\OptionsBaselineStore;

class OptionsBaselineStoreTest extends TestCase
{
    public function testBaselinePersistsAcrossInstances(): void
    {
        $store = new OptionsBaselineStore();
        $baseline = [
            'generated_at' => 123,
            'files' => [
                'core/index.php' => ['hash' => 'abc', 'size' => 10, 'mtime' => 123],
            ],
        ];

        $store->saveBaseline($baseline);

        $next = new OptionsBaselineStore();
        $this->assertSame($baseline, $next->loadBaseline());

        $store->saveBaseline([]);
    }

    public function testQuarantinePersistsAcrossInstances(): void
    {
        $store = new OptionsBaselineStore();
        $records = [
            'core/malicious.php' => ['flagged_at' => 456, 'reason' => 'Detected eval usage'],
        ];

        $store->saveQuarantine($records);

        $next = new OptionsBaselineStore();
        $this->assertSame($records, $next->loadQuarantine());

        $store->saveQuarantine([]);
    }
}
