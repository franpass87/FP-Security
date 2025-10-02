<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Rules\RuleRepository;

class RuleRepositoryTest extends TestCase
{
    public function testAllReturnsMergedRules(): void
    {
        $repository = new RuleRepository();
        $repository->setRules([
            ['id' => 'builtin-1'],
        ]);
        $repository->setFeedRules([
            ['id' => 'feed-1'],
        ]);
        $repository->setCustomRules([
            ['id' => 'custom-1'],
        ]);

        $rules = $repository->all();
        $this->assertSame(['builtin-1', 'feed-1', 'custom-1'], array_column($rules, 'id'));
    }
}
