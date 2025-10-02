<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Rules\RuleManager;
use WPRTWAF\Rules\RuleRepository;

class RuleManagerTest extends TestCase
{
    public function testReplaceCustomRulesSanitizesInput(): void
    {
        $repository = new RuleRepository();
        $manager = new RuleManager($repository);

        $manager->replaceCustomRules([
            [
                'pattern' => '/test/i',
                'severity' => 'CRITICAL',
                'targets' => ['Body'],
            ],
            'invalid',
        ]);

        $rules = $repository->getCustomRules();
        $this->assertCount(1, $rules);
        $rule = $rules[0];
        $this->assertSame('critical', $rule['severity']);
        $this->assertSame(['body'], $rule['targets']);
        $this->assertStringStartsWith('custom-', $rule['id']);
    }
}
