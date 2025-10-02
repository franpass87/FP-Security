<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Http\NormalizedRequest;
use WPRTWAF\Rules\RuleEngine;
use WPRTWAF\Rules\RuleRepository;

class RuleEngineTest extends TestCase
{
    public function testMatchReturnsRuleWhenPatternMatches(): void
    {
        $repository = new RuleRepository();
        $repository->setRules([
            [
                'id' => 'test-rule',
                'type' => 'regex',
                'pattern' => '/__PAYLOAD__/i',
                'targets' => ['body'],
                'action' => 'block',
            ],
        ]);

        $engine = new RuleEngine($repository);

        $request = new NormalizedRequest(
            'POST',
            '/submit',
            '198.51.100.5',
            ['user-agent' => 'ExampleBot'],
            [],
            ['payload' => '__PAYLOAD__'],
            [],
            '__PAYLOAD__'
        );

        $match = $engine->match($request);

        $this->assertNotNull($match);
        $this->assertSame('test-rule', $match->getRule()['id']);
        $this->assertSame('body', $match->getTarget());
    }

    public function testMatchReturnsNullWhenNoRulesApply(): void
    {
        $repository = new RuleRepository();
        $repository->setRules([
            [
                'id' => 'test-rule',
                'type' => 'regex',
                'pattern' => '/forbidden/i',
                'targets' => ['uri'],
                'action' => 'block',
            ],
        ]);

        $engine = new RuleEngine($repository);

        $request = new NormalizedRequest(
            'GET',
            '/safe',
            '198.51.100.5',
            ['user-agent' => 'ExampleBot'],
            [],
            [],
            [],
            ''
        );

        $match = $engine->match($request);

        $this->assertNull($match);
    }

    public function testDisabledRuleIsIgnored(): void
    {
        $repository = new RuleRepository();
        $repository->setRules([
            [
                'id' => 'disabled-rule',
                'type' => 'regex',
                'pattern' => '/blocked/i',
                'targets' => ['query'],
                'action' => 'block',
                'enabled' => false,
            ],
        ]);

        $engine = new RuleEngine($repository);

        $request = new NormalizedRequest(
            'GET',
            '/endpoint',
            '203.0.113.5',
            ['user-agent' => 'ExampleBot'],
            ['search' => 'blocked'],
            [],
            [],
            ''
        );

        $match = $engine->match($request);

        $this->assertNull($match);
    }
}
