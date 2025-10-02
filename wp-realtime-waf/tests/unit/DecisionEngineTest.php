<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Actions\Decision;
use WPRTWAF\Actions\DecisionEngine;
use WPRTWAF\Http\NormalizedRequest;
use WPRTWAF\Http\PreFilterDecision;
use WPRTWAF\Rules\RuleMatch;

class DecisionEngineTest extends TestCase
{
    public function testMonitorModeAlwaysReturnsMonitor(): void
    {
        $options = [
            'mode' => 'monitor',
            'trusted_proxies' => [],
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
        ];

        $engine = new DecisionEngine(static fn (): array => $options);

        $request = $this->createRequest();
        $match = new RuleMatch(['id' => 'test', 'action' => Decision::BLOCK], 'body', []);

        $result = $engine->decide($request, null, $match);

        $this->assertSame(Decision::MONITOR, $result->decision);
    }

    public function testBlockModeHonorsRuleAction(): void
    {
        $options = [
            'mode' => 'block',
            'trusted_proxies' => [],
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
        ];

        $engine = new DecisionEngine(static fn (): array => $options);

        $request = $this->createRequest();
        $match = new RuleMatch(['id' => 'test', 'action' => Decision::BLOCK], 'body', []);

        $result = $engine->decide($request, null, $match);

        $this->assertSame(Decision::BLOCK, $result->decision);
    }

    public function testChallengeModeEscalatesToChallenge(): void
    {
        $options = [
            'mode' => 'challenge',
            'trusted_proxies' => [],
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
        ];

        $engine = new DecisionEngine(static fn (): array => $options);

        $request = $this->createRequest();
        $match = new RuleMatch(['id' => 'test', 'action' => Decision::BLOCK], 'body', []);

        $result = $engine->decide($request, null, $match);

        $this->assertSame(Decision::CHALLENGE, $result->decision);
    }

    public function testPrefilterAllowOverridesMode(): void
    {
        $options = [
            'mode' => 'block',
            'trusted_proxies' => [],
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
        ];

        $engine = new DecisionEngine(static fn (): array => $options);

        $request = $this->createRequest();
        $prefilter = new PreFilterDecision(Decision::ALLOW, 'ip_allowlist');

        $result = $engine->decide($request, $prefilter, null);

        $this->assertSame(Decision::ALLOW, $result->decision);
    }

    private function createRequest(): NormalizedRequest
    {
        return new NormalizedRequest('GET', '/test', '198.51.100.1', ['user-agent' => 'Example'], [], [], [], '');
    }
}
