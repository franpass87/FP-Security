<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Actions\Decision;
use WPRTWAF\Http\NormalizedRequest;
use WPRTWAF\Http\PreFilter;
use WPRTWAF\RateLimit\RateLimiterInterface;

class PreFilterTest extends TestCase
{
    public function testAllowListBypassesFurtherChecks(): void
    {
        $options = [
            'ip_allowlist' => ['198.51.100.10'],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
        ];

        $rateLimiter = $this->createMock(RateLimiterInterface::class);
        $rateLimiter->expects($this->never())->method('allow');

        $prefilter = new PreFilter(static fn (): array => $options + [
            'mode' => 'monitor',
            'trusted_proxies' => [],
            'rate_limit' => ['enabled' => false],
        ], $rateLimiter);

        $request = new NormalizedRequest(
            'GET',
            '/test',
            '198.51.100.10',
            ['user-agent' => 'ExampleBot'],
            [],
            [],
            [],
            ''
        );

        $decision = $prefilter->evaluate($request);

        $this->assertNotNull($decision);
        $this->assertSame(Decision::ALLOW, $decision->decision);
        $this->assertSame('ip_allowlist', $decision->reason);
    }

    public function testBlockListTriggersBlock(): void
    {
        $options = [
            'ip_allowlist' => [],
            'ip_blocklist' => ['203.0.113.0/24'],
            'user_agent_blocklist' => [],
        ];

        $rateLimiter = $this->createMock(RateLimiterInterface::class);
        $rateLimiter->expects($this->never())->method('allow');

        $prefilter = new PreFilter(static fn (): array => $options + [
            'mode' => 'monitor',
            'trusted_proxies' => [],
            'rate_limit' => ['enabled' => true],
        ], $rateLimiter);

        $request = new NormalizedRequest(
            'GET',
            '/test',
            '203.0.113.5',
            ['user-agent' => 'ExampleBot'],
            [],
            [],
            [],
            ''
        );

        $decision = $prefilter->evaluate($request);

        $this->assertNotNull($decision);
        $this->assertSame(Decision::BLOCK, $decision->decision);
        $this->assertSame('ip_blocklist', $decision->reason);
    }

    public function testUserAgentBlocklistMatchesWildcard(): void
    {
        $options = [
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => ['BadBot*'],
        ];

        $rateLimiter = $this->createMock(RateLimiterInterface::class);
        $rateLimiter->expects($this->never())->method('allow');

        $prefilter = new PreFilter(static fn (): array => $options + [
            'mode' => 'monitor',
            'trusted_proxies' => [],
            'rate_limit' => ['enabled' => true],
        ], $rateLimiter);

        $request = new NormalizedRequest(
            'GET',
            '/test',
            '198.51.100.20',
            ['user-agent' => 'BadBotScanner'],
            [],
            [],
            [],
            ''
        );

        $decision = $prefilter->evaluate($request);

        $this->assertNotNull($decision);
        $this->assertSame(Decision::BLOCK, $decision->decision);
        $this->assertSame('user_agent_blocklist', $decision->reason);
    }

    public function testRateLimiterBlockReturnsDecision(): void
    {
        $options = [
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
            'rate_limit' => ['enabled' => true],
        ];

        $rateLimiter = $this->createMock(RateLimiterInterface::class);
        $rateLimiter->expects($this->once())->method('allow')->willReturn(false);

        $prefilter = new PreFilter(static fn (): array => $options + [
            'mode' => 'monitor',
            'trusted_proxies' => [],
        ], $rateLimiter);

        $request = new NormalizedRequest(
            'POST',
            '/submit',
            '198.51.100.30',
            ['user-agent' => 'ExampleBot'],
            [],
            [],
            [],
            ''
        );

        $decision = $prefilter->evaluate($request);

        $this->assertNotNull($decision);
        $this->assertSame(Decision::BLOCK, $decision->decision);
        $this->assertSame('rate_limit', $decision->reason);
    }
}
