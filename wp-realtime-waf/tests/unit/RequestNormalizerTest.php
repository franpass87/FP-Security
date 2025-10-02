<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Http\ClientIpResolver;
use WPRTWAF\Http\RequestContext;
use WPRTWAF\Http\RequestNormalizer;

class RequestNormalizerTest extends TestCase
{
    public function testNormalizeFlattensDataAndResolvesIp(): void
    {
        $options = [
            'mode' => 'monitor',
            'trusted_proxies' => ['198.51.100.10'],
            'ip_allowlist' => [],
            'ip_blocklist' => [],
            'user_agent_blocklist' => [],
        ];

        $resolver = new ClientIpResolver(static fn (): array => $options);
        $normalizer = new RequestNormalizer($resolver);

        $context = new RequestContext(
            'POST',
            '/test?foo=bar',
            [
                'Content-Type' => 'application/json',
                'X-Forwarded-For' => '203.0.113.77, 10.0.0.1',
            ],
            ['foo' => 'bar'],
            ['nested' => ['value' => 1]],
            ['session' => ['id' => 'abc'], 'simple' => 'value'],
            '{"payload":"__TEST__"}',
            [
                'REMOTE_ADDR' => '198.51.100.10',
            ]
        );

        $normalized = $normalizer->normalize($context);

        $this->assertSame('POST', $normalized->getMethod());
        $this->assertSame('203.0.113.77', $normalized->getIp());
        $this->assertSame('application/json', $normalized->getHeader('content-type'));
        $this->assertArrayHasKey('nested.value', $normalized->getBody());
        $this->assertSame('1', $normalized->getBody()['nested.value']);
        $this->assertArrayHasKey('session.id', $normalized->getCookies());
        $this->assertStringContainsString('__TEST__', $normalized->getTargetValue('body'));
    }
}
