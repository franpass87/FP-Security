<?php

namespace WPRTWAF\Tests\Integration;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Http\ClientIpResolver;
use WPRTWAF\Http\RequestContext;
use WPRTWAF\Http\RequestNormalizer;
use WPRTWAF\Rules\RuleEngine;
use WPRTWAF\Rules\RuleRepository;

class FuzzPipelineTest extends TestCase
{
    private RequestNormalizer $normalizer;

    private RuleEngine $ruleEngine;

    protected function setUp(): void
    {
        $this->normalizer = new RequestNormalizer(new ClientIpResolver(static fn (): array => [
            'trusted_proxies' => [],
        ]));

        $repository = new RuleRepository();
        $repository->setRules([
            [
                'id' => 'fuzz-signal',
                'description' => 'Detects fuzz payload marker',
                'pattern' => '/FUZZ_PAYLOAD/i',
                'targets' => ['all'],
                'enabled' => true,
                'severity' => 'medium',
                'tags' => ['test'],
            ],
        ]);
        $this->ruleEngine = new RuleEngine($repository);
    }

    /**
     * @dataProvider provideFuzzPayloads
     *
     * @param array{
     *     query: string,
     *     header: string,
     *     body: array<string, mixed>,
     *     cookie: string,
     *     raw: string,
     *     shouldMatch: bool
     * } $payload
     */
    public function testPipelineHandlesFuzzPayloads(array $payload): void
    {
        $context = new RequestContext(
            method: 'POST',
            uri: '/index.php?sample=' . rawurlencode($payload['query']),
            headers: [
                'User-Agent' => $payload['header'],
                'X-Custom' => "start\0" . $payload['header'],
            ],
            query: ['sample' => $payload['query']],
            body: $payload['body'],
            cookies: ['fuzz' => $payload['cookie']],
            rawBody: $payload['raw'],
            server: ['REMOTE_ADDR' => '203.0.113.10']
        );

        $normalized = $this->normalizer->normalize($context);
        $this->assertSame('203.0.113.10', $normalized->getIp());
        $this->assertNotSame('', $normalized->getTargetValue('headers'));
        $this->assertNotSame('', $normalized->getTargetValue('all'));

        $match = $this->ruleEngine->match($normalized);
        if ($payload['shouldMatch']) {
            $this->assertNotNull($match);
            $this->assertSame('fuzz-signal', $match->getRule()['id'] ?? null);
        } else {
            $this->assertNull($match);
        }
    }

    /**
     * @return iterable<string, array<int, array{query: string, header: string, body: array<string, mixed>, cookie: string, raw: string, shouldMatch: bool}>>
     */
    public function provideFuzzPayloads(): iterable
    {
        yield 'unicode and control characters' => [[
            'query' => "こんにちは世界",
            'header' => "FuzzAgent/1.0\u{2028}",
            'body' => [
                'nested' => [
                    'emoji' => '🌐',
                    'null_byte' => "null\0byte",
                ],
            ],
            'cookie' => base64_encode(random_bytes(8)),
            'raw' => json_encode([
                'data' => "⚡" . str_repeat('a', 16),
            ], JSON_THROW_ON_ERROR),
            'shouldMatch' => false,
        ]];

        yield 'deeply nested array' => [[
            'query' => 'level=1',
            'header' => 'Nested/2.0',
            'body' => [
                'level1' => [
                    'level2' => [
                        'level3' => ['value' => 'safe'],
                    ],
                ],
            ],
            'cookie' => 'nested-cookie',
            'raw' => 'plain body content',
            'shouldMatch' => false,
        ]];

        yield 'payload match in raw body' => [[
            'query' => 'action=test',
            'header' => 'Match/1.1',
            'body' => [
                'data' => 'FUZZ_PAYLOAD',
            ],
            'cookie' => 'match-cookie',
            'raw' => 'FUZZ_PAYLOAD inside body',
            'shouldMatch' => true,
        ]];
    }
}
