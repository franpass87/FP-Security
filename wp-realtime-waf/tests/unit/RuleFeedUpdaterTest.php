<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Rules\RuleFeedUpdater;
use WPRTWAF\Rules\RuleRepository;

class RuleFeedUpdaterTest extends TestCase
{
    private string $feedPath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->feedPath = tempnam(sys_get_temp_dir(), 'feed');
    }

    protected function tearDown(): void
    {
        if (is_file($this->feedPath)) {
            @unlink($this->feedPath);
        }

        parent::tearDown();
    }

    public function testAppliesFeedAndPersistsState(): void
    {
        $repository = new RuleRepository();
        $options = [];
        $secret = 'wprtwaf-local-feed-secret';
        $payload = [
            'version' => '2024.06',
            'issued_at' => '2024-06-01T00:00:00Z',
            'expires_at' => '2099-06-01T00:00:00Z',
            'rules' => [
                [
                    'id' => 'feed-rfi-001',
                    'pattern' => '/feed-test/',
                    'action' => 'block',
                    'targets' => ['body'],
                ],
            ],
        ];

        $this->writeFeed($payload, $secret, $this->feedPath);

        $updater = new RuleFeedUpdater(
            $repository,
            $this->feedPath,
            $secret,
            function (string $key, mixed $default) use (&$options): mixed {
                return $options[$key] ?? $default;
            },
            function (string $key, array $value) use (&$options): void {
                $options[$key] = $value;
            },
            static fn (): int => strtotime('2024-06-15T00:00:00Z')
        );

        $updater->maybeUpdate();

        $feedRules = $repository->getFeedRules();
        $this->assertCount(1, $feedRules);
        $this->assertSame('feed-rfi-001', $feedRules[0]['id']);

        $this->assertArrayHasKey('wp_realtime_waf_rule_feed_state', $options);
        $state = $options['wp_realtime_waf_rule_feed_state'];
        $this->assertSame('2024.06', $state['version']);
        $this->assertNotEmpty($state['hash']);
        $this->assertSame($feedRules, $state['rules']);
    }

    public function testSkipsWhenSignatureInvalid(): void
    {
        $repository = new RuleRepository();
        $options = [];
        $secret = 'wprtwaf-local-feed-secret';
        $payload = [
            'version' => '2024.06',
            'issued_at' => '2024-06-01T00:00:00Z',
            'expires_at' => '2099-06-01T00:00:00Z',
            'rules' => [
                [
                    'id' => 'feed-rfi-001',
                    'pattern' => '/feed-test/',
                    'action' => 'block',
                    'targets' => ['body'],
                ],
            ],
        ];

        // Write feed with wrong secret to break signature validation.
        $this->writeFeed($payload, 'invalid-secret', $this->feedPath);

        $updater = new RuleFeedUpdater(
            $repository,
            $this->feedPath,
            $secret,
            function (string $key, mixed $default) use (&$options): mixed {
                return $options[$key] ?? $default;
            },
            function (string $key, array $value) use (&$options): void {
                $options[$key] = $value;
            },
            static fn (): int => strtotime('2024-06-15T00:00:00Z')
        );

        $updater->maybeUpdate();

        $this->assertSame([], $repository->getFeedRules());
        $this->assertArrayNotHasKey('wp_realtime_waf_rule_feed_state', $options);
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function writeFeed(array $payload, string $secret, string $path): void
    {
        $encodedPayload = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $signature = hash_hmac('sha256', (string) $encodedPayload, $secret);

        $feed = [
            'payload' => $payload,
            'signature' => $signature,
            'algorithm' => 'sha256',
            'note' => 'test feed',
        ];

        file_put_contents($path, json_encode($feed, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }
}
