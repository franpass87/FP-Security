<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Http\NormalizedRequest;
use WPRTWAF\RateLimit\RateLimitStoreInterface;
use WPRTWAF\RateLimit\RateLimiter;

class RateLimiterTest extends TestCase
{
    public function testDisabledRateLimiterDoesNotConsumeCounters(): void
    {
        $store = new class implements RateLimitStoreInterface {
            public array $increments = [];

            public function increment(string $key, int $window, int $now): int
            {
                $this->increments[] = $key;

                return count($this->increments);
            }
        };

        $rateLimiter = new RateLimiter($store, fn (): array => ['rate_limit' => ['enabled' => false]], fn (): int => 1000);

        $request = $this->request('198.51.100.10');

        $this->assertTrue($rateLimiter->allow($request));
        $this->assertSame([], $store->increments);
    }

    public function testIpLimitBlocksWhenThresholdExceeded(): void
    {
        $store = new class implements RateLimitStoreInterface {
            private array $counts = [];

            public function increment(string $key, int $window, int $now): int
            {
                $this->counts[$key] = ($this->counts[$key] ?? []);
                $this->counts[$key][] = $now;

                return count($this->counts[$key]);
            }
        };

        $config = [
            'rate_limit' => [
                'enabled' => true,
                'ip_max' => 2,
                'ip_window' => 60,
                'endpoint_max' => 0,
                'endpoint_window' => 60,
            ],
        ];

        $rateLimiter = new RateLimiter($store, fn (): array => $config, fn (): int => 1000);
        $request = $this->request('198.51.100.10');

        $this->assertTrue($rateLimiter->allow($request));
        $this->assertTrue($rateLimiter->allow($request));
        $this->assertFalse($rateLimiter->allow($request));
    }

    public function testEndpointLimitEvaluatesPerPath(): void
    {
        $store = new class implements RateLimitStoreInterface {
            private array $counts = [];

            public function increment(string $key, int $window, int $now): int
            {
                $this->counts[$key] = ($this->counts[$key] ?? 0) + 1;

                return $this->counts[$key];
            }
        };

        $config = [
            'rate_limit' => [
                'enabled' => true,
                'ip_max' => 0,
                'ip_window' => 60,
                'endpoint_max' => 1,
                'endpoint_window' => 60,
            ],
        ];

        $time = 0;
        $rateLimiter = new RateLimiter($store, fn (): array => $config, function () use (&$time): int {
            return 1000 + $time++;
        });

        $requestA = $this->request('203.0.113.5', '/api/login');
        $requestB = $this->request('203.0.113.5', '/api/logout');

        $this->assertTrue($rateLimiter->allow($requestA));
        $this->assertFalse($rateLimiter->allow($requestA));
        $this->assertTrue($rateLimiter->allow($requestB));
    }

    private function request(string $ip, string $uri = '/test'): NormalizedRequest
    {
        return new NormalizedRequest(
            'GET',
            $uri,
            $ip,
            ['user-agent' => 'phpunit'],
            [],
            [],
            [],
            ''
        );
    }
}
