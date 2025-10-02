<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\RateLimit\RedisRateLimitStore;

class RedisRateLimitStoreTest extends TestCase
{
    public function testSlidingWindowBehaviour(): void
    {
        $client = new class {
            public array $data = [];
            public array $expires = [];

            public function zremrangebyscore(string $key, int|float $min, int|float $max): void
            {
                if (!isset($this->data[$key])) {
                    return;
                }

                foreach ($this->data[$key] as $member => $score) {
                    if ($score <= $max) {
                        unset($this->data[$key][$member]);
                    }
                }
            }

            public function zadd(string $key, array $values): void
            {
                foreach ($values as $member => $score) {
                    $this->data[$key][$member] = $score;
                }
            }

            public function zcard(string $key): int
            {
                return isset($this->data[$key]) ? count($this->data[$key]) : 0;
            }

            public function expire(string $key, int $ttl): void
            {
                $this->expires[$key] = $ttl;
            }
        };

        $store = new RedisRateLimitStore($client);

        $this->assertSame(1, $store->increment('rl', 10, 100));
        $this->assertSame(2, $store->increment('rl', 10, 101));
        $this->assertSame(1, $store->increment('rl', 10, 200));
        $this->assertGreaterThanOrEqual(10, $client->expires['rl']);
    }
}
