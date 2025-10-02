<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use WPRTWAF\RateLimit\FallbackRateLimitStore;
use WPRTWAF\RateLimit\RateLimitStoreInterface;

class FallbackRateLimitStoreTest extends TestCase
{
    public function testFallsBackAfterPrimaryFailure(): void
    {
        $primary = new class implements RateLimitStoreInterface {
            private int $calls = 0;

            public function increment(string $key, int $window, int $now): int
            {
                $this->calls++;

                if ($this->calls > 1) {
                    throw new RuntimeException('Simulated failure');
                }

                return 1;
            }
        };

        $fallback = new class implements RateLimitStoreInterface {
            public int $calls = 0;

            public function increment(string $key, int $window, int $now): int
            {
                $this->calls++;

                return 10;
            }
        };

        $store = new FallbackRateLimitStore($primary, $fallback);

        $this->assertSame(1, $store->increment('key', 10, 100));
        $this->assertSame(10, $store->increment('key', 10, 101));
        $this->assertSame(1, $fallback->calls);
    }
}
