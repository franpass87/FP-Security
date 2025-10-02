<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\RateLimit\OptionsRateLimitStore;

class OptionsRateLimitStoreTest extends TestCase
{
    public function testIncrementPrunesExpiredEvents(): void
    {
        $store = new OptionsRateLimitStore();

        $this->assertSame(1, $store->increment('test', 10, 100));
        $this->assertSame(2, $store->increment('test', 10, 105));
        $this->assertSame(2, $store->increment('test', 10, 111));
    }

    public function testDataPersistsWithinRequestLifecycle(): void
    {
        $store = new OptionsRateLimitStore();
        $now = time();
        $store->increment('persist', 10, $now);
        $store->flush();

        $nextStore = new OptionsRateLimitStore();
        $this->assertSame(2, $nextStore->increment('persist', 10, $now + 5));
    }
}
