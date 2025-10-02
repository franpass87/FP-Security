<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Auth\OptionsLoginAttemptStore;

class OptionsLoginAttemptStoreTest extends TestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();
        if (function_exists('delete_option')) {
            delete_option('wp_realtime_waf_login_limits');
        }
    }

    public function testRecordAndLockLifecycle(): void
    {
        $store = new OptionsLoginAttemptStore();

        $this->assertSame(1, $store->recordAttempt('key', 60, 100));
        $this->assertSame(2, $store->recordAttempt('key', 60, 110));

        $store->lock('key', 30, 110);
        $this->assertTrue($store->isLocked('key', 120));
        $this->assertFalse($store->isLocked('key', 200));

        $store->clearAttempts('key');
        $this->assertFalse($store->isLocked('key', 300));
    }
}
