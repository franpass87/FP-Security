<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Bootstrap\EarlyBlocker;

class EarlyBlockerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (!defined('WP_REALTIME_WAF_MODE')) {
            define('WP_REALTIME_WAF_MODE', 'block');
        }
    }

    public function testBlocksWhenSignaturePresent(): void
    {
        $blocker = new EarlyBlocker();

        $_SERVER['REQUEST_URI'] = '/?test=__TEST_SUSPECT__';

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Forbidden');

        $blocker->maybeBlock();
    }
}
