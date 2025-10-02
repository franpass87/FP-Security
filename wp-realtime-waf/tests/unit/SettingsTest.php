<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Admin\Settings;

class SettingsTest extends TestCase
{
    public function testSanitizeLoggingOptions(): void
    {
        $settings = new Settings();

        $result = $settings->sanitize([
            'mode' => 'invalid',
            'logging' => [
                'anonymize_ip' => '0',
                'max_events' => '5',
                'default_severity' => 'CRITICAL',
                'alerts' => [
                    'min_severity' => 'unknown',
                    'throttle' => '0',
                    'only_blocking' => '1',
                    'email' => [
                        'enabled' => '1',
                        'recipient' => 'not-an-email',
                    ],
                    'webhook' => [
                        'enabled' => '1',
                        'url' => 'ftp://example.com',
                        'secret' => '  secret  ',
                    ],
                ],
            ],
        ]);

        $logging = $result['logging'];
        $this->assertSame(10, $logging['max_events']);
        $this->assertSame('critical', $logging['default_severity']);
        $this->assertSame('medium', $logging['alerts']['min_severity']);
        $this->assertSame(300, $logging['alerts']['throttle']);
        $this->assertSame('', $logging['alerts']['email']['recipient']);
        $this->assertSame('', $logging['alerts']['webhook']['url']);
        $this->assertSame('secret', $logging['alerts']['webhook']['secret']);
    }
}
