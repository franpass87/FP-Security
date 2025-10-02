<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Actions\Decision;
use WPRTWAF\Logging\AlertManager;
use WPRTWAF\Logging\Event;

class AlertManagerTest extends TestCase
{
    public function testThrottlePreventsRepeatedAlerts(): void
    {
        $emails = [];
        $requests = [];

        $options = [
            'logging' => [
                'alerts' => [
                    'min_severity' => 'medium',
                    'throttle' => 300,
                    'only_blocking' => true,
                    'email' => [
                        'enabled' => true,
                        'recipient' => 'admin@example.com',
                    ],
                    'webhook' => [
                        'enabled' => true,
                        'url' => 'https://example.org/webhook',
                        'secret' => 'shared',
                    ],
                ],
            ],
        ];

        $manager = new AlertManager(
            static fn () => $options,
            function (string $to, string $subject, string $message) use (&$emails): bool {
                $emails[] = [$to, $subject, $message];

                return true;
            },
            function (string $url, array $payload) use (&$requests): void {
                $requests[] = [$url, $payload];
            }
        );

        $event = Event::create(
            Decision::BLOCK,
            'high',
            '198.51.100.10',
            '/login',
            'POST',
            'rule:test',
            'rule-test',
            'block',
            'all',
            [],
            'UnitTest'
        );

        $manager->handle($event);
        $manager->handle($event);

        $this->assertCount(1, $emails);
        $this->assertCount(1, $requests);
        $this->assertSame('https://example.org/webhook', $requests[0][0]);
        $this->assertArrayHasKey('signature', $requests[0][1]);
    }
}
