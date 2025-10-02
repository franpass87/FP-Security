<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use WPRTWAF\Actions\Decision;
use WPRTWAF\Actions\DecisionResult;
use WPRTWAF\Http\NormalizedRequest;
use WPRTWAF\Logging\AlertManager;
use WPRTWAF\Logging\Event;
use WPRTWAF\Logging\EventLogger;
use WPRTWAF\Logging\EventStoreInterface;
use WPRTWAF\Rules\RuleMatch;

class EventLoggerTest extends TestCase
{
    public function testLogsAnonymizedEventAndTriggersAlerts(): void
    {
        $store = new class implements EventStoreInterface {
            public array $events = [];

            public function setMaxEvents(int $maxEvents): void
            {
            }

            public function append(Event $event): void
            {
                $this->events[] = $event->toArray();
            }

            public function getEvents(int $limit, int $offset = 0): array
            {
                return [];
            }

            public function all(): array
            {
                return $this->events;
            }

            public function count(): int
            {
                return count($this->events);
            }

            public function getDecisionCounts(): array
            {
                return [];
            }

            public function getTopAttackers(int $limit = 5): array
            {
                return [];
            }

            public function replace(array $events): void
            {
            }
        };

        $alerts = new class extends AlertManager {
            public array $received = [];

            public function __construct()
            {
            }

            public function handle(Event $event): void
            {
                $this->received[] = $event;
            }
        };

        $options = [
            'mode' => Decision::BLOCK,
            'logging' => [
                'anonymize_ip' => true,
                'max_events' => 100,
            ],
        ];

        $logger = new EventLogger(
            $store,
            new NullLogger(),
            static fn () => $options,
            $alerts
        );

        $request = new NormalizedRequest(
            'POST',
            'https://example.com/login',
            '192.0.2.123',
            ['user-agent' => 'UnitTest'],
            ['a' => 'b'],
            ['payload' => 'value'],
            ['cookie' => '1'],
            'payload=value'
        );

        $match = new RuleMatch(['id' => 'test-rule', 'severity' => 'critical'], 'body', ['payload' => 'value']);
        $result = new DecisionResult(Decision::BLOCK, $match, 'rule:test-rule');

        $logger->logDecision($request, $result);

        $this->assertCount(1, $store->events);
        $event = $store->events[0];
        $this->assertSame('192.0.2.0', $event['ip']);
        $this->assertSame('critical', $event['severity']);
        $this->assertCount(1, $alerts->received);
    }
}
