<?php

namespace WPRTWAF\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WPRTWAF\Logging\Event;
use WPRTWAF\Logging\OptionsEventStore;

class OptionsEventStoreTest extends TestCase
{
    public function testAppendRespectsMaxEvents(): void
    {
        $store = new OptionsEventStore('waf_test_events', 3);

        for ($i = 0; $i < 5; $i++) {
            $store->append(Event::create(
                'block',
                'high',
                '203.0.113.' . $i,
                '/test',
                'GET',
                'reason',
                'rule-' . $i,
                'block',
                'all',
                ['match' => 'value'],
                'UA/' . $i
            ));
        }

        $events = $store->all();
        $this->assertCount(3, $events);
        $this->assertSame('203.0.113.4', $events[2]['ip']);
    }

    public function testDecisionCountsAndTopAttackers(): void
    {
        $store = new OptionsEventStore('waf_test_events_counts', 10);

        $store->append(Event::create('allow', 'low', '198.51.100.1', '/', 'GET', 'ok', 'rule', 'monitor', 'all', [], 'UA'));
        $store->append(Event::create('block', 'high', '198.51.100.2', '/', 'GET', 'match', 'rule', 'block', 'all', [], 'UA'));
        $store->append(Event::create('block', 'high', '198.51.100.2', '/', 'GET', 'match', 'rule', 'block', 'all', [], 'UA'));

        $counts = $store->getDecisionCounts();
        $this->assertSame(1, $counts['allow']);
        $this->assertSame(2, $counts['block']);

        $top = $store->getTopAttackers(1);
        $this->assertCount(1, $top);
        $this->assertSame('198.51.100.2', $top[0]['ip']);
        $this->assertSame(2, $top[0]['count']);
    }
}
